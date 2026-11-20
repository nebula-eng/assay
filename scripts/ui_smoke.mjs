#!/usr/bin/env node
/**
 * Headless UI smoke test over the Chrome DevTools Protocol.
 *
 * Why this exists: `vite build` proves the bundle compiles, not that it renders.
 * A missing export, a null dereference in a `.map`, or a CSS layout that collapses
 * to zero height all survive the build and produce a white screen. This script
 * opens the built bundle in a real engine, waits for React to mount, and asserts
 * on the rendered text — which is the cheapest possible check that the workbench
 * actually works.
 *
 * It also collects console errors and unhandled exceptions, because those are the
 * failures that a DOM assertion alone would miss.
 *
 * Usage:
 *   node scripts/ui_smoke.mjs [--url http://127.0.0.1:8765/] [--browser <path>]
 *
 * Exit code 0 when every assertion passes.
 */

import { launchBrowser, resolveBrowserOrExit } from "./browser.mjs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const argValue = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : fallback;
};

const TARGET_URL = argValue("--url", "http://127.0.0.1:8801/");
const BROWSER = resolveBrowserOrExit(argValue("--browser", ""));

const PORT = 9333;
const PROFILE = mkdtempSync(join(tmpdir(), "assay-smoke-"));

const checks = [];
function check(label, fn) {
  try {
    fn();
    checks.push({ label, ok: true });
    console.log(`  ok    ${label}`);
  } catch (error) {
    checks.push({ label, ok: false, error: error.message });
    console.log(`  FAIL  ${label}`);
    console.log(`        ${error.message}`);
  }
}

function require_(condition, message) {
  if (!condition) throw new Error(message);
}

async function main() {
  console.log(`assay ui smoke · ${TARGET_URL}`);
  console.log(`  browser: ${BROWSER}`);

  const session = await launchBrowser({ browser: BROWSER, port: PORT, profile: PROFILE });

  try {
    const { cdp, evaluate } = session;

    const consoleErrors = [];
    const exceptions = [];
    await cdp.send("Runtime.enable");
    await cdp.send("Log.enable");
    cdp.on("Runtime.consoleAPICalled", (params) => {
      if (params.type === "error") {
        consoleErrors.push(
          params.args.map((a) => a.value ?? a.description ?? a.type).join(" "),
        );
      }
    });
    cdp.on("Runtime.exceptionThrown", (params) => {
      exceptions.push(params.exceptionDetails?.text ?? "unknown exception");
    });

    await cdp.send("Page.enable");
    await cdp.send("Page.navigate", { url: TARGET_URL });
    // React mounts synchronously after the module executes; 1.2 s is generous
    // for a 208 KB bundle and keeps the script fast enough for CI.
    await new Promise((resolve) => setTimeout(resolve, 1200));

    console.log("\n[render]");
    const text = await evaluate("document.body.innerText");
    const html = await evaluate("document.getElementById('root').innerHTML.length");

    check("React mounted into #root", () => {
      require_(html > 500, `#root innerHTML is only ${html} chars — likely a blank screen`);
    });
    check("brand is rendered", () => {
      require_(/assay/i.test(text), "brand name missing");
    });
    // `innerText` returns the CSS-transformed text, so the demo badge reads
    // "DEMO". Compare case-insensitively rather than encoding that detail here.
    check("demo mode is labelled", () => {
      require_(/\bdemo\b/i.test(text), "no demo indicator in the header");
    });
    check("verdict line is rendered", () => {
      require_(text.includes("score") || text.includes("Score"), "no verdict text");
    });
    check("tabs are present", () => {
      for (const tab of ["Overview", "Structure", "Imports", "Strings", "Indicators", "ATT&CK", "Findings"]) {
        require_(text.includes(tab), `tab "${tab}" missing`);
      }
    });
    check("score factors are shown", () => {
      require_(
        text.toLowerCase().includes("capability") || text.toLowerCase().includes("packing"),
        "factor names missing",
      );
    });

    console.log("\n[navigation]");
    for (const tab of ["Structure", "ATT&CK", "Findings", "Indicators"]) {
      await evaluate(
        `(() => {
           const el = [...document.querySelectorAll('button')].find(b => b.textContent.trim().startsWith(${JSON.stringify(tab)}));
           if (el) el.click();
           return true;
         })()`,
      );
      await new Promise((resolve) => setTimeout(resolve, 220));
      const body = await evaluate("document.body.innerText");
      check(`tab "${tab}" renders content`, () => {
        require_(body.length > 400, "tab body is suspiciously short");
      });
    }

    console.log("\n[hygiene]");
    check("no unhandled exceptions", () => {
      require_(exceptions.length === 0, exceptions.join(" | "));
    });
    check("no console errors", () => {
      require_(consoleErrors.length === 0, consoleErrors.join(" | "));
    });
    check("no layout overflow", async () => {
      // Checked after the loop below; placeholder to keep ordering readable.
    });
    const overflow = await evaluate(
      "document.documentElement.scrollWidth - document.documentElement.clientWidth",
    );
    checks.pop();
    check("no horizontal overflow", () => {
      require_(overflow <= 1, `page overflows horizontally by ${overflow}px`);
    });
  } finally {
    session.close();
    // Give the profile lock a moment to release before removing it.
    await new Promise((resolve) => setTimeout(resolve, 300));
    try {
      rmSync(PROFILE, { recursive: true, force: true });
    } catch {
      // A leftover temp profile is not worth failing the run over.
    }
  }

  const failed = checks.filter((c) => !c.ok);
  console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
  if (failed.length > 0) {
    console.log("\nfailures:");
    for (const failure of failed) console.log(`  - ${failure.label}: ${failure.error}`);
    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
