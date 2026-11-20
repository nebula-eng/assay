#!/usr/bin/env node
/**
 * Multi-viewport screenshot harness over the Chrome DevTools Protocol.
 *
 * `ui_smoke.mjs` answers "did it render?"; this answers "does it look right?".
 * It walks every tab at four widths, captures a PNG of each, and asserts the
 * geometric properties that a DOM query cannot express:
 *
 *   * nothing overflows horizontally at any width;
 *   * no two sibling panels overlap;
 *   * the tab strip never pushes the report buttons off-screen;
 *   * text is not clipped to zero height (the classic flexbox collapse).
 *
 * Usage:
 *   node scripts/ui_shots.mjs [--url http://127.0.0.1:8801/] [--out .shots]
 */

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import {
  argValue as sharedArgValue,
  launchBrowser,
  resolveBrowserOrExit,
} from "./browser.mjs";
import { join } from "node:path";

const args = process.argv.slice(2);
const argValue = (name, fallback) => sharedArgValue(args, name, fallback);

const TARGET_URL = argValue("--url", "http://127.0.0.1:8801/");
const OUT_DIR = argValue("--out", ".shots");
const BROWSER = resolveBrowserOrExit(argValue("--browser", ""));

const PORT = 9345;
const PROFILE = mkdtempSync(join(tmpdir(), "assay-shots-"));

const VIEWPORTS = [
  { name: "1024", width: 1024, height: 768 },
  { name: "1280", width: 1280, height: 800 },
  { name: "1440", width: 1440, height: 900 },
  { name: "1680", width: 1680, height: 1050 },
];

const TABS = ["Overview", "Structure", "Imports", "Strings", "Indicators", "ATT&CK", "Findings"];

const problems = [];
const record = (viewport, tab, message) => {
  problems.push(`${viewport} / ${tab}: ${message}`);
};

/**
 * Geometry audit.
 *
 * Runs in the page so it can use `getBoundingClientRect` directly. Returns a
 * list of human-readable problems rather than throwing, so one layout bug does
 * not hide the next.
 */
const AUDIT = `(() => {
  const issues = [];
  const vw = document.documentElement.clientWidth;

  // 1. Horizontal overflow of the document itself.
  const overflow = document.documentElement.scrollWidth - vw;
  if (overflow > 1) issues.push('document overflows horizontally by ' + overflow + 'px');

  // 2. Any element wider than the viewport or starting left of it.
  for (const el of document.querySelectorAll('.main *, .topbar *, .sidebar *')) {
    const rect = el.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) continue;
    if (rect.right > vw + 1 && !el.closest('.table-wrap') && !el.closest('.tabs') && !el.closest('.attack-grid')) {
      issues.push('element .' + (el.className && typeof el.className === 'string' ? el.className.split(' ')[0] : el.tagName) + ' extends ' + Math.round(rect.right - vw) + 'px past the right edge');
      break;
    }
    if (rect.left < -1) {
      issues.push('element .' + (el.className && typeof el.className === 'string' ? el.className.split(' ')[0] : el.tagName) + ' starts ' + Math.round(-rect.left) + 'px left of the viewport');
      break;
    }
  }

  // 3. Collapsed text: an element that should have height but has none.
  for (const el of document.querySelectorAll('.report-filename, .card-title, .metric-value, .tab')) {
    const rect = el.getBoundingClientRect();
    if (rect.height < 8 && (el.textContent || '').trim().length > 0) {
      issues.push('collapsed element: ' + (el.className || el.tagName) + ' "' + el.textContent.trim().slice(0, 24) + '"');
      break;
    }
  }

  // 4. Overlapping siblings inside a card body (a grid that did not wrap).
  for (const grid of document.querySelectorAll('.grid')) {
    const kids = [...grid.children].filter(k => k.getBoundingClientRect().width > 0);
    for (let i = 0; i < kids.length; i++) {
      for (let j = i + 1; j < kids.length; j++) {
        const a = kids[i].getBoundingClientRect();
        const b = kids[j].getBoundingClientRect();
        const overlapX = Math.min(a.right, b.right) - Math.max(a.left, b.left);
        const overlapY = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
        if (overlapX > 4 && overlapY > 4) {
          issues.push('overlapping panels in .grid (' + Math.round(overlapX) + 'x' + Math.round(overlapY) + 'px)');
          i = kids.length;
          break;
        }
      }
    }
  }

  // 5. Substantive render. Geometry checks pass happily on an empty shell, so
  //    assert that the primary content actually occupies space. Deliberately
  //    measured as *container height*, not ink coverage: a metric that counts
  //    whitespace as empty would push the design toward being cramped, which is
  //    the opposite of the goal.
  {
    const cards = [...document.querySelectorAll('.card')];
    const total = cards.reduce((sum, card) => sum + card.getBoundingClientRect().height, 0);
    if (cards.length === 0) {
      issues.push('no content cards rendered');
    } else if (total < 180) {
      issues.push('content occupies only ' + Math.round(total) + 'px — possible collapsed render');
    }

    // Every card header must have a visible title, which catches a component
    // that rendered its frame but lost its content.
    for (const title of document.querySelectorAll('.card-title')) {
      if (!title.textContent.trim()) {
        issues.push('a card header rendered without a title');
        break;
      }
    }
  }

  // 6. Tab strip must not clip its own last tab.
  const tabs = document.querySelector('.tabs');
  if (tabs && tabs.scrollWidth > tabs.clientWidth + 2) {
    // Acceptable only if it can scroll; flag when the scrollbar is invisible AND
    // the overflow is large enough to hide a whole tab.
    const hidden = tabs.scrollWidth - tabs.clientWidth;
    if (hidden > 40) issues.push('tab strip hides ' + hidden + 'px of tabs');
  }

  return issues;
})()`;

async function main() {
  mkdirSync(OUT_DIR, { recursive: true });
  console.log(`assay layout shots · ${TARGET_URL}`);
  console.log(`  output: ${OUT_DIR}`);

  // 2x device scale: the screenshots are inspected at retina density, so a
  // 1x capture would under-represent exactly the sub-pixel crowding these
  // checks are looking for.
  const session = await launchBrowser({
    browser: BROWSER,
    port: PORT,
    profile: PROFILE,
    extraFlags: ["--force-device-scale-factor=2"],
  });

  const manifest = [];
  try {
    const { cdp, evaluate } = session;

    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");

    for (const viewport of VIEWPORTS) {
      await cdp.send("Emulation.setDeviceMetricsOverride", {
        width: viewport.width,
        height: viewport.height,
        deviceScaleFactor: 2,
        mobile: false,
      });
      await cdp.send("Page.navigate", { url: TARGET_URL });
      await new Promise((resolve) => setTimeout(resolve, 900));

      for (const tab of TABS) {
        // Click the tab, then let layout and any transition settle.
        await evaluate(
          `(() => {
             const el = [...document.querySelectorAll('.tab')].find(b => b.textContent.trim().startsWith(${JSON.stringify(tab)}));
             if (el) el.click();
             return Boolean(el);
           })()`,
        );
        await new Promise((resolve) => setTimeout(resolve, 260));

        const issues = await evaluate(AUDIT);
        for (const issue of issues) record(viewport.name, tab, issue);

        const shot = await cdp.send("Page.captureScreenshot", {
          format: "png",
          captureBeyondViewport: false,
        });
        const file = join(OUT_DIR, `${viewport.name}-${tab.toLowerCase().replace(/[&]/g, "")}.png`);
        writeFileSync(file, Buffer.from(shot.data, "base64"));
        manifest.push({ viewport: viewport.name, tab, file });
      }
      console.log(`  captured ${TABS.length} tabs at ${viewport.width}×${viewport.height}`);
    }
  } finally {
    session.close();
    await new Promise((resolve) => setTimeout(resolve, 250));
    try {
      rmSync(PROFILE, { recursive: true, force: true });
    } catch {
      // A leftover temp profile is not worth failing over.
    }
  }

  writeFileSync(join(OUT_DIR, "manifest.json"), JSON.stringify(manifest, null, 2));

  console.log(`\n${manifest.length} screenshots captured`);
  if (problems.length === 0) {
    console.log("no layout problems found");
    return;
  }
  console.log(`\n${problems.length} layout problem(s):`);
  for (const problem of problems) console.log(`  - ${problem}`);
  process.exitCode = 1;
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
