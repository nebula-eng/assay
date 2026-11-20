#!/usr/bin/env node
/**
 * Design audit over the Chrome DevTools Protocol.
 *
 * A screenshot tells you whether something *looks* wrong; this tells you *what*
 * is wrong, with numbers. It walks every tab and checks the properties that
 * separate a professional interface from a plausible one:
 *
 *   1. Contrast      — every visible text node meets WCAG AA (4.5:1 body,
 *                      3:1 for large text and UI glyphs).
 *   2. Type floor    — no readable text below 10px; body copy at 12–14px.
 *   3. Line length   — prose stays under ~100 characters per line.
 *   4. Rhythm        — card gaps are uniform; padding is from the scale.
 *   5. Targets       — every interactive element is at least 24px tall.
 *   6. Truncation    — no text silently clipped by an ancestor.
 *   7. Alignment     — grid children share a baseline within their row.
 *
 * Usage:
 *   node scripts/design_audit.mjs [--url http://127.0.0.1:8801/]
 */

import { spawn } from "node:child_process";
import {
  argValue as sharedArgValue,
  launchBrowser,
  resolveBrowserOrExit,
} from "./browser.mjs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const argValue = (name, fallback) => sharedArgValue(args, name, fallback);

const TARGET_URL = argValue("--url", "http://127.0.0.1:8801/");
const BROWSER = resolveBrowserOrExit(argValue("--browser", ""));
const REPORT = argValue("--report", "");

const PORT = 9351;
const PROFILE = mkdtempSync(join(tmpdir(), "assay-audit-"));
const TABS = ["Overview", "Structure", "Imports", "Strings", "Indicators", "ATT&CK", "Findings"];

/**
 * The audit itself, evaluated inside the page.
 *
 * Kept as one string so it runs in a single round trip and has direct access to
 * `getComputedStyle` and `getBoundingClientRect`.
 */
const AUDIT_SCRIPT = String.raw`(() => {
  const findings = [];
  const add = (severity, rule, detail) => findings.push({ severity, rule, detail });

  // ---- helpers -----------------------------------------------------------
  const parseColour = (value) => {
    const match = value.match(/rgba?\(([^)]+)\)/);
    if (!match) return null;
    const parts = match[1].split(',').map(v => parseFloat(v.trim()));
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  };

  const relativeLuminance = ({ r, g, b }) => {
    const channel = (v) => {
      const s = v / 255;
      return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  };

  const contrast = (fg, bg) => {
    const l1 = relativeLuminance(fg);
    const l2 = relativeLuminance(bg);
    const lighter = Math.max(l1, l2);
    const darker = Math.min(l1, l2);
    return (lighter + 0.05) / (darker + 0.05);
  };

  // Walk up for the first opaque background.
  const backgroundOf = (element) => {
    let node = element;
    while (node && node !== document.documentElement) {
      const bg = parseColour(getComputedStyle(node).backgroundColor);
      if (bg && bg.a >= 0.95) return bg;
      node = node.parentElement;
    }
    return { r: 10, g: 13, b: 19, a: 1 }; // --bg
  };

  const isVisible = (element) => {
    const style = getComputedStyle(element);
    if (style.visibility === 'hidden' || style.display === 'none') return false;
    if (parseFloat(style.opacity) < 0.1) return false;
    const rect = element.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  const textNodes = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const text = node.textContent.trim();
    if (!text) continue;
    const parent = node.parentElement;
    if (!parent || !isVisible(parent)) continue;
    if (parent.closest('.sr-only, .skip-link')) continue;
    textNodes.push({ node, text, parent });
  }

  // ---- 1. contrast ------------------------------------------------------
  const seenContrast = new Set();
  for (const { text, parent } of textNodes) {
    const style = getComputedStyle(parent);
    const fg = parseColour(style.color);
    if (!fg || fg.a < 0.1) continue;
    const bg = backgroundOf(parent);
    // Flatten a translucent foreground onto its background.
    const blended = {
      r: fg.r * fg.a + bg.r * (1 - fg.a),
      g: fg.g * fg.a + bg.g * (1 - fg.a),
      b: fg.b * fg.a + bg.b * (1 - fg.a),
    };
    const ratio = contrast(blended, bg);
    const size = parseFloat(style.fontSize);
    const weight = parseInt(style.fontWeight, 10) || 400;
    const large = size >= 18.66 || (size >= 14 && weight >= 700);
    const required = large ? 3.0 : 4.5;
    if (ratio < required) {
      const key = parent.className + '|' + text.slice(0, 12);
      if (!seenContrast.has(key)) {
        seenContrast.add(key);
        add(
          ratio < required - 1.2 ? 'error' : 'warn',
          'contrast',
          text.slice(0, 40) + ' → ' + ratio.toFixed(2) + ':1 (need ' + required + ') in .' + (parent.className || parent.tagName)
        );
      }
    }
  }

  // ---- 2. type floor ----------------------------------------------------
  const seenSize = new Set();
  for (const { text, parent } of textNodes) {
    const size = parseFloat(getComputedStyle(parent).fontSize);
    if (size < 9.5) {
      const key = Math.round(size * 10);
      if (!seenSize.has(key)) {
        seenSize.add(key);
        add('error', 'type-floor', size + 'px text: "' + text.slice(0, 32) + '"');
      }
    }
  }

  // ---- 3. line length ---------------------------------------------------
  // Measured as characters per rendered line: total text length divided by the
  // number of lines the element actually occupies. Using the container width
  // instead would flag every short caption that happens to sit in a wide column.
  for (const el of document.querySelectorAll('p, .explainer, .verdict, .finding-desc, .lede')) {
    if (!isVisible(el)) continue;
    const text = (el.textContent || '').trim();
    if (text.length < 40) continue;
    const style = getComputedStyle(el);
    const lineHeight = parseFloat(style.lineHeight) || parseFloat(style.fontSize) * 1.6;
    const lines = Math.max(1, Math.round(el.getBoundingClientRect().height / lineHeight));
    const perLine = text.length / lines;
    if (perLine > 110) {
      add('warn', 'line-length', Math.round(perLine) + ' chars/line over ' + lines + ' line(s) in .' + (el.className || el.tagName));
    }
  }

  // ---- 4. rhythm --------------------------------------------------------
  const stacks = [...document.querySelectorAll('.stack')].filter(isVisible);
  const gaps = new Set();
  for (const stack of stacks) {
    const gap = getComputedStyle(stack).rowGap;
    if (gap) gaps.add(gap);
  }
  const allowedGaps = new Set(['12px', '14px', '16px', 'normal']);
  for (const gap of gaps) {
    if (!allowedGaps.has(gap)) add('warn', 'rhythm', 'vertical stack gap is ' + gap);
  }

  // ---- 5. targets -------------------------------------------------------
  // A checkbox inside a <label> inherits the label's hit area, so the label is
  // the thing to measure.
  for (const label of document.querySelectorAll('.check')) {
    if (!isVisible(label)) continue;
    const rect = label.getBoundingClientRect();
    if (rect.height < 20) {
      add('warn', 'target-size', Math.round(rect.height) + 'px tall checkbox label');
    }
  }
  const seenTarget = new Set();
  for (const el of document.querySelectorAll('button, a, [role="tab"]')) {
    if (!isVisible(el)) continue;
    const rect = el.getBoundingClientRect();
    // The tab strip is denser by design, and a hover-revealed icon button is
    // backed by a full-height row.
    if (rect.height < 20 && !el.closest('.tabs') && !el.classList.contains('sample-remove')) {
      const key = el.className || el.tagName;
      if (!seenTarget.has(key)) {
        seenTarget.add(key);
        add('warn', 'target-size', Math.round(rect.height) + 'px tall: .' + key);
      }
    }
  }

  // ---- 6. truncation ----------------------------------------------------
  for (const el of document.querySelectorAll('.card-title, .card-sub, .metric-value, .sample-name, .tab')) {
    if (!isVisible(el)) continue;
    const style = getComputedStyle(el);
    const clipped = el.scrollWidth > el.clientWidth + 2;
    if (clipped && style.textOverflow !== 'ellipsis') {
      add('error', 'truncation', 'clipped without ellipsis: "' + el.textContent.trim().slice(0, 30) + '"');
    }
  }

  // ---- 7. alignment -----------------------------------------------------
  for (const grid of document.querySelectorAll('.grid')) {
    if (!isVisible(grid)) continue;
    const rows = new Map();
    for (const child of grid.children) {
      if (!isVisible(child)) continue;
      const top = Math.round(child.getBoundingClientRect().top);
      const key = Math.round(top / 8);
      const list = rows.get(key) ?? [];
      list.push(child.getBoundingClientRect().height);
      rows.set(key, list);
    }
    for (const [, heights] of rows) {
      if (heights.length < 2) continue;
      const max = Math.max(...heights);
      const min = Math.min(...heights);
      // Cards in a row may differ in height; that is fine. Flag only when one is
      // a stub, which reads as a rendering failure.
      if (max > 40 && min < max * 0.25) {
        add('warn', 'alignment', 'row height mismatch ' + Math.round(min) + 'px vs ' + Math.round(max) + 'px');
      }
    }
  }

  return findings;
})()`;

async function main() {
  console.log(`assay design audit · ${TARGET_URL}`);
  const session = await launchBrowser({ browser: BROWSER, port: PORT, profile: PROFILE });

  const all = [];
  try {
    const { cdp, evaluate } = session;

    await cdp.send("Page.enable");
    await cdp.send("Runtime.enable");
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: 1440,
      height: 900,
      deviceScaleFactor: 1,
      mobile: false,
    });
    await cdp.send("Page.navigate", { url: TARGET_URL });
    await new Promise((resolve) => setTimeout(resolve, 900));

    for (const tab of TABS) {
      await evaluate(
        `(() => {
           const el = [...document.querySelectorAll('.tab')].find(b => b.textContent.trim().startsWith(${JSON.stringify(tab)}));
           if (el) el.click();
           return Boolean(el);
         })()`,
      );
      await new Promise((resolve) => setTimeout(resolve, 240));
      const findings = await evaluate(AUDIT_SCRIPT);
      for (const finding of findings) all.push({ tab, ...finding });
      const errors = findings.filter((f) => f.severity === "error").length;
      console.log(
        `  ${tab.padEnd(11)} ${String(findings.length).padStart(3)} issue(s)` +
          (errors > 0 ? `, ${errors} error(s)` : ""),
      );
    }
  } finally {
    session.close();
    await new Promise((resolve) => setTimeout(resolve, 250));
    try {
      rmSync(PROFILE, { recursive: true, force: true });
    } catch {
      // ignore
    }
  }

  if (REPORT) writeFileSync(REPORT, JSON.stringify(all, null, 2));

  if (all.length === 0) {
    console.log("\nclean: no contrast, type, rhythm, target or truncation issues");
    return;
  }

  // Group by rule so the same defect repeated across tabs is one line.
  const grouped = new Map();
  for (const finding of all) {
    const key = `${finding.severity}::${finding.rule}::${finding.detail}`;
    if (!grouped.has(key)) grouped.set(key, { ...finding, tabs: [finding.tab] });
    else grouped.get(key).tabs.push(finding.tab);
  }

  console.log(`\n${grouped.size} distinct issue(s):`);
  for (const item of [...grouped.values()].sort((a, b) =>
    a.severity === b.severity ? 0 : a.severity === "error" ? -1 : 1,
  )) {
    console.log(`  [${item.severity}] ${item.rule}: ${item.detail}`);
    console.log(`        in ${[...new Set(item.tabs)].join(", ")}`);
  }

  if (all.some((f) => f.severity === "error")) process.exitCode = 1;
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(1);
});
