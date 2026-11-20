/**
 * Browser discovery and argument parsing shared by the three UI check scripts.
 *
 * All three drive a real browser over the DevTools protocol, because none of the
 * layout questions this project asks — is anything overlapping, is that text
 * legible at 4.5:1, does a card collapse to zero height — can be answered by a
 * bundler or by parsing HTML.
 *
 * The browser is a *dependency*, so failing to find one is a setup problem and
 * must say so in those terms. Silently falling back to a hard-coded Windows
 * path, as the earlier per-script copies did, turns a missing dependency into
 * an opaque `ENOENT` on Linux and macOS.
 */

import { existsSync } from "node:fs";
import { spawn } from "node:child_process";

/** Candidate locations, most specific first, per platform. */
const CANDIDATES = {
  win32: [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  ],
  darwin: [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
  ],
  linux: [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
  ],
};

/** Read `--name value` from argv, falling back when absent. */
export function argValue(args, name, fallback) {
  const index = args.indexOf(name);
  return index >= 0 && index + 1 < args.length ? args[index + 1] : fallback;
}

/**
 * Resolve the browser executable.
 *
 * Precedence: explicit `--browser`, then `ASSAY_BROWSER`, then the first
 * existing candidate for this platform. Throws with an actionable message when
 * nothing is found, rather than letting `spawn` fail with ENOENT later.
 */
export function resolveBrowser(explicit) {
  if (explicit) {
    if (!existsSync(explicit)) {
      throw new Error(
        `--browser points at ${explicit}, which does not exist.\n` +
          "Pass the path to a Chromium-based browser (Chrome, Edge or Chromium).",
      );
    }
    return explicit;
  }

  const fromEnv = process.env.ASSAY_BROWSER;
  if (fromEnv) {
    if (!existsSync(fromEnv)) {
      throw new Error(`ASSAY_BROWSER is set to ${fromEnv}, which does not exist.`);
    }
    return fromEnv;
  }

  const candidates = CANDIDATES[process.platform] ?? CANDIDATES.linux;
  const found = candidates.find((path) => existsSync(path));
  if (found) return found;

  throw new Error(
    `No Chromium-based browser found for platform "${process.platform}".\n` +
      "Tried:\n" +
      candidates.map((path) => `  ${path}`).join("\n") +
      "\nInstall Chrome/Edge/Chromium, or point at one explicitly:\n" +
      "  --browser /path/to/chrome    or    ASSAY_BROWSER=/path/to/chrome",
  );
}

/**
 * Resolve the browser, or exit with a readable message.
 *
 * `resolveBrowser` throws, and a throw during module initialisation surfaces as
 * an unhandled rejection with a stack trace pointing at this file — noise that
 * buries the one line the reader needs. This wrapper turns it into a plain
 * message and exit code 3, matching the CLI's documented "setup or usage error"
 * code so a CI script can treat both the same way.
 */
export function resolveBrowserOrExit(explicit) {
  try {
    return resolveBrowser(explicit);
  } catch (error) {
    process.stderr.write(`\n${error.message}\n\n`);
    process.exit(3);
  }
}

/**
 * Launch flags shared by all three scripts.
 *
 * Kept deliberately minimal: every flag here can change how layout is measured,
 * and these scripts assert on measured geometry, so an extra flag is a silent
 * change to what the assertions mean. `--headless=new` is the mode that still
 * lays out and paints — the legacy `--headless` path on some builds returns
 * empty boxes, which would make every geometry assertion vacuously pass.
 *
 * @param {string} profileDir Per-run profile directory, so a check never
 *   inherits state from a previous run.
 * @param {number} port DevTools port; each script uses a distinct one so three
 *   checks can run concurrently.
 * @param {string[]} extra Additional flags, e.g. the 2x device scale factor the
 *   screenshot script needs.
 */
export function browserFlags(profileDir, port, extra = []) {
  return [
    `--remote-debugging-port=${port}`,
    "--headless=new",
    "--disable-gpu",
    "--disable-extensions",
    "--no-first-run",
    "--no-default-browser-check",
    ...extra,
    `--user-data-dir=${profileDir}`,
    "about:blank",
  ];
}

/**
 * A minimal DevTools protocol client over one WebSocket.
 *
 * Substantially the same class existed in all three check scripts, which meant a
 * protocol fix had to be made three times and usually was not. The variant kept
 * here is the one that also dispatches events, because the render check needs
 * `Runtime.exceptionThrown` and the others simply ignore it.
 */
class Cdp {
  constructor(socket) {
    this.socket = socket;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
      } else if (message.method) {
        for (const listener of this.listeners.get(message.method) ?? []) {
          listener(message.params);
        }
      }
    });
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.socket.send(JSON.stringify({ id, method, params }));
    });
  }

  on(method, listener) {
    const list = this.listeners.get(method) ?? [];
    list.push(listener);
    this.listeners.set(method, list);
  }

  /**
   * Evaluate an expression in the page and return its value.
   *
   * `returnByValue` is required: without it the reply is a remote-object handle
   * that has to be resolved by a second round trip. `awaitPromise` lets the
   * caller write an async expression and get the settled value.
   */
  async evaluate(expression) {
    const result = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      const detail = result.exceptionDetails;
      throw new Error(
        `evaluation failed: ${detail.text} ${detail.exception?.description ?? ""}`.trim(),
      );
    }
    return result.result.value;
  }
}

/** Poll the DevTools endpoint until a page target appears. */
async function waitForEndpoint(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`);
      if (response.ok) {
        const targets = await response.json();
        const page = targets.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
        if (page) return page;
      }
    } catch {
      // The browser has not bound the port yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 120));
  }
  throw new Error(`the browser did not expose a page target on port ${port}`);
}

/**
 * Launch a browser, attach to it, and return the session.
 *
 * The caller is responsible for calling `close()`. That is deliberate: these
 * scripts assert on measured geometry, so the browser must stay alive until the
 * last measurement is taken, and a `finally` in the caller is the only place
 * that knows when that is.
 *
 * @param {object} options
 * @param {string} options.browser Executable, from `resolveBrowserOrExit`.
 * @param {number} options.port DevTools port.
 * @param {string} options.profile Per-run profile directory.
 * @param {string[]} [options.extraFlags]
 */
export async function launchBrowser({ browser, port, profile, extraFlags = [] }) {
  const child = spawn(browser, browserFlags(profile, port, extraFlags), {
    stdio: "ignore",
  });

  const page = await waitForEndpoint(port);
  const socket = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("WebSocket failed")), {
      once: true,
    });
  });

  const cdp = new Cdp(socket);
  return {
    cdp,
    evaluate: (expression) => cdp.evaluate(expression),
    close() {
      try {
        socket.close();
      } catch {
        // Already closed; nothing to do.
      }
      child.kill();
    },
  };
}
