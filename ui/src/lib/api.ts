/**
 * The single boundary between the UI and the analysis engine.
 *
 * Two transports exist:
 *
 * * **Desktop** — Tauri `invoke` calls into `assay-desktop`, which runs the same
 *   `assay-core` pipeline the CLI uses. Paths come from the native file dialog
 *   or a drag-and-drop event.
 * * **Browser** — no filesystem access is possible, so the UI runs in *demo
 *   mode* against a report generated from a synthetic sample. This keeps the
 *   interface reviewable and developable without a Rust build, and the mode is
 *   surfaced in the header rather than silently faked.
 */

import type { Report } from "../types";
import demoReport from "./demo-report.json";

type TauriInvoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

function tauriInvoke(): TauriInvoke | null {
  if (typeof window === "undefined") return null;
  const g = window as unknown as { __TAURI_INTERNALS__?: { invoke?: TauriInvoke } };
  const fn = g.__TAURI_INTERNALS__?.invoke;
  return typeof fn === "function" ? fn : null;
}

/** True when the page is hosted inside the native shell. */
export function isDesktop(): boolean {
  return tauriInvoke() !== null;
}

export class EngineError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "EngineError";
  }
}

/**
 * Analyse one file by absolute path.
 *
 * Errors from Rust arrive as plain strings; they are wrapped so the UI can show
 * a consistent message without caring which side failed.
 */
export async function analyzePath(path: string): Promise<Report> {
  const invoke = tauriInvoke();
  if (!invoke) {
    throw new EngineError(
      "File analysis needs the desktop shell. This browser preview can only show the bundled demo sample.",
    );
  }
  try {
    return await invoke<Report>("analyze_path", { path });
  } catch (error) {
    const message = typeof error === "string" ? error : String(error);
    throw new EngineError(message, error);
  }
}

/** The bundled demo report, structurally identical to a live one. */
export function demo(): Report {
  return demoReport as unknown as Report;
}

/** Open the native multi-select dialog. Returns `[]` when cancelled. */
export async function pickFiles(): Promise<string[]> {
  const invoke = tauriInvoke();
  if (!invoke) {
    throw new EngineError("The file picker is only available in the desktop shell.");
  }
  try {
    return await invoke<string[]>("pick_files", {});
  } catch (error) {
    // A cancelled dialog is not an error worth surfacing.
    const message = typeof error === "string" ? error : String(error);
    if (!message || message === "null") return [];
    throw new EngineError(message, error);
  }
}

/**
 * Register a drag-and-drop handler.
 *
 * Returns an unsubscribe function. In a browser this is a no-op that returns a
 * no-op, so callers never need to branch.
 */
export function onFileDrop(handler: (paths: string[]) => void): () => void {
  if (!isDesktop()) {
    return () => undefined;
  }

  const globals = window as unknown as {
    __TAURI__?: {
      webview?: {
        getCurrentWebview: () => {
          onDragDropEvent: (
            cb: (event: { payload: { type: string; paths?: string[] } }) => void,
          ) => Promise<() => void>;
        };
      };
    };
  };

  // Tauri injects `__TAURI__` only when `withGlobalTauri` is enabled; fall back
  // to the module import path when it is not.
  let disposed = false;
  let unlisten: (() => void) | null = null;

  void (async () => {
    try {
      const api = globals.__TAURI__?.webview?.getCurrentWebview
        ? globals.__TAURI__.webview
        : await import("@tauri-apps/api/webview").then((m) => ({
            getCurrentWebview: m.getCurrentWebview,
          }));
      const stop = await api.getCurrentWebview().onDragDropEvent((event) => {
        if (event.payload.type === "drop" && event.payload.paths?.length) {
          handler(event.payload.paths);
        }
      });
      if (disposed) stop();
      else unlisten = stop;
    } catch {
      // Drag-and-drop is an enhancement; its absence must not break the app.
    }
  })();

  return () => {
    disposed = true;
    unlisten?.();
  };
}

/** Reveal a file in the OS file manager. No-op outside the desktop shell. */
export async function revealInFolder(path: string): Promise<void> {
  const invoke = tauriInvoke();
  if (!invoke) return;
  try {
    await invoke<void>("reveal_in_folder", { path });
  } catch {
    // Best effort: failing to open a file manager is not worth an error dialog.
  }
}
