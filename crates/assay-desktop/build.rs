//! Build script for the Tauri shell.
//!
//! Two jobs: hand the configuration to `tauri-build`, and refuse to produce a
//! binary that would open an empty window.

use std::path::Path;

fn main() {
    // `frontendDist` points at `ui/dist`, which is produced by `npm run build`
    // and is deliberately not committed. Tauri compiles without it and embeds a
    // path to nothing, so the failure surfaces at launch as a blank window with
    // no message — the least debuggable outcome available. Failing here instead
    // costs the reader one line and names the command to run.
    let dist = Path::new("../../ui/dist/index.html");
    if !dist.exists() {
        panic!(
            "\n\n  ui/dist/index.html is missing, so the desktop shell would open an \
             empty window.\n  Build the front end first:\n\n      npm --prefix ui install\n      \
             npm --prefix ui run build\n\n  (or run `make desktop`, which does both.)\n"
        );
    }

    // Re-run only when the bundle or this script changes; without this cargo
    // caches the panic and reports the same stale failure forever.
    println!("cargo:rerun-if-changed=../../ui/dist/index.html");
    println!("cargo:rerun-if-changed=build.rs");

    tauri_build::build()
}
