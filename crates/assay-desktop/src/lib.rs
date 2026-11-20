//! Desktop shell for Assay.
//!
//! This crate is deliberately thin: it owns the window, the file dialog and the
//! drag-and-drop plumbing, and nothing else. All analysis lives in
//! `assay-core`, so the UI and the CLI can never drift into producing different
//! verdicts for the same file — a property that matters more than it sounds,
//! because a workbench that disagrees with the CI gate is a workbench nobody
//! trusts.
//!
//! ## Threading
//!
//! `#[tauri::command]` handlers run on a worker thread pool, not the UI thread,
//! so a 400 MB installer will not freeze the window. Analyses are also
//! independent and read-only, which means the front end can dispatch several at
//! once without any locking here.

use std::path::{Path, PathBuf};

// Aliased: the Tauri command below is also called `analyze_path`, and without the
// rename the recursive call would silently resolve to the command itself.
use assay_core::{analyze_path as run_analysis, AnalyzeOptions, Report};

/// Extensions offered in the file dialog. Not exhaustive by design — the
/// dialog also accepts "All files", because the point of a static analyser is to
/// be pointed at things that lie about their extension.
const KNOWN_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "scr", "cpl", "ocx", "efi", "msi", "cab", "lib", "obj", "pdb", "elf",
    "so", "o", "a", "ko", "dylib", "dylib", "app", "bundle", "macho", "bin", "zip", "jar", "apk",
    "whl", "nupkg", "vsix", "aar", "tar", "gz", "tgz", "xz", "deb", "rpm", "pkg", "dmg", "iso",
    "img", "ps1", "sh", "bat", "cmd", "py", "js",
];

/// Analyse one artefact.
///
/// Errors are stringified because Tauri's IPC boundary only carries
/// serialisable payloads; the front end wraps them into `EngineError`.
#[tauri::command]
async fn analyze_path(path: String) -> Result<Report, String> {
    let options = AnalyzeOptions::default();
    tauri::async_runtime::spawn_blocking(move || {
        run_analysis(Path::new(&path), &options).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| format!("analysis task failed: {error}"))?
}

/// Open a native multi-select dialog and return the chosen paths.
///
/// Uses the callback form and bridges it through a channel so the command can
/// await without blocking the UI thread. A cancelled dialog yields an empty
/// list rather than an error — cancelling is a normal thing to do.
#[tauri::command]
async fn pick_files(app: tauri::AppHandle) -> Result<Vec<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let (sender, receiver) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .set_title("Select artefacts to analyse")
        .add_filter("Executables and packages", KNOWN_EXTENSIONS)
        .add_filter("All files", &["*"])
        .pick_files(move |selection| {
            let _ = sender.send(selection);
        });

    let selection = receiver
        .recv()
        .map_err(|error| format!("file dialog closed unexpectedly: {error}"))?;

    Ok(selection
        .unwrap_or_default()
        .into_iter()
        .filter_map(|entry| entry.into_path().ok())
        .map(path_to_string)
        .collect())
}

/// Reveal a file in the platform file manager.
///
/// Split into one function per platform rather than one function with `cfg`
/// blocks and mid-body `return`s: each platform's invocation differs in a way
/// that matters (Explorer needs `/select,<path>` as a single argument, Finder
/// uses `-R`, Linux has no reveal verb at all), and a reader should see exactly
/// one of them at a time.
#[tauri::command]
fn reveal_in_folder(path: String) -> Result<(), String> {
    reveal(Path::new(&path))
}

#[cfg(target_os = "windows")]
fn reveal(target: &Path) -> Result<(), String> {
    // `/select,` and the path must be one argument; splitting them makes
    // Explorer open the parent folder and select nothing.
    std::process::Command::new("explorer")
        .arg(format!("/select,{}", target.display()))
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("cannot launch Explorer: {error}"))
}

#[cfg(target_os = "macos")]
fn reveal(target: &Path) -> Result<(), String> {
    std::process::Command::new("open")
        .arg("-R")
        .arg(target)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("cannot launch Finder: {error}"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn reveal(target: &Path) -> Result<(), String> {
    // No portable "reveal" verb on Linux; open the containing directory.
    let directory = target.parent().unwrap_or(target);
    std::process::Command::new("xdg-open")
        .arg(directory)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("cannot launch the file manager: {error}"))
}

fn path_to_string(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

/// Entry point used by the desktop binary and by mobile targets.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            analyze_path,
            pick_files,
            reveal_in_folder
        ])
        .run(tauri::generate_context!())
        .expect("failed to start the Assay desktop shell");
}
