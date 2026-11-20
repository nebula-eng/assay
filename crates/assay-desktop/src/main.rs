//! Desktop binary entry point.
//!
//! All behaviour lives in the library so that the same code can be reused by
//! the mobile targets Tauri generates, where `main` is provided by the harness.

// Release builds should not open a console window behind the app.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    assay_desktop::run();
}
