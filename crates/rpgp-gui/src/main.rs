// Hide the console window on Windows release builds. rpgp targets Linux and
// macOS today, but the attribute is free and keeps a cross-compile honest.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! The binary is a wrapper: everything it does lives in the library beside it,
//! so the parts worth benchmarking can be reached from `benches/`.

fn main() -> std::process::ExitCode {
    rpgp_gui::run_app()
}
