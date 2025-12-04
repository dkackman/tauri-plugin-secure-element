// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    eprintln!("[MAIN] Initializing Tauri app...");
    eprintln!("[MAIN] Registering tauri-plugin-secure-element...");
    tauri::Builder::default()
        .plugin(tauri_plugin_secure_element::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}