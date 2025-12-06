const COMMANDS: &[&str] = &["ping"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        // Note: macOS desktop implementation is in src/desktop/macos.rs (Rust-based)
        // The Swift code in macos/ directory is available but not currently integrated
        .build();
}
