const COMMANDS: &[&str] = &["ping"];

fn main() {
    let mut builder = tauri_plugin::Builder::new(COMMANDS);

    builder = builder
        .android_path("android")
        .ios_path("ios");

    // macOS uses Swift implementation similar to iOS
    #[cfg(target_os = "macos")]
    {
        // Try to add macOS-specific path if the builder supports it
        // Otherwise, the ios_plugin_binding in desktop.rs will handle it
        builder = builder.ios_path("macos");
    }

    builder.build();
}
