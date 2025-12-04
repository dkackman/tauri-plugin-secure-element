const COMMANDS: &[&str] = &["ping", "generate_secure_key", "sign_data"];

fn main() {
  tauri_plugin::Builder::new(COMMANDS)
    .android_path("android")
    .ios_path("ios")
    .build();
}
