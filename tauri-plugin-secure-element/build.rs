use std::env;
use std::path::PathBuf;
use std::process::Command;

const COMMANDS: &[&str] = &["ping"];

fn main() {
    // Build Swift library for macOS
    #[cfg(target_os = "macos")]
    build_swift_library();

    // Build Tauri plugin
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}

#[cfg(target_os = "macos")]
fn build_swift_library() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let macos_dir = manifest_dir.join("macos");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=macos/Sources/FFIBridge.swift");

    // Compile Swift to object file
    let swift_sources = vec![macos_dir.join("Sources/FFIBridge.swift")];

    let object_file = out_dir.join("FFIBridge.o");

    let mut cmd = Command::new("swiftc");
    cmd.arg("-c") // Compile only, don't link
        .arg("-parse-as-library") // Treat as library
        .arg("-module-name")
        .arg("SecureElementSwift")
        .arg("-emit-object")
        .arg("-o")
        .arg(&object_file);

    // Add source files
    for source in &swift_sources {
        cmd.arg(source);
    }

    // Add framework imports
    cmd.arg("-framework")
        .arg("Security")
        .arg("-framework")
        .arg("Foundation");

    println!("Running: {:?}", cmd);

    let status = cmd.status().expect("Failed to compile Swift code");

    if !status.success() {
        panic!("Swift compilation failed");
    }

    // Create static library from object file
    let lib_file = out_dir.join("libSecureElementSwift.a");

    let ar_status = Command::new("ar")
        .arg("rcs")
        .arg(&lib_file)
        .arg(&object_file)
        .status()
        .expect("Failed to create static library");

    if !ar_status.success() {
        panic!("Failed to create static library");
    }

    // Tell Cargo where to find the library
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=SecureElementSwift");

    // Link required system frameworks
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=Foundation");
}
