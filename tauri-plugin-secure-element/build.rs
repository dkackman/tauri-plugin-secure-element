const COMMANDS: &[&str] = &["ping"];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();

    // Compile Swift code for macOS
    #[cfg(target_os = "macos")]
    {
        use std::path::PathBuf;
        use std::process::Command;

        let swift_file = PathBuf::from("swift/secure_element.swift");
        if !swift_file.exists() {
            return;
        }

        // Tell Cargo to rerun this build script if the Swift file changes
        println!("cargo:rerun-if-changed={}", swift_file.display());

        let out_dir = std::env::var("OUT_DIR").unwrap();

        // Get macOS SDK path
        let sdk_output = Command::new("xcrun")
            .args(["--show-sdk-path", "--sdk", "macosx"])
            .output();

        let sdk_path = match sdk_output {
            Ok(output) => {
                let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if path.is_empty() {
                    println!("cargo:warning=Failed to get macOS SDK path");
                    return;
                }
                path
            }
            Err(e) => {
                println!("cargo:warning=Failed to run xcrun: {}", e);
                return;
            }
        };

        // Compile Swift file to object file
        let object_file = format!("{}/secure_element.o", out_dir);
        let swift_status = Command::new("swiftc")
            .args([
                "-c",
                swift_file.to_str().unwrap(),
                "-o",
                object_file.as_str(),
                "-target",
                "arm64-apple-macosx11.0",
                "-sdk",
                sdk_path.as_str(),
            ])
            .output();

        match swift_status {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    println!("cargo:warning=Swift compilation failed: {}", stderr);
                    return;
                }
            }
            Err(e) => {
                println!("cargo:warning=Failed to run swiftc: {}", e);
                return;
            }
        }

        // Create static library from object file
        let lib_path = format!("{}/libsecure_element.a", out_dir);
        let ar_status = Command::new("ar")
            .args(["rcs", lib_path.as_str(), object_file.as_str()])
            .output();

        if let Ok(output) = ar_status {
            if output.status.success() {
                // Get Swift toolchain path for compatibility libraries
                let toolchain_swift_lib = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/macosx";

                // Tell cargo to link the library
                println!("cargo:rustc-link-search=native={}", out_dir);
                println!("cargo:rustc-link-search=native={}", toolchain_swift_lib);
                println!("cargo:rustc-link-lib=static=secure_element");
                println!("cargo:rustc-link-lib=framework=Security");
                println!("cargo:rustc-link-lib=framework=Foundation");
                // Link Swift compatibility libraries
                println!("cargo:rustc-link-lib=static=swiftCompatibility56");
                println!("cargo:rustc-link-lib=static=swiftCompatibilityConcurrency");
            }
        }
    }
}
