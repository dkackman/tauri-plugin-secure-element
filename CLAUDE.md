# Tauri Plugin Secure Element

A Tauri plugin providing secure element functionality for iOS, Android, macOS, and Windows platforms.

This is a **pnpm workspace monorepo**: the main plugin lives in `tauri-plugin-secure-element/` and an example app in `test-app/`.

## Development Workflow

### Prerequisites

Beyond Rust/Node/pnpm/Tauri CLI, the non-obvious platform tooling:

- iOS: Xcode, swiftformat, swiftlint
- Android: Android Studio, Android SDK, ktlint — do not install it yourself. The lint
  scripts run `pnpm exec ktlint`, which resolves the pinned `@naturalcycles/ktlint`,
  and `android/build.gradle.kts` hands the ktlint Gradle plugin that same version. A
  `ktlint` on `PATH` from Homebrew or `~/.ktlint` is a different version that will
  disagree with CI about the same files; if you bump one, bump all three.
- macOS: Xcode (for Secure Enclave FFI), provisioning profile (see docs/)
- Windows: Visual Studio Build Tools, Windows SDK (for Windows Hello/TPM)

### Building

Build order matters: the plugin's TypeScript bindings (`dist-js/`) must exist before the test app builds. The test app's `prebuild`/`predev` scripts handle this automatically; `pnpm build` from the root does it in dependency order.

To run anything Gradle in `tauri-plugin-secure-element/android` — `./gradlew test`, `ktlintCheck` — `android/.tauri/tauri-api` has to exist. It is the `:tauri-android` project `settings.gradle` includes: a copy of the tauri crate's own `mobile/android` library that the Tauri CLI drops there while building an app for Android. It is gitignored and no build step in this repository creates it, so on a fresh checkout Gradle fails with "No matching variant of project :tauri-android ... No variants exist". Run `scripts/materialize-tauri-android.sh` (what CI does) to copy it from the crate source cargo has already downloaded.

### Running the Test App

```bash
cd test-app

# iOS
pnpm tauri ios dev

# Android
pnpm tauri android dev

# macOS (requires special setup - see docs/macos-development.md)
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/test-app.app

# Windows
pnpm tauri dev
```

**macOS Note:** Secure Enclave access on macOS requires a provisioning profile and special code signing. See `docs/macos-development.md` for setup instructions.

**Windows Note:** Windows Hello integration requires a TPM 2.0 compatible device and Windows 10 version 1607 (build 14393) or higher. Minimum requirement for reliable TPM 2.0 support.

### Non-obvious source files

Most of the tree is self-explanatory; these three are not:

- `src/error_sanitize.rs` - returns detailed errors in debug builds and generic messages in release, so failures don't leak sensitive information
- `src/der.rs` - converts the raw ECDSA R||S signatures NCrypt produces into DER, so Windows signatures match the other platforms
- `src/windows_raii.rs` - RAII wrappers for NCrypt handles; Windows code must go through these rather than raw handles

## Debugging

Use the VS Code launch configurations in `.vscode/launch.json`. View Android logs: `./adb-logs.sh`

## Common Tasks

### Before committing

```bash
# From root
pnpm format              # Format all code
pnpm lint                # Ensure all lints pass
pnpm build               # Ensure everything builds
```

## Notes

- Swift tooling (swiftformat, swiftlint) is optional but recommended for iOS/macOS development
- Secure element features require physical devices - simulators/emulators lack hardware security modules
