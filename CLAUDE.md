# Tauri Plugin Secure Element

A Tauri plugin providing secure element functionality for iOS, Android, macOS, and Windows platforms.

This is a **pnpm workspace monorepo**: the main plugin lives in `tauri-plugin-secure-element/` and an example app in `test-app/`.

## Development Workflow

### Prerequisites

Beyond Rust/Node/pnpm/Tauri CLI, the non-obvious platform tooling:

- iOS: Xcode, swiftformat, swiftlint
- Android: Android Studio, Android SDK, ktlint (installed via pnpm)
- macOS: Xcode (for Secure Enclave FFI), provisioning profile (see docs/)
- Windows: Visual Studio Build Tools, Windows SDK (for Windows Hello/TPM)

### Building

The build order matters due to dependencies:

1. **Build plugin JavaScript bindings**:

   ```bash
   cd tauri-plugin-secure-element
   pnpm build
   ```

   This compiles TypeScript to `dist-js/`

2. **Build test app** (automatically builds plugin first):

   ```bash
   cd test-app
   pnpm build
   ```

3. **Build everything** (from root):

   ```bash
   pnpm build
   ```

Or use the VS Code task `build-all` which builds in the correct sequence.

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

Note: The `predev` script automatically builds the plugin before running.

**macOS Note:** Secure Enclave access on macOS requires a provisioning profile and special code signing. See `docs/macos-development.md` for setup instructions.

**Windows Note:** Windows Hello integration requires a TPM 2.0 compatible device and Windows 10 version 1607 (build 14393) or higher. Minimum requirement for reliable TPM 2.0 support.

### Code Quality

Format/lint scripts live in the root `package.json` (`pnpm format`, `pnpm lint`, plus per-language `:js`/`:rust`/`:swift`/`:kotlin` variants). Swift needs swiftformat/swiftlint; Kotlin uses ktlint.

### Important Files

**Rust Core:**

- `tauri-plugin-secure-element/src/lib.rs` - Main plugin entry point
- `tauri-plugin-secure-element/src/commands.rs` - Tauri command implementations
- `tauri-plugin-secure-element/src/models.rs` - Data models and types
- `tauri-plugin-secure-element/src/error.rs` - Plugin `Error` enum and `Result<T>` type alias
- `tauri-plugin-secure-element/src/error_sanitize.rs` - Returns detailed errors in debug builds, generic messages in release (avoids leaking sensitive info)
- `tauri-plugin-secure-element/src/validation.rs` - Input validation for key names, sign data size, and public key filters
- `tauri-plugin-secure-element/src/mobile.rs` - Mobile platform interface
- `tauri-plugin-secure-element/src/desktop.rs` - Desktop platform implementation (macOS/Windows)
- `tauri-plugin-secure-element/src/windows.rs` - Core Windows NCrypt/TPM implementation: key creation, signing, export, enumeration
- `tauri-plugin-secure-element/src/windows_hello.rs` - Windows Hello availability check via `UserConsentVerifier` WinRT API
- `tauri-plugin-secure-element/src/windows_raii.rs` - RAII wrappers for NCrypt handles (`ProviderHandle`, `KeyHandle`, `EnumStateGuard`, `KeyNameBufferGuard`)
- `tauri-plugin-secure-element/src/der.rs` - Converts raw ECDSA R||S signatures (from NCrypt) to DER format for cross-platform compatibility
- `tauri-plugin-secure-element/guest-js/index.ts` - JavaScript API

**Platform Implementations:**

- `tauri-plugin-secure-element/swift/SecureEnclaveCore.swift` - Shared Secure Enclave logic (iOS/macOS)
- `tauri-plugin-secure-element/swift/secure_element_ffi.swift` - Swift FFI bindings for macOS
- `tauri-plugin-secure-element/ios/Sources/Plugin.swift` - iOS Tauri plugin wrapper
- `tauri-plugin-secure-element/android/src/main/java/SecureKeysPlugin.kt` - Android Keystore implementation

## Debugging

Use the VS Code launch configurations defined in `.vscode/launch.json` for debugging:

- **Launch Tauri App (Debug)** - Launch with LLDB debugger attached
- **Attach to Tauri App** - Attach debugger to running process
- **Launch Tauri App (Tauri Dev)** - Run `pnpm tauri dev` in terminal
- **Launch Tauri App (Full Debug)** - Combined launch with debugger

View Android logs: `./adb-logs.sh`

## Common Tasks

### Adding a new plugin command

1. Define the command in `tauri-plugin-secure-element/src/commands.rs`
2. Add mobile interface in `src/mobile.rs` (for iOS/Android)
3. Add desktop implementation in `src/desktop.rs` (for macOS/Windows)
4. Implement platform-specific code:
   - iOS: `ios/Sources/Plugin.swift` and `swift/SecureEnclaveCore.swift`
   - Android: `android/src/main/java/SecureKeysPlugin.kt`
   - macOS: `swift/SecureEnclaveCore.swift` (via FFI)
   - Windows: `src/windows.rs`
5. Export JavaScript API in `guest-js/index.ts`
6. Rebuild: `cd tauri-plugin-secure-element && pnpm build`

### Testing changes

1. Build the plugin: `cd tauri-plugin-secure-element && pnpm build`
2. Run test app: `cd test-app && pnpm tauri [ios|android] dev`

### Before committing

```bash
# From root
pnpm format              # Format all code
pnpm lint                # Ensure all lints pass
pnpm build               # Ensure everything builds
```

## Platform Support

- **iOS**: Uses Secure Enclave via Swift (Tauri mobile plugin)
- **Android**: Uses Android StrongBox/TEE Keystore via Kotlin (Tauri mobile plugin)
- **macOS**: Uses Secure Enclave via Swift FFI bindings (requires provisioning profile setup)
- **Windows**: Uses Windows Hello with TPM 2.0 for key storage and biometric/PIN authentication

## Notes

- The test app's prebuild/predev scripts ensure the plugin is built before running
- Swift tooling (swiftformat, swiftlint) is optional but recommended for iOS/macOS development
- Kotlin formatting uses ktlint (installed via pnpm)
- All commands should be run from the appropriate directory (root, plugin, or test-app)
- Secure element features require physical devices - simulators/emulators lack hardware security modules
- Run `pnpm test` from root to run all tests, or `pnpm test:rust` for Rust unit tests only
