# Tauri Plugin Secure Element

A Tauri plugin providing secure element functionality for iOS, Android, macOS, and Windows platforms.

## Project Structure

This is a **pnpm workspace monorepo** with the following structure:

```bash
tauri-plugin-secure-element/          # Root monorepo
├── tauri-plugin-secure-element/      # Main plugin code
│   ├── src/                          # Rust plugin implementation
│   ├── guest-js/                     # TypeScript guest bindings
│   ├── swift/                        # Shared Swift code (Secure Enclave, FFI)
│   ├── ios/                          # Swift iOS plugin wrapper
│   ├── android/                      # Kotlin implementation
│   ├── permissions/                  # Plugin permissions
│   └── dist-js/                      # Built JavaScript bindings (generated)
├── test-app/                         # Example Tauri application
│   ├── src/                          # Svelte frontend
│   └── src-tauri/                    # Tauri backend
└── docs/                             # Additional documentation
```

## Tech Stack

- **Rust**: Plugin backend (v1.77.2+)
- **TypeScript**: Guest JavaScript API
- **Swift**: iOS implementation
- **Kotlin**: Android implementation
- **Svelte**: Test app UI
- **Tauri**: v2.x framework
- **pnpm**: Package manager

## Development Workflow

### Prerequisites

Ensure these are installed before starting:

- Rust (latest stable)
- Node.js 20.19+ or 22.12+
- pnpm
- Tauri CLI (via pnpm)
- Platform-specific dependencies:
  - iOS: Xcode, swiftformat, swiftlint
  - Android: Android Studio, Android SDK, ktlint (installed via pnpm)
  - macOS: Xcode (for Secure Enclave FFI), provisioning profile (see docs/)
  - Windows: Visual Studio Build Tools, Windows SDK (for Windows Hello/TPM)

### Setup

```bash
# Install all dependencies
pnpm install
```

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

**Windows Note:** Windows Hello integration requires a TPM 2.0 compatible device and Windows 10/11. On Windows, run `setup-msvc-env.ps1` from the repo root if you encounter build issues with the Windows SDK.

### Code Quality

All code quality scripts can be run from the root or individual packages:

**Formatting**:

```bash
pnpm format              # Format all code (Rust, JS, Swift, Kotlin)
pnpm format:check        # Check formatting without changes
pnpm format:js           # Format JavaScript/TypeScript only
pnpm format:rust         # Format Rust only
pnpm format:swift        # Format Swift only (requires swiftformat)
pnpm format:kotlin       # Format Kotlin only
```

**Linting**:

```bash
pnpm lint                # Lint all code
pnpm lint:js             # Lint JavaScript/TypeScript only
pnpm lint:rust           # Lint Rust only (cargo clippy)
pnpm lint:swift          # Lint Swift only (requires swiftlint)
pnpm lint:kotlin         # Lint Kotlin only
```

### Important Files

**Rust Core:**

- `tauri-plugin-secure-element/src/lib.rs` - Main plugin entry point
- `tauri-plugin-secure-element/src/commands.rs` - Tauri command implementations
- `tauri-plugin-secure-element/src/models.rs` - Data models and types
- `tauri-plugin-secure-element/src/mobile.rs` - Mobile platform interface
- `tauri-plugin-secure-element/src/desktop.rs` - Desktop platform implementation (macOS/Windows)
- `tauri-plugin-secure-element/src/windows.rs` - Windows Hello/TPM implementation
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

## Dependencies

**Main plugin (Rust)**:

- `tauri` 2.9.4
- `serde` / `serde_json` 1.0
- `thiserror` 2
- `rand` 0.8
- `hex` 0.4
- `base64` 0.22
- `sha2` 0.10
- Platform-specific: `libc` (macOS), `windows` + `winver` (Windows)

**Guest JS**:

- `@tauri-apps/api` ^2.0.0

**Test app**:

- Svelte 5
- Vite 7
- Tauri CLI 2

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
