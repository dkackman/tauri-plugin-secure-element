# Tauri Plugin Secure Element

A Tauri plugin providing secure element functionality for iOS and Android platforms.

## Project Structure

This is a **pnpm workspace monorepo** with the following structure:

```
tauri-plugin-secure-element/          # Root monorepo
├── tauri-plugin-secure-element/      # Main plugin code
│   ├── src/                          # Rust plugin implementation
│   ├── guest-js/                     # TypeScript guest bindings
│   ├── ios/                          # Swift implementation
│   ├── android/                      # Kotlin implementation
│   ├── permissions/                  # Plugin permissions
│   └── dist-js/                      # Built JavaScript bindings (generated)
└── test-app/                         # Example Tauri application
    ├── src/                          # Svelte frontend
    └── src-tauri/                    # Tauri backend
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
```

Note: The `predev` script automatically builds the plugin before running.

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

- `tauri-plugin-secure-element/src/lib.rs` - Main Rust plugin entry point
- `tauri-plugin-secure-element/src/commands.rs` - Tauri command implementations
- `tauri-plugin-secure-element/src/mobile.rs` - Mobile platform interface
- `tauri-plugin-secure-element/src/desktop.rs` - Desktop platform stub
- `tauri-plugin-secure-element/guest-js/index.ts` - JavaScript API
- `tauri-plugin-secure-element/ios/` - Swift iOS implementation
- `tauri-plugin-secure-element/android/` - Kotlin Android implementation

## Debugging

Use the VS Code launch configurations defined in `.vscode/launch.json` for debugging:
- Debug on iOS
- Debug on Android
- Debug test app

View Android logs: `./view-adb-logs.sh`

## Common Tasks

### Adding a new plugin command

1. Define the command in `tauri-plugin-secure-element/src/commands.rs`
2. Add mobile interface in `src/mobile.rs`
3. Implement platform-specific code:
   - iOS: `ios/Sources/`
   - Android: `android/src/`
4. Export JavaScript API in `guest-js/index.ts`
5. Rebuild: `cd tauri-plugin-secure-element && pnpm build`

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

**Main plugin**:
- `tauri` 2.9.4
- `serde` 1.0
- `thiserror` 2
- `rand` 0.8
- `hex` 0.4

**Guest JS**:
- `@tauri-apps/api` ^2.0.0

**Test app**:
- Svelte 5
- Vite 7
- Tauri CLI 2

## Platform Support

- iOS: Uses Secure Enclave via Swift
- Android: Uses Android Keystore via Kotlin
- Desktop: Currently stubbed (returns errors)

## Notes

- This is a **mobile-first** plugin; desktop platforms are not fully supported
- The test app's prebuild/predev scripts ensure the plugin is built before running
- Swift tooling (swiftformat, swiftlint) is optional but recommended for iOS development
- Kotlin formatting uses ktlint (installed via pnpm)
- All commands should be run from the appropriate directory (root, plugin, or test-app)
