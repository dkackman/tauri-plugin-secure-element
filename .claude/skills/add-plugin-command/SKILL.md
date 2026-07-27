---
name: add-plugin-command
description: Use when adding a new command to the secure element Tauri plugin - lists every layer (Rust command, mobile/desktop interfaces, per-platform Swift/Kotlin/Windows implementations, JS binding) that must be touched so none is missed.
---

# Adding a new plugin command

A command is not complete until every layer below has it. Missing one usually shows up as a runtime "command not found" on a single platform.

1. Define the command in `tauri-plugin-secure-element/src/commands.rs`
2. Add the mobile interface in `src/mobile.rs` (iOS/Android)
3. Add the desktop implementation in `src/desktop.rs` (macOS/Windows)
4. Implement the platform-specific code:
   - iOS: `ios/Sources/Plugin.swift` and `swift/SecureEnclaveCore.swift`
   - Android: `android/src/main/java/SecureKeysPlugin.kt`
   - macOS: `swift/SecureEnclaveCore.swift` (via the FFI bindings in `swift/secure_element_ffi.swift`)
   - Windows: `src/windows.rs`
5. Export the JavaScript API in `guest-js/index.ts`
6. Rebuild the bindings: `cd tauri-plugin-secure-element && pnpm build`

Then verify on a real device — simulators and emulators lack the hardware security modules these commands depend on:

```bash
cd test-app && pnpm tauri [ios|android] dev
```
