# Review Findings — 2026-10-28

Findings from a whole-solution review of the plugin at v0.1.0-beta.9 (commit 2561fee). Each
item is verified against the source. The dependency-bump findings from the same review
were resolved separately (bump reverted, `windows-future` pin documented) and are not
repeated here.

Severity: **H** = wrong result or security-relevant; **M** = wrong error/behaviour in a
reachable path; **L** = contract drift, diagnostics, docs.

## Android — `tauri-plugin-secure-element/android/src/main/java/SecureKeysPlugin.kt`

- **A1 (H) Concurrent auth prompts are cross-wired.** Each `BiometricPrompt(...)`
  construction replaces the single callback androidx stores per Activity, and a second
  `authenticate` while a prompt is showing does not open a new prompt. A superseded
  `signWithKey(A)` leaves A's prompt on screen; on approval, B's callback receives A's
  `CryptoObject` and signs B's data with key A. A pending sign prompt can likewise
  satisfy a later `deleteKey(requireAuth)`. (sign: ~L925–1045; delete: ~L1140–1193)
- **A2 (M) `biometricOnly` keys are prompted with DEVICE_CREDENTIAL allowed.**
  `buildPromptInfo` (L415) always sets BIOMETRIC_STRONG|DEVICE_CREDENTIAL; a successful
  PIN entry then fails in `performSign` and surfaces as `authFailed`.
- **A3 (M) Invoke hangs when the prompt silently refuses to start.** androidx returns
  without any callback when the FragmentManager has saved state or the activity is gone;
  the plugin never checks, so the JS promise never settles. (L1034, L1186)
- **A4 (L) `backing` under-reports StrongBox on API 30.** `backingOf` (L553–590) only
  reads `securityLevel` on API ≥ 31; on API 30 a StrongBox key reports `integrated`.
- **A5 (L) StrongBox fallback catches every `Exception`** (L783), masking real errors.
- **A6 (L) `ERROR_HW_NOT_PRESENT`/`ERROR_HW_UNAVAILABLE` map to `deviceNotSecure`**
  (L283–284); `unsupported` is the documented code for missing hardware.
- **A7 (L) Release logs interpolate key names and full exceptions** unconditionally
  (L388, 402, 564, 587, 838, 851, 1087, 1094).
- **A8 (L) `none` keys sign while the device is locked** (no `setUnlockedDeviceRequired`),
  unlike Apple's `WhenUnlockedThisDeviceOnly`. Resolve by documenting the divergence.

## Windows — `tauri-plugin-secure-element/src/windows.rs`, `windows_hello.rs`, `desktop.rs`

- **W1 (M) TPM key namespace is not injective.** `tpm_key_name` (L152) is
  `tauri_se_tpm_{esc(app)}_{key}`; `_` is a legal key character, so app `com.example`
  with key `x2Eapp_mykey` is the same NCrypt name as app `com.example.app` with key
  `mykey`. NGC names use `/` and are safe.
- **W2 (M) `try_open_key_auto` swallows SID / NGC-provider failures** with `if let Ok`
  (L464–466), so "could not look" becomes "not found" and `deleteKey` reports success
  without deleting.
- **W3 (M) `NTE_PERM` is folded into "not found" in `try_open_key`** (L554) although the
  module documents it as "exists but inaccessible" (L35–39, L622–628) and
  `key_present_in_provider` (L629) already resolves it by enumeration for create.
- **W4 (M) `NCRYPT_USE_CONTEXT_PROPERTY` value is not NUL-terminated** (L1065–1068); the
  API documents a null-terminated Unicode string.
- **W5 (L) Every non-`Verified` consent result becomes `userCancelled`**
  (`windows_hello.rs` L66, `desktop.rs` L654–659): RetriesExhausted, NotConfiguredForUser,
  DisabledByPolicy, DeviceNotPresent are all misreported.
- **W6 (L) `NTE_EXISTS` from `NCryptCreatePersistedKey` is unclassified**, so the create
  race yields `internal` instead of `keyAlreadyExists`.
- **W7 (L) `is_windows_hello_configured` turns an API error into "not configured"**
  (`windows_hello.rs` L14), reported as `deviceNotSecure` instead of `internal`.
- Windows code cannot be compiled on the macOS dev machine; only CI's `rust-windows`
  job exercises it.

## Apple — `tauri-plugin-secure-element/swift/SecureEnclaveCore.swift`, `secure_element_ffi.swift`, `build.rs`

- **S1 (M) Duplicate keys under concurrent generate on macOS.** `generateSecureKey`
  (L449–500) is check-then-create; the application tag is not part of the keychain
  primary key. Two concurrent calls both succeed. `deleteKeyMatchingPublicKey` (L773)
  then deletes by *name query*, removing every duplicate. iOS is unaffected (Tauri
  serializes plugin calls there).
- **S2 (L) `#if DEBUG` is never true on macOS** because `build.rs` (L127–141) passes no
  `-D DEBUG`; debug builds get generic error text.
- **S3 (L) Rosetta misreports the backing tier**: `detectMacSecureElementType` (L790) is
  compile-time `#if arch(arm64)`, so an x86_64 build on Apple Silicon reports T2/`discrete`.
- **S4 (L) Biometry lockout maps to `deviceNotSecure`** for `biometricOnly` generate
  (L395, L440); `authFailed` is the documented code.
- **S5 (L) Locked keychain during generate/list/delete-by-public-key yields `internal`**
  (L455, L569, L750); `signWithKey` (L595) already maps `errSecInteractionNotAllowed` to
  `keyNotAccessible`.
- **S6 (L) Empty C strings weaken the FFI contract**: `fromCString` (ffi L95) maps `""`
  to `nil`, so an empty `authReason` disables the delete auth gate and an empty
  `authMode` becomes the default instead of failing closed.
- **S7 (L) `Package.swift` declares `.macOS(.v10_13)`** while the core imports CryptoKit
  (10.15+).

## Rust core — `tauri-plugin-secure-element/src/desktop.rs`

- **R1 (L) Delete auth fails open on a NUL in `reason`.** On macOS (L596–600) a reason that
  cannot become a `CString` becomes a null pointer, which Swift reads as "no auth".
  Validation prevents this today; the path should fail closed regardless.
- **R2 (L) macOS `sign_with_key` and `delete_key` parse FFI JSON directly** (L518, L608)
  and skip the 1 MB cap `parse_ffi_response` applies elsewhere.

## Docs

- **D1** README Node.js verification example throws on Node 24 (`format: "raw"` is not a
  valid key format). A JWK import verified against the recorded vectors works.
- **D2** README "Hardware Backing Tiers" table omits the `software` tier.
- **D3** README security model does not mention that Android `none` keys sign while
  locked (A8).
- **D4** README/CHANGELOG must record the Windows TPM key-name change from W1.
