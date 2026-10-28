# Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every finding in the 2026-10-28 review spec across the Android, Windows, Apple and Rust-core layers, with each fix pinned by a host-runnable test wherever the logic can be made pure.

**Architecture:** Four independent tracks, one per layer, each touching disjoint files so they can run in parallel as separate subagents on separate branches. Where a platform's bug lives in logic that cannot run on the host (NCrypt, Keystore, Keychain), the fix extracts the decision into a pure helper that *can* run on the host and tests that; the platform call site becomes a thin caller. Track B (Windows) cannot be compiled on the macOS dev machine: its only verification is CI's `rust-windows` job, so that track pushes a branch and watches CI after every task.

**Tech Stack:** Rust 2021 (tauri 2.11, windows 0.62), Kotlin (androidx.biometric 1.1.0, JUnit 4 host tests via `./gradlew test`), Swift 5 (XCTest via `xcodebuild` on an iOS simulator), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-28-review-findings.md`

## Global Constraints

- Error codes are the API. Only these strings may be emitted: `userCancelled`, `authFailed`, `keyInvalidated`, `keyNotFound`, `keyAlreadyExists`, `keyNotAccessible`, `deviceNotSecure`, `unsupported`, `validation`, `internal` (`src/error.rs`).
- Wire shapes do not change: public key = base64 of 65-byte `04||X||Y`; signature = base64 DER; `signature`/`data` are base64 strings.
- Detailed error text only in debug builds (`error_sanitize.rs`, `BuildConfig.DEBUG`, `#if DEBUG`).
- Before every commit in a track: `pnpm format` and `pnpm lint` from the repo root must pass for that track's language (Rust: `cargo fmt --check`, `cargo clippy -- -D warnings`; Kotlin: `pnpm lint:kotlin`; Swift: `swiftformat --lint ios/ swift/` and `swiftlint lint`).
- Kotlin: do not install ktlint; the scripts resolve the pinned `@naturalcycles/ktlint`. `./gradlew test` needs `android/.tauri/tauri-api` (run `scripts/materialize-tauri-android.sh`) and a JDK ≤ 21 on `PATH` (JDK 25 fails with "Unsupported class file major version 69"; use `JAVA_HOME=$(/usr/libexec/java_home -v 17)` if installed). Preferred local runner: `act -j kotlin` from the repo root, which runs CI's `kotlin` job (ktlint + `./gradlew test`) in an Ubuntu container with the JDK 17 the workflow installs. `act` cannot run the `windows-latest` or `macos-latest` jobs.
- Windows track: nothing compiles locally. Verify with `git push -u origin <branch>` then `gh run watch` on the triggered CI run; the `rust-windows` job must be green before the task is done.
- Every track adds its lines under `## [Unreleased]` in `CHANGELOG.md`; expect trivial merge conflicts there.
- Branch names: `fix/android-auth-prompts`, `fix/windows-key-paths`, `fix/apple-generate-lock`, `fix/rust-core-ffi`. One PR per track.

## Review Focus

1. Two `signWithKey` invokes for different keys while a prompt is up on Android: the second must be rejected immediately and the first must still be signed with its own key. Pinned by Task A1's `AuthSlot` tests plus the `cryptoObject` identity check.
2. Android `deleteKey(requireAuth)` arriving after the app is backgrounded: the promise must settle (`userCancelled`), never hang. Pinned by Task A3's `promptCanBeShown` tests.
3. Windows key name `a_b` under app `x` versus key `b` under app `x_a` (and the `x2E` case from the spec): distinct NCrypt names, and listing under one app never shows the other's keys. Pinned by Task B1's injectivity and decode tests, which run on every host.
4. Windows: NGC provider unavailable while a TPM key exists: `signWithKey` and `deleteKey` must return an error, not "not found"/success. Pinned by Task B2 (code review on CI only; no host test possible).
5. macOS: two concurrent `generateSecureKey("k")`: exactly one succeeds, the other returns `keyAlreadyExists`; `listKeys` shows one entry. Pinned by Task C1's lock (verified by manual test-app run; no host test possible).

---

# Track A — Android

All tasks modify `tauri-plugin-secure-element/android/src/main/java/SecureKeysPlugin.kt` and test in `tauri-plugin-secure-element/android/src/test/java/PluginUnitTest.kt`. Run tests with `cd tauri-plugin-secure-element/android && ./gradlew test --no-daemon`.

### Task A1: Single in-flight authentication slot (spec A1)

**Files:**
- Create: `tauri-plugin-secure-element/android/src/main/java/AuthSlot.kt`
- Modify: `SecureKeysPlugin.kt` — `pendingSignInvoke` (L355), `signWithBiometricPrompt` (~L925–1045), the delete auth helper (~L1140–1193)
- Test: `PluginUnitTest.kt`

**Interfaces:**
- Produces: `internal class AuthSlot { fun tryAcquire(): Boolean; fun release() }` in package `net.kackman.secureelement`, backed by an `AtomicBoolean`.
- Plugin field: `private val authSlot = AuthSlot()`.

- [ ] **Step 1: Write the failing tests**

```kotlin
@Test fun `auth slot acquires once`() {
    val slot = AuthSlot()
    assertTrue(slot.tryAcquire())
    assertFalse(slot.tryAcquire())
}
@Test fun `auth slot can be reacquired after release`() {
    val slot = AuthSlot()
    assertTrue(slot.tryAcquire()); slot.release()
    assertTrue(slot.tryAcquire())
}
@Test fun `release without acquire is a no-op`() {
    val slot = AuthSlot(); slot.release()
    assertTrue(slot.tryAcquire())
}
```

- [ ] **Step 2: Run tests, expect FAIL** ("Unresolved reference: AuthSlot").
- [ ] **Step 3: Implement `AuthSlot`** in the new file.
- [ ] **Step 4: Wire it in.** In `signWithBiometricPrompt` and the delete-auth helper, before constructing `BiometricPrompt`: `if (!authSlot.tryAcquire()) { invoke.reject("Another authentication prompt is already in progress", ErrorCodes.INTERNAL); return }`. Call `authSlot.release()` on every terminal path (success, `onAuthenticationError`, synchronous `authenticate` throw, `initSign` failure). Remove the "superseded" rejection at L943 and the `pendingSignInvoke.getAndSet(invoke)` pattern; keep an `AtomicReference<Invoke?>` per call (as delete already does) for exactly-once settling.
- [ ] **Step 5: Verify the CryptoObject identity in sign's `onAuthenticationSucceeded`.** Capture `val signature = Signature.getInstance(...)` before creating the `CryptoObject`; in the callback, `if (result.cryptoObject?.signature !== signature) { pending.reject("Authentication result does not belong to this request", ErrorCodes.INTERNAL); return }`.
- [ ] **Step 6: Run tests, expect PASS.** Run `pnpm lint:kotlin` from `tauri-plugin-secure-element/`.
- [ ] **Step 7: Commit** `fix(android): serialize authentication prompts and verify CryptoObject identity`.

### Task A2: Prompt authenticators match the key's auth mode (spec A2)

**Files:**
- Modify: `SecureKeysPlugin.kt` — `buildPromptInfo` (L415), `signWithBiometricPrompt`
- Test: `PluginUnitTest.kt`

**Interfaces:**
- Produces (companion, `internal`): `fun allowedAuthenticatorsFor(userAuthenticationType: Int?): Int` — returns `BIOMETRIC_STRONG` when `userAuthenticationType == KeyProperties.AUTH_BIOMETRIC_STRONG`, else `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`. `null` (unknown / API 30) → both.
- `buildPromptInfo(subtitle: String, authenticators: Int)`: sets `setNegativeButtonText("Cancel")` iff `authenticators and DEVICE_CREDENTIAL == 0`.

- [ ] **Step 1: Write the failing tests**

```kotlin
@Test fun `biometric-only keys prompt with biometric only`() =
    assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG,
        SecureKeysPlugin.allowedAuthenticatorsFor(KeyProperties.AUTH_BIOMETRIC_STRONG))
@Test fun `mixed keys prompt with biometric or credential`() =
    assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL,
        SecureKeysPlugin.allowedAuthenticatorsFor(AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL))
@Test fun `unknown auth type prompts with both`() =
    assertEquals(BIOMETRIC_STRONG or DEVICE_CREDENTIAL, SecureKeysPlugin.allowedAuthenticatorsFor(null))
```

- [ ] **Step 2: Run tests, expect FAIL.**
- [ ] **Step 3: Implement** the helper and the `buildPromptInfo` overload. In `signWithBiometricPrompt`, read `keyInfo.userAuthenticationType` via `KeyFactory.getKeySpec(entry.privateKey, KeyInfo::class.java)` when `Build.VERSION.SDK_INT >= S`, else `null`. Delete keeps both authenticators.
- [ ] **Step 4: Run tests, expect PASS; lint.**
- [ ] **Step 5: Commit** `fix(android): prompt biometric-only keys without the device-credential option`.

### Task A3: Refuse to start a prompt that cannot call back (spec A3)

**Files:**
- Modify: `SecureKeysPlugin.kt` — before both `biometricPrompt.authenticate(...)` calls (L1034, L1186)
- Test: `PluginUnitTest.kt`

**Interfaces:**
- Produces (companion): `fun promptCanBeShown(isStateSaved: Boolean, isFinishing: Boolean, isDestroyed: Boolean): Boolean` — true only when all three are false.

- [ ] **Step 1: Tests**: four cases (all false → true; each flag true alone → false).
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement**; at both call sites: `if (!promptCanBeShown(fragmentActivity.supportFragmentManager.isStateSaved, fragmentActivity.isFinishing, fragmentActivity.isDestroyed)) { pending.getAndSet(null)?.reject("Authentication prompt cannot be shown while the app is not in the foreground", ErrorCodes.USER_CANCELLED); authSlot.release(); return }`.
- [ ] **Step 4: Run, expect PASS; lint.**
- [ ] **Step 5: Commit** `fix(android): settle the invoke when the auth prompt cannot be shown`.

### Task A4: Backing tier on API 30 and StrongBox fallback (spec A4, A5)

**Files:**
- Modify: `SecureKeysPlugin.kt` — `backingOf` (L553–590), StrongBox fallback catch (L783)
- Test: `PluginUnitTest.kt`

**Interfaces:**
- Produces (companion): `fun backingFromKeyInfo(sdkInt: Int, securityLevel: Int?, insideSecureHardware: Boolean, usedStrongBox: Boolean): String` (returns one of `BACKING_DISCRETE/INTEGRATED/SOFTWARE`). On `sdkInt < 31`: `DISCRETE` iff `usedStrongBox && insideSecureHardware`, `INTEGRATED` iff `insideSecureHardware`, else `SOFTWARE`. On ≥ 31 the existing `securityLevel` mapping.
- Produces (companion): `fun isStrongBoxUnavailable(e: Throwable): Boolean` — true for `StrongBoxUnavailableException` or any `Throwable` whose cause chain contains one.
- `backingOf(alias: String, usedStrongBox: Boolean)`.

- [ ] **Step 1: Tests**: API 30 + StrongBox + secure hardware → discrete; API 30 + secure hardware only → integrated; API 30 + not secure → software; API 31 + `SECURITY_LEVEL_STRONGBOX` → discrete; `isStrongBoxUnavailable(ProviderException("x", StrongBoxUnavailableException()))` true; `isStrongBoxUnavailable(IllegalStateException())` false.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement**; the fallback `catch` becomes `catch (e: Exception) { if (!isStrongBoxUnavailable(e)) throw e; ... }`.
- [ ] **Step 4: Run, expect PASS; lint.**
- [ ] **Step 5: Commit** `fix(android): report StrongBox backing on API 30; only fall back on StrongBoxUnavailable`.

### Task A5: Error-code mapping and release logging (spec A6, A7)

**Files:**
- Modify: `SecureKeysPlugin.kt` — `classifyBiometricError` (L269–290), log lines L388, 402, 564, 587, 838, 851, 1087, 1094
- Test: `PluginUnitTest.kt` (~L338 existing biometric mapping test)

- [ ] **Step 1: Update the existing test**: `ERROR_HW_NOT_PRESENT` → `ErrorCodes.UNSUPPORTED`, `ERROR_HW_UNAVAILABLE` → `ErrorCodes.INTERNAL`; keep `NO_BIOMETRICS`/`NO_DEVICE_CREDENTIAL` → `DEVICE_NOT_SECURE`.
- [ ] **Step 2: Run, expect FAIL.**
- [ ] **Step 3: Implement the mapping.** Then wrap each listed log line in `if (BuildConfig.DEBUG)`, or log a message without `$keyName`/`$alias`/the exception in release.
- [ ] **Step 4: Run, expect PASS; lint. Add CHANGELOG lines under Unreleased → Fixed for A1–A6.**
- [ ] **Step 5: Commit** `fix(android): map missing biometric hardware to unsupported; keep key names out of release logs`.

---

# Track B — Windows

Local verification is limited to `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` (which exercise only the new host-portable module). Each task ends with a push and `gh run watch`.

### Task B1: Host-portable, injective key naming (spec W1)

**Files:**
- Create: `tauri-plugin-secure-element/src/windows_names.rs` (compiled on all targets, `#![allow(dead_code)]` like `der.rs`)
- Modify: `src/lib.rs` (add `mod windows_names;`), `src/windows.rs` L95–170 (move `KEY_PREFIX_TPM_BASE`, `NGC_DOMAIN`, `APP_ID_RESERVED_CHARS`, `sanitize_app_id`, `tpm_key_prefix`, `tpm_key_name`, `ngc_key_marker`, `ngc_key_name`, `extract_ngc_key_name` out), `find_keys` L1230–1236, tests L1404–1515 (move)
- Test: `src/windows_names.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `pub(crate) fn tpm_key_name(app_id: &str, key_name: &str) -> String` = `KEY_PREFIX_TPM_BASE + sanitize_app_id(&format!("{app_id}/{key_name}"))`. Because `/` is reserved it escapes to `_x2F`, and `sanitize_app_id` is a prefix code, so the name is injective in `(app_id, key_name)`.
- Produces: `pub(crate) fn tpm_key_prefix(app_id: &str) -> String` = `KEY_PREFIX_TPM_BASE + sanitize_app_id(app_id) + "_x2F"`.
- Produces: `pub(crate) fn decode_tpm_key_name(full_name: &str, app_id: &str) -> Option<String>`: strip `tpm_key_prefix(app_id)`, then unescape (`__` → `_`; any other `_` → `None`), then `None` unless every char is `[A-Za-z0-9_-]`.
- All other moved functions keep their signatures.

- [ ] **Step 1: Write the failing tests** in `windows_names.rs`:

```rust
#[test] fn tpm_name_is_injective_across_delimiter_tricks() {
    assert_ne!(tpm_key_name("com.example", "x2Eapp_mykey"), tpm_key_name("com.example.app", "mykey"));
    assert_ne!(tpm_key_name("a", "_k"), tpm_key_name("a_", "k"));
    assert_ne!(tpm_key_name("x", "a_b"), tpm_key_name("x_a", "b"));
}
#[test] fn tpm_name_round_trips_through_decode() {
    for key in ["k", "a_b", "a__b", "_k", "k_", "A-9_"] {
        assert_eq!(decode_tpm_key_name(&tpm_key_name("com.example", key), "com.example").as_deref(), Some(key));
    }
}
#[test] fn decode_rejects_other_apps_keys() {
    assert_eq!(decode_tpm_key_name(&tpm_key_name("com.example.app", "mykey"), "com.example"), None);
    assert_eq!(decode_tpm_key_name(&tpm_key_name("a_", "k"), "a"), None);
}
#[test] fn tpm_name_uses_escaped_slash_as_delimiter() {
    assert_eq!(tpm_key_name("com.example", "k"), "tauri_se_tpm_com_x2Eexample_x2Fk");
}
```

- [ ] **Step 2: `cargo test windows_names`, expect FAIL** (module missing).
- [ ] **Step 3: Create the module**, move the functions and their existing tests, implement `decode_tpm_key_name`, update `windows.rs` imports and replace the `strip_prefix` closure in `find_keys` with `decode_tpm_key_name(full_name, app_id)`.
- [ ] **Step 4: `cargo test`, expect PASS** (all old `sanitize_app_id`/`ngc_*` tests now run on macOS too). `cargo clippy -- -D warnings`.
- [ ] **Step 5: Docs.** README "Breaking changes" → update the "Windows key names changed" paragraph: TPM keys created by earlier betas are not found by this version. CHANGELOG Unreleased → Changed.
- [ ] **Step 6: Commit** `fix(windows): make TPM key names injective; move naming to a host-testable module`, push, `gh run watch`; `rust-windows` must pass.

### Task B2: Do not swallow lookup failures; resolve NTE_PERM (spec W2, W3)

**Files:**
- Modify: `src/windows.rs` — `try_open_key` (L533–565), `try_open_key_auto` (L459–497), `key_present_in_provider` (L629–670)

**Interfaces:**
- Produces: `enum KeyProbe { Opened(KeyHandle), NotFound, AccessDenied }` and `fn try_open_key(provider: &ProviderHandle, full_name: &str) -> crate::Result<KeyProbe>`; `NTE_PERM` → `AccessDenied`, the three not-found codes → `NotFound`, other errors → `Err` via `ncrypt_error`.
- `try_open_key_auto` uses `get_current_user_sid()?` and `open_ngc_provider()?` (no `if let Ok`). On `AccessDenied` from NGC: `if enumerate_key_names(&ngc_provider)?.iter().any(|n| n == &ngc_full_name) { return Err(crate::Error::platform(ErrorCode::KeyNotAccessible, sanitize_error(..., "Key is not accessible"))) }` else continue to TPM.
- `key_present_in_provider` reimplemented on top of `try_open_key` + the same enumeration branch.

- [ ] **Step 1: Implement** as above. Update the doc comment at L455–458 to say the SID/provider failures now propagate.
- [ ] **Step 2: Local gate**: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test` (host).
- [ ] **Step 3: Commit** `fix(windows): propagate provider failures and report inaccessible NGC keys`, push, `gh run watch`.

### Task B3: NUL-terminate the Use Context string; classify NTE_EXISTS (spec W4, W6)

**Files:**
- Modify: `src/windows.rs` — L1063–1068 (`context_bytes`), `classify_ncrypt_error` (L72–85), `create_ngc_key` create error (~L799–812), `create_tpm_key` create error (~L904–917), tests near L1357

- [ ] **Step 1: Add a test** in the existing `tests` module: `classify_ncrypt_error(&error(NTE_EXISTS)) == ErrorCode::KeyAlreadyExists` (this module is `cfg(windows)`; it runs on CI only).
- [ ] **Step 2: Implement**: `const NTE_EXISTS: HRESULT = HRESULT(0x8009000Fu32 as i32);`, add the match arm, route both `NCryptCreatePersistedKey` errors through `ncrypt_error`. Change `context_bytes` to `context_message.encode_utf16().chain(std::iter::once(0u16)).flat_map(u16::to_le_bytes).collect()`.
- [ ] **Step 3: Local gate; commit** `fix(windows): NUL-terminate the Hello prompt text; classify NTE_EXISTS`, push, `gh run watch`.

### Task B4: Precise consent and availability results (spec W5, W7)

**Files:**
- Modify: `src/windows_hello.rs` (`request_user_consent` L52–67, `is_windows_hello_configured` L11–15), `src/desktop.rs` delete block (L643–659), `src/windows.rs` call site of `is_windows_hello_configured` in `create_ngc_key`

**Interfaces:**
- Produces: `pub fn request_user_consent(hwnd: isize, message: &str) -> Result<UserConsentVerificationResult, windows::core::Error>`.
- Produces: `pub fn consent_result_error(result: UserConsentVerificationResult) -> Option<(crate::ErrorCode, &'static str)>`: `Verified` → `None`; `Canceled` → `UserCancelled`; `RetriesExhausted` → `AuthFailed`; `NotConfiguredForUser` → `DeviceNotSecure`; `DeviceNotPresent`, `DisabledByPolicy` → `Unsupported`; anything else → `Internal`. Message text is the generic phrase for that code.
- Produces: `pub fn is_windows_hello_configured() -> Result<bool, windows::core::Error>`; caller maps `Err` to `ErrorCode::Internal` ("Could not determine Windows Hello availability") instead of `DeviceNotSecure`.

- [ ] **Step 1: Add tests** in `windows_hello.rs`'s `tests` module for each `consent_result_error` arm.
- [ ] **Step 2: Implement**; in `desktop.rs` replace the `if !verified` block with a match on `consent_result_error(result)`.
- [ ] **Step 3: Local gate; CHANGELOG lines for W2–W7; commit** `fix(windows): report consent outcomes with their own error codes`, push, `gh run watch`.

---

# Track C — Apple

Verification: `cargo test` in `tauri-plugin-secure-element/` (compiles and links the Swift), `swiftformat --lint ios/ swift/`, `swiftlint lint`, and the iOS XCTest run from `package.json` `test:swift` (root script) for pure helpers. Behavioural checks use the test app (`cd test-app && ./build-macos-dev.sh`).

### Task C1: Serialize generate/delete and delete the matched item (spec S1)

**Files:**
- Modify: `tauri-plugin-secure-element/swift/SecureEnclaveCore.swift` — `generateSecureKey` (L435–510), `deleteKey` (L698–733), `deleteKeyMatchingPublicKey` (L734–788)

**Interfaces:**
- Produces: `private static let mutationLock = NSLock()`. `generateSecureKey` holds it from the existence probe through `SecKeyCreateRandomKey`. `deleteKey` runs `authenticateDeviceOwner` first (unlocked, since it blocks on the user), then holds the lock for lookup + delete.
- `deleteKeyMatchingPublicKey` deletes the matched item with `SecItemDelete([kSecClass: kSecClassKey, kSecValueRef: privateKey] as CFDictionary)` instead of a name query.

- [ ] **Step 1: Implement** (use `defer { mutationLock.unlock() }` right after `lock()`).
- [ ] **Step 2: Verify**: `cargo test` passes; `swiftformat --lint ios/ swift/`; `swiftlint lint`. Manual: in the test app, fire two `generateSecureKey("dup")` without awaiting the first; expect one success, one `keyAlreadyExists`, one entry in `listKeys`.
- [ ] **Step 3: Commit** `fix(macos): serialize key creation and deletion; delete matched key by reference`.

### Task C2: Classify query failures; lockout → authFailed; empty FFI strings (spec S4, S5, S6)

**Files:**
- Modify: `SecureEnclaveCore.swift` — L455, L569, L750 (query status handling), `checkBiometricAvailability` (L380–412) and its use at L440
- Modify: `swift/secure_element_ffi.swift` — `fromCString` (L95–99), generate (L112), delete (L198)
- Test: `ios/Tests/PluginTests/PluginTests.swift`

**Interfaces:**
- Produces: `public static func queryFailure(_ status: OSStatus) -> SecureEnclaveError` — `errSecInteractionNotAllowed` → `.keyNotAccessible`, else `.failedToQueryKeys(status)`.
- `checkBiometricAvailability()` returns `SecureEnclaveError?`: `LAError.biometryLockout` → `.authFailed("Biometry is locked out; unlock with the device passcode and retry")`, other failures → `.biometricNotAvailable(detail)`, `nil` when usable.
- FFI: generate passes `authMode.map { String(cString: $0) }` (empty string reaches `getAccessControlFlags` and fails closed). Delete: if `authReason` is non-nil but empty, return `strdup(argumentErrorJson("authReason must not be empty"))!`.

- [ ] **Step 1: Write the failing XCTest**

```swift
final class QueryFailureTests: XCTestCase {
    func testLockedKeychainIsNotAccessible() {
        XCTAssertEqual(SecureEnclaveCore.queryFailure(errSecInteractionNotAllowed).code, "keyNotAccessible")
    }
    func testOtherStatusIsInternal() {
        XCTAssertEqual(SecureEnclaveCore.queryFailure(errSecParam).code, "internal")
    }
}
```

- [ ] **Step 2: Run `pnpm test:swift` from the repo root, expect FAIL.**
- [ ] **Step 3: Implement** the three items.
- [ ] **Step 4: Run, expect PASS; `cargo test`; swiftformat/swiftlint.**
- [ ] **Step 5: Commit** `fix(apple): keyNotAccessible for locked keychain, authFailed for lockout, fail closed on empty FFI strings`.

### Task C3: macOS build diagnostics and platform floors (spec S2, S3, S7)

**Files:**
- Modify: `tauri-plugin-secure-element/build.rs` L127–141 (swiftc args), `SecureEnclaveCore.swift` `detectMacSecureElementType` (L790–804), `ios/Package.swift` L9

- [ ] **Step 1: build.rs**: when `std::env::var("PROFILE").as_deref() == Ok("debug")`, append `"-D", "DEBUG"` to the `swiftc` args.
- [ ] **Step 2: Rosetta**: in `detectMacSecureElementType`, read `sysctlbyname("sysctl.proc_translated")`; when it returns 1, return `(discrete: false, integrated: true)` regardless of compile-time arch.
- [ ] **Step 3: `Package.swift`**: `.macOS(.v10_15)`.
- [ ] **Step 4: Verify**: `cargo test` (debug) passes; in the test app debug build, trigger a known failure (e.g. generate a duplicate name) and confirm the message carries detail. CHANGELOG lines for S1–S7.
- [ ] **Step 5: Commit** `fix(apple): enable DEBUG diagnostics in debug builds; detect Rosetta; correct macOS platform floor`.

---

# Track D — Rust core and docs

### Task D1: Fail-closed delete auth and capped FFI parsing on macOS (spec R1, R2)

**Files:**
- Modify: `tauri-plugin-secure-element/src/desktop.rs` — delete block L586–625, sign block L516–549, `ffi_helpers` tests
- Test: `src/desktop.rs` (`#[cfg(all(test, target_os = "macos"))]`)

**Interfaces:**
- Produces: `#[cfg(target_os = "macos")] fn delete_auth_reason(require_auth: bool, reason: Option<&str>) -> crate::Result<Option<std::ffi::CString>>` — `Ok(None)` when `!require_auth`; otherwise `CString::new(resolve_delete_prompt(reason))` mapped to `Error::Validation("Authentication reason contains a NUL byte")`.
- Produces: `#[derive(Deserialize)] struct SignFfiResponse { signature: String }` and `struct DeleteFfiResponse { success: bool }`; sign and delete go through `ffi_helpers::parse_ffi_response`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn delete_auth_reason_is_none_when_auth_not_required() {
    assert!(delete_auth_reason(false, Some("x")).unwrap().is_none());
}
#[test] fn delete_auth_reason_uses_default_prompt() {
    assert_eq!(delete_auth_reason(true, None).unwrap().unwrap().to_str().unwrap(), DEFAULT_DELETE_PROMPT);
}
#[test] fn delete_auth_reason_fails_closed_on_nul() {
    assert!(matches!(delete_auth_reason(true, Some("a\0b")), Err(crate::Error::Validation(_))));
}
```

- [ ] **Step 2: `cargo test delete_auth_reason`, expect FAIL.**
- [ ] **Step 3: Implement**; replace the `optional_to_cstring(auth_reason.as_ref())` pair with the new helper, and the manual `serde_json::Value` parsing in sign/delete with `parse_ffi_response::<SignFfiResponse>` / `::<DeleteFfiResponse>` followed by base64 decode of `signature`.
- [ ] **Step 4: `cargo test`, `cargo clippy -- -D warnings`, expect PASS.**
- [ ] **Step 5: Commit** `fix(desktop): fail closed on an unencodable delete prompt; cap FFI response size on every macOS path`.

### Task D2: README and CHANGELOG corrections (spec D1–D3, A8)

**Files:**
- Modify: `tauri-plugin-secure-element/README.md` — Node.js example (L474–500), tier table (L262–267), Security model → Key isolation (L623–644)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Replace the Node.js example** with the JWK form (verified on Node 24 against the recorded vectors):

```typescript
import { createPublicKey, createVerify } from "crypto";
function verifySignature(publicKeyBase64: string, data: Uint8Array, signatureDer: Uint8Array): boolean {
  const point = Buffer.from(publicKeyBase64, "base64"); // 0x04 || X || Y
  const key = createPublicKey({ format: "jwk", key: { kty: "EC", crv: "P-256",
    x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33, 65).toString("base64url") } });
  const verify = createVerify("SHA256"); verify.update(data);
  return verify.verify({ key, dsaEncoding: "der" }, Buffer.from(signatureDer));
}
```

- [ ] **Step 2: Verify the snippet** by running it with `node -e` against `test-app/src/cross-platform-test-vectors.json` vector 0; expect `true`.
- [ ] **Step 3: Add a `software` row** to the tier table ("Key exists but is protected by the OS only: Android emulator, devices with no TEE").
- [ ] **Step 4: Document A8** under Key isolation: Android `none` keys remain usable while the device is locked; Apple keys are `WhenUnlockedThisDeviceOnly`. Add CHANGELOG Unreleased → Fixed lines for R1, R2, D1–D3.
- [ ] **Step 5: `pnpm exec prettier --check .`; commit** `docs: working Node.js verification example; software tier; Android locked-device note`.

---

## Execution notes

- Tracks A, B, C, D touch disjoint files except `CHANGELOG.md`. Run them as four parallel subagents, each on its own branch from `main`, each opening a PR. Merge order does not matter; resolve CHANGELOG conflicts by keeping all lines.
- Track B's subagent must have `gh` access and must not claim completion until the `rust-windows` CI job is green on its branch.
- Out of scope (deliberately): raising the MSRV / Tauri release train, adding an MSRV CI job, building the test app in CI. These were discussed with the dependency bump and are a separate decision.
