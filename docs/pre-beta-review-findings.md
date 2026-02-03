# Pre-Beta Release Code Review Findings

**Date:** 2026-02-03
**Reviewer:** Claude Code (Opus 4.5)
**Status:** In Progress

## Summary

A comprehensive security and quality review was performed before the beta release. The review identified 9 issues across the codebase. One issue (Android key namespace) was dismissed after analysis showed Android's per-app keystore isolation makes it a non-concern.

---

## Windows-Specific Issues

These issues require a Windows environment to fix and test. They are grouped here for convenience.

### Windows Issue A: NGC Signing Without Per-Operation Authentication (Critical #2)

**Location:** `tauri-plugin-secure-element/src/windows.rs:664-713`

#### Problem

The `sign_hash_with_window` function sets `NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY` to force a fresh Windows Hello prompt for each signing operation, but the result is silently ignored:

```rust
// windows.rs:699-709
let gesture_property = HSTRING::from(NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY);
let gesture_required: u32 = 1;
let gesture_bytes = gesture_required.to_le_bytes();

let _ = NCryptSetProperty(   // <-- Result ignored!
    key.0,
    PCWSTR(gesture_property.as_ptr()),
    &gesture_bytes,
    NCRYPT_FLAGS(0),
);
```

If this property set fails, signing proceeds using cached Windows Hello credentials without user interaction.

#### Cross-Platform Comparison

| Platform | Auth Model | Enforcement |
|----------|------------|-------------|
| iOS/macOS | Per-operation | Hardcoded via `.userPresence` / `.biometryCurrentSet` flags at key creation |
| Android | Per-operation | Hardcoded via `setUserAuthenticationParameters(0, ...)` - timeout=0 means no session caching |
| Windows | Session-based (default) | Relies on runtime `NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY` to force per-operation |

Windows is the only platform where per-operation auth can silently fail, falling back to session-based auth.

#### Recommended Fix

Make the gesture-required property set a hard failure for NGC keys:

```rust
// Replace the silent ignore with error handling:
NCryptSetProperty(
    key.0,
    PCWSTR(gesture_property.as_ptr()),
    &gesture_bytes,
    NCRYPT_FLAGS(0),
).map_err(|e| {
    crate::Error::Io(std::io::Error::other(sanitize_error(
        &format!("Failed to set gesture required property: {}", e),
        "Failed to configure per-operation authentication",
    )))
})?;
```

#### Testing

1. Create an NGC key with `authMode: "pinOrBiometric"`
2. Sign data - should prompt Windows Hello
3. Immediately sign again - should prompt again (not use cached credentials)
4. Verify that if property set fails, signing returns an error instead of proceeding

---

### Windows Issue B: NGC Double-Auth Prompt (Critical #4)

**Location:** `tauri-plugin-secure-element/src/windows.rs:715-751`

#### Problem

`sign_hash_internal` makes two `NCryptSignHash` calls:

```rust
// First call (line 720) - size query
NCryptSignHash(key.0, None, hash, None, &mut sig_size, NCRYPT_FLAGS(0)).map_err(...)?;

// Second call (line 728) - actual signing
NCryptSignHash(key.0, None, hash, Some(&mut signature), &mut sig_size, NCRYPT_FLAGS(0)).map_err(...)?;
```

For NGC keys, the size-query call can trigger the Windows Hello authentication prompt, consuming the user's gesture. The second call may then:
- Prompt the user again (poor UX - double prompt)
- Fail because the gesture was already consumed
- Succeed silently if credentials are still cached

#### Recommended Fix

**Option A:** Pass `NCRYPT_SILENT_FLAG` for the sizing call to prevent it from triggering authentication:

```rust
// Size query - should NOT trigger auth
NCryptSignHash(key.0, None, hash, None, &mut sig_size, NCRYPT_SILENT_FLAG).map_err(|e| {
    crate::Error::Io(std::io::Error::other(sanitize_error(
        &format!("Failed to get signature size: {}", e),
        "Failed to sign",
    )))
})?;

// Actual signing - SHOULD trigger auth (no SILENT flag)
let mut signature = vec![0u8; sig_size as usize];
NCryptSignHash(key.0, None, hash, Some(&mut signature), &mut sig_size, NCRYPT_FLAGS(0)).map_err(...)?;
```

**Option B:** Skip the sizing call entirely and use a known buffer size. P-256 ECDSA signatures are:
- Max 72 bytes for DER-encoded (typical: 70-72)
- Exactly 64 bytes for raw R||S format

Since we're using P-256 keys exclusively, we could allocate a 72-byte buffer and use the returned `sig_size` to truncate.

#### Testing

1. Create an NGC key
2. Sign data
3. Verify user sees exactly ONE Windows Hello prompt (not two)
4. Verify the signature is valid

---

### Windows Issue C: Other Silently Ignored NCryptSetProperty Calls

**Location:** `tauri-plugin-secure-element/src/windows.rs:670-697`

#### Context

Two other `NCryptSetProperty` calls also ignore errors:

```rust
// Window handle property (line 676)
let _ = NCryptSetProperty(
    key.0,
    PCWSTR(hwnd_property.as_ptr()),
    &hwnd_bytes,
    NCRYPT_FLAGS(0),
);

// Use context message property (line 692)
let _ = NCryptSetProperty(
    key.0,
    PCWSTR(context_property.as_ptr()),
    &context_bytes,
    NCRYPT_FLAGS(0),
);
```

#### Assessment

These are less critical than the gesture-required property:
- **Window handle:** Affects dialog positioning, not security. Silent failure is acceptable.
- **Context message:** Affects the text shown in the prompt, not security. Silent failure is acceptable.

#### Recommendation

Leave these as-is (silent ignore) but consider logging a warning in debug builds:

```rust
if let Err(e) = NCryptSetProperty(...) {
    #[cfg(debug_assertions)]
    eprintln!("Warning: Failed to set window handle property: {}", e);
}
```

---

### Windows Testing Checklist

Before merging Windows fixes:

- [ ] **TPM keys (authMode: "none")**
  - [ ] Generate key succeeds
  - [ ] Sign succeeds without any prompt
  - [ ] List keys shows the key
  - [ ] Delete key succeeds

- [ ] **NGC keys (authMode: "pinOrBiometric")**
  - [ ] Generate key succeeds (shows Windows Hello setup if needed)
  - [ ] Sign shows exactly ONE Windows Hello prompt
  - [ ] Signing again immediately shows another prompt (per-operation, not session)
  - [ ] If gesture-required property fails, signing returns an error (not silent success)
  - [ ] List keys shows the key
  - [ ] Delete key succeeds

- [ ] **Error handling**
  - [ ] Signing with non-existent key returns clear error
  - [ ] Signing when user cancels Windows Hello returns clear error

---

## Other Critical Issues

### Issue #3: Android deleteKey Dangling Promise

**Priority:** Critical
**Location:** `tauri-plugin-secure-element/android/src/main/java/SecureKeysPlugin.kt:814-817`

#### Problem

When both `keyName` and `publicKey` are null, `deleteKey` returns without resolving or rejecting the invoke:

```kotlin
val targetPublicKey = args.publicKey
if (targetPublicKey == null) {
    return  // <-- Bare return, promise never settles!
}
```

#### Recommended Fix

```kotlin
val targetPublicKey = args.publicKey
if (targetPublicKey == null) {
    invoke.reject("Either keyName or publicKey must be provided")
    return
}
```

**Note:** Rust-side validation in `commands.rs:57-61` should catch this before it reaches Android, but defensive programming requires handling it in Kotlin too.

---

## Important Issues

### Issue #5: Cross-Platform Signature Hashing Convention Undocumented

**Priority:** Important
**Location:** All platform implementations

All platforms hash the input data with SHA-256 before signing, but this is implicit. Document that:
- Callers should pass raw data (not pre-hashed)
- Verifiers should hash the original data with SHA-256 before verification
- All platforms produce compatible ECDSA-SHA256 signatures

---

### Issue #6: macOS FFI Memory Leak on Panic

**Priority:** Important
**Location:** `tauri-plugin-secure-element/src/desktop.rs:39-68`

`ffi_string_to_owned` can leak memory if a panic occurs between receiving the pointer and calling `libc::free`. Use an RAII guard pattern:

```rust
struct MallocGuard(*mut std::ffi::c_char);
impl Drop for MallocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::free(self.0 as *mut libc::c_void); }
        }
    }
}
```

---

### Issue #7: Swift escapeJsonString Missing Control Characters

**Priority:** Important
**Location:** `tauri-plugin-secure-element/swift/secure_element_ffi.swift:30-37`

`escapeJsonString` only escapes `\`, `"`, `\n`, `\r`, `\t`. JSON requires escaping all control characters U+0000-U+001F. Use `JSONSerialization` or a proper per-character escape loop.

---

### Issue #8: Default Permissions Overly Permissive

**Priority:** Important
**Location:** `tauri-plugin-secure-element/permissions/default.toml`

Default permissions grant all operations including `generate_secure_key`, `sign_with_key`, and `delete_key`. Consider making the default read-only (`check_secure_element_support`, `list_keys`, `ping`) with sensitive operations requiring explicit opt-in.

---

### Issue #9: checkSupport Creates Hardware Key on Every Call

**Priority:** Important (Performance)
**Location:** `tauri-plugin-secure-element/swift/SecureEnclaveCore.swift:519-541`

`checkSupport` creates and deletes a test Secure Enclave key on every call. Cache the result since hardware capabilities don't change at runtime.

---

### Issue #10: TypeScript Nullish Coalescing

**Priority:** Important
**Location:** `tauri-plugin-secure-element/guest-js/index.ts:53,85-86`

Uses `||` instead of `??` for optional parameters, coercing empty strings to null:

```typescript
// Current (wrong)
keyName || null

// Should be
keyName ?? null
```

---

## Dismissed Issues

### Android Key Namespace (Originally Issue #1)

**Status:** Dismissed - Not a concern

The reviewer flagged that Android's `listKeys` returns all AndroidKeyStore keys without prefix filtering. However:

1. Android's AndroidKeyStore is **per-application (per UID)** at the OS level
2. Each app integrating the plugin gets its own isolated keystore
3. Other apps cannot see or access these keys

The only scenario where this matters is if another library *within the same app* also uses AndroidKeyStore - their keys would be visible. This is an edge case with minimal security impact since:
- Key names would likely be distinct
- Deleting another library's key requires knowing its exact name
- This is a UX issue at worst, not a security vulnerability

Windows uses prefixes (`tauri_se_tpm_`, `tauri_se/`) because Windows key storage is system-wide. Android's per-app isolation makes this unnecessary.

---

## Action Items

### Windows (requires Windows environment)
- [ ] Fix Issue A (gesture-required error handling)
- [ ] Fix Issue B (double-prompt / NCRYPT_SILENT_FLAG)
- [ ] Run Windows testing checklist

### Cross-Platform
- [ ] Fix Issue #3 (Android dangling promise)
- [ ] Fix Issue #5 (Document hashing convention)
- [ ] Fix Issue #6 (macOS FFI memory safety)
- [ ] Fix Issue #7 (Swift JSON escaping)
- [ ] Review Issue #8 (Permissions - may be intentional design choice)
- [ ] Fix Issue #9 (Cache checkSupport)
- [ ] Fix Issue #10 (TypeScript nullish coalescing)
