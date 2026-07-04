Fable 5 Review complete. I read every source file across the five implementations (Rust core, Windows NCrypt, macOS/iOS Swift, Android Kotlin, TypeScript bindings), ran the Rust test suite (30/30 pass), and cross-checked the docs against git history. Overall verdict: this is a well-built plugin — centralized input validation before platform dispatch, consistent P-256/X9.62/DER formats across all platforms, RAII wrappers on every Windows handle, debug/release error sanitization everywhere, and per-plugin key namespacing on all platforms. The findings below are mostly edge cases and doc drift, with one lost-work discovery that I'd fix first.

The headline finding: security documentation was never merged

Commit 8dd9697 ("document that delete is unauthenticated") lives on the unmerged branch docs/delete-not-authenticated and never landed on main. Your session history says this work was "completed," but main doesn't have it. What's missing from the current README and guest-js/index.ts:

- The security note that key deletion is not gated by authentication on any platform — a pinOrBiometric key can be deleted without any prompt. This is the most important security caveat the plugin has, and it's currently undocumented.
- The Signature Format section (DER ECDSA over SHA-256, cross-platform verifiable).
- The Windows 10 1607 / build 14393 minimum — the code enforces it (windows.rs:128), but the README's Platform Limitations section instead says TPM 2.0 is supported "since version 1507," which contradicts the runtime check.
- JSDoc for deleteKey explaining idempotency and the exactly-one-parameter rule.

The branch itself is stale (it predates newer main work), so don't merge it — cherry-pick the README/index.ts doc hunks from 8dd9697 onto current main. (I verified the other suspect branch, windows-per-use-auth tip 13aeb4d, did land content-wise — its windows.rs is byte-identical to main's.)

Security

1. README auth-mode table contradicts the code (README ~line 348): it says biometricOnly is "❌ Not supported" on iOS/macOS, but SecureEnclaveCore.swift:169 implements it with .biometryCurrentSet (the strict variant that invalidates on re-enrollment — good), plus an enrollment precheck. The table is wrong in a security-relevant matrix; a developer could settle for pinOrBiometric believing biometric-only isn't available.
2. Windows key_exists probes without the silent flag (windows.rs:421-439): it uses open_key_internal rather than try_open_key, so probing the NGC provider during create_key could trigger a Windows Hello prompt, and any provider error is conflated with "doesn't exist." You built try_open_key for exactly this; key_exists should use it.
3. Informational, both fine but worth being deliberate about: the default permission set grants all six commands including delete-key and sign-with-key; and Windows key scoping (tauri_se_tpm_{app_id}_, NGC marker) is namespacing, not a security boundary — any process running as the user can reach these keys, silently for authMode: "none". The TS doc for "none" covers this well; the lost README note would cover deletion.

Correctness

4. Windows delete swallows real errors and reports success (desktop.rs:453-455): Err(_) => return Ok(DeleteKeyResponse { success: true }) treats every open_key_auto failure — including the "corrupted key / service fault" errors that open_key_auto deliberately propagates — as "already deleted." The same pattern compounds in the delete-by-public-key path: windows::list_keys swallows provider errors (if let Ok at windows.rs:1057-1074, and the enum loop at windows.rs:928 breaks on any error), so a transient provider failure yields an empty list → success: true while the key still exists. Callers doing "delete then verify gone" get a false confirmation. Only genuine not-found errors should map to idempotent success.
5. Capability cache goes stale on Apple platforms (commands.rs:10): the OnceLock caches check_secure_element_support for the process lifetime on the premise that "hardware capabilities don't change at runtime" — but canEnforceBiometricOnly on iOS/macOS reflects biometric enrollment and lockout state (SecureEnclaveCore.swift:610), which does change at runtime. A user who enrolls Face ID after launch will see false until app restart, and the README explicitly tells developers to consult this field before creating biometric-only keys. Android (API-level check) and Windows (hardcoded false) are genuinely static. Suggest caching only the hardware tiers, or skipping the cache on Apple platforms.
6. Android pinOrBiometric is likely broken on API 28–29 (SecureKeysPlugin.kt:206-256, 794): androidx BiometricPrompt doesn't support BIOMETRIC_STRONG | DEVICE_CREDENTIAL on API 28–29, and CryptoObject-based authentication with DEVICE_CREDENTIAL requires API 30+ — authenticate(promptInfo, cryptoObject) should error out on those versions. The pre-R key spec fallback setUserAuthenticationValidityDurationSeconds(0) also has murky semantics (0 was historically "auth token must be ≤0 seconds old," which can render keys unusable; the documented per-use value is -1, which is biometric-only). I can't verify without a device; either test on Android 9/10 hardware or reject pinOrBiometric below API 30 the way you already reject biometricOnly.
7. iOS still burns a test key per keygen (ios/Sources/Plugin.swift:63): generateSecureKey derives backing via checkSupport(), which creates an ephemeral SE probe key each call. Commit 2f04b51 fixed exactly this on the macOS FFI path with strongestBacking() (secure_element_ffi.swift:102); the iOS wrapper was missed. Same pattern on Android: generateSecureKey calls isTeeSupported() (SecureKeysPlugin.kt:472) — a throwaway keygen+delete — on every generate on non-StrongBox devices; worth caching in the plugin instance.

Minor quality notes

- windows.rs:509 — &*(buffer.as_ptr() as *const TOKEN_USER) on a Vec<u8> is technically unaligned-reference UB (fine in practice given allocator alignment, but easy to fix with an aligned buffer).
- CLAUDE.md says tauri 2.10.1; Cargo.toml has 2.11.2.
- secure_element_ffi.swift:120 — var info never mutated; should be let.
- The Windows Hello context string "Authenticate to sign data" (windows.rs:801) isn't localizable.
- macOS FFI calls (including a sign that blocks on a Touch ID prompt) run synchronously on the async runtime's worker thread; spawn_blocking would be kinder in multi-command apps.

Things I checked that are solid: the iOS/macOS shared-core symlink is real (not a drifting copy); build.rs COMMANDS matches all six registered commands and permissions; the DER converter handles all edge cases with good tests; NUL/control-char injection into the macOS FFI filter path is blocked by validation; the NGC auth-mandatory policy is persisted at key creation with a sensible legacy-name fallback; and the Android biometric invoke lifecycle (pendingSignInvoke) correctly guarantees exactly-once resolution.

If you want, I can cherry-pick the lost docs from 8dd9697 and fix items 4, 5, and 7 — those are the concrete, low-risk ones.
