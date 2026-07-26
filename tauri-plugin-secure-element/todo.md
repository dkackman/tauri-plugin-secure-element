# Road to 1.0

Remaining work from the security/quality/correctness reviews of `0.1.0-beta.4`.
Items are ordered by what should gate the next release.

This file replaces an earlier prose review that lived here; its findings are folded in
below (the two reviews independently agreed on items 1, 2, 4 and 5, which is worth
weighting when triaging). One claim from that review could **not** be reproduced and is
not carried forward: it reported that commit `8dd9697` on a branch
`docs/delete-not-authenticated` held unmerged security documentation. No such commit,
branch, or commit message exists in any ref of this repository, and no README revision in
history contains that text. The underlying _content_ gap is real, so it is captured as
item 2 below — but there is no lost branch to cherry-pick from; the docs need writing.

Already fixed (see git history):

- The capabilities cache freezing `canEnforceBiometricOnly` for the process lifetime.
- Windows `deleteKey` reporting `success: true` on unknown failure.
- The Android `minSdk` 21/23 mismatch (`KeyGenParameterSpec` is API 23+).
- `cargo test` missing from every CI job.
- The release workflow gating on only 2 of 6 CI jobs — it now reuses `ci.yml` wholesale,
  so Windows, macOS, Swift and Kotlin all gate a release.
- The macOS Swift FFI silently not compiling: a trailing comma in a call argument list
  (Swift 6.1+ only) broke the build, `build.rs` downgraded the failure to a
  `cargo:warning`, and `cargo check` — exactly what CI runs — passed with zero FFI
  symbols built. `build.rs` now panics on a Swift compile error, and invokes swiftc via
  `xcrun` so the compiler and SDK always come from the same toolchain.
- **Broken TypeScript types in the published package.** `tsconfig.json` never set
  `rootDir`, so TypeScript inferred it — and that inference shifted under a newer
  compiler, moving declarations from `dist-js/index.d.ts` to
  `dist-js/guest-js/index.d.ts` while `package.json` `"types"` still pointed at the
  former. **`0.1.0-beta.8` is live on npm with types that do not resolve at all**
  (beta.3 and beta.4 were fine). `rootDir` is now pinned explicitly. This alone
  justifies a prompt beta.6.
- The expensive keygen probes are now memoized at the platform layer, which also
  resolves the "iOS burns an ephemeral Secure Enclave key on every `generateSecureKey`"
  finding: `Plugin.swift` still calls `checkSupport()`, but the probe inside it now runs
  at most once per process.

---

## Must fix before dropping `-beta`

### 1. Verify `pinOrBiometric` signing on Android API 23-29

`buildPromptInfo` always allows `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`
(`android/src/main/java/SecureKeysPlugin.kt`), and that prompt is passed to
`biometricPrompt.authenticate(promptInfo, cryptoObject)`. androidx.biometric is
believed to throw `IllegalArgumentException("Crypto-based authentication is not
supported for Device Credential prior to API 30")` in that combination.

If confirmed, **every `pinOrBiometric` signature fails on API 23-29** — which is most
of the range the README advertises.

- [ ] Reproduce on an API 29 emulator/device, or confirm against the androidx.biometric
      1.1.0 source.
- [ ] If confirmed: on pre-30, build prompt info with `BIOMETRIC_STRONG` only and offer
      device-credential fallback through a separate non-crypto path (or reject
      `pinOrBiometric` on pre-30 the way `biometricOnly` is already rejected, and say so
      in the README).
- [ ] Fix the double-reject: the throw escapes into `signWithKey`'s outer `catch` _after_
      `pendingSignInvoke` already holds the invoke, so the same invoke can be rejected
      twice. Wrap the `authenticate` call so failure goes through
      `pendingSignInvoke.getAndSet(null)`.
- [ ] Add a regression test for the "prompt construction fails" path.
- [ ] Separately, audit the pre-R fallback `setUserAuthenticationValidityDurationSeconds(0)`.
      AOSP's `KeymasterUtils` does treat `0` as per-use authentication, but the documented
      per-use value for that deprecated API is `-1`, and `0` has historically been read as
      "auth token must be ≤ 0 seconds old," which can render a key permanently unusable.
      Confirm on API 23-29 hardware which semantics apply.

### 2. Write the threat model / security model docs

The per-platform boundaries differ sharply and callers cannot infer them. Add a
`## Security model` section to the README (and a `SECURITY.md` with a reporting address).
Must state, at minimum:

- [ ] **Windows `authMode: "none"`** creates a Platform Crypto Provider key that _any_
      process running as the same user can sign with silently, given the key name — and
      the name is `tauri_se_tpm_{app_id}_{key_name}`, derivable from the public app
      identifier. `guest-js/index.ts` documents this honestly; the README does not
      mention it at all.
- [ ] **Windows keys are scoped per-user, not per-app.** `app_id` is only a name prefix,
      so a different app run by the same user can open them. Contrast with iOS/macOS
      (keychain access groups) and Android (per-app keystore), where the OS enforces the
      app boundary.
- [ ] **`sanitize_app_id` collisions**: `.` → `_` means identifiers `a.b` and `a_b` land
      in the same Windows namespace.
- [ ] **Deletion never requires authentication on any platform** (`SecItemDelete`,
      `NCryptDeleteKey`, `keyStore.deleteEntry` all proceed for auth-mandatory keys). Any
      code that can reach the plugin — including injected webview JS holding
      `secure-element:default` — can destroy every key. Document it as an availability
      property, and recommend a narrower capability for apps that never delete.
- [ ] **The default capability grants all six commands.** Show a minimal capability
      example (e.g. sign-only) alongside `secure-element:default`.
- [ ] What the plugin does _not_ protect against: a compromised renderer can request
      signatures over attacker-chosen bytes for any non-auth key; auth-required keys
      limit this to one signature per user gesture, over data the user cannot see.

### 3. Reconcile `biometricOnly` docs with behavior

The README auth-mode table says `biometricOnly` is ❌ not supported on iOS/macOS, but
`SecureEnclaveCore.getAccessControlFlags` implements it with `.biometryCurrentSet` and
`checkSupport()` reports `canEnforceBiometricOnly: true` when biometrics are enrolled.
Docs and code disagree on a security-relevant setting.

- [ ] Decide which is true and make them agree (the code looks correct — fix the table).
- [ ] Document that `.biometryCurrentSet` **permanently invalidates the key when the
      enrolled biometric set changes** — adding a fingerprint or re-enrolling Face ID
      destroys the key and its signing capability forever. This is currently documented
      nowhere and will surprise anyone using `biometricOnly` for anything durable.
- [ ] Decide whether `biometricOnly` should use `.biometryAny` instead, which survives
      enrollment changes, and document the tradeoff either way.
- [ ] Align the semantics of `canEnforceBiometricOnly` across platforms: Apple returns
      _current enrollment_, Android returns _API level ≥ 30_ regardless of enrollment.
      Same field name, two different questions.

---

## Should fix before 1.0

### 4. Verify Windows Hello prompting during `listKeys` / `generateSecureKey`

`list_ngc_keys` and `key_exists` open NGC keys via `open_key_internal` with
`NCRYPT_FLAGS(0)`, while the enumeration itself and `try_open_key` correctly pass
`NCRYPT_SILENT_FLAG`. If opening or `export_public_key` on an auth-mandatory NGC key
triggers UI, a plain `listKeys()` produces one Windows Hello prompt per key.

- [ ] Test on hardware with several `pinOrBiometric` keys present.
- [ ] If it prompts, switch both call sites to the silent path.

### 5. Cross-provider name collisions on Windows

- [ ] `key_exists` returns `false` whenever `open_ngc_provider()` fails, so a TPM key can
      be created under a name an NGC key already owns. `open_key_auto` then always
      resolves NGC first, so sign/delete hit a different key than the one just created,
      and `list_keys` returns two entries with the same `keyName`. Make `key_exists`
      propagate "could not determine" instead of treating it as "does not exist".
- [ ] `key_exists` also uses the non-silent `open_key_internal` (same as item 4).
- [ ] Delete-by-public-key matches a key, takes `keys[0].key_name`, then re-resolves _by
      name_ (`desktop.rs`) instead of deleting the key it matched. Carry the provider and
      full key name through so the matched key is the deleted key.
- [ ] Consider returning the provider/auth-mode in `KeyInfo` so callers can tell a
      silent TPM key from a Hello-protected one. Right now `listKeys` cannot distinguish
      them, which matters for any security decision made from the list.

### 6. Verify the cross-platform test vectors in CI

`test-app/src/cross-platform-test-vectors.json` holds real iOS/Android/Windows
signatures with public keys and messages, and nothing automated checks them. `der.rs`
tests assert DER _structure_ but no test anywhere verifies an actual signature.

- [ ] Add a `cargo test` that loads the vectors and verifies each signature against its
      public key with a P-256 verifier (`p256`/`ecdsa` crate, dev-dependency only).
      This single test locks down DER encoding, X9.62 public-key export, and the
      hash-then-sign convention across all four platforms.
- [ ] Add a vector for macOS once the FFI is exercised on a signed build.
- [ ] Add a negative case (tampered message must fail) so the test can't pass vacuously.

### 7. Close the remaining CI gaps

- [ ] `SecureEnclaveCore.swift` — the largest and most security-critical Swift file — is
      **not linted or format-checked at all**. `swiftformat --lint ios/` reports "2 files
      skipped" because it is a symlink into `swift/`. Point the lint at `swift/` too, or
      resolve symlinks. Note `swift/` currently has ~4 pre-existing `guard`/`else`
      formatting diffs that will need fixing once it is covered.
- [ ] Add a `.swift-version` file — swiftformat warns that some rules are disabled
      without it.
- [ ] Kotlin unit tests (`android/src/test/java/PluginUnitTest.kt`) never run in CI; the
      kotlin job only runs ktlint. Wire up `gradlew test` if the `:tauri-android`
      project dependency can be resolved in CI.
- [ ] The local `~/.ktlint/ktlint` binary rejects valid Kotlin trailing commas
      ("Not a valid Kotlin file") on pristine `main` — version skew with the `1.1.1`
      pinned in `build.gradle.kts`. Pin one version across gradle, the pnpm script, and
      the docs so local and CI agree.
- [ ] Consider a build job (not just `cargo check`) on macOS/Windows so link errors —
      e.g. missing Swift FFI symbols — are caught. `cargo check` does not link.
- [ ] `cargo test` now runs on all three platforms, but nothing runs `cargo package
--dry-run`; the `build.rs` packaging path is untested.

---

## Quality / polish

### Soundness

- [ ] `windows.rs:530` — `&*(buffer.as_ptr() as *const TOKEN_USER)` creates a reference
      into a `Vec<u8>` (alignment 1) for a type requiring 8-byte alignment. Creating an
      unaligned reference is UB even if the read never faults; it works today only because
      the allocator happens to return aligned memory. Use `std::ptr::read_unaligned`, or
      allocate the buffer as `Vec<u64>`/via a properly aligned type.
- [ ] `KeyNameBufferGuard::as_ref` (`windows_raii.rs`) dereferences a raw pointer in a
      safe `fn` with only a doc comment saying it must be called from an unsafe context.
      Make it `unsafe fn`.

### Everything else

- [ ] `der.rs` uses `debug_assert!` for the DER short-form length invariant. Unreachable
      for valid 64-byte input, but returning `Err` costs nothing and removes a
      release-only silent-corruption path.
- [ ] `getAccessControlFlags` (`SecureEnclaveCore.swift`) silently downgrades unknown
      auth modes to `.userPresence` via `case "pinOrBiometric", _`. The Rust enum gates
      this today, but the `@_cdecl` FFI entry points are public. Fail closed instead.
- [ ] `probeTeeSupport` now returns `false` when the generated key can't be inspected
      (it previously assumed TEE). Confirm on a range of devices that this doesn't
      false-negative anyone.
- [ ] `isEmulator()` fingerprint sniffing is easily defeated and easily wrong. Either
      document `emulated` as best-effort on Android or derive it from the keystore
      security level, which is already being read.
- [ ] `signWithKey` marshals `data` as a JSON number array (`guest-js/index.ts`); at the
      1 MB validation ceiling that is ~4 MB of JSON per call. Consider base64 over the
      IPC boundary, or lower the ceiling to something a signing API actually needs.
- [ ] Windows error sanitization is inconsistent: the "already exists" and Windows-Hello
      -not-configured messages use plain `format!`, bypassing `sanitize_error`, so
      release builds still emit the key name.
- [ ] Android toolchain upgrade — blocks all androidx dependency bumps. Attempted and
      reverted; the constraints are: - **`androidx.biometric` has no stable upgrade.** 1.1.0 (2020) is still the newest
      stable release; 1.2.0, 1.3.0 and 1.4.0 have only ever shipped as alphas. So
      item 1 cannot be fixed by bumping the library — it needs a code change. - `core-ktx:1.19.0`, `appcompat:1.7.1`, `fragment-ktx:1.8.9` and `material:1.14.0`
      all ship **Kotlin 2.1.0 metadata**, but `settings.gradle` pins Kotlin **1.8.20**
      (and AGP **8.0.2**), which reads at most 1.9.0. Bumping them fails the build with
      "Module was compiled with an incompatible version of Kotlin". - Raising the plugin's Kotlin version is not purely local: this is a **library**,
      and its metadata must be readable by the consuming app. Tauri's generated Android
      project currently uses Kotlin **1.9.25**, so compiling the plugin against 2.x
      would break consumers until Tauri's template moves. Check what Tauri generates
      before touching this. - Sequence when it is time: Tauri template Kotlin version → plugin `settings.gradle`
      (Kotlin + AGP) → `compileOptions`/`jvmTarget` (Java 8 is likely too old for
      AGP 8.1+) → ktlint gradle plugin → then the androidx versions.
- [ ] `android/build.gradle.kts` declares `consumerProguardFiles("consumer-rules.pro")`
      but that file does not exist; every build logs
      "Supplied consumer proguard configuration does not exist". Create it or drop the
      declaration.
- [ ] The Android build warns it is "incompatible with Gradle 9.0" (deprecated features).
      Worth resolving as part of the toolchain upgrade above.
- [ ] `build.rs` comment says the permissions files are included "via the `include`
      field"; `Cargo.toml` uses `exclude`.
- [ ] README's `GenerateSecureKeyResult` omits the `backing` field the API returns.
- [ ] README "Platform Limitations → Windows" says TPM 2.0 is supported on Windows 10
      "since version 1507", but the code requires build 14393 (1607) and errors below it.
- [ ] Add `CHANGELOG.md` and a stated MSRV / deprecation policy before 1.0.
- [ ] `CLAUDE.md` says `tauri` 2.10.1; `Cargo.toml` pins 2.11.5.
- [ ] `secure_element_ffi.swift:120` — `var info` is never mutated; should be `let`.
- [ ] The Windows Hello prompt string `"Authenticate to sign data"` (`windows.rs`) is
      hardcoded English and not localizable. Consider accepting it from the caller, which
      also lets apps explain _what_ is being signed.
- [ ] macOS FFI calls run synchronously on the async runtime's worker thread — including
      `sign`, which blocks on a Touch ID prompt. Wrap them in `spawn_blocking` so one
      pending signature can't stall other plugin commands.

---

## Open questions

- [ ] Should `listKeys` require a capability separate from `signWithKey`? Enumerating
      public keys is a much weaker operation than signing, and apps may want to grant
      them differently.
- [ ] Is there a use case for `authMode: "none"` on Windows given that any same-user
      process can use the key? If not, consider requiring an explicit opt-in flag so it
      can't be reached by passing a default.
- [ ] Key attestation is not exposed on any platform (Android `KeyStore` attestation
      certificates, TPM attestation). Without it, a relying party cannot verify a public
      key really came from hardware. Worth scoping for a post-1.0 release — it is the
      main thing a remote verifier would want from a plugin like this.
