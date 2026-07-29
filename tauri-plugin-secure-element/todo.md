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
- **The cross-platform signature vectors are now verified in CI.**
  `test-app/src/cross-platform-test-vectors.json` was recorded from hardware but nothing
  checked it. `tests/cross_platform_vectors.rs` now verifies every vector against its
  public key with a P-256 verifier (`p256`, dev-dependency only), which locks down DER
  encoding — including `der.rs`'s raw R||S conversion on Windows — X9.62 public-key
  export, and the hash-then-sign convention on all four platforms. It also asserts
  platform coverage and includes two negative cases (tampered message, foreign key) so
  it cannot pass vacuously. macOS vectors are recorded now that the FFI has been
  exercised on a signed build. `cargo test` already runs on Linux, macOS and Windows, so
  this gates every release. `/tests` is excluded from the published crate because the
  test `include_str!`s a path under `test-app/`.
- **The remaining CI gaps are closed.**
  - `SecureEnclaveCore.swift` and the macOS-only `secure_element_ffi.swift` are
    format-checked and linted now. swiftformat runs against `ios/ swift/` — it skips the
    symlink, so `swift/` is where the shared file actually gets checked — and
    `.swiftlint.yml` adds `swift` to `included` while excluding the symlink so nothing is
    linted twice. Fixing the backlog of diffs also surfaced one real violation the gap
    had been hiding.
  - The swiftformat "no Swift version was specified" warning is gone, but via
    `--swiftversion 5.7` in a new `.swiftformat` rather than the `.swift-version` file
    the item asked for: swiftly reads `.swift-version` as a _toolchain selector_ and
    refuses to run when no toolchain of exactly that version is installed, which breaks
    every `swift` command in the tree. 5.7 rather than the newest because at 5.9 the
    `redundantReturn` rule rewrites `switch` statements into implicit-return switch
    _expressions_, raising the minimum toolchain to Xcode 15 for anyone building the iOS
    package.
  - Kotlin unit tests run in CI — 10 tests that had only ever run on a developer's
    machine. `:tauri-android` resolves only if `android/.tauri/tauri-api` exists, and
    nothing in this repository's build creates it: it is a copy of the tauri crate's
    `mobile/android` project that the Tauri CLI drops there while building an app for
    Android, and it is gitignored, so a fresh checkout cannot run `./gradlew` at all.
    `scripts/materialize-tauri-android.sh` does that copy from the crate source cargo
    already has, and CI runs it before Gradle.
  - The whole kotlin job was run locally under `act` against a Linux Docker host, which
    caught two things a reading would not have: the ktlint step needs a JDK (the npm
    package is a shell wrapper around a jar, and it was ordered before the JDK setup,
    working on GitHub's runners only by accident of a preinstalled Java), and the
    `:tauri-android` problem above, which had been masked locally by a copy left behind
    from an earlier `tauri android` build.
  - ktlint is pinned in all three places. `@naturalcycles/ktlint` is pinned exactly, the
    scripts call it through `pnpm exec` so a Homebrew or `~/.ktlint` binary can no longer
    shadow it, and the Gradle plugin moved from `1.1.1` to the `1.8.0` that ships with it.
  - Link errors are caught without adding a build job. The gap was verified first, by
    renaming an `extern "C"` declaration to a symbol Swift does not export — check,
    clippy and test all passed. `desktop.rs` and `windows.rs` now
    each carry a test that takes the address of every FFI entry point, forcing the linker
    to resolve them, and the same experiment now fails to link. This catches more than a
    build job would, since `cargo build` on a lib crate does not link an executable
    either.
  - `cargo package` runs in the Linux job, the only thing that exercises `build.rs`'s
    packaging branch and proves the crate that would be published builds.
- The expensive keygen probes are now memoized at the platform layer, which also
  resolves the "iOS burns an ephemeral Secure Enclave key on every `generateSecureKey`"
  finding: `Plugin.swift` still calls `checkSupport()`, but the probe inside it now runs
  at most once per process.
- **`generateSecureKey` failed with `errSecAuthFailed` (-25293) for `pinOrBiometric`
  keys on the iOS Simulator (and on any real device with no passcode set), while
  `checkSecureElementSupport()` reported the device as fully capable.** Root cause:
  the capability probe (`isSecureEnclaveAvailable`) creates its test key with
  `kSecAttrIsPermanent: false`, and the Keychain only enforces the `.userPresence`
  access-control flag on items it actually persists — so the probe never exercised the
  passcode requirement that real, permanent `pinOrBiometric` keys are subject to.
  `SecureEnclaveCore.checkDeviceSecure()` now precedes `pinOrBiometric` key generation
  with an explicit `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)` check,
  mirroring Android's `checkDeviceSecure()`/`KeyguardManager.isDeviceSecure` gate, and
  rejects with a clear "no passcode set" message instead of surfacing the raw OSStatus.
  README's iOS platform-limitations section documents the Simulator passcode/biometric
  setup this requires; the previous "Simulator does not support Secure Enclave" line
  was stale left over from before `checkSupport()` was taught to probe (rather than
  hardcode-reject) the Simulator.

---

## Must fix before dropping `-beta`

### 1. ~~Verify `pinOrBiometric` signing on Android API 23-29~~ — moot, `minSdk` raised to 30

`buildPromptInfo` always allows `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`
(`android/src/main/java/SecureKeysPlugin.kt`), and that prompt is passed to
`biometricPrompt.authenticate(promptInfo, cryptoObject)`. androidx.biometric throws
`IllegalArgumentException("Crypto-based authentication is not supported for Device
Credential prior to API 30")` in that combination — confirmed against the
1.1.0 source rather than reproduced on hardware, since there's no longer a supported
device to reproduce it on.

Rather than reproduce-and-work-around this on API 23-29, `android/build.gradle.kts`
now sets `minSdk = 30` (was 23): those are 8+-year-old devices the maintainer has no
way to adequately test against, and androidx.biometric has no stable release newer
than 1.1.0 to fix this with (1.2-1.4 only ever shipped as alphas), so there was no
library-bump fix available anyway. This closes the item instead of implementing it:

- The pre-30 `setUserAuthenticationValidityDurationSeconds(0)` fallback branch in
  `buildKeyGenParameterSpec` is deleted — `AUTH_DEVICE_CREDENTIAL` is unconditional now,
  since API 30 is this library's floor. The "which semantics apply" audit that fallback
  needed is moot along with it.
- README's Android platform-limitations table gained a "Minimum Android version: API
  30+" row and a note explaining why.
- `biometricOnly`'s existing API 30+ gate is now redundant with the plugin-wide floor,
  but left in place — it is what makes the backing-provenance decision in `KeyInfo`
  unambiguous by construction (see the `[x]` item above on `KeyInfo`/`getUserAuthenticationType()`), so removing it is a separate, unrelated change.

- [x] The double-reject risk is real and NOT API-level-specific: if
      `biometricPrompt.authenticate()` throws synchronously for _any_ reason, the throw
      used to escape `signWithKey`'s outer `catch` _after_ `pendingSignInvoke` already
      held the invoke, so the same invoke could be rejected twice. The `authenticate`
      call (`SecureKeysPlugin.kt`, in `signWithBiometricPrompt`) is now wrapped so
      failure goes through `pendingSignInvoke.getAndSet(null)`, like every other exit
      path in that function already does.
- [ ] Add a regression test for the "prompt construction fails" path — **blocked**, not
      done. `signWithBiometricPrompt` requires a real `FragmentActivity` and
      `androidx.biometric.BiometricPrompt`, neither constructible on the host JVM;
      `SecureKeysPlugin` itself can't be instantiated off-device either, since its
      constructor requires a real `Activity` and its superclass is a Tauri `Plugin`.
      This module's unit tests (`PluginUnitTest.kt`) only cover pure functions for
      exactly this reason, and there is no Robolectric dependency or `androidTest`
      source set in this module to fall back to (the vendored `.tauri/tauri-api` has one;
      this plugin's own `android/src/` does not). Covering this for real needs one of:
      add Robolectric (new test dependency, shadows `BiometricPrompt`), or add an
      `androidTest` instrumented suite (needs a device/emulator in CI). Until then this
      path is exercised manually via the test app.

### 2. ~~Write the threat model / security model docs~~ — done

The per-platform boundaries differ sharply and callers cannot infer them. Added a
`## Security model` section to the README and a root `SECURITY.md` with a reporting
address (<dkackman@gmail.com>).

- [x] **Windows `authMode: "none"`** creates a Platform Crypto Provider key that _any_
      process running as the same user can sign with silently, given the key name — and
      the name is `tauri_se_tpm_{app_id}_{key_name}`, derivable from the public app
      identifier. `guest-js/index.ts` documented this already; the README now does too.
- [x] **Windows keys are scoped per-user, not per-app.** `app_id` is only a name prefix,
      so a different app run by the same user can open them. Contrast with iOS/macOS
      (keychain access groups) and Android (per-app keystore), where the OS enforces the
      app boundary.
- [x] **`sanitize_app_id` collisions**: `.` → `_` meant identifiers `a.b` and `a_b` landed
      in the same Windows namespace. **Now fixed rather than only documented**: the
      encoding is injective (`_` doubles to `__`, reserved characters become `_x{HH}`),
      so distinct identifiers always get distinct namespaces. Breaking for existing
      Windows keys created under an identifier containing a reserved character — they
      remain in the provider under the old name and are no longer resolved. Documented
      under "Breaking changes" in the README.
- [x] **Deletion never requires authentication on any platform** (`SecItemDelete`,
      `NCryptDeleteKey`, `keyStore.deleteEntry` all proceed for auth-mandatory keys). Any
      code that can reach the plugin — including injected webview JS holding
      `secure-element:default` — can destroy every key. Documented as an availability
      property, and since **mitigated in three ways**: `allow-delete-key` was removed from
      the default permission set, the recommendation to grant it narrowly stands, and
      `deleteKey` now takes `requireAuth` to gate deletion behind a device-owner
      authentication prompt the plugin enforces itself (LAContext on Apple,
      BiometricPrompt on Android, `IUserConsentVerifierInterop` on Windows). The prompt
      deliberately runs _before_ the key lookup so it cannot be used as an
      existence oracle. **Not yet exercised on hardware on any platform.**
- [x] **The default capability grants all six commands.** `allow-delete-key` has been
      removed from `permissions/default.toml`, so the default set is now the five
      non-destructive commands and deletion requires an explicit grant. README shows a
      minimal sign-only capability alongside it. Breaking for apps that call `deleteKey`
      under `secure-element:default`; the test app's own capability was updated to match.
- [x] What the plugin does _not_ protect against: a compromised renderer can request
      signatures over attacker-chosen bytes for any non-auth key; auth-required keys
      limit this to one signature per user gesture, over data the user cannot see. Also
      documented: no platform exposes key attestation, and the plugin assumes OS/hardware
      security is intact (no protection against a jailbroken/rooted device). Partially
      mitigated since: `signWithKey` takes a caller-supplied `reason` shown in the prompt,
      so the user is told what they are approving. The README is explicit that this is
      app-supplied text no platform binds to the signed bytes.

### 2b. Structured error codes — done

Every failure used to reach JS as a free-form string, and `error_sanitize` replaced it
with a _generic_ string in release builds, so a shipping app could not tell "the user
tapped Cancel" from "hardware failure" from "the key was destroyed". Nothing anywhere
handled Android's `KeyPermanentlyInvalidatedException`, which meant the `biometryCurrentSet`
invalidation documented under item 3 was undetectable as well as unrecoverable — the app
was told to design around a state it had no way to observe.

- [x] `ErrorCode` in `src/error.rs`: `userCancelled`, `authFailed`, `keyInvalidated`,
      `keyNotFound`, `keyAlreadyExists`, `keyNotAccessible`, `deviceNotSecure`,
      `unsupported`, `validation`, `internal`. Errors now serialize as
      `{code, message}` rather than a bare string — breaking for JS callers that read the
      rejection as a string.
- [x] Codes carry no key names or OS status values, so unlike messages they survive
      release-build sanitization intact. Unknown codes collapse to `internal` at both the
      Rust and TypeScript boundaries, so a newer platform layer against older bindings
      degrades rather than erroring twice.
- [x] Per-platform classification. Apple: `SecureEnclaveError.code`, plus
      `classifyAuthError` mapping `LAError`/OSStatus (cancel, auth failure, lockout,
      not-accessible). Android: `classifyBiometricError` over the `BiometricPrompt.ERROR_*`
      codes and `classifyKeyUseException` for `KeyPermanentlyInvalidatedException` —
      Android is the only platform that can report `keyInvalidated` precisely. Windows:
      `classify_ncrypt_error` over NCrypt HRESULTs, including all three spellings of
      "user cancelled" (`NTE_USER_CANCELLED`, `SCARD_W_CANCELLED_BY_USER`,
      `HRESULT_FROM_WIN32(ERROR_CANCELLED)`).
- [x] Codes cross the mobile bridge via Tauri's own `Invoke.reject(message, code)` and
      `ErrorResponse.code`, rather than a message-prefix convention. The macOS FFI carries
      it as a `"code"` field alongside `"error"` in the response JSON.
- [x] `SecureElementError` and `isSecureElementError` in `guest-js`, with every command
      routed through a wrapper so plugin errors and Tauri's own IPC errors reach callers
      in one shape.
- [x] Covered by unit tests on all three: Rust (code round-trip, serialization, FFI
      parsing, NCrypt classification), Kotlin (biometric and key-use classification).
      **The Apple `classifyAuthError` mapping is not exercised on hardware** — the OSStatus
      and `LAError` values it keys on are documented ones, but which of them a given
      failure actually produces is unverified.
- [ ] Apple cannot distinguish an invalidated `.biometryCurrentSet` key from a failed
      authentication — both are `errSecAuthFailed` — so `keyInvalidated` is never reported
      on iOS/macOS. Documented rather than guessed at; worth revisiting if Apple exposes a
      distinct status.

### 3. Reconcile `biometricOnly` docs with behavior

The README auth-mode table says `biometricOnly` is ❌ not supported on iOS/macOS, but
`SecureEnclaveCore.getAccessControlFlags` implements it with `.biometryCurrentSet` and
`checkSupport()` reports `canEnforceBiometricOnly: true` when biometrics are enrolled.
Docs and code disagree on a security-relevant setting.

- [x] Decide which is true and make them agree (the code looks correct — fix the table).
- [x] Document that `.biometryCurrentSet` **permanently invalidates the key when the
      enrolled biometric set changes** — adding a fingerprint or re-enrolling Face ID
      destroys the key and its signing capability forever. This is currently documented
      nowhere and will surprise anyone using `biometricOnly` for anything durable.
- [x] Decide whether `biometricOnly` should use `.biometryAny` instead, which survives
      enrollment changes, and document the tradeoff either way. Decision: keep
      `.biometryCurrentSet` — it matches the strict intent of "biometric only" and
      Android already behaves the same way by default
      (`setInvalidatedByBiometricEnrollment` defaults to `true`), so switching iOS/macOS
      would make it the odd one out rather than more consistent. Tradeoff documented in
      the README.
- [x] Align the semantics of `canEnforceBiometricOnly` across platforms: Apple returns
      _current enrollment_, Android returns _API level ≥ 30_ regardless of enrollment.
      Same field name, two different questions. Android's `checkSecureElementSupport`
      now also requires `checkBiometricAvailability() == null` (live `BiometricManager`
      enrollment check), matching Apple's live-enrollment semantics.

---

## Should fix before 1.0

### 4. Verify Windows Hello prompting during `listKeys` / `generateSecureKey`

`list_ngc_keys` and `key_exists` open NGC keys via `open_key_internal` with
`NCRYPT_FLAGS(0)`, while the enumeration itself and `try_open_key` correctly pass
`NCRYPT_SILENT_FLAG`. If opening or `export_public_key` on an auth-mandatory NGC key
triggers UI, a plain `listKeys()` produces one Windows Hello prompt per key.

- [x] Test on hardware with several `pinOrBiometric` keys present. Confirmed: `listKeys`
      does not prompt with multiple pin/biometric keys present.

### 5. Cross-provider name collisions on Windows

- [x] `key_exists` returned `false` whenever `open_ngc_provider()` failed, letting a TPM
      key be created under a name an NGC key already owned. It now returns
      `crate::Result<bool>` and propagates every failure it can't interpret, so
      `create_key` refuses rather than guessing a name is free. Verified on hardware for
      both `none` and `pinOrBiometric`; a duplicate name still reports `AlreadyExists`.
- [x] `try_open_key` treated `NTE_PERM` as "key not found", conflating a missing key with
      an existing-but-inaccessible one. Left as-is on the `try_open_key_auto` fallback
      path, where that's harmless. Fixed on the path where it isn't: `key_present_in_provider`
      disambiguates `NTE_PERM` via authoritative provider enumeration instead.
- [x] Delete-by-public-key matched a key, then re-resolved it by name instead of deleting
      the match, a race if a same-named key existed in the other provider. `FoundKey` now
      carries the provider alongside the name, and `open_found_key` reopens the exact match.
      Collapsed the near-duplicate `list_keys_from_provider`/`list_ngc_keys` enumeration
      loops into one `find_keys_in_provider`. Behavior change: enumeration failures now
      propagate instead of being skipped, so `listKeys` can error where it used to return a
      partial list, deliberate, since delete-by-public-key reads an empty result as
      "already gone, success" and a swallowed failure would misreport a surviving key as
      deleted. A key that enumerates but can't be opened or exported is still skipped
      rather than propagated (kept tolerant on purpose).
- [x] **Won't do:** exposing provider/auth-mode in `KeyInfo`. No consistent meaning across
      platforms, OS-attested on Windows/Android, but write-only on Apple (the
      `SecAccessControlCreateFlags` used at key creation have no public read accessor), so
      the field would be sometimes-attested with no way to tell which. Nothing downstream
      needs it: `FoundKey` already tracks the provider internally, and callers already know
      the auth mode they requested at creation.

---

## Quality / polish

### Soundness

- [x] `windows.rs:530` — `&*(buffer.as_ptr() as *const TOKEN_USER)` creates a reference
      into a `Vec<u8>` (alignment 1) for a type requiring 8-byte alignment. Creating an
      unaligned reference is UB even if the read never faults; it works today only because
      the allocator happens to return aligned memory. Use `std::ptr::read_unaligned`, or
      allocate the buffer as `Vec<u64>`/via a properly aligned type.
- [x] `KeyNameBufferGuard::as_ref` (`windows_raii.rs`) dereferences a raw pointer in a
      safe `fn` with only a doc comment saying it must be called from an unsafe context.
      Make it `unsafe fn`.

### Everything else

- [x] `der.rs` uses `debug_assert!` for the DER short-form length invariant. Unreachable
      for valid 64-byte input, but returning `Err` costs nothing and removes a
      release-only silent-corruption path.
- [x] `getAccessControlFlags` (`SecureEnclaveCore.swift`) silently downgrades unknown
      auth modes to `.userPresence` via `case "pinOrBiometric", _`. The Rust enum gates
      this today, but the `@_cdecl` FFI entry points are public. Fail closed instead.
- [x] `probeTeeSupport`/`backingOf` report `BACKING_SOFTWARE` whenever a generated key
      can't be inspected (`entry?.privateKey == null`, or `KeyFactory.getKeySpec` throws)
      rather than assuming TEE. The fail-closed design is sound and documented in code;
      what's unverified is whether any real OEM `KeyFactory`/`KeyInfo` implementation
      throws for a key that IS actually hardware-backed (buggy AOSP forks / low-end
      OEMs are the usual suspects), which would false-negative that device. Needs
      physical-device testing across a spread of OEMs and API levels — not
      reproducible in this environment (no real secure hardware in emulators/CI).
- [x] `isEmulator()` fingerprint sniffing is easily defeated and easily wrong. Either
      document `emulated` as best-effort on Android or derive it from the keystore
      security level, which is already being read. (Documented as best-effort — deriving
      from keystore security level was considered and rejected: `BACKING_SOFTWARE` means
      "no hardware backing," which real TEE-less devices also report, so that derivation
      would misclassify genuine hardware as emulated.)
- [x] `signWithKey` marshals `data` as a JSON number array (`guest-js/index.ts`); at the
      1 MB validation ceiling that is ~4 MB of JSON per call. Consider base64 over the
      IPC boundary, or lower the ceiling to something a signing API actually needs.
      (Chose base64: the API deliberately signs raw pre-hash data up to 1 MB, so there's
      no smaller ceiling that's actually correct for the use case. `SignWithKeyRequest`
      now (de)serializes `data` as base64 via a `#[serde(with = "base64_bytes")]` module in
      `models.rs`; `guest-js` base64-encodes before `invoke()`. This also changed what iOS
      gets over the mobile IPC bridge — `SignWithKeyArgs.data` in `Plugin.swift` moved from
      `[UInt8]` to `Data`, which decodes base64 by default. Android's Jackson `ByteArray`
      deserializer already accepts both encodings, so no Kotlin change was needed.)
- [x] Windows error sanitization is inconsistent: the "already exists" and Windows-Hello
      -not-configured messages use plain `format!`, bypassing `sanitize_error`, so
      release builds still emit the key name. (Both now route through `sanitize_error`;
      the Windows-Hello-not-configured message didn't previously name the key at all, so
      the detailed variant now includes it for parity with the rest of the file's debug
      messages, while the release-build generic variant is unchanged.)
- [ ] Android toolchain upgrade — blocks all androidx dependency bumps. Attempted and
      reverted; the constraints are: - **`androidx.biometric` has no stable upgrade.** 1.1.0 (2020) is still the newest
      stable release; 1.2.0, 1.3.0 and 1.4.0 have only ever shipped as alphas. (This no
      longer blocks item 1 — that item closed by raising `minSdk` to 30 rather than by a
      library bump or code change — but the library itself is still stuck on 1.1.0.) - `core-ktx:1.19.0`, `appcompat:1.7.1`, `fragment-ktx:1.8.9` and `material:1.14.0`
      all ship **Kotlin 2.1.0 metadata**, but `settings.gradle` pins Kotlin **1.8.20**
      (and AGP **8.0.2**), which reads at most 1.9.0. Bumping them fails the build with
      "Module was compiled with an incompatible version of Kotlin". - Raising the plugin's Kotlin version is not purely local: this is a **library**,
      and its metadata must be readable by the consuming app. Tauri's generated Android
      project currently uses Kotlin **1.9.25**, so compiling the plugin against 2.x
      would break consumers until Tauri's template moves. Check what Tauri generates
      before touching this. - Sequence when it is time: Tauri template Kotlin version → plugin `settings.gradle`
      (Kotlin + AGP) → `compileOptions`/`jvmTarget` (Java 8 is likely too old for
      AGP 8.1+) → ktlint gradle plugin → then the androidx versions.
- [x] `android/build.gradle.kts` declares `consumerProguardFiles("consumer-rules.pro")`
      but that file does not exist; every build logs
      "Supplied consumer proguard configuration does not exist". Create it or drop the
      declaration.
- [ ] The Android build warns it is "incompatible with Gradle 9.0" (deprecated features).
      Worth resolving as part of the toolchain upgrade above.
- [x] `build.rs` comment says the permissions files are included "via the `include`
      field"; `Cargo.toml` uses `exclude`.
- [x] README's `GenerateSecureKeyResult` omits the `backing` field the API returns.
      Already fixed — the README documents `backing` and its fallback semantics; no
      change needed here.
- [x] README "Platform Limitations → Windows" says TPM 2.0 is supported on Windows 10
      "since version 1507", but the code requires build 14393 (1607) and errors below it.
      Confirmed against `src/windows.rs`'s `require_windows_10_1607` gate and fixed the
      README to state the actual 1607/14393 requirement.
- [ ] Add `CHANGELOG.md` and a stated MSRV / deprecation policy before 1.0.
- [x] `CLAUDE.md` says `tauri` 2.10.1; `Cargo.toml` pins 2.11.5.
- [x] `secure_element_ffi.swift:120` — `var info` is never mutated; should be `let`.
- [x] The Windows Hello prompt string `"Authenticate to sign data"` (`windows.rs`) is
      hardcoded English and not localizable. Fixed, and promoted out of polish: this was
      the mitigation for the documented "the user is not shown what they are signing"
      gap, not just an i18n nit. `signWithKey` now takes an optional `reason` that
      reaches `NCRYPT_USE_CONTEXT_PROPERTY` on Windows, `LAContext.localizedReason` on
      Apple (attached to the key lookup via `kSecUseAuthenticationContext`, so it is still
      in force when `SecKeyCreateSignature` prompts) and `PromptInfo.setSubtitle` on
      Android. The hardcoded strings remain only as fallbacks. Validated at the command
      layer: trimmed, max 200 characters, no control characters, non-blank.
      **Not yet exercised on hardware on any platform.**
- [x] macOS FFI calls run synchronously on the async runtime's worker thread — including
      `sign`, which blocks on a Touch ID prompt. Wrap them in `spawn_blocking` so one
      pending signature can't stall other plugin commands.
      Fixed at the `commands.rs` layer rather than in `desktop.rs`, since the exact same
      bug exists on Windows (`sign_hash_with_window` blocks on a Windows Hello prompt) —
      a new `run_blocking` helper wraps every `SecureElement` call in
      `tauri::async_runtime::spawn_blocking`, fixing both platforms with one change.
      `ping` is left unwrapped since it does no I/O.

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
