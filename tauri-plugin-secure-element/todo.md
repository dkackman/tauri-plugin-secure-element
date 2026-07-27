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

- [x] `key_exists` returned `false` whenever `open_ngc_provider()` failed, so a TPM key
      could be created under a name an NGC key already owned. `open_key_auto` always
      resolves NGC first, so sign/delete hit a different key than the one just created,
      and `list_keys` returned two entries with the same `keyName`. `key_exists` now
      returns `crate::Result<bool>` and propagates every failure it cannot interpret —
      SID lookup, either provider open, and any unrecognized `NCryptOpenKey` error — so
      `create_key` refuses rather than guessing that a name is free. It also probes
      silently now. Verified on hardware: `generateSecureKey` still succeeds for both
      `none` and `pinOrBiometric` — the case that matters, since creating a plain TPM key
      now depends on `open_ngc_provider()` succeeding — and a duplicate name still reports
      `AlreadyExists`.
- [x] `try_open_key` treats `NTE_PERM` as "key not found". The comment justifies it — the
      NGC provider returns access-denied for keys that don't exist — but it conflates the
      other direction too: an NGC key that exists and is genuinely inaccessible reads as
      absent. Left as-is on the `try_open_key_auto` path, where the conflation is safe
      (the caller falls through to the other provider and a wrong answer costs a
      misleading "not found", not a wrong key). Fixed where it is _not_ safe: the new
      `key_present_in_provider` disambiguates `NTE_PERM` by enumerating the provider,
      which is authoritative and needs no access to the key. Enumeration there goes
      through a new `enumerate_key_names` that propagates errors, unlike the display
      listing paths which stop at the first failure and return a short list.
- [x] Delete-by-public-key matched a key, took `keys[0].key_name`, then re-resolved _by
      name_ (`desktop.rs`) instead of deleting the key it matched. A new `FoundKey`
      carries the provider and the provider-qualified name alongside the name and public
      key; `find_keys` returns those and `open_found_key` reopens the matched key in the
      provider it was found in, so delete-by-public-key no longer goes back through
      name resolution. This did not need the public `KeyInfo` change below — `list_keys`
      is now a thin projection of `find_keys`, so the provider stays internal to the
      Windows layer until that item is taken up. - Collapsed `list_keys_from_provider` and `list_ngc_keys`, which were near-identical
      copies of the same unsafe enumeration loop, into one `find_keys_in_provider` over
      `enumerate_key_names`. The two differed only in how a caller-facing name is
      recovered from an enumerated one, which is now a closure parameter. - **Behavior change beyond the bullet:** `find_keys` propagates provider-open and
      enumeration failures instead of skipping that provider, so `listKeys` now errors
      where it used to return a partial list. Deliberate — delete-by-public-key treats
      an empty result as "already gone, success", so a swallowed enumeration failure
      there reports a key destroyed that still exists. It also makes the pre-existing
      "propagate provider errors" comment in `desktop.rs` true, which it was not. - Residual: a key that enumerates but cannot be opened or exported is still skipped
      rather than propagated, so it too reads as "already gone" on a delete-by-public-key.
      Left tolerant on purpose — one unreadable key should not break `listKeys` entirely.
- [x] Return the provider/auth-mode in `KeyInfo` so callers can tell a silent TPM key
      from a Hello-protected one. **Decision: won't do — dropped deliberately, do not
      re-propose without new platform capability.** It cannot be given the same meaning
      on all four platforms: - Windows: OS-attested and free. NGC vs Platform Crypto Provider is already
      computed at enumeration and lives in `FoundKey`. - Android: OS-attested, one `KeyFactory.getKeySpec(privateKey, KeyInfo::class.java)`
      per key per listing — a metadata read of the Keymaster characteristics, so no
      prompt. `isUserAuthenticationRequired()` is API 23+; the `biometricOnly` vs
      `pinOrBiometric` discriminator `getUserAuthenticationType()` is API 30+, but
      `biometricOnly` is already rejected below 30, so it is unambiguous by construction. - Apple: **not recoverable at all.** All three modes are created with the same
      `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; the only difference is the
      `SecAccessControlCreateFlags`, and `SecAccessControl` has no public flags
      accessor (`SecAccessControlCreateWithFlags` and `SecAccessControlGetTypeID` are
      the whole API). The mode is write-only: converted to flags at creation and
      discarded.

      So the field would be OS-attested on two platforms and self-persisted on the third,
              with no way for a caller to tell which one they are holding — the same trap as the
              old `canEnforceBiometricOnly` split (one field name, two different questions), which
              was fixed by aligning semantics rather than shipping the ambiguity. For a field
              whose whole purpose is informing a security decision, sometimes-attested is worse
              than absent. Apple keys created before any such change would also have no recorded
              mode, so it could never be more than optional anyway.

              Nothing needs it: the delete-by-public-key fix carries the provider internally in
              `FoundKey` and never exposes it, and the caller already knows the mode because they
              passed it to `generateSecureKey`. Persisting it is the app's job, which the app can
              do reliably on all four platforms.

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
- [x] `android/build.gradle.kts` declares `consumerProguardFiles("consumer-rules.pro")`
      but that file does not exist; every build logs
      "Supplied consumer proguard configuration does not exist". Create it or drop the
      declaration.
- [ ] The Android build warns it is "incompatible with Gradle 9.0" (deprecated features).
      Worth resolving as part of the toolchain upgrade above.
- [x] `build.rs` comment says the permissions files are included "via the `include`
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
