# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries cover the plugin (`tauri-plugin-secure-element` on crates.io,
`tauri-plugin-secure-element-api` on npm); the two are versioned and released
together.

## [Unreleased]

## [0.1.0-beta.9] - 2026-08-02

### Added

- `deleteKey` accepts `requireAuth`/`reason` options: an explicit device-owner
  authentication check before destruction, since no platform authenticates key
  deletion on its own. Deletion of a nonexistent key still prompts, so the
  prompt cannot be used as a key-existence oracle.
- `SECURITY.md` and a "Security model" README section documenting key
  isolation, unauthenticated deletion, and what the plugin does not protect
  against.
- Swift unit tests now run in CI against an iOS simulator; Kotlin unit tests
  run in CI via Gradle.

### Changed

- **Breaking (Android):** minimum SDK raised to 30. Pre-30 devices cannot
  persist the biometric-only requirement at the key level and had unreliable
  BiometricPrompt behavior.
- `signWithKey` payloads cross the IPC boundary base64-encoded in both
  directions — the request `data` and the response `signature` — instead of as
  JSON number arrays (~4x smaller). Transparent to callers of the JS API, which
  still takes and returns `Uint8Array`.
- Secure-element calls run on a blocking thread pool so an in-flight
  authentication prompt no longer stalls unrelated plugin commands.
- `getAccessControlFlags` (Apple) fails on unrecognized auth modes instead of
  silently downgrading.

### Fixed

- Key-existence checks and deletion logic no longer permit name collisions.
- Synchronous exceptions during Android biometric authentication no longer
  cause a double rejection.
- Error messages for key creation and Windows Hello configuration are
  sanitized in release builds.

## [0.1.0-beta.8] - 2026-07-26

Packaging-only iterations (beta.6 and beta.7 were superseded within hours):
verification of the npm tarball contents and entry points, so a build that
emits type declarations to the wrong path can no longer publish.

## [0.1.0-beta.5] - 2026-07-26

### Added

- Package entry-point verification (`verify:package`) wired into CI and
  `prepublishOnly`.
- CI runs the full test suites; the release workflow reuses the entire CI
  workflow as a gate instead of a partial copy.
- Secure-element backing-tier detection and reporting without creating
  throwaway test keys.
- The Android plugin module builds and tests standalone (see
  `scripts/materialize-tauri-android.sh`).

### Changed

- **Breaking (Windows):** key names now escape the app identifier injectively.
  Keys created by an earlier beta under an app identifier containing `.`, `/`,
  `:` or other reserved characters resolve under the old name and will not be
  found (they still exist in the provider). Windows only.
- Secure-element keys are scoped to the plugin's own namespace.
- Windows NGC (Windows Hello) keys enforce authentication on each use.
- NGC key-creation errors surface after the legacy code path also fails,
  instead of being swallowed.

## [0.1.0-beta.4] - 2026-02-22

### Changed

- **Breaking:** removed the `hardwareBacking` property from the
  `generateSecureKey` response (superseded by the `backing` field).
- Key deletion asks for confirmation in the test app; error messages carry
  more detail in debug builds.
- Windows handle management moved to std `OwnedHandle`.
- Test app rebuilt around tabbed navigation with a dedicated
  integration-test and test-vector UI.

## [0.1.0-beta.3] - 2026-02-04

Documentation and formatting fixes only.

## [0.1.0-beta.2] - 2026-02-03

### Added

- TPM 2.0 detection on Windows, including firmware-vs-discrete backing tiers.
- Per-operation Windows Hello authentication.
- Input validation rejects empty strings.

### Fixed

- JSON escaping in the Swift layer.
- Memory leak in Windows key enumeration (`enum_state`); memory allocated
  across the Swift FFI boundary is freed on panic.
- Capabilities are cached where genuinely immutable; the plugin runs on the
  iOS simulator with emulation reported by the capabilities check.

## [0.1.0-beta.1] - 2026-01-01

### Added

- Windows support: NCrypt-backed keys (Platform Crypto Provider and Windows
  Hello/NGC), RAII wrappers for all NCrypt handles, keys scoped to the Tauri
  app identifier, raw-to-DER ECDSA signature conversion.
- Error sanitization: detailed messages in debug builds, generic in release.
- Key creation refuses auth modes the device cannot currently satisfy.

## [0.1.0-alpha.3] through [0.1.0-alpha.5] - 2025-12

Initial platform bring-up: Secure Enclave (iOS/macOS), Android Keystore
(StrongBox and TEE), the six-command API surface (`ping`,
`generateSecureKey`, `listKeys`, `signWithKey`, `deleteKey`,
`checkSecureElementSupport`), and the test app.

[Unreleased]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.9...HEAD
[0.1.0-beta.9]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.8...v0.1.0-beta.9
[0.1.0-beta.8]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.5...v0.1.0-beta.8
[0.1.0-beta.5]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.4...v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/dkackman/tauri-plugin-secure-element/compare/v0.1.0-alpha.5...v0.1.0-beta.1
[0.1.0-alpha.5]: https://github.com/dkackman/tauri-plugin-secure-element/releases/tag/v0.1.0-alpha.5
[0.1.0-alpha.3]: https://github.com/dkackman/tauri-plugin-secure-element/releases/tag/v0.1.0-alpha.3
