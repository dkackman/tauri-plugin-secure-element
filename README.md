# Tauri Plugin Secure Element

A Tauri plugin for secure element functionality on Windows (TPM 2.0), macOS & iOS (Secure Enclave) and Android (StrongBox & TEE).

[![npm](https://img.shields.io/npm/v/tauri-plugin-secure-element-api)](https://www.npmjs.com/package/tauri-plugin-secure-element-api)
[![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/tauri-plugin-secure-element)](https://crates.io/crates/tauri-plugin-secure-element)

- Generate hardware-backed keys and sign with them, without the private key ever leaving the secure element
- List, inspect and delete keys
- Report what hardware backing a device actually has, and what a given key actually got
- `none`, `pinOrBiometric` and `biometricOnly` authentication modes
- One API across macOS, Windows, iOS and Android

> **Using the plugin in your app?** The consumer documentation — installation, API
> reference, error codes, platform limitations and the **security model** — lives in
> **[`tauri-plugin-secure-element/README.md`](tauri-plugin-secure-element/README.md)**,
> which is also what renders on
> [npm](https://www.npmjs.com/package/tauri-plugin-secure-element-api) and
> [crates.io](https://crates.io/crates/tauri-plugin-secure-element). This file covers
> working on the repository itself.
>
> Read the [security model](tauri-plugin-secure-element/README.md#security-model) before
> relying on the plugin for anything where the per-platform differences matter — key
> isolation, deletion and silent signing do not behave the same way on every platform.

> **Beta.** Every release so far is a prerelease and the API may still change between
> betas. See [`tauri-plugin-secure-element/todo.md`](tauri-plugin-secure-element/todo.md)
> for the known issues and the remaining work before 1.0.

## Repository layout

A pnpm workspace monorepo:

| Path                                                       | What it is                                                              |
| ---------------------------------------------------------- | ----------------------------------------------------------------------- |
| [`tauri-plugin-secure-element/`](tauri-plugin-secure-element/) | The plugin — Rust core, Swift (iOS/macOS), Kotlin (Android), TS bindings |
| [`test-app/`](test-app/)                                    | A Tauri app exercising the plugin on each platform                       |
| [`docs/`](docs/)                                            | Platform setup guides, notably macOS code signing                        |

Within the plugin, three files are worth knowing about because their purpose isn't
obvious from the name:

- `src/error_sanitize.rs` — returns detailed errors in debug builds and generic ones in release, so failures don't leak key names or OS status values
- `src/der.rs` — converts the raw ECDSA R‖S signatures NCrypt produces into DER, so Windows signatures match the other platforms
- `src/windows_raii.rs` — RAII wrappers for NCrypt handles; Windows code goes through these rather than raw handles

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable)
- [Node.js](https://nodejs.org/) 20.19+ or 22.12+, and [pnpm](https://pnpm.io/)
- [Tauri system dependencies](https://v2.tauri.app/start/prerequisites/)

Per platform:

- **iOS** — Xcode; swiftformat and swiftlint for the lint tasks
- **Android** — Android Studio and the Android SDK. Do **not** install ktlint yourself: the lint scripts run `pnpm exec ktlint`, which resolves the pinned `@naturalcycles/ktlint`, and `android/build.gradle.kts` hands the ktlint Gradle plugin that same version. A `ktlint` on `PATH` from Homebrew or `~/.ktlint` is a different version that will disagree with CI about the same files; if you bump one, bump all three.
- **macOS** — Xcode for the Secure Enclave FFI, plus a provisioning profile (see [`docs/macos-development.md`](docs/macos-development.md))
- **Windows** — Visual Studio Build Tools and the Windows SDK, for Windows Hello and TPM

## Build

```bash
pnpm install
pnpm build
```

Build order matters: the plugin's TypeScript bindings (`dist-js/`) must exist before the
test app builds. `pnpm build` from the root handles this in dependency order, and the test
app's `prebuild`/`predev` scripts do it automatically.

### Gradle needs `.tauri/tauri-api` first

To run anything Gradle in `tauri-plugin-secure-element/android` — `./gradlew test`,
`ktlintCheck` — `android/.tauri/tauri-api` has to exist. It is the `:tauri-android`
project that `settings.gradle` includes: a copy of the tauri crate's own `mobile/android`
library that the Tauri CLI drops there while building an app for Android. It is gitignored
and no build step in this repository creates it, so on a fresh checkout Gradle fails with
`No matching variant of project :tauri-android ... No variants exist`. Run
`scripts/materialize-tauri-android.sh` (what CI does) to copy it from the crate source
cargo has already downloaded.

## Running the test app

```bash
cd test-app

pnpm tauri ios dev        # iOS
pnpm tauri android dev    # Android
pnpm tauri dev            # Windows
```

**macOS** needs a provisioning profile and special code signing — `pnpm tauri dev` will
not work, because it runs the raw binary without a bundle structure or a signed
provisioning profile. See the
**[macOS Development Guide](docs/macos-development.md)**, then:

```bash
cd test-app
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/test-app.app
```

**Windows** needs a TPM 2.0 device and Windows 10 1607 (build 14393) or higher.

Secure element features need real hardware — simulators and emulators have no hardware
security module, and report themselves as emulated.

## Before committing

```bash
pnpm format   # Format all code
pnpm lint     # Rust, Swift and Kotlin lints
pnpm build    # Everything builds
```

Rust tests run with `cargo test`; Kotlin unit tests with `./gradlew test` from
`tauri-plugin-secure-element/android` (after the `.tauri/tauri-api` step above). CI runs
all of these on Linux, macOS and Windows, and every job gates a release.

## Debugging

Use the VS Code launch configurations in `.vscode/launch.json`. Android logs:
`./adb-logs.sh`.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md). For what the plugin does and
does not protect against, see the
[security model](tauri-plugin-secure-element/README.md#security-model).

## License

Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- [Plugin documentation](tauri-plugin-secure-element/README.md)
- [Repository](https://github.com/dkackman/tauri-plugin-secure-element)
- [Issues](https://github.com/dkackman/tauri-plugin-secure-element/issues)
