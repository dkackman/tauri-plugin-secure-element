#!/usr/bin/env bash
#
# Materialises .tauri/tauri-api (at the plugin crate root, a sibling of ios/), the
# "Tauri" package ios/Package.swift depends on via
# `.package(name: "Tauri", path: "../.tauri/tauri-api")` — that path is relative to
# ios/Package.swift itself, so it resolves one directory above ios/, not inside it.
#
# It is a copy of the tauri crate's own mobile/ios-api Swift package. Normally the
# Tauri CLI drops it there while building an app for iOS — nothing in this
# repository's build does it, and it is gitignored, so a fresh checkout cannot run
# `swift build`/`swift test` against ios/Package.swift at all. This performs the same
# copy straight from the crate source cargo has already downloaded, which is what
# makes `swift test` runnable in CI without building an entire iOS app first.
#
# The tauri version comes from the test app's lockfile, not a fresh resolution. This
# plugin directory has no Cargo.lock, so a bare `cargo metadata` here would resolve
# whatever the newest tauri 2.x is today. test-app/src-tauri/Cargo.lock is the pinned
# version the repo actually builds against, and newer tauri Gradle/Swift scripts can
# need a newer Kotlin plugin than android/settings.gradle pins (tauri 2.12.5's
# mobile/android uses `compilerOptions`, which Kotlin Gradle plugin 1.8.20 rejects).
#
# Safe to re-run: an existing copy is replaced.
set -euo pipefail

cd "$(dirname "$0")/.."
manifest="$(pwd)/../test-app/src-tauri/Cargo.toml"

tauri_src=$(
  cargo metadata --format-version 1 --manifest-path "$manifest" | python3 -c '
import json, os, sys

meta = json.load(sys.stdin)
manifests = [p["manifest_path"] for p in meta["packages"] if p["name"] == "tauri"]
if len(manifests) != 1:
    sys.exit(f"expected exactly one tauri package, found {len(manifests)}")
print(os.path.dirname(manifests[0]))
'
)

ios_src="$tauri_src/mobile/ios-api"
if [ ! -d "$ios_src" ]; then
  echo "tauri crate at $tauri_src has no mobile/ios-api directory" >&2
  exit 1
fi

dest=".tauri/tauri-api"
mkdir -p "$(dirname "$dest")"
rm -rf "$dest"
cp -R "$ios_src" "$dest"

echo "Materialised $dest from $ios_src"
