#!/usr/bin/env bash
#
# Materialises android/.tauri/tauri-api, the :tauri-android project that
# android/settings.gradle includes.
#
# It is a copy of the tauri crate's own mobile/android library project. Normally the
# Tauri CLI drops it there while building an app for Android — nothing in this
# repository's build does it, and it is gitignored, so a fresh checkout cannot run
# ./gradlew at all. This performs the same copy straight from the crate source cargo
# has already downloaded, which is what makes `./gradlew test` runnable in CI without
# building an entire Android app first.
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

android_src="$tauri_src/mobile/android"
if [ ! -d "$android_src" ]; then
  echo "tauri crate at $tauri_src has no mobile/android directory" >&2
  exit 1
fi

dest="android/.tauri/tauri-api"
mkdir -p "$(dirname "$dest")"
rm -rf "$dest"
cp -R "$android_src" "$dest"

echo "Materialised $dest from $android_src"
