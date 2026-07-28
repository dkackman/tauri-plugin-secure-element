#!/usr/bin/env bash
#
# Materialises ios/.tauri/tauri-api, the "Tauri" package ios/Package.swift depends on
# via `.package(name: "Tauri", path: "../.tauri/tauri-api")`.
#
# It is a copy of the tauri crate's own mobile/ios-api Swift package. Normally the
# Tauri CLI drops it there while building an app for iOS — nothing in this
# repository's build does it, and it is gitignored, so a fresh checkout cannot run
# `swift build`/`swift test` against ios/Package.swift at all. This performs the same
# copy straight from the crate source cargo has already downloaded, which is what
# makes `swift test` runnable in CI without building an entire iOS app first.
#
# Safe to re-run: an existing copy is replaced.
set -euo pipefail

cd "$(dirname "$0")/.."

tauri_src=$(
  cargo metadata --format-version 1 | python3 -c '
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

dest="ios/.tauri/tauri-api"
mkdir -p "$(dirname "$dest")"
rm -rf "$dest"
cp -R "$ios_src" "$dest"

echo "Materialised $dest from $ios_src"
