#!/usr/bin/env bash
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <tag>"
    echo "Example: $0 v0.1.0-beta.4"
    exit 1
fi

TAG="$1"

# Ensure tag starts with 'v'
if [[ "$TAG" != v* ]]; then
    echo "Error: tag must start with 'v' (e.g. v0.1.0-beta.4)"
    exit 1
fi

# Ensure working tree is clean
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Error: working tree has uncommitted changes. Commit or stash them first."
    exit 1
fi

echo "Tagging $TAG and pushing..."

git tag "$TAG" -m "Release $TAG"
git push origin HEAD
git push origin "$TAG"

echo "Done. Release workflow triggered for $TAG."

echo "Run the following command to update the npm dist-tag:"
echo "npm dist-tag add tauri-plugin-secure-element-api@$TAG latest"
