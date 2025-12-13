#!/bin/bash
# Sign the macOS app with entitlements for Secure Enclave access
# Usage: ./sign_app.sh [debug|release]
# Defaults to debug if not specified

BUILD_TYPE="${1:-debug}"
APP_PATH="target/${BUILD_TYPE}/bundle/macos/test-app.app"
ENTITLEMENTS="gen/apple/test-app_macOS/test-app_macOS.entitlements"

if [ -d "$APP_PATH" ]; then
    echo "Signing $APP_PATH with entitlements..."
    codesign --force --deep --sign - --entitlements "$ENTITLEMENTS" "$APP_PATH"
    echo "Done! App signed with entitlements for Secure Enclave access."
else
    echo "App not found at $APP_PATH"
    echo "Make sure you've built the app first with: pnpm tauri build"
    exit 1
fi
