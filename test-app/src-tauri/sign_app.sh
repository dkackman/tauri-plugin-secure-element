#!/bin/bash
# Sign the macOS app with entitlements for Secure Enclave access
APP_PATH="target/debug/bundle/macos/test-app.app"
ENTITLEMENTS="gen/apple/test-app_macOS/test-app_macOS.entitlements"

if [ -d "$APP_PATH" ]; then
    echo "Signing $APP_PATH with entitlements..."
    codesign --force --deep --sign - --entitlements "$ENTITLEMENTS" "$APP_PATH"
    echo "Done!"
else
    echo "App not found at $APP_PATH"
fi
