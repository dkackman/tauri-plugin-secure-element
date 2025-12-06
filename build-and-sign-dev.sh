#!/bin/bash
# Build and sign the test app for Secure Enclave testing
# This script creates a properly signed .app bundle that can access the Keychain

set -e

echo "🔨 Building Secure Enclave Test App"
echo "===================================="
echo ""

cd "$(dirname "$0")/test-app"

# Check we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ ERROR: This script must be run on macOS"
    exit 1
fi

echo "📦 Step 1: Building app bundle..."
pnpm tauri build --debug

APP_PATH="src-tauri/target/debug/bundle/macos/test-app.app"

if [ ! -d "$APP_PATH" ]; then
    echo "❌ ERROR: App bundle not found at $APP_PATH"
    exit 1
fi

echo "✅ App built successfully"
echo ""

echo "🔑 Step 2: Code signing with entitlements..."

# Ad-hoc sign the app with entitlements
# This is required for Keychain access even in development
codesign --force --deep --sign - \
    --entitlements src-tauri/Entitlements.plist \
    "$APP_PATH"

if [ $? -eq 0 ]; then
    echo "✅ App signed successfully"
else
    echo "❌ ERROR: Code signing failed"
    exit 1
fi

echo ""

echo "🔍 Step 3: Verifying entitlements..."
echo ""
codesign -d --entitlements - "$APP_PATH"
echo ""

echo "✅ Step 4: Verification complete"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ BUILD COMPLETE!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🚀 To run the app:"
echo "   open $APP_PATH"
echo ""
echo "Or run directly:"
echo "   $APP_PATH/Contents/MacOS/test-app"
echo ""
echo "⚠️  IMPORTANT:"
echo "   - This build includes proper code signing for Keychain access"
echo "   - Error -34018 should NOT occur with this build"
echo "   - Use this method instead of 'pnpm tauri dev' for Secure Enclave testing"
echo ""
