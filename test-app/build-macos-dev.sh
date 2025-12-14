#!/bin/bash
# Build and sign macOS app for Secure Enclave development
#
# PREREQUISITES:
# 1. You must have an Apple Developer account (paid or free)
# 2. You must create an App ID at https://developer.apple.com/account/resources/identifiers/list
#    - Bundle ID: net.kackman.secureelement.example
# 3. You must create a Mac Development provisioning profile at:
#    https://developer.apple.com/account/resources/profiles/list
#    - Select "macOS App Development" as the type
#    - Select your App ID (net.kackman.secureelement.example)
#    - Select your Mac Development certificate
#    - Select your Mac device
#    - Download the .mobileprovision file
# 4. Place the downloaded profile as: test-app/embedded.provisionprofile
#
# Then run this script from the test-app directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Configuration
TEAM_ID="86TDY6D9V2"
BUNDLE_ID="net.kackman.secureelement.example"
APP_NAME="test-app"
ENTITLEMENTS="src-tauri/gen/apple/test-app_macOS/test-app_macOS.dev.entitlements"
PROVISIONING_PROFILE="embedded.provisionprofile"

# Check for provisioning profile
if [ ! -f "$PROVISIONING_PROFILE" ]; then
    echo "ERROR: Provisioning profile not found at $PROVISIONING_PROFILE"
    echo ""
    echo "You need to create a Mac Development provisioning profile:"
    echo ""
    echo "1. Go to https://developer.apple.com/account/resources/identifiers/list"
    echo "   - Click '+' to register a new App ID"
    echo "   - Platform: macOS"
    echo "   - Bundle ID: $BUNDLE_ID"
    echo "   - Description: Tauri Secure Element Test App"
    echo ""
    echo "2. Go to https://developer.apple.com/account/resources/profiles/list"
    echo "   - Click '+' to create a new profile"
    echo "   - Select 'macOS App Development'"
    echo "   - Select your App ID ($BUNDLE_ID)"
    echo "   - Select your development certificate"
    echo "   - Select your Mac device(s)"
    echo "   - Download the profile"
    echo ""
    echo "3. Copy the downloaded .mobileprovision file to:"
    echo "   $SCRIPT_DIR/$PROVISIONING_PROFILE"
    echo ""
    exit 1
fi

# Check for entitlements
if [ ! -f "$ENTITLEMENTS" ]; then
    echo "ERROR: Entitlements file not found at $ENTITLEMENTS"
    exit 1
fi

# Find signing identity
IDENTITY=$(security find-identity -v -p codesigning | grep "Apple Development" | head -1 | sed 's/.*"\(.*\)".*/\1/')
if [ -z "$IDENTITY" ]; then
    echo "ERROR: No Apple Development signing identity found."
    echo "Make sure you have a valid development certificate installed."
    exit 1
fi

echo "=== Building macOS App for Secure Enclave Development ==="
echo "Team ID: $TEAM_ID"
echo "Bundle ID: $BUNDLE_ID"
echo "Signing Identity: $IDENTITY"
echo ""

# Step 1: Build the Tauri app as a bundle (debug mode)
echo "Step 1: Building Tauri app bundle..."
pnpm tauri build --debug --bundles app

# The bundle should be at target/debug/bundle/macos/test-app.app
BUNDLE_PATH="src-tauri/target/debug/bundle/macos/${APP_NAME}.app"

if [ ! -d "$BUNDLE_PATH" ]; then
    echo "ERROR: Bundle not found at $BUNDLE_PATH"
    echo "Make sure 'pnpm tauri build --debug --bundles app' succeeded."
    exit 1
fi

echo "Bundle found at: $BUNDLE_PATH"

# Step 2: Copy provisioning profile into bundle
echo ""
echo "Step 2: Embedding provisioning profile..."
cp "$PROVISIONING_PROFILE" "$BUNDLE_PATH/Contents/embedded.provisionprofile"

# Step 3: Remove existing signature (if any)
echo ""
echo "Step 3: Removing existing signature..."
codesign --remove-signature "$BUNDLE_PATH" 2>/dev/null || true

# Step 4: Sign the bundle with entitlements
echo ""
echo "Step 4: Signing bundle with entitlements..."
codesign --force \
    --sign "$IDENTITY" \
    --entitlements "$ENTITLEMENTS" \
    --timestamp \
    --options runtime \
    "$BUNDLE_PATH"

# Step 5: Verify the signature and entitlements
echo ""
echo "Step 5: Verifying signature..."
codesign -dv --verbose=4 "$BUNDLE_PATH" 2>&1 | head -20

echo ""
echo "Step 6: Verifying entitlements..."
codesign -d --entitlements - "$BUNDLE_PATH" 2>&1

echo ""
echo "=== Build Complete ==="
echo ""
echo "The signed app bundle is at:"
echo "  $BUNDLE_PATH"
echo ""
echo "To run: open '$BUNDLE_PATH'"
echo ""
echo "Or run directly: '$BUNDLE_PATH/Contents/MacOS/$APP_NAME'"
echo ""
