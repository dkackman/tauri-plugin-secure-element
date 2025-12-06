#!/bin/bash
# Test script for macOS Secure Enclave FFI implementation
# Run this on macOS to verify the build and basic functionality

set -e

echo "🔍 macOS Secure Enclave Build Test"
echo "=================================="
echo ""

# Check we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ ERROR: This script must be run on macOS"
    exit 1
fi

echo "✅ Running on macOS"
echo ""

# Check for required tools
echo "🔧 Checking build tools..."

if ! command -v swiftc &> /dev/null; then
    echo "❌ ERROR: swiftc not found. Install Xcode Command Line Tools:"
    echo "   xcode-select --install"
    exit 1
fi
echo "  ✅ swiftc: $(swiftc --version | head -n1)"

if ! command -v cargo &> /dev/null; then
    echo "❌ ERROR: cargo not found. Install Rust from https://rustup.rs"
    exit 1
fi
echo "  ✅ cargo: $(cargo --version)"

if ! command -v ar &> /dev/null; then
    echo "❌ ERROR: ar not found"
    exit 1
fi
echo "  ✅ ar: found"

echo ""

# Navigate to plugin directory
cd "$(dirname "$0")/tauri-plugin-secure-element"

echo "📦 Building Rust plugin with Swift FFI bridge..."
echo ""

# Clean previous builds
cargo clean

# Build
echo "Running: cargo build"
if cargo build 2>&1 | tee build.log; then
    echo ""
    echo "✅ BUILD SUCCESSFUL!"
    echo ""

    # Check that Swift library was created
    if ls target/debug/build/tauri-plugin-secure-element-*/out/libSecureElementSwift.a 1> /dev/null 2>&1; then
        LIBPATH=$(ls target/debug/build/tauri-plugin-secure-element-*/out/libSecureElementSwift.a | head -n1)
        echo "✅ Swift static library created: $LIBPATH"
        echo "   Size: $(du -h "$LIBPATH" | cut -f1)"
        echo ""
    else
        echo "⚠️  WARNING: Swift static library not found"
        echo ""
    fi

    # Check that the built library has the expected symbols
    echo "🔍 Verifying FFI symbols..."
    BUILT_LIB=$(find target/debug -name "libtauri_plugin_secure_element.dylib" -o -name "libtauri_plugin_secure_element.so" | head -n1)

    if [ -f "$BUILT_LIB" ]; then
        echo "Checking symbols in: $BUILT_LIB"

        # Check for key FFI functions
        if nm "$BUILT_LIB" 2>/dev/null | grep -q "secure_element_check_support"; then
            echo "  ✅ secure_element_check_support found"
        else
            echo "  ⚠️  secure_element_check_support NOT found"
        fi

        if nm "$BUILT_LIB" 2>/dev/null | grep -q "secure_element_generate_key"; then
            echo "  ✅ secure_element_generate_key found"
        else
            echo "  ⚠️  secure_element_generate_key NOT found"
        fi

        if nm "$BUILT_LIB" 2>/dev/null | grep -q "secure_element_sign_data"; then
            echo "  ✅ secure_element_sign_data found"
        else
            echo "  ⚠️  secure_element_sign_data NOT found"
        fi
        echo ""
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "✅ BUILD COMPLETE!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Next steps:"
    echo "1. Test in the demo app:"
    echo "   cd ../test-app"
    echo "   pnpm tauri dev"
    echo ""
    echo "2. In the app, test the API:"
    echo "   - Check support (should return true on Apple Silicon/T2 Macs)"
    echo "   - Generate a key"
    echo "   - Sign data"
    echo "   - List keys"
    echo "   - Delete key"
    echo ""
    echo "See MACOS_FFI_IMPLEMENTATION.md for detailed testing instructions."
    echo ""

    exit 0
else
    echo ""
    echo "❌ BUILD FAILED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Check build.log for details"
    echo ""
    echo "Common issues:"
    echo "1. Missing Xcode Command Line Tools:"
    echo "   xcode-select --install"
    echo ""
    echo "2. Swift compiler not found:"
    echo "   Make sure you're on macOS"
    echo ""
    echo "3. Framework linking errors:"
    echo "   This is normal on non-macOS systems"
    echo ""

    exit 1
fi
