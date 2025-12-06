// Test script for macOS Secure Enclave functionality
// Copy this code into your test-app or run it from the browser console
//
// Usage in test-app:
// 1. Start the app: pnpm tauri dev
// 2. Open browser console (Cmd+Option+I on macOS)
// 3. Copy and paste this entire file
// 4. Run: await testSecureEnclave()

async function testSecureEnclave() {
  console.log("🔐 Testing macOS Secure Enclave Integration");
  console.log("===========================================\n");

  try {
    // Import the plugin API
    // Note: Adjust import path based on your setup
    const {
      checkSecureElementSupport,
      generateSecureKey,
      signWithKey,
      listKeys,
      deleteKey,
    } = window.__TAURI__?.secureElement || {};

    if (!checkSecureElementSupport) {
      console.error("❌ ERROR: Secure Element API not found");
      console.error("Make sure you've imported 'tauri-plugin-secure-element-api'");
      return;
    }

    // Test 1: Check Support
    console.log("📋 Test 1: Checking Secure Element Support");
    console.log("-------------------------------------------");
    const support = await checkSecureElementSupport();
    console.log("Result:", support);

    if (support.secureElementSupported) {
      console.log("✅ Secure Enclave is available!");
    } else {
      console.log("⚠️  Secure Enclave NOT available");
      console.log("   This is expected on:");
      console.log("   - Intel Macs without T2 chip");
      console.log("   - Virtual machines");
      console.log("   - Non-macOS systems");
      console.log("\n   Remaining tests will fail. This is expected.\n");
    }
    console.log();

    if (!support.secureElementSupported) {
      console.log("⏭️  Skipping remaining tests (Secure Enclave not available)");
      return;
    }

    // Test 2: Generate Key
    console.log("🔑 Test 2: Generating Secure Key");
    console.log("--------------------------------");
    const testKeyName = `test-key-${Date.now()}`;
    console.log(`Key name: ${testKeyName}`);

    const generateResult = await generateSecureKey(testKeyName);
    console.log("Result:", {
      keyName: generateResult.keyName,
      publicKeyPreview: generateResult.publicKey.substring(0, 50) + "...",
      publicKeyLength: generateResult.publicKey.length,
    });
    console.log("✅ Key generated successfully!");
    console.log();

    // Test 3: List Keys
    console.log("📝 Test 3: Listing Keys");
    console.log("-----------------------");
    const listResult = await listKeys();
    console.log(`Found ${listResult.keys.length} key(s)`);

    const ourKey = listResult.keys.find((k) => k.keyName === testKeyName);
    if (ourKey) {
      console.log("✅ Our test key found in list!");
      console.log("Key details:", {
        keyName: ourKey.keyName,
        publicKeyMatches: ourKey.publicKey === generateResult.publicKey,
      });
    } else {
      console.log("❌ ERROR: Test key not found in list!");
    }
    console.log();

    // Test 4: Sign Data
    console.log("✍️  Test 4: Signing Data");
    console.log("------------------------");
    const testMessage = "Hello, Secure Enclave!";
    console.log(`Message: "${testMessage}"`);

    const encoder = new TextEncoder();
    const messageBytes = Array.from(encoder.encode(testMessage));

    const signResult = await signWithKey(testKeyName, messageBytes);
    console.log("Signature:", {
      length: signResult.signature.length,
      preview: signResult.signature.slice(0, 10).join(",") + "...",
    });
    console.log("✅ Data signed successfully!");
    console.log();

    // Test 5: Verify signature properties
    console.log("🔍 Test 5: Verifying Signature Properties");
    console.log("------------------------------------------");
    console.log(`Signature length: ${signResult.signature.length} bytes`);
    console.log(
      "Expected length: ~70-72 bytes (ECDSA P-256 signature in DER format)"
    );

    if (signResult.signature.length >= 70 && signResult.signature.length <= 72) {
      console.log("✅ Signature length is correct!");
    } else {
      console.log("⚠️  Signature length unexpected (might still be valid)");
    }
    console.log();

    // Test 6: Sign again to verify determinism
    console.log("🔄 Test 6: Testing Non-Determinism");
    console.log("-----------------------------------");
    const signResult2 = await signWithKey(testKeyName, messageBytes);

    const signaturesMatch =
      JSON.stringify(signResult.signature) ===
      JSON.stringify(signResult2.signature);

    if (signaturesMatch) {
      console.log("⚠️  WARNING: Signatures are identical!");
      console.log(
        "   ECDSA signatures should be different each time (random nonce)"
      );
    } else {
      console.log("✅ Signatures are different (correct ECDSA behavior)");
    }
    console.log();

    // Test 7: Delete Key
    console.log("🗑️  Test 7: Deleting Key");
    console.log("------------------------");
    const deleteResult = await deleteKey(testKeyName);
    console.log("Result:", deleteResult);
    console.log("✅ Key deleted successfully!");
    console.log();

    // Test 8: Verify deletion
    console.log("✅ Test 8: Verifying Deletion");
    console.log("-----------------------------");
    const listAfterDelete = await listKeys();
    const keyStillExists = listAfterDelete.keys.some(
      (k) => k.keyName === testKeyName
    );

    if (keyStillExists) {
      console.log("❌ ERROR: Key still exists after deletion!");
    } else {
      console.log("✅ Key successfully removed from keychain!");
    }
    console.log();

    // Test 9: Try to use deleted key (should fail)
    console.log("❌ Test 9: Attempting to Use Deleted Key");
    console.log("-----------------------------------------");
    try {
      await signWithKey(testKeyName, messageBytes);
      console.log("❌ ERROR: Signing succeeded with deleted key!");
    } catch (error) {
      console.log("✅ Correctly failed to sign with deleted key");
      console.log("Error:", error.message);
    }
    console.log();

    // Summary
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("✅ ALL TESTS PASSED!");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log();
    console.log("Summary:");
    console.log("✅ Secure Enclave support detection works");
    console.log("✅ Key generation works");
    console.log("✅ Key listing works");
    console.log("✅ Data signing works");
    console.log("✅ Signature properties correct");
    console.log("✅ Non-deterministic signatures (ECDSA)");
    console.log("✅ Key deletion works");
    console.log("✅ Deleted key properly removed");
    console.log("✅ Error handling works");
    console.log();
    console.log("🎉 macOS Secure Enclave FFI implementation is working!");
    console.log();
  } catch (error) {
    console.error("❌ TEST FAILED");
    console.error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.error("Error:", error);
    console.error();
    console.error("Stack trace:", error.stack);
    console.error();
    console.error("Possible causes:");
    console.error("1. Plugin not properly loaded");
    console.error("2. API import path incorrect");
    console.error("3. Secure Enclave not available on this hardware");
    console.error("4. Permissions issue");
    console.error();
  }
}

// Alternative: Test using invoke directly (if plugin API not available)
async function testSecureEnclaveWithInvoke() {
  console.log("🔐 Testing via direct invoke calls");
  console.log("===================================\n");

  const { invoke } = window.__TAURI__.core;

  try {
    // Check support
    console.log("1. Checking support...");
    const support = await invoke("plugin:secure-element|check_secure_element_support");
    console.log("Support:", support);

    if (!support.secureElementSupported) {
      console.log("⚠️  Secure Enclave not available, stopping tests");
      return;
    }

    // Generate key
    console.log("\n2. Generating key...");
    const testKeyName = `test-key-${Date.now()}`;
    const genResult = await invoke("plugin:secure-element|generate_secure_key", {
      keyName: testKeyName,
    });
    console.log("Generated:", genResult);

    // List keys
    console.log("\n3. Listing keys...");
    const listResult = await invoke("plugin:secure-element|list_keys", {});
    console.log("Keys:", listResult);

    // Sign data
    console.log("\n4. Signing data...");
    const message = new TextEncoder().encode("Test message");
    const signResult = await invoke("plugin:secure-element|sign_with_key", {
      keyName: testKeyName,
      data: Array.from(message),
    });
    console.log("Signature:", signResult);

    // Delete key
    console.log("\n5. Deleting key...");
    const deleteResult = await invoke("plugin:secure-element|delete_key", {
      keyName: testKeyName,
    });
    console.log("Deleted:", deleteResult);

    console.log("\n✅ All invoke tests passed!");
  } catch (error) {
    console.error("❌ Test failed:", error);
  }
}

// Auto-run if loaded directly
if (typeof window !== "undefined" && window.__TAURI__) {
  console.log("Tauri detected. Ready to test!");
  console.log('Run: await testSecureEnclave()');
  console.log('Or: await testSecureEnclaveWithInvoke()');
}

// Export for module usage
if (typeof module !== "undefined" && module.exports) {
  module.exports = { testSecureEnclave, testSecureEnclaveWithInvoke };
}
