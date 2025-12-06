# macOS Secure Enclave Troubleshooting Guide

## ⚠️ CRITICAL: Do NOT Use `tauri dev` for Secure Enclave Testing

**Error -34018 will ALWAYS occur with `pnpm tauri dev` or `cargo run`** because:
- Development mode doesn't create a proper .app bundle
- Entitlements are NOT applied to non-bundled binaries
- macOS Keychain requires proper code signing for Secure Enclave access

### ✅ SOLUTION: Use the Proper Build Script

```bash
# From the repository root:
./build-and-sign-dev.sh

# Then run the app:
open test-app/src-tauri/target/debug/bundle/macos/test-app.app
```

This script:
1. Builds a proper .app bundle (even for debug builds)
2. Code signs it with entitlements
3. Allows Keychain access for Secure Enclave

---

## Common Errors and Solutions

### Error -34018: errSecMissingEntitlement

**Symptom:**
```
Error: The operation couldn't be completed. (OSStatus error -34018 - failed to add key to keychain: ...)
```

**Cause:**
This error occurs when:
1. The app doesn't have proper entitlements for Keychain access
2. The access control flags are incorrect for Secure Enclave keys
3. Code signing is not properly configured

**Solutions:**

#### 1. ✅ Fixed in Latest Version

The latest version includes the proper access control flags (`.privateKeyUsage`) which resolve this issue for most cases.

#### 2. Ensure Entitlements File Exists

Check that `test-app/src-tauri/Entitlements.plist` exists with these contents:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>$(AppIdentifierPrefix)com.tauri.secureelement.example</string>
    </array>

    <key>com.apple.security.application-groups</key>
    <array>
        <string>$(TeamIdentifierPrefix)com.tauri.secureelement.example</string>
    </array>
</dict>
</plist>
```

#### 3. Verify tauri.conf.json Configuration

Ensure `test-app/src-tauri/tauri.conf.json` includes:

```json
{
  "bundle": {
    "macOS": {
      "entitlements": "Entitlements.plist",
      "signingIdentity": "-"
    }
  }
}
```

#### 4. Clean and Rebuild

```bash
cd test-app
rm -rf src-tauri/target
pnpm tauri dev
```

#### 5. Verify Code Signing (For Releases)

For production builds:

```bash
# Check if the app is properly signed
codesign -dv --verbose=4 test-app/src-tauri/target/release/bundle/macos/test-app.app

# Verify entitlements are applied
codesign -d --entitlements - test-app/src-tauri/target/release/bundle/macos/test-app.app
```

### Error -25293: errSecItemNotFound

**Symptom:**
```
Error: Key not found: my-key-name
```

**Cause:**
Trying to use a key that doesn't exist or was deleted.

**Solution:**
- Generate the key first using `generateSecureKey()`
- Check available keys using `listKeys()`

### Error -50: errSecParam

**Symptom:**
```
Error: One or more parameters passed to a function were not valid
```

**Cause:**
- Invalid key name (empty string, special characters)
- Invalid data to sign (empty array)

**Solution:**
- Use alphanumeric key names with hyphens/underscores only
- Ensure data is a non-empty Uint8Array or number array

### Error: "Secure Enclave not available"

**Symptom:**
```json
{
  "secureElementSupported": false,
  "teeSupported": false
}
```

**Cause:**
This is expected on:
- Intel Macs without T2 chip (pre-2018 models)
- macOS running in virtual machines
- Non-macOS systems

**Solution:**
This is not an error - the hardware doesn't support Secure Enclave. Check `checkSecureElementSupport()` before attempting operations:

```javascript
const support = await checkSecureElementSupport();
if (!support.secureElementSupported) {
  console.log("Secure Enclave not available on this hardware");
  // Use alternative auth method
  return;
}
```

### Build Errors

#### "swiftc: command not found"

**Solution:**
```bash
xcode-select --install
```

#### "Framework not found: Security"

**Solution:**
Ensure you're building on macOS. The Security framework is macOS-only.

#### Linker errors with libSecureElementSwift.a

**Solution:**
```bash
cd tauri-plugin-secure-element
cargo clean
cargo build
```

## Hardware Requirements

### Supported Hardware

✅ **Apple Silicon Macs (M1/M2/M3)**
- MacBook Air (2020+)
- MacBook Pro (2020+)
- Mac mini (2020+)
- iMac (2021+)
- Mac Studio (2022+)
- Mac Pro (2023+)

✅ **Intel Macs with T2 Chip**
- MacBook Air (2018-2020)
- MacBook Pro (2018-2020)
- Mac mini (2018-2020)
- iMac (2020)
- iMac Pro (2017+)
- Mac Pro (2019-2022)

❌ **Intel Macs without T2**
- All pre-2018 Macs
- Some 2018 iMacs

### Checking Your Hardware

```bash
# Check for Apple Silicon
uname -m
# arm64 = Apple Silicon ✅
# x86_64 = Intel (may or may not have T2)

# Check for T2 chip (Intel Macs only)
system_profiler SPiBridgeDataType
# If you see "Apple T2 Security Chip" then ✅
# If "No drivers loaded" then ❌
```

## Testing Checklist

After fixing error -34018, test all functionality:

- [ ] Build succeeds without errors
- [ ] `checkSecureElementSupport()` returns `true`
- [ ] Can generate a key
- [ ] Key appears in `listKeys()`
- [ ] Can sign data with the key
- [ ] Signature length is ~70-72 bytes
- [ ] Two signatures of same data are different (ECDSA randomness)
- [ ] Can delete the key
- [ ] Key no longer appears in `listKeys()`
- [ ] Signing with deleted key fails appropriately

Use the included test script:

```bash
./test-macos-build.sh
```

Or the JavaScript test suite in your app console:

```javascript
// Copy test-secure-enclave.js contents to browser console
await testSecureEnclave();
```

## Debug Mode

To see detailed FFI bridge logs, modify `FFIBridge.swift` to add logging:

```swift
import os.log

let logger = OSLog(subsystem: "com.tauri.secureelement", category: "FFI")

// In functions:
os_log("Generating key: %{public}@", log: logger, type: .debug, keyName)
```

Then view logs:

```bash
# In one terminal - start the app
cd test-app && pnpm tauri dev

# In another terminal - watch logs
log stream --predicate 'subsystem == "com.tauri.secureelement"' --level debug
```

## Getting Help

If you're still experiencing issues:

1. **Verify Hardware Support:**
   ```bash
   system_profiler SPiBridgeDataType
   ```

2. **Check App Entitlements:**
   ```bash
   codesign -d --entitlements - /path/to/app
   ```

3. **Review Build Logs:**
   ```bash
   cd tauri-plugin-secure-element
   cargo clean
   cargo build 2>&1 | tee build.log
   ```

4. **Test Manually in Swift:**
   ```bash
   cd macos/Sources
   swiftc -o test FFIBridge.swift -framework Security -framework Foundation
   ```

5. **File an Issue:**
   Include:
   - macOS version: `sw_vers`
   - Hardware: `system_profiler SPHardwareDataType | grep "Model\|Chip"`
   - Build logs
   - Runtime error messages

## Next Steps

Once error -34018 is resolved:

1. ✅ Rebuild the project:
   ```bash
   cd test-app
   pnpm tauri dev
   ```

2. ✅ Run the test suite (see test-secure-enclave.js)

3. ✅ Verify all operations work

4. 🎉 Start using Secure Enclave in your app!

## Production Deployment

For production apps:

1. **Obtain Apple Developer Certificate**
   - Free for development (`signingIdentity: "-"`)
   - Required for distribution ($99/year)

2. **Update Identifiers**
   - Change `com.tauri.secureelement.example` to your app ID
   - Update both `tauri.conf.json` and `Entitlements.plist`

3. **Enable Hardened Runtime**
   ```json
   {
     "bundle": {
       "macOS": {
         "entitlements": "Entitlements.plist",
         "hardenedRuntime": true
       }
     }
   }
   ```

4. **Test on Clean System**
   - The error -34018 can behave differently on development vs production builds
   - Always test the final .app bundle on a clean Mac

## Reference

- [Apple TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychain-apis-and-implementations)
- [Storing Keys in the Secure Enclave](https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave)
- [SecAccessControlCreateFlags](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)
- [OSStatus Error Codes](https://www.osstatus.com)
