# macOS Secure Enclave Development Guide

This guide explains how to set up and run the Tauri Secure Element plugin on macOS with Secure Enclave support.

## Background

The Secure Enclave on macOS uses the **data protection keychain**, which has strict code signing requirements. Unlike iOS where apps are automatically signed through Xcode, macOS development builds require additional setup to access the Secure Enclave.

### Why Special Setup is Needed

The macOS Secure Enclave requires:

1. **Restricted entitlements** that must be authorized by a provisioning profile:
   - `com.apple.application-identifier`
   - `com.apple.developer.team-identifier`
   - `keychain-access-groups`

2. **A provisioning profile** embedded in the app bundle at `Contents/embedded.provisionprofile`

3. **An app bundle structure** (not a raw binary)

Simply signing with `codesign` is insufficient - the OS validates that restricted entitlements are authorized by a provisioning profile.

> **Note:** Running `tauri dev` will NOT work for Secure Enclave testing because it runs the raw binary without a bundle structure or provisioning profile.

## Prerequisites

- An Apple Developer account (free or paid)
- Xcode installed with command line tools
- A Mac with Apple Silicon (M1 or later) for Secure Enclave hardware support

## Setup Instructions

### Step 1: Create an App ID

1. Go to [Apple Developer - Identifiers](https://developer.apple.com/account/resources/identifiers/list)
2. Click the **+** button to register a new identifier
3. Select **App IDs** and click **Continue**
4. Select **App** and click **Continue**
5. Fill in the details:
   - **Platform:** macOS
   - **Description:** Tauri Secure Element Test App
   - **Bundle ID:** Select "Explicit" and enter `com.tauri.secureelement.example`
6. Click **Continue**, then **Register**

### Step 2: Register Your Mac Device

1. Go to [Apple Developer - Devices](https://developer.apple.com/account/resources/devices/list)
1. Click the **+** button to register a new device
1. Select **macOS** as the platform
1. Get your Mac's hardware UUID:

```bash
system_profiler SPHardwareDataType | grep "Hardware UUID"
```

1. Enter your device name and the UUID
1. Click **Continue**, then **Register**

### Step 3: Create a Provisioning Profile

1. Go to [Apple Developer - Profiles](https://developer.apple.com/account/resources/profiles/list)
2. Click the **+** button to create a new profile
3. Select **macOS App Development** and click **Continue**
4. Select your App ID (`com.tauri.secureelement.example`) and click **Continue**
5. Select your development certificate and click **Continue**
6. Select your Mac device(s) and click **Continue**
7. Enter a profile name (e.g., "Tauri Secure Element Dev") and click **Generate**
8. Download the `.mobileprovision` file

### Step 4: Install the Provisioning Profile

Copy the downloaded provisioning profile to the test-app directory:

```bash
cp ~/Downloads/Tauri_Secure_Element_Dev.mobileprovision test-app/embedded.provisionprofile
```

### Step 5: Verify Your Signing Identity

Check that you have a valid development certificate:

```bash
security find-identity -v -p codesigning
```

You should see an entry like:

```
1) XXXXXXXX "Apple Development: your@email.com (XXXXXX)"
```

### Step 6: Build and Sign the App

From the repository root:

```bash
cd test-app
./build-macos-dev.sh
```

This script will:

1. Build the Tauri app as a bundle (debug mode)
2. Embed the provisioning profile
3. Sign the bundle with the required entitlements
4. Verify the signature

### Step 7: Run the App

```bash
open src-tauri/target/debug/bundle/macos/test-app.app
```

Or run directly:

```bash
./src-tauri/target/debug/bundle/macos/test-app.app/Contents/MacOS/test-app
```

## Troubleshooting

### Error: `-34018` (errSecMissingEntitlement)

This error means the app is not properly signed with the required entitlements. Check:

1. **Provisioning profile is embedded:**

   ```bash
   ls -la src-tauri/target/debug/bundle/macos/test-app.app/Contents/embedded.provisionprofile
   ```

2. **Entitlements are correct:**

   ```bash
   codesign -d --entitlements - src-tauri/target/debug/bundle/macos/test-app.app
   ```

   You should see:
   - `com.apple.application-identifier`
   - `com.apple.developer.team-identifier`
   - `keychain-access-groups`

3. **Team ID matches:** Ensure the Team ID in your entitlements matches your provisioning profile.

### Error: "Killed" or App Won't Launch

This usually means code signing failed or the signature is invalid. Try:

```bash
codesign -vv src-tauri/target/debug/bundle/macos/test-app.app
```

If you see errors, re-run `./build-macos-dev.sh`.

### Error: "No provisioning profile found"

Make sure the profile is in the correct location:

```bash
test-app/embedded.provisionprofile
```

### Checking Runtime Entitlements

To verify entitlements are actually available at runtime, check the system log:

```bash
log stream --predicate 'subsystem == "com.apple.securityd"' --level debug
```

## Development Workflow

Since `tauri dev` doesn't work with Secure Enclave, use this workflow:

1. **Make code changes** to the plugin or test app
1. **Rebuild and sign:**

```bash
cd test-app
./build-macos-dev.sh
```

1. **Run the signed app:**

```bash
open src-tauri/target/debug/bundle/macos/test-app.app
```

For frontend-only changes, you can run the Vite dev server separately and point the signed app to it (advanced setup).

## Configuration Files

### Entitlements (`test-app_macOS.dev.entitlements`)

Located at `test-app/src-tauri/gen/apple/test-app_macOS/test-app_macOS.dev.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>com.apple.application-identifier</key>
        <string>TEAM_ID.com.tauri.secureelement.example</string>
        <key>com.apple.developer.team-identifier</key>
        <string>TEAM_ID</string>
        <key>keychain-access-groups</key>
        <array>
            <string>TEAM_ID.com.tauri.secureelement.example</string>
        </array>
    </dict>
</plist>
```

Replace `TEAM_ID` with your actual Apple Developer Team ID.

### Tauri Config (`tauri.conf.json`)

The macOS signing configuration in `test-app/src-tauri/tauri.conf.json`:

```json
{
  "bundle": {
    "macOS": {
      "signingIdentity": "Apple Development: your@email.com (XXXXXX)",
      "entitlements": "gen/apple/test-app_macOS/test-app_macOS.dev.entitlements"
    }
  }
}
```

## References

- [Apple TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)
- [Apple TN3125: Inside Code Signing: Provisioning Profiles](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
- [Tauri macOS Code Signing](https://v2.tauri.app/distribute/sign/macos/)
- [Apple Developer Forums: -34018 when using Secure Enclave](https://developer.apple.com/forums/thread/728150)
