# Tauri Plugin Secure Element

A Tauri plugin that provides access to platform-specific secure hardware for cryptographic key storage and operations.

## Features

- **Hardware-Backed Key Storage**: Keys are stored in dedicated secure hardware (Secure Enclave, StrongBox, etc.)
- **EC P-256 Support**: Generate and use NIST P-256 elliptic curve keys
- **ECDSA Signing**: Sign data using hardware-protected keys with SHA-256
- **Runtime Capability Detection**: Check platform support at runtime
- **Cross-Platform API**: Consistent API across iOS, Android, and macOS

## Platform Support

| Platform | Secure Element | TEE Support | Coverage | Status |
|----------|----------------|-------------|----------|--------|
| iOS 12+ | ✅ Secure Enclave | ✅ Secure Enclave | ~95% | ✅ Supported |
| Android 9+ | ✅ StrongBox | ✅ TEE | ~90% / ~99% | ✅ Supported |
| macOS 10.13+ | ✅ Secure Enclave | ✅ Secure Enclave | ~95% (T2/M-series) | ✅ **NEW** |
| Windows | ❌ Not Implemented | ❌ Not Implemented | N/A | 🔜 Planned |
| Linux | ❌ Not Implemented | ❌ Not Implemented | N/A | 🔜 Planned |

### Hardware Requirements

#### iOS
- All physical iOS devices (iPhone, iPad) with iOS 12+
- Simulator: Returns `secureElementSupported: false`

#### Android
- **StrongBox**: Android 9+ devices with dedicated hardware security module
- **TEE**: Android 4.3+ devices with hardware-backed keystore
- Automatic fallback from StrongBox to TEE if StrongBox unavailable

#### macOS
- **Apple Silicon**: All M1, M2, M3, M4 series Macs (2020+)
- **Intel with T2**: Macs with T2 Security Chip (2018-2020)
  - MacBook Air 2018+
  - MacBook Pro 2018+
  - Mac mini 2018+
  - iMac 2019+, iMac Pro 2017+
  - Mac Pro 2019+
- **Intel without T2**: Returns `secureElementSupported: false`

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Node.js](https://nodejs.org/) (version 20.19+ or 22.12+)
- [pnpm](https://pnpm.io/) (package manager)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (installed via pnpm)
- [Setup system dependencies for Tauri](https://v2.tauri.app/start/prerequisites/)

## Installation

- Install dependencies:

```bash
pnpm install
```

## Building

### Build the Plugin

Build the Rust plugin and JavaScript bindings:

```bash
cd tauri-plugin-secure-element
pnpm build
```

This will:

- Compile the Rust plugin code
- Build the TypeScript guest JavaScript code into `dist-js/`

### Build the Example App

Build the example Tauri application:

```bash
cd test-app
pnpm build
```

The example app's `prebuild` script will automatically build the plugin first.

### Build Everything

From the plugin root directory:

```bash
pnpm build
```

Or use the VS Code task "build-all" to build everything in sequence.

## Running

### Run the Test App in Development Mode

```bash
cd test-app
pnpm tauri ios dev      # iOS
pnpm tauri android dev  # Android
pnpm tauri dev          # macOS/Windows/Linux
```

## API Usage

### Check Platform Support

Always check if secure element hardware is available before attempting operations:

```javascript
import { checkSecureElementSupport } from 'tauri-plugin-secure-element-api';

const { secureElementSupported, teeSupported } = await checkSecureElementSupport();

if (!secureElementSupported) {
  console.warn("Secure Element not available on this device");
  // Fall back to alternative authentication method
}
```

### Generate a Key

Generate an EC P-256 key in the secure element:

```javascript
import { generateSecureKey } from 'tauri-plugin-secure-element-api';

try {
  const { publicKey, keyName } = await generateSecureKey("my-signing-key");
  console.log("Public key (base64):", publicKey);
  // Store publicKey for verification, send to server, etc.
} catch (error) {
  console.error("Failed to generate key:", error);
}
```

### List Keys

Retrieve all keys or filter by name/public key:

```javascript
import { listKeys } from 'tauri-plugin-secure-element-api';

// List all keys
const { keys } = await listKeys();
console.log("All keys:", keys);
// [{ keyName: "key1", publicKey: "..." }, { keyName: "key2", publicKey: "..." }]

// Filter by name
const { keys: filtered } = await listKeys("my-signing-key");

// Filter by public key
const { keys: matching } = await listKeys(undefined, publicKeyBase64);
```

### Sign Data

Sign data using a stored key:

```javascript
import { signWithKey } from 'tauri-plugin-secure-element-api';

const message = "Hello, Secure Element!";
const data = new TextEncoder().encode(message);

const { signature } = await signWithKey("my-signing-key", Array.from(data));
console.log("Signature:", signature);
// Signature is ECDSA with SHA-256, in DER format
```

### Delete a Key

Remove a key from secure storage:

```javascript
import { deleteKey } from 'tauri-plugin-secure-element-api';

const { success } = await deleteKey("my-signing-key");
console.log("Deleted:", success);
// Returns true even if key didn't exist (idempotent)
```

### Complete Example

```javascript
import {
  checkSecureElementSupport,
  generateSecureKey,
  signWithKey,
  listKeys,
  deleteKey
} from 'tauri-plugin-secure-element-api';

async function setupSecureAuth() {
  // 1. Check support
  const support = await checkSecureElementSupport();
  if (!support.secureElementSupported && !support.teeSupported) {
    throw new Error("No secure hardware available");
  }

  // 2. Generate key
  const { publicKey } = await generateSecureKey("auth-key");

  // 3. Register public key with server
  await fetch("/api/register-key", {
    method: "POST",
    body: JSON.stringify({ publicKey })
  });

  // 4. Sign challenge
  const challenge = await fetchChallenge();
  const { signature } = await signWithKey("auth-key", challenge);

  // 5. Verify with server
  const verified = await verifySignature(challenge, signature);
  return verified;
}
```

## API Reference

### `checkSecureElementSupport()`
Check if secure hardware is available.

**Returns:**
```typescript
{
  secureElementSupported: boolean;  // True if dedicated secure element available
  teeSupported: boolean;            // True if any TEE/hardware backing available
}
```

### `generateSecureKey(keyName: string)`
Generate an EC P-256 key in secure hardware.

**Parameters:**
- `keyName`: Unique identifier for the key

**Returns:**
```typescript
{
  publicKey: string;  // Base64-encoded DER public key
  keyName: string;    // Echo of the key name
}
```

### `listKeys(keyName?: string, publicKey?: string)`
List stored keys with optional filtering.

**Parameters:**
- `keyName` (optional): Filter by key name
- `publicKey` (optional): Filter by public key

**Returns:**
```typescript
{
  keys: Array<{
    keyName: string;
    publicKey: string;  // Base64-encoded DER
  }>;
}
```

### `signWithKey(keyName: string, data: number[])`
Sign data using a stored key.

**Parameters:**
- `keyName`: Key to use for signing
- `data`: Byte array to sign

**Returns:**
```typescript
{
  signature: number[];  // ECDSA signature (DER format)
}
```

### `deleteKey(keyName: string)`
Delete a key from secure storage.

**Parameters:**
- `keyName`: Key to delete

**Returns:**
```typescript
{
  success: boolean;  // Always true (idempotent)
}
```

## Security Properties

### iOS & macOS
- Keys stored in **Secure Enclave** (dedicated security coprocessor)
- Private keys **never leave** the Secure Enclave
- Keys are **non-exportable**
- Keys accessible only when device is **unlocked**

### Android
- Keys stored in **StrongBox** (dedicated HSM) or **TEE** (Trusted Execution Environment)
- Private keys **hardware-isolated** from Android OS
- Keys are **non-exportable**
- Automatic fallback: StrongBox → TEE → Software (plugin uses hardware only)

### Cryptographic Details
- **Algorithm**: NIST P-256 (secp256r1) elliptic curve
- **Key Size**: 256 bits
- **Signing**: ECDSA with SHA-256 digest
- **Signature Format**: DER-encoded (X9.62 on iOS/macOS)
- **Public Key Format**: DER/X.509 encoding, base64 string

## Error Handling

```javascript
try {
  await generateSecureKey("my-key");
} catch (error) {
  if (error.includes("Unsupported")) {
    // Platform doesn't support secure elements
    console.warn("Secure Element not available, using fallback");
  } else if (error.includes("Failed to create key")) {
    // Hardware error or permission denied
    console.error("Hardware security module unavailable");
  } else {
    // Other error
    console.error("Unexpected error:", error);
  }
}
```

## Development

```bash
cd test-app
pnpm tauri ios dev      # iOS
pnpm tauri android dev  # Android
pnpm tauri dev          # macOS/Windows/Linux
```
