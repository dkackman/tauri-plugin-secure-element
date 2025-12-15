# Tauri Plugin Secure Element

A Tauri plugin for secure element functionality.

![npm](https://img.shields.io/npm/v/tauri-plugin-secure-element-api)
![Crates.io Downloads (latest version)](https://img.shields.io/crates/dv/tauri-plugin-secure-element)

## Prerequisites

- [Rust](https://www.rust-lang.org/) (latest stable version)
- [Node.js](https://nodejs.org/) (version 20.19+ or 22.12+)
- [pnpm](https://pnpm.io/) (package manager)
- [Tauri CLI](https://tauri.app/v1/guides/getting-started/prerequisites) (installed via pnpm)
- [Setup system dependencies for Tauri](https://v2.tauri.app/start/prerequisites/)

## Install and Build

```bash
pnpm install
pnpm build
```

This will install dependencies, build the plugin, its js bindings and the test app front-end.

## Running

### iOS

```bash
pnpm tauri ios dev
```

### Android

```bash
cd test-app
pnpm tauri android dev
```

### macOS

macOS Secure Enclave access requires special code signing setup with a provisioning profile. See the **[macOS Development Guide](docs/macos-development.md)** for detailed instructions.

Quick start (after setup):

```bash
cd test-app
./build-macos-dev.sh
open src-tauri/target/debug/bundle/macos/test-app.app
```

## Using Tauri Plugin Secure Element

A Tauri plugin for secure element functionality on iOS (Secure Enclave) and Android (Strongbox and TEE).

## Features

- Generate secure keys using hardware-backed secure storage
- Sign data with keys stored in secure elements
- List and manage secure keys
- Check secure element support on the device
- Support for biometric and PIN authentication modes
- Cross-platform support for iOS and Android

### Installation

#### npm

```bash
npm install tauri-plugin-secure-element-api
# or
pnpm add tauri-plugin-secure-element-api
# or
yarn add tauri-plugin-secure-element-api
```

#### Cargo

```toml
[dependencies]
tauri-plugin-secure-element = "0.1.0"
```

### Setup

Add the plugin to your `tauri.conf.json`:

```json
{
  "plugins": {
    "secure-element": {
      "all": true
    }
  }
}
```

### Usage

```typescript
import {
  checkSecureElementSupport,
  generateSecureKey,
  listKeys,
  signWithKey,
  deleteKey,
  type AuthenticationMode,
} from "tauri-plugin-secure-element-api";

// Check if secure element is supported
const support = await checkSecureElementSupport();
console.log("Secure element supported:", support.secureElementSupported);

// Generate a new secure key
const { publicKey, keyName } = await generateSecureKey(
  "my-key-name",
  "pinOrBiometric" // or 'none' or 'biometricOnly'
);

// List all keys
const keys = await listKeys();

// Sign data with a key
const data = new Uint8Array([1, 2, 3, 4]);
const signature = await signWithKey("my-key-name", data);

// Delete a key
await deleteKey("my-key-name");
```

## API Reference

### `checkSecureElementSupport()`

Returns information about secure element support on the device.

**Returns:** `Promise<SecureElementSupport>`

```typescript
interface SecureElementSupport {
  secureElementSupported: boolean;
  teeSupported: boolean;
  canEnforceBiometricOnly: boolean;
}
```

### `generateSecureKey(keyName: string, authMode?: AuthenticationMode)`

Generates a new secure key in the device's secure element.

**Parameters:**

- `keyName`: Unique name for the key
- `authMode`: Authentication mode (`'none'`, `'pinOrBiometric'`, or `'biometricOnly'`)

**Returns:** `Promise<{ publicKey: string; keyName: string }>`

### `listKeys(keyName?: string, publicKey?: string)`

Lists keys stored in the secure element. Can filter by key name or public key.

**Returns:** `Promise<KeyInfo[]>`

```typescript
interface KeyInfo {
  keyName: string;
  publicKey: string;
  requiresAuthentication?: boolean;
}
```

### `signWithKey(keyName: string, data: Uint8Array)`

Signs data using a key stored in the secure element.

**Parameters:**

- `keyName`: Name of the key to use
- `data`: Data to sign as `Uint8Array`

**Returns:** `Promise<Uint8Array>` - The signature

### `deleteKey(keyName?: string, publicKey?: string)`

Deletes a key from the secure element. At least one parameter must be provided.

**Returns:** `Promise<boolean>` - Success status

## Platform Support

- **iOS**: Uses Secure Enclave for key generation and signing
- **Android**: Uses Strongbox and TEE (Trusted Execution Environment) when available

## License

Apache-2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
