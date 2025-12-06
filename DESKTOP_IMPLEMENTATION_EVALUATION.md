# Desktop Secure Element Support Evaluation

## Executive Summary

The secure element plugin currently supports iOS (Secure Enclave) and Android (StrongBox/TEE). This document evaluates the feasibility of implementing equivalent functionality on desktop platforms (macOS, Windows, Linux) where TEE support is more varied.

**Key Findings:**
- ✅ **macOS**: Excellent support via Secure Enclave (T2/M-series chips)
- ⚠️ **Windows**: Good support via TPM 2.0, requires capability detection
- ⚠️ **Linux**: Varied support, requires runtime capability detection

---

## Current API Requirements

Based on iOS/Android implementations, desktop must support:

1. **`generate_secure_key(key_name)`** - EC P-256 key generation in secure hardware
2. **`list_keys(filter?)`** - Enumerate stored keys
3. **`sign_with_key(key_name, data)`** - ECDSA-SHA256 signing
4. **`delete_key(key_name)`** - Remove keys
5. **`check_secure_element_support()`** - Report hardware capabilities

### Cryptographic Requirements
- **Algorithm**: EC P-256 (secp256r1)
- **Signing**: ECDSA with SHA-256
- **Key Storage**: Hardware-backed, non-exportable private keys
- **Public Key Export**: DER/X.509 format, base64 encoded
- **Key Persistence**: Permanent storage (survives app restarts)

---

## Platform Evaluation

### 1. macOS

#### Hardware Support
- **Secure Enclave**: Available on Macs with:
  - **T2 Security Chip** (2018-2020 Intel Macs)
  - **Apple Silicon** (M1, M2, M3, etc.)
- **Coverage**: ~95% of Macs still in use (2018+)

#### API Access
- **Framework**: Security Framework (same as iOS)
- **Language**: Swift/Objective-C
- **Rust Integration**: Via `security-framework` crate

#### Capabilities
```rust
// Capability detection (similar to iOS)
pub enum SecureHardwareType {
    SecureEnclave,  // T2 or Apple Silicon
    None,
}

pub struct MacOSCapabilities {
    secure_element_supported: bool,  // Secure Enclave available
    tee_supported: bool,             // Same as secure_element (macOS)
}
```

#### Implementation Strategy
```swift
// Use kSecAttrTokenIDSecureEnclave (iOS code is directly portable)
let attributes: [String: Any] = [
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrIsPermanent as String: true,
    kSecPrivateKeyAttrs as String: [
        kSecAttrApplicationTag as String: keyName.data(using: .utf8)!
    ]
]
```

**Pros:**
- ✅ iOS code is ~95% reusable
- ✅ Consistent API across Apple platforms
- ✅ Excellent hardware coverage on modern Macs
- ✅ No additional dependencies

**Cons:**
- ❌ Older Macs (pre-2018) lack Secure Enclave
- ❌ Requires runtime detection

**Recommendation**: **High Priority** - Easy to implement, high success rate

---

### 2. Windows

#### Hardware Support
- **TPM 2.0**: Available on:
  - All Windows 11 PCs (required)
  - Most Windows 10 PCs (2016+)
  - Firmware TPM (fTPM) on AMD/Intel CPUs
- **Coverage**: ~85% of Windows PCs

#### API Access
- **Framework**: Windows CNG (Cryptography API: Next Generation)
- **Language**: Win32 API (C/C++)
- **Rust Integration**: Via `windows-rs` crate

#### Capabilities
```rust
pub enum SecureHardwareType {
    TPM20,          // Discrete or firmware TPM 2.0
    TPM12,          // Legacy TPM (limited support)
    PlatformCrypto, // Software-backed (fallback)
    None,
}

pub struct WindowsCapabilities {
    secure_element_supported: bool,  // TPM 2.0 with EC P-256 support
    tee_supported: bool,             // TPM 1.2/2.0 available
    tpm_version: Option<String>,     // "2.0", "1.2", or None
}
```

#### Implementation Strategy
```rust
// Use Microsoft Platform Crypto Provider with TPM backing
// Provider: "Microsoft Platform Crypto Provider"
// Storage Provider: "Microsoft Software Key Storage Provider" + TPM

use windows::Win32::Security::Cryptography::{
    NCryptOpenStorageProvider,
    NCryptCreatePersistedKey,
    NCryptFinalizeKey,
    NCryptSignHash,
    NCRYPT_OVERWRITE_KEY_FLAG,
};

const PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
const ALGORITHM: &str = "ECDSA_P256"; // BCRYPT_ECDSA_P256_ALGORITHM

// Key properties
// - NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY (VBS if available)
// - NCRYPT_PREFER_VIRTUAL_ISOLATION_PROPERTY
// - TPM-backed storage
```

**Key Detection Strategy:**
```rust
// 1. Check TPM presence via WMI
//    Query: SELECT * FROM Win32_Tpm
// 2. Check TPM version (IsActivated, IsEnabled, SpecVersion)
// 3. Attempt test key creation with NCRYPT_PREFER_VIRTUAL_ISOLATION_PROPERTY
// 4. Verify key is hardware-backed via NCRYPT_IMPL_TYPE_PROPERTY
```

**Pros:**
- ✅ Good hardware coverage (Windows 11 requirement)
- ✅ Mature cryptographic APIs
- ✅ Supports EC P-256 natively
- ✅ `windows-rs` provides safe Rust bindings

**Cons:**
- ❌ Complex API (compared to macOS)
- ❌ Requires TPM detection logic
- ❌ TPM 1.2 has limited EC support (RSA only)
- ❌ Performance varies (discrete vs fTPM)

**Recommendation**: **Medium Priority** - More complex, but necessary for Windows support

---

### 3. Linux

#### Hardware Support (Highly Varied)
- **TPM 2.0**: Available on enterprise laptops/workstations
  - ThinkPad, Dell Latitude, HP EliteBook
  - ~30-40% of business Linux machines
- **ARM TrustZone**: Available on ARM SBCs (Raspberry Pi 4+, etc.)
- **Intel SGX**: Limited availability, being phased out
- **AMD PSP/SEV**: Server-focused, not accessible via standard APIs
- **Coverage**: ~30% have usable TEE

#### API Access Options

##### Option 1: TPM 2.0 (via tpm2-tss)
- **Library**: tpm2-tss (TPM2 Software Stack)
- **Rust Integration**: `tss-esapi` crate
- **Access**: `/dev/tpm0` or `/dev/tpmrm0`

##### Option 2: PKCS#11
- **Library**: OpenSC, SoftHSM2
- **Rust Integration**: `cryptoki` crate
- **Backends**: TPM, smart cards, HSMs

##### Option 3: Kernel Keyring + TEE
- **API**: Linux Key Retention Service
- **Access**: `keyctl` syscalls
- **Rust Integration**: Custom FFI or `linux-keyutils` crate

#### Capabilities
```rust
pub enum SecureHardwareType {
    TPM20,        // TPM 2.0 via tpm2-tss
    PKCS11,       // PKCS#11 module (TPM, smart card, etc.)
    TrustZone,    // ARM TrustZone (OP-TEE)
    None,
}

pub struct LinuxCapabilities {
    secure_element_supported: bool,  // TPM 2.0 with EC support
    tee_supported: bool,             // Any TEE available
    tee_type: Option<SecureHardwareType>,
    tpm_version: Option<String>,
}
```

#### Implementation Strategy (Recommended: TPM 2.0 focus)
```rust
// Use tss-esapi crate for TPM 2.0
use tss_esapi::{
    Context,
    structures::{EccScheme, EccCurve, PublicEccParameters},
    interface_types::algorithm::HashingAlgorithm,
};

// 1. Check /dev/tpm0 or /dev/tpmrm0 exists
// 2. Connect to TPM via TCTI (TPM Command Transmission Interface)
// 3. Create EC P-256 key with:
//    - Curve: EccCurve::NistP256
//    - Scheme: EccScheme::EcDsa (SHA256)
//    - Attributes: fixedTPM, fixedParent, userWithAuth
// 4. Persist key in TPM NV storage
```

**Detection Strategy:**
```rust
// 1. Check /dev/tpm0 or /dev/tpmrm0 exists (requires udev rules/permissions)
// 2. Attempt TPM context creation
// 3. Query TPM capabilities (TPM2_GetCapability)
// 4. Verify EC P-256 support in ECC capabilities
// 5. Fallback to PKCS#11 if available
```

**Pros:**
- ✅ TPM 2.0 is standardized
- ✅ `tss-esapi` is well-maintained
- ✅ No kernel patches required

**Cons:**
- ❌ Low hardware coverage (~30%)
- ❌ Requires TPM device access (permissions)
- ❌ Complex setup (udev rules, tpm2-abrmd daemon)
- ❌ Performance varies greatly
- ❌ Multiple TEE types require different implementations

**Recommendation**: **Low Priority** - Complex, low success rate, consider software fallback

---

## Recommended Implementation Approach

### Phase 1: macOS Support (High Value, Low Effort)
1. **Reuse iOS Swift code** with minimal modifications
2. **Add runtime detection** for Secure Enclave availability
3. **Return errors** on non-Secure Enclave Macs (consistent with mobile behavior)

```rust
// desktop.rs (macOS-specific)
#[cfg(target_os = "macos")]
pub async fn generate_secure_key(
    app: AppHandle<R>,
    request: GenerateSecureKeyRequest,
) -> Result<GenerateSecureKeyResponse> {
    // Call Swift implementation (similar to mobile.rs)
    app.run_mobile_plugin("generateSecureKey", request)
        .map_err(Into::into)
}

#[cfg(target_os = "macos")]
pub async fn check_secure_element_support(
    app: AppHandle<R>,
) -> Result<CheckSecureElementSupportResponse> {
    // Swift checks for Secure Enclave availability
    app.run_mobile_plugin("checkSecureElementSupport", ())
        .map_err(Into::into)
}
```

### Phase 2: Windows Support (Medium Value, Medium Effort)
1. **Implement TPM 2.0 support** via `windows-rs`
2. **Add capability detection** with fallback logic
3. **Return meaningful errors** when TPM unavailable

```rust
// desktop.rs (Windows-specific)
#[cfg(target_os = "windows")]
mod windows_impl {
    use windows::Win32::Security::Cryptography::*;

    pub struct WindowsSecureElement {
        provider_handle: NCRYPT_PROV_HANDLE,
    }

    impl WindowsSecureElement {
        pub async fn check_capabilities() -> Capabilities {
            // 1. Query TPM via WMI
            // 2. Attempt test key creation
            // 3. Verify hardware backing
        }

        pub async fn generate_key(name: &str) -> Result<PublicKey> {
            // Use NCrypt APIs with TPM backing
        }
    }
}
```

### Phase 3: Linux Support (Optional, High Effort)
1. **Implement TPM 2.0** via `tss-esapi` (primary)
2. **Consider PKCS#11** as alternative backend
3. **Document limitations** clearly
4. **Provide software fallback** option (with clear warnings)

```rust
// desktop.rs (Linux-specific)
#[cfg(target_os = "linux")]
mod linux_impl {
    use tss_esapi::Context;

    pub struct LinuxSecureElement {
        tpm_context: Option<Context>,
        backend_type: BackendType,
    }

    impl LinuxSecureElement {
        pub async fn check_capabilities() -> Capabilities {
            // 1. Check /dev/tpm0
            // 2. Try PKCS#11 modules
            // 3. Return detailed capability info
        }
    }
}
```

---

## Proposed API Extension

### Extended Capability Detection

```rust
// models.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSecureElementSupportResponse {
    /// True if dedicated secure element available (Secure Enclave, StrongBox)
    pub secure_element_supported: bool,

    /// True if any TEE/hardware-backed storage available
    pub tee_supported: bool,

    /// Detailed platform information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_info: Option<PlatformInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformInfo {
    pub platform: String,           // "macos", "windows", "linux", "ios", "android"
    pub hardware_type: String,      // "SecureEnclave", "TPM2.0", "StrongBox", etc.
    pub version: Option<String>,    // TPM version, chip model, etc.
}
```

### Graceful Degradation Strategy

```rust
// When hardware unavailable, return clear error
pub enum SecureElementError {
    Unsupported {
        platform: String,
        reason: String,
        suggestion: Option<String>,
    },
    HardwareUnavailable {
        platform: String,
        required: String,  // "TPM 2.0", "Secure Enclave", etc.
    },
    // ... existing errors
}

// Example error messages
// macOS: "Secure Enclave not available (requires T2 chip or Apple Silicon)"
// Windows: "TPM 2.0 not found or not enabled in BIOS"
// Linux: "No TEE detected. Install TPM 2.0 support: sudo apt install tpm2-tools"
```

---

## Security Considerations

### macOS
- ✅ **Key Isolation**: Secure Enclave provides hardware isolation
- ✅ **Attestation**: Can verify Secure Enclave backing
- ⚠️ **Root Access**: Root user can potentially access keychain (consider app-specific access controls)

### Windows
- ✅ **TPM Isolation**: Keys sealed to TPM, non-exportable
- ⚠️ **Admin Access**: Admin can reset TPM (destroys keys)
- ⚠️ **Firmware TPM**: Less secure than discrete TPM (shared CPU resources)
- ⚠️ **Key Migration**: TPM keys are machine-specific (backup considerations)

### Linux
- ⚠️ **Device Access**: Requires permissions to `/dev/tpm0`
- ⚠️ **User Context**: Key access control depends on TPM hierarchy
- ⚠️ **Daemon Dependency**: tpm2-abrmd or in-kernel resource manager required
- ❌ **Varied Security**: Security guarantees depend on specific TEE implementation

---

## Implementation Checklist

### macOS (High Priority)
- [ ] Create `macos/Sources/Plugin.swift` (copy from iOS)
- [ ] Update `desktop.rs` with macOS-specific bridge
- [ ] Add Secure Enclave capability detection
- [ ] Test on Intel (T2) and Apple Silicon Macs
- [ ] Handle graceful degradation for older Macs

### Windows (Medium Priority)
- [ ] Add `windows-rs` dependency
- [ ] Implement TPM 2.0 detection via WMI
- [ ] Implement NCrypt-based key generation
- [ ] Implement ECDSA signing with TPM keys
- [ ] Add key enumeration (NCryptEnumKeys)
- [ ] Test on Windows 11 (TPM 2.0 required)
- [ ] Test on Windows 10 (TPM optional)

### Linux (Low Priority / Optional)
- [ ] Add `tss-esapi` dependency
- [ ] Implement TPM device detection
- [ ] Implement TPM 2.0 key operations
- [ ] Document permission requirements
- [ ] Consider PKCS#11 alternative backend
- [ ] Provide clear error messages for unsupported systems

### Cross-Platform
- [ ] Update `check_secure_element_support()` with platform details
- [ ] Add integration tests for each platform
- [ ] Update documentation with platform support matrix
- [ ] Add examples for handling unsupported platforms in user code

---

## Recommended Dependencies

```toml
# Cargo.toml additions

[target.'cfg(target_os = "macos")'.dependencies]
security-framework = "2.9"  # macOS Security Framework bindings
core-foundation = "0.9"     # Apple Core Foundation types

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.52", features = [
    "Win32_Security_Cryptography",
    "Win32_System_Wmi",
] }

[target.'cfg(target_os = "linux")'.dependencies]
tss-esapi = "7.4"           # TPM 2.0 support
# Optional: cryptoki = "0.6"  # PKCS#11 support
```

---

## Summary and Recommendation

| Platform | Priority | Effort | Success Rate | Recommendation |
|----------|----------|--------|--------------|----------------|
| **macOS** | High | Low | ~95% | ✅ Implement (Phase 1) |
| **Windows** | Medium | Medium | ~85% | ⚠️ Implement (Phase 2) |
| **Linux** | Low | High | ~30% | ❌ Optional (Phase 3) |

### Next Steps
1. **Start with macOS** - Reuse existing iOS Swift code, high success rate
2. **Add Windows support** - TPM 2.0 coverage is good on modern Windows
3. **Consider Linux optional** - Low hardware coverage, high complexity
4. **Enhance capability detection** - Return detailed platform information
5. **Document limitations** - Be transparent about hardware requirements
6. **Provide examples** - Show how to handle unsupported platforms gracefully

The modular architecture allows shipping macOS support first while Windows/Linux remain stubbed, with clear error messages guiding users toward supported platforms.
