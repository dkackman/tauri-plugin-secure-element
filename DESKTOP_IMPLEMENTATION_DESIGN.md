# Desktop Implementation Design

This document provides detailed technical design for implementing desktop support in the Tauri Secure Element plugin.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (TypeScript)                │
│              invoke("plugin:secure-element|*")          │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              Tauri Command Layer (commands.rs)          │
│              app.secure_element().method()              │
└────────────────────────┬────────────────────────────────┘
                         │
           ┌─────────────┴──────────────┐
           │                            │
┌──────────▼────────┐        ┌─────────▼──────────┐
│   mobile.rs       │        │    desktop.rs      │
│  (iOS/Android)    │        │  Platform Router   │
└──────────┬────────┘        └─────────┬──────────┘
           │                           │
           │              ┌────────────┼────────────┐
           │              │            │            │
┌──────────▼────────┐  ┌──▼──────┐ ┌──▼──────┐ ┌──▼──────┐
│ Swift/Kotlin      │  │  macOS  │ │ Windows │ │  Linux  │
│ Secure Enclave/   │  │  Impl   │ │  Impl   │ │  Impl   │
│ StrongBox         │  │ (Swift) │ │ (Rust)  │ │ (Rust)  │
└───────────────────┘  └─────────┘ └─────────┘ └─────────┘
```

## File Structure

```
tauri-plugin-secure-element/
├── src/
│   ├── desktop.rs                 # Desktop platform router
│   ├── desktop/
│   │   ├── mod.rs                 # Module exports
│   │   ├── macos.rs              # macOS-specific Rust glue
│   │   ├── windows.rs            # Windows implementation
│   │   └── linux.rs              # Linux implementation
│   └── ...
├── macos/                         # NEW: macOS native code
│   └── Sources/
│       └── Plugin.swift           # Reuse/adapt from iOS
├── ios/Sources/Plugin.swift       # Existing iOS implementation
└── android/.../SecureKeysPlugin.kt # Existing Android implementation
```

## Phase 1: macOS Implementation

### 1.1 Capability Detection

macOS has the same Secure Enclave API as iOS, but we need to handle:
- Intel Macs without T2 chip (2017 and earlier)
- Intel Macs with T2 chip (2018-2020)
- Apple Silicon Macs (2020+)

#### Swift Implementation (macos/Sources/Plugin.swift)

```swift
import Security
import CryptoKit
import Foundation

@objc class SecureElementPlugin: NSObject {

    /// Check if Secure Enclave is available
    @objc static func checkSecureElementSupport() -> [String: Any] {
        let hasSecureEnclave = isSecureEnclaveAvailable()

        return [
            "secureElementSupported": hasSecureEnclave,
            "teeSupported": hasSecureEnclave,  // On macOS, Secure Enclave IS the TEE
            "platformInfo": [
                "platform": "macos",
                "hardwareType": hasSecureEnclave ? "SecureEnclave" : "None",
                "version": getHardwareInfo()
            ] as [String: Any]
        ]
    }

    /// Test if Secure Enclave is available by attempting to create a test key
    private static func isSecureEnclaveAvailable() -> Bool {
        // Create a temporary key to test Secure Enclave availability
        let tag = "temp.secure.enclave.test".data(using: .utf8)!

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,  // Don't persist test key
                kSecAttrApplicationTag as String: tag
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            // Secure Enclave not available
            return false
        }

        // Clean up is automatic since kSecAttrIsPermanent: false
        return true
    }

    /// Get hardware information
    private static func getHardwareInfo() -> String {
        #if arch(arm64)
        return "AppleSilicon"
        #else
        // Try to determine if T2 chip is present (Intel Mac)
        // This is heuristic-based since there's no direct API
        if isSecureEnclaveAvailable() {
            return "T2"
        } else {
            return "IntelNoT2"
        }
        #endif
    }

    // MARK: - Key Generation

    @objc static func generateSecureKey(keyName: String) -> [String: Any]? {
        let tag = keyName.data(using: .utf8)!

        // Delete existing key if present (allow regeneration)
        let deleteAttributes: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        SecItemDelete(deleteAttributes as CFDictionary)

        // Create new key in Secure Enclave
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [],  // No additional flags (no biometry requirement)
                    nil
                )!
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            NSLog("Failed to generate key: \(error!.takeRetainedValue())")
            return nil
        }

        // Extract public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            NSLog("Failed to extract public key: \(error?.takeRetainedValue() ?? "unknown" as! CFError)")
            return nil
        }

        let publicKeyBase64 = publicKeyData.base64EncodedString()

        return [
            "publicKey": publicKeyBase64,
            "keyName": keyName
        ]
    }

    // MARK: - Key Listing

    @objc static func listKeys(keyNameFilter: String?, publicKeyFilter: String?) -> [[String: String]] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnAttributes as String: true,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        // Add filter if provided
        if let keyName = keyNameFilter {
            query[kSecAttrApplicationTag as String] = keyName.data(using: .utf8)
        }

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)

        guard status == errSecSuccess,
              let itemsArray = items as? [[String: Any]] else {
            return []
        }

        var results: [[String: String]] = []

        for item in itemsArray {
            guard let tag = item[kSecAttrApplicationTag as String] as? Data,
                  let keyName = String(data: tag, encoding: .utf8),
                  let keyRef = item[kSecValueRef as String] as! SecKey? else {
                continue
            }

            // Extract public key
            guard let publicKey = SecKeyCopyPublicKey(keyRef),
                  let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                continue
            }

            let publicKeyBase64 = publicKeyData.base64EncodedString()

            // Apply public key filter if provided
            if let pubKeyFilter = publicKeyFilter, publicKeyBase64 != pubKeyFilter {
                continue
            }

            results.append([
                "keyName": keyName,
                "publicKey": publicKeyBase64
            ])
        }

        return results
    }

    // MARK: - Signing

    @objc static func signWithKey(keyName: String, data: Data) -> Data? {
        let tag = keyName.data(using: .utf8)!

        // Find the key
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess,
              let privateKey = item as! SecKey? else {
            NSLog("Key not found: \(keyName)")
            return nil
        }

        // Hash the data (SHA-256)
        let digest = SHA256.hash(data: data)
        let digestData = Data(digest)

        // Sign the digest
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            digestData as CFData,
            &error
        ) as Data? else {
            NSLog("Failed to sign: \(error!.takeRetainedValue())")
            return nil
        }

        return signature
    }

    // MARK: - Key Deletion

    @objc static func deleteKey(keyName: String) -> Bool {
        let tag = keyName.data(using: .utf8)!

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]

        let status = SecItemDelete(query as CFDictionary)

        // Return true if deleted or already didn't exist
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
```

### 1.2 Rust Desktop Router (src/desktop.rs)

```rust
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::models::*;

#[cfg(target_os = "macos")]
use serde_json::Value as JsonValue;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    Ok(SecureElement(app.clone()))
}

pub struct SecureElement<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        Ok(PingResponse {
            value: payload.value,
        })
    }

    // macOS uses Swift implementation (similar to iOS)
    #[cfg(target_os = "macos")]
    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        self.0
            .plugin_handle()
            .run_mobile_plugin("generateSecureKey", payload)
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        self.0
            .plugin_handle()
            .run_mobile_plugin("listKeys", payload)
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        self.0
            .plugin_handle()
            .run_mobile_plugin("signWithKey", payload)
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        self.0
            .plugin_handle()
            .run_mobile_plugin("deleteKey", payload)
            .map_err(Into::into)
    }

    #[cfg(target_os = "macos")]
    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        self.0
            .plugin_handle()
            .run_mobile_plugin::<(), CheckSecureElementSupportResponse>(
                "checkSecureElementSupport",
                (),
            )
            .map_err(Into::into)
    }

    // Windows implementation (native Rust)
    #[cfg(target_os = "windows")]
    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        desktop::windows::generate_secure_key(payload)
    }

    #[cfg(target_os = "windows")]
    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        desktop::windows::list_keys(payload)
    }

    #[cfg(target_os = "windows")]
    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        desktop::windows::sign_with_key(payload)
    }

    #[cfg(target_os = "windows")]
    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        desktop::windows::delete_key(payload)
    }

    #[cfg(target_os = "windows")]
    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        desktop::windows::check_secure_element_support()
    }

    // Linux implementation (native Rust)
    #[cfg(target_os = "linux")]
    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        desktop::linux::generate_secure_key(payload)
    }

    #[cfg(target_os = "linux")]
    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        desktop::linux::list_keys(payload)
    }

    #[cfg(target_os = "linux")]
    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        desktop::linux::sign_with_key(payload)
    }

    #[cfg(target_os = "linux")]
    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        desktop::linux::delete_key(payload)
    }

    #[cfg(target_os = "linux")]
    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        desktop::linux::check_secure_element_support()
    }
}

// Platform-specific implementations
#[cfg(any(target_os = "windows", target_os = "linux"))]
mod desktop {
    use crate::models::*;

    #[cfg(target_os = "windows")]
    pub mod windows {
        use super::*;
        use std::io::{Error as IoError, ErrorKind};

        pub fn generate_secure_key(
            _payload: GenerateSecureKeyRequest,
        ) -> crate::Result<GenerateSecureKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Windows TPM support not yet implemented",
            )))
        }

        pub fn list_keys(_payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Windows TPM support not yet implemented",
            )))
        }

        pub fn sign_with_key(
            _payload: SignWithKeyRequest,
        ) -> crate::Result<SignWithKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Windows TPM support not yet implemented",
            )))
        }

        pub fn delete_key(_payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Windows TPM support not yet implemented",
            )))
        }

        pub fn check_secure_element_support(
        ) -> crate::Result<CheckSecureElementSupportResponse> {
            // Even stubbed, we can return a meaningful response
            Ok(CheckSecureElementSupportResponse {
                secure_element_supported: false,
                tee_supported: false,
            })
        }
    }

    #[cfg(target_os = "linux")]
    pub mod linux {
        use super::*;
        use std::io::{Error as IoError, ErrorKind};

        pub fn generate_secure_key(
            _payload: GenerateSecureKeyRequest,
        ) -> crate::Result<GenerateSecureKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Linux TPM support not yet implemented",
            )))
        }

        pub fn list_keys(_payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Linux TPM support not yet implemented",
            )))
        }

        pub fn sign_with_key(
            _payload: SignWithKeyRequest,
        ) -> crate::Result<SignWithKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Linux TPM support not yet implemented",
            )))
        }

        pub fn delete_key(_payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
            Err(crate::Error::Io(IoError::new(
                ErrorKind::Unsupported,
                "Linux TPM support not yet implemented",
            )))
        }

        pub fn check_secure_element_support(
        ) -> crate::Result<CheckSecureElementSupportResponse> {
            Ok(CheckSecureElementSupportResponse {
                secure_element_supported: false,
                tee_supported: false,
            })
        }
    }
}
```

### 1.3 macOS Plugin Configuration

Create `macos/plugin.json`:

```json
{
  "name": "secure-element",
  "version": "1.0.0",
  "ios": {
    "source": "../ios/Sources/Plugin.swift"
  },
  "macos": {
    "source": "Sources/Plugin.swift"
  }
}
```

## Phase 2: Windows Implementation

### 2.1 Windows TPM Implementation (src/desktop/windows.rs)

```rust
use windows::{
    core::*,
    Win32::Security::Cryptography::*,
    Win32::System::Wmi::*,
};

use crate::models::*;
use std::ptr;

pub struct WindowsTpm {
    provider: NCRYPT_PROV_HANDLE,
}

impl WindowsTpm {
    /// Open the Microsoft Platform Crypto Provider
    pub fn new() -> crate::Result<Self> {
        let provider_name: PCWSTR = w!("Microsoft Platform Crypto Provider");
        let mut provider = NCRYPT_PROV_HANDLE::default();

        unsafe {
            NCryptOpenStorageProvider(&mut provider, provider_name, 0)
                .map_err(|e| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Failed to open crypto provider: {}", e),
                    ))
                })?;
        }

        Ok(Self { provider })
    }

    /// Check TPM capabilities
    pub fn check_capabilities() -> crate::Result<CheckSecureElementSupportResponse> {
        // Check if TPM 2.0 is present via WMI
        let tpm_info = Self::query_tpm_info()?;

        Ok(CheckSecureElementSupportResponse {
            secure_element_supported: tpm_info.tpm_version == "2.0" && tpm_info.is_activated,
            tee_supported: tpm_info.is_present && tpm_info.is_activated,
        })
    }

    /// Query TPM information via WMI
    fn query_tpm_info() -> crate::Result<TpmInfo> {
        // Simplified - actual implementation would use WMI COM APIs
        // Query: SELECT * FROM Win32_Tpm

        // For now, attempt to create provider as capability check
        match Self::new() {
            Ok(_) => Ok(TpmInfo {
                is_present: true,
                is_activated: true,
                tpm_version: "2.0".to_string(),
            }),
            Err(_) => Ok(TpmInfo {
                is_present: false,
                is_activated: false,
                tpm_version: "".to_string(),
            }),
        }
    }

    /// Generate EC P-256 key
    pub fn generate_key(&self, key_name: &str) -> crate::Result<GenerateSecureKeyResponse> {
        let algorithm = BCRYPT_ECDSA_P256_ALGORITHM;
        let mut key_handle = NCRYPT_KEY_HANDLE::default();

        unsafe {
            // Create persisted key
            NCryptCreatePersistedKey(
                self.provider,
                &mut key_handle,
                algorithm,
                PCWSTR::from_raw(
                    key_name.encode_utf16()
                        .chain(std::iter::once(0))
                        .collect::<Vec<u16>>()
                        .as_ptr()
                ),
                0,
                NCRYPT_OVERWRITE_KEY_FLAG,
            ).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create key: {}", e),
                ))
            })?;

            // Set TPM backing preference
            let prefer_tpm: u32 = 1;
            NCryptSetProperty(
                key_handle,
                NCRYPT_USE_VIRTUAL_ISOLATION_PROPERTY,
                &prefer_tpm as *const u32 as *const u8,
                std::mem::size_of::<u32>() as u32,
                0,
            ).ok(); // Best effort

            // Finalize key
            NCryptFinalizeKey(key_handle, 0).map_err(|e| {
                NCryptDeleteKey(key_handle, 0).ok();
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to finalize key: {}", e),
                ))
            })?;

            // Export public key
            let mut public_key_size: u32 = 0;
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                None,
                0,
                &mut public_key_size,
                0,
            ).map_err(|e| {
                NCryptDeleteKey(key_handle, 0).ok();
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to get public key size: {}", e),
                ))
            })?;

            let mut public_key_blob = vec![0u8; public_key_size as usize];
            NCryptExportKey(
                key_handle,
                NCRYPT_KEY_HANDLE::default(),
                BCRYPT_ECCPUBLIC_BLOB,
                None,
                Some(public_key_blob.as_mut_ptr()),
                public_key_size,
                &mut public_key_size,
                0,
            ).map_err(|e| {
                NCryptDeleteKey(key_handle, 0).ok();
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to export public key: {}", e),
                ))
            })?;

            NCryptFreeObject(key_handle).ok();

            // Convert to base64
            let public_key_base64 = base64::encode(&public_key_blob);

            Ok(GenerateSecureKeyResponse {
                public_key: public_key_base64,
                key_name: key_name.to_string(),
            })
        }
    }

    // Similar implementations for:
    // - list_keys() - use NCryptEnumKeys
    // - sign_with_key() - use NCryptSignHash
    // - delete_key() - use NCryptDeleteKey
}

struct TpmInfo {
    is_present: bool,
    is_activated: bool,
    tpm_version: String,
}

impl Drop for WindowsTpm {
    fn drop(&mut self) {
        unsafe {
            NCryptFreeObject(self.provider).ok();
        }
    }
}

// Public API functions
pub fn check_secure_element_support() -> crate::Result<CheckSecureElementSupportResponse> {
    WindowsTpm::check_capabilities()
}

pub fn generate_secure_key(
    payload: GenerateSecureKeyRequest,
) -> crate::Result<GenerateSecureKeyResponse> {
    let tpm = WindowsTpm::new()?;
    tpm.generate_key(&payload.key_name)
}

// ... other functions
```

## Phase 3: Linux Implementation (Optional)

### 3.1 Linux TPM Implementation (src/desktop/linux.rs)

```rust
use tss_esapi::{
    Context, TctiNameConf,
    structures::{
        Public, PublicBuilder, PublicEccParameters,
        EccScheme, EccPoint, SymmetricDefinitionObject,
    },
    interface_types::{
        resource_handles::Hierarchy,
        algorithm::{HashingAlgorithm, EccCurve},
    },
};

use crate::models::*;

pub struct LinuxTpm {
    context: Context,
}

impl LinuxTpm {
    /// Create new TPM context
    pub fn new() -> crate::Result<Self> {
        // Try in-kernel resource manager first, then device
        let tcti = TctiNameConf::Device(
            tss_esapi::tcti_ldr::DeviceConfig::from_str("/dev/tpmrm0")
                .or_else(|_| {
                    tss_esapi::tcti_ldr::DeviceConfig::from_str("/dev/tpm0")
                })
                .map_err(|e| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("TPM device not found: {}", e),
                    ))
                })?,
        );

        let context = Context::new(tcti).map_err(|e| {
            crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Failed to create TPM context: {}", e),
            ))
        })?;

        Ok(Self { context })
    }

    /// Check if TPM 2.0 with EC P-256 support is available
    pub fn check_capabilities() -> crate::Result<CheckSecureElementSupportResponse> {
        // Try to create context
        let tpm = match Self::new() {
            Ok(tpm) => tpm,
            Err(_) => {
                return Ok(CheckSecureElementSupportResponse {
                    secure_element_supported: false,
                    tee_supported: false,
                });
            }
        };

        // Query TPM capabilities
        // Check if ECC P-256 is supported
        // (Implementation details omitted for brevity)

        Ok(CheckSecureElementSupportResponse {
            secure_element_supported: true,  // TPM 2.0 with EC support
            tee_supported: true,
        })
    }

    /// Generate EC P-256 key in TPM
    pub fn generate_key(&mut self, key_name: &str) -> crate::Result<GenerateSecureKeyResponse> {
        // Build public key template
        let ecc_params = PublicEccParameters::builder()
            .ecc_scheme(EccScheme::EcDsa(HashingAlgorithm::Sha256))
            .curve(EccCurve::NistP256)
            .symmetric(SymmetricDefinitionObject::Null)
            .build()
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to build ECC params: {}", e),
                ))
            })?;

        let public = PublicBuilder::new()
            .with_public_algorithm(tss_esapi::interface_types::algorithm::PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(
                tss_esapi::attributes::ObjectAttributes::new()
                    .with_fixed_tpm(true)
                    .with_fixed_parent(true)
                    .with_sensitive_data_origin(true)
                    .with_user_with_auth(true)
                    .with_sign_encrypt(true),
            )
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to build public key: {}", e),
                ))
            })?;

        // Create key in TPM
        let key_handle = self.context
            .create_primary(
                Hierarchy::Owner,
                public,
                None,  // No auth
                None,  // No sensitive data
                None,  // No outside info
                None,  // No PCR selection
            )
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to create key: {}", e),
                ))
            })?;

        // Persist key (using evict control)
        // Extract public key
        // (Implementation details omitted)

        Ok(GenerateSecureKeyResponse {
            public_key: "...".to_string(),  // Extract and encode public key
            key_name: key_name.to_string(),
        })
    }
}

// Public API functions
pub fn check_secure_element_support() -> crate::Result<CheckSecureElementSupportResponse> {
    LinuxTpm::check_capabilities()
}

pub fn generate_secure_key(
    payload: GenerateSecureKeyRequest,
) -> crate::Result<GenerateSecureKeyResponse> {
    let mut tpm = LinuxTpm::new()?;
    tpm.generate_key(&payload.key_name)
}

// ... other functions
```

## Testing Strategy

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_capability_detection() {
        let result = check_secure_element_support();
        assert!(result.is_ok());
        // Actual support depends on hardware
    }

    #[test]
    fn test_ping() {
        let response = ping(PingRequest {
            value: Some("test".to_string()),
        });
        assert_eq!(response.unwrap().value, Some("test".to_string()));
    }
}
```

### Integration Tests

Create `examples/desktop-test/`:

```javascript
// examples/desktop-test/main.js
import { invoke } from '@tauri-apps/api/core';

async function testSecureElement() {
  try {
    // Check support
    const support = await invoke('plugin:secure-element|check_secure_element_support');
    console.log('Platform support:', support);

    if (!support.secureElementSupported && !support.teeSupported) {
      console.warn('No secure hardware available on this platform');
      return;
    }

    // Generate key
    const keyResult = await invoke('plugin:secure-element|generate_secure_key', {
      payload: { keyName: 'test-key-1' }
    });
    console.log('Generated key:', keyResult);

    // List keys
    const keys = await invoke('plugin:secure-element|list_keys', {
      payload: {}
    });
    console.log('Keys:', keys);

    // Sign data
    const signature = await invoke('plugin:secure-element|sign_with_key', {
      payload: {
        keyName: 'test-key-1',
        data: Array.from(new TextEncoder().encode('Hello, World!'))
      }
    });
    console.log('Signature:', signature);

    // Delete key
    const deleteResult = await invoke('plugin:secure-element|delete_key', {
      payload: { keyName: 'test-key-1' }
    });
    console.log('Deleted:', deleteResult);

  } catch (error) {
    console.error('Error:', error);
  }
}

testSecureElement();
```

## Documentation Updates

Update `README.md` with platform support matrix:

```markdown
## Platform Support

| Platform | Secure Element | TEE/Hardware Backing | API | Coverage |
|----------|----------------|---------------------|-----|----------|
| iOS 12+ | ✅ Secure Enclave | ✅ Secure Enclave | Security Framework | ~95% |
| Android 9+ | ✅ StrongBox | ✅ TEE (API 18+) | KeyStore | ~90% (StrongBox), ~99% (TEE) |
| macOS 10.14+ | ✅ Secure Enclave (T2/Apple Silicon) | ✅ Secure Enclave | Security Framework | ~95% (2018+ Macs) |
| Windows 10/11 | ⚠️ TPM 2.0 (in progress) | ⚠️ TPM 1.2/2.0 | CNG/NCrypt | ~85% (Win11: 100%) |
| Linux | ❌ TPM 2.0 (planned) | ❌ TPM/TEE | tss-esapi | ~30% |

### macOS Requirements
- Secure Enclave support requires:
  - Mac with T2 Security Chip (2018-2020 Intel Macs)
  - Mac with Apple Silicon (M1, M2, M3, etc.)
- Older Macs will return `secure_element_supported: false`
```

## Summary

This design provides:

1. **macOS Support** - Reuses iOS Swift code with minimal changes
2. **Windows Support** - Native Rust implementation using Windows CNG
3. **Linux Support** - Native Rust using TPM 2.0 (optional)
4. **Graceful Degradation** - Clear capability detection and error messages
5. **Consistent API** - Same API surface across all platforms
6. **Platform-Specific Optimizations** - Uses best available secure hardware on each platform

The modular design allows shipping macOS support immediately while keeping Windows/Linux stubbed with clear error messages until those implementations are complete.
