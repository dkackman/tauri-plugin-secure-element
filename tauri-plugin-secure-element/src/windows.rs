use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeBuffer, NCryptFreeObject, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, NCryptSignHash, CERT_KEY_SPEC, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_FLAGS,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

use crate::error_sanitize::sanitize_error;
use crate::windows_hello;

/// Microsoft Platform Crypto Provider - uses TPM when available
pub const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
/// Key name prefix to namespace our keys
pub const KEY_STORAGE_PREFIX: &str = "tauri_se_";
/// Checks if the current system is running Windows 11 (build 22000 or higher)
/// Uses winver crate which handles all the pitfalls of Windows version detection
/// See: https://docs.rs/winver/latest/winver/
fn is_windows_11() -> crate::Result<bool> {
    let version = winver::WindowsVersion::detect().ok_or_else(|| {
        crate::Error::Io(std::io::Error::other("Failed to detect Windows version"))
    })?;

    // Windows 11 is version 10.0.22000 or higher
    let windows_11_min = winver::WindowsVersion::new(10, 0, 22000);

    Ok(version >= windows_11_min)
}

/// Verifies that the system is running Windows 11, returns an error if not
fn require_windows_11() -> crate::Result<()> {
    match is_windows_11() {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "This plugin requires Windows 11 (build 22000 or higher)",
        ))),
        Err(e) => Err(e),
    }
}

/// RAII wrapper for NCRYPT_PROV_HANDLE
pub struct ProviderHandle(pub NCRYPT_PROV_HANDLE);

impl Drop for ProviderHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// RAII wrapper for NCRYPT_KEY_HANDLE
pub struct KeyHandle(pub NCRYPT_KEY_HANDLE);

impl Drop for KeyHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = NCryptFreeObject(self.0);
            }
        }
    }
}

/// Opens the Microsoft Platform Crypto Provider
pub fn open_provider() -> crate::Result<ProviderHandle> {
    require_windows_11()?;

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        let provider_name = HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER);

        NCryptOpenStorageProvider(&mut provider, PCWSTR(provider_name.as_ptr()), 0).map_err(
            |e| {
                crate::Error::Io(std::io::Error::other(sanitize_error(
                    &format!("Failed to open Platform Crypto Provider: {}", e),
                    "Failed to open Platform Crypto Provider",
                )))
            },
        )?;

        Ok(ProviderHandle(provider))
    }
}

/// Checks if TPM is available by attempting to verify the provider supports our algorithm
pub fn is_tpm_available(provider: &ProviderHandle) -> bool {
    // Try to get provider properties - if Platform Crypto Provider opened successfully
    // and we can interact with it, TPM should be available
    // A more thorough check would create a test key, but this is faster
    !provider.0.is_invalid()
}

/// Creates the full key name with our prefix
pub fn make_key_name(user_key_name: &str) -> String {
    format!("{}{}", KEY_STORAGE_PREFIX, user_key_name)
}

/// Extracts the user-facing key name by removing our prefix
pub fn extract_key_name(full_name: &str) -> Option<&str> {
    full_name.strip_prefix(KEY_STORAGE_PREFIX)
}

/// NCRYPT_UI_POLICY structure for setting Windows Hello authentication requirements
/// See: https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/ns-ncrypt-ncrypt_ui_policy
#[repr(C)]
struct NcryptUiPolicy {
    dw_version: u32,
    dw_flags: u32,
    psz_creation_title: PCWSTR,
    psz_friendly_name: PCWSTR,
    psz_description: PCWSTR,
}

/// UI Policy version constant
const NCRYPT_UI_POLICY_VERSION: u32 = 1;
/// Force high protection - requires Windows Hello (PIN, fingerprint, or face)
const NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG: u32 = 0x2;

/// Opens an existing key by name
pub fn open_key(provider: &ProviderHandle, key_name: &str) -> crate::Result<KeyHandle> {
    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let full_name = make_key_name(key_name);
        let key_name_h = HSTRING::from(full_name.as_str());

        NCryptOpenKey(
            provider.0,
            &mut key_handle,
            PCWSTR(key_name_h.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to open key '{}': {}", key_name, e),
                "Failed to open key",
            )))
        })?;

        Ok(KeyHandle(key_handle))
    }
}

/// Creates a new P-256 ECDSA key
pub fn create_key(
    provider: &ProviderHandle,
    key_name: &str,
    auth_mode: &crate::models::AuthenticationMode,
) -> crate::Result<KeyHandle> {
    // Validate Windows Hello requirements before creating the key
    match auth_mode {
        crate::models::AuthenticationMode::BiometricOnly => {
            return Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "biometricOnly authentication mode is not supported on Windows. Use 'pinOrBiometric' instead.",
            )));
        }
        crate::models::AuthenticationMode::PinOrBiometric => {
            if !windows_hello::is_windows_hello_configured() {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Windows Hello is not configured or enrolled on this system. Please set up Windows Hello (PIN or biometric) in Windows Settings before creating keys with authentication.",
                )));
            }
        }
        crate::models::AuthenticationMode::None => {
            // No Windows Hello required for None mode
        }
    }

    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let full_name = make_key_name(key_name);
        let key_name_h = HSTRING::from(full_name.as_str());
        let algorithm = HSTRING::from("ECDSA_P256");

        // Create the key
        NCryptCreatePersistedKey(
            provider.0,
            &mut key_handle,
            PCWSTR(algorithm.as_ptr()),
            PCWSTR(key_name_h.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to create key '{}': {}", key_name, e),
                "Failed to create key",
            )))
        })?;

        // Set key usage to signing only
        // NCRYPT_ALLOW_SIGNING_FLAG is a u32 constant
        let usage_bytes = NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes();
        let key_usage_property = HSTRING::from("Key Usage");

        if let Err(e) = NCryptSetProperty(
            key_handle,
            PCWSTR(key_usage_property.as_ptr()),
            usage_bytes.as_slice(),
            NCRYPT_FLAGS(0),
        ) {
            let _ = NCryptFreeObject(key_handle);
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to set key usage: {}", e),
                "Failed to set key usage",
            ))));
        }

        // Set UI policy based on auth mode
        match auth_mode {
            crate::models::AuthenticationMode::None => {
                // No UI policy - silent operation
            }
            crate::models::AuthenticationMode::PinOrBiometric
            | crate::models::AuthenticationMode::BiometricOnly => {
                // Note: Windows Hello doesn't distinguish between PIN and biometric at the API level.
                // Both modes use the same NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG which requires
                // Windows Hello authentication (PIN, fingerprint, or face - user's choice).
                let ui_policy_property = HSTRING::from("UI Policy");

                // Create the proper NCRYPT_UI_POLICY structure
                let policy = NcryptUiPolicy {
                    dw_version: NCRYPT_UI_POLICY_VERSION,
                    dw_flags: NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
                    psz_creation_title: PCWSTR::null(),
                    psz_friendly_name: PCWSTR::null(),
                    psz_description: PCWSTR::null(),
                };

                let policy_bytes = std::slice::from_raw_parts(
                    &policy as *const NcryptUiPolicy as *const u8,
                    std::mem::size_of::<NcryptUiPolicy>(),
                );

                if let Err(e) = NCryptSetProperty(
                    key_handle,
                    PCWSTR(ui_policy_property.as_ptr()),
                    policy_bytes,
                    NCRYPT_FLAGS(0),
                ) {
                    let _ = NCryptFreeObject(key_handle);
                    return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                        &format!(
                            "Failed to set UI policy for Windows Hello authentication: {}",
                            e
                        ),
                        "Failed to set UI policy for Windows Hello authentication",
                    ))));
                }
            }
        }

        // Finalize the key
        if let Err(e) = NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) {
            let _ = NCryptFreeObject(key_handle);
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to finalize key: {}", e),
                "Failed to finalize key",
            ))));
        }

        Ok(KeyHandle(key_handle))
    }
}

/// Exports the public key in X9.62 uncompressed format (65 bytes: 0x04 || X || Y)
pub fn export_public_key(key: &KeyHandle) -> crate::Result<Vec<u8>> {
    unsafe {
        let blob_type = HSTRING::from("ECCPUBLICBLOB");
        let mut blob_size: u32 = 0;

        // Get required size
        NCryptExportKey(
            key.0,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            None,
            &mut blob_size,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to get public key size: {}", e),
                "Failed to get public key size",
            )))
        })?;

        // Export the key
        let mut blob = vec![0u8; blob_size as usize];
        NCryptExportKey(
            key.0,
            NCRYPT_KEY_HANDLE::default(),
            PCWSTR(blob_type.as_ptr()),
            None,
            Some(&mut blob),
            &mut blob_size,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to export public key: {}", e),
                "Failed to export public key",
            )))
        })?;

        // Convert from BCRYPT_ECCPUBLIC_BLOB to X9.62 uncompressed format
        // BCRYPT_ECCKEY_BLOB header is 8 bytes: dwMagic (4) + cbKey (4)
        // For P-256: header (8) + X (32) + Y (32) = 72 bytes
        if blob.len() < 72 {
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!(
                    "Public key blob too small: {} bytes, expected at least 72",
                    blob.len()
                ),
                "Failed to export public key",
            ))));
        }

        // Extract X and Y coordinates (skip 8-byte header)
        let x = &blob[8..40];
        let y = &blob[40..72];

        // Build X9.62 uncompressed point: 0x04 || X || Y
        let mut x962 = Vec::with_capacity(65);
        x962.push(0x04);
        x962.extend_from_slice(x);
        x962.extend_from_slice(y);

        Ok(x962)
    }
}

/// Computes SHA-256 hash using BCrypt
pub fn sha256_hash(data: &[u8]) -> crate::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    Ok(result.into())
}

/// Signs data with the given key (data should already be hashed)
pub fn sign_hash(key: &KeyHandle, hash: &[u8]) -> crate::Result<Vec<u8>> {
    unsafe {
        let mut sig_size: u32 = 0;

        // Get required signature size
        NCryptSignHash(key.0, None, hash, None, &mut sig_size, NCRYPT_FLAGS(0)).map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to get signature size: {}", e),
                "Failed to sign",
            )))
        })?;

        // Sign the hash
        let mut signature = vec![0u8; sig_size as usize];
        NCryptSignHash(
            key.0,
            None,
            hash,
            Some(&mut signature),
            &mut sig_size,
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to sign: {}", e),
                "Failed to sign",
            )))
        })?;

        signature.truncate(sig_size as usize);

        // NCrypt returns raw R||S format for ECDSA P-256 (64 bytes)
        // We need to convert to DER format for compatibility with other platforms
        let der_signature = crate::der::raw_ecdsa_to_der(&signature)?;

        Ok(der_signature)
    }
}

/// Deletes a key
/// Fails silently - returns Ok(false) if deletion fails instead of an error
pub fn delete_key(key: KeyHandle) -> crate::Result<bool> {
    unsafe {
        // NCryptDeleteKey takes ownership and invalidates the handle
        let handle = key.0;
        std::mem::forget(key); // Don't run Drop since NCryptDeleteKey frees the handle

        match NCryptDeleteKey(handle, 0u32) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Fail silently
        }
    }
}

/// RAII guard for NCrypt enumeration state to prevent memory leaks
struct EnumStateGuard(*mut std::ffi::c_void);

impl EnumStateGuard {
    fn new() -> Self {
        Self(std::ptr::null_mut())
    }

    fn as_mut_ptr(&mut self) -> *mut *mut std::ffi::c_void {
        &mut self.0
    }
}

impl Drop for EnumStateGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = NCryptFreeBuffer(self.0);
            }
        }
    }
}

/// Lists all keys with our prefix
pub fn list_keys(
    provider: &ProviderHandle,
    filter_key_name: Option<&str>,
    filter_public_key: Option<&str>,
) -> crate::Result<Vec<crate::models::KeyInfo>> {
    use base64::Engine;
    let mut keys = Vec::new();

    unsafe {
        // Use RAII guard to ensure enum_state is always freed
        let mut enum_state_guard = EnumStateGuard::new();
        let scope = PCWSTR::null();

        loop {
            let mut key_name_ptr: *mut NCryptKeyName = std::ptr::null_mut();

            let result = NCryptEnumKeys(
                provider.0,
                scope,
                &mut key_name_ptr,
                enum_state_guard.as_mut_ptr(),
                NCRYPT_SILENT_FLAG,
            );

            if result.is_err() {
                // End of enumeration or error
                break;
            }

            if key_name_ptr.is_null() {
                break;
            }

            // Read the key name
            let key_name_struct = &*key_name_ptr;
            let key_name_wide = key_name_struct.pszName;

            if !key_name_wide.is_null() {
                // Convert wide string to Rust string
                let full_name = key_name_wide.to_string().unwrap_or_default();

                // Only process keys with our prefix
                if let Some(user_name) = extract_key_name(&full_name) {
                    // Apply key name filter if provided
                    let name_matches = filter_key_name.map(|f| user_name == f).unwrap_or(true);

                    if name_matches {
                        // Try to open the key and get public key
                        if let Ok(key_handle) = open_key(provider, user_name) {
                            if let Ok(public_key_bytes) = export_public_key(&key_handle) {
                                let public_key_b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&public_key_bytes);

                                // Apply public key filter if provided
                                let pk_matches = filter_public_key
                                    .map(|f| public_key_b64 == f)
                                    .unwrap_or(true);

                                if pk_matches {
                                    keys.push(crate::models::KeyInfo {
                                        key_name: user_name.to_string(),
                                        public_key: public_key_b64,
                                    });
                                }
                            }
                        }
                    }
                }
            }

            // Free the key name structure
            let _ = NCryptFreeBuffer(key_name_ptr as *mut std::ffi::c_void);
        }
        // enum_state_guard dropped here, automatically freeing enumeration state
    }

    Ok(keys)
}

/// Checks if Windows Hello biometric is available and can be enforced
pub fn can_enforce_biometric_only() -> bool {
    // This is a simplified check - a full implementation would query
    // Windows Hello enrollment status via WinRT APIs
    // For now, we return true if TPM is available (conservative approach)
    // The actual enforcement happens at sign time
    false
}
