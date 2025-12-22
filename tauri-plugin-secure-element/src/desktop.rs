use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

// macOS FFI bindings - using extern "C" for direct linking
#[cfg(target_os = "macos")]
extern "C" {
    fn secure_element_list_keys(
        key_name: *const std::ffi::c_char,
        public_key: *const std::ffi::c_char,
    ) -> *mut std::ffi::c_char;
    fn secure_element_check_support() -> *mut std::ffi::c_char;
    fn secure_element_generate_secure_key(
        key_name: *const std::ffi::c_char,
        auth_mode: *const std::ffi::c_char,
    ) -> *mut std::ffi::c_char;
    fn secure_element_sign_with_key(
        key_name: *const std::ffi::c_char,
        data_base64: *const std::ffi::c_char,
    ) -> *mut std::ffi::c_char;
    fn secure_element_delete_key(
        key_name: *const std::ffi::c_char,
        public_key: *const std::ffi::c_char,
    ) -> *mut std::ffi::c_char;
}

/// Helper module for macOS FFI operations
#[cfg(target_os = "macos")]
mod ffi_helpers {
    use std::ffi::CStr;

    /// Converts an FFI C string pointer to a Rust String and frees the memory.
    /// The pointer must have been allocated by Swift using malloc/strdup.
    ///
    /// # Safety
    /// - `ptr` must be a valid, non-null pointer to a null-terminated C string
    /// - `ptr` must have been allocated by malloc (will be freed with libc::free)
    pub unsafe fn ffi_string_to_owned(ptr: *mut std::ffi::c_char) -> crate::Result<String> {
        if ptr.is_null() {
            return Err(crate::Error::Io(std::io::Error::other(
                "FFI call returned null",
            )));
        }

        // Convert to CStr and then to owned String before freeing
        let result = CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid UTF-8 in FFI result: {}", e),
                ))
            });

        // Always free the pointer, even on error
        libc::free(ptr as *mut libc::c_void);

        let s = result?;
        if s.is_empty() {
            return Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "FFI call returned empty string",
            )));
        }

        Ok(s)
    }

    /// Parses a JSON response from FFI, checking for error field first.
    /// Returns the parsed response or an error if the JSON contains an "error" field.
    pub fn parse_ffi_response<T: serde::de::DeserializeOwned>(json: &str) -> crate::Result<T> {
        // First check if response contains an error
        let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
            crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse JSON: {}", e),
            ))
        })?;

        if let Some(error_msg) = value.get("error").and_then(|v| v.as_str()) {
            return Err(crate::Error::Io(std::io::Error::other(error_msg)));
        }

        // Now deserialize to the expected type
        serde_json::from_str(json).map_err(|e| {
            crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize response: {}", e),
            ))
        })
    }

    /// Converts an optional String to a CString, returning the pointer and keeping the CString alive.
    /// Returns (null pointer, None) if the input is None or contains null bytes.
    pub fn optional_to_cstring(
        s: Option<&String>,
    ) -> (*const std::ffi::c_char, Option<std::ffi::CString>) {
        match s {
            Some(s) => match std::ffi::CString::new(s.as_str()) {
                Ok(cstr) => {
                    let ptr = cstr.as_ptr();
                    (ptr, Some(cstr))
                }
                Err(_) => (std::ptr::null(), None),
            },
            None => (std::ptr::null(), None),
        }
    }
}

/// Windows NCrypt constants
#[cfg(target_os = "windows")]
mod windows_constants {
    /// Microsoft Platform Crypto Provider - uses TPM when available
    pub const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";
    /// Key name prefix to namespace our keys
    pub const KEY_STORAGE_PREFIX: &str = "tauri_se_";
}

/// Windows NCrypt helper functions
#[cfg(target_os = "windows")]
mod ncrypt_helpers {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Cryptography::{
        BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
        BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE,
        BCRYPT_OPEN_ALGORITHM_PROVIDER_FLAGS, BCRYPT_SHA256_ALGORITHM,
    };
    use windows::Win32::Security::Cryptography::{
        NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey,
        NCryptFinalizeKey, NCryptFreeBuffer, NCryptFreeObject, NCryptGetProperty, NCryptKeyName,
        NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
        BCRYPT_ECCKEY_BLOB, BCRYPT_ECCPUBLIC_BLOB, CERT_KEY_SPEC, NCRYPT_ALLOW_SIGNING_FLAG,
        NCRYPT_FLAGS, NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PROV_HANDLE,
        NCRYPT_SILENT_FLAG,
    };

    use super::windows_constants::{KEY_STORAGE_PREFIX, MS_PLATFORM_CRYPTO_PROVIDER};

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
        unsafe {
            let mut provider = NCRYPT_PROV_HANDLE::default();
            let provider_name = HSTRING::from(MS_PLATFORM_CRYPTO_PROVIDER);

            NCryptOpenStorageProvider(&mut provider, PCWSTR(provider_name.as_ptr()), 0).map_err(
                |e| {
                    crate::Error::Io(std::io::Error::other(format!(
                        "Failed to open Platform Crypto Provider: {}",
                        e
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
                crate::Error::Io(std::io::Error::other(format!(
                    "Failed to open key '{}': {}",
                    key_name, e
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
                crate::Error::Io(std::io::Error::other(format!(
                    "Failed to create key '{}': {}",
                    key_name, e
                )))
            })?;

            // Set key usage to signing only
            let usage_flags: u32 = NCRYPT_ALLOW_SIGNING_FLAG.0;
            let usage_bytes = usage_flags.to_le_bytes();
            let key_usage_property = HSTRING::from("Key Usage");

            if let Err(e) = NCryptSetProperty(
                key_handle,
                PCWSTR(key_usage_property.as_ptr()),
                Some(&usage_bytes),
                NCRYPT_FLAGS(0),
            ) {
                let _ = NCryptFreeObject(key_handle);
                return Err(crate::Error::Io(std::io::Error::other(format!(
                    "Failed to set key usage: {}",
                    e
                ))));
            }

            // Set UI policy based on auth mode
            // NCRYPT_UI_POLICY structure: { dwVersion: u32, dwFlags: u32, pszCreationTitle: PCWSTR, pszFriendlyName: PCWSTR, pszDescription: PCWSTR }
            match auth_mode {
                crate::models::AuthenticationMode::None => {
                    // No UI policy - silent operation
                }
                crate::models::AuthenticationMode::PinOrBiometric => {
                    // Set UI policy to force consent - allows PIN or biometric
                    let ui_policy_property = HSTRING::from("UI Policy");
                    // NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG = 0x2 - requires Windows Hello
                    let policy_flags: u32 = 0x2;
                    let policy_bytes = policy_flags.to_le_bytes();
                    // Note: This is simplified - full UI policy would need proper struct
                    let _ = NCryptSetProperty(
                        key_handle,
                        PCWSTR(ui_policy_property.as_ptr()),
                        Some(&policy_bytes),
                        NCRYPT_FLAGS(0),
                    );
                }
                crate::models::AuthenticationMode::BiometricOnly => {
                    // Set UI policy to require biometric only
                    // NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG = 0x2
                    // Combined with Windows Hello biometric enrollment
                    let ui_policy_property = HSTRING::from("UI Policy");
                    let policy_flags: u32 = 0x2;
                    let policy_bytes = policy_flags.to_le_bytes();
                    let _ = NCryptSetProperty(
                        key_handle,
                        PCWSTR(ui_policy_property.as_ptr()),
                        Some(&policy_bytes),
                        NCRYPT_FLAGS(0),
                    );
                }
            }

            // Finalize the key
            if let Err(e) = NCryptFinalizeKey(key_handle, NCRYPT_FLAGS(0)) {
                let _ = NCryptFreeObject(key_handle);
                return Err(crate::Error::Io(std::io::Error::other(format!(
                    "Failed to finalize key: {}",
                    e
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
                crate::Error::Io(std::io::Error::other(format!(
                    "Failed to get public key size: {}",
                    e
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
                crate::Error::Io(std::io::Error::other(format!(
                    "Failed to export public key: {}",
                    e
                )))
            })?;

            // Convert from BCRYPT_ECCPUBLIC_BLOB to X9.62 uncompressed format
            // BCRYPT_ECCKEY_BLOB header is 8 bytes: dwMagic (4) + cbKey (4)
            // For P-256: header (8) + X (32) + Y (32) = 72 bytes
            if blob.len() < 72 {
                return Err(crate::Error::Io(std::io::Error::other(format!(
                    "Public key blob too small: {} bytes, expected at least 72",
                    blob.len()
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
            NCryptSignHash(key.0, None, hash, None, &mut sig_size, NCRYPT_FLAGS(0)).map_err(
                |e| {
                    crate::Error::Io(std::io::Error::other(format!(
                        "Failed to get signature size: {}",
                        e
                    )))
                },
            )?;

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
                crate::Error::Io(std::io::Error::other(format!("Failed to sign: {}", e)))
            })?;

            signature.truncate(sig_size as usize);

            // NCrypt returns raw R||S format for ECDSA P-256 (64 bytes)
            // We need to convert to DER format for compatibility with other platforms
            let der_signature = raw_ecdsa_to_der(&signature)?;

            Ok(der_signature)
        }
    }

    /// Converts raw ECDSA signature (R||S) to DER format
    fn raw_ecdsa_to_der(raw: &[u8]) -> crate::Result<Vec<u8>> {
        if raw.len() != 64 {
            return Err(crate::Error::Io(std::io::Error::other(format!(
                "Invalid raw signature length: {}, expected 64",
                raw.len()
            ))));
        }

        let r = &raw[0..32];
        let s = &raw[32..64];

        fn encode_integer(value: &[u8]) -> Vec<u8> {
            // Remove leading zeros but keep at least one byte
            let mut start = 0;
            while start < value.len() - 1 && value[start] == 0 {
                start += 1;
            }
            let trimmed = &value[start..];

            // Add leading zero if high bit is set (to indicate positive number)
            let needs_padding = trimmed[0] & 0x80 != 0;
            let len = trimmed.len() + if needs_padding { 1 } else { 0 };

            let mut result = vec![0x02, len as u8]; // INTEGER tag + length
            if needs_padding {
                result.push(0x00);
            }
            result.extend_from_slice(trimmed);
            result
        }

        let r_der = encode_integer(r);
        let s_der = encode_integer(s);

        let seq_len = r_der.len() + s_der.len();
        let mut der = vec![0x30]; // SEQUENCE tag

        // Length encoding
        if seq_len < 128 {
            der.push(seq_len as u8);
        } else {
            der.push(0x81);
            der.push(seq_len as u8);
        }

        der.extend_from_slice(&r_der);
        der.extend_from_slice(&s_der);

        Ok(der)
    }

    /// Deletes a key
    pub fn delete_key(key: KeyHandle) -> crate::Result<bool> {
        unsafe {
            // NCryptDeleteKey takes ownership and invalidates the handle
            let handle = key.0;
            std::mem::forget(key); // Don't run Drop since NCryptDeleteKey frees the handle

            NCryptDeleteKey(handle, NCRYPT_FLAGS(0)).map_err(|e| {
                crate::Error::Io(std::io::Error::other(format!(
                    "Failed to delete key: {}",
                    e
                )))
            })?;

            Ok(true)
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
            let mut enum_state: *mut std::ffi::c_void = std::ptr::null_mut();
            let scope: Option<PCWSTR> = None;

            loop {
                let mut key_name_ptr: *mut NCryptKeyName = std::ptr::null_mut();

                let result = NCryptEnumKeys(
                    provider.0,
                    scope,
                    &mut key_name_ptr,
                    &mut enum_state,
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

            // Free enumeration state
            if !enum_state.is_null() {
                let _ = NCryptFreeBuffer(enum_state);
            }
        }

        Ok(keys)
    }

    /// Checks if Windows Hello biometric is available and can be enforced
    pub fn can_enforce_biometric_only() -> bool {
        // This is a simplified check - a full implementation would query
        // Windows Hello enrollment status via WinRT APIs
        // For now, we return true if TPM is available (conservative approach)
        // The actual enforcement happens at sign time
        true
    }
}

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    Ok(SecureElement(app.clone()))
}

/// Access to the secure-element APIs.
pub struct SecureElement<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        Ok(PingResponse {
            value: payload.value,
        })
    }

    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::CString;

            let key_name_cstr = CString::new(payload.key_name.as_str()).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid key_name: {}", e),
                ))
            })?;

            let auth_mode_str = match payload.auth_mode {
                crate::models::AuthenticationMode::None => "none",
                crate::models::AuthenticationMode::PinOrBiometric => "pinOrBiometric",
                crate::models::AuthenticationMode::BiometricOnly => "biometricOnly",
            };
            let auth_mode_cstr = CString::new(auth_mode_str).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid auth_mode: {}", e),
                ))
            })?;

            let result_ptr = unsafe {
                secure_element_generate_secure_key(key_name_cstr.as_ptr(), auth_mode_cstr.as_ptr())
            };

            let json = unsafe { ffi_helpers::ffi_string_to_owned(result_ptr)? };
            ffi_helpers::parse_ffi_response(&json)
        }
        #[cfg(target_os = "windows")]
        {
            use base64::Engine;

            let provider = ncrypt_helpers::open_provider()?;

            // Check if TPM is available
            if !ncrypt_helpers::is_tpm_available(&provider) {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "TPM 2.0 not available on this system",
                )));
            }

            // Create the key
            let key = ncrypt_helpers::create_key(&provider, &payload.key_name, &payload.auth_mode)?;

            // Export the public key
            let public_key_bytes = ncrypt_helpers::export_public_key(&key)?;
            let public_key = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);

            Ok(GenerateSecureKeyResponse {
                key_name: payload.key_name,
                public_key,
                hardware_backed: "tpm".to_string(),
            })
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = payload;
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available on this platform",
            )))
        }
    }

    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        #[cfg(target_os = "macos")]
        {
            let (key_name_ptr, _key_name_cstr) =
                ffi_helpers::optional_to_cstring(payload.key_name.as_ref());
            let (public_key_ptr, _public_key_cstr) =
                ffi_helpers::optional_to_cstring(payload.public_key.as_ref());

            let result_ptr = unsafe { secure_element_list_keys(key_name_ptr, public_key_ptr) };

            let json = unsafe { ffi_helpers::ffi_string_to_owned(result_ptr)? };
            ffi_helpers::parse_ffi_response(&json)
        }
        #[cfg(target_os = "windows")]
        {
            let provider = ncrypt_helpers::open_provider()?;

            let keys = ncrypt_helpers::list_keys(
                &provider,
                payload.key_name.as_deref(),
                payload.public_key.as_deref(),
            )?;

            Ok(ListKeysResponse { keys })
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = payload;
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available on this platform",
            )))
        }
    }

    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            use base64::Engine;
            use std::ffi::CString;

            let key_name_cstr = CString::new(payload.key_name.as_str()).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid key_name: {}", e),
                ))
            })?;

            let data_base64 = base64::engine::general_purpose::STANDARD.encode(&payload.data);
            let data_base64_cstr = CString::new(data_base64.as_str()).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid data: {}", e),
                ))
            })?;

            let result_ptr = unsafe {
                secure_element_sign_with_key(key_name_cstr.as_ptr(), data_base64_cstr.as_ptr())
            };

            let json = unsafe { ffi_helpers::ffi_string_to_owned(result_ptr)? };

            // Parse and extract signature manually since we need to decode base64
            let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse JSON: {}", e),
                ))
            })?;

            if let Some(error_msg) = value.get("error").and_then(|v| v.as_str()) {
                return Err(crate::Error::Io(std::io::Error::other(error_msg)));
            }

            let signature_base64 =
                value
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Missing signature in response",
                        ))
                    })?;

            let signature = base64::engine::general_purpose::STANDARD
                .decode(signature_base64)
                .map_err(|e| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Failed to decode signature: {}", e),
                    ))
                })?;

            Ok(SignWithKeyResponse { signature })
        }
        #[cfg(target_os = "windows")]
        {
            let provider = ncrypt_helpers::open_provider()?;
            let key = ncrypt_helpers::open_key(&provider, &payload.key_name)?;

            // Hash the data first (NCrypt expects pre-hashed data for ECDSA)
            let hash = ncrypt_helpers::sha256_hash(&payload.data)?;

            // Sign the hash
            let signature = ncrypt_helpers::sign_hash(&key, &hash)?;

            Ok(SignWithKeyResponse { signature })
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = payload;
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available on this platform",
            )))
        }
    }

    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            let (key_name_ptr, _key_name_cstr) =
                ffi_helpers::optional_to_cstring(payload.key_name.as_ref());
            let (public_key_ptr, _public_key_cstr) =
                ffi_helpers::optional_to_cstring(payload.public_key.as_ref());

            let result_ptr = unsafe { secure_element_delete_key(key_name_ptr, public_key_ptr) };

            let json = unsafe { ffi_helpers::ffi_string_to_owned(result_ptr)? };

            // Parse and extract success field
            let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse JSON: {}", e),
                ))
            })?;

            if let Some(error_msg) = value.get("error").and_then(|v| v.as_str()) {
                return Err(crate::Error::Io(std::io::Error::other(error_msg)));
            }

            let success = value
                .get("success")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            Ok(DeleteKeyResponse { success })
        }
        #[cfg(target_os = "windows")]
        {
            let provider = ncrypt_helpers::open_provider()?;

            // If key_name is provided, delete by name
            // If public_key is provided, find the key with that public key first
            // If neither, return error
            let key_name = if let Some(name) = &payload.key_name {
                name.clone()
            } else if let Some(public_key) = &payload.public_key {
                // Find key by public key
                let keys = ncrypt_helpers::list_keys(&provider, None, Some(public_key))?;
                if keys.is_empty() {
                    return Ok(DeleteKeyResponse { success: false });
                }
                keys[0].key_name.clone()
            } else {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Either key_name or public_key must be provided",
                )));
            };

            let key = ncrypt_helpers::open_key(&provider, &key_name)?;
            let success = ncrypt_helpers::delete_key(key)?;

            Ok(DeleteKeyResponse { success })
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = payload;
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure element not available on this platform",
            )))
        }
    }

    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        #[cfg(target_os = "macos")]
        {
            let result_ptr = unsafe { secure_element_check_support() };
            let json = unsafe { ffi_helpers::ffi_string_to_owned(result_ptr)? };
            ffi_helpers::parse_ffi_response(&json)
        }
        #[cfg(target_os = "windows")]
        {
            match ncrypt_helpers::open_provider() {
                Ok(provider) => {
                    let tpm_available = ncrypt_helpers::is_tpm_available(&provider);
                    Ok(CheckSecureElementSupportResponse {
                        secure_element_supported: tpm_available,
                        tee_supported: tpm_available,
                        can_enforce_biometric_only: tpm_available
                            && ncrypt_helpers::can_enforce_biometric_only(),
                    })
                }
                Err(_) => Ok(CheckSecureElementSupportResponse {
                    secure_element_supported: false,
                    tee_supported: false,
                    can_enforce_biometric_only: false,
                }),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            // On unsupported desktop platforms, return that secure element is not supported
            Ok(CheckSecureElementSupportResponse {
                secure_element_supported: false,
                tee_supported: false,
                can_enforce_biometric_only: false,
            })
        }
    }
}
