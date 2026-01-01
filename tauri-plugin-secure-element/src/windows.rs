use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeBuffer, NCryptFreeObject, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, NCryptSignHash, CERT_KEY_SPEC, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_FLAGS,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};

use crate::error_sanitize::sanitize_error;
use crate::windows_hello;

/// Microsoft Platform Crypto Provider - uses TPM when available (for keys without Windows Hello)
pub const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// Microsoft Passport Key Storage Provider - for Windows Hello protected keys
pub const MS_NGC_KEY_STORAGE_PROVIDER: &str = "Microsoft Passport Key Storage Provider";

/// Key name prefix for TPM keys without Windows Hello protection
pub const KEY_PREFIX_TPM: &str = "tauri_se_tpm_";

/// Property to require gesture (biometric/PIN) for each operation
const NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY: &str = "PinCacheIsGestureRequired";

/// Window handle property for UI parenting
const NCRYPT_WINDOW_HANDLE_PROPERTY: &str = "HWND Handle";

/// Use context property for custom UI messages
const NCRYPT_USE_CONTEXT_PROPERTY: &str = "Use Context";

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

/// Opens the Microsoft Platform Crypto Provider (TPM-backed, no Windows Hello)
pub fn open_provider() -> crate::Result<ProviderHandle> {
    open_provider_by_name(MS_PLATFORM_CRYPTO_PROVIDER)
}

/// Opens the Microsoft Passport Key Storage Provider (Windows Hello)
pub fn open_ngc_provider() -> crate::Result<ProviderHandle> {
    open_provider_by_name(MS_NGC_KEY_STORAGE_PROVIDER)
}

/// Opens a storage provider by name
fn open_provider_by_name(provider_name: &str) -> crate::Result<ProviderHandle> {
    require_windows_11()?;

    unsafe {
        let mut provider = NCRYPT_PROV_HANDLE::default();
        let provider_name_h = HSTRING::from(provider_name);

        NCryptOpenStorageProvider(&mut provider, PCWSTR(provider_name_h.as_ptr()), 0).map_err(
            |e| {
                crate::Error::Io(std::io::Error::other(sanitize_error(
                    &format!("Failed to open {}: {}", provider_name, e),
                    &format!("Failed to open {}", provider_name),
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

/// Determines the provider type from a key name based on its prefix
pub enum KeyProviderType {
    /// NGC (Windows Hello) protected key
    Ngc,
    /// TPM key without Windows Hello
    Tpm,
}

/// Opens an existing key by name, automatically detecting the correct provider
pub fn open_key_auto(key_name: &str) -> crate::Result<(KeyHandle, KeyProviderType)> {
    // Try NGC provider first (keys have format {SID}//tauri_se//{key_name})
    if let Ok(sid) = get_current_user_sid() {
        let ngc_full_name = format!("{}//tauri_se//{}", sid, key_name);
        if let Ok(ngc_provider) = open_ngc_provider() {
            if let Ok(key) = open_key_internal(&ngc_provider, &ngc_full_name) {
                return Ok((key, KeyProviderType::Ngc));
            }
        }
    }

    // Try TPM provider
    let tpm_full_name = format!("{}{}", KEY_PREFIX_TPM, key_name);
    let tpm_provider = open_provider()?;
    let key = open_key_internal(&tpm_provider, &tpm_full_name)?;
    Ok((key, KeyProviderType::Tpm))
}

/// Opens an existing key by full name from a specific provider
fn open_key_internal(provider: &ProviderHandle, full_name: &str) -> crate::Result<KeyHandle> {
    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_name_h = HSTRING::from(full_name);

        NCryptOpenKey(
            provider.0,
            &mut key_handle,
            PCWSTR(key_name_h.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to open key '{}': {}", full_name, e),
                "Failed to open key",
            )))
        })?;

        Ok(KeyHandle(key_handle))
    }
}

/// Checks if a key with the given name already exists in either provider
fn key_exists(key_name: &str) -> bool {
    // Check NGC provider
    if let Ok(sid) = get_current_user_sid() {
        let ngc_full_name = format!("{}//tauri_se//{}", sid, key_name);
        if let Ok(ngc_provider) = open_ngc_provider() {
            if open_key_internal(&ngc_provider, &ngc_full_name).is_ok() {
                return true;
            }
        }
    }

    // Check TPM provider
    let tpm_full_name = format!("{}{}", KEY_PREFIX_TPM, key_name);
    if let Ok(tpm_provider) = open_provider() {
        if open_key_internal(&tpm_provider, &tpm_full_name).is_ok() {
            return true;
        }
    }

    false
}

/// Creates a new P-256 ECDSA key with the appropriate provider based on auth mode
pub fn create_key(
    key_name: &str,
    auth_mode: &crate::models::AuthenticationMode,
) -> crate::Result<KeyHandle> {
    // Check if a key with this name already exists in either provider
    if key_exists(key_name) {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("A key with name '{}' already exists", key_name),
        )));
    }

    // Validate Windows Hello requirements before creating the key
    match auth_mode {
        crate::models::AuthenticationMode::BiometricOnly => {
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "biometricOnly authentication mode is not supported on Windows. Use 'pinOrBiometric' instead.",
            )))
        }
        crate::models::AuthenticationMode::PinOrBiometric => {
            if !windows_hello::is_windows_hello_configured() {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Windows Hello is not configured or enrolled on this system. Please set up Windows Hello (PIN or biometric) in Windows Settings before creating keys with authentication.",
                )));
            }
            create_ngc_key(key_name)
        }
        crate::models::AuthenticationMode::None => create_tpm_key(key_name),
    }
}

/// Gets the current user's SID as a string
fn get_current_user_sid() -> crate::Result<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to open process token: {}",
                e
            )))
        })?;

        // Get required buffer size
        let mut size_needed: u32 = 0;
        let _ = GetTokenInformation(token_handle, TokenUser, None, 0, &mut size_needed);

        // Allocate buffer and get token info
        let mut buffer = vec![0u8; size_needed as usize];
        let result = GetTokenInformation(
            token_handle,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            size_needed,
            &mut size_needed,
        );

        // Close token handle now that we're done with it
        let _ = CloseHandle(token_handle);

        result.map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to get token information: {}",
                e
            )))
        })?;

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);

        // Convert SID to string
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        let mut sid_string_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string_ptr).map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to convert SID to string: {}",
                e
            )))
        })?;

        let sid_string = sid_string_ptr.to_string().map_err(|e| {
            // Free the SID string before returning error
            let _ = LocalFree(HLOCAL(sid_string_ptr.as_ptr() as *mut _));
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to read SID string: {}",
                e
            )))
        })?;

        // Free the SID string allocated by ConvertSidToStringSidW
        let _ = LocalFree(HLOCAL(sid_string_ptr.as_ptr() as *mut _));

        Ok(sid_string)
    }
}

/// Creates a key in the NGC (Windows Hello) provider
fn create_ngc_key(key_name: &str) -> crate::Result<KeyHandle> {
    let provider = open_ngc_provider()?;

    // Get current user SID for the key name format required by Passport KSP
    let sid = get_current_user_sid()?;

    // Format: [SID]//[Domain]/[SubDomain]/[KeyName]
    // Domain = "tauri_se", SubDomain = "", KeyName = user's key name
    let full_name = format!("{}//tauri_se//{}", sid, key_name);

    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_name_h = HSTRING::from(full_name.as_str());

        // Use ECDSA P-256 for cross-platform consistency
        let algorithm = HSTRING::from("ECDSA_P256");

        // Create the key - dwLegacyKeySpec is ignored for CNG, use 0
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
                &format!("NCryptCreatePersistedKey failed for '{}': {}", key_name, e),
                "Failed to create key",
            )))
        })?;

        // Set key usage to signing only
        let usage: u32 = NCRYPT_ALLOW_SIGNING_FLAG;
        let key_usage_property = HSTRING::from("Key Usage");

        if let Err(e) = NCryptSetProperty(
            key_handle,
            PCWSTR(key_usage_property.as_ptr()),
            &usage.to_le_bytes(),
            NCRYPT_FLAGS(0),
        ) {
            let _ = NCryptFreeObject(key_handle);
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to set key usage: {}", e),
                "Failed to set key usage",
            ))));
        }

        // Finalize the key with NCRYPT_SILENT_FLAG to prevent Windows Hello prompt
        // The prompt should only appear during signing, not creation
        if let Err(e) = NCryptFinalizeKey(key_handle, NCRYPT_SILENT_FLAG) {
            let _ = NCryptFreeObject(key_handle);
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("NCryptFinalizeKey failed: {}", e),
                "Failed to finalize key",
            ))));
        }

        // Note: We intentionally do NOT set NgcCacheType here.
        // The Passport KSP already triggers Windows Hello during signing operations
        // by default when keys are stored in the NGC container.

        Ok(KeyHandle(key_handle))
    }
}

/// Creates a key in the TPM provider (no Windows Hello)
fn create_tpm_key(key_name: &str) -> crate::Result<KeyHandle> {
    let provider = open_provider()?;

    // Check if TPM is available
    if !is_tpm_available(&provider) {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TPM 2.0 not available on this system",
        )));
    }

    let full_name = format!("{}{}", KEY_PREFIX_TPM, key_name);

    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
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
                &format!("Failed to create TPM key '{}': {}", key_name, e),
                "Failed to create key",
            )))
        })?;

        // Set key usage to signing only
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

        // No UI policy for TPM keys - silent operation

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
/// For TPM keys, this is silent. For NGC keys, use sign_hash_with_window instead.
pub fn sign_hash(key: &KeyHandle, hash: &[u8]) -> crate::Result<Vec<u8>> {
    sign_hash_internal(key, hash)
}

/// Signs data with the given NGC key, triggering Windows Hello authentication
/// The hwnd parameter is used to parent the Windows Hello dialog
pub fn sign_hash_with_window(
    key: &KeyHandle,
    hash: &[u8],
    hwnd: Option<isize>,
) -> crate::Result<Vec<u8>> {
    unsafe {
        // Set window handle for UI parenting if provided
        if let Some(handle) = hwnd {
            let hwnd_property = HSTRING::from(NCRYPT_WINDOW_HANDLE_PROPERTY);
            let hwnd_bytes = handle.to_ne_bytes();

            // Ignore errors - the signing will still work, just with a potentially
            // less well-positioned dialog
            let _ = NCryptSetProperty(
                key.0,
                PCWSTR(hwnd_property.as_ptr()),
                &hwnd_bytes,
                NCRYPT_FLAGS(0),
            );
        }

        // Set use context for a custom message
        let context_property = HSTRING::from(NCRYPT_USE_CONTEXT_PROPERTY);
        let context_message = HSTRING::from("Authenticate to sign data");
        let context_bytes: Vec<u8> = context_message
            .as_wide()
            .iter()
            .flat_map(|&c| c.to_le_bytes())
            .collect();

        let _ = NCryptSetProperty(
            key.0,
            PCWSTR(context_property.as_ptr()),
            &context_bytes,
            NCRYPT_FLAGS(0),
        );

        // Set gesture required property to force biometric/PIN prompt
        let gesture_property = HSTRING::from(NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY);
        let gesture_required: u32 = 1;
        let gesture_bytes = gesture_required.to_le_bytes();

        let _ = NCryptSetProperty(
            key.0,
            PCWSTR(gesture_property.as_ptr()),
            &gesture_bytes,
            NCRYPT_FLAGS(0),
        );
    }

    // Now perform the actual signing - this should trigger Windows Hello
    sign_hash_internal(key, hash)
}

/// Internal signing function
fn sign_hash_internal(key: &KeyHandle, hash: &[u8]) -> crate::Result<Vec<u8>> {
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

/// NGC key marker in the key name format: {SID}/{GUID}/tauri_se//{key_name}
/// Windows inserts a GUID between SID and our domain, so we look for /tauri_se//
const NGC_KEY_MARKER: &str = "/tauri_se//";

/// Extracts user key name from NGC format: {SID}//tauri_se//{key_name} -> key_name
fn extract_ngc_key_name(full_name: &str) -> Option<&str> {
    full_name
        .find(NGC_KEY_MARKER)
        .map(|pos| &full_name[pos + NGC_KEY_MARKER.len()..])
}

/// Lists keys from a specific provider with the given prefix (for TPM keys)
fn list_keys_from_provider(
    provider: &ProviderHandle,
    prefix: &str,
    filter_key_name: Option<&str>,
    filter_public_key: Option<&str>,
) -> crate::Result<Vec<crate::models::KeyInfo>> {
    use base64::Engine;
    let mut keys = Vec::new();

    unsafe {
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
                break;
            }

            if key_name_ptr.is_null() {
                break;
            }

            let key_name_struct = &*key_name_ptr;
            let key_name_wide = key_name_struct.pszName;

            if !key_name_wide.is_null() {
                let full_name = key_name_wide.to_string().unwrap_or_default();

                // Only process keys with our prefix
                if let Some(user_name) = full_name.strip_prefix(prefix) {
                    let name_matches = filter_key_name.map(|f| user_name == f).unwrap_or(true);

                    if name_matches {
                        // Try to open the key and get public key
                        if let Ok(key_handle) = open_key_internal(provider, &full_name) {
                            if let Ok(public_key_bytes) = export_public_key(&key_handle) {
                                let public_key_b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&public_key_bytes);

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

            let _ = NCryptFreeBuffer(key_name_ptr as *mut std::ffi::c_void);
        }
    }

    Ok(keys)
}

/// Lists keys from the NGC provider (keys have format {SID}/{GUID}/tauri_se//{key_name})
fn list_ngc_keys(
    provider: &ProviderHandle,
    filter_key_name: Option<&str>,
    filter_public_key: Option<&str>,
) -> crate::Result<Vec<crate::models::KeyInfo>> {
    use base64::Engine;
    let mut keys = Vec::new();

    unsafe {
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
                break;
            }

            if key_name_ptr.is_null() {
                break;
            }

            let key_name_struct = &*key_name_ptr;
            let key_name_wide = key_name_struct.pszName;

            if !key_name_wide.is_null() {
                let full_name = key_name_wide.to_string().unwrap_or_default();

                // Check for our NGC key marker: /tauri_se//
                if let Some(user_name) = extract_ngc_key_name(&full_name) {
                    let name_matches = filter_key_name.map(|f| user_name == f).unwrap_or(true);

                    if name_matches {
                        // Try to open the key and get public key
                        if let Ok(key_handle) = open_key_internal(provider, &full_name) {
                            if let Ok(public_key_bytes) = export_public_key(&key_handle) {
                                let public_key_b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&public_key_bytes);

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

            let _ = NCryptFreeBuffer(key_name_ptr as *mut std::ffi::c_void);
        }
    }

    Ok(keys)
}

/// Lists all keys from both providers
pub fn list_keys(
    filter_key_name: Option<&str>,
    filter_public_key: Option<&str>,
) -> crate::Result<Vec<crate::models::KeyInfo>> {
    let mut all_keys = Vec::new();

    // List keys from TPM provider
    if let Ok(tpm_provider) = open_provider() {
        if let Ok(tpm_keys) = list_keys_from_provider(
            &tpm_provider,
            KEY_PREFIX_TPM,
            filter_key_name,
            filter_public_key,
        ) {
            all_keys.extend(tpm_keys);
        }
    }

    // List keys from NGC provider (uses different key name format)
    if let Ok(ngc_provider) = open_ngc_provider() {
        if let Ok(ngc_keys) = list_ngc_keys(&ngc_provider, filter_key_name, filter_public_key) {
            all_keys.extend(ngc_keys);
        }
    }

    Ok(all_keys)
}

/// Checks if Windows Hello biometric-only mode is available
pub fn can_enforce_biometric_only() -> bool {
    // Windows Hello doesn't distinguish between PIN and biometric at the API level,
    // so biometricOnly mode is not supported. Always return false.
    false
}

/// Gets the HWND as an isize from a raw window handle
#[cfg(target_os = "windows")]
pub fn hwnd_from_raw(handle: raw_window_handle::RawWindowHandle) -> Option<isize> {
    match handle {
        raw_window_handle::RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}
