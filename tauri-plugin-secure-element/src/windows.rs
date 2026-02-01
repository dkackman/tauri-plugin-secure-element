use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptGetProperty, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty, NCryptSignHash, CERT_KEY_SPEC, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_FLAGS,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsi_GetDeviceInfo, Tbsip_Context_Close, TBS_CONTEXT_PARAMS2,
    TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, TPM_DEVICE_INFO, TPM_VERSION_12, TPM_VERSION_20,
};

use crate::error_sanitize::sanitize_error;
use crate::windows_hello;
use crate::windows_raii::{
    EnumStateGuard, HLocalGuard, KeyHandle, KeyNameBufferGuard, ProviderHandle, WindowsHandleGuard,
};

/// Microsoft Platform Crypto Provider - uses TPM when available (for keys without Windows Hello)
pub const MS_PLATFORM_CRYPTO_PROVIDER: &str = "Microsoft Platform Crypto Provider";

/// Microsoft Passport Key Storage Provider - for Windows Hello protected keys
pub const MS_NGC_KEY_STORAGE_PROVIDER: &str = "Microsoft Passport Key Storage Provider";

/// Key name prefix base for TPM keys without Windows Hello protection
/// Full format: tauri_se_tpm_{app_id}_{key_name}
const KEY_PREFIX_TPM_BASE: &str = "tauri_se_tpm_";

/// Domain for NGC keys
const NGC_DOMAIN: &str = "tauri_se";

/// NTE_EXISTS error code - returned when trying to create a key that already exists
/// Value: 0x8009000F
const NTE_EXISTS: i32 = -2146893809i32;

/// Sanitizes an app identifier for use in key names.
/// Replaces dots, slashes, and other problematic characters with underscores.
fn sanitize_app_id(app_id: &str) -> String {
    app_id
        .chars()
        .map(|c| match c {
            '.' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            _ => c,
        })
        .collect()
}

/// Checks if a Windows error indicates that a key already exists (NTE_EXISTS)
fn is_key_exists_error(error: &windows::core::Error) -> bool {
    error.code().0 == NTE_EXISTS
}

/// Builds the TPM key prefix including the app identifier
fn tpm_key_prefix(app_id: &str) -> String {
    format!("{}{}_", KEY_PREFIX_TPM_BASE, sanitize_app_id(app_id))
}

/// Builds the full TPM key name
fn tpm_key_name(app_id: &str, key_name: &str) -> String {
    format!("{}{}", tpm_key_prefix(app_id), key_name)
}

/// Builds the NGC key marker for the given app identifier
/// Format: /tauri_se/{app_id}//
fn ngc_key_marker(app_id: &str) -> String {
    format!("/{}/{}/", NGC_DOMAIN, sanitize_app_id(app_id))
}

/// Builds the full NGC key name
/// Format: {SID}//tauri_se/{app_id}/{key_name}
fn ngc_key_name(sid: &str, app_id: &str, key_name: &str) -> String {
    format!(
        "{}//{}/{}/{}",
        sid,
        NGC_DOMAIN,
        sanitize_app_id(app_id),
        key_name
    )
}

/// Property to require gesture (biometric/PIN) for each operation
const NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY: &str = "PinCacheIsGestureRequired";

/// Window handle property for UI parenting
const NCRYPT_WINDOW_HANDLE_PROPERTY: &str = "HWND Handle";

/// Use context property for custom UI messages
const NCRYPT_USE_CONTEXT_PROPERTY: &str = "Use Context";

fn is_windows_11() -> crate::Result<bool> {
    let version = winver::WindowsVersion::detect().ok_or_else(|| {
        crate::Error::Io(std::io::Error::other("Failed to detect Windows version"))
    })?;

    // Windows 11 is version 10.0.22000 or higher
    let windows_11_min = winver::WindowsVersion::new(10, 0, 22000);

    Ok(version >= windows_11_min)
}

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

/// TPM version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmVersion {
    /// TPM 1.2 (older, limited algorithms)
    Tpm12,
    /// TPM 2.0 (current standard, required for this plugin)
    Tpm20,
    /// Unknown TPM version
    Unknown(u32),
}

impl std::fmt::Display for TpmVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmVersion::Tpm12 => write!(f, "TPM 1.2"),
            TpmVersion::Tpm20 => write!(f, "TPM 2.0"),
            TpmVersion::Unknown(v) => write!(f, "TPM (unknown version: {})", v),
        }
    }
}

/// Detailed TPM status information
#[derive(Debug)]
pub struct TpmStatus {
    /// Whether a TPM is present in the system
    pub present: bool,
    /// The TPM version, if detected
    pub version: Option<TpmVersion>,
    /// Whether the TPM meets requirements (TPM 2.0)
    pub meets_requirements: bool,
    /// Whether the Platform Crypto Provider can be opened
    pub provider_available: bool,
    /// Whether the provider is hardware-backed
    pub hardware_backed: bool,
    /// Human-readable status message
    pub message: String,
}

/// RAII guard for TBS context handle
struct TbsContextGuard(usize);

impl TbsContextGuard {
    fn new() -> Self {
        Self(0)
    }

    fn as_mut_ptr(&mut self) -> *mut usize {
        &mut self.0
    }

    fn handle(&self) -> usize {
        self.0
    }

    fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

impl Drop for TbsContextGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                let _ = Tbsip_Context_Close(self.0);
            }
        }
    }
}

/// Checks if a TPM is present using the TPM Base Services (TBS) API.
/// This is the most direct way to detect TPM presence.
pub fn is_tpm_present_tbs() -> bool {
    unsafe {
        let mut device_info = TPM_DEVICE_INFO::default();
        let result = Tbsi_GetDeviceInfo(std::mem::size_of::<TPM_DEVICE_INFO>() as u32, &mut device_info);
        result == TBS_SUCCESS
    }
}

/// Gets the TPM version using the TBS API.
/// Returns None if no TPM is present or version cannot be determined.
pub fn get_tpm_version() -> Option<TpmVersion> {
    unsafe {
        let mut device_info = TPM_DEVICE_INFO::default();
        let result = Tbsi_GetDeviceInfo(std::mem::size_of::<TPM_DEVICE_INFO>() as u32, &mut device_info);

        if result != TBS_SUCCESS {
            return None;
        }

        Some(match device_info.tpmVersion {
            TPM_VERSION_12 => TpmVersion::Tpm12,
            TPM_VERSION_20 => TpmVersion::Tpm20,
            v => TpmVersion::Unknown(v),
        })
    }
}

/// Checks if a TPM 2.0 is present and accessible.
pub fn is_tpm_2_0_present() -> bool {
    matches!(get_tpm_version(), Some(TpmVersion::Tpm20))
}

/// Verifies TPM functionality by attempting to create a TBS context.
/// This is a more thorough check than just querying device info.
pub fn can_create_tbs_context() -> bool {
    unsafe {
        let mut context = TbsContextGuard::new();
        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: std::mem::zeroed(),
        };

        let result = Tbsi_Context_Create(
            &params as *const TBS_CONTEXT_PARAMS2 as *const _,
            context.as_mut_ptr(),
        );

        // Context is automatically closed when guard is dropped
        result == TBS_SUCCESS && context.is_valid()
    }
}

/// NCrypt implementation type property name
const NCRYPT_IMPL_TYPE_PROPERTY: &str = "Impl Type";

/// Implementation type flag indicating hardware-based implementation
const NCRYPT_IMPL_HARDWARE_FLAG: u32 = 0x00000001;

/// Checks if the NCrypt provider is hardware-backed by querying its implementation type.
pub fn is_provider_hardware_backed(provider: &ProviderHandle) -> bool {
    if provider.0.is_invalid() {
        return false;
    }

    unsafe {
        let prop_name = HSTRING::from(NCRYPT_IMPL_TYPE_PROPERTY);
        let mut impl_type: u32 = 0;
        let mut result_size: u32 = 0;

        let result = NCryptGetProperty(
            provider.0,
            PCWSTR(prop_name.as_ptr()),
            Some(std::slice::from_raw_parts_mut(
                &mut impl_type as *mut u32 as *mut u8,
                std::mem::size_of::<u32>(),
            )),
            &mut result_size,
            NCRYPT_FLAGS(0),
        );

        if result.is_ok() && result_size == std::mem::size_of::<u32>() as u32 {
            (impl_type & NCRYPT_IMPL_HARDWARE_FLAG) != 0
        } else {
            false
        }
    }
}

/// Gets comprehensive TPM status information.
/// This performs multiple checks to provide detailed information about TPM availability.
pub fn get_tpm_status() -> TpmStatus {
    // Check 1: TBS API device info (most direct check)
    let tbs_present = is_tpm_present_tbs();
    let version = get_tpm_version();
    let is_tpm_2 = matches!(version, Some(TpmVersion::Tpm20));

    // Check 2: Can we create a TBS context? (functional check)
    let tbs_functional = if tbs_present {
        can_create_tbs_context()
    } else {
        false
    };

    // Check 3: Can we open the Platform Crypto Provider?
    let (provider_available, hardware_backed) = match open_provider_by_name(MS_PLATFORM_CRYPTO_PROVIDER) {
        Ok(provider) => {
            let hw_backed = is_provider_hardware_backed(&provider);
            (true, hw_backed)
        }
        Err(_) => (false, false),
    };

    // Determine overall status
    let meets_requirements = is_tpm_2 && tbs_functional && provider_available;

    let message = if !tbs_present {
        "No TPM detected in this system".to_string()
    } else if !is_tpm_2 {
        format!(
            "TPM detected but version is {}, TPM 2.0 required",
            version.map(|v| v.to_string()).unwrap_or_else(|| "unknown".to_string())
        )
    } else if !tbs_functional {
        "TPM 2.0 detected but TBS context creation failed - TPM may be disabled in BIOS".to_string()
    } else if !provider_available {
        "TPM 2.0 detected but Platform Crypto Provider unavailable".to_string()
    } else if !hardware_backed {
        "TPM 2.0 detected but provider reports software implementation".to_string()
    } else {
        "TPM 2.0 available and functional".to_string()
    };

    TpmStatus {
        present: tbs_present,
        version,
        meets_requirements,
        provider_available,
        hardware_backed,
        message,
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

/// Checks if TPM 2.0 is available and functional.
/// This performs comprehensive checks:
/// 1. Verifies the provider handle is valid
/// 2. Uses TBS API to confirm TPM 2.0 presence
/// 3. Verifies the provider is hardware-backed
pub fn is_tpm_available(provider: &ProviderHandle) -> bool {
    // Quick check: is the provider handle valid?
    if provider.0.is_invalid() {
        return false;
    }

    // Comprehensive check: is TPM 2.0 actually present and functional?
    is_tpm_2_0_present() && is_provider_hardware_backed(provider)
}

pub enum KeyProviderType {
    /// NGC (Windows Hello) protected key
    Ngc,
    /// TPM key without Windows Hello
    Tpm,
}

/// Opens an existing key by name, automatically detecting the correct provider
pub fn open_key_auto(app_id: &str, key_name: &str) -> crate::Result<(KeyHandle, KeyProviderType)> {
    // Try NGC provider first (keys have format {SID}//tauri_se/{app_id}/{key_name})
    if let Ok(sid) = get_current_user_sid() {
        let ngc_full_name = ngc_key_name(&sid, app_id, key_name);
        if let Ok(ngc_provider) = open_ngc_provider() {
            if let Ok(key) = open_key_internal(&ngc_provider, &ngc_full_name) {
                return Ok((key, KeyProviderType::Ngc));
            }
        }
    }

    // Try TPM provider
    let tpm_full_name = tpm_key_name(app_id, key_name);
    let tpm_provider = open_provider()?;
    let key = open_key_internal(&tpm_provider, &tpm_full_name)?;
    Ok((key, KeyProviderType::Tpm))
}

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

/// Creates a new P-256 ECDSA key with the appropriate provider based on auth mode
pub fn create_key(
    app_id: &str,
    key_name: &str,
    auth_mode: &crate::models::AuthenticationMode,
) -> crate::Result<KeyHandle> {
    // Note: We don't pre-check for key existence here to avoid TOCTOU race conditions.
    // Instead, we let NCryptCreatePersistedKey fail with NTE_EXISTS if the key already
    // exists, and handle that error appropriately in create_ngc_key/create_tpm_key.

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
            create_ngc_key(app_id, key_name)
        }
        crate::models::AuthenticationMode::None => create_tpm_key(app_id, key_name),
    }
}

fn get_current_user_sid() -> crate::Result<String> {
    unsafe {
        let mut token_handle_guard = WindowsHandleGuard::new();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            std::ptr::addr_of_mut!(token_handle_guard.0),
        )
        .map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to open process token: {}",
                e
            )))
        })?;

        // Get required buffer size
        let mut size_needed: u32 = 0;
        let _ = GetTokenInformation(token_handle_guard.0, TokenUser, None, 0, &mut size_needed);
        let mut buffer = vec![0u8; size_needed as usize];
        let result = GetTokenInformation(
            token_handle_guard.0,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            size_needed,
            &mut size_needed,
        );

        result.map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to get token information: {}",
                e
            )))
        })?;

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_string_ptr = windows::core::PWSTR::null();
        ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string_ptr).map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to convert SID to string: {}",
                e
            )))
        })?;

        let mut sid_string_guard = HLocalGuard::new();
        sid_string_guard.set_from_pwstr(sid_string_ptr);

        let sid_string = sid_string_ptr.to_string().map_err(|e| {
            crate::Error::Io(std::io::Error::other(format!(
                "Failed to read SID string: {}",
                e
            )))
        })?;

        Ok(sid_string)
    }
}

fn create_ngc_key(app_id: &str, key_name: &str) -> crate::Result<KeyHandle> {
    let provider = open_ngc_provider()?;

    let sid = get_current_user_sid()?;

    // Format: [SID]//[Domain]/[SubDomain]/[KeyName]
    // Domain = "tauri_se", SubDomain = sanitized app_id, KeyName = user's key name
    let full_name = ngc_key_name(&sid, app_id, key_name);

    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_name_h = HSTRING::from(full_name.as_str());

        let algorithm = HSTRING::from("ECDSA_P256");

        if let Err(e) = NCryptCreatePersistedKey(
            provider.0,
            &mut key_handle,
            PCWSTR(algorithm.as_ptr()),
            PCWSTR(key_name_h.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ) {
            // Check if the error is "key already exists" (NTE_EXISTS)
            if is_key_exists_error(&e) {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    sanitize_error(
                        &format!("A key with name '{}' already exists", key_name),
                        "Key already exists",
                    ),
                )));
            }
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("NCryptCreatePersistedKey failed for '{}': {}", key_name, e),
                "Failed to create key",
            ))));
        }

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

        if let Err(e) = NCryptFinalizeKey(key_handle, NCRYPT_SILENT_FLAG) {
            let _ = NCryptFreeObject(key_handle);
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("NCryptFinalizeKey failed: {}", e),
                "Failed to finalize key",
            ))));
        }

        Ok(KeyHandle(key_handle))
    }
}

fn create_tpm_key(app_id: &str, key_name: &str) -> crate::Result<KeyHandle> {
    let provider = open_provider()?;

    // Check if TPM is available
    if !is_tpm_available(&provider) {
        return Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TPM 2.0 not available on this system",
        )));
    }

    let full_name = tpm_key_name(app_id, key_name);

    unsafe {
        let mut key_handle = NCRYPT_KEY_HANDLE::default();
        let key_name_h = HSTRING::from(full_name.as_str());
        let algorithm = HSTRING::from("ECDSA_P256");

        if let Err(e) = NCryptCreatePersistedKey(
            provider.0,
            &mut key_handle,
            PCWSTR(algorithm.as_ptr()),
            PCWSTR(key_name_h.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        ) {
            // Check if the error is "key already exists" (NTE_EXISTS)
            if is_key_exists_error(&e) {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    sanitize_error(
                        &format!("A key with name '{}' already exists", key_name),
                        "Key already exists",
                    ),
                )));
            }
            return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
                &format!("Failed to create TPM key '{}': {}", key_name, e),
                "Failed to create key",
            ))));
        }

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

    sign_hash_internal(key, hash)
}

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

pub fn delete_key(key: KeyHandle) -> crate::Result<bool> {
    unsafe {
        // NCryptDeleteKey takes ownership and invalidates the handle
        // Use take() to extract the handle and prevent Drop from being called
        match NCryptDeleteKey(key.take(), 0u32) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Fail silently
        }
    }
}

/// Extracts user key name from NGC format: {SID}//tauri_se/{app_id}/{key_name} -> key_name
fn extract_ngc_key_name<'a>(full_name: &'a str, app_id: &str) -> Option<&'a str> {
    let marker = ngc_key_marker(app_id);
    full_name
        .find(&marker)
        .map(|pos| &full_name[pos + marker.len()..])
}

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

            // Wrap in RAII guard to ensure cleanup even on panic
            let key_name_guard = KeyNameBufferGuard::new(key_name_ptr);
            let key_name_struct = key_name_guard.as_ref();
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
            // key_name_guard is dropped here, freeing the buffer
        }
    }

    Ok(keys)
}

fn list_ngc_keys(
    provider: &ProviderHandle,
    app_id: &str,
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

            // Wrap in RAII guard to ensure cleanup even on panic
            let key_name_guard = KeyNameBufferGuard::new(key_name_ptr);
            let key_name_struct = key_name_guard.as_ref();
            let key_name_wide = key_name_struct.pszName;

            if !key_name_wide.is_null() {
                let full_name = key_name_wide.to_string().unwrap_or_default();

                // Check for our NGC key marker: /tauri_se/{app_id}/
                if let Some(user_name) = extract_ngc_key_name(&full_name, app_id) {
                    let name_matches = filter_key_name.map(|f| user_name == f).unwrap_or(true);

                    if name_matches {
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
            // key_name_guard is dropped here, freeing the buffer
        }
    }

    Ok(keys)
}

pub fn list_keys(
    app_id: &str,
    filter_key_name: Option<&str>,
    filter_public_key: Option<&str>,
) -> crate::Result<Vec<crate::models::KeyInfo>> {
    let mut all_keys = Vec::new();

    let tpm_prefix = tpm_key_prefix(app_id);
    if let Ok(tpm_provider) = open_provider() {
        if let Ok(tpm_keys) = list_keys_from_provider(
            &tpm_provider,
            &tpm_prefix,
            filter_key_name,
            filter_public_key,
        ) {
            all_keys.extend(tpm_keys);
        }
    }

    if let Ok(ngc_provider) = open_ngc_provider() {
        if let Ok(ngc_keys) =
            list_ngc_keys(&ngc_provider, app_id, filter_key_name, filter_public_key)
        {
            all_keys.extend(ngc_keys);
        }
    }

    Ok(all_keys)
}

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
