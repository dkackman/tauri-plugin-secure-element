use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptDeleteKey, NCryptEnumKeys, NCryptExportKey, NCryptFinalizeKey,
    NCryptFreeObject, NCryptKeyName, NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty,
    NCryptSignHash, CERT_KEY_SPEC, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_FLAGS, NCRYPT_KEY_HANDLE,
    NCRYPT_PROV_HANDLE, NCRYPT_SILENT_FLAG,
};
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::TpmBaseServices::{Tbsi_GetDeviceInfo, TPM_DEVICE_INFO};

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

/// Checks if the Windows version supports TPM 2.0 via the Platform Crypto Provider.
/// Minimum requirement: Windows 10 version 1607 (Anniversary Update, build 14393).
/// This is when TPM 2.0 became mandatory for new Windows 10 devices and the
/// Platform Crypto Provider gained full TPM 2.0 support.
fn is_windows_10_1607_or_higher() -> crate::Result<bool> {
    let version = winver::WindowsVersion::detect().ok_or_else(|| {
        crate::Error::Io(std::io::Error::other("Failed to detect Windows version"))
    })?;

    // Windows 10 version 1607 (Anniversary Update) is build 14393
    // This is the minimum version for reliable TPM 2.0 support
    let windows_10_1607_min = winver::WindowsVersion::new(10, 0, 14393);

    Ok(version >= windows_10_1607_min)
}

fn require_windows_10_1607() -> crate::Result<()> {
    match is_windows_10_1607_or_higher() {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "This plugin requires Windows 10 version 1607 (build 14393) or higher",
        ))),
        Err(e) => Err(e),
    }
}

/// TPM version constants returned by TPM_DEVICE_INFO
const TPM_VERSION_20: u32 = 2;

/// TPM interface type constants from TPM_DEVICE_INFO
/// See: https://learn.microsoft.com/en-us/windows/win32/api/tbs/ns-tbs-tpm_device_info
const TPM_IFTYPE_UNKNOWN: u32 = 0;
const TPM_IFTYPE_1: u32 = 1; // TPM 1.2 interface (LPC)
const TPM_IFTYPE_TRUSTZONE: u32 = 2; // ARM TrustZone
const TPM_IFTYPE_HW: u32 = 3; // Hardware/discrete TPM
const TPM_IFTYPE_EMULATOR: u32 = 4; // Software emulator
const TPM_IFTYPE_SPB: u32 = 5; // Simple Peripheral Bus (SPI/I2C)

/// Classification of TPM type based on interface
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmType {
    /// No TPM detected (or emulator only)
    None,
    /// Firmware TPM (fTPM) - Intel PTT, AMD PSP, or similar
    Firmware,
    /// On-die integrated security (ARM TrustZone)
    Integrated,
    /// Discrete hardware TPM chip
    Discrete,
}

/// Result of TPM detection
#[derive(Debug, Clone)]
pub struct TpmInfo {
    /// Whether a TPM is present
    pub present: bool,
    /// TPM version (1 = TPM 1.2, 2 = TPM 2.0)
    pub version: Option<u32>,
    /// TPM interface type (raw value from TPM_DEVICE_INFO)
    pub interface_type: Option<u32>,
    /// Classified TPM type (discrete vs firmware)
    pub tpm_type: TpmType,
    /// TPM implementation revision
    #[allow(dead_code)]
    pub implementation_revision: Option<u32>,
}

/// Detects TPM presence and version using the TPM Base Services API.
/// Returns detailed information about the TPM if present.
pub fn detect_tpm() -> TpmInfo {
    unsafe {
        let mut device_info = TPM_DEVICE_INFO {
            structVersion: 1,
            tpmVersion: 0,
            tpmInterfaceType: 0,
            tpmImpRevision: 0,
        };

        let size = std::mem::size_of::<TPM_DEVICE_INFO>() as u32;
        let result = Tbsi_GetDeviceInfo(size, &mut device_info as *mut _ as *mut std::ffi::c_void);

        // TBS_SUCCESS is 0
        if result == 0 {
            let interface_type = device_info.tpmInterfaceType;

            // Classify TPM type based on interface:
            // - TPM_IFTYPE_HW (3): Discrete hardware TPM chip
            // - TPM_IFTYPE_SPB (5): SPI/I2C-attached discrete TPM
            // - TPM_IFTYPE_1 (1): LPC-attached TPM (typically TPM 1.2 discrete)
            // - TPM_IFTYPE_TRUSTZONE (2): ARM TrustZone - on-die integrated security
            // - TPM_IFTYPE_UNKNOWN (0): Often firmware TPM (Intel PTT, AMD fTPM)
            // - TPM_IFTYPE_EMULATOR (4): Software emulator - not hardware backed
            let tpm_type = match interface_type {
                TPM_IFTYPE_HW | TPM_IFTYPE_SPB | TPM_IFTYPE_1 => TpmType::Discrete,
                TPM_IFTYPE_TRUSTZONE => TpmType::Integrated,
                TPM_IFTYPE_UNKNOWN => TpmType::Firmware, // fTPM typically reports as unknown
                TPM_IFTYPE_EMULATOR => TpmType::None,    // Emulator is not hardware-backed
                _ => TpmType::Firmware,                  // Default for unrecognized types
            };

            TpmInfo {
                present: true,
                version: Some(device_info.tpmVersion),
                interface_type: Some(interface_type),
                tpm_type,
                implementation_revision: Some(device_info.tpmImpRevision),
            }
        } else {
            // TPM not present or error accessing it
            TpmInfo {
                present: false,
                version: None,
                interface_type: None,
                tpm_type: TpmType::None,
                implementation_revision: None,
            }
        }
    }
}

/// Checks if TPM 2.0 is available on this system.
/// Returns true only if a TPM is present AND it is version 2.0 or higher.
pub fn is_tpm2_available() -> bool {
    let info = detect_tpm();
    info.present && info.version.map(|v| v >= TPM_VERSION_20).unwrap_or(false)
}

/// Gets the secure element capabilities for Windows.
/// Returns information about what types of hardware security are available.
pub fn get_secure_element_capabilities() -> crate::models::CheckSecureElementSupportResponse {
    let info = detect_tpm();

    // Check if TPM is emulated (virtual TPM in a VM)
    let emulated = info
        .interface_type
        .map(|t| t == TPM_IFTYPE_EMULATOR)
        .unwrap_or(false);

    // Check if we have TPM 2.0
    let has_tpm2 = info.present && info.version.map(|v| v >= TPM_VERSION_20).unwrap_or(false);

    if !has_tpm2 {
        return crate::models::CheckSecureElementSupportResponse {
            discrete: false,
            integrated: false,
            firmware: false,
            emulated,
            strongest: crate::models::SecureElementBacking::None,
            can_enforce_biometric_only: false,
        };
    }

    // Determine capabilities based on TPM type
    let (discrete, integrated, firmware) = match info.tpm_type {
        TpmType::Discrete => (true, false, false),
        TpmType::Integrated => (false, true, false), // ARM TrustZone on Windows ARM
        TpmType::Firmware => (false, false, true),
        TpmType::None => (false, false, false),
    };

    // Determine strongest backing (discrete > integrated > firmware > none)
    let strongest = if discrete {
        crate::models::SecureElementBacking::Discrete
    } else if integrated {
        crate::models::SecureElementBacking::Integrated
    } else if firmware {
        crate::models::SecureElementBacking::Firmware
    } else {
        crate::models::SecureElementBacking::None
    };

    crate::models::CheckSecureElementSupportResponse {
        discrete,
        integrated,
        firmware,
        emulated,
        strongest,
        can_enforce_biometric_only: can_enforce_biometric_only(),
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
    require_windows_10_1607()?;

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

/// Checks if TPM 2.0 is available for use with the given provider.
/// This verifies both that the provider handle is valid AND that the system has TPM 2.0.
pub fn is_tpm_available(provider: &ProviderHandle) -> bool {
    // Provider handle must be valid AND system must have TPM 2.0
    !provider.0.is_invalid() && is_tpm2_available()
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

fn key_exists(app_id: &str, key_name: &str) -> bool {
    if let Ok(sid) = get_current_user_sid() {
        let ngc_full_name = ngc_key_name(&sid, app_id, key_name);
        if let Ok(ngc_provider) = open_ngc_provider() {
            if open_key_internal(&ngc_provider, &ngc_full_name).is_ok() {
                return true;
            }
        }
    }

    let tpm_full_name = tpm_key_name(app_id, key_name);
    if let Ok(tpm_provider) = open_provider() {
        if open_key_internal(&tpm_provider, &tpm_full_name).is_ok() {
            return true;
        }
    }

    false
}

/// Creates a new P-256 ECDSA key with the appropriate provider based on auth mode
pub fn create_key(
    app_id: &str,
    key_name: &str,
    auth_mode: &crate::models::AuthenticationMode,
) -> crate::Result<KeyHandle> {
    // Check if a key with this name already exists in either provider
    if key_exists(app_id, key_name) {
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
