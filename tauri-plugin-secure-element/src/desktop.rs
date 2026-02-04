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

    /// RAII guard for malloc'd pointers that automatically calls libc::free on drop.
    /// Ensures memory is freed even if a panic occurs during string conversion.
    pub struct MallocGuard(*mut std::ffi::c_char);

    impl MallocGuard {
        /// Creates a new guard that will free the pointer on drop.
        /// Returns None if the pointer is null.
        pub fn new(ptr: *mut std::ffi::c_char) -> Option<Self> {
            if ptr.is_null() {
                None
            } else {
                Some(Self(ptr))
            }
        }

        /// Returns the raw pointer for use with CStr functions.
        pub fn as_ptr(&self) -> *const std::ffi::c_char {
            self.0
        }
    }

    impl Drop for MallocGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    libc::free(self.0 as *mut libc::c_void);
                }
            }
        }
    }

    /// Converts an FFI C string pointer to a Rust String and frees the memory.
    /// The pointer must have been allocated by Swift using malloc/strdup.
    ///
    /// # Safety
    /// - `ptr` must be a valid, non-null pointer to a null-terminated C string
    /// - `ptr` must have been allocated by malloc (will be freed with libc::free)
    pub unsafe fn ffi_string_to_owned(ptr: *mut std::ffi::c_char) -> crate::Result<String> {
        let guard = MallocGuard::new(ptr)
            .ok_or_else(|| crate::Error::Io(std::io::Error::other("FFI call returned null")))?;

        // Convert to owned String - guard ensures ptr is freed even if this panics
        let s = CStr::from_ptr(guard.as_ptr())
            .to_str()
            .map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid UTF-8 in FFI result: {}", e),
                ))
            })?
            .to_string();

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

#[cfg(target_os = "windows")]
use crate::windows;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    Ok(SecureElement(app.clone()))
}

/// Access to the secure-element APIs.
pub struct SecureElement<R: Runtime>(AppHandle<R>);

impl<R: Runtime> SecureElement<R> {
    /// Gets the application identifier for key scoping
    #[cfg(target_os = "windows")]
    fn get_app_id(&self) -> String {
        self.0.config().identifier.clone()
    }
}

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        Ok(PingResponse {
            value: payload.value,
        })
    }

    /// Gets the HWND from the main window for Windows Hello UI parenting
    #[cfg(target_os = "windows")]
    fn get_main_window_hwnd(&self) -> Option<isize> {
        use raw_window_handle::HasWindowHandle;
        use tauri::Manager;

        let webview_windows = self.0.webview_windows();
        let window = webview_windows.values().next()?;
        let handle = window.window_handle().ok()?;
        windows::hwnd_from_raw(handle.as_raw())
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

            let app_id = self.get_app_id();

            // Create the key with the appropriate provider based on auth mode
            let key = windows::create_key(&app_id, &payload.key_name, &payload.auth_mode)?;

            // Export the public key
            let public_key_bytes = windows::export_public_key(&key)?;
            let public_key = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);

            // Determine hardware backing based on auth mode
            let hardware_backing = match payload.auth_mode {
                crate::models::AuthenticationMode::PinOrBiometric => "ngc", // Windows Hello NGC
                _ => "tpm", // Platform Crypto Provider with TPM
            };

            Ok(GenerateSecureKeyResponse {
                key_name: payload.key_name,
                public_key,
                hardware_backing: hardware_backing.to_string(),
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
            let app_id = self.get_app_id();

            // List keys from both providers
            let keys = windows::list_keys(
                &app_id,
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
            let app_id = self.get_app_id();

            // Open the key and detect which provider it's from
            let (key, provider_type) = windows::open_key_auto(&app_id, &payload.key_name)?;

            // Hash the data first (NCrypt expects pre-hashed data for ECDSA)
            let hash = windows::sha256_hash(&payload.data)?;

            // Sign the hash - use Windows Hello for NGC keys
            let signature = match provider_type {
                windows::KeyProviderType::Ngc => {
                    // Get HWND for Windows Hello dialog parenting
                    let hwnd = self.get_main_window_hwnd();
                    windows::sign_hash_with_window(&key, &hash, hwnd)?
                }
                windows::KeyProviderType::Tpm => {
                    // Silent signing for TPM keys
                    windows::sign_hash(&key, &hash)?
                }
            };

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
            let app_id = self.get_app_id();

            // If key_name is provided, delete by name
            // If public_key is provided, find the key with that public key first
            // If neither, return error
            let key_name = if let Some(name) = &payload.key_name {
                name.clone()
            } else if let Some(public_key) = &payload.public_key {
                // Find key by public key - fail silently if not found
                let keys = match windows::list_keys(&app_id, None, Some(public_key)) {
                    Ok(keys) => keys,
                    Err(_) => return Ok(DeleteKeyResponse { success: true }),
                };
                if keys.is_empty() {
                    return Ok(DeleteKeyResponse { success: true });
                }
                keys[0].key_name.clone()
            } else {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Either key_name or public_key must be provided",
                )));
            };

            // Open key - fail silently if key not found
            // Use open_key_auto to find the key in either provider
            let (key, _provider_type) = match windows::open_key_auto(&app_id, &key_name) {
                Ok(result) => result,
                Err(_) => return Ok(DeleteKeyResponse { success: true }),
            };
            let success = windows::delete_key(key)?;

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
            Ok(windows::get_secure_element_capabilities())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            // On unsupported desktop platforms, return that secure element is not supported
            Ok(CheckSecureElementSupportResponse {
                discrete: false,
                integrated: false,
                firmware: false,
                emulated: false,
                strongest: crate::models::SecureElementBacking::None,
                can_enforce_biometric_only: false,
            })
        }
    }
}
