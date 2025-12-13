use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

#[cfg(not(target_os = "macos"))]
use tauri::plugin::PluginHandle;

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_secure_element);

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
}

// initializes the Kotlin or Swift plugin classes
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    #[allow(unused)] api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    #[cfg(target_os = "macos")]
    {
        // On macOS, we can't use the iOS plugin APIs, so we'll use a placeholder
        // TODO: Implement proper FFI bindings to call Swift functions directly
        // For now, return a macOS struct that will handle calls via FFI (to be implemented)
        Ok(SecureElement(std::marker::PhantomData::<fn() -> R>))
    }
    #[cfg(target_os = "android")]
    {
        let handle =
            api.register_android_plugin("net.kackman.secureelement", "SecureKeysPlugin")?;
        Ok(SecureElement(handle))
    }
    #[cfg(target_os = "ios")]
    {
        let handle = api.register_ios_plugin(init_plugin_secure_element)?;
        Ok(SecureElement(handle))
    }
}

/// Access to the secure-element APIs.
#[cfg(target_os = "macos")]
pub struct SecureElement<R: Runtime>(std::marker::PhantomData<fn() -> R>);

#[cfg(not(target_os = "macos"))]
pub struct SecureElement<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        #[cfg(target_os = "macos")]
        {
            let _ = self;
            // TODO: Implement direct FFI call to Swift plugin
            // For now, return a simple response
            Ok(PingResponse {
                value: payload.value,
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("ping", payload)
                .map_err(Into::into)
        }
    }

    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::{CStr, CString};

            // Convert key_name to C string
            let key_name_cstr = CString::new(payload.key_name.as_str()).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Invalid key_name: {}", e),
                ))
            })?;

            // Convert auth_mode to C string (keep alive for FFI call)
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

            // Call Swift FFI function
            let result_ptr = unsafe {
                secure_element_generate_secure_key(key_name_cstr.as_ptr(), auth_mode_cstr.as_ptr())
            };

            if result_ptr.is_null() {
                return Err(crate::Error::Io(std::io::Error::other(
                    "FFI call returned null",
                )));
            }

            // Convert C string to Rust string BEFORE freeing
            let result_str = {
                // Validate pointer is readable (check first byte)
                unsafe {
                    if *result_ptr == 0 {
                        libc::free(result_ptr as *mut libc::c_void);
                        return Err(crate::Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Swift function returned empty/null string",
                        )));
                    }
                }

                let result_cstr = unsafe { CStr::from_ptr(result_ptr) };

                // Debug: check the raw bytes before conversion
                let len = unsafe { libc::strlen(result_ptr) };

                let str_result = result_cstr.to_str().map_err(|e| {
                    // Free before returning error
                    unsafe {
                        libc::free(result_ptr as *mut libc::c_void);
                    }
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid UTF-8 in FFI result: {} (pointer: {:p}, len: {})",
                            e, result_ptr, len
                        ),
                    ))
                })?;

                // Copy to owned String immediately to ensure it's valid after free
                let owned = str_result.to_string();
                eprintln!(
                    "DEBUG: Converted to Rust string: '{}' (len: {})",
                    owned,
                    owned.len()
                );
                owned
            };

            // Now free the C string allocated by Swift
            unsafe {
                libc::free(result_ptr as *mut libc::c_void);
            }

            if result_str.is_empty() {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Swift function returned empty string",
                )));
            }

            // Parse JSON response and check for errors
            let response: serde_json::Value = serde_json::from_str(&result_str).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse JSON response: {} (response was: '{}', len: {}, bytes: {:?})", 
                        e, result_str, result_str.len(), result_str.as_bytes()),
                ))
            })?;

            // Check for error in response
            if let Some(error_msg) = response.get("error").and_then(|v| v.as_str()) {
                return Err(crate::Error::Io(std::io::Error::other(error_msg)));
            }

            // Deserialize directly from the JSON string
            let generate_response: GenerateSecureKeyResponse = serde_json::from_str(&result_str)
                .map_err(|e| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Failed to deserialize GenerateSecureKeyResponse: {} (JSON was: {})",
                            e, result_str
                        ),
                    ))
                })?;

            Ok(generate_response)
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("generateSecureKey", payload)
                .map_err(Into::into)
        }
    }

    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::{CStr, CString};

            // Convert optional strings to C strings (pass null pointer for None)
            let (key_name_ptr, _key_name_cstr) = match payload.key_name.as_ref() {
                Some(s) => {
                    if let Ok(cstr) = CString::new(s.as_str()) {
                        (cstr.as_ptr(), Some(cstr))
                    } else {
                        (std::ptr::null(), None)
                    }
                }
                None => (std::ptr::null(), None),
            };

            let (public_key_ptr, _public_key_cstr) = match payload.public_key.as_ref() {
                Some(s) => {
                    if let Ok(cstr) = CString::new(s.as_str()) {
                        (cstr.as_ptr(), Some(cstr))
                    } else {
                        (std::ptr::null(), None)
                    }
                }
                None => (std::ptr::null(), None),
            };

            // Call Swift FFI function
            let result_ptr = unsafe { secure_element_list_keys(key_name_ptr, public_key_ptr) };

            if result_ptr.is_null() {
                return Err(crate::Error::Io(std::io::Error::other(
                    "FFI call returned null",
                )));
            }

            // Convert C string to Rust string BEFORE freeing
            // Read the string first, then free
            let result_str = {
                // Validate pointer is readable (check first byte)
                unsafe {
                    if *result_ptr == 0 {
                        libc::free(result_ptr as *mut libc::c_void);
                        return Err(crate::Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Swift function returned empty/null string",
                        )));
                    }
                }

                let result_cstr = unsafe { CStr::from_ptr(result_ptr) };

                let str_result = result_cstr.to_str().map_err(|e| {
                    // Free before returning error
                    let len = unsafe { libc::strlen(result_ptr) };
                    unsafe {
                        libc::free(result_ptr as *mut libc::c_void);
                    }
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid UTF-8 in FFI result: {} (pointer: {:p}, len: {})",
                            e, result_ptr, len
                        ),
                    ))
                })?;

                // Copy to owned String immediately to ensure it's valid after free
                str_result.to_string()
            };

            // Now free the C string allocated by Swift
            unsafe {
                libc::free(result_ptr as *mut libc::c_void);
            }

            if result_str.is_empty() {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Swift function returned empty string",
                )));
            }

            // Parse JSON response and check for errors
            let response: serde_json::Value = serde_json::from_str(&result_str).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse JSON response: {} (response was: '{}', len: {}, bytes: {:?})", 
                        e, result_str, result_str.len(), result_str.as_bytes()),
                ))
            })?;

            // Check for error in response
            if let Some(error_msg) = response.get("error").and_then(|v| v.as_str()) {
                return Err(crate::Error::Io(std::io::Error::other(error_msg)));
            }

            // Deserialize directly from the JSON string instead of going through Value
            // This ensures proper handling of the camelCase field names
            let list_response: ListKeysResponse =
                serde_json::from_str(&result_str).map_err(|e| {
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Failed to deserialize ListKeysResponse: {} (JSON was: {})",
                            e, result_str
                        ),
                    ))
                })?;

            Ok(list_response)
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("listKeys", payload)
                .map_err(Into::into)
        }
    }

    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            let _ = (self, payload);
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "macOS FFI bindings not yet fully implemented",
            )))
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("signWithKey", payload)
                .map_err(Into::into)
        }
    }

    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        #[cfg(target_os = "macos")]
        {
            let _ = (self, payload);
            Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "macOS FFI bindings not yet fully implemented",
            )))
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("deleteKey", payload)
                .map_err(Into::into)
        }
    }

    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::CStr;

            // Call Swift FFI function
            let result_ptr = unsafe { secure_element_check_support() };

            if result_ptr.is_null() {
                return Err(crate::Error::Io(std::io::Error::other(
                    "FFI call returned null",
                )));
            }

            // Convert C string to Rust string BEFORE freeing
            let result_str = {
                // Validate pointer is readable (check first byte)
                unsafe {
                    if *result_ptr == 0 {
                        libc::free(result_ptr as *mut libc::c_void);
                        return Err(crate::Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Swift function returned empty/null string",
                        )));
                    }
                }

                let result_cstr = unsafe { CStr::from_ptr(result_ptr) };

                // Debug: check the raw bytes before conversion
                let len = unsafe { libc::strlen(result_ptr) };
                eprintln!("DEBUG: C string length: {}, pointer: {:p}", len, result_ptr);

                let str_result = result_cstr.to_str().map_err(|e| {
                    // Free before returning error
                    unsafe {
                        libc::free(result_ptr as *mut libc::c_void);
                    }
                    crate::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid UTF-8 in FFI result: {} (pointer: {:p}, len: {})",
                            e, result_ptr, len
                        ),
                    ))
                })?;

                // Copy to owned String immediately to ensure it's valid after free
                let owned = str_result.to_string();
                eprintln!(
                    "DEBUG: Converted to Rust string: '{}' (len: {})",
                    owned,
                    owned.len()
                );
                owned
            };

            // Now free the C string allocated by Swift
            unsafe {
                libc::free(result_ptr as *mut libc::c_void);
            }

            if result_str.is_empty() {
                return Err(crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Swift function returned empty string",
                )));
            }

            // Parse JSON response and check for errors
            let response: serde_json::Value = serde_json::from_str(&result_str).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse JSON response: {} (response was: '{}', len: {}, bytes: {:?})", 
                        e, result_str, result_str.len(), result_str.as_bytes()),
                ))
            })?;

            // Check for error in response
            if let Some(error_msg) = response.get("error").and_then(|v| v.as_str()) {
                return Err(crate::Error::Io(std::io::Error::other(error_msg)));
            }

            // Deserialize directly from the JSON string
            let support_response: CheckSecureElementSupportResponse = serde_json::from_str(&result_str).map_err(|e| {
                crate::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to deserialize CheckSecureElementSupportResponse: {} (JSON was: {})", e, result_str),
                ))
            })?;

            Ok(support_response)
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0
                .run_mobile_plugin("checkSecureElementSupport", ())
                .map_err(Into::into)
        }
    }
}
