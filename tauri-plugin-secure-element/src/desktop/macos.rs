// macOS Secure Enclave Implementation via Swift FFI Bridge
//
// This module provides Rust bindings to the Swift Security Framework implementation.
// The Swift code handles all Secure Enclave operations, and we call it via C FFI.

use crate::models::*;
use std::ffi::{CStr, CString};
use std::io::{Error as IoError, ErrorKind};
use std::os::raw::{c_char, c_int};
use std::ptr;

// MARK: - FFI Declarations

// Link to the Swift static library (built separately)
#[link(name = "SecureElementSwift", kind = "static")]
extern "C" {
    fn secure_element_check_support(
        supported: *mut bool,
        tee_supported: *mut bool,
    ) -> c_int;

    fn secure_element_generate_key(
        key_name: *const c_char,
        public_key_out: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn secure_element_sign_data(
        key_name: *const c_char,
        data_ptr: *const u8,
        data_len: usize,
        signature_out: *mut *mut u8,
        signature_len_out: *mut usize,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn secure_element_list_keys(
        key_name_filter: *const c_char,
        public_key_filter: *const c_char,
        keys_json_out: *mut *mut c_char,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn secure_element_delete_key(
        key_name: *const c_char,
        error_out: *mut *mut c_char,
    ) -> c_int;

    fn ffi_string_result_free(ptr: *mut c_char);
    fn ffi_signature_free(ptr: *mut u8, len: usize);
}

// MARK: - Helper Functions

/// Convert C string to Rust String and free the C string
unsafe fn take_c_string(ptr: *mut c_char) -> Result<String, IoError> {
    if ptr.is_null() {
        return Err(IoError::new(ErrorKind::Other, "Null pointer"));
    }
    let c_str = CStr::from_ptr(ptr);
    let result = c_str
        .to_str()
        .map_err(|e| IoError::new(ErrorKind::InvalidData, e))?
        .to_string();
    ffi_string_result_free(ptr);
    Ok(result)
}

/// Get error message from FFI error pointer
unsafe fn get_error_message(error_ptr: *mut c_char) -> String {
    if error_ptr.is_null() {
        "Unknown error".to_string()
    } else {
        let error_msg = take_c_string(error_ptr).unwrap_or_else(|_| "Unknown error".to_string());
        error_msg
    }
}

// MARK: - Public API Implementation

/// Check if Secure Enclave is available
pub fn check_secure_element_support() -> crate::Result<CheckSecureElementSupportResponse> {
    unsafe {
        let mut supported = false;
        let mut tee_supported = false;

        let result = secure_element_check_support(&mut supported, &mut tee_supported);

        if result != 0 {
            return Err(crate::Error::Io(IoError::new(
                ErrorKind::Other,
                "Failed to check Secure Enclave support",
            )));
        }

        Ok(CheckSecureElementSupportResponse {
            secure_element_supported: supported,
            tee_supported,
        })
    }
}

/// Generate a new EC P-256 key in the Secure Enclave
pub fn generate_secure_key(
    request: GenerateSecureKeyRequest,
) -> crate::Result<GenerateSecureKeyResponse> {
    unsafe {
        let key_name_c = CString::new(request.key_name.clone())
            .map_err(|e| crate::Error::Io(IoError::new(ErrorKind::InvalidInput, e)))?;

        let mut public_key_ptr: *mut c_char = ptr::null_mut();
        let mut error_ptr: *mut c_char = ptr::null_mut();

        let result = secure_element_generate_key(
            key_name_c.as_ptr(),
            &mut public_key_ptr,
            &mut error_ptr,
        );

        if result != 0 {
            let error_msg = get_error_message(error_ptr);
            return Err(crate::Error::Io(IoError::new(ErrorKind::Other, error_msg)));
        }

        let public_key = take_c_string(public_key_ptr)?;

        Ok(GenerateSecureKeyResponse {
            public_key,
            key_name: request.key_name,
        })
    }
}

/// List all Secure Enclave keys
pub fn list_keys(request: ListKeysRequest) -> crate::Result<ListKeysResponse> {
    unsafe {
        let key_name_filter_c = request
            .key_name
            .as_ref()
            .map(|s| CString::new(s.clone()))
            .transpose()
            .map_err(|e| crate::Error::Io(IoError::new(ErrorKind::InvalidInput, e)))?;

        let public_key_filter_c = request
            .public_key
            .as_ref()
            .map(|s| CString::new(s.clone()))
            .transpose()
            .map_err(|e| crate::Error::Io(IoError::new(ErrorKind::InvalidInput, e)))?;

        let key_name_ptr = key_name_filter_c
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());
        let public_key_ptr = public_key_filter_c
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null());

        let mut keys_json_ptr: *mut c_char = ptr::null_mut();
        let mut error_ptr: *mut c_char = ptr::null_mut();

        let result = secure_element_list_keys(
            key_name_ptr,
            public_key_ptr,
            &mut keys_json_ptr,
            &mut error_ptr,
        );

        if result != 0 {
            let error_msg = get_error_message(error_ptr);
            return Err(crate::Error::Io(IoError::new(ErrorKind::Other, error_msg)));
        }

        let keys_json = take_c_string(keys_json_ptr)?;

        // Parse JSON
        let keys: Vec<KeyInfo> = serde_json::from_str(&keys_json).map_err(|e| {
            crate::Error::Io(IoError::new(
                ErrorKind::InvalidData,
                format!("Failed to parse keys JSON: {}", e),
            ))
        })?;

        Ok(ListKeysResponse { keys })
    }
}

/// Sign data with a Secure Enclave key
pub fn sign_with_key(request: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
    unsafe {
        let key_name_c = CString::new(request.key_name.clone())
            .map_err(|e| crate::Error::Io(IoError::new(ErrorKind::InvalidInput, e)))?;

        let mut signature_ptr: *mut u8 = ptr::null_mut();
        let mut signature_len: usize = 0;
        let mut error_ptr: *mut c_char = ptr::null_mut();

        let result = secure_element_sign_data(
            key_name_c.as_ptr(),
            request.data.as_ptr(),
            request.data.len(),
            &mut signature_ptr,
            &mut signature_len,
            &mut error_ptr,
        );

        if result != 0 {
            let error_msg = get_error_message(error_ptr);
            return Err(crate::Error::Io(IoError::new(ErrorKind::Other, error_msg)));
        }

        // Copy signature data
        let signature = std::slice::from_raw_parts(signature_ptr, signature_len).to_vec();

        // Free the signature buffer
        ffi_signature_free(signature_ptr, signature_len);

        Ok(SignWithKeyResponse { signature })
    }
}

/// Delete a Secure Enclave key
pub fn delete_key(request: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
    unsafe {
        let key_name_c = CString::new(request.key_name.clone())
            .map_err(|e| crate::Error::Io(IoError::new(ErrorKind::InvalidInput, e)))?;

        let mut error_ptr: *mut c_char = ptr::null_mut();

        let result = secure_element_delete_key(key_name_c.as_ptr(), &mut error_ptr);

        if result != 0 {
            let error_msg = get_error_message(error_ptr);
            return Err(crate::Error::Io(IoError::new(ErrorKind::Other, error_msg)));
        }

        Ok(DeleteKeyResponse { success: true })
    }
}
