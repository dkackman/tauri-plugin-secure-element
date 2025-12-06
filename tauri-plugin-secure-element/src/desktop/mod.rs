// Desktop platform implementation
//
// Platform-specific modules:
// - macos: Full Secure Enclave support via Swift FFI bridge
// - windows: Not implemented (returns errors)
// - linux: Not implemented (returns errors)

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

// Platform-specific modules
#[cfg(target_os = "macos")]
pub mod macos;

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

    #[cfg(target_os = "macos")]
    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        macos::generate_secure_key(payload)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn generate_secure_key(
        &self,
        _payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
        )))
    }

    #[cfg(target_os = "macos")]
    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        macos::list_keys(payload)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn list_keys(&self, _payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
        )))
    }

    #[cfg(target_os = "macos")]
    pub fn sign_with_key(
        &self,
        payload: SignWithKeyRequest,
    ) -> crate::Result<SignWithKeyResponse> {
        macos::sign_with_key(payload)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn sign_with_key(
        &self,
        _payload: SignWithKeyRequest,
    ) -> crate::Result<SignWithKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
        )))
    }

    #[cfg(target_os = "macos")]
    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        macos::delete_key(payload)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn delete_key(&self, _payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
        )))
    }

    #[cfg(target_os = "macos")]
    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        macos::check_secure_element_support()
    }

    #[cfg(not(target_os = "macos"))]
    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        Ok(CheckSecureElementSupportResponse {
            secure_element_supported: false,
            tee_supported: false,
        })
    }
}
