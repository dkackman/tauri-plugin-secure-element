use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

#[cfg(target_os = "macos")]
use tauri::plugin::PluginHandle;

use crate::models::*;

#[cfg(target_os = "macos")]
tauri::ios_plugin_binding!(init_plugin_secure_element);

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<SecureElement<R>> {
    #[cfg(target_os = "macos")]
    {
        let handle = api.register_ios_plugin(init_plugin_secure_element)?;
        Ok(SecureElement::MacOS(handle))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = api; // Suppress unused warning
        Ok(SecureElement::Other(app.clone()))
    }
}

/// Access to the secure-element APIs.
pub enum SecureElement<R: Runtime> {
    #[cfg(target_os = "macos")]
    MacOS(PluginHandle<R>),
    #[cfg(not(target_os = "macos"))]
    Other(AppHandle<R>),
}

impl<R: Runtime> SecureElement<R> {
    pub fn ping(&self, payload: PingRequest) -> crate::Result<PingResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle.run_mobile_plugin("ping", payload).map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Ok(PingResponse {
                value: payload.value,
            }),
        }
    }

    pub fn generate_secure_key(
        &self,
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle
                .run_mobile_plugin("generateSecureKey", payload)
                .map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
            ))),
        }
    }

    pub fn list_keys(&self, payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle
                .run_mobile_plugin("listKeys", payload)
                .map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
            ))),
        }
    }

    pub fn sign_with_key(
        &self,
        payload: SignWithKeyRequest,
    ) -> crate::Result<SignWithKeyResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle
                .run_mobile_plugin("signWithKey", payload)
                .map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
            ))),
        }
    }

    pub fn delete_key(&self, payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle
                .run_mobile_plugin("deleteKey", payload)
                .map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Secure Enclave not available on this platform. Requires macOS with T2 chip or Apple Silicon.",
            ))),
        }
    }

    pub fn check_secure_element_support(&self) -> crate::Result<CheckSecureElementSupportResponse> {
        match self {
            #[cfg(target_os = "macos")]
            SecureElement::MacOS(handle) => handle
                .run_mobile_plugin("checkSecureElementSupport", ())
                .map_err(Into::into),
            #[cfg(not(target_os = "macos"))]
            SecureElement::Other(_) => Ok(CheckSecureElementSupportResponse {
                secure_element_supported: false,
                tee_supported: false,
            }),
        }
    }
}
