use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Runtime};

use crate::models::*;

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
        _payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Desktop Secure Enclave not implemented",
        )))
    }

    pub fn list_keys(&self, _payload: ListKeysRequest) -> crate::Result<ListKeysResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Desktop Secure Enclave not implemented",
        )))
    }

    pub fn sign_with_key(
        &self,
        _payload: SignWithKeyRequest,
    ) -> crate::Result<SignWithKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Desktop Secure Enclave not implemented",
        )))
    }

    pub fn delete_key(&self, _payload: DeleteKeyRequest) -> crate::Result<DeleteKeyResponse> {
        Err(crate::Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Desktop Secure Enclave not implemented",
        )))
    }
}
