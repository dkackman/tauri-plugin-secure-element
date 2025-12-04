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
        payload: GenerateSecureKeyRequest,
    ) -> crate::Result<GenerateSecureKeyResponse> {
        use rand::RngCore;

        let key_size = payload.key_size.unwrap_or(32); // Default to 32 bytes (256 bits)
        let mut key = vec![0u8; key_size as usize];
        rand::thread_rng().fill_bytes(&mut key);

        Ok(GenerateSecureKeyResponse {
            key: Some(hex::encode(key)),
        })
    }

    pub fn sign_with_key(&self, payload: SignWithKeyRequest) -> crate::Result<SignWithKeyResponse> {
        // Pass-through implementation for now
        Ok(SignWithKeyResponse {
            signature: payload.data,
        })
    }
}
