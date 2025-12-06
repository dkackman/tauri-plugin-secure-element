use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::SecureElementExt;

#[command]
pub(crate) async fn ping<R: Runtime>(
    app: AppHandle<R>,
    payload: PingRequest,
) -> Result<PingResponse> {
    app.secure_element().ping(payload)
}

#[command]
pub(crate) async fn generate_secure_key<R: Runtime>(
    app: AppHandle<R>,
    payload: GenerateSecureKeyRequest,
) -> Result<GenerateSecureKeyResponse> {
    app.secure_element().generate_secure_key(payload)
}

#[command]
pub(crate) async fn list_keys<R: Runtime>(
    app: AppHandle<R>,
    payload: ListKeysRequest,
) -> Result<ListKeysResponse> {
    let result = app.secure_element().list_keys(payload);
    match &result {
        Ok(response) => {
            for (i, key) in response.keys.iter().enumerate() {
                eprintln!(
                    "[RUST] list_keys: Key {}: name={}, public_key_len={}",
                    i,
                    key.key_name,
                    key.public_key.len()
                );
            }
        }
        Err(e) => {
            eprintln!("[RUST] list_keys: Error - {}", e);
        }
    }
    result
}

#[command]
pub(crate) async fn sign_with_key<R: Runtime>(
    app: AppHandle<R>,
    payload: SignWithKeyRequest,
) -> Result<SignWithKeyResponse> {
    app.secure_element().sign_with_key(payload)
}

#[command]
pub(crate) async fn delete_key<R: Runtime>(
    app: AppHandle<R>,
    payload: DeleteKeyRequest,
) -> Result<DeleteKeyResponse> {
    app.secure_element().delete_key(payload)
}
