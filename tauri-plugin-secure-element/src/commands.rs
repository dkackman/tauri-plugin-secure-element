use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::Result;
use crate::SecureElementExt;
use crate::validation::validate_key_name;

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
    validate_key_name(&payload.key_name)?;
    app.secure_element().generate_secure_key(payload)
}

#[command]
pub(crate) async fn list_keys<R: Runtime>(
    app: AppHandle<R>,
    payload: ListKeysRequest,
) -> Result<ListKeysResponse> {
    // Validate optional key name filter if provided
    if let Some(ref key_name) = payload.key_name {
        validate_key_name(key_name)?;
    }
    app.secure_element().list_keys(payload)
}

#[command]
pub(crate) async fn sign_with_key<R: Runtime>(
    app: AppHandle<R>,
    payload: SignWithKeyRequest,
) -> Result<SignWithKeyResponse> {
    validate_key_name(&payload.key_name)?;
    app.secure_element().sign_with_key(payload)
}

#[command]
pub(crate) async fn delete_key<R: Runtime>(
    app: AppHandle<R>,
    payload: DeleteKeyRequest,
) -> Result<DeleteKeyResponse> {
    validate_key_name(&payload.key_name)?;
    app.secure_element().delete_key(payload)
}

#[command]
pub(crate) async fn check_secure_element_support<R: Runtime>(
    app: AppHandle<R>,
) -> Result<CheckSecureElementSupportResponse> {
    app.secure_element().check_secure_element_support()
}
