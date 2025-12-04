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
pub(crate) async fn sign_with_key<R: Runtime>(
    app: AppHandle<R>,
    payload: SignWithKeyRequest,
) -> Result<SignWithKeyResponse> {
    app.secure_element().sign_with_key(payload)
}
