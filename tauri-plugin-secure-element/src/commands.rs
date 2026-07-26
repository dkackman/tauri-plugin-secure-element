use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::validation::{validate_key_name, validate_public_key_filter, validate_sign_data_size};
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
    validate_key_name(&payload.key_name)?;
    app.secure_element().generate_secure_key(payload)
}

#[command]
pub(crate) async fn list_keys<R: Runtime>(
    app: AppHandle<R>,
    mut payload: ListKeysRequest,
) -> Result<ListKeysResponse> {
    // Validate optional key name filter if provided
    if let Some(ref key_name) = payload.key_name {
        validate_key_name(key_name)?;
    }
    // Validate optional public key filter if provided.
    // validate_public_key_filter returns the trimmed/normalized form, which we
    // store back so callers get consistent exact-match behavior against
    // plugin-generated base64 strings (which never have surrounding whitespace).
    if let Some(ref public_key) = payload.public_key {
        payload.public_key = Some(validate_public_key_filter(public_key)?);
    }
    app.secure_element().list_keys(payload)
}

#[command]
pub(crate) async fn sign_with_key<R: Runtime>(
    app: AppHandle<R>,
    payload: SignWithKeyRequest,
) -> Result<SignWithKeyResponse> {
    validate_key_name(&payload.key_name)?;
    validate_sign_data_size(&payload.data)?;
    app.secure_element().sign_with_key(payload)
}

#[command]
pub(crate) async fn delete_key<R: Runtime>(
    app: AppHandle<R>,
    mut payload: DeleteKeyRequest,
) -> Result<DeleteKeyResponse> {
    // At least one of key_name or public_key must be provided
    if payload.key_name.is_none() && payload.public_key.is_none() {
        return Err(crate::Error::Validation(
            "Either key_name or public_key must be provided".to_string(),
        ));
    }

    if payload.key_name.is_some() && payload.public_key.is_some() {
        return Err(crate::Error::Validation(
            "Only one of key_name or public_key must be provided".to_string(),
        ));
    }

    // Validate optional key name if provided
    if let Some(ref key_name) = payload.key_name {
        validate_key_name(key_name)?;
    }

    // Validate optional public key if provided.
    // validate_public_key_filter returns the trimmed/normalized form, which we
    // store back so callers get consistent exact-match behavior against
    // plugin-generated base64 strings (which never have surrounding whitespace).
    if let Some(ref public_key) = payload.public_key {
        payload.public_key = Some(validate_public_key_filter(public_key)?);
    }

    app.secure_element().delete_key(payload)
}

/// Queries the platform on every call — deliberately uncached.
///
/// The hardware tier fields (`discrete`/`integrated`/`firmware`/`emulated`/`strongest`)
/// really are fixed for the life of the process, but `can_enforce_biometric_only` is
/// not: it reflects whether biometrics are currently *enrolled and usable*, which
/// changes when the user enrolls or removes a biometric, or when biometry locks out
/// after repeated failures. Caching the whole response froze that flag at whatever it
/// was on first call, so an app gating `generateSecureKey(.., "biometricOnly")` on it
/// would keep refusing on a device where biometrics had since been enrolled (or keep
/// trying on one that had since locked out).
///
/// The expensive, genuinely immutable probes are memoized in the platform layers
/// instead — see `SecureEnclaveCore.checkSupport` (iOS/macOS) and
/// `SecureKeysPlugin.checkSecureElementSupport` (Android) — so repeat calls stay cheap
/// without freezing the mutable authentication state.
#[command]
pub(crate) async fn check_secure_element_support<R: Runtime>(
    app: AppHandle<R>,
) -> Result<CheckSecureElementSupportResponse> {
    app.secure_element().check_secure_element_support()
}
