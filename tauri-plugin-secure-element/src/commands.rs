use tauri::{command, AppHandle, Runtime};

use crate::models::*;
use crate::validation::{
    validate_key_name, validate_public_key_filter, validate_sign_data_size, validate_sign_reason,
};
use crate::Result;
use crate::SecureElementExt;

/// Runs a blocking secure-element call off the async runtime's worker thread.
///
/// `SecureElement`'s methods do synchronous FFI/OS calls — on macOS via `extern "C"`
/// into Swift, on Windows via NCrypt — some of which block on a Touch ID or Windows
/// Hello prompt waiting for the user. Calling them directly from an `async fn` command
/// runs them on a worker thread shared with every other pending command, so one
/// in-flight prompt stalls unrelated calls (e.g. a `listKeys` from another window)
/// until the user responds.
async fn run_blocking<F, T>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| crate::Error::Io(std::io::Error::other(e.to_string())))?
}

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
    run_blocking(move || app.secure_element().generate_secure_key(payload)).await
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
    run_blocking(move || app.secure_element().list_keys(payload)).await
}

#[command]
pub(crate) async fn sign_with_key<R: Runtime>(
    app: AppHandle<R>,
    mut payload: SignWithKeyRequest,
) -> Result<SignWithKeyResponse> {
    validate_key_name(&payload.key_name)?;
    validate_sign_data_size(&payload.data)?;
    // Store the normalized form back so every platform renders the same string
    // in its prompt, rather than each trimming (or not) on its own.
    if let Some(ref reason) = payload.reason {
        payload.reason = Some(validate_sign_reason(reason)?);
    }
    run_blocking(move || app.secure_element().sign_with_key(payload)).await
}

/// Confirms exactly one of `key_name`/`public_key` was given.
///
/// Pulled out of `delete_key` so this branching is unit-testable without an
/// `AppHandle` — `delete_key` itself needs a running Tauri app to construct one.
fn validate_delete_key_selector(payload: &DeleteKeyRequest) -> Result<()> {
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

    Ok(())
}

#[command]
pub(crate) async fn delete_key<R: Runtime>(
    app: AppHandle<R>,
    mut payload: DeleteKeyRequest,
) -> Result<DeleteKeyResponse> {
    validate_delete_key_selector(&payload)?;

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

    // Same normalization as `sign_with_key`: the prompt string is only rendered
    // when `require_auth` is set, but validating it unconditionally means a
    // caller cannot smuggle an invalid one past the check by leaving the flag
    // off and turning it on later.
    if let Some(ref reason) = payload.reason {
        payload.reason = Some(validate_sign_reason(reason)?);
    }

    run_blocking(move || app.secure_element().delete_key(payload)).await
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
    run_blocking(move || app.secure_element().check_secure_element_support()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(key_name: Option<&str>, public_key: Option<&str>) -> DeleteKeyRequest {
        DeleteKeyRequest {
            key_name: key_name.map(str::to_string),
            public_key: public_key.map(str::to_string),
            require_auth: false,
            reason: None,
        }
    }

    #[test]
    fn validate_delete_key_selector_accepts_key_name_only() {
        assert!(validate_delete_key_selector(&payload(Some("my-key"), None)).is_ok());
    }

    #[test]
    fn validate_delete_key_selector_accepts_public_key_only() {
        assert!(validate_delete_key_selector(&payload(None, Some("base64"))).is_ok());
    }

    #[test]
    fn validate_delete_key_selector_rejects_neither() {
        assert!(validate_delete_key_selector(&payload(None, None)).is_err());
    }

    #[test]
    fn validate_delete_key_selector_rejects_both() {
        assert!(validate_delete_key_selector(&payload(Some("my-key"), Some("base64"))).is_err());
    }
}
