use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;

/// Checks if Windows Hello is configured/enrolled on the system
/// Returns true if Windows Hello PIN or biometric is actually enrolled (not just available)
/// Uses the official Windows Runtime API for reliable detection
///
/// `Ok(false)` means Hello is definitively not usable; `Err` means the check itself
/// failed, which callers must not conflate with "not configured".
pub fn is_windows_hello_configured() -> Result<bool, windows::core::Error> {
    check_windows_hello_availability()
}

/// Checks Windows Hello availability using the UserConsentVerifier API
/// This is the official and reliable way to check if Windows Hello is provisioned
fn check_windows_hello_availability() -> Result<bool, windows::core::Error> {
    // Call the async API and wait for the result
    let availability_async = UserConsentVerifier::CheckAvailabilityAsync()?;
    let availability = availability_async.join()?;

    Ok(availability_means_configured(availability))
}

/// Windows Hello is only considered configured if the verifier reports `Available`.
/// Every other state — `DeviceNotPresent`, `NotConfiguredForUser`, `DisabledByPolicy`,
/// `DeviceBusy`, or anything Windows adds later — means it is not usable right now.
fn availability_means_configured(availability: UserConsentVerifierAvailability) -> bool {
    availability == UserConsentVerifierAvailability::Available
}

/// Prompts the user for Windows Hello consent and blocks until they respond.
///
/// Used to gate destructive operations that NCrypt itself performs without any
/// authentication — deleting a key, in particular, which `NCryptDeleteKey` will
/// happily do to an auth-mandatory key with no prompt at all.
///
/// `UserConsentVerifier::RequestVerificationAsync` cannot be called directly
/// from a Win32 desktop app: WinRT needs a window to parent the modal to, and
/// the parameterless form fails without one. The documented workaround is the
/// `IUserConsentVerifierInterop` interop interface, which takes an explicit
/// `HWND` — the same handle the Windows Hello signing path already parents its
/// dialog to.
///
/// Returns the verifier's result; only [`UserConsentVerificationResult::Verified`]
/// authorizes the operation (see [`consent_result_error`]). A genuine API failure
/// propagates as `Err`, so a broken verifier cannot be mistaken for a refusal
/// (or, worse, for consent).
pub fn request_user_consent(
    hwnd: isize,
    message: &str,
) -> Result<UserConsentVerificationResult, windows::core::Error> {
    let interop: IUserConsentVerifierInterop =
        windows::core::factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;

    // `IAsyncOperation` lives in the `windows-future` crate that `windows`
    // re-exports through its own generated bindings, which is why the type is
    // named through `windows_future` rather than `windows::Foundation`.
    let operation: windows_future::IAsyncOperation<UserConsentVerificationResult> = unsafe {
        interop.RequestVerificationForWindowAsync(
            HWND(hwnd as *mut core::ffi::c_void),
            &HSTRING::from(message),
        )?
    };

    operation.join()
}

/// Maps a consent result to the error that should be reported, or `None` when the
/// user was verified. Anything unrecognised is `Internal`, never success.
pub fn consent_result_error(
    result: UserConsentVerificationResult,
) -> Option<(crate::ErrorCode, &'static str)> {
    use crate::ErrorCode;
    if result == UserConsentVerificationResult::Verified {
        None
    } else if result == UserConsentVerificationResult::Canceled {
        Some((
            ErrorCode::UserCancelled,
            "Authentication was cancelled; key not deleted",
        ))
    } else if result == UserConsentVerificationResult::RetriesExhausted {
        Some((
            ErrorCode::AuthFailed,
            "Authentication failed; key not deleted",
        ))
    } else if result == UserConsentVerificationResult::NotConfiguredForUser {
        Some((
            ErrorCode::DeviceNotSecure,
            "Windows Hello is not configured for this user",
        ))
    } else if result == UserConsentVerificationResult::DeviceNotPresent
        || result == UserConsentVerificationResult::DisabledByPolicy
    {
        Some((
            ErrorCode::Unsupported,
            "Windows Hello is not available on this device",
        ))
    } else {
        Some((ErrorCode::Internal, "Windows Hello verification failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The security-relevant mapping in this module: exactly one verifier state
    // authorizes treating Windows Hello as configured. A refactor that lets any
    // other state through would silently offer auth-gated key creation on
    // machines that cannot actually prompt.
    #[test]
    fn only_available_counts_as_configured() {
        assert!(availability_means_configured(
            UserConsentVerifierAvailability::Available
        ));
        for not_usable in [
            UserConsentVerifierAvailability::DeviceNotPresent,
            UserConsentVerifierAvailability::NotConfiguredForUser,
            UserConsentVerifierAvailability::DisabledByPolicy,
            UserConsentVerifierAvailability::DeviceBusy,
        ] {
            assert!(!availability_means_configured(not_usable));
        }
    }

    // Future/unknown states the enum does not name yet must also map to "not
    // configured" — the WinRT enum is open-ended over RPC.
    #[test]
    fn unknown_availability_state_is_not_configured() {
        assert!(!availability_means_configured(
            UserConsentVerifierAvailability(i32::MAX)
        ));
    }

    // Same link-check idea as src/windows.rs: taking the address forces the
    // linker to resolve the WinRT interop imports this module depends on.
    #[test]
    fn public_entry_points_link() {
        let _ = is_windows_hello_configured as fn() -> Result<bool, windows::core::Error>;
        let _ = request_user_consent
            as fn(isize, &str) -> Result<UserConsentVerificationResult, windows::core::Error>;
    }

    #[test]
    fn verified_has_no_error() {
        assert_eq!(
            consent_result_error(UserConsentVerificationResult::Verified),
            None
        );
    }

    #[test]
    fn consent_outcomes_map_to_their_own_codes() {
        use crate::ErrorCode;
        let code = |r| consent_result_error(r).map(|(c, _)| c);
        assert_eq!(
            code(UserConsentVerificationResult::Canceled),
            Some(ErrorCode::UserCancelled)
        );
        assert_eq!(
            code(UserConsentVerificationResult::RetriesExhausted),
            Some(ErrorCode::AuthFailed)
        );
        assert_eq!(
            code(UserConsentVerificationResult::NotConfiguredForUser),
            Some(ErrorCode::DeviceNotSecure)
        );
        assert_eq!(
            code(UserConsentVerificationResult::DeviceNotPresent),
            Some(ErrorCode::Unsupported)
        );
        assert_eq!(
            code(UserConsentVerificationResult::DisabledByPolicy),
            Some(ErrorCode::Unsupported)
        );
        assert_eq!(
            code(UserConsentVerificationResult::DeviceBusy),
            Some(ErrorCode::Internal)
        );
        assert_eq!(
            code(UserConsentVerificationResult(i32::MAX)),
            Some(ErrorCode::Internal)
        );
    }
}
