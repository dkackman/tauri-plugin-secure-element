use windows::core::HSTRING;
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;

/// Checks if Windows Hello is configured/enrolled on the system
/// Returns true if Windows Hello PIN or biometric is actually enrolled (not just available)
/// Uses the official Windows Runtime API for reliable detection
pub fn is_windows_hello_configured() -> bool {
    // Use the official Windows Hello API to check availability
    // Returns false if the check fails (Windows Hello not available or error occurred)
    check_windows_hello_availability().unwrap_or_default()
}

/// Checks Windows Hello availability using the UserConsentVerifier API
/// This is the official and reliable way to check if Windows Hello is provisioned
fn check_windows_hello_availability() -> Result<bool, windows::core::Error> {
    // Call the async API and wait for the result
    let availability_async = UserConsentVerifier::CheckAvailabilityAsync()?;
    let availability = availability_async.join()?;

    // Windows Hello is only considered configured if it returns Available
    // Other states like DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy mean it's not usable
    match availability {
        UserConsentVerifierAvailability::Available => Ok(true),
        UserConsentVerifierAvailability::DeviceNotPresent => Ok(false),
        UserConsentVerifierAvailability::NotConfiguredForUser => Ok(false),
        UserConsentVerifierAvailability::DisabledByPolicy => Ok(false),
        _ => Ok(false),
    }
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
/// Returns `Ok(true)` only on [`UserConsentVerificationResult::Verified`]. Every
/// other outcome — the user cancelled, retries exhausted, Hello not configured —
/// is `Ok(false)`, since none of them authorize the operation. A genuine API
/// failure propagates as `Err`, so a broken verifier cannot be mistaken for a
/// refusal (or, worse, for consent).
pub fn request_user_consent(hwnd: isize, message: &str) -> Result<bool, windows::core::Error> {
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

    Ok(operation.join()? == UserConsentVerificationResult::Verified)
}
