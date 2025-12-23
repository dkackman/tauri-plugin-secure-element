use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};

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
    let availability = availability_async.get()?;

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
