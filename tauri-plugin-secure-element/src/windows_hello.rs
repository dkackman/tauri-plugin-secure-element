use windows::Security::Credentials::UI::{
    UserConsentVerifier, UserConsentVerifierAvailability,
};

/// Checks if Windows Hello is configured/enrolled on the system
/// Returns true if Windows Hello PIN or biometric is actually enrolled (not just available)
/// Uses the official Windows Runtime API for reliable detection
pub fn is_windows_hello_configured() -> bool {
    eprintln!("[secure-element] Checking Windows Hello configuration using UserConsentVerifier API");

    // Use the official Windows Hello API to check availability
    match check_windows_hello_availability() {
        Ok(is_configured) => {
            eprintln!("[secure-element] Windows Hello configured: {}", is_configured);
            is_configured
        }
        Err(e) => {
            eprintln!("[secure-element] Error checking Windows Hello: {:?}", e);
            false
        }
    }
}

/// Checks Windows Hello availability using the UserConsentVerifier API
/// This is the official and reliable way to check if Windows Hello is provisioned
fn check_windows_hello_availability() -> Result<bool, windows::core::Error> {
    // Call the async API and wait for the result
    let availability_async = UserConsentVerifier::CheckAvailabilityAsync()?;
    let availability = availability_async.get()?;

    eprintln!("[secure-element] UserConsentVerifier availability: {:?}", availability);

    // Windows Hello is only considered configured if it returns Available
    // Other states like DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy mean it's not usable
    match availability {
        UserConsentVerifierAvailability::Available => {
            eprintln!("[secure-element] Windows Hello is available and configured");
            Ok(true)
        }
        UserConsentVerifierAvailability::DeviceNotPresent => {
            eprintln!("[secure-element] No biometric device present");
            Ok(false)
        }
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            eprintln!("[secure-element] Windows Hello not configured for user (no PIN or biometric enrolled)");
            Ok(false)
        }
        UserConsentVerifierAvailability::DisabledByPolicy => {
            eprintln!("[secure-element] Windows Hello disabled by policy");
            Ok(false)
        }
        _ => {
            eprintln!("[secure-element] Windows Hello not available (unknown status)");
            Ok(false)
        }
    }
}
