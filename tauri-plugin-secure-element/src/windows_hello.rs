use windows::core::{HSTRING, PCWSTR};
use windows::Win32::System::Registry::{
    RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_RT_ANY,
};

/// Checks if Windows Hello is configured/enrolled on the system
/// Returns true if Windows Hello PIN or biometric is actually enrolled (not just available)
/// Checks for actual NGC (Next Generation Credentials) enrollment, not just service availability
pub fn is_windows_hello_configured() -> bool {
    use std::path::Path;

    // The most reliable check: verify that NGC folder exists and contains enrolled credentials
    // NGC folder: C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC
    let ngc_path = Path::new(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\NGC");

    eprintln!("[secure-element] Checking NGC folder: {:?}", ngc_path);

    if !ngc_path.exists() {
        eprintln!("[secure-element] NGC folder does not exist - Windows Hello not enrolled");
        return false;
    }

    // Check if NGC folder contains any credential files (indicates actual enrollment)
    // NGC stores credentials in .dat files
    match std::fs::read_dir(ngc_path) {
        Ok(entries) => {
            let mut has_credentials = false;
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "dat" || ext == "tmp" {
                            eprintln!("[secure-element] Found NGC credential file: {:?}", path);
                            has_credentials = true;
                            break;
                        }
                    }
                }
            }

            if has_credentials {
                eprintln!("[secure-element] Windows Hello detected - NGC folder contains credentials");
                return true;
            } else {
                eprintln!("[secure-element] NGC folder exists but contains no credentials - Windows Hello not enrolled");
                return false;
            }
        }
        Err(e) => {
            eprintln!("[secure-element] Error reading NGC folder: {:?}", e);
            // Fall back to registry check if we can't read the folder
            return is_windows_hello_configured_registry_fallback();
        }
    }
}

/// Fallback registry check if NGC folder is not accessible
/// Checks multiple registry locations for actual Windows Hello PIN enrollment
fn is_windows_hello_configured_registry_fallback() -> bool {
    unsafe {
        // Check 1: NgcPin\PinHash - indicates PIN is enrolled
        let ngc_pin_key = HSTRING::from(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin");
        let pin_hash_value = HSTRING::from("PinHash");
        let mut data_size: u32 = 0;

        let pin_hash_result = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(ngc_pin_key.as_ptr()),
            PCWSTR::from_raw(pin_hash_value.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut data_size),
        );

        eprintln!("[secure-element] Registry check 1 (NgcPin\\PinHash): result={:?}, size={}", pin_hash_result.is_ok(), data_size);
        if pin_hash_result.is_ok() && data_size > 0 {
            eprintln!("[secure-element] Windows Hello PIN detected via PinHash");
            return true;
        }

        // Check 2: Check if there are any NGC keys under the user's SID
        // This is a more reliable indicator of actual enrollment
        // We check if NgcPin key exists (even without PinHash, the key existing indicates enrollment)
        let ngc_pin_key_check = HSTRING::from(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\NgcPin");
        let mut key_exists_size: u32 = 0;

        // Try to read any value from NgcPin key to see if it exists
        let key_check_result = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(ngc_pin_key_check.as_ptr()),
            PCWSTR::null(),
            RRF_RT_ANY,
            None,
            None,
            Some(&mut key_exists_size),
        );

        eprintln!("[secure-element] Registry check 2 (NgcPin key exists): result={:?}, size={}", key_check_result.is_ok(), key_exists_size);
        if key_check_result.is_ok() {
            eprintln!("[secure-element] Windows Hello PIN detected - NgcPin registry key exists");
            return true;
        }

        // Check 3: Alternative location - check for NGC enrollment in Credential Providers
        let ngc_enrollment_key = HSTRING::from(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{D6886603-9D2F-4EB2-B667-1971041FA96B}");
        let mut enrollment_size: u32 = 0;

        let enrollment_check = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(ngc_enrollment_key.as_ptr()),
            PCWSTR::null(),
            RRF_RT_ANY,
            None,
            None,
            Some(&mut enrollment_size),
        );

        eprintln!("[secure-element] Registry check 3 (NGC Credential Provider): result={:?}, size={}", enrollment_check.is_ok(), enrollment_size);

        // If the NGC provider key exists, Windows Hello is likely configured
        // But this is less reliable than the PinHash check
        let result = enrollment_check.is_ok();
        if result {
            eprintln!("[secure-element] Windows Hello detected via NGC Credential Provider");
        } else {
            eprintln!("[secure-element] Windows Hello not detected - all registry checks failed");
        }
        result
    }
}

