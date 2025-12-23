//! Error sanitization helpers
//!
//! Expose detailed errors only in debug builds to avoid leaking
//! sensitive information in production. This aligns with the Android
//! pattern of sanitizing errors for release builds.

// Allow dead_code because these functions are only used on Windows
#![allow(dead_code)]

/// Returns detailed error message in debug builds, generic message in release builds
#[cfg(debug_assertions)]
pub fn sanitize_error(detailed: &str, _generic: &str) -> String {
    detailed.to_string()
}

#[cfg(not(debug_assertions))]
pub fn sanitize_error(_detailed: &str, generic: &str) -> String {
    generic.to_string()
}

/// Returns "operation: key_name" in debug builds, just "operation" in release builds
#[cfg(debug_assertions)]
pub fn sanitize_error_with_key_name(key_name: &str, operation: &str) -> String {
    format!("{}: {}", operation, key_name)
}

#[cfg(not(debug_assertions))]
pub fn sanitize_error_with_key_name(_key_name: &str, operation: &str) -> String {
    operation.to_string()
}
