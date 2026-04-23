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

#[cfg(test)]
mod tests {
    use super::*;

    // cargo test always compiles with debug_assertions, so these tests cover the
    // debug path. The release path (returning the generic string verbatim) is
    // trivial enough to verify by inspection and cannot be exercised in the same
    // binary without rebuilding with --release.

    #[test]
    fn sanitize_error_returns_detailed_in_debug() {
        let result = sanitize_error("detailed message", "generic message");
        assert_eq!(result, "detailed message");
    }

    #[test]
    fn sanitize_error_detailed_can_contain_sensitive_context() {
        let result = sanitize_error(
            "failed to open key 'my-key': os error 5",
            "Failed to open key",
        );
        assert!(result.contains("my-key"));
        assert!(result.contains("os error 5"));
    }

    #[test]
    fn sanitize_error_with_key_name_formats_correctly_in_debug() {
        let result = sanitize_error_with_key_name("my-key", "Key not found");
        assert_eq!(result, "Key not found: my-key");
    }

    #[test]
    fn sanitize_error_with_key_name_operation_comes_first() {
        let result = sanitize_error_with_key_name("k", "op");
        assert_eq!(result, "op: k");
    }

    #[test]
    fn sanitize_error_with_empty_key_name_still_formats() {
        let result = sanitize_error_with_key_name("", "Delete failed");
        assert_eq!(result, "Delete failed: ");
    }
}
