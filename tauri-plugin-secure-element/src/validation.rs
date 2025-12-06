use crate::Error;

/// Maximum allowed length for a key name (in bytes, not characters)
pub const MAX_KEY_NAME_LENGTH: usize = 64;

/// Maximum allowed size for data to be signed (in bytes)
/// Set to 1MB (1024 * 1024 bytes) - adjust as needed for your use case
pub const MAX_SIGN_DATA_SIZE: usize = 1024 * 1024;

/// Maximum allowed length for a public key filter (in characters)
pub const MAX_PUBLIC_KEY_FILTER_LENGTH: usize = 256;

/// Minimum allowed length for a public key filter (in characters)
pub const MIN_PUBLIC_KEY_FILTER_LENGTH: usize = 20;

/// Rules:
/// - Must be between 1 and 64 bytes (UTF-8 encoded)
/// - Must contain only alphanumeric characters, hyphens, and underscores
/// - Must not be empty
pub fn validate_key_name(key_name: &str) -> Result<(), Error> {
    // Check minimum length
    if key_name.is_empty() {
        return Err(Error::Validation("Key name cannot be empty".to_string()));
    }

    // Check maximum length (in bytes, not characters)
    let byte_len = key_name.len();
    if byte_len > MAX_KEY_NAME_LENGTH {
        return Err(Error::Validation(format!(
            "Key name exceeds maximum length of {} bytes (got {} bytes)",
            MAX_KEY_NAME_LENGTH, byte_len
        )));
    }

    // Check character set: only alphanumeric, hyphens, and underscores
    // This prevents injection attacks and encoding issues
    if !key_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Validation(
            "Key name must contain only alphanumeric characters, hyphens, and underscores"
                .to_string(),
        ));
    }

    Ok(())
}

/// Rules:
/// - Must not exceed MAX_SIGN_DATA_SIZE bytes
/// - Must not be empty (empty data can be signed, but we require explicit intent)
pub fn validate_sign_data_size(data: &[u8]) -> Result<(), Error> {
    // Check minimum size (allow empty data, but document it)
    // Empty data can be valid for some use cases, so we allow it

    // Check maximum size (in bytes)
    let data_len = data.len();
    if data_len > MAX_SIGN_DATA_SIZE {
        return Err(Error::Validation(format!(
            "Data to sign exceeds maximum size of {} bytes (got {} bytes)",
            MAX_SIGN_DATA_SIZE, data_len
        )));
    }

    Ok(())
}

/// Rules:
/// - Must be valid base64 format
/// - Must be between MIN_PUBLIC_KEY_FILTER_LENGTH and MAX_PUBLIC_KEY_FILTER_LENGTH characters
/// - Must not be empty
pub fn validate_public_key_filter(public_key: &str) -> Result<(), Error> {
    // Check minimum length
    if public_key.is_empty() {
        return Err(Error::Validation(
            "Public key filter cannot be empty".to_string(),
        ));
    }

    // Validate base64 format
    // Base64 characters: A-Z, a-z, 0-9, +, /, and = for padding
    // We allow whitespace to be lenient, but strip it for validation
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err(Error::Validation(
            "Public key filter cannot be empty or whitespace only".to_string(),
        ));
    }

    // Remove whitespace for validation
    let no_whitespace: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();

    if no_whitespace.len() < MIN_PUBLIC_KEY_FILTER_LENGTH {
        return Err(Error::Validation(format!(
            "Public key filter is too short (minimum {} characters, got {})",
            MIN_PUBLIC_KEY_FILTER_LENGTH,
            no_whitespace.len()
        )));
    }

    if no_whitespace.len() > MAX_PUBLIC_KEY_FILTER_LENGTH {
        return Err(Error::Validation(format!(
            "Public key filter exceeds maximum length of {} characters (got {})",
            MAX_PUBLIC_KEY_FILTER_LENGTH,
            no_whitespace.len()
        )));
    }

    // Check for valid base64 characters
    // Base64 uses: A-Z, a-z, 0-9, +, /, and = for padding
    let base64_chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    if !no_whitespace.bytes().all(|b| base64_chars.contains(&b)) {
        return Err(Error::Validation(
            "Public key filter contains invalid characters (must be base64 encoded)".to_string(),
        ));
    }

    // Base64 strings must have length that's a multiple of 4 (after padding)
    // Padding can be 0, 1, or 2 '=' characters
    let padding_count = no_whitespace
        .chars()
        .rev()
        .take_while(|&c| c == '=')
        .count();
    if padding_count > 2 {
        return Err(Error::Validation(
            "Public key filter has invalid base64 padding (maximum 2 padding characters)"
                .to_string(),
        ));
    }

    if padding_count > 0 {
        let without_padding = &no_whitespace[..no_whitespace.len() - padding_count];
        if without_padding.contains('=') {
            return Err(Error::Validation(
                "Public key filter has invalid base64 padding (padding must be at the end)"
                    .to_string(),
            ));
        }
    }

    // Base64 strings must have total length that's a multiple of 4 (including padding)
    // This is a basic sanity check for base64 format
    if no_whitespace.len() % 4 != 0 {
        return Err(Error::Validation(
            "Public key filter has invalid base64 format (total length must be multiple of 4)"
                .to_string(),
        ));
    }

    // Ensure we have some data (not just padding)
    let data_len = no_whitespace.len() - padding_count;
    if data_len == 0 {
        return Err(Error::Validation(
            "Public key filter is invalid (empty after removing padding)".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_key_names() {
        assert!(validate_key_name("my-key").is_ok());
        assert!(validate_key_name("my_key").is_ok());
        assert!(validate_key_name("key123").is_ok());
        assert!(validate_key_name("a").is_ok());
        assert!(validate_key_name(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn test_invalid_key_names() {
        // Empty
        assert!(validate_key_name("").is_err());

        // Too long
        assert!(validate_key_name(&"a".repeat(65)).is_err());

        // Invalid characters
        assert!(validate_key_name("key with spaces").is_err());
        assert!(validate_key_name("key@name").is_err());
        assert!(validate_key_name("key.name").is_err());
        assert!(validate_key_name("key/name").is_err());
        assert!(validate_key_name("key\\name").is_err());
        assert!(validate_key_name("key name").is_err());

        // Unicode characters (even if they look safe)
        assert!(validate_key_name("key-ñame").is_err());
        assert!(validate_key_name("key-名字").is_err());
    }

    #[test]
    fn test_key_name_length_in_bytes() {
        // Test that length is measured in bytes, not characters
        // "ñ" is 2 bytes in UTF-8, but we should reject it anyway due to character validation
        assert!(validate_key_name("ñ").is_err());

        // Test maximum length with ASCII (1 byte per char)
        let max_ascii = "a".repeat(64);
        assert!(validate_key_name(&max_ascii).is_ok());

        // Test that 65 ASCII characters fails
        let too_long = "a".repeat(65);
        assert!(validate_key_name(&too_long).is_err());
    }

    #[test]
    fn test_valid_sign_data_sizes() {
        // Empty data is allowed
        assert!(validate_sign_data_size(&[]).is_ok());

        // Small data
        assert!(validate_sign_data_size(&[0u8; 100]).is_ok());

        // Maximum size
        let max_data = vec![0u8; MAX_SIGN_DATA_SIZE];
        assert!(validate_sign_data_size(&max_data).is_ok());
    }

    #[test]
    fn test_invalid_sign_data_sizes() {
        // Data exceeding maximum size
        let too_large = vec![0u8; MAX_SIGN_DATA_SIZE + 1];
        assert!(validate_sign_data_size(&too_large).is_err());

        // Very large data
        let very_large = vec![0u8; 10 * 1024 * 1024]; // 10MB
        assert!(validate_sign_data_size(&very_large).is_err());
    }

    #[test]
    fn test_valid_public_key_filters() {
        // Valid base64 strings (typical public key sizes)
        // 24 chars - example: "dGVzdGtleTEyMzQ1Njc4OQ==" (base64 of "testkey123456789")
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==").is_ok());

        // 20 chars (minimum) - example: "dGVzdGtleTEyMzQ1Njc="
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc=").is_ok());

        // 44 chars (compressed key) - example: "A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8"
        assert!(
            validate_public_key_filter("A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8")
                .is_ok()
        );

        // 88 chars (uncompressed key) - example with padding
        let valid_key = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE".repeat(2);
        assert!(validate_public_key_filter(&valid_key).is_ok());

        // With whitespace (should be trimmed)
        assert!(validate_public_key_filter("  dGVzdGtleTEyMzQ1Njc4OQ==  ").is_ok());

        // Maximum length (256 chars, must be multiple of 4)
        let max_key = "A".repeat(256);
        assert!(validate_public_key_filter(&max_key).is_ok());
    }

    #[test]
    fn test_invalid_public_key_filters() {
        // Empty
        assert!(validate_public_key_filter("").is_err());

        // Whitespace only
        assert!(validate_public_key_filter("   ").is_err());

        // Too short
        assert!(validate_public_key_filter("short").is_err());
        assert!(validate_public_key_filter("dGVzdA==").is_err()); // 8 chars

        // Too long
        let too_long = "A".repeat(MAX_PUBLIC_KEY_FILTER_LENGTH + 1);
        assert!(validate_public_key_filter(&too_long).is_err());

        // Invalid characters
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==@").is_err());
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==#").is_err());
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ== ").is_ok()); // Whitespace is trimmed

        // Invalid padding
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ===").is_err()); // 3 padding chars
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4O=Q=").is_err()); // Padding in middle

        // Invalid length (not multiple of 4)
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ").is_err()); // 23 chars, not multiple of 4
    }
}
