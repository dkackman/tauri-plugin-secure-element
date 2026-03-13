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
/// - Must not be empty
/// - Must not exceed MAX_SIGN_DATA_SIZE bytes
pub fn validate_sign_data_size(data: &[u8]) -> Result<(), Error> {
    // Check maximum size (in bytes)
    let data_len = data.len();
    if data_len > MAX_SIGN_DATA_SIZE {
        return Err(Error::Validation(format!(
            "Data to sign exceeds maximum size of {} bytes (got {} bytes)",
            MAX_SIGN_DATA_SIZE, data_len
        )));
    }
    if data_len == 0 {
        return Err(Error::Validation(
            "Data to sign cannot be empty".to_string(),
        ));
    }

    Ok(())
}

/// Validates and normalizes a public key filter string.
/// Trims whitespace and checks length bounds.
/// The filter is only used for exact `==` comparison against known-good base64 strings,
/// so detailed base64 format validation is unnecessary.
pub fn validate_public_key_filter(public_key: &str) -> Result<String, Error> {
    let trimmed = public_key.trim();

    if trimmed.is_empty() {
        return Err(Error::Validation(
            "Public key filter cannot be empty".to_string(),
        ));
    }

    if trimmed.len() < MIN_PUBLIC_KEY_FILTER_LENGTH {
        return Err(Error::Validation(format!(
            "Public key filter is too short (minimum {} characters, got {})",
            MIN_PUBLIC_KEY_FILTER_LENGTH,
            trimmed.len()
        )));
    }

    if trimmed.len() > MAX_PUBLIC_KEY_FILTER_LENGTH {
        return Err(Error::Validation(format!(
            "Public key filter exceeds maximum length of {} characters (got {})",
            MAX_PUBLIC_KEY_FILTER_LENGTH,
            trimmed.len()
        )));
    }

    Ok(trimmed.to_string())
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
        // Small data
        assert!(validate_sign_data_size(&[0u8; 1]).is_ok());
        assert!(validate_sign_data_size(&[0u8; 100]).is_ok());

        // Maximum size
        let max_data = vec![0u8; MAX_SIGN_DATA_SIZE];
        assert!(validate_sign_data_size(&max_data).is_ok());
    }

    #[test]
    fn test_invalid_sign_data_sizes() {
        // Empty data is not allowed
        assert!(validate_sign_data_size(&[]).is_err());

        // Data exceeding maximum size
        let too_large = vec![0u8; MAX_SIGN_DATA_SIZE + 1];
        assert!(validate_sign_data_size(&too_large).is_err());

        // Very large data
        let very_large = vec![0u8; 10 * 1024 * 1024]; // 10MB
        assert!(validate_sign_data_size(&very_large).is_err());
    }

    #[test]
    fn test_valid_public_key_filters() {
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==").is_ok());
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc=").is_ok());
        assert!(validate_public_key_filter(&"A".repeat(256)).is_ok());

        // Whitespace is trimmed and the cleaned string is returned
        assert_eq!(
            validate_public_key_filter("  dGVzdGtleTEyMzQ1Njc4OQ==  ").unwrap(),
            "dGVzdGtleTEyMzQ1Njc4OQ=="
        );
    }

    #[test]
    fn test_invalid_public_key_filters() {
        assert!(validate_public_key_filter("").is_err());
        assert!(validate_public_key_filter("   ").is_err());
        assert!(validate_public_key_filter("short").is_err());
        assert!(validate_public_key_filter(&"A".repeat(257)).is_err());
    }
}
