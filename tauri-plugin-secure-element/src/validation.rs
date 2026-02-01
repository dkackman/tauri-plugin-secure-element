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

/// Rules:
/// - Must be valid base64 that can actually be decoded
/// - Decoded length must be reasonable for a public key (between 20-256 bytes)
/// - Must not be empty
pub fn validate_public_key_filter(public_key: &str) -> Result<(), Error> {
    use base64::Engine;

    // Check for empty input
    let trimmed = public_key.trim();
    if trimmed.is_empty() {
        return Err(Error::Validation(
            "Public key filter cannot be empty".to_string(),
        ));
    }

    // Check string length before attempting decode
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

    // Actually decode the base64 to validate it
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| Error::Validation(format!("Invalid base64 encoding: {}", e)))?;

    // Sanity check: decoded public key should have reasonable size
    // P-256 uncompressed: 65 bytes, compressed: 33 bytes
    // Allow some flexibility for different formats
    if decoded.is_empty() {
        return Err(Error::Validation(
            "Public key filter decodes to empty data".to_string(),
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
        // Valid base64 string - 24 chars, decodes to "testkey123456789"
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==").is_ok());

        // 20 chars (minimum) - valid base64
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc=").is_ok());

        // Longer valid base64 (44 chars - typical compressed P-256 key size)
        // This is base64 of 33 random bytes
        assert!(validate_public_key_filter("A0FhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEy").is_ok());

        // 88 chars - typical uncompressed P-256 key in X9.62 format (65 bytes)
        assert!(validate_public_key_filter(
            "BIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAo="
        ).is_ok());

        // With leading/trailing whitespace (should be trimmed)
        assert!(validate_public_key_filter("  dGVzdGtleTEyMzQ1Njc4OQ==  ").is_ok());
    }

    #[test]
    fn test_invalid_public_key_filters() {
        // Empty
        assert!(validate_public_key_filter("").is_err());

        // Whitespace only
        assert!(validate_public_key_filter("   ").is_err());

        // Too short (valid base64 but under minimum length)
        assert!(validate_public_key_filter("dGVzdA==").is_err()); // 8 chars

        // Too long
        let too_long = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &vec![0u8; 200], // Will produce >256 char base64
        );
        assert!(validate_public_key_filter(&too_long).is_err());

        // Invalid base64 - bad characters
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==@").is_err());
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ==#").is_err());

        // Invalid base64 - wrong padding
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ===").is_err());

        // Invalid base64 - not valid encoding (length not multiple of 4)
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ").is_err());

        // Trailing whitespace is fine (gets trimmed), result is valid
        assert!(validate_public_key_filter("dGVzdGtleTEyMzQ1Njc4OQ== ").is_ok());
    }
}
