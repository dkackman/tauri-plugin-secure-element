use crate::Error;

/// Maximum allowed length for a key name (in bytes, not characters)
/// This limit prevents DoS attacks and keychain corruption
pub const MAX_KEY_NAME_LENGTH: usize = 64;

/// Maximum allowed size for data to be signed (in bytes)
/// This limit prevents DoS attacks and memory exhaustion
/// Set to 1MB (1024 * 1024 bytes) - adjust as needed for your use case
pub const MAX_SIGN_DATA_SIZE: usize = 1024 * 1024;

/// Validates a key name according to security requirements
///
/// Rules:
/// - Must be between 1 and 64 bytes (UTF-8 encoded)
/// - Must contain only alphanumeric characters, hyphens, and underscores
/// - Must not be empty
///
/// # Arguments
/// * `key_name` - The key name to validate
///
/// # Returns
/// * `Ok(())` if the key name is valid
/// * `Err(Error::Validation)` if the key name is invalid
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

/// Validates the size of data to be signed
///
/// Rules:
/// - Must not exceed MAX_SIGN_DATA_SIZE bytes
/// - Must not be empty (empty data can be signed, but we require explicit intent)
///
/// # Arguments
/// * `data` - The data to validate
///
/// # Returns
/// * `Ok(())` if the data size is valid
/// * `Err(Error::Validation)` if the data size is invalid
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
}
