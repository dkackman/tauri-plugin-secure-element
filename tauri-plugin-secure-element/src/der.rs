//! DER encoding utilities for ECDSA signatures
//!
//! This module provides cross-platform DER encoding for ECDSA signatures.
//! NCrypt on Windows returns raw R||S format, which needs to be converted
//! to DER format for compatibility with other platforms (iOS, Android, macOS).

// Allow dead_code because these functions are only used on Windows,
// but tests run on all platforms
#![allow(dead_code)]

use crate::error_sanitize::sanitize_error;

/// Converts raw ECDSA signature (R||S) to DER format
///
/// NCrypt returns raw R||S format for ECDSA P-256 (64 bytes: 32 bytes R + 32 bytes S).
/// This function converts it to DER format: SEQUENCE { INTEGER R, INTEGER S }
///
/// # Arguments
/// * `raw` - Raw signature bytes, must be exactly 64 bytes (32 for R, 32 for S)
///
/// # Returns
/// DER-encoded signature (typically 70-72 bytes for P-256)
pub fn raw_ecdsa_to_der(raw: &[u8]) -> crate::Result<Vec<u8>> {
    if raw.len() != 64 {
        return Err(crate::Error::Io(std::io::Error::other(sanitize_error(
            &format!("Invalid raw signature length: {}, expected 64", raw.len()),
            "Failed to sign",
        ))));
    }

    let r = &raw[0..32];
    let s = &raw[32..64];

    let r_der = encode_integer(r);
    let s_der = encode_integer(s);

    let seq_len = r_der.len() + s_der.len();
    let mut der = vec![0x30]; // SEQUENCE tag

    // Length encoding (DER definite form)
    if seq_len < 128 {
        der.push(seq_len as u8);
    } else {
        der.push(0x81);
        der.push(seq_len as u8);
    }

    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);

    Ok(der)
}

/// Encodes a big-endian unsigned integer as a DER INTEGER
fn encode_integer(value: &[u8]) -> Vec<u8> {
    // Remove leading zeros but keep at least one byte
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let trimmed = &value[start..];

    // Add leading zero if high bit is set (to indicate positive number in DER)
    let needs_padding = trimmed[0] & 0x80 != 0;
    let len = trimmed.len() + if needs_padding { 1 } else { 0 };

    let mut result = vec![0x02, len as u8]; // INTEGER tag + length
    if needs_padding {
        result.push(0x00);
    }
    result.extend_from_slice(trimmed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a 64-byte raw signature from R and S components
    fn make_raw_sig(r: &[u8], s: &[u8]) -> Vec<u8> {
        let mut raw = vec![0u8; 64];
        // Pad R to 32 bytes (left-padded with zeros)
        let r_start = 32 - r.len();
        raw[r_start..32].copy_from_slice(r);
        // Pad S to 32 bytes (left-padded with zeros)
        let s_start = 64 - s.len();
        raw[s_start..64].copy_from_slice(s);
        raw
    }

    /// Verify DER structure is valid: SEQUENCE { INTEGER, INTEGER }
    fn verify_der_structure(der: &[u8]) -> bool {
        if der.is_empty() || der[0] != 0x30 {
            return false; // Must start with SEQUENCE tag
        }

        // Parse sequence length
        let (seq_len, header_len) = if der[1] < 128 {
            (der[1] as usize, 2)
        } else if der[1] == 0x81 {
            (der[2] as usize, 3)
        } else {
            return false; // Unexpected length encoding
        };

        if der.len() != header_len + seq_len {
            return false; // Length mismatch
        }

        // Parse first INTEGER (R)
        let mut pos = header_len;
        if der[pos] != 0x02 {
            return false; // Must be INTEGER tag
        }
        let r_len = der[pos + 1] as usize;
        pos += 2 + r_len;

        // Parse second INTEGER (S)
        if pos >= der.len() || der[pos] != 0x02 {
            return false;
        }
        let s_len = der[pos + 1] as usize;
        pos += 2 + s_len;

        pos == der.len() // Should have consumed all bytes
    }

    #[test]
    fn test_der_encoding_minimal_values() {
        // R = 1, S = 1 (minimal non-zero values)
        let raw = make_raw_sig(&[1], &[1]);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // Expected: 30 06 02 01 01 02 01 01
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_der_encoding_all_zeros() {
        // R = 0, S = 0 (edge case: all zeros)
        let raw = vec![0u8; 64];
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // Expected: 30 06 02 01 00 02 01 00
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_der_encoding_high_bit_set() {
        // R = 0x80, S = 0xFF (high bit set, needs padding)
        let raw = make_raw_sig(&[0x80], &[0xFF]);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // Both need 0x00 padding: 30 08 02 02 00 80 02 02 00 FF
        assert_eq!(
            der,
            vec![0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x02, 0x00, 0xFF]
        );
    }

    #[test]
    fn test_der_encoding_no_padding_needed() {
        // R = 0x7F, S = 0x01 (high bit clear, no padding needed)
        let raw = make_raw_sig(&[0x7F], &[0x01]);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // No padding: 30 06 02 01 7F 02 01 01
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x7F, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_der_encoding_full_32_bytes_with_high_bit() {
        // Full 32-byte R starting with 0xFF (needs padding, total 33 bytes for R)
        let r = vec![0xFF; 32];
        let s = vec![0x01];
        let raw = make_raw_sig(&r, &s);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // R: 33 bytes (0x21) with padding, S: 1 byte
        // Total sequence: 2 + 33 + 2 + 1 = 38 bytes
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[1], 38); // Length
        assert_eq!(der[2], 0x02); // INTEGER tag for R
        assert_eq!(der[3], 33); // R length (32 + 1 padding)
        assert_eq!(der[4], 0x00); // Padding byte
        assert_eq!(der[5], 0xFF); // First R byte
    }

    #[test]
    fn test_der_encoding_full_32_bytes_no_padding() {
        // Full 32-byte R starting with 0x7F (no padding needed)
        let r = vec![0x7F; 32];
        let s = vec![0x01];
        let raw = make_raw_sig(&r, &s);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // R: 32 bytes, S: 1 byte
        // Total sequence: 2 + 32 + 2 + 1 = 37 bytes
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[1], 37); // Length
        assert_eq!(der[2], 0x02); // INTEGER tag for R
        assert_eq!(der[3], 32); // R length (no padding)
        assert_eq!(der[4], 0x7F); // First R byte
    }

    #[test]
    fn test_der_encoding_typical_signature() {
        // Simulate a typical signature with mixed values
        let r: Vec<u8> = (0..32).map(|i| ((i * 7) % 256) as u8).collect();
        let s: Vec<u8> = (0..32).map(|i| ((i * 13 + 5) % 256) as u8).collect();

        let mut raw = vec![0u8; 64];
        raw[..32].copy_from_slice(&r);
        raw[32..].copy_from_slice(&s);

        let der = raw_ecdsa_to_der(&raw).unwrap();
        assert!(verify_der_structure(&der));
    }

    #[test]
    fn test_der_encoding_max_values() {
        // Both R and S are maximum (all 0xFF) - both need padding
        let raw = vec![0xFF; 64];
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // Both R and S: 33 bytes each (32 + 1 padding)
        // Total sequence: 2 + 33 + 2 + 33 = 70 bytes
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(der[1], 70); // Length
    }

    #[test]
    fn test_der_encoding_invalid_length() {
        // Wrong length should fail
        let raw = vec![0u8; 63]; // 63 bytes instead of 64
        let result = raw_ecdsa_to_der(&raw);
        assert!(result.is_err());

        let raw = vec![0u8; 65]; // 65 bytes instead of 64
        let result = raw_ecdsa_to_der(&raw);
        assert!(result.is_err());
    }

    #[test]
    fn test_der_encoding_leading_zeros_stripped() {
        // R with many leading zeros should be trimmed
        // R = 0x00...00 0x42 (31 leading zeros, then 0x42)
        let raw = make_raw_sig(&[0x42], &[0x01]);
        let der = raw_ecdsa_to_der(&raw).unwrap();

        assert!(verify_der_structure(&der));
        // R should be just 1 byte (0x42), S should be 1 byte (0x01)
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x42, 0x02, 0x01, 0x01]);
    }
}
