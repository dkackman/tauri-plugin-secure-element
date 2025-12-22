use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};

/// Verifies an ECDSA signature using a P-256 public key.
///
/// This function uses the p256 crate (not the plugin) to verify signatures,
/// providing independent validation that the plugin's keys and signatures
/// are correctly formatted and interoperable.
///
/// # Arguments
/// * `public_key_base64` - Base64-encoded public key in SEC1 uncompressed format (65 bytes)
/// * `message` - The original message that was signed (will be hashed internally)
/// * `signature_der` - DER-encoded ECDSA signature bytes
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(String)` if there's a parsing error
#[tauri::command]
fn verify_signature(
    public_key_base64: String,
    message: Vec<u8>,
    signature_der: Vec<u8>,
) -> Result<bool, String> {
    // Decode the base64 public key
    let pk_bytes = STANDARD
        .decode(&public_key_base64)
        .map_err(|e| format!("Failed to decode public key base64: {}", e))?;

    // Parse the public key from SEC1 uncompressed format (0x04 + X + Y = 65 bytes)
    let verifying_key = VerifyingKey::from_sec1_bytes(&pk_bytes)
        .map_err(|e| format!("Failed to parse public key: {}", e))?;

    // Parse the DER-encoded signature
    let signature = DerSignature::from_bytes(&signature_der)
        .map_err(|e| format!("Failed to parse DER signature: {}", e))?;

    // Verify the signature (p256 hashes the message internally with SHA-256)
    Ok(verifying_key.verify(&message, &signature).is_ok())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![verify_signature])
        .plugin(tauri_plugin_secure_element::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
