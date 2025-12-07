use serde::{Deserialize, Serialize};

/// Authentication mode for secure element operations
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthenticationMode {
    /// No authentication required
    None,
    /// Allow PIN or biometric authentication (default)
    #[default]
    PinOrBiometric,
    /// Require biometric authentication only
    BiometricOnly,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingRequest {
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingResponse {
    pub value: Option<String>,
}

/// Request to generate a new non-ephemeral key in the Secure Enclave
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateSecureKeyRequest {
    /// The name/identifier for this key. Must be unique.
    pub key_name: String,
    /// Authentication mode for key operations (default: PinOrBiometric)
    #[serde(default)]
    pub auth_mode: AuthenticationMode,
}

/// Response containing the public key for the newly created key
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateSecureKeyResponse {
    /// The public key in base64 encoding
    pub public_key: String,
    /// The key name that was used
    pub key_name: String,
}

/// Request to list all available keys
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListKeysRequest {
    /// Optional filter by key name
    pub key_name: Option<String>,
    /// Optional filter by public key (base64)
    pub public_key: Option<String>,
}

/// Information about a key
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    /// The key name/identifier
    pub key_name: String,
    /// The public key in base64 encoding
    pub public_key: String,
    /// The authentication mode required by this key (None, PinOrBiometric, or BiometricOnly)
    pub auth_mode: AuthenticationMode,
}

/// Response containing list of keys
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListKeysResponse {
    /// List of keys matching the filter
    pub keys: Vec<KeyInfo>,
}

/// Request to sign data with a specific key
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignWithKeyRequest {
    /// The name of the key to use for signing
    pub key_name: String,
    /// The data to sign
    pub data: Vec<u8>,
    // Note: Authentication is enforced automatically by the platform based on the key's requirements
    // set at creation time. The auth_mode parameter is ignored for signing operations.
}

/// Response containing the signature
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignWithKeyResponse {
    /// The signature in bytes
    pub signature: Vec<u8>,
}

/// Request to delete a key
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteKeyRequest {
    /// The name of the key to delete
    pub key_name: String,
    // Note: Authentication requirements are determined by the key's own attributes,
    // not by app-specified parameters. The platform enforces the key's requirements.
}

/// Response for key deletion
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteKeyResponse {
    /// Whether the deletion was successful
    pub success: bool,
}

/// Response for Secure Element support check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSecureElementSupportResponse {
    /// Whether Secure Element (StrongBox on Android, Secure Enclave on iOS) is supported
    pub secure_element_supported: bool,
    /// Whether Trusted Execution Environment (TEE) / hardware-backed keystore is supported
    pub tee_supported: bool,
}
