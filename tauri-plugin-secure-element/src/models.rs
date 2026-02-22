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
    /// Optional: The name of the key to delete
    pub key_name: Option<String>,
    /// Optional: The public key (base64) of the key to delete
    pub public_key: Option<String>,
    // Note: At least one of key_name or public_key must be provided.
    // Authentication requirements are determined by the key's own attributes,
    // not by app-specified parameters. The platform enforces the key's requirements.
}

/// Response for key deletion
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteKeyResponse {
    /// Whether the deletion was successful
    pub success: bool,
}

/// Secure element hardware backing tiers.
/// Ordered weakest → strongest so that PartialOrd/Ord work naturally.
/// `capabilities.strongest >= SecureElementBacking::Integrated` reads well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SecureElementBacking {
    /// No secure element available (software-only)
    #[default]
    None,
    /// Firmware-backed, no dedicated secure processor (e.g. Windows fTPM via Intel PTT or AMD PSP)
    Firmware,
    /// On-die isolated security core (e.g. Apple Silicon Secure Enclave, ARM TrustZone/TEE)
    Integrated,
    /// Physically discrete security processor (e.g. discrete TPM 2.0, macOS T2, Android StrongBox)
    Discrete,
}

/// Response for Secure Element capabilities check
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckSecureElementSupportResponse {
    /// A discrete physical security chip is available (e.g. discrete TPM, T2, StrongBox)
    pub discrete: bool,
    /// An on-die isolated security core is available (e.g. Secure Enclave, TrustZone/TEE)
    pub integrated: bool,
    /// Firmware-backed security is available but no dedicated secure processor (e.g. fTPM)
    pub firmware: bool,
    /// The security is emulated/virtual (e.g. vTPM in a VM, iOS Simulator)
    pub emulated: bool,
    /// The strongest tier available on this device
    pub strongest: SecureElementBacking,
    /// Whether biometric-only authentication can be enforced at the key level
    /// (Android API < 30 doesn't persist this requirement)
    pub can_enforce_biometric_only: bool,
}
