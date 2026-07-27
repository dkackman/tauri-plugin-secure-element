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
    /// The actual hardware backing tier used for this key.
    /// On Android this may differ from the device's strongest tier if StrongBox
    /// creation failed and the plugin fell back to TEE.
    pub backing: SecureElementBacking,
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
///
/// This deliberately carries no authentication mode or provider, and should not
/// be given one. That field cannot be made to mean the same thing on every
/// platform:
///
/// - Windows: OS-attested and free. NGC (Windows Hello) vs Platform Crypto
///   Provider is already known at enumeration time.
/// - Android: OS-attested, at the cost of one
///   `KeyFactory.getKeySpec(privateKey, KeyInfo::class.java)` per key per
///   listing. That reads the Keymaster characteristics rather than using the
///   key, so it does not prompt.
/// - Apple: not recoverable at all. All three modes are created with the same
///   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so the mode lives only in
///   the `SecAccessControlCreateFlags` — and `SecAccessControl` exposes no
///   accessor for them (`SecAccessControlCreateWithFlags` and
///   `SecAccessControlGetTypeID` are the entire API). The mode is write-only:
///   converted to flags at creation and discarded.
///
/// A field that is OS-attested on two platforms and a memo the plugin wrote to
/// itself on the third, with no way for a caller to tell which one they are
/// holding, is worse than no field at all for anything security-relevant —
/// absent at least fails obviously. It is the same trap as the old
/// `canEnforceBiometricOnly`, which answered live-enrollment on Apple and an
/// API-level check on Android under one name until the semantics were aligned.
///
/// Callers needing the mode already know it — they passed it to
/// `generateSecureKey` — and can persist it themselves on all four platforms,
/// which is more than this plugin can do. The Windows layer keeps the provider
/// internally in `FoundKey`, where delete-by-public-key needs it, without
/// exposing it here.
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
    /// No key storage available at all.
    #[default]
    None,
    /// The key exists but is protected only by the OS, not by hardware (e.g. the
    /// Android emulator's software KeyMint, or a device with no TEE). The key is
    /// functional — it signs and verifies correctly — but it is extractable by a
    /// sufficiently privileged attacker. Callers that require hardware protection
    /// must reject this tier explicitly.
    Software,
    /// Firmware-backed, no dedicated secure processor (e.g. Windows fTPM via Intel PTT or AMD PSP)
    Firmware,
    /// On-die isolated security core (e.g. Apple Silicon Secure Enclave, ARM TrustZone/TEE)
    Integrated,
    /// Physically discrete security processor (e.g. discrete TPM 2.0, macOS T2, Android StrongBox)
    Discrete,
}

#[cfg(test)]
mod backing_tests {
    use super::*;

    // Ordering: None < Software < Firmware < Integrated < Discrete
    #[test]
    fn backing_order_is_weakest_to_strongest() {
        assert!(SecureElementBacking::None < SecureElementBacking::Software);
        assert!(SecureElementBacking::Software < SecureElementBacking::Firmware);
        assert!(SecureElementBacking::Firmware < SecureElementBacking::Integrated);
        assert!(SecureElementBacking::Integrated < SecureElementBacking::Discrete);
    }

    // The hardware/software boundary is the comparison callers gate on, so pin it:
    // everything at or above Firmware is hardware-protected, everything below is not.
    #[test]
    fn software_sorts_below_every_hardware_tier() {
        for hw in [
            SecureElementBacking::Firmware,
            SecureElementBacking::Integrated,
            SecureElementBacking::Discrete,
        ] {
            assert!(SecureElementBacking::Software < hw);
        }
    }

    #[test]
    fn backing_transitive_none_less_than_discrete() {
        assert!(SecureElementBacking::None < SecureElementBacking::Discrete);
    }

    #[test]
    fn backing_default_is_none() {
        assert_eq!(SecureElementBacking::default(), SecureElementBacking::None);
    }

    #[test]
    fn backing_equality() {
        assert_eq!(
            SecureElementBacking::Discrete,
            SecureElementBacking::Discrete
        );
        assert_ne!(
            SecureElementBacking::Discrete,
            SecureElementBacking::Integrated
        );
    }

    // Serde: each variant must round-trip through JSON as its camelCase string.
    // The JS API depends on these exact string values.
    #[test]
    fn backing_serializes_to_camelcase_strings() {
        assert_eq!(
            serde_json::to_string(&SecureElementBacking::None).unwrap(),
            "\"none\""
        );
        assert_eq!(
            serde_json::to_string(&SecureElementBacking::Software).unwrap(),
            "\"software\""
        );
        assert_eq!(
            serde_json::to_string(&SecureElementBacking::Firmware).unwrap(),
            "\"firmware\""
        );
        assert_eq!(
            serde_json::to_string(&SecureElementBacking::Integrated).unwrap(),
            "\"integrated\""
        );
        assert_eq!(
            serde_json::to_string(&SecureElementBacking::Discrete).unwrap(),
            "\"discrete\""
        );
    }

    #[test]
    fn backing_deserializes_from_camelcase_strings() {
        assert_eq!(
            serde_json::from_str::<SecureElementBacking>("\"none\"").unwrap(),
            SecureElementBacking::None
        );
        assert_eq!(
            serde_json::from_str::<SecureElementBacking>("\"software\"").unwrap(),
            SecureElementBacking::Software
        );
        assert_eq!(
            serde_json::from_str::<SecureElementBacking>("\"firmware\"").unwrap(),
            SecureElementBacking::Firmware
        );
        assert_eq!(
            serde_json::from_str::<SecureElementBacking>("\"integrated\"").unwrap(),
            SecureElementBacking::Integrated
        );
        assert_eq!(
            serde_json::from_str::<SecureElementBacking>("\"discrete\"").unwrap(),
            SecureElementBacking::Discrete
        );
    }

    #[test]
    fn backing_serde_roundtrip() {
        for variant in [
            SecureElementBacking::None,
            SecureElementBacking::Software,
            SecureElementBacking::Firmware,
            SecureElementBacking::Integrated,
            SecureElementBacking::Discrete,
        ] {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SecureElementBacking = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // The generate response must include backing and it must serde correctly.
    #[test]
    fn generate_response_backing_field_serializes() {
        let resp = GenerateSecureKeyResponse {
            public_key: "abc".to_string(),
            key_name: "k".to_string(),
            backing: SecureElementBacking::Discrete,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"backing\":\"discrete\""));
        assert!(json.contains("\"publicKey\":\"abc\""));
    }
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
