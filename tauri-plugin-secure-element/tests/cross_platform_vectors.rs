//! Verifies the recorded cross-platform signature vectors.
//!
//! `test-app/src/cross-platform-test-vectors.json` holds real signatures captured from
//! hardware on every supported platform: iOS and macOS (Secure Enclave), Android
//! (StrongBox/TEE) and Windows (TPM/NGC). Verifying them here locks down three things
//! that would otherwise only be caught by hand-testing on four devices:
//!
//! * the DER encoding of the signature — for Windows that means `src/der.rs`, which
//!   converts the raw R||S NCrypt returns;
//! * the X9.62 uncompressed public-key export;
//! * the hash-then-sign convention (SHA-256 over the raw message bytes).
//!
//! The vectors live under `test-app/` because that is what generates them, and are
//! pulled in at compile time. `tests/` is excluded from the published crate, so the
//! path never has to resolve outside this repository.

use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../../test-app/src/cross-platform-test-vectors.json");

/// Every platform that must be represented. A vector file that quietly loses a platform
/// still passes every per-vector check, so assert the coverage separately.
const REQUIRED_PLATFORMS: [&str; 4] = ["ios", "macos", "android", "windows"];

#[derive(Deserialize)]
struct VectorFile {
    algorithm: String,
    #[serde(rename = "signatureFormat")]
    signature_format: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    platform: String,
    label: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    message: String,
    #[serde(rename = "signatureBase64")]
    signature_base64: String,
}

fn load() -> VectorFile {
    let file: VectorFile = serde_json::from_str(VECTORS_JSON).expect("vector file must parse");
    assert_eq!(file.algorithm, "ECDSA-P256-SHA256");
    assert_eq!(file.signature_format, "DER");
    assert!(!file.vectors.is_empty(), "vector file must not be empty");
    file
}

fn decode(what: &str, label: &str, value: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap_or_else(|e| panic!("{label}: {what} is not valid base64: {e}"))
}

fn verifying_key(vector: &Vector) -> VerifyingKey {
    let bytes = decode("public key", &vector.label, &vector.public_key);
    assert_eq!(
        bytes.len(),
        65,
        "{}: expected a 65-byte X9.62 uncompressed point, got {}",
        vector.label,
        bytes.len()
    );
    assert_eq!(
        bytes[0], 0x04,
        "{}: public key is not an uncompressed point",
        vector.label
    );
    VerifyingKey::from_sec1_bytes(&bytes).unwrap_or_else(|e| {
        panic!(
            "{}: public key is not a valid P-256 point: {e}",
            vector.label
        )
    })
}

fn signature(vector: &Vector) -> Signature {
    let bytes = decode("signature", &vector.label, &vector.signature_base64);
    Signature::from_der(&bytes)
        .unwrap_or_else(|e| panic!("{}: signature is not valid DER: {e}", vector.label))
}

#[test]
fn every_recorded_signature_verifies() {
    let file = load();

    for vector in &file.vectors {
        let key = verifying_key(vector);
        let sig = signature(vector);

        // `verify` hashes with SHA-256 internally, so this also asserts that every
        // platform signs the SHA-256 digest of the raw UTF-8 message bytes.
        key.verify(vector.message.as_bytes(), &sig)
            .unwrap_or_else(|e| panic!("{}: signature does not verify: {e}", vector.label));
    }
}

#[test]
fn every_platform_is_covered() {
    let file = load();

    for platform in REQUIRED_PLATFORMS {
        let count = file
            .vectors
            .iter()
            .filter(|v| v.platform == platform)
            .count();
        assert!(count > 0, "no test vectors recorded for {platform}");
    }

    // A non-ASCII message exercises the byte-length handling that a character-length
    // bug would sail past.
    for platform in REQUIRED_PLATFORMS {
        assert!(
            file.vectors
                .iter()
                .any(|v| v.platform == platform && !v.message.is_ascii()),
            "{platform} has no non-ASCII message vector"
        );
    }
}

#[test]
fn a_tampered_message_does_not_verify() {
    let file = load();

    for vector in &file.vectors {
        let key = verifying_key(vector);
        let sig = signature(vector);

        let mut tampered = vector.message.clone().into_bytes();
        // Flip the last byte's low bit — still the same length, still a different message.
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;

        assert!(
            key.verify(&tampered, &sig).is_err(),
            "{}: a tampered message verified — the test is passing vacuously",
            vector.label
        );
    }
}

#[test]
fn a_signature_from_another_key_does_not_verify() {
    let file = load();

    for vector in &file.vectors {
        let key = verifying_key(vector);

        // Any vector signed under a different public key must not verify under this one.
        let foreign = file
            .vectors
            .iter()
            .find(|v| v.public_key != vector.public_key && v.message == vector.message);
        let Some(foreign) = foreign else { continue };

        assert!(
            key.verify(vector.message.as_bytes(), &signature(foreign))
                .is_err(),
            "{}: verified a signature made by {}'s key",
            vector.label,
            foreign.label
        );
    }
}
