//! Host-portable key-name encoding for the Windows backend
//!
//! Pure string manipulation, kept out of `windows.rs` so it compiles and is
//! tested on every host rather than only on Windows.

// Allow dead_code because these functions are only used on Windows,
// but tests run on all platforms
#![allow(dead_code)]

/// Key name prefix base for TPM keys without Windows Hello protection
/// Full format: tauri_se_tpm_{enc(app_id/key_name)}
pub(crate) const KEY_PREFIX_TPM_BASE: &str = "tauri_se_tpm_";

/// Domain for NGC keys
pub(crate) const NGC_DOMAIN: &str = "tauri_se";

/// Characters that cannot appear literally in a key name.
///
/// `/` and `\` would break the `{SID}//tauri_se/{app_id}/{key_name}` structure
/// that `extract_ngc_key_name` parses; the rest are rejected or reserved by the
/// key storage providers.
pub(crate) const APP_ID_RESERVED_CHARS: [char; 10] =
    ['.', '/', '\\', ':', '*', '?', '"', '<', '>', '|'];

/// Encodes an app identifier for use in key names, injectively.
///
/// Windows scopes keys per-user, not per-app (see the Security model section of
/// the README), so the app identifier is only a namespace prefix — but it still
/// has to be a *faithful* one. The previous encoding mapped all of
/// [`APP_ID_RESERVED_CHARS`] onto `_`, which is many-to-one: `com.example.app`
/// and `com_example_app` produced the same namespace, so two different apps
/// installed by the same user would read and write each other's keys, and
/// `deleteKey` in one could destroy the other's.
///
/// The escape scheme here is a decodable one — `_` doubles to `__`, every other
/// reserved character becomes `_x{HH}` — so distinct identifiers always produce
/// distinct namespaces. `__` and `_x` cannot be confused because the escape is
/// resolved left to right from a `_`. Names stay readable in `certutil -key`
/// output, which a hash would have cost.
///
/// This is deliberately not an attempt at obscurity: key names remain derivable
/// from the public app identifier, and on Windows that is not a security
/// boundary in the first place.
///
/// **Compatibility:** this changes the key names an app resolves. Keys created
/// by an earlier beta under an app identifier containing any reserved character
/// are not found by this version — they still exist in the provider, but under
/// the old name. Generate fresh keys after upgrading.
pub(crate) fn sanitize_app_id(app_id: &str) -> String {
    let mut encoded = String::with_capacity(app_id.len());
    for c in app_id.chars() {
        if c == '_' {
            encoded.push_str("__");
        } else if APP_ID_RESERVED_CHARS.contains(&c) {
            // Every reserved character is ASCII, so one byte is the whole char.
            encoded.push_str(&format!("_x{:02X}", c as u32));
        } else {
            encoded.push(c);
        }
    }
    encoded
}

/// Builds the TPM key prefix for an app: every key name of that app starts with it.
///
/// `/` is a reserved character, so `sanitize_app_id` always escapes it to `_x2F`,
/// which makes `_x2F` an unambiguous delimiter between app and key.
pub(crate) fn tpm_key_prefix(app_id: &str) -> String {
    format!("{}{}_x2F", KEY_PREFIX_TPM_BASE, sanitize_app_id(app_id))
}

/// Builds the full TPM key name.
///
/// The encoding is applied to `{app_id}/{key_name}` as a whole. `sanitize_app_id`
/// is a prefix code, so the result is injective in `(app_id, key_name)`; the
/// previous `{app}_{key}` join let different pairs collide.
///
/// Precondition: `key_name` contains no `/` (it is validated upstream). A `/`
/// in `key_name` would escape to the same `_x2F` as the delimiter and break
/// injectivity in the pair.
pub(crate) fn tpm_key_name(app_id: &str, key_name: &str) -> String {
    format!(
        "{}{}",
        KEY_PREFIX_TPM_BASE,
        sanitize_app_id(&format!("{app_id}/{key_name}"))
    )
}

/// Recovers the caller-facing key name from an enumerated TPM key name.
///
/// Returns `None` for other apps' keys, for names that are not a valid encoding
/// (a `_` not doubled), and for anything whose decoded form falls outside the
/// `[A-Za-z0-9_-]` alphabet that key names are validated to, and for an empty
/// key name (never a valid key).
///
/// Relies on the same precondition as [`tpm_key_name`]: `key_name` contains no
/// `/`, validated upstream. That is what makes the encoding injective in the pair.
pub(crate) fn decode_tpm_key_name(full_name: &str, app_id: &str) -> Option<String> {
    let rest = full_name.strip_prefix(tpm_key_prefix(app_id).as_str())?;
    let mut decoded = String::with_capacity(rest.len());
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        if c == '_' {
            if chars.next() != Some('_') {
                return None;
            }
            decoded.push('_');
        } else {
            decoded.push(c);
        }
    }
    (!decoded.is_empty()
        && decoded
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
    .then_some(decoded)
}

/// Builds the NGC key marker for the given app identifier
/// Format: /tauri_se/{app_id}//
pub(crate) fn ngc_key_marker(app_id: &str) -> String {
    format!("/{}/{}/", NGC_DOMAIN, sanitize_app_id(app_id))
}

/// Builds the full NGC key name
/// Format: {SID}//tauri_se/{app_id}/{key_name}
pub(crate) fn ngc_key_name(sid: &str, app_id: &str, key_name: &str) -> String {
    format!(
        "{}//{}/{}/{}",
        sid,
        NGC_DOMAIN,
        sanitize_app_id(app_id),
        key_name
    )
}

/// Extracts user key name from NGC format: {SID}//tauri_se/{app_id}/{key_name} -> key_name
pub(crate) fn extract_ngc_key_name<'a>(full_name: &'a str, app_id: &str) -> Option<&'a str> {
    let marker = ngc_key_marker(app_id);
    full_name
        .find(&marker)
        .map(|pos| &full_name[pos + marker.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_name_is_injective_across_delimiter_tricks() {
        assert_ne!(
            tpm_key_name("com.example", "x2Eapp_mykey"),
            tpm_key_name("com.example.app", "mykey")
        );
        assert_ne!(tpm_key_name("a", "_k"), tpm_key_name("a_", "k"));
        assert_ne!(tpm_key_name("x", "a_b"), tpm_key_name("x_a", "b"));
    }

    #[test]
    fn tpm_name_round_trips_through_decode() {
        for key in ["k", "a_b", "a__b", "_k", "k_", "A-9_"] {
            assert_eq!(
                decode_tpm_key_name(&tpm_key_name("com.example", key), "com.example").as_deref(),
                Some(key)
            );
        }
    }

    #[test]
    fn decode_rejects_other_apps_keys() {
        assert_eq!(
            decode_tpm_key_name(&tpm_key_name("com.example.app", "mykey"), "com.example"),
            None
        );
        assert_eq!(decode_tpm_key_name(&tpm_key_name("a_", "k"), "a"), None);
    }

    #[test]
    fn decode_rejects_invalid_characters_and_stray_escapes() {
        let prefix = tpm_key_prefix("com.example");
        assert_eq!(
            decode_tpm_key_name(&format!("{prefix}a_b"), "com.example"),
            None
        );
        assert_eq!(
            decode_tpm_key_name(&format!("{prefix}a.b"), "com.example"),
            None
        );
        assert_eq!(
            decode_tpm_key_name(&format!("{prefix}a_"), "com.example"),
            None
        );
        assert_eq!(decode_tpm_key_name("unrelated", "com.example"), None);
    }

    #[test]
    fn decode_rejects_empty_key_name() {
        assert_eq!(
            decode_tpm_key_name(&tpm_key_prefix("com.example"), "com.example"),
            None
        );
    }

    #[test]
    fn tpm_name_uses_escaped_slash_as_delimiter() {
        assert_eq!(
            tpm_key_name("com.example", "k"),
            "tauri_se_tpm_com_x2Eexample_x2Fk"
        );
    }

    #[test]
    fn sanitize_app_id_escapes_every_reserved_character() {
        assert_eq!(
            sanitize_app_id("com.example.app/v1:test?\"<>|\\"),
            "com_x2Eexample_x2Eapp_x2Fv1_x3Atest_x3F_x22_x3C_x3E_x7C_x5C"
        );
        assert_eq!(sanitize_app_id(""), "");
    }

    /// The bug this encoding exists to fix: `.` and `_` used to collapse
    /// together, so two apps installed by the same user shared one key
    /// namespace and could read, overwrite, or delete each other's keys.
    #[test]
    fn identifiers_differing_only_in_separators_do_not_collide() {
        assert_ne!(
            sanitize_app_id("com.example.app"),
            sanitize_app_id("com_example_app")
        );
    }

    /// Injectivity is the whole property; spot-check it over identifiers
    /// specifically chosen to stress the escape prefixes (`__` vs `_x`).
    #[test]
    fn distinct_identifiers_produce_distinct_namespaces() {
        let identifiers = [
            "com.example.app",
            "com_example_app",
            "com.example_app",
            "com_example.app",
            "com__example",
            "com_x2Eexample",
            "a.b",
            "a_b",
            "a__b",
            "",
            "_",
            ".",
        ];
        let mut seen = std::collections::HashMap::new();
        for id in identifiers {
            let encoded = sanitize_app_id(id);
            if let Some(previous) = seen.insert(encoded.clone(), id) {
                panic!("'{}' and '{}' both encode to '{}'", previous, id, encoded);
            }
        }
    }

    /// An identifier that already looks like an escape sequence must survive:
    /// the literal text `com_x2E` has to stay distinguishable from an encoded
    /// `com.`, which is exactly what doubling `_` buys.
    #[test]
    fn literal_escape_sequences_are_themselves_escaped() {
        assert_eq!(sanitize_app_id("com_x2E"), "com__x2E");
        assert_ne!(sanitize_app_id("com_x2E"), sanitize_app_id("com."));
    }

    #[test]
    fn tpm_key_prefix_includes_sanitized_app_id() {
        assert_eq!(
            tpm_key_prefix("com.example.app"),
            "tauri_se_tpm_com_x2Eexample_x2Eapp_x2F"
        );
    }

    #[test]
    fn tpm_key_name_appends_key_name_to_prefix() {
        assert_eq!(
            tpm_key_name("com.example.app", "my-key"),
            "tauri_se_tpm_com_x2Eexample_x2Eapp_x2Fmy-key"
        );
    }

    #[test]
    fn ngc_key_marker_wraps_sanitized_app_id() {
        assert_eq!(
            ngc_key_marker("com.example.app"),
            "/tauri_se/com_x2Eexample_x2Eapp/"
        );
    }

    #[test]
    fn ngc_key_name_builds_full_name() {
        assert_eq!(
            ngc_key_name("S-1-5-21-123", "com.example.app", "my-key"),
            "S-1-5-21-123//tauri_se/com_x2Eexample_x2Eapp/my-key"
        );
    }

    #[test]
    fn extract_ngc_key_name_round_trips_through_ngc_key_name() {
        let full = ngc_key_name("S-1-5-21-123", "com.example.app", "my-key");
        assert_eq!(
            extract_ngc_key_name(&full, "com.example.app"),
            Some("my-key")
        );
    }

    #[test]
    fn extract_ngc_key_name_returns_none_for_a_different_app() {
        let full = ngc_key_name("S-1-5-21-123", "com.example.app", "my-key");
        assert_eq!(extract_ngc_key_name(&full, "com.other.app"), None);
    }

    #[test]
    fn extract_ngc_key_name_returns_none_when_marker_absent() {
        assert_eq!(
            extract_ngc_key_name("not-an-ngc-name", "com.example.app"),
            None
        );
    }
}
