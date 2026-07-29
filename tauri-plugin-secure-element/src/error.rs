use serde::{ser::SerializeStruct, ser::Serializer, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

/// A stable, machine-readable classification of a failure.
///
/// Every error this plugin returns carries one. The accompanying message is
/// prose meant for a log — it is generic in release builds (see
/// [`crate::error_sanitize`]) and its wording is not part of the API. The code
/// is: it never contains key names or OS status values, so it survives release
/// sanitization intact and is the only thing a caller should branch on.
///
/// Codes are additive. Treat an unrecognized value the same as
/// [`ErrorCode::Internal`] rather than matching exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    /// The user dismissed the authentication prompt, or the OS cancelled it on
    /// their behalf (app backgrounded, a competing prompt took over).
    ///
    /// Expected and benign — the usual response is to do nothing, not to show
    /// an error.
    UserCancelled,

    /// Authentication ran and was rejected: a wrong PIN, an unrecognized
    /// fingerprint, or biometry locked out after too many attempts.
    ///
    /// Distinct from [`ErrorCode::UserCancelled`] — the user tried and failed
    /// rather than declining — so retrying is reasonable.
    AuthFailed,

    /// The key still exists but can never be used again, because the enrolled
    /// biometric set changed after it was created.
    ///
    /// There is no recovery: the private key material is gone. The only remedy
    /// is to delete the key and generate a new one, which for most
    /// applications also means re-enrolling the new public key wherever the old
    /// one was registered.
    ///
    /// Only Android reports this precisely (`KeyPermanentlyInvalidatedException`).
    /// Apple platforms cannot distinguish an invalidated key from a failed
    /// authentication and report [`ErrorCode::AuthFailed`] instead — see the
    /// Security model section of the README.
    KeyInvalidated,

    /// No key matched the requested name or public key.
    KeyNotFound,

    /// A key with the requested name already exists.
    KeyAlreadyExists,

    /// The key exists but is not usable right now — typically because the
    /// device is locked. Unlike [`ErrorCode::KeyInvalidated`] this is
    /// transient; retrying once the device is unlocked will succeed.
    KeyNotAccessible,

    /// The device has no passcode/PIN set, or no biometric enrolled, and the
    /// requested authentication mode requires one.
    ///
    /// Actionable by the user: they can set a passcode or enroll a biometric
    /// and retry.
    DeviceNotSecure,

    /// The operation or authentication mode is not available on this platform,
    /// OS version, or hardware — for example `biometricOnly` on Windows.
    /// Retrying will not help.
    Unsupported,

    /// Caller-supplied arguments failed validation before reaching the
    /// platform. A bug in the calling code, not a runtime condition.
    Validation,

    /// Anything else: an unmapped OS status, an FFI fault, a provider error.
    /// Also the correct fallback for any code a caller does not recognize.
    Internal,
}

impl ErrorCode {
    /// The wire representation, matching the `serde` `camelCase` renaming.
    ///
    /// Used to parse codes back out of the mobile bridge, where they arrive as
    /// strings chosen by the Kotlin and Swift layers.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserCancelled => "userCancelled",
            Self::AuthFailed => "authFailed",
            Self::KeyInvalidated => "keyInvalidated",
            Self::KeyNotFound => "keyNotFound",
            Self::KeyAlreadyExists => "keyAlreadyExists",
            Self::KeyNotAccessible => "keyNotAccessible",
            Self::DeviceNotSecure => "deviceNotSecure",
            Self::Unsupported => "unsupported",
            Self::Validation => "validation",
            Self::Internal => "internal",
        }
    }

    /// Parses a code emitted by the Kotlin/Swift layers or the macOS FFI.
    ///
    /// Unknown strings collapse to [`ErrorCode::Internal`] rather than failing,
    /// so a newer platform layer paired with an older Rust core degrades to
    /// "something went wrong" instead of erroring twice.
    pub fn parse(s: &str) -> Self {
        match s {
            "userCancelled" => Self::UserCancelled,
            "authFailed" => Self::AuthFailed,
            "keyInvalidated" => Self::KeyInvalidated,
            "keyNotFound" => Self::KeyNotFound,
            "keyAlreadyExists" => Self::KeyAlreadyExists,
            "keyNotAccessible" => Self::KeyNotAccessible,
            "deviceNotSecure" => Self::DeviceNotSecure,
            "unsupported" => Self::Unsupported,
            "validation" => Self::Validation,
            _ => Self::Internal,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(mobile)]
    #[error(transparent)]
    PluginInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
    #[error("Validation error: {0}")]
    Validation(String),
    /// A failure the platform layer classified itself.
    ///
    /// This is the variant every Windows, macOS-FFI and mobile-bridge error
    /// should land in, because it is the only one that carries a deliberate
    /// [`ErrorCode`] rather than an inferred one.
    #[error("{message}")]
    Platform { code: ErrorCode, message: String },
}

impl Error {
    /// Builds an [`Error::Platform`] from a code and message.
    pub fn platform(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Platform {
            code,
            message: message.into(),
        }
    }

    /// The code a caller should branch on.
    ///
    /// [`Error::Platform`] carries one deliberately. The remaining variants
    /// predate codes and are classified here: `Io` by its
    /// [`std::io::ErrorKind`], which the desktop layer already sets
    /// meaningfully (`Unsupported` for "not available on this platform",
    /// `InvalidInput` for bad arguments), and `PluginInvoke` by the `code`
    /// Kotlin/Swift passed to `Invoke.reject`.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Platform { code, .. } => *code,
            Self::Validation(_) => ErrorCode::Validation,
            Self::Io(e) => match e.kind() {
                std::io::ErrorKind::Unsupported => ErrorCode::Unsupported,
                std::io::ErrorKind::InvalidInput => ErrorCode::Validation,
                std::io::ErrorKind::NotFound => ErrorCode::KeyNotFound,
                std::io::ErrorKind::PermissionDenied => ErrorCode::KeyNotAccessible,
                _ => ErrorCode::Internal,
            },
            #[cfg(mobile)]
            Self::PluginInvoke(e) => match e {
                tauri::plugin::mobile::PluginInvokeError::InvokeRejected(response) => response
                    .code
                    .as_deref()
                    .map(ErrorCode::parse)
                    .unwrap_or(ErrorCode::Internal),
                _ => ErrorCode::Internal,
            },
        }
    }

    /// The human-readable message, without the `[code] - ` prefix Tauri's
    /// mobile `ErrorResponse` prepends in its own `Display`.
    ///
    /// That prefix would otherwise be duplicated: the code travels in its own
    /// field, so repeating it inside the message just makes logs harder to read.
    pub fn message(&self) -> String {
        #[cfg(mobile)]
        if let Self::PluginInvoke(tauri::plugin::mobile::PluginInvokeError::InvokeRejected(
            response,
        )) = self
        {
            if let Some(message) = &response.message {
                return message.clone();
            }
        }
        self.to_string()
    }
}

/// Serializes as `{"code": "...", "message": "..."}`.
///
/// Tauri rejects the JS promise with whatever this produces, so this shape is
/// the plugin's error contract with `guest-js`. It is deliberately an object
/// rather than the bare string earlier betas emitted: a caller cannot branch on
/// prose that changes between debug and release builds.
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Error", 2)?;
        state.serialize_field("code", &self.code())?;
        state.serialize_field("message", &self.message())?;
        state.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trips_through_its_wire_form() {
        let all = [
            ErrorCode::UserCancelled,
            ErrorCode::AuthFailed,
            ErrorCode::KeyInvalidated,
            ErrorCode::KeyNotFound,
            ErrorCode::KeyAlreadyExists,
            ErrorCode::KeyNotAccessible,
            ErrorCode::DeviceNotSecure,
            ErrorCode::Unsupported,
            ErrorCode::Validation,
            ErrorCode::Internal,
        ];
        for code in all {
            assert_eq!(ErrorCode::parse(code.as_str()), code);
        }
    }

    /// `as_str` is hand-written while the wire form comes from serde's
    /// `camelCase` renaming; they have to agree or codes parse back as
    /// `Internal` on the mobile bridge.
    #[test]
    fn as_str_matches_serde_representation() {
        let json = serde_json::to_string(&ErrorCode::KeyInvalidated).unwrap();
        assert_eq!(json, "\"keyInvalidated\"");
        assert_eq!(json, format!("\"{}\"", ErrorCode::KeyInvalidated.as_str()));
    }

    #[test]
    fn unknown_code_parses_as_internal() {
        assert_eq!(ErrorCode::parse("somethingNewer"), ErrorCode::Internal);
    }

    #[test]
    fn platform_error_keeps_its_code() {
        let err = Error::platform(ErrorCode::UserCancelled, "User cancelled");
        assert_eq!(err.code(), ErrorCode::UserCancelled);
        assert_eq!(err.message(), "User cancelled");
    }

    #[test]
    fn validation_error_is_classified() {
        let err = Error::Validation("bad name".to_string());
        assert_eq!(err.code(), ErrorCode::Validation);
    }

    #[test]
    fn io_error_kind_drives_the_code() {
        let unsupported = Error::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "no secure element",
        ));
        assert_eq!(unsupported.code(), ErrorCode::Unsupported);

        let invalid_input = Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bad arg",
        ));
        assert_eq!(invalid_input.code(), ErrorCode::Validation);

        let other = Error::Io(std::io::Error::other("boom"));
        assert_eq!(other.code(), ErrorCode::Internal);
    }

    #[test]
    fn serializes_as_code_and_message() {
        let err = Error::platform(ErrorCode::KeyNotFound, "Key not found");
        let json: serde_json::Value = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "keyNotFound");
        assert_eq!(json["message"], "Key not found");
    }

    /// The whole point of the code field is that it survives release
    /// sanitization, where the message is replaced with a generic string.
    #[test]
    fn code_carries_no_key_name() {
        let err = Error::platform(
            ErrorCode::KeyAlreadyExists,
            crate::error_sanitize::sanitize_error(
                "Key already exists: secret",
                "Key already exists",
            ),
        );
        assert!(!err.code().as_str().contains("secret"));
    }
}
