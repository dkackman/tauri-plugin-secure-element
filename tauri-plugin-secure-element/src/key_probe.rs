//! Host-portable resolution of a key-open probe
//!
//! One rule shared by the NGC and TPM providers: an access-denied open is
//! ambiguous, and enumeration decides whether the key exists.

// Allow dead_code because these functions are only used on Windows,
// but tests run on all platforms
#![allow(dead_code)]

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ProbeOutcome {
    Found,
    Absent,
    Inaccessible,
}

/// `probe_denied` is whether the open returned access-denied; `enumerated_present` is called only in that case.
pub(crate) fn resolve_probe(
    opened: bool,
    probe_denied: bool,
    enumerated_present: impl FnOnce() -> crate::Result<bool>,
) -> crate::Result<ProbeOutcome> {
    if opened {
        return Ok(ProbeOutcome::Found);
    }
    if !probe_denied {
        return Ok(ProbeOutcome::Absent);
    }
    Ok(if enumerated_present()? {
        ProbeOutcome::Inaccessible
    } else {
        ProbeOutcome::Absent
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn run(
        opened: bool,
        denied: bool,
        present: crate::Result<bool>,
    ) -> (crate::Result<ProbeOutcome>, bool) {
        let called = Cell::new(false);
        let r = resolve_probe(opened, denied, || {
            called.set(true);
            present
        });
        (r, called.get())
    }

    #[test]
    fn opened_is_found_without_enumerating() {
        let (r, called) = run(true, false, Ok(true));
        assert_eq!(r.unwrap(), ProbeOutcome::Found);
        assert!(!called);
    }

    #[test]
    fn not_denied_is_absent_without_enumerating() {
        let (r, called) = run(false, false, Ok(true));
        assert_eq!(r.unwrap(), ProbeOutcome::Absent);
        assert!(!called);
    }

    #[test]
    fn denied_and_present_is_inaccessible() {
        let (r, called) = run(false, true, Ok(true));
        assert_eq!(r.unwrap(), ProbeOutcome::Inaccessible);
        assert!(called);
    }

    #[test]
    fn denied_and_absent_is_absent() {
        let (r, called) = run(false, true, Ok(false));
        assert_eq!(r.unwrap(), ProbeOutcome::Absent);
        assert!(called);
    }

    #[test]
    fn denied_with_enumeration_error_propagates() {
        let err = crate::Error::platform(crate::ErrorCode::Internal, "boom".to_string());
        let (r, _) = run(false, true, Err(err));
        assert!(r.is_err());
    }
}
