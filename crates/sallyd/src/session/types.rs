//! Session ids and stop reasons (Task 12, architect Q57).

use std::io;

use crate::sandbox::SessionId;

/// Random bytes in a session id: 64 bits, written as 16 lowercase hex digits.
pub(crate) const ID_BYTES: usize = 8;

/// Why a session ended: the `reason` of its `session.stop` entry. Every `session.start` gets
/// exactly one `session.stop`, with one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A client asked (`sessions.stop`).
    Request,
    /// `runtime.timeout` ran out; `session.timeout` is audited before the kill.
    Timeout,
    /// A session task panicked; `session.crash` is audited first.
    Crash,
    /// `sallyd` is shutting down (SIGTERM, SIGINT).
    Shutdown,
    /// Something after `session.start` failed (the socket bind, the listener).
    StartFailed,
    /// The container ended on its own.
    Exited,
}

impl StopReason {
    /// The audited form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Timeout => "timeout",
            Self::Crash => "crash",
            Self::Shutdown => "shutdown",
            Self::StartFailed => "start-failed",
            Self::Exited => "exited",
        }
    }
}

/// The session id written from `bytes`: lowercase hex, so it always meets
/// [`SessionId::parse`].
#[must_use]
pub(crate) fn id_from(bytes: [u8; ID_BYTES]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The id `scope-<hex>`, or `<hex>` with an empty scope (production; a test fixture scopes
/// its ids so that its cleanup finds its own containers).
#[must_use]
pub(crate) fn scoped_id(scope: &str, bytes: [u8; ID_BYTES]) -> String {
    if scope.is_empty() {
        id_from(bytes)
    } else {
        format!("{scope}-{}", id_from(bytes))
    }
}

/// A fresh session id from the kernel's random source, in `scope`.
///
/// # Errors
/// The `getrandom` error, or [`std::io::ErrorKind::InvalidInput`] when the scope makes the id
/// invalid.
pub fn fresh_id(scope: &str) -> io::Result<SessionId> {
    let mut bytes = [0u8; ID_BYTES];
    // getrandom(2) fills up to 256 bytes in one call once the pool is ready (it blocks until
    // then); a short read is refused rather than looped over.
    let n = rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty())?;
    if n != ID_BYTES {
        return Err(io::Error::other("getrandom returned a short read"));
    }
    SessionId::parse(&scoped_id(scope, bytes))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_has_its_audited_form() {
        let all = [
            (StopReason::Request, "request"),
            (StopReason::Timeout, "timeout"),
            (StopReason::Crash, "crash"),
            (StopReason::Shutdown, "shutdown"),
            (StopReason::StartFailed, "start-failed"),
            (StopReason::Exited, "exited"),
        ];
        for (r, s) in all {
            assert_eq!(r.as_str(), s);
        }
    }

    #[test]
    fn an_id_is_sixteen_hex_digits_and_parses() {
        assert_eq!(
            id_from([0, 1, 0xab, 0xff, 0x10, 0x09, 0x7f, 0x80]),
            "0001abff10097f80"
        );
        let id = fresh_id("").unwrap();
        assert_eq!(id.as_str().len(), 2 * ID_BYTES);
        assert!(SessionId::parse(id.as_str()).is_ok());
    }

    #[test]
    fn a_scope_prefixes_the_id() {
        assert_eq!(scoped_id("t1-2", [0xab; ID_BYTES]), "t1-2-abababababababab");
        assert_eq!(scoped_id("", [0xab; ID_BYTES]), "abababababababab");
        let id = fresh_id("t1-2").unwrap();
        assert!(id.as_str().starts_with("t1-2-"), "{}", id.as_str());
        assert_eq!(id.as_str().len(), "t1-2-".len() + 2 * ID_BYTES);
        for bad in ["-x", "T", &"a".repeat(64)] {
            let e = fresh_id(bad).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{bad}");
        }
    }

    #[test]
    fn fresh_ids_differ() {
        let ids: std::collections::HashSet<String> = (0..64)
            .map(|_| fresh_id("").unwrap().as_str().to_owned())
            .collect();
        assert_eq!(ids.len(), 64);
    }
}
