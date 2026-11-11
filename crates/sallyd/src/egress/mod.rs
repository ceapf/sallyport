//! The egress proxy (SI-9; Task 8): one CONNECT-only listener per session, bound to that
//! session's policy. Hostname rules decide; a denied name is never resolved; resolved addresses
//! pass the [`addr`] filter before the proxy connects to the pinned address.

pub mod addr;
