//! The egress proxy (SI-9; Task 8): one CONNECT-only listener per session, bound to that
//! session's policy. Hostname rules decide; a denied name is never resolved; resolved addresses
//! pass the [`addr`] filter before the proxy connects to the pinned address.

pub mod addr;
pub mod authority;
pub mod ca;
pub mod head;
pub mod hostaddrs;
pub mod net;
pub mod policy;
pub mod roots;
#[cfg(test)]
pub(crate) mod scratch;
pub mod server;
pub mod tunnel;
