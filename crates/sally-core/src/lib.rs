//! Pure, trust-critical logic for Sallyport: manifest, secrets, audit.
//!
//! No sandbox or network I/O lives here; policy decisions are pure functions so they can be
//! unit-tested without containers.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod config;
pub mod manifest;
