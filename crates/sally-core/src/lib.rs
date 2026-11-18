//! Pure, trust-critical logic for Sallyport: manifest, secrets, audit, model-file checks.
//!
//! No sandbox or network I/O lives here; policy decisions are pure functions so they can be
//! unit-tested without containers.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod config;
pub mod fd;
mod fsutil;
pub mod hf;
pub mod library;
pub mod manifest;
pub mod model;
pub mod paths;
pub mod secrets;
pub mod text;
