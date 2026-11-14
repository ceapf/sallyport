//! `sally`, the command-line client of `sallyd` (Task 12; architect Q78, Q80). The session and
//! approval commands talk to `control.sock` only, and print nothing from the daemon that has
//! not passed the clean-check ([`clean`]). `doctor`, `manifest`, `audit` and `secrets` run here
//! without `sallyd` ([`doctor`], [`local`], [`secrets`]; architect Q52, Q106–Q110), reading and
//! writing only the user's own files.
//!
//! The binary (`main.rs`) parses arguments and calls one command here; every command takes the
//! client (if any) and the writers it prints to, so each is tested without a terminal. A
//! command line that does not parse gets fixed text ([`usage`]).
#![forbid(unsafe_code)]

pub mod approve;
pub mod clean;
pub mod client;
pub mod commands;
pub mod doctor;
pub mod local;
pub mod secrets;
pub mod usage;

/// The command did what was asked.
pub const EXIT_OK: u8 = 0;
/// `sallyd` refused, or something was not shown (a cut list, text that failed the
/// clean-check), or a prompt was denied because the terminal closed. Locally: an invalid
/// manifest, a refused or cancelled secret value, an absent secret name, a failed doctor check,
/// or an audit log that failed verification or holds lines that are not entries.
pub const EXIT_REFUSED: u8 = 1;
/// `sallyd` could not be reached or spoke out of turn, or the command could not run at all: a
/// command line that does not parse, a file, store, log, terminal or stdin that cannot be read
/// or written, a doctor fact that cannot be read.
pub const EXIT_FAILED: u8 = 2;
