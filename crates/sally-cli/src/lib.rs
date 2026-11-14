//! `sally`, the command-line client of `sallyd` (Task 12; architect Q78, Q80): it talks to
//! `control.sock` only, and prints nothing from the daemon that has not passed the clean-check
//! ([`clean`]).
//!
//! The binary (`main.rs`) parses arguments and calls one command here; every command takes the
//! client and the writers it prints to, so each is tested without a terminal.
#![forbid(unsafe_code)]

pub mod approve;
pub mod clean;
pub mod client;
pub mod commands;
pub mod doctor;
pub mod local;
pub mod secrets;

/// The command did what was asked.
pub const EXIT_OK: u8 = 0;
/// `sallyd` refused, or something was not shown (a cut list, text that failed the
/// clean-check), or a prompt was denied because the terminal closed.
pub const EXIT_REFUSED: u8 = 1;
/// `sallyd` could not be reached or spoke out of turn, or the command could not run at all.
pub const EXIT_FAILED: u8 = 2;
