//! Human approval of gated actions (SI-5; ARCHITECTURE §2.1, MANIFEST_SPEC §1.1 and §3; Task 10).

pub mod action;
pub mod glob;
pub mod handler;
pub mod policy;
pub mod queue;
pub mod render;

#[cfg(test)]
mod rt_tests;

pub use handler::{Executor, Gated, Prepared};
pub use queue::{
    Approver, Client, DecideError, Decision, Desk, Gate, Limits, Refusal, Ticket, Withdraw, new,
};
