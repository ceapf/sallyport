//! The `sallyd` broker: sandbox driver, RPC, egress and token proxy, approvals, brokered tools.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod approvals;
pub mod egress;
pub mod llm;
pub mod rpc;
pub mod sandbox;
pub mod tools;
