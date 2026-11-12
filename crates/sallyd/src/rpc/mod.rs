//! The broker's JSON-RPC surface (Task 7): newline-delimited JSON-RPC 2.0 over Unix stream
//! sockets. `agent.sock` serves the MCP subset of AMENDMENTS-01 §3.1 to the untrusted harness.

pub mod agent;
pub mod control;
pub mod frame;
pub mod json;
pub mod listen;
pub mod mcp;
pub mod message;
pub mod rate;
pub mod record;

#[cfg(test)]
pub(crate) mod testkit;
