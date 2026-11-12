//! `llm.sock`: the OpenAI-compatible endpoint the harness talks to (AMENDMENTS-01 §3.2, Task 7).

pub mod body;
pub mod head;
pub mod io;
pub mod reply;
pub mod server;

#[cfg(test)]
mod probe_tests;
