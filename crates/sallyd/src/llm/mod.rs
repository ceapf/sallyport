//! `llm.sock`: the OpenAI-compatible endpoint the harness talks to (ARCHITECTURE §4.4, Task 7).

pub mod body;
pub mod head;
pub(crate) mod io;
pub(crate) mod reply;
pub mod server;

#[cfg(test)]
mod probe_tests;
