//! `llm.sock`: the OpenAI-compatible endpoint the harness talks to (ARCHITECTURE §4.4, Task 7).

pub mod body;
pub mod head;
pub mod io;
pub mod reply;
pub mod server;

#[cfg(test)]
mod probe_tests;
