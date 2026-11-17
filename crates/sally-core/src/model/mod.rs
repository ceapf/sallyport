//! Model files (SI-6): which format a file is ([`detect`]) and the strict parser for it
//! ([`gguf`]). A file reaches an engine only after the extension allowlist, the magic, the strict
//! header parse and its SHA-256; these are the first three.

pub mod detect;
pub mod gguf;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
