//! Model files (SI-6): which format a file is ([`detect`]), the strict parser for it ([`gguf`])
//! and its SHA-256 ([`hash`]). A file reaches an engine only after the extension allowlist, the
//! magic, the strict header parse and its SHA-256; the library's import runs all four.

pub mod detect;
pub mod gguf;
pub mod hash;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
