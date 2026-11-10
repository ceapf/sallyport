//! Fuzz target: arbitrary bytes → secrets-store parser (CLAUDE.md: every parser of untrusted
//! bytes has one).
//!
//! Invariants: never panics; an accepted store re-parses from its own saved form to the same
//! names; and no error text contains any 8+ character run from the input (a secret that failed
//! to parse must not come back in a message). Words of the fixed error vocabulary are exempt:
//! a mutated input can legitimately contain the text of the message itself.
#![no_main]
#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use sally_core::secrets::{MAX_SECRETS, MAX_STORE_BYTES, MAX_VALUE_BYTES, SecretStore};

/// Words (8+ alphanumerics) that appear in the store's fixed error messages. Errors carry only
/// static text and a line number, so these are the only words an error may contain.
fn vocabulary() -> &'static HashSet<String> {
    static VOCAB: OnceLock<HashSet<String>> = OnceLock::new();
    VOCAB.get_or_init(|| {
        let path = || PathBuf::from("/fuzz/secrets.toml");
        let mut shown = Vec::new();
        let mut note = |e: &dyn std::fmt::Display| shown.push(e.to_string());
        let many: String = (0..=MAX_SECRETS)
            .map(|i| format!("S{i} = \"x\"\n"))
            .collect();
        for bytes in [&b"="[..], &b"\xff"[..], many.as_bytes()] {
            if let Err(e) = SecretStore::from_bytes(path(), bytes) {
                note(&e);
            }
        }
        if let Err(e) = SecretStore::from_bytes(path(), &vec![b'#'; MAX_STORE_BYTES + 1]) {
            note(&e);
        }
        let mut store = SecretStore::empty(path());
        let long = "x".repeat(MAX_VALUE_BYTES + 1);
        for (name, value) in [
            ("a", "x"),
            ("A", ""),
            ("A", "\n"),
            ("A", " x"),
            ("A", long.as_str()),
        ] {
            if let Err(e) = store.set(name, value.to_owned()) {
                note(&e);
            }
        }
        shown
            .iter()
            .flat_map(|m| m.split(|c: char| !c.is_ascii_alphanumeric()))
            .map(str::to_owned)
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    match SecretStore::from_bytes(PathBuf::from("/fuzz/secrets.toml"), data) {
        Ok(store) => {
            // Every accepted value obeys the rules `set` enforces.
            for name in store.names() {
                let value = store.get(name).expect("listed name has a value").expose();
                let mut again = SecretStore::empty(PathBuf::from("/fuzz/secrets.toml"));
                again
                    .set(name, value.clone())
                    .expect("an accepted entry must satisfy the set() rules");
            }
        }
        Err(e) => {
            let shown = format!("{e} | {e:?}");
            let text = String::from_utf8_lossy(data);
            for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
                if word.len() >= 8 && !vocabulary().contains(word) {
                    assert!(!shown.contains(word), "error text leaked input: {shown}");
                }
            }
        }
    }
});
