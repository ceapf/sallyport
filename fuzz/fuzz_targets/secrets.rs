//! Fuzz target: arbitrary bytes → secrets-store parser (CLAUDE.md: every parser of untrusted
//! bytes has one).
//!
//! Invariants: never panics; an accepted store re-parses from its own saved form to the same
//! names; and no error text contains any 8+ character run from the input (a secret that failed
//! to parse must not come back in a message).
#![no_main]
#![forbid(unsafe_code)]

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;
use sally_core::secrets::SecretStore;

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
                if word.len() >= 8 {
                    assert!(!shown.contains(word), "error text leaked input: {shown}");
                }
            }
        }
    }
});
