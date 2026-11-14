//! Fuzz target: arbitrary bytes → the two `podman inspect` parsers of the OCI config verifier
//! (Task 14, #15, RT-SUP-04; security review). `ImageConfig::parse` reads an image's `Config`,
//! which a third-party image supplies; `ContainerPaths::parse` reads the container's paths.
//! The first byte picks the parser (even: image, odd: container); the rest is its input.
//!
//! Invariants: never panics; input over the bound is refused; a mismatch is printable ASCII
//! within its caps (it goes to the audit log); accepted container paths lie under the id's
//! userdata directories.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use sallyd::sandbox::oci::Mismatch;
use sallyd::sandbox::oci::facts::{ContainerPaths, ImageConfig, MAX_INSPECT};

fn printable(m: &Mismatch) {
    for part in [&m.field, &m.why] {
        assert!(part.bytes().all(|b| (0x20..0x7f).contains(&b)), "not printable: {part:?}");
        assert!(part.len() <= 200, "over the cap: {}", part.len());
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, input)) = data.split_first() else {
        return;
    };
    let id = "c".repeat(64);
    let over = input.len() > MAX_INSPECT;
    if pick % 2 == 0 {
        match ImageConfig::parse(input) {
            Ok(_) => assert!(!over, "over the bound"),
            Err(m) => printable(&m),
        }
    } else {
        match ContainerPaths::parse(input, &id) {
            Ok(p) => {
                assert!(!over, "over the bound");
                assert_eq!(p.id, id);
                assert!(p.config.contains(&id), "config outside the id: {}", p.config);
            }
            Err(m) => printable(&m),
        }
    }
});
