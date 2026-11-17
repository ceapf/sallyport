#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeSet;

use super::detect::DetectError;
use super::gguf::error::tests::every_variant;

/// A refusal code means one thing across the model module: the only code detect and the GGUF
/// parser share is `magic_mismatch`, which means the same in both (the first bytes are not the
/// format's magic).
#[test]
fn detect_and_gguf_codes_do_not_collide() {
    let detect: BTreeSet<&str> = [DetectError::FormatNotAllowed, DetectError::MagicMismatch]
        .into_iter()
        .map(DetectError::code)
        .collect();
    let gguf: BTreeSet<&str> = every_variant().iter().map(|(e, _)| e.code()).collect();
    let shared: Vec<&str> = detect.intersection(&gguf).copied().collect();
    assert_eq!(shared, ["magic_mismatch"]);
}
