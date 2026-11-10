//! YAML → [`Manifest`] with hard resource limits (RT-MAN-01).
//!
//! Manifests use a deliberately small YAML subset: one document, no anchors/aliases/merge keys,
//! no duplicate keys. Everything outside that subset is a `syntax` error, which removes the
//! alias-bomb class entirely instead of budgeting it.
#![deny(clippy::indexing_slicing)]

use serde_saphyr::{Budget, DuplicateKeyPolicy, MergeKeyPolicy, NonFiniteFloatPolicy, Options};

use super::diag::{Code, Rejected};
use super::types::Manifest;

/// Maximum manifest size in bytes. Real manifests are a few KiB.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// Parser limits. Values are far above any legitimate manifest and far below anything that
/// costs measurable time or memory.
fn options() -> Options {
    let mut budget = Budget::default();
    budget.max_events = 50_000;
    budget.max_aliases = 0;
    budget.max_anchors = 0;
    budget.max_depth = 16;
    budget.max_documents = 1;
    budget.max_nodes = 20_000;
    budget.max_reader_input_bytes = Some(MAX_MANIFEST_BYTES);

    let mut opts = Options::default();
    opts.budget = Some(budget);
    opts.duplicate_keys = DuplicateKeyPolicy::Error;
    opts.merge_keys = MergeKeyPolicy::Error;
    opts.with_snippet = false;
    // What you see is what you get: no YAML 1.1 `yes`/`on` booleans, no numbers or booleans
    // where a string is expected, no custom tags, and `!!binary` never decodes into a string.
    opts.strict_booleans = true;
    opts.no_schema = true;
    opts.reject_unsupported_tags = true;
    opts.reject_tagged_field_names = true;
    opts.ignore_binary_tag_for_string = true;
    opts.non_finite_float_policy = NonFiniteFloatPolicy::Reject;
    opts
}

/// Parses manifest bytes. Checks size and UTF-8 before handing anything to the YAML parser.
///
/// # Errors
/// [`Rejected`] with exactly one error: `too-large`, `syntax`, or `schema` (with field path).
pub fn parse_bytes(bytes: &[u8]) -> Result<Manifest, Rejected> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Rejected::single(
            "",
            Code::TooLarge,
            format!(
                "manifest is {} bytes; the limit is {MAX_MANIFEST_BYTES}",
                bytes.len()
            ),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Rejected::single("", Code::Syntax, format!("not UTF-8: {e}")))?;
    parse(text)
}

/// Parses manifest text.
///
/// # Errors
/// [`Rejected`] with exactly one error: `too-large`, `syntax`, or `schema` (with field path).
pub fn parse(text: &str) -> Result<Manifest, Rejected> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(Rejected::single(
            "",
            Code::TooLarge,
            format!(
                "manifest is {} bytes; the limit is {MAX_MANIFEST_BYTES}",
                text.len()
            ),
        ));
    }
    // serde_path_to_error knows the field path of a schema error; serde-saphyr's own error
    // knows the line/column. The closure smuggles the path out alongside the parser error.
    let mut schema_path: Option<String> = None;
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options(), |de| {
        serde_path_to_error::deserialize::<_, Manifest>(de).map_err(|e| {
            schema_path = Some(e.path().to_string());
            e.into_inner()
        })
    });
    result.map_err(|e| {
        let code = if is_syntax_error(&e) {
            Code::Syntax
        } else {
            Code::Schema
        };
        // serde_path_to_error prints the root as "." (or "?" when unknown); any deeper path is kept even for
        // syntax errors (a duplicate key is more useful as `runtime.pids` than as nothing).
        let path = schema_path
            .map(|p| p.trim_end_matches(".?").trim_end_matches('?').to_owned())
            .filter(|p| !p.is_empty() && p != ".")
            .unwrap_or_default();
        Rejected::single(path, code, e.to_string())
    })
}

/// YAML-level and resource-budget failures. Everything else, including any variant a future
/// serde-saphyr adds, counts as a schema error so it keeps its field path.
fn is_syntax_error(e: &serde_saphyr::Error) -> bool {
    use serde_saphyr::Error as E;
    matches!(
        e,
        E::ExternalMessage { .. }
            | E::Eof { .. }
            | E::MultipleDocuments { .. }
            | E::MergeKeyNotAllowed { .. }
            | E::MergeValueNotMapOrSeqOfMaps { .. }
            | E::UnexpectedSequenceEnd { .. }
            | E::UnexpectedMappingEnd { .. }
            | E::UnexpectedContainerEndWhileSkippingNode { .. }
            | E::UnexpectedContainerEndWhileReadingKeyNode { .. }
            | E::ContainerEndMismatch { .. }
            | E::InvalidUtf8Input
            | E::DuplicateMappingKey { .. }
            | E::UnknownAnchor { .. }
            | E::AliasError { .. }
            | E::AliasReplayCounterOverflow { .. }
            | E::AliasReplayLimitExceeded { .. }
            | E::AliasExpansionLimitExceeded { .. }
            | E::AliasReplayStackDepthExceeded { .. }
            | E::FoldedBlockScalarMustIndentContent { .. }
            | E::IndentationError { .. }
            | E::Budget { .. }
            | E::IOError { .. }
            | E::UnsupportedTag { .. }
            | E::TaggedStructFieldName { .. }
    )
}

/// Serializes a manifest to canonical YAML. Parsing the output yields an equal [`Manifest`].
///
/// # Errors
/// Only if the serializer fails, which indicates a bug.
pub fn to_yaml(m: &Manifest) -> Result<String, serde_saphyr::ser::Error> {
    serde_saphyr::to_string(m)
}
