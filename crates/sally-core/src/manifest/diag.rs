//! Diagnostics: every manifest error/warning names the field path and carries a stable code.

use std::fmt;

/// Stable, documented diagnostic codes (MANIFEST_SPEC §4). Tests and the UI match on these,
/// never on message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// Input exceeds the size cap.
    TooLarge,
    /// Not valid YAML, or YAML features manifests do not allow (anchors, aliases, tags,
    /// duplicate keys, multiple documents).
    Syntax,
    /// Wrong shape: unknown field, missing field, wrong type, unknown enum value.
    Schema,
    /// A string has the wrong format.
    InvalidValue,
    /// A number, size, or duration is outside its allowed range.
    OutOfRange,
    /// A mount host path is, is inside, or contains a denylisted path.
    Denylisted,
    /// A mount host path is itself a symlink.
    IsSymlink,
    /// A mount host path is not a directory.
    NotDirectory,
    /// A mount host path does not exist.
    NotFound,
    /// A path contains characters that cannot be passed safely to the container runtime.
    PathChars,
    /// A guest path is not a clean path under `/workspace/`.
    GuestPath,
    /// A list entry repeats an earlier one.
    Duplicate,
    /// Two mounts overlap (host or guest side).
    Overlap,
    /// `runtime.image` is not pinned by digest.
    NotPinned,
    /// A hostname or host pattern is malformed or too broad.
    BadHost,
    /// An IP literal was used where only hostnames are allowed (SI-9).
    IpLiteral,
    /// A wildcard was used where an exact hostname is required.
    NotExactHost,
    /// `host: "*"` without `acknowledge_unrestricted_egress: true`.
    UnacknowledgedWildcard,
    /// A setting requires `network.mode: proxy`.
    NetworkDisabled,
    /// A referenced secret is not in the secrets store.
    SecretMissing,
    /// A secret's injection host has no exact `network.allow` rule.
    SecretHostNotAllowed,
    /// An MCP env var name looks like it carries a secret.
    SecretLikeEnv,
    /// An injection header name is malformed or reserved.
    BadHeader,
    /// An injection format lacks exactly one `{value}` or contains control characters.
    BadFormat,
    /// A mount root changed between validation and launch (RT-FS-06).
    MountChanged,
    /// A risky setting that needs its `acknowledge_*` flag (SI-5: widening is always explicit).
    UnacknowledgedRisk,
    /// A writable mount is or is inside git metadata the host executes (`.git`, hooks, config).
    /// Also the broker's `fs_write`/`fs_delete` denial code for protected paths (AMENDMENTS §6.3).
    ProtectedPath,
    /// A mount tree contains a Unix socket. Emitted by the bounded launch-time scan (sandbox
    /// driver), not by validation.
    SocketInMount,
    /// A plain-HTTP request to a host with a secret grant. No longer emitted: the egress proxy
    /// refuses every plain-HTTP request 405 `plain-http-unsupported` before policy (Task 9a-2).
    // TODO(#59): the maintainer decides whether this code and its gate row are deleted.
    InjectRequiresTls,
    /// Private data (a mount or secret) and an outward channel (an allow rule) coexist
    /// (warning; AMENDMENTS §5).
    DataCanLeave,
    /// Settings that contradict each other or have no effect (warnings).
    Inconsistent,
    /// An effective-but-risky setting (warnings).
    Risky,
}

impl Code {
    /// The stable kebab-case spelling, e.g. `denylisted`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too-large",
            Self::Syntax => "syntax",
            Self::Schema => "schema",
            Self::InvalidValue => "invalid-value",
            Self::OutOfRange => "out-of-range",
            Self::Denylisted => "denylisted",
            Self::IsSymlink => "is-symlink",
            Self::NotDirectory => "not-directory",
            Self::NotFound => "not-found",
            Self::PathChars => "path-chars",
            Self::GuestPath => "guest-path",
            Self::Duplicate => "duplicate",
            Self::Overlap => "overlap",
            Self::NotPinned => "not-pinned",
            Self::BadHost => "bad-host",
            Self::IpLiteral => "ip-literal",
            Self::NotExactHost => "not-exact-host",
            Self::UnacknowledgedWildcard => "unacknowledged-wildcard",
            Self::NetworkDisabled => "network-disabled",
            Self::SecretMissing => "secret-missing",
            Self::SecretHostNotAllowed => "secret-host-not-allowed",
            Self::SecretLikeEnv => "secret-like-env",
            Self::BadHeader => "bad-header",
            Self::BadFormat => "bad-format",
            Self::MountChanged => "mount-changed",
            Self::UnacknowledgedRisk => "unacknowledged-risk",
            Self::ProtectedPath => "protected-path",
            Self::SocketInMount => "socket-in-mount",
            Self::InjectRequiresTls => "inject-requires-tls",
            Self::DataCanLeave => "data-can-leave",
            Self::Inconsistent => "inconsistent",
            Self::Risky => "risky",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error or warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Severity {
    /// The manifest is rejected.
    Error,
    /// The manifest is accepted; the user should look at this.
    Warning,
}

/// One finding about a manifest. Constructed only inside this crate, always scrubbed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diagnostic {
    /// Error or warning.
    pub severity: Severity,
    /// Field path, e.g. `filesystem.mounts[0].host`; empty for whole-document problems.
    pub path: String,
    /// Stable code.
    pub code: Code,
    /// Human-readable explanation.
    pub message: String,
}

impl Diagnostic {
    /// Every diagnostic goes through here: path and message become single-line, bounded, and
    /// token-looking quoted values are masked, so diagnostics are safe for the UI and the audit
    /// log even when the user pasted a secret into the wrong field.
    fn new(severity: Severity, path: String, code: Code, message: &str) -> Self {
        Self {
            severity,
            path: scrub_path(&path),
            code,
            message: scrub(message),
        }
    }
}

/// Longest diagnostic text kept, in characters.
const MAX_TEXT: usize = 300;
/// Quoted spans at least this long that look like tokens are masked.
const TOKEN_MIN: usize = 20;

/// Single-line, bounded, token-masked.
pub(crate) fn scrub(s: &str) -> String {
    let flat: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let masked = mask_quoted(&flat);
    match masked.char_indices().nth(MAX_TEXT) {
        Some((i, _)) => format!("{}…", masked.get(..i).unwrap_or_default()),
        None => masked,
    }
}

/// Paths can contain user-supplied keys (an unknown field's name is its last segment), so
/// token-looking segments are masked too.
fn scrub_path(path: &str) -> String {
    let flat = scrub(path);
    flat.split('.')
        .map(|seg| {
            if looks_like_token(without_index(seg)) {
                let head: String = seg.chars().take(4).collect();
                format!("{head}…")
            } else {
                seg.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Replaces the body of any `"…"` or `` `…` `` span that looks like a credential (long, no
/// spaces or slashes, contains a digit) with its first 4 characters and a length.
fn mask_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(open) = rest.find(['"', '`']) {
        let (before, from_quote) = rest.split_at(open);
        out.push_str(before);
        let mut chars = from_quote.chars();
        let Some(q) = chars.next() else { break };
        let body_and_after = chars.as_str();
        let Some(close) = body_and_after.find(q) else {
            out.push_str(from_quote);
            return out;
        };
        let (body, after) = body_and_after.split_at(close);
        out.push(q);
        if looks_like_token(body) {
            let head: String = body.chars().take(4).collect();
            out.push_str(&format!("{head}…[{} chars hidden]", body.chars().count()));
        } else {
            out.push_str(body);
        }
        out.push(q);
        rest = after.get(q.len_utf8()..).unwrap_or_default();
    }
    out.push_str(rest);
    out
}

/// A path segment without a trailing list index (`acknowledge_unapproved[12]` →
/// `acknowledge_unapproved`), so the index's digits do not make a long field name look like a
/// token. Only an all-digit index is removed: a user key such as `x[<token>]` is judged whole.
/// A list index this long is not a real index (lists are bounded far below it); a longer digit
/// run stays part of the segment and is masked like any other token.
const MAX_INDEX_DIGITS: usize = 4;

fn without_index(seg: &str) -> &str {
    match seg.strip_suffix(']').and_then(|s| s.rsplit_once('[')) {
        Some((name, idx))
            if (1..=MAX_INDEX_DIGITS).contains(&idx.len())
                && idx.bytes().all(|b| b.is_ascii_digit()) =>
        {
            name
        }
        _ => seg,
    }
}

/// Long, no spaces or slashes, and containing a digit. Field names (which can be long, e.g.
/// `acknowledge_unrestricted_egress`) never contain digits; 20+ character credentials do.
fn looks_like_token(body: &str) -> bool {
    body.chars().count() >= TOKEN_MIN
        && !body.contains(['/', ' ', '\\'])
        && body.chars().any(|c| c.is_ascii_digit())
}

impl fmt::Display for Diagnostic {
    /// `error: filesystem.mounts[0].host: "~/" is the home directory root [denylisted]`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sev = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        if self.path.is_empty() {
            write!(f, "{sev}: {} [{}]", self.message, self.code)
        } else {
            write!(f, "{sev}: {}: {} [{}]", self.path, self.message, self.code)
        }
    }
}

/// A manifest that failed to load or validate. Always has at least one error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error("manifest rejected with {} error(s)", errors.len())]
pub struct Rejected {
    /// At least one error.
    pub errors: Vec<Diagnostic>,
    /// Warnings found before rejection (may be empty).
    pub warnings: Vec<Diagnostic>,
}

impl Rejected {
    pub(crate) fn single(path: impl Into<String>, code: Code, message: impl Into<String>) -> Self {
        Self {
            errors: vec![Diagnostic::new(
                Severity::Error,
                path.into(),
                code,
                &message.into(),
            )],
            warnings: Vec::new(),
        }
    }
}

/// Collects diagnostics during validation.
#[derive(Debug, Default)]
pub(crate) struct Diags {
    errors: Vec<Diagnostic>,
    warnings: Vec<Diagnostic>,
}

impl Diags {
    pub(crate) fn error(&mut self, path: impl Into<String>, code: Code, msg: impl Into<String>) {
        let d = Diagnostic::new(Severity::Error, path.into(), code, &msg.into());
        self.errors.push(d);
    }

    pub(crate) fn warn(&mut self, path: impl Into<String>, code: Code, msg: impl Into<String>) {
        let d = Diagnostic::new(Severity::Warning, path.into(), code, &msg.into());
        self.warnings.push(d);
    }

    /// `Ok(warnings)` if no errors were recorded.
    pub(crate) fn finish(self) -> Result<Vec<Diagnostic>, Rejected> {
        if self.errors.is_empty() {
            Ok(self.warnings)
        } else {
            Err(Rejected {
                errors: self.errors,
                warnings: self.warnings,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_masks_token_like_quoted_values() {
        // Token-shaped values are assembled from parts so no source literal matches a real
        // credential format (secret scanners and the repository's guard hooks).
        let gh = ["gh", "p_"].concat();
        let sk = ["s", "k-"].concat();
        let m = scrub(&format!(
            "invalid value: string \"{gh}0123456789abcdefghijABCDEF\", expected x"
        ));
        assert_eq!(
            m,
            format!("invalid value: string \"{gh}…[30 chars hidden]\", expected x")
        );
        let m = scrub(&format!(
            "unknown field `{sk}proj-abcdefghij0123456789`, expected one of a"
        ));
        assert!(m.contains(&format!("`{sk}p…[28 chars hidden]`")), "{m}");
    }

    #[test]
    fn scrub_keeps_paths_hosts_and_short_values() {
        for s in [
            "\"/home/u/code/myproject-2024/very/long/path\" is not a directory",
            "\"files.pythonhosted.org\" needs its own exact entry",
            "\"8GB\" bad",
            "unterminated \"quote",
        ] {
            assert_eq!(scrub(s), s);
        }
    }

    #[test]
    fn scrub_flattens_and_bounds() {
        assert_eq!(scrub("a\nb\tc"), "a b c");
        assert_eq!(scrub(&"x".repeat(1000)).chars().count(), MAX_TEXT + 1);
    }

    #[test]
    fn list_indices_do_not_make_long_field_names_look_like_tokens() {
        assert_eq!(
            scrub_path("tools.acknowledge_unapproved[1]"),
            "tools.acknowledge_unapproved[1]"
        );
        assert_eq!(
            scrub_path("network.acknowledge_unrestricted_egress[123]"),
            "network.acknowledge_unrestricted_egress[123]"
        );
        let tok = ["gh", "p_", "abcdefghij0123456789xyz"].concat();
        // A token-like key stays masked, with or without an index-looking suffix.
        assert_eq!(scrub_path(&format!("tools.{tok}")), "tools.ghp_…");
        assert_eq!(scrub_path(&format!("tools.{tok}[0]")), "tools.ghp_…");
        assert_eq!(scrub_path(&format!("tools.x[{tok}]")), "tools.x[gh…");
        // A long digit run is not an index: it is masked with its segment.
        let digits = "1234567890123456789012";
        assert_eq!(scrub_path(&format!("tools.x[{digits}]")), "tools.x[12…");
        assert_eq!(
            scrub_path(&format!("tools.acknowledge_unapproved[{digits}]")),
            "tools.ackn…"
        );
    }
}
