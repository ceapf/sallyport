//! `secrets[]` and `tools.mcp[]` checks: everything that could carry a credential.

use std::collections::{HashMap, HashSet};

use super::super::diag::{Code, Diags};
use super::super::host::{HostPattern, parse_hostname};
use super::super::types::{Manifest, McpServer, NetworkMode, SecretGrant};
use super::net::host_error;
use super::rest::is_slug;
use super::{EgressRule, SecretCatalog};
use crate::secrets::is_secret_name;

/// Headers the proxy owns (framing, hop-by-hop, routing). Injecting a secret into these could
/// break request framing or redirect the request. Every `Proxy-*` header is refused as well.
/// `Cookie` is allowed.
const RESERVED_HEADERS: [&str; 12] = [
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "expect",
    "proxy-authorization",
    "proxy-authenticate",
    "proxy-connection",
];

pub(super) fn check_secrets(
    m: &Manifest,
    egress: &[EgressRule],
    catalog: &dyn SecretCatalog,
    d: &mut Diags,
) {
    if !m.secrets.is_empty() && m.network.mode == NetworkMode::None {
        d.error(
            "secrets",
            Code::NetworkDisabled,
            "secrets are injected by the proxy; set network.mode: proxy",
        );
    }
    // One grant per (secret, host); one secret per (host, header); one secret per exposed name.
    let mut grants = HashSet::new();
    let mut targets = HashSet::new();
    let mut exposed: HashMap<&str, &str> = HashMap::new();
    for (i, s) in m.secrets.iter().enumerate() {
        let at = |f: &str| format!("secrets[{i}].{f}");
        check_secret_name(s, &at("name"), catalog, d);
        check_inject_host(s, &at("inject.host"), m.network.mode, egress, d);
        // A malformed name is not echoed anywhere (it is the likeliest place for a pasted
        // value), so the duplicate checks that would echo it are skipped.
        let name_ok = is_secret_name(&s.name);
        if name_ok && !grants.insert((s.name.as_str(), s.inject.host.as_str())) {
            d.error(
                at("inject.host"),
                Code::Duplicate,
                format!("{:?} is already granted toward this host", s.name),
            );
        }
        if let Err(msg) = check_header(&s.inject.header) {
            d.error(at("inject.header"), Code::BadHeader, msg);
        }
        check_scheme(s, i, d);
        let target = (s.inject.host.as_str(), s.inject.header.to_ascii_lowercase());
        if !targets.insert(target) {
            d.error(
                at("inject"),
                Code::Duplicate,
                "another secret already injects this header for this host",
            );
        }
        if let Some(env) = &s.expose_env {
            check_expose_env(env, &at("expose_env"), d);
            if !name_ok {
                continue;
            }
            match exposed.insert(env.as_str(), s.name.as_str()) {
                Some(prev) if prev != s.name => d.error(
                    at("expose_env"),
                    Code::Duplicate,
                    format!("{env:?} is already exposed for {prev:?}"),
                ),
                Some(_) | None => {}
            }
        }
    }
}

fn check_secret_name(s: &SecretGrant, path: &str, catalog: &dyn SecretCatalog, d: &mut Diags) {
    if !is_secret_name(&s.name) {
        // Not echoed: a malformed "name" is the likeliest place for a pasted value.
        d.error(path, Code::InvalidValue, "must match [A-Z][A-Z0-9_]{0,63}");
    } else if !catalog.contains(&s.name) {
        d.error(
            path,
            Code::SecretMissing,
            format!(
                "{0:?} is not in the secrets store (sally secrets set {0})",
                s.name
            ),
        );
    }
}

/// `format` holds exactly one of `{value}` / `{basic}`; `{basic}` needs `basic_user`.
fn check_scheme(s: &SecretGrant, i: usize, d: &mut Diags) {
    let at = |f: &str| format!("secrets[{i}].inject.{f}");
    let format = &s.inject.format;
    if let Err(msg) = check_format(format) {
        d.error(at("format"), Code::BadFormat, msg);
    }
    let basic = format.contains(BASIC_PLACEHOLDER);
    match (&s.inject.basic_user, basic) {
        (None, true) => d.error(
            at("basic_user"),
            Code::InvalidValue,
            "required when format uses {basic} (e.g. x-access-token for git over HTTPS)",
        ),
        (Some(_), false) => d.error(
            at("basic_user"),
            Code::InvalidValue,
            "only allowed when format uses {basic}",
        ),
        (Some(user), true) => {
            if let Err(msg) = check_basic_user(user) {
                d.error(at("basic_user"), Code::InvalidValue, msg);
            }
        }
        (None, false) => {}
    }
}

/// RFC 7617 user-id: no `:`, no control characters, not a credential. Not echoed.
fn check_basic_user(u: &str) -> Result<(), &'static str> {
    if u.is_empty() || u.len() > MAX_BASIC_USER {
        return Err("must be 1–256 bytes");
    }
    if looks_like_credential(u) {
        return Err("looks like a credential; put it in the secrets store, never the manifest");
    }
    if u.contains(':') || u.chars().any(char::is_control) {
        return Err("must not contain ':' or control characters");
    }
    Ok(())
}

/// The placeholder name must look like a token variable and must not be one Sallyport sets or
/// one that changes how programs load code, find sockets, or verify TLS. Its value is a public
/// constant, so the remaining risk is a program reading the placeholder as configuration.
fn check_expose_env(name: &str, path: &str, d: &mut Diags) {
    if !is_env_name(name) || !is_token_env_name(name) || is_reserved_env(name) {
        d.error(
            path,
            Code::InvalidValue,
            "must be a token-style variable name such as GITHUB_TOKEN (not SALLY_*, LD_*, or a \
             proxy/CA variable)",
        );
    }
}

fn check_inject_host(
    s: &SecretGrant,
    path: &str,
    mode: NetworkMode,
    egress: &[EgressRule],
    d: &mut Diags,
) {
    match parse_hostname(&s.inject.host) {
        Err(e) => host_error(d, path.to_owned(), &s.inject.host, e),
        Ok(h)
            if mode == NetworkMode::Proxy
                && !egress
                    .iter()
                    .any(|r| r.host == HostPattern::Exact(h.clone())) =>
        {
            d.error(
                path,
                Code::SecretHostNotAllowed,
                format!("{h:?} needs its own exact entry in network.allow"),
            );
        }
        Ok(_) => {}
    }
}

/// RFC 9110 `token`, at most 64 bytes, not reserved.
fn check_header(h: &str) -> Result<(), String> {
    let tchar = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
    if h.is_empty() || h.len() > 64 || !h.bytes().all(tchar) {
        return Err("not a valid header name (RFC 9110 token, at most 64 bytes)".into());
    }
    let lower = h.to_ascii_lowercase();
    if RESERVED_HEADERS.contains(&lower.as_str()) || lower.starts_with("proxy-") {
        return Err(format!("{h:?} is reserved for the proxy"));
    }
    Ok(())
}

const VALUE_PLACEHOLDER: &str = "{value}";
const BASIC_PLACEHOLDER: &str = "{basic}";
const MAX_BASIC_USER: usize = 256;
/// Env names a placeholder may never take (compared case-insensitively): Sallyport's own
/// variables, the dynamic loader, git config injection, and anything proxy-, CA- or
/// socket-related (`sallyd` sets the proxy and CA variables itself: ARCHITECTURE §3, §7).
const RESERVED_ENV_PREFIXES: [&str; 3] = ["SALLY_", "LD_", "GIT_CONFIG"];
const RESERVED_ENV_SUBSTRINGS: [&str; 5] = ["PROXY", "CA_BUNDLE", "CAINFO", "CERT", "SOCK"];
const RESERVED_ENV_NAMES: [&str; 9] = [
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "NODE_TLS_REJECT_UNAUTHORIZED",
    "PYTHONHTTPSVERIFY",
    "GIT_SSL_NO_VERIFY",
    "CURL_HOME",
];

/// Last segment names a token (`GH_TOKEN`, `OPENAI_API_KEY`); no segment names a file, path,
/// or config (`GOOGLE_APPLICATION_CREDENTIALS`, `AWS_SHARED_CREDENTIALS_FILE`): a repo could ship a
/// file named after the placeholder and have it loaded as credentials or config.
fn is_token_env_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    let segs: Vec<&str> = up.split('_').filter(|s| !s.is_empty()).collect();
    let last_ok = segs
        .last()
        .is_some_and(|l| TOKEN_ENV_LAST_SEGMENTS.contains(l));
    let no_path = !segs.iter().any(|s| PATHLIKE_ENV_SEGMENTS.contains(s));
    let no_prefix = !TOKEN_ENV_FORBIDDEN_PREFIXES
        .iter()
        .any(|p| up.starts_with(p));
    last_ok && no_path && no_prefix
}

const TOKEN_ENV_LAST_SEGMENTS: [&str; 6] = ["TOKEN", "KEY", "APIKEY", "PAT", "SECRET", "PASSWORD"];
const PATHLIKE_ENV_SEGMENTS: [&str; 6] = ["FILE", "PATH", "DIR", "CONFIG", "CREDENTIALS", "HOME"];
const TOKEN_ENV_FORBIDDEN_PREFIXES: [&str; 3] = ["NPM_CONFIG_", "GIT_", "SSH_"];

fn is_reserved_env(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    RESERVED_ENV_PREFIXES.iter().any(|p| up.starts_with(p))
        || RESERVED_ENV_SUBSTRINGS.iter().any(|p| up.contains(p))
        || RESERVED_ENV_NAMES.contains(&up.as_str())
}

fn check_format(f: &str) -> Result<(), String> {
    if f.len() > 1024 {
        return Err("format is longer than 1024 bytes".into());
    }
    if f.chars().any(char::is_control) {
        return Err("format contains a control character (CR/LF would split the header)".into());
    }
    if looks_like_credential(f) {
        // Not echoed.
        return Err(
            "format contains what looks like a credential; only {value}/{basic} may carry it"
                .into(),
        );
    }
    match f.matches(VALUE_PLACEHOLDER).count() + f.matches(BASIC_PLACEHOLDER).count() {
        1 => Ok(()),
        n => Err(format!(
            "exactly one of {{value}} or {{basic}} must appear (found {n})"
        )),
    }
}

/// `_`-delimited name segments that mark a credential (case-insensitive). Matching whole
/// segments keeps `AUTHOR_NAME` and `KEYBOARD_LAYOUT` usable while refusing `GH_AUTH`.
/// False positives are acceptable: the remedy (secret injection) is always available.
const SECRET_ENV_SEGMENTS: [&str; 20] = [
    "TOKEN",
    "KEY",
    "KEYS",
    "KEYFILE",
    "APIKEY",
    "SECRET",
    "SECRETS",
    "PASS",
    "PASSWD",
    "PASSWORD",
    "PASSPHRASE",
    "PWD",
    "PAT",
    "CREDENTIAL",
    "CREDENTIALS",
    "CREDS",
    "AUTH",
    "BEARER",
    "COOKIE",
    "PRIVATE",
];
/// Segment suffixes for run-together names (`ACCESSTOKEN`, `CLIENTSECRET`, `DBPASSWORD`).
const SECRET_ENV_SEGMENT_SUFFIXES: [&str; 4] = ["TOKEN", "KEY", "SECRET", "PASSWORD"];
/// Value prefixes of well-known credential formats.
const SECRET_VALUE_PREFIXES: [&str; 12] = [
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
    "xox",
    "AKIA",
    "ASIA",
    "hf_",
];
/// Any whitespace/comma-separated word starts with a known credential prefix.
fn looks_like_credential(s: &str) -> bool {
    s.split(|c: char| c.is_whitespace() || c == ',')
        .any(|w| SECRET_VALUE_PREFIXES.iter().any(|p| w.starts_with(p)))
}

const MAX_MCP: usize = 32;
const MAX_ARGS: usize = 256;
const MAX_ARG_LEN: usize = 4096;

pub(super) fn check_mcp(servers: &[McpServer], d: &mut Diags) {
    if servers.len() > MAX_MCP {
        d.error(
            "tools.mcp",
            Code::OutOfRange,
            format!("at most {MAX_MCP} servers"),
        );
        return;
    }
    let mut names = HashSet::new();
    for (i, s) in servers.iter().enumerate() {
        let at = |f: &str| format!("tools.mcp[{i}].{f}");
        if !is_slug(&s.name) {
            d.error(at("name"), Code::InvalidValue, "must match [a-z0-9-]{1,64}");
        } else if !names.insert(s.name.as_str()) {
            d.error(
                at("name"),
                Code::Duplicate,
                format!("{:?} is listed twice", s.name),
            );
        }
        check_command(s, i, d);
        check_env(s, i, d);
    }
}

fn check_command(s: &McpServer, i: usize, d: &mut Diags) {
    if s.command.is_empty() || s.command.len() > MAX_ARGS {
        let msg = format!("command must have 1–{MAX_ARGS} elements");
        d.error(format!("tools.mcp[{i}].command"), Code::InvalidValue, msg);
    }
    for (j, arg) in s.command.iter().enumerate() {
        if arg.contains('\0') || arg.len() > MAX_ARG_LEN {
            let path = format!("tools.mcp[{i}].command[{j}]");
            d.error(
                path,
                Code::InvalidValue,
                "argument has a NUL byte or is too long",
            );
        }
    }
}

fn check_env(s: &McpServer, i: usize, d: &mut Diags) {
    const ADVICE: &str = "grant secrets via `secrets:` injection, never env";
    for (k, v) in &s.env {
        if !is_env_name(k) {
            // Quoted index form so a hostile key cannot inject text into the path.
            let path = format!("tools.mcp[{i}].env[{k:?}]");
            d.error(
                path,
                Code::InvalidValue,
                "not a valid environment variable name",
            );
            continue;
        }
        let path = format!("tools.mcp[{i}].env.{k}");
        if is_reserved_env(k) {
            d.error(
                path,
                Code::InvalidValue,
                format!(
                    "{k:?} changes how the workspace loads code, finds sockets, or verifies TLS; \
                     Sallyport sets these itself"
                ),
            );
        } else if is_secret_like_name(k) {
            d.error(
                path,
                Code::SecretLikeEnv,
                format!("{k:?} is a secret-like env name; {ADVICE}"),
            );
        } else if SECRET_VALUE_PREFIXES
            .iter()
            .any(|p| v.trim_start().starts_with(p))
        {
            // Never echo the value.
            d.error(
                path,
                Code::SecretLikeEnv,
                format!("value looks like a credential; {ADVICE}"),
            );
        } else if v.contains('\0') || v.len() > MAX_ARG_LEN {
            d.error(
                path,
                Code::InvalidValue,
                "value has a NUL byte or is too long",
            );
        }
    }
}

fn is_env_name(k: &str) -> bool {
    let mut b = k.bytes();
    k.len() <= 128
        && b.next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn is_secret_like_name(k: &str) -> bool {
    let up = k.to_ascii_uppercase();
    // A bare `PWD` is the shell's working directory, not a password.
    if up == "PWD" {
        return false;
    }
    up.split('_').any(|seg| {
        SECRET_ENV_SEGMENTS.contains(&seg)
            || SECRET_ENV_SEGMENT_SUFFIXES
                .iter()
                .any(|sfx| seg.ends_with(sfx))
    })
}
