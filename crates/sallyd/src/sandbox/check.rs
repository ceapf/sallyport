//! The argv gate (CLAUDE.md hard rules; THREAT_MODEL SI-1, SI-2, SI-11). An **allowlist**: every
//! podman option must be one the builders emit, with a value of the expected shape, and the
//! hardening flags must all be present. An unforeseen flag fails closed instead of slipping past a
//! denylist. The red-team harness also greps argv for the forbidden flags; this is the same rule
//! enforced in-process before anything is launched.

use std::path::{Component, Path};

use super::types::{ArgvError, ImageRef};

/// Options that take a separate value when written without `=`.
const VALUE_FLAGS: [&str; 16] = [
    "--name",
    "--ulimit",
    "--tmpfs",
    "--security-opt",
    "--user",
    "--pids-limit",
    "--cpus",
    "--memory",
    "--hostname",
    "--env",
    "-v",
    "--device",
    "--network",
    "--userns",
    "--pull",
    "--cap-drop",
];
/// `llama-server` flags that grant file or network reach, or a web UI (AMENDMENTS-01 §6.2).
const LLAMA_FORBIDDEN: [&str; 5] = [
    "--models-dir",
    "--models-preset",
    "--slot-save-path",
    "--webui",
    "--ui",
];

fn forbid<T>(msg: impl Into<String>) -> Result<T, ArgvError> {
    Err(ArgvError::Forbidden(msg.into()))
}

/// Checks a podman argv (the arguments after the program name). `roots` are the host paths a
/// `-v` source (and an overlay's upper/work directory) may lie in: validated mount roots and the
/// session's own directories.
///
/// # Errors
/// [`ArgvError::Forbidden`] naming the first offending option.
pub fn check_argv(args: &[String], roots: &[&Path]) -> Result<(), ArgvError> {
    match args {
        [flag, runtime, run, ..]
            if flag == "--runtime" && run == "run" && Path::new(runtime).is_absolute() => {}
        _ => return forbid("argv must start with --runtime <absolute path> run"),
    }
    let mut seen: Vec<(String, Option<String>)> = Vec::new();
    let mut i = 3;
    let image_at = loop {
        let Some(tok) = args.get(i) else {
            return forbid("no image");
        };
        if !tok.starts_with('-') {
            break i;
        }
        let (flag, value) = match tok.split_once('=') {
            Some((f, v)) => (f.to_owned(), Some(v.to_owned())),
            None if VALUE_FLAGS.contains(&tok.as_str()) => {
                i += 1;
                let Some(v) = args.get(i) else {
                    return forbid(format!("{tok} has no value"));
                };
                (tok.clone(), Some(v.clone()))
            }
            None => (tok.clone(), None),
        };
        check_option(&flag, value.as_deref(), roots)?;
        seen.push((flag, value));
        i += 1;
    };
    require(&seen)?;
    let image = args.get(image_at).map_or("", String::as_str);
    ImageRef::parse(image)
        .map_err(|_| ArgvError::Forbidden("image must be pinned by digest".into()))?;
    for tok in args.get(image_at + 1..).unwrap_or_default() {
        if tok != "--no-webui" && LLAMA_FORBIDDEN.iter().any(|f| tok.starts_with(f)) {
            return forbid(format!("command flag {tok} grants file or network reach"));
        }
    }
    Ok(())
}

fn check_option(flag: &str, value: Option<&str>, roots: &[&Path]) -> Result<(), ArgvError> {
    let fixed = |want: &str| match value {
        Some(v) if v == want => Ok(()),
        _ => forbid(format!("{flag} must be {want}")),
    };
    match (flag, value) {
        ("--rm" | "--no-hosts" | "--read-only" | "--init", None) => Ok(()),
        ("--pull", _) => fixed("never"),
        ("--http-proxy" | "--read-only-tmpfs" | "--env-host", _) => fixed("false"),
        ("--log-driver" | "--network", _) => fixed("none"),
        ("--cap-drop", _) => fixed("ALL"),
        ("--userns", _) => fixed("keep-id"),
        ("--ulimit", _) => fixed("core=0"),
        ("--hostname", _) => fixed("sandbox"),
        ("--security-opt", Some(v)) => security_opt(v),
        ("--name", Some(v))
            if v.starts_with("sp-")
                && v.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') =>
        {
            Ok(())
        }
        ("--user", Some(v)) if ids(v) => Ok(()),
        ("--pids-limit", Some(v)) if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(())
        }
        ("--cpus", Some(v))
            if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
        {
            Ok(())
        }
        ("--memory", Some(v))
            if v.strip_suffix('b')
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) =>
        {
            Ok(())
        }
        ("--tmpfs", Some(v)) if tmpfs(v) => Ok(()),
        ("--env", Some(v)) if env(v) => Ok(()),
        ("--device", Some(v)) if v.starts_with("nvidia.com/gpu=") => Ok(()),
        ("-v", Some(v)) => volume(v, roots),
        _ => forbid(format!("podman option {flag} is not allowed here")),
    }
}

fn security_opt(v: &str) -> Result<(), ArgvError> {
    if v == "no-new-privileges" || v == "label=disable" {
        return Ok(());
    }
    match v.strip_prefix("seccomp=") {
        Some(p) if Path::new(p).is_absolute() && p.ends_with(".json") => Ok(()),
        _ => forbid(format!("--security-opt {v} is not allowed")),
    }
}

fn ids(v: &str) -> bool {
    v.split_once(':').is_some_and(|(u, g)| {
        [u, g]
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    })
}

fn tmpfs(v: &str) -> bool {
    v.strip_prefix("/tmp:").is_some_and(|opts| {
        let o: Vec<&str> = opts.split(',').collect();
        o.contains(&"nosuid") && o.contains(&"nodev") && !o.contains(&"suid") && !o.contains(&"dev")
    })
}

fn env(v: &str) -> bool {
    v.split_once('=').is_some_and(|(name, _)| {
        let mut b = name.bytes();
        b.next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
            && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
            && !name.starts_with("LD_")
    })
}

/// `src:dst:opts` with `src` under a root, and opts either exactly `{ro|rw},nosuid,nodev,bind`
/// or exactly `O,upperdir=<root path>,workdir=<root path>`.
fn volume(v: &str, roots: &[&Path]) -> Result<(), ArgvError> {
    let parts: Vec<&str> = v.split(':').collect();
    let [src, dst, opts] = parts.as_slice() else {
        return forbid(format!("-v {v} is not src:dst:options"));
    };
    if !under_root(src, roots) {
        return forbid(format!(
            "-v source {src} is not a validated mount or session directory"
        ));
    }
    if !dst.starts_with('/') || dst.split('/').any(|s| s == "..") {
        return forbid(format!("-v destination {dst} must be absolute"));
    }
    let o: Vec<&str> = opts.split(',').collect();
    match o.as_slice() {
        [access, "nosuid", "nodev", "bind"] if *access == "ro" || *access == "rw" => Ok(()),
        ["O", upper, work] => {
            let ok = upper
                .strip_prefix("upperdir=")
                .is_some_and(|p| under_root(p, roots))
                && work
                    .strip_prefix("workdir=")
                    .is_some_and(|p| under_root(p, roots));
            if ok {
                Ok(())
            } else {
                forbid(format!("-v overlay options {opts} are not allowed"))
            }
        }
        _ => forbid(format!(
            "-v options {opts} must be ro|rw,nosuid,nodev,bind or an overlay"
        )),
    }
}

fn under_root(p: &str, roots: &[&Path]) -> bool {
    let path = Path::new(p);
    path.is_absolute()
        && path
            .components()
            .all(|c| !matches!(c, Component::ParentDir | Component::CurDir))
        && roots.iter().any(|r| path.starts_with(r))
}

/// The hardening that must be present in every argv, exactly once where it matters.
fn require(seen: &[(String, Option<String>)]) -> Result<(), ArgvError> {
    let count = |flag: &str, value: Option<&str>| {
        seen.iter()
            .filter(|(f, v)| f == flag && v.as_deref() == value)
            .count()
    };
    let needed: [(&str, Option<&str>); 7] = [
        ("--network", Some("none")),
        ("--cap-drop", Some("ALL")),
        ("--security-opt", Some("no-new-privileges")),
        ("--read-only", None),
        ("--pull", Some("never")),
        ("--rm", None),
        ("--userns", Some("keep-id")),
    ];
    for (flag, value) in needed {
        if count(flag, value) != 1 {
            return forbid(format!(
                "{flag} {} must appear exactly once",
                value.unwrap_or("")
            ));
        }
    }
    if !seen.iter().any(|(f, v)| {
        f == "--security-opt" && v.as_deref().is_some_and(|v| v.starts_with("seccomp="))
    }) {
        return forbid("a seccomp profile is required");
    }
    Ok(())
}
