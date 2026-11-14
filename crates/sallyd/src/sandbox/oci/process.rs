//! `process`: identity, command, environment, working directory, capabilities, rlimits and
//! `no_new_privs` (architect Q101–Q104).

use std::collections::BTreeMap;

use super::config::{Capabilities, Process, Rlimit, User};
use super::facts::Facts;
use super::intent::Intent;
use super::{Mismatch, ensure};

/// `--init`: podman runs the checked catatonit at this path, then the command.
pub const INIT_GUEST: &str = "/run/podman-init";
/// The umask podman gives the process (0o022).
const UMASK: u32 = 0o022;

/// Checks `p` against the intent; `hostname` is the config's (podman sets `HOSTNAME` from it).
///
/// # Errors
/// The first [`Mismatch`].
pub fn check(p: &Process, i: &Intent, f: &Facts, hostname: &str) -> Result<(), Mismatch> {
    check_user(&p.user, i)?;
    check_args(&p.args, i, f)?;
    check_env(&p.env, i, f, hostname)?;
    let cwd = f
        .image
        .working_dir
        .as_deref()
        .filter(|d| !d.is_empty())
        .unwrap_or("/");
    ensure(
        p.cwd == cwd,
        "process.cwd",
        "not the image's working directory",
    )?;
    check_caps(&p.capabilities)?;
    check_rlimits(&p.rlimits, f)?;
    ensure(p.no_new_privileges, "process.noNewPrivileges", "not set")
}

fn check_user(u: &User, i: &Intent) -> Result<(), Mismatch> {
    ensure(
        u.uid == i.ids.uid,
        "process.user.uid",
        "not the session uid",
    )?;
    ensure(
        u.gid == i.ids.gid,
        "process.user.gid",
        "not the session gid",
    )?;
    ensure(
        u.additional_gids == [i.ids.gid],
        "process.user.additionalGids",
        "not exactly the session gid",
    )?;
    ensure(u.umask == Some(UMASK), "process.user.umask", "not 0022")
}

/// `[INIT_GUEST, "--", command…]`; an image entrypoint would sit between, so an image that has
/// one is refused (architect Q102). TODO(#117): pass `--entrypoint` instead.
fn check_args(args: &[String], i: &Intent, f: &Facts) -> Result<(), Mismatch> {
    let entry = f.image.entrypoint.as_deref().unwrap_or_default();
    ensure(
        entry.is_empty(),
        "process.args",
        "the image has an entrypoint (refused until #117)",
    )?;
    let want = [INIT_GUEST, "--"]
        .into_iter()
        .chain(i.command.iter().map(String::as_str));
    ensure(
        args.iter().map(String::as_str).eq(want),
        "process.args",
        "not the command the argv built",
    )
}

/// `NAME=value` → (`NAME`, `value`); a name must be non-empty.
fn split(pair: &str) -> Option<(&str, &str)> {
    pair.split_once('=').filter(|(n, _)| !n.is_empty())
}

/// What the environment must be: the image's `Env`, then `container=podman`, then the argv's
/// `--env` pairs, then `HOSTNAME` and `HOME` (the image's `HOME` if it sets one, else `/`).
fn wanted_env<'a>(
    i: &'a Intent,
    f: &'a Facts,
    hostname: &'a str,
) -> Result<BTreeMap<&'a str, &'a str>, Mismatch> {
    let mut want = BTreeMap::new();
    for pair in f.image.env.as_deref().unwrap_or_default() {
        let (n, v) = split(pair).ok_or_else(|| Mismatch::new("image.Env", "not NAME=value"))?;
        want.insert(n, v);
    }
    let home = want.get("HOME").copied().unwrap_or("/");
    want.insert("container", "podman");
    for (n, v) in &i.env {
        want.insert(n.as_str(), v.as_str());
    }
    want.insert("HOSTNAME", hostname);
    want.insert("HOME", home);
    Ok(want)
}

/// Every name once, each with the value wanted, nothing extra and nothing missing. A mismatch
/// names the variable, never its value (architect Q110).
fn check_env(env: &[String], i: &Intent, f: &Facts, hostname: &str) -> Result<(), Mismatch> {
    let want = wanted_env(i, f, hostname)?;
    let mut seen = BTreeMap::new();
    for pair in env {
        let (n, v) = split(pair).ok_or_else(|| Mismatch::new("process.env", "not NAME=value"))?;
        let field = format!("process.env.{n}");
        ensure(seen.insert(n, v).is_none(), &field, "set twice")?;
        match want.get(n) {
            None => return Err(Mismatch::new(field, "not set by the argv or the image")),
            Some(w) => ensure(*w == v, &field, "not the value intended")?,
        }
    }
    match want.keys().find(|n| !seen.contains_key(*n)) {
        Some(n) => Err(Mismatch::new(format!("process.env.{n}"), "missing")),
        None => Ok(()),
    }
}

fn check_caps(c: &Capabilities) -> Result<(), Mismatch> {
    for (set, caps) in [
        ("bounding", &c.bounding),
        ("effective", &c.effective),
        ("inheritable", &c.inheritable),
        ("permitted", &c.permitted),
        ("ambient", &c.ambient),
    ] {
        ensure(
            caps.is_empty(),
            &format!("process.capabilities.{set}"),
            "not empty",
        )?;
    }
    Ok(())
}

/// Exactly `RLIMIT_CORE` 0/0 (`--ulimit core=0`) and podman's inherited `RLIMIT_NOFILE` and
/// `RLIMIT_NPROC`, each with soft ≤ hard ≤ `sallyd`'s own hard limit (architect Q103).
fn check_rlimits(limits: &[Rlimit], f: &Facts) -> Result<(), Mismatch> {
    let mut seen = Vec::new();
    for r in limits {
        let field = format!("process.rlimits.{}", r.kind);
        ensure(!seen.contains(&r.kind.as_str()), &field, "set twice")?;
        seen.push(r.kind.as_str());
        let own = match r.kind.as_str() {
            "RLIMIT_CORE" => {
                ensure(r.hard == 0 && r.soft == 0, &field, "not 0")?;
                continue;
            }
            "RLIMIT_NOFILE" => f.own_nofile,
            "RLIMIT_NPROC" => f.own_nproc,
            _ => return Err(Mismatch::new(field, "not a limit podman sets")),
        };
        ensure(r.soft <= r.hard, &field, "soft above hard")?;
        ensure(r.hard <= own, &field, "above sallyd's own hard limit")?;
    }
    ensure(
        seen.len() == 3,
        "process.rlimits",
        "not exactly RLIMIT_CORE, RLIMIT_NOFILE and RLIMIT_NPROC",
    )
}
