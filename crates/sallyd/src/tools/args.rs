//! Arguments of the built-in tools (ARCHITECTURE §4.3; architect ruling Q35). Pure: the
//! harness's `arguments` object in, typed arguments out. A wrong type, a missing or unknown key,
//! a non-canonical base64 body, or a bound crossed is `bad-arguments`; paths are checked later by
//! `path.rs`, against the session's mounts.

use base64::Engine as _;
use serde_json::{Map, Value};

use super::path::MAX_PATH;

/// Most bytes one `fs_read` returns; a larger `len` is cut to it.
pub const READ_CAP: u64 = 1 << 20;
/// Most elements in a `shell` command.
pub const MAX_ARGV: usize = 256;

/// The `denied: <code>` text for arguments that do not fit the tool.
pub const BAD: &str = "bad-arguments";

/// Typed arguments of one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Args {
    /// `fs_read {path, offset?, len?}`.
    Read {
        /// Guest path.
        path: String,
        /// First byte (default 0).
        offset: u64,
        /// Most bytes (default and cap [`READ_CAP`]).
        len: u64,
    },
    /// `fs_list {path}`.
    List {
        /// Guest path.
        path: String,
    },
    /// `fs_write {path, content_b64}`.
    Write {
        /// Guest path.
        path: String,
        /// The decoded content.
        content: Vec<u8>,
    },
    /// `fs_delete {path}`.
    Delete {
        /// Guest path.
        path: String,
    },
    /// `shell {cmd, cwd?}`.
    Shell {
        /// The command and its arguments.
        cmd: Vec<String>,
        /// Absolute guest working directory, canonical (`None`: the tool's default).
        cwd: Option<String>,
    },
}

/// Parses `a` as the arguments of `tool` (a built-in wire name).
///
/// # Errors
/// [`BAD`], or `unknown-tool` for a name that is no built-in tool.
pub fn parse(tool: &str, a: &Map<String, Value>) -> Result<Args, &'static str> {
    match tool {
        "fs_read" => {
            only(a, &["path", "offset", "len"])?;
            let offset = opt_u64(a, "offset")?.unwrap_or(0);
            let len = opt_u64(a, "len")?.unwrap_or(READ_CAP).min(READ_CAP);
            offset.checked_add(len).ok_or(BAD)?;
            Ok(Args::Read {
                path: string(a, "path")?,
                offset,
                len,
            })
        }
        "fs_list" => {
            only(a, &["path"])?;
            Ok(Args::List {
                path: string(a, "path")?,
            })
        }
        "fs_write" => {
            only(a, &["path", "content_b64"])?;
            let b64 = string(a, "content_b64")?;
            let content = base64::engine::general_purpose::STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| BAD)?;
            Ok(Args::Write {
                path: string(a, "path")?,
                content,
            })
        }
        "fs_delete" => {
            only(a, &["path"])?;
            Ok(Args::Delete {
                path: string(a, "path")?,
            })
        }
        "shell" => {
            only(a, &["cmd", "cwd"])?;
            let cmd = argv(a.get("cmd").ok_or(BAD)?)?;
            let cwd = match a.get("cwd") {
                None => None,
                Some(Value::String(s)) => Some(cwd(s)?),
                Some(_) => return Err(BAD),
            };
            Ok(Args::Shell { cmd, cwd })
        }
        _ => Err("unknown-tool"),
    }
}

/// Refuses a key not in `keys`.
fn only(a: &Map<String, Value>, keys: &[&str]) -> Result<(), &'static str> {
    if a.keys().all(|k| keys.contains(&k.as_str())) {
        Ok(())
    } else {
        Err(BAD)
    }
}

fn string(a: &Map<String, Value>, key: &str) -> Result<String, &'static str> {
    match a.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(BAD),
    }
}

fn opt_u64(a: &Map<String, Value>, key: &str) -> Result<Option<u64>, &'static str> {
    match a.get(key) {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or(BAD),
    }
}

/// 1 to [`MAX_ARGV`] strings; the first not empty; no NUL anywhere (it would cut the argument
/// short in `execve`, so what ran would not be what was shown).
fn argv(v: &Value) -> Result<Vec<String>, &'static str> {
    let Value::Array(items) = v else {
        return Err(BAD);
    };
    if items.is_empty() || items.len() > MAX_ARGV {
        return Err(BAD);
    }
    let cmd = items
        .iter()
        .map(|x| match x {
            Value::String(s) if !s.contains('\0') => Ok(s.clone()),
            _ => Err(BAD),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if cmd.first().is_none_or(String::is_empty) {
        return Err(BAD);
    }
    Ok(cmd)
}

/// An absolute guest directory with no `..` and no control bytes, in canonical form.
fn cwd(s: &str) -> Result<String, &'static str> {
    if !s.starts_with('/') || s.len() > MAX_PATH || s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(BAD);
    }
    let segs: Vec<&str> = s
        .split('/')
        .filter(|x| !x.is_empty() && *x != ".")
        .collect();
    if segs.contains(&"..") {
        return Err(BAD);
    }
    Ok(format!("/{}", segs.join("/")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::json;

    use super::*;

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn p(tool: &str, v: Value) -> Result<Args, &'static str> {
        parse(tool, &args(v))
    }

    #[test]
    fn reads_default_to_the_cap_and_cut_a_larger_len() {
        assert_eq!(
            p("fs_read", json!({"path": "/w/a"})),
            Ok(Args::Read {
                path: "/w/a".into(),
                offset: 0,
                len: READ_CAP
            })
        );
        assert_eq!(
            p("fs_read", json!({"path": "/w/a", "offset": 5, "len": 7})),
            Ok(Args::Read {
                path: "/w/a".into(),
                offset: 5,
                len: 7
            })
        );
        for (asked, got) in [
            (READ_CAP - 1, READ_CAP - 1),
            (READ_CAP, READ_CAP),
            (READ_CAP + 1, READ_CAP),
            (u64::MAX, READ_CAP),
        ] {
            let r = p("fs_read", json!({"path": "/w/a", "len": asked})).unwrap();
            assert!(matches!(r, Args::Read { len, .. } if len == got), "{asked}");
        }
        assert_eq!(READ_CAP, 1_048_576);
    }

    #[test]
    fn a_read_range_that_overflows_or_is_not_a_count_is_bad() {
        let max = u64::MAX;
        assert_eq!(
            p("fs_read", json!({"path": "/w/a", "offset": max})),
            Err(BAD)
        );
        let edge = u64::MAX - READ_CAP;
        assert!(p("fs_read", json!({"path": "/w/a", "offset": edge})).is_ok());
        assert_eq!(
            p("fs_read", json!({"path": "/w/a", "offset": edge + 1})),
            Err(BAD)
        );
        for bad in [json!(-1), json!(1.5), json!("1"), json!(null)] {
            assert_eq!(
                p("fs_read", json!({"path": "/w/a", "offset": bad.clone()})),
                Err(BAD)
            );
            assert_eq!(p("fs_read", json!({"path": "/w/a", "len": bad})), Err(BAD));
        }
    }

    #[test]
    fn every_tool_refuses_unknown_keys_missing_paths_and_wrong_types() {
        for tool in ["fs_read", "fs_list", "fs_delete"] {
            assert_eq!(p(tool, json!({"path": "/w/a", "x": 1})), Err(BAD), "{tool}");
            assert_eq!(p(tool, json!({})), Err(BAD), "{tool}");
            assert_eq!(p(tool, json!({"path": 1})), Err(BAD), "{tool}");
            assert!(p(tool, json!({"path": "/w/a"})).is_ok(), "{tool}");
        }
        assert_eq!(
            p(
                "fs_write",
                json!({"path": "/w/a", "content_b64": "", "mode": 1})
            ),
            Err(BAD)
        );
        assert_eq!(p("fs_write", json!({"path": "/w/a"})), Err(BAD));
        assert_eq!(p("fs_write", json!({"content_b64": ""})), Err(BAD));
        assert_eq!(
            p("fs_write", json!({"path": "/w/a", "content_b64": 1})),
            Err(BAD)
        );
        assert_eq!(p("shell", json!({"cmd": ["ls"], "env": {}})), Err(BAD));
        assert_eq!(p("fetch", json!({})), Err("unknown-tool"));
        assert_eq!(p("nope", json!({})), Err("unknown-tool"));
    }

    #[test]
    fn write_content_is_strict_canonical_base64() {
        assert_eq!(
            p("fs_write", json!({"path": "/w/a", "content_b64": "aGk="})),
            Ok(Args::Write {
                path: "/w/a".into(),
                content: b"hi".to_vec()
            })
        );
        assert_eq!(
            p("fs_write", json!({"path": "/w/a", "content_b64": ""})),
            Ok(Args::Write {
                path: "/w/a".into(),
                content: vec![]
            })
        );
        // Missing padding, non-zero trailing bits, URL alphabet, whitespace: all refused.
        for bad in ["aGk", "aGl=", "aG-=", "aG k=", "aGk=\n", "====", "a"] {
            assert_eq!(
                p("fs_write", json!({"path": "/w/a", "content_b64": bad})),
                Err(BAD),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_command_is_one_to_max_argv_strings_without_nul() {
        assert_eq!(
            p("shell", json!({"cmd": ["ls", "-l", ""]})),
            Ok(Args::Shell {
                cmd: vec!["ls".into(), "-l".into(), String::new()],
                cwd: None
            })
        );
        let full: Vec<String> = (0..MAX_ARGV).map(|i| i.to_string()).collect();
        assert!(p("shell", json!({"cmd": full})).is_ok());
        let over: Vec<String> = (0..=MAX_ARGV).map(|i| i.to_string()).collect();
        assert_eq!(p("shell", json!({"cmd": over})), Err(BAD));
        for bad in [
            json!([]),
            json!([""]),
            json!(["ls", 1]),
            json!(["l\0s"]),
            json!(["ls", "a\0"]),
            json!("ls"),
            json!(null),
        ] {
            assert_eq!(p("shell", json!({"cmd": bad.clone()})), Err(BAD), "{bad}");
        }
        assert_eq!(p("shell", json!({})), Err(BAD));
    }

    #[test]
    fn cwd_is_absolute_canonical_and_never_climbs() {
        let cwd_of = |c: &str| match p("shell", json!({"cmd": ["ls"], "cwd": c})) {
            Ok(Args::Shell { cwd, .. }) => Ok(cwd.unwrap()),
            Ok(other) => panic!("{other:?}"),
            Err(e) => Err(e),
        };
        assert_eq!(cwd_of("/workspace/p"), Ok("/workspace/p".into()));
        assert_eq!(cwd_of("//workspace/./p/"), Ok("/workspace/p".into()));
        assert_eq!(cwd_of("/"), Ok("/".into()));
        // A space is the first byte past the control range.
        assert_eq!(cwd_of("/a b"), Ok("/a b".into()));
        for bad in [
            "workspace",
            "",
            "/workspace/../etc",
            "/..",
            "/a\nb",
            "/a\x7f",
            "/a\0",
        ] {
            assert_eq!(cwd_of(bad), Err(BAD), "{bad:?}");
        }
        let at_bound = format!("/{}", "a".repeat(MAX_PATH - 1));
        assert!(cwd_of(&at_bound).is_ok());
        assert_eq!(cwd_of(&format!("{at_bound}a")), Err(BAD));
        assert_eq!(p("shell", json!({"cmd": ["ls"], "cwd": 1})), Err(BAD));
    }
}
