//! The canonical action an approval is bound to (maintainer's Task 10 decision 3).
//!
//! A tool handler builds an [`Action`] from what will run: the argv as it is passed to
//! `podman exec`, resolved paths, a write's content, a fetch's method, URL, headers and body, an
//! MCP call's arguments. An approval binds the [`digest`](Bound::digest) of the action together
//! with the session and the broker's call number, and the digest covers every byte that runs
//! (architect ruling Q24), also where the prompt shows only a size and hash. The executor runs
//! the [`Ticket`](super::Ticket)'s copy, never the harness's arguments.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Bytes that run (a write's content, a fetch body, MCP arguments), with their SHA-256. `Debug`
/// shows the length and hash only, never the bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Payload {
    bytes: Vec<u8>,
    sha256: String,
}

impl Payload {
    /// Wraps `bytes` and hashes them.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        let sha256 = hex(&Sha256::digest(&bytes));
        Self { bytes, sha256 }
    }

    /// The bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        u64::try_from(self.bytes.len()).unwrap_or(u64::MAX)
    }

    /// Whether there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// SHA-256 (hex) of the bytes.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn canonical(&self) -> Value {
        json!({"bytes": self.len(), "sha256": self.sha256})
    }
}

impl std::fmt::Debug for Payload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Payload({} bytes, sha256 {})", self.len(), self.sha256)
    }
}

/// One gated action, in the form in which it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// `shell`: the argv given to `podman exec` and the guest working directory.
    Shell {
        /// The command and its arguments, exactly as executed.
        argv: Vec<String>,
        /// Guest working directory.
        cwd: String,
    },
    /// `fs_write` on a mount.
    FsWrite {
        /// The target.
        target: Target,
        /// The content written.
        content: Payload,
    },
    /// `fs_delete` on a mount.
    FsDelete {
        /// The target.
        target: Target,
    },
    /// `fetch` through the broker's egress path.
    Fetch {
        /// HTTP method, as sent.
        method: String,
        /// The URL, as sent.
        url: String,
        /// The request headers (name, value), in order, as sent.
        headers: Vec<(String, String)>,
        /// The body sent.
        body: Payload,
    },
    /// A tool of a declared MCP server (M4).
    Mcp {
        /// The server's name in the manifest.
        server: String,
        /// The server's tool name.
        tool: String,
        /// The arguments, serialized as relayed.
        args: Payload,
    },
}

/// A file on a mount, after resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The mount's guest root (`/workspace/notes`).
    pub mount: String,
    /// The canonical path relative to the mount (no leading `/`, no `.`/`..`/empty segments).
    pub rel: String,
    /// The host realpath of the target.
    pub host: String,
}

impl Target {
    /// The guest path of the target.
    #[must_use]
    pub fn guest(&self) -> String {
        format!("{}/{}", self.mount, self.rel)
    }
}

impl Action {
    /// The tool's name on the wire.
    #[must_use]
    pub fn tool(&self) -> String {
        match self {
            Self::Shell { .. } => "shell".to_owned(),
            Self::FsWrite { .. } => "fs_write".to_owned(),
            Self::FsDelete { .. } => "fs_delete".to_owned(),
            Self::Fetch { .. } => "fetch".to_owned(),
            Self::Mcp { server, tool, .. } => format!("{server}__{tool}"),
        }
    }

    /// The canonical form: a JSON object with sorted keys; payloads appear as size and hash.
    #[must_use]
    pub fn canonical(&self) -> Value {
        match self {
            Self::Shell { argv, cwd } => json!({"tool": "shell", "argv": argv, "cwd": cwd}),
            Self::FsWrite { target, content } => json!({
                "tool": "fs_write", "target": target_json(target), "content": content.canonical(),
            }),
            Self::FsDelete { target } => {
                json!({"tool": "fs_delete", "target": target_json(target)})
            }
            Self::Fetch {
                method,
                url,
                headers,
                body,
            } => json!({
                "tool": "fetch", "method": method, "url": url, "headers": headers,
                "body": body.canonical(),
            }),
            Self::Mcp { server, tool, args } => json!({
                "tool": "mcp", "server": server, "name": tool, "args": args.canonical(),
            }),
        }
    }
}

fn target_json(t: &Target) -> Value {
    json!({"mount": t.mount, "rel": t.rel, "host": t.host})
}

/// An action bound to its session and the broker's call number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The session.
    pub session: String,
    /// The broker's number for the `tools/call` (unique in the session; architect ruling Q19).
    pub call: u64,
    /// The action.
    pub action: Action,
}

impl Bound {
    /// SHA-256 (hex) over the canonical session, call and action: what an approval binds.
    #[must_use]
    pub fn digest(&self) -> String {
        let body = json!({
            "session": self.session, "call": self.call, "action": self.action.canonical(),
        });
        hex(&Sha256::digest(body.to_string().as_bytes()))
    }
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn shell(argv: &[&str]) -> Action {
        Action::Shell {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: "/workspace/p".to_owned(),
        }
    }

    fn bound(action: Action) -> Bound {
        Bound {
            session: "s1".to_owned(),
            call: 7,
            action,
        }
    }

    fn target(rel: &str) -> Target {
        Target {
            mount: "/workspace/notes".to_owned(),
            rel: rel.to_owned(),
            host: format!("/home/u/notes/{rel}"),
        }
    }

    fn payload(b: &[u8]) -> Payload {
        Payload::new(b.to_vec())
    }

    #[test]
    fn the_digest_is_stable_and_hex() {
        let d = bound(shell(&["touch", "x"])).digest();
        assert_eq!(d.len(), 64);
        assert!(d.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(d, bound(shell(&["touch", "x"])).digest());
    }

    #[test]
    fn every_bound_part_changes_the_digest() {
        let base = bound(shell(&["touch", "x"]));
        let mut other_session = base.clone();
        other_session.session = "s2".to_owned();
        let mut other_call = base.clone();
        other_call.call = 8;
        let variants = [
            other_session,
            other_call,
            bound(shell(&["touch", "y"])),
            bound(shell(&["touch", "x", ""])),
            bound(shell(&["touch x"])),
            bound(Action::Shell {
                argv: vec!["touch".to_owned(), "x".to_owned()],
                cwd: "/workspace/q".to_owned(),
            }),
        ];
        for v in variants {
            assert_ne!(v.digest(), base.digest(), "{v:?}");
        }
    }

    #[test]
    fn a_write_binds_its_content_and_paths() {
        let w = |rel: &str, content: &[u8]| {
            bound(Action::FsWrite {
                target: target(rel),
                content: payload(content),
            })
            .digest()
        };
        let base = w("a.md", b"abc");
        assert_eq!(base, w("a.md", b"abc"));
        assert_ne!(base, w("b.md", b"abc"));
        assert_ne!(base, w("a.md", b"abd"));
        assert_ne!(base, w("a.md", b"abcd"));
        let mut moved = target("a.md");
        moved.host = "/home/u/other/a.md".to_owned();
        let moved = bound(Action::FsWrite {
            target: moved,
            content: payload(b"abc"),
        });
        assert_ne!(base, moved.digest());
        let delete = bound(Action::FsDelete {
            target: target("a.md"),
        });
        assert_ne!(base, delete.digest());
    }

    #[test]
    fn fetch_binds_method_url_header_values_and_body() {
        let f = |method: &str, url: &str, hdr: (&str, &str), body: &[u8]| {
            bound(Action::Fetch {
                method: method.to_owned(),
                url: url.to_owned(),
                headers: vec![(hdr.0.to_owned(), hdr.1.to_owned())],
                body: payload(body),
            })
            .digest()
        };
        let base = f("POST", "https://h/x", ("a", "1"), b"b");
        assert_ne!(base, f("PUT", "https://h/x", ("a", "1"), b"b"));
        assert_ne!(base, f("POST", "https://h/y", ("a", "1"), b"b"));
        assert_ne!(base, f("POST", "https://h/x", ("c", "1"), b"b"));
        assert_ne!(base, f("POST", "https://h/x", ("a", "2"), b"b"));
        assert_ne!(base, f("POST", "https://h/x", ("a", "1"), b"c"));
    }

    #[test]
    fn mcp_binds_server_tool_and_full_arguments() {
        let m = |server: &str, tool: &str, args: &[u8]| {
            bound(Action::Mcp {
                server: server.to_owned(),
                tool: tool.to_owned(),
                args: payload(args),
            })
            .digest()
        };
        let base = m("gh", "issue", b"{}");
        assert_ne!(base, m("gx", "issue", b"{}"));
        assert_ne!(base, m("gh", "issuf", b"{}"));
        assert_ne!(base, m("gh", "issue", b"{\"a\":1}"));
    }

    #[test]
    fn a_payload_hides_its_bytes_in_debug() {
        let p = payload(b"secret body");
        assert_eq!(p.len(), 11);
        assert!(!p.is_empty() && payload(b"").is_empty());
        assert_eq!(p.bytes(), b"secret body");
        let d = format!("{p:?}");
        assert!(d.starts_with("Payload(11 bytes, sha256 ") && !d.contains("secret"));
        assert_eq!(p.sha256(), hex(&Sha256::digest(b"secret body")));
    }

    #[test]
    fn tool_names_are_the_wire_names() {
        assert_eq!(shell(&["ls"]).tool(), "shell");
        let file = target("a");
        let w = Action::FsWrite {
            target: file.clone(),
            content: payload(b""),
        };
        assert_eq!(w.tool(), "fs_write");
        assert_eq!(Action::FsDelete { target: file }.tool(), "fs_delete");
        let f = Action::Fetch {
            method: "GET".to_owned(),
            url: String::new(),
            headers: vec![],
            body: payload(b""),
        };
        assert_eq!(f.tool(), "fetch");
        let m = Action::Mcp {
            server: "gh".to_owned(),
            tool: "issue".to_owned(),
            args: payload(b""),
        };
        assert_eq!(m.tool(), "gh__issue");
        assert_eq!(target("a/b").guest(), "/workspace/notes/a/b");
    }

    #[test]
    fn hex_is_lower_case_and_padded() {
        assert_eq!(hex(&[0, 0x0f, 0xab]), "000fab");
        assert_eq!(hex(&[]), "");
    }
}
