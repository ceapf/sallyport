//! RT-SEC-15 (#162, #161; architect Q271, Q275, Q276, Q288, Q289, Q291): session X sends a
//! live session Y's secret in text the sandbox chooses, and no form of it reaches either log.
//!
//! Y's forms are registered through [`Redactors::for_logs`] with a real [`AuditWriter`] and an
//! [`Oplog`] to a buffer, as `serve` wires them. X's entries come from the production builders:
//! - a proxy target (`egress.request` with grants; a refused target without) at its start and
//!   straddling 256;
//! - a proxy method at its start and straddling 256 (only a value that is an HTTP token);
//! - a fetch URL, method and header value at their start, and a header value and a shell
//!   argument straddling `AUDIT_ACTION_CHARS`. All go through the approval's action text, which
//!   one builder makes for all six events that carry it (`tool.pending`, `approval.decide`,
//!   `approval.deny`, `tool.deny`, `tool.run`, `tool.read`); this test writes `tool.pending`;
//! - an extension method and string id (`rpc.deny`), and a `tools/call` argument key and tool
//!   name (`rpc.request`), at their start and straddling 64.
//!
//! One entry is built by hand: a wildcard CONNECT host in plain `egress.allow` args (Q289). It
//! proves that the writer's whole-args pass masks an undeclared plain arg. `egress::server_tests`
//! drives the proxy's own allow and close builders (Q301).
//!
//! Each value is plain, or holds a quote, a backslash and a non-printable byte. The oplog's
//! values straddle its 4096 cap. X runs once without grants and once with its own grant (its
//! own pass intact).
//!
//! Control: the same entries in a writer the redactors never reach (the union pass removed)
//! keep a run of Y's secret in every case. Checked by hand once: the writer masking after it
//! styles a declared text (sally-core `declared.rs`) also fails this test.

use serde_json::Map;

use super::*;
use crate::approvals::action::{Action, Bound, Payload};
use crate::approvals::queue::{AUDIT_ACTION_CHARS, Fields};
use crate::egress::authority;
use crate::egress::redact::Redaction;
use crate::rpc::agent::{call_entry, deny_entry};
use crate::rpc::mcp::Era;
use crate::rpc::message::Id;

/// Y's secrets: plain, with a quote, a backslash and a non-printable byte, and a DNS-safe
/// lower-case label (the only form that can stand in a host).
const Y_PLAIN: &str = "sp-y-plain-vvvvvvvvvvvvvvvvvvvv";
const Y_ODD: &str = "q\"u\\o\x01te-sp-y-odd-wwwwwwwwwwww";
/// Y's DNS-safe value (architect Q279 (b), Q301): letters and digits only, assembled at run time.
fn y_host() -> String {
    format!("yhost{}", "h".repeat(20))
}
const X_OWN: &str = "sp-x-own-xxxxxxxxxxxxxxxxxxxx";

fn y_forms() -> Arc<SessionForms> {
    let (p, o, h) = (
        Secret::new(Y_PLAIN.to_owned()),
        Secret::new(Y_ODD.to_owned()),
        Secret::new(y_host()),
    );
    SessionForms::build([
        ("Y_PLAIN", &p, vec![]),
        ("Y_ODD", &o, vec![]),
        ("Y_HOST", &h, vec![]),
    ])
}

/// `v` at the start of the text, and placed so it straddles a cut at `cut` bytes of `lead`.
fn placed(v: &str, lead: usize, cut: usize) -> [String; 2] {
    [
        format!("{v}/tail"),
        format!("{}{v}/tail", "a".repeat(cut - lead - 10)),
    ]
}

/// Every entry X's builders write with `v` in each sandbox-chosen place; `own` is X's own pass.
fn entries(v: &str, own: Option<&Redaction>) -> Vec<NewEntry> {
    let x = |event: &str| NewEntry::new(Actor::Harness, event).session("x");
    let mut out = Vec::new();
    // A proxy target and method across 256: `egress.request` for X with grants (the
    // intercepting builder), a refused target for X without.
    let a = authority::parse("h.test:443").unwrap();
    for t in placed(v, "/".len(), 256) {
        let target = format!("/{t}");
        out.push(match own {
            Some(r) => {
                let m = hyper::http::Method::from_bytes(b"EXT").unwrap();
                crate::egress::server::request_entry(x("egress.request"), &a, &m, &target, &[], r)
            }
            None => {
                authority::with_target(x("egress.deny"), serde_json::Value::Null, &target, None)
            }
        });
    }
    if let Some(r) = own {
        // A method is a token: only a value without a quote or a backslash can be one.
        // At the start, and straddling the method's cut at 256.
        for m in [format!("M{v}"), format!("M{}{v}", "A".repeat(256 - 1 - 10))] {
            if let Ok(m) = hyper::http::Method::from_bytes(m.as_bytes()) {
                out.push(crate::egress::server::request_entry(
                    x("egress.request"),
                    &a,
                    &m,
                    "/",
                    &[],
                    r,
                ));
            }
        }
    }
    // A fetch URL, method and header value at their start, a header value and a shell argument
    // across AUDIT_ACTION_CHARS.
    let fetch = Action::Fetch {
        method: format!("M{v}"),
        url: format!("https://h.test/?q={v}"),
        headers: vec![("x-k".to_owned(), format!("Bearer {v}"))],
        body: Payload::new(Vec::new()),
    };
    let lead = "fetch \"GET\" \"https://h.test/\" headers [\"x-k\": \"".len();
    let header = placed(v, lead, AUDIT_ACTION_CHARS).map(|s| Action::Fetch {
        method: "GET".to_owned(),
        url: "https://h.test/".to_owned(),
        headers: vec![("x-k".to_owned(), s)],
        body: Payload::new(Vec::new()),
    });
    let lead = "run [\"".len();
    let long = placed(v, lead, AUDIT_ACTION_CHARS).map(|s| Action::Shell {
        argv: vec![s],
        cwd: "/workspace".to_owned(),
    });
    for action in std::iter::once(fetch).chain(header).chain(long) {
        let b = Bound {
            session: "x".to_owned(),
            call: 1,
            action,
        };
        out.push(Fields::of(&b).on(x("tool.pending")));
    }
    // An extension method, a tools/call argument key and a tool name, across 64.
    for t in placed(v, 0, 64) {
        out.push(deny_entry(
            x("rpc.deny"),
            Some(&Id::Str(t.clone())),
            Some(&t),
            "method-not-found",
        ));
        let mut args = Map::new();
        args.insert(t.clone(), serde_json::json!(1));
        out.push(call_entry(
            x("rpc.request"),
            &Id::Num(1),
            Era::Modern,
            &t,
            &args,
        ));
    }
    out
}

/// A wildcard CONNECT host's `egress.allow` (Q289), built by hand here: the parsed,
/// lower-cased host in plain args, undeclared. It proves the real writer's whole-args pass
/// under the union masks a plain arg (Q301 (ii)); `egress::server_tests`'s RT-SEC-15 case
/// drives the proxy's own `egress.allow` and `egress.close` builders (Q301 (i)).
fn allow_entry() -> NewEntry {
    let a = authority::parse(&format!("{}.mock.test:443", y_host())).unwrap();
    NewEntry::new(Actor::Sallyd, "egress.allow")
        .session("x")
        .args(json!({"host": a.host, "port": a.port}))
}

fn shared(dir: &Path) -> Arc<SharedAudit> {
    Arc::new(SharedAudit(Mutex::new(
        AuditWriter::open(dir, Box::new(SystemClock)).unwrap(),
    )))
}

/// Every spelling a log could hold of each form of `v`: raw, `\"`-escaped, `\xNN`, and the
/// text format's escape.
fn spellings(v: &str) -> Vec<String> {
    let mut out = Vec::new();
    for f in sally_core::audit::secret_forms(v) {
        let f = f.expose();
        out.push(f.to_owned());
        out.push(sally_core::text::escape_backslash_quoted(f.as_bytes()));
        out.push(sally_core::text::hex_capped(f.as_bytes(), usize::MAX).0);
        out.push(sally_core::text::escape(f.as_bytes()));
        out.push(sally_core::text::escape_quoted_capped(
            f.as_bytes(),
            usize::MAX,
        ));
    }
    out
}

/// The first 8-byte run of any spelling of `v` in `text`.
fn run_of(text: &str, v: &str) -> Option<String> {
    spellings(v).iter().find_map(|s| {
        s.as_bytes()
            .windows(8)
            .filter_map(|w| std::str::from_utf8(w).ok())
            .find(|w| text.contains(w))
            .map(str::to_owned)
    })
}

#[test]
fn rt_sec_15_no_form_of_a_live_sessions_secret_reaches_a_log_from_another_session() {
    let dir = scratch("cross");
    let audit = shared(&dir.join("audit"));
    let control = shared(&dir.join("control"));
    let lines = Lines::default();
    let oplog = Oplog::new(lines.clone());
    let raw_lines_out = Lines::default();
    let raw_oplog = Oplog::new(raw_lines_out.clone());
    let redactors = Redactors::for_logs(&audit, &oplog);
    redactors.register("y", y_forms());
    let x_own = Redaction::of(forms("X_OWN", X_OWN)).unwrap();
    redactors.register("x", forms("X_OWN", X_OWN));
    for own in [None, Some(&x_own)] {
        for v in [Y_PLAIN, Y_ODD] {
            for e in entries(v, own) {
                audit.append(e.clone(), AuditLevel::Full).unwrap();
                control.append(e, AuditLevel::Full).unwrap();
            }
            // An oplog value, raw as every caller passes it, across the oplog's 4096 cap.
            for t in placed(v, 0, 4096) {
                oplog.info("test", "x text", &[("session", "x"), ("detail", &t)]);
                raw_oplog.info("test", "x text", &[("session", "x"), ("detail", &t)]);
            }
        }
    }
    audit.append(allow_entry(), AuditLevel::Full).unwrap();
    control.append(allow_entry(), AuditLevel::Full).unwrap();
    assert!(oplog.flush(std::time::Duration::from_secs(10)));
    assert!(raw_oplog.flush(std::time::Duration::from_secs(10)));
    let raw_text = raw_lines_out.text();
    let raw_op: Vec<&str> = raw_text.lines().filter(|l| l.contains("x text")).collect();
    assert_eq!(raw_op.len(), 8, "{raw_text}");
    for l in &raw_op {
        assert!(
            [Y_PLAIN, Y_ODD].iter().any(|v| run_of(l, v).is_some()),
            "control: no run of Y's secret in the unredacted oplog line ending {:?}",
            &l[l.len().saturating_sub(80)..]
        );
    }
    let logged = format!("{}{}", all_text(&dir.join("audit")), lines.text());
    let host = y_host();
    for v in [Y_PLAIN, Y_ODD, host.as_str()] {
        assert_eq!(run_of(&logged, v), None, "a run of {v:?} in the logs");
    }
    // Presence in each log on its own, and on every audit line of session x (each held a run
    // of Y's secret in the control below): the text was masked, not dropped.
    let audit_text = all_text(&dir.join("audit"));
    for name in ["Y_PLAIN", "Y_ODD", "Y_HOST"] {
        assert!(audit_text.contains(&format!("[REDACTED:{name}]")), "{name}");
    }
    for name in ["Y_PLAIN", "Y_ODD"] {
        assert!(
            lines.text().contains(&format!("[REDACTED:{name}]")),
            "{name}"
        );
    }
    let x_lines: Vec<&str> = audit_text.lines().filter(|l| l.contains("\"x\"")).collect();
    assert!(x_lines.len() > 20, "{}", x_lines.len());
    for l in &x_lines {
        assert!(l.contains("[REDACTED"), "no placeholder in {l}");
    }
    // Control: without the writer's union pass, every entry keeps a run of Y's secret.
    let raw = all_text(&dir.join("control"));
    let raw_lines: Vec<&str> = raw.lines().filter(|l| l.contains("\"x\"")).collect();
    assert!(raw_lines.len() > 20, "{}", raw_lines.len());
    for l in &raw_lines {
        let leaked = [Y_PLAIN, Y_ODD, host.as_str()]
            .iter()
            .any(|v| run_of(l, v).is_some());
        assert!(leaked, "control: no run of Y's secret in {l}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
