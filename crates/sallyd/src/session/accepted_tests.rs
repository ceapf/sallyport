#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use sally_core::manifest::{Code, Diagnostic, HostEnv, Severity, load};

use super::*;

const HEAD: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

/// Shell commands run unapproved, acknowledged: one acknowledged risk and one warning.
const RISKY: &str = "tools:\n  builtin: [shell]\n  shell: allow\n  \
                     destructive_requires_approval: false\n  acknowledge_unapproved: [shell]\n";

fn validated(body: &str) -> Validated {
    let env = HostEnv {
        home: std::env::temp_dir(),
        other_homes: Vec::new(),
        xdg_config_home: None,
        xdg_data_home: None,
        xdg_runtime_dir: None,
        podman_storage: Vec::new(),
        env_dirs: Vec::new(),
        nproc: 8,
        mem_bytes: 16 << 30,
    };
    let names = std::collections::BTreeSet::<String>::new();
    load(&format!("{HEAD}{body}"), &env, &names).unwrap()
}

/// A warning at `tools.mcp[i]` whose message carries a marker (a real warning, re-pointed: the
/// type has no public constructor).
fn warning(i: usize) -> Diagnostic {
    let mut w = validated(RISKY).warnings[0].clone();
    assert_eq!((w.severity, w.code), (Severity::Warning, Code::Risky));
    w.path = format!("tools.mcp[{i}]");
    w.message = format!("MARKq7zX message {i}");
    w
}

#[test]
fn an_acknowledged_risk_and_a_warning_are_each_recorded() {
    let v = validated(RISKY);
    let e = entries("s-1", &v);
    let events: Vec<&str> = e.iter().map(NewEntry::event).collect();
    assert_eq!(events, ["manifest.acknowledged_risk", "manifest.warn"]);
    assert_eq!(e[0].decision_value(), Some("allow"));
    assert_eq!(
        *e[0].arguments(),
        json!({"risk": "tools.acknowledge_unapproved: shell"})
    );
    assert_eq!(e[1].decision_value(), None);
    assert_eq!(
        *e[1].arguments(),
        json!({"count": 1, "warnings": [{"code": "risky", "path": "tools.shell"}]})
    );
}

#[test]
fn nothing_accepted_records_nothing() {
    let v = validated("");
    assert!(v.warnings.is_empty() && v.manifest.acknowledged_risks().is_empty());
    assert!(entries("s-1", &v).is_empty());
}

#[test]
fn a_warning_alone_is_recorded_without_a_risk() {
    let mut v = validated("");
    v.warnings.push(warning(0));
    let e = entries("s-1", &v);
    let events: Vec<&str> = e.iter().map(NewEntry::event).collect();
    assert_eq!(events, ["manifest.warn"]);
}

#[test]
fn warnings_are_listed_up_to_the_cap_and_counted_in_full() {
    for (n, listed) in [
        (MAX_LISTED_WARNINGS, MAX_LISTED_WARNINGS),
        (MAX_LISTED_WARNINGS + 1, MAX_LISTED_WARNINGS),
    ] {
        let mut v = validated("");
        v.warnings = (0..n).map(warning).collect();
        let e = entries("s-1", &v);
        let a = e[0].arguments();
        assert_eq!(a["count"], json!(n));
        let got = a["warnings"].as_array().unwrap();
        assert_eq!(got.len(), listed, "{n}");
        assert_eq!(
            got[listed - 1]["path"],
            json!(format!("tools.mcp[{}]", listed - 1))
        );
        // Code and field only: the message is never recorded.
        assert!(!a.to_string().contains("MARKq7zX"), "{a}");
    }
}

/// `audit.level` sets detail, never coverage (SI-4): under `actions` the writer still writes
/// both launch entries.
#[test]
fn under_audit_level_actions_both_entries_are_written() {
    use sally_core::audit::{Appended, AuditWriter, SystemClock};
    use sally_core::manifest::AuditLevel;

    let v = validated(&format!("{RISKY}audit:\n  level: actions\n"));
    let level = v.manifest.manifest().audit.level;
    assert_eq!(level, AuditLevel::Actions);
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/session-accepted-tests")
        .join(format!("actions-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut w = AuditWriter::open(&dir, Box::new(SystemClock)).unwrap();
    let e = entries("s-1", &v);
    let events: Vec<String> = e.iter().map(|x| x.event().to_owned()).collect();
    assert_eq!(events, ["manifest.acknowledged_risk", "manifest.warn"]);
    for entry in e {
        let written = w.append(entry, level).unwrap();
        assert!(matches!(written, Appended::Written { .. }), "{written:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_cap_is_thirty_two() {
    assert_eq!(MAX_LISTED_WARNINGS, 32);
}
