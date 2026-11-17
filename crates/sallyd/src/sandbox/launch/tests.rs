#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn audit_text_is_capped_at_a_character_boundary() {
    assert_eq!(capped("short"), "short");
    let long = "é".repeat(AUDIT_TEXT_CAP);
    let c = capped(&long);
    assert!(c.len() <= AUDIT_TEXT_CAP + "…".len());
    assert!(c.ends_with('…'));
}

/// Architect Q288 (7, 8): a declared detail keeps `capped`'s format, and a form of a live
/// session's secret straddling the cut is masked whole before it. Control: the detail
/// capped before it is declared (the old builders).
#[test]
fn a_declared_detail_is_masked_before_its_cut_in_the_capped_format() {
    let value = "q\"u\\o\x01te-secret-value-0123456789";
    let r = sally_core::audit::Redactor::new([("Y", value)]);
    let detail = |raw: &str, r: &sally_core::audit::Redactor| {
        NewEntry::new(Actor::Sallyd, "sandbox.stop_failed")
            .text("detail", raw, DETAIL_STYLE)
            .resolved(r)["detail"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    for raw in ["short".to_owned(), "é".repeat(AUDIT_TEXT_CAP)] {
        assert_eq!(detail(&raw, &r), capped(&raw));
    }
    // At the stated max (architect Q294 c, Q295): a command's stderr held whole up to
    // OUTPUT_CAP, forms throughout.
    let cap = crate::sandbox::commands::OUTPUT_CAP;
    assert_eq!(cap, 64 * 1024, "the size DETAIL_STYLE's doc quotes");
    assert!(cap >= AUDIT_TEXT_CAP);
    let largest = value.repeat(cap / value.len());
    let text = format!(
        "exit status: 125: {}",
        error::stderr_text(largest.as_bytes(), cap)
    );
    let shown = detail(&text, &r);
    assert!(shown.contains("[REDACTED:Y]"), "{}", &shown[..60]);
    assert!(shown.len() <= AUDIT_TEXT_CAP + "…".len());
    for w in value.as_bytes().windows(8) {
        assert!(!shown.contains(std::str::from_utf8(w).unwrap()));
    }
    // Past it, a long secret repeated, its last copy straddling OUTPUT_CAP: masking
    // shrinks the text, so a cut at OUTPUT_CAP would leave a partial copy inside the
    // audit cut. Withheld whole, nothing of it is shown. Control: the old cut.
    let long = format!("long-secret-{}", "k0123456789".repeat(90));
    let rl = sally_core::audit::Redactor::new([("L", long.as_str())]);
    let over = long.repeat(cap / long.len() + 1);
    let text = format!(
        "exit status: 125: {}",
        error::stderr_text(over.as_bytes(), cap)
    );
    let shown = detail(&text, &rl);
    assert!(shown.starts_with("exit status: 125: "), "{shown}");
    for w in long.as_bytes().windows(8) {
        let w = std::str::from_utf8(w).unwrap();
        assert!(!shown.contains(w), "{w:?} in {shown}");
    }
    let straddle = format!("{}{value}", "x".repeat(AUDIT_TEXT_CAP - 20));
    let shown = detail(&straddle, &r);
    assert!(
        shown.ends_with("[REDACTED:Y]"),
        "{}",
        &shown[shown.len() - 40..]
    );
    for w in value.as_bytes().windows(8) {
        assert!(!shown.contains(std::str::from_utf8(w).unwrap()));
    }
}

/// Architect Q297: a launch task that panicked with a live form in its message (quote,
/// backslash, non-printable) is refused with the fixed detail; no run of the form. Control:
/// tokio's text (the old `join_err`) escapes the message before the writer's mask.
#[tokio::test]
async fn a_panicked_launch_tasks_detail_holds_no_byte_of_its_message() {
    let value = "q\"u\\o\x01te-secret-value-0123456789";
    let r = sally_core::audit::Redactor::new([("Y", value)]);
    let h = tokio::task::spawn_blocking(move || panic!("scan of {value} failed"));
    let e = join_err(h.await.unwrap_err());
    let v = NewEntry::new(Actor::Sallyd, "sandbox.refuse")
        .text("detail", e.to_string(), DETAIL_STYLE)
        .resolved(&r);
    let shown = v["detail"].as_str().expect("the detail is logged");
    assert_eq!(
        shown,
        format!("internal: {}", crate::daemon::crash::JOIN_PANICKED)
    );
    for w in value.as_bytes().windows(8) {
        let w = std::str::from_utf8(w).unwrap();
        assert!(!shown.contains(w), "{w:?} in {shown}");
    }
}

/// #48 (architect Q45): a session over the descriptor budget is refused `fd-budget`, the
/// message naming needed, free and limit; an overlap keeps its own reason.
#[test]
fn an_fd_budget_refusal_has_its_own_reason() {
    use crate::sandbox::budget::FdRefusal;
    use crate::sandbox::overlap::ReserveError;
    let e = LaunchError::from(ReserveError::FdBudget(FdRefusal {
        needed: 256,
        free: 100,
        limit: 512,
    }));
    assert_eq!(e.reason(), "fd-budget");
    let msg = e.to_string();
    assert!(
        msg.contains("256") && msg.contains("100") && msg.contains("512"),
        "{msg}"
    );
    let dup = LaunchError::from(ReserveError::Duplicate("a".into()));
    assert_eq!(dup.reason(), "overlap");
}

/// Architect Q58: no manifest image and no bundled default.
#[test]
fn a_missing_default_image_has_its_own_reason() {
    let e = LaunchError::NoDefaultImage;
    assert_eq!(e.reason(), "no-default-image");
    assert_eq!(
        e.to_string(),
        "runtime.image: no bundled workspace image is installed; the manifest must name a \
         digest-pinned image"
    );
}

#[test]
fn a_listener_failure_has_its_own_reason() {
    let e = LaunchError::Egress(EgressError::Listener(std::io::ErrorKind::AddrInUse.into()));
    assert_eq!(e.reason(), "egress-listener");
    assert!(e.to_string().starts_with("network: net.sock: "), "{e}");
}

/// Task 9a-3 (architect D7): each refusal of a session's credentials names its cause; a
/// malformed `{basic}` grant is a `secret-grant` like any other (Task 9b, ruling A3).
#[test]
fn a_missing_secret_and_an_unreadable_store_have_their_own_reasons() {
    use crate::egress::inject::CredentialsError;
    use sally_core::secrets::SecretsError;
    let missing = LaunchError::Egress(CredentialsError::Missing("GH".into()).into());
    assert_eq!(missing.reason(), "secret-missing");
    assert_eq!(
        missing.to_string(),
        "network: secret GH: not in the secrets store"
    );
    let store = LaunchError::Egress(EgressError::Store(SecretsError::TooLarge));
    assert_eq!(store.reason(), "secret-store");
    assert!(
        store.to_string().starts_with("network: secrets store: "),
        "{store}"
    );
    // Architect Q8: a collective refusal, so its own reason and no secret named.
    let filler = LaunchError::Egress(CredentialsError::NoFiller.into());
    assert_eq!(filler.reason(), "secret-filler");
    assert_eq!(
        filler.to_string(),
        "network: no redaction filler: every candidate occurs in a secret form"
    );
    for other in [
        CredentialsError::Format("GH".into()),
        CredentialsError::Header("GH".into()),
        CredentialsError::Duplicate {
            host: "a.mock.test".into(),
            header: "authorization".into(),
        },
        CredentialsError::TooLong(crate::egress::redact::TooLong("GH".into())),
    ] {
        assert_eq!(LaunchError::Egress(other.into()).reason(), "secret-grant");
    }
    let unmatched = LaunchError::Egress(crate::egress::ca::CaError::Unmatched.into());
    assert_eq!(unmatched.reason(), "session-ca");
}

#[test]
fn missing_trust_roots_and_a_failed_session_ca_have_their_own_reasons() {
    use crate::egress::ca::CaError;
    use crate::egress::roots::RootsError;
    let roots = LaunchError::Egress(RootsError::NotFound("/x".into()).into());
    assert_eq!(roots.reason(), "trust-roots");
    assert!(
        roots.to_string().starts_with("network: trust roots: "),
        "{roots}"
    );
    let ca = LaunchError::Egress(CaError::NoHosts.into());
    assert_eq!(ca.reason(), "session-ca");
    let files = LaunchError::Egress(EgressError::Files(std::io::ErrorKind::AlreadyExists.into()));
    assert_eq!(files.reason(), "session-ca");
    assert!(
        files.to_string().starts_with("network: CA files: "),
        "{files}"
    );
}
