#![allow(clippy::unwrap_used)]

use super::*;

fn good() -> Facts {
    Facts {
        cgroup_fs: Ok(CGROUP2_MAGIC),
        kernel: Ok("6.6.87-generic\n".into()),
        runtime_dir: Some(Ok((1000, 0o40700, true))),
        euid: 1000,
        storage_conf: false,
    }
}

fn is_fail(v: &Verdict) -> bool {
    matches!(v, Verdict::Fail(_))
}

#[test]
fn a_ready_host_passes_every_check() {
    let (all, code) = verdicts(&good());
    assert_eq!(code, EXIT_OK);
    assert!(all.iter().all(|v| matches!(v, Verdict::Pass(_))), "{all:?}");
}

#[test]
fn cgroup_v1_fails() {
    assert!(is_fail(&cgroup(&Ok(0x0102_7184))));
    assert!(matches!(cgroup(&Err("x".into())), Verdict::Unknown(_)));
    let f = Facts {
        cgroup_fs: Ok(0x0102_7184),
        ..good()
    };
    assert_eq!(verdicts(&f).1, EXIT_REFUSED);
}

#[test]
fn a_kernel_before_5_8_fails() {
    for (r, ok) in [
        ("5.8.0", true),
        ("5.15.0-91-generic", true),
        ("6.0", true),
        ("5.7.19", false),
        ("4.19.0", false),
    ] {
        assert_eq!(!is_fail(&kernel(&Ok(r.into()))), ok, "{r}");
    }
    assert!(matches!(kernel(&Ok("v".into())), Verdict::Unknown(_)));
    assert!(matches!(kernel(&Err("x".into())), Verdict::Unknown(_)));
}

#[test]
fn the_runtime_dir_must_be_a_private_directory_of_the_user() {
    assert!(is_fail(&runtime_dir(&None, 1000)));
    assert!(is_fail(&runtime_dir(&Some(Ok((1000, 0o700, false))), 1000)));
    assert!(is_fail(&runtime_dir(&Some(Ok((1001, 0o700, true))), 1000)));
    assert!(is_fail(&runtime_dir(&Some(Ok((1000, 0o750, true))), 1000)));
    assert!(is_fail(&runtime_dir(&Some(Ok((1000, 0o1700, true))), 1000)));
    assert!(matches!(
        runtime_dir(&Some(Ok((1000, 0o40700, true))), 1000),
        Verdict::Pass(_)
    ));
    assert!(matches!(
        runtime_dir(&Some(Err("x".into())), 1000),
        Verdict::Unknown(_)
    ));
}

#[test]
fn root_fails_and_a_storage_conf_is_only_noted() {
    assert!(is_fail(&not_root(0)));
    assert!(matches!(not_root(1), Verdict::Pass(_)));
    assert!(matches!(storage_conf(true), Verdict::Note(_)));
    let f = Facts {
        storage_conf: true,
        ..good()
    };
    assert_eq!(verdicts(&f).1, EXIT_OK);
}

#[test]
fn an_unreadable_fact_outranks_a_failure() {
    let f = Facts {
        euid: 0,
        kernel: Err("x".into()),
        ..good()
    };
    assert_eq!(verdicts(&f).1, EXIT_FAILED);
}

#[test]
fn doctor_prints_one_tagged_line_per_check() {
    let f = Facts {
        euid: 0,
        runtime_dir: Some(Ok((0, 0o40700, true))),
        storage_conf: true,
        ..good()
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = doctor(
        &f,
        &mut Out {
            out: &mut out,
            err: &mut err,
        },
    );
    assert_eq!(code, EXIT_REFUSED);
    let out = String::from_utf8(out).unwrap();
    let tags: Vec<&str> = out.lines().map(|l| &l[..4]).collect();
    assert_eq!(tags, ["PASS", "PASS", "PASS", "FAIL", "NOTE"]);
}
