#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sally_core::audit::{Actor, AuditWriter, NewEntry, SystemClock};
use sally_core::manifest::{AuditLevel, MAX_MANIFEST_BYTES};
use serde_json::json;

use super::*;

const VALID: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

/// The files a validation reads besides the manifest.
fn files<'a>(store: &'a Path, config: &'a Path) -> Files<'a> {
    Files { store, config }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("sc-loc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn file(&self, name: &str, text: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    fn audit(&self) -> PathBuf {
        self.0.join("audit")
    }

    /// The secrets store's path (no file: an empty store).
    fn store(&self) -> PathBuf {
        self.0.join("secrets.toml")
    }

    /// The `config.toml` path (no file: the defaults).
    fn config(&self) -> PathBuf {
        self.0.join("config.toml")
    }

    /// A log with `n` entries whose `args.note` is `note`.
    fn log(&self, n: usize, note: &str) {
        let mut w = AuditWriter::open(&self.audit(), Box::new(SystemClock)).unwrap();
        for i in 0..n {
            let e = NewEntry::new(Actor::Sallyd, "tool.run").args(json!({"i": i, "note": note}));
            w.append(e, AuditLevel::Full).unwrap();
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(f: impl FnOnce(&mut Out<'_>) -> u8) -> (u8, String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = f(&mut Out {
        out: &mut out,
        err: &mut err,
    });
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn a_valid_manifest_is_valid_and_summarized() {
    let s = Scratch::new("valid");
    let m = s.file("m.yaml", VALID);
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_OK, "{err}");
    assert!(
        out.ends_with("valid (sallyd checks again when a session starts)\n"),
        "{out}"
    );
    let (code, out, err) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""));
    assert!(!out.is_empty() && out.ends_with('\n'));
}

#[test]
fn a_rejected_manifest_prints_its_errors_and_no_summary() {
    let s = Scratch::new("reject");
    let m = s.file("m.yaml", &format!("{VALID}bogus: 1\n"));
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
    assert!(err.starts_with("error: "), "{err}");
    let (code, out, _) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
}

/// A manifest granting `GH` on `api.github.com`.
fn granting(s: &Scratch) -> PathBuf {
    granting_with(s, "")
}

/// [`granting`], with `extra` (whole top-level sections) after the model.
fn granting_with(s: &Scratch, extra: &str) -> PathBuf {
    s.file(
        "m.yaml",
        &format!(
            "{VALID}{extra}network:\n  mode: proxy\n  allow:\n    - host: api.github.com\n\
             secrets:\n  - name: GH\n    inject:\n      host: api.github.com\n      header: \
             Authorization\n      format: \"Bearer {{value}}\"\n"
        ),
    )
}

/// Stores `GH` in the scratch store.
fn store_gh(s: &Scratch) {
    let mut store = sally_core::secrets::SecretStore::empty(s.store());
    store
        .set("GH", format!("sp-cli-{}", "v".repeat(20)))
        .unwrap();
    store.save().unwrap();
}

/// A directory removed on drop.
struct Gone(PathBuf);

impl Drop for Gone {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Architect Q221: the CLI reads the store's names as `sallyd` does. A grant of a name the
/// store lacks is refused, naming the `sally secrets set` line; once stored it is valid.
#[test]
fn a_secret_grant_needs_the_name_in_the_store() {
    let s = Scratch::new("secret");
    let m = granting(&s);
    let (code, _, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_REFUSED, "{err}");
    assert!(err.contains("[secret-missing]"), "{err}");
    assert!(err.contains("sally secrets set \"GH\""), "{err}");
    store_gh(&s);
    // Architect Q226: its `[data-can-leave]` warning is plain ASCII, so the run is clean (0).
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(
        out.contains("[data-can-leave]")
            && !out.contains("\\u{")
            && out.ends_with("valid (sallyd checks again when a session starts)\n"),
        "{out}"
    );
    // Its summary ends with the hash of the text read, which a launch's flag names (0).
    let (code, out, _) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_OK, "{out}");
    let text = std::fs::read_to_string(&m).unwrap();
    assert!(
        out.ends_with(&format!("sha256 {}\n", consent::digest(&text).as_hex())),
        "{out}"
    );
}

/// A manifest mounting a folder named `name` (made under the build's target folder, since `/tmp`
/// is denylisted as a mount) with a grant, so the `[data-can-leave]` warning names it: (the
/// scratch, the manifest, the folder as the summary quotes it, the folder's guard).
fn mounting(tag: &str, name: &str) -> (Scratch, PathBuf, String, Gone) {
    let s = Scratch::new(tag);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("sc-loc-{tag}-{}", std::process::id()))
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    let gone = Gone(dir.parent().unwrap().to_owned());
    let real = std::fs::canonicalize(&dir).unwrap();
    let quoted = sally_core::text::quoted_path(real.as_os_str().as_encoded_bytes());
    let m = granting_with(
        &s,
        &format!(
            "filesystem:\n  mounts:\n    - host: \"{}\"\n      guest: /workspace/p\n      \
             mode: ro\n",
            dir.display()
        ),
    );
    store_gh(&s);
    (s, m, quoted, gone)
}

/// RT-MAN-05: a mount path with a letter outside ASCII is shown escaped, quoted alike in the
/// `[data-can-leave]` warning, the summary's first line and its mount line, and can be consented
/// to: `manifest validate` exits 0 and `manifest summary` prints the hash.
#[test]
fn a_non_ascii_letter_in_a_mount_path_is_shown_escaped_and_can_be_accepted() {
    let (s, m, quoted, _gone) = mounting("letter", "caf\u{e9}");
    assert!(quoted.ends_with("/caf\\u{e9}\""), "{quoted}");
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(
        out.contains("[data-can-leave]")
            && out.contains(&quoted)
            && out.ends_with("valid (sallyd checks again when a session starts)\n"),
        "{out}"
    );
    let (code, out, err) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    // The summary on stdout; the warning a launch shows, on stderr.
    assert_eq!(code, EXIT_OK, "{err}");
    assert!(
        err.starts_with("warning: network.allow: ") && err.contains(&quoted),
        "{err}"
    );
    let first = out.lines().next().unwrap_or_default();
    assert!(
        first.starts_with("[data-can-leave] ") && first.contains(&quoted),
        "{out}"
    );
    assert!(
        out.contains(&format!("- can read {quoted} (at /workspace/p).")),
        "{out}"
    );
    let hash = consent::digest(&std::fs::read_to_string(&m).unwrap());
    assert!(
        out.ends_with(&format!("sha256 {}\n", hash.as_hex())),
        "{out}"
    );
}

/// RT-MAN-05, the twin: a direction mark in a mount path (the validator accepts it) is shown
/// escaped too, but a launch never shows it, so `manifest validate` prints `valid` and exits 1,
/// and `manifest summary` prints no hash and exits 1, each naming the line and the escape.
#[test]
fn a_direction_mark_in_a_mount_path_is_shown_escaped_and_starts_nothing() {
    let (s, m, quoted, _gone) = mounting("mark", "a\u{202e}b");
    assert!(quoted.ends_with("/a\\u{202e}b\""), "{quoted}");
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_REFUSED, "{out}{err}");
    assert!(
        out.contains(&quoted)
            && out.ends_with("valid (sallyd checks again when a session starts)\n"),
        "{out}"
    );
    let said = "sally: a launch cannot show this line, so it starts nothing: ";
    assert!(
        err.starts_with(said) && err.contains(&quoted) && err.contains("it holds \\u{202e}"),
        "{err}"
    );
    let (code, out, err) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_REFUSED, "{out}");
    assert!(out.contains(&quoted) && !out.contains("sha256 "), "{out}");
    assert!(
        err.contains(said) && err.contains("it holds \\u{202e}"),
        "{err}"
    );
}

/// A long path of letters outside ASCII pushes the warning past the diagnostic cut (300
/// characters, each letter written as an 8-byte escape): the cut ends before an escape, never
/// inside one, so the block still reads and the manifest can be accepted.
#[test]
fn a_long_non_ascii_mount_path_is_cut_between_escapes_and_can_be_accepted() {
    let (s, m, _, _gone) = mounting("long", &"\u{4e2d}".repeat(40));
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""), "{out}");
    assert!(
        out.contains("... [data-can-leave]"),
        "the warning is cut: {out}"
    );
    let (code, out, err) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_OK, "{err}");
    assert!(out.contains("sha256 "), "{out}");
}

/// Architect Q221: a store that cannot be read fails a manifest naming a secret with 2 (could
/// not read), naming the file and never its text; a manifest naming none never opens it.
#[test]
fn an_unreadable_store_fails_a_grant_and_is_not_opened_without_one() {
    let s = Scratch::new("badstore");
    let path = s.file("secrets.toml", "GH = \"sp-store-text\"\nnot a store\n");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let m = granting(&s);
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!((code, out.as_str()), (EXIT_FAILED, ""), "{err}");
    assert!(
        err.starts_with("sally: ") && err.contains("secrets.toml"),
        "{err}"
    );
    assert!(
        !err.contains("sp-store-text") && !err.contains("secret-missing"),
        "{err}"
    );
    let (code, _, err) = run(|o| manifest_summary(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_FAILED, "{err}");
    let plain = s.file("plain.yaml", VALID);
    let (code, _, err) = run(|o| manifest_validate(&plain, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_OK, "no secret named: {err}");
}

/// The unit twin of the CLI test of the same rule: a binary `config.toml` names makes its
/// folder a denylist rule (1, `denylisted` at the mount). Control: with no `config.toml` the
/// same manifest is valid (0), so the config is what refuses it. A symlinked `config.toml` is
/// never followed: could not read (2), naming the file, on validate and summary alike. The
/// setting's name is pinned by the CLI test and `paths.rs`, not here: a diagnostic is cut at
/// 300 characters, and in a long checkout (a mutation run's copy) the two paths before the
/// name fill them.
#[test]
fn the_folder_of_a_binary_the_config_names_is_refused() {
    let s = Scratch::new("binf");
    // Not below the temp dir: `/tmp` is denylisted as a mount.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../target/sc-loc-binf-{}", std::process::id()));
    let _gone = Gone(dir.clone());
    std::fs::create_dir_all(dir.join("tools/crun")).unwrap();
    let crun = dir.join("tools/crun/crun");
    std::fs::write(&crun, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).unwrap();
    let m = s.file(
        "m.yaml",
        &format!(
            "{VALID}filesystem:\n  mounts:\n    - host: \"{}\"\n      guest: /workspace/t\n      \
             mode: ro\n",
            dir.join("tools").display()
        ),
    );
    let (code, out, err) = run(|o| manifest_validate(&m, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_OK, "control: {out}{err}");
    let config = s.file(
        "config.toml",
        &format!("[sandbox]\nruntime_path = \"{}\"\n", crun.display()),
    );
    for summary in [false, true] {
        let (code, out, err) = run(|o| {
            if summary {
                manifest_summary(&m, files(&s.store(), &config), o)
            } else {
                manifest_validate(&m, files(&s.store(), &config), o)
            }
        });
        assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""), "{err}");
        assert!(
            err.starts_with("error: filesystem.mounts[0].host: ")
                && err.trim_end().ends_with("[denylisted]"),
            "{err}"
        );
    }
    std::fs::remove_file(&config).unwrap();
    std::os::unix::fs::symlink(&crun, &config).unwrap();
    for summary in [false, true] {
        let (code, out, err) = run(|o| {
            if summary {
                manifest_summary(&m, files(&s.store(), &config), o)
            } else {
                manifest_validate(&m, files(&s.store(), &config), o)
            }
        });
        assert_eq!((code, out.as_str()), (EXIT_FAILED, ""), "{err}");
        assert!(
            err.starts_with("sally: ") && err.contains("config.toml: a symlink is not followed"),
            "{err}"
        );
    }
}

#[test]
fn an_unreadable_or_oversized_manifest_fails() {
    let s = Scratch::new("unread");
    let (code, _, err) =
        run(|o| manifest_validate(&s.0.join("absent.yaml"), files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_FAILED, "{err}");
    let big = s.file("big.yaml", &"#".repeat(MAX_MANIFEST_BYTES + 1));
    let (code, _, err) = run(|o| manifest_summary(&big, files(&s.store(), &s.config()), o));
    assert_eq!(code, EXIT_FAILED);
    assert!(err.contains("larger than"), "{err}");
}

#[test]
fn verify_reports_a_good_log_and_names_a_bad_one() {
    let s = Scratch::new("verify");
    s.log(3, "x");
    let (code, out, _) = run(|o| audit_verify(&s.audit(), o));
    assert_eq!(code, EXIT_OK);
    assert_eq!(
        out,
        "ok: 3 entries in 1 file(s), last seq 3, head current\n"
    );
    let file = std::fs::read_dir(s.audit())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replacen("\"i\":1", "\"i\":7", 1)).unwrap();
    let (code, out, err) = run(|o| audit_verify(&s.audit(), o));
    assert_eq!((code, out.as_str()), (EXIT_REFUSED, ""));
    assert!(err.contains("seq 2"), "{err}");
}

/// Architect Q115: a log that cannot be read is exit 2, not a verdict.
#[test]
fn verify_of_a_log_that_cannot_be_read_fails() {
    let s = Scratch::new("verify-io");
    let (code, out, err) = run(|o| audit_verify(&s.0.join("none"), o));
    assert_eq!((code, out.as_str()), (EXIT_FAILED, ""), "{err}");
    s.log(2, "x");
    let file = std::fs::read_dir(s.audit())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    std::fs::remove_file(&file).unwrap();
    std::fs::create_dir(&file).unwrap();
    let (code, _, err) = run(|o| audit_verify(&s.audit(), o));
    assert_eq!(code, EXIT_FAILED, "{err}");
}

#[test]
fn tail_prints_the_newest_entries_escaped() {
    let s = Scratch::new("tail");
    s.log(4, "caf\u{e9}");
    let (code, out, err) = run(|o| audit_tail(&s.audit(), 2, o));
    assert_eq!((code, err.as_str()), (EXIT_OK, ""));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].contains("\"i\":2") && lines[1].contains("\"i\":3"),
        "{out}"
    );
    assert!(out.contains("caf\\u{e9}"), "{out}");
    assert!(
        out.bytes()
            .all(|b| (b' '..=b'~').contains(&b) || b == b'\n')
    );
}

#[test]
fn tail_counts_lines_that_are_not_entries_and_fails() {
    let s = Scratch::new("tailbad");
    s.log(1, "x");
    let file = std::fs::read_dir(s.audit())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .unwrap();
    let mut text = std::fs::read_to_string(&file).unwrap();
    text.push_str("garbage\n");
    std::fs::write(&file, text).unwrap();
    let (code, out, err) = run(|o| audit_tail(&s.audit(), TAIL_DEFAULT, o));
    assert_eq!(code, EXIT_REFUSED);
    assert_eq!(out.lines().count(), 1);
    assert!(
        err.starts_with("sally: 1 line(s) are not audit entries"),
        "{err}"
    );
}

/// Architect Q115: a log that cannot be read is exit 2, and the error names the path.
#[test]
fn tail_of_a_log_that_cannot_be_read_fails_naming_it() {
    let s = Scratch::new("tail-io");
    let none = s.0.join("none");
    let (code, out, err) = run(|o| audit_tail(&none, 5, o));
    assert_eq!((code, out.as_str()), (EXIT_FAILED, ""));
    assert!(err.contains(&none.display().to_string()), "{err}");
}
