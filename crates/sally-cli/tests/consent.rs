//! RT-MAN-03 through the binary, against a fake `sallyd`: a launch (`sally session start`,
//! `sally sandbox run`) shows what its manifest grants before it asks for anything, refuses a
//! manifest kept inside a folder that manifest lets the session write, and needs consent bound to
//! the exact text it sends, whatever its warnings: the text's SHA-256 (`--accept-manifest`), or
//! with no hash a `yes` typed on a terminal. Each property runs once per command through one
//! helper.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{Fake, result, stderr, stdout};
use serde_json::json;

const HEAD: &str = "apiVersion: sallyport/v1\nkind: Manifest\nname: t\nmodel:\n  ref: any\n";

/// One acknowledged risk and its warning: shell commands run unapproved.
const RISKY: &str = "tools:\n  builtin: [shell]\n  shell: allow\n  \
                     destructive_requires_approval: false\n  acknowledge_unapproved: [shell]\n";

/// What the launch shows for [`RISKY`]'s acknowledgement.
const ACKNOWLEDGED: &str = "acknowledged: tools.acknowledge_unapproved: shell";

/// The question asked on a terminal.
const QUESTION: &str = "Start a session with this manifest? Type yes to start: ";

/// How long a step may take before the test gives up on it.
const WAIT: Duration = Duration::from_secs(20);

/// The two launch commands.
#[derive(Clone, Copy, Debug)]
enum Launch {
    Start,
    Run,
}

impl Launch {
    /// The command line for `manifest`, with `extra` options before any `--`.
    fn args(self, manifest: &Path, extra: &[&str]) -> Vec<String> {
        let m = manifest.to_str().unwrap().to_owned();
        let mut a: Vec<String> = match self {
            Self::Start => vec!["session".into(), "start".into(), m],
            Self::Run => vec!["sandbox".into(), "run".into(), "--manifest".into(), m],
        };
        a.extend(extra.iter().map(|s| (*s).to_owned()));
        if let Self::Run = self {
            a.extend(["--".to_owned(), "true".to_owned()]);
        }
        a
    }
}

/// A home folder for the binary, holding the folder `p` the manifests mount. It lives under the
/// build's own temporary folder: a mount under `/tmp` or `$XDG_RUNTIME_DIR` is denylisted.
struct Home(PathBuf);

impl Home {
    fn new(tag: &str) -> Self {
        let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("sc-h-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("p")).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(d)
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    fn write(&self, rel: &str, text: &str) -> PathBuf {
        let p = self.join(rel);
        std::fs::write(&p, text).unwrap();
        p
    }

    /// `c` with this home's `$HOME` and XDG folders.
    fn apply<'c>(&self, c: &'c mut Command) -> &'c mut Command {
        c.env("HOME", &self.0)
            .env("XDG_CONFIG_HOME", self.0.join(".config"))
            .env("XDG_DATA_HOME", self.0.join(".local/share"))
            .env("XDG_STATE_HOME", self.0.join(".local/state"))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fake answering `sessions.create` with a running session and anything else with `{}`;
/// `on_create` runs when the create arrives, before the reply.
fn daemon(tag: &str, on_create: impl Fn() + Send + 'static) -> Fake {
    Fake::new(tag, move |req| {
        if req["method"] == "sessions.create" {
            on_create();
            let none = json!({"kind": "none", "driven": false});
            let s = json!({"id": "s-1", "manifest": "t", "container": "sp-w-s-1",
                           "state": "running", "model": none});
            return result(req, s);
        }
        result(req, json!({}))
    })
}

/// The manifest text of each `sessions.create` the fake received.
fn created(f: &Fake) -> Vec<String> {
    let reqs = f.requests.lock().unwrap();
    reqs.iter()
        .filter(|r| r["method"] == "sessions.create")
        .map(|r| r["params"]["manifest"].as_str().unwrap().to_owned())
        .collect()
}

/// A launch off a terminal (stdin is not one).
fn launch(f: &Fake, h: &Home, l: Launch, manifest: &Path, extra: &[&str]) -> Output {
    let args = l.args(manifest, extra);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    h.apply(&mut f.command(&args))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

/// [`launch`] with its stderr written to the file `err` as it goes, so a fake can read what was
/// shown when a request arrives.
fn launch_logged(
    f: &Fake,
    h: &Home,
    l: Launch,
    manifest: &Path,
    extra: &[&str],
    err: &Path,
) -> Output {
    let args = l.args(manifest, extra);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    h.apply(&mut f.command(&args))
        .stdin(Stdio::null())
        .stderr(std::fs::File::create(err).unwrap())
        .output()
        .unwrap()
}

/// A fake that keeps what the file `err` held when each `sessions.create` arrived: (the fake,
/// the last such text, taken by the reader).
fn daemon_seeing(tag: &str, err: &Path) -> (Fake, Arc<Mutex<Option<String>>>) {
    let seen: Arc<Mutex<Option<String>>> = Arc::default();
    let (path, at_create) = (err.to_owned(), Arc::clone(&seen));
    let f = daemon(tag, move || {
        // Taken and removed, so a later create from a launch whose stderr is not logged reads
        // no file and keeps an empty text.
        *at_create.lock().unwrap() = Some(std::fs::read_to_string(&path).unwrap_or_default());
        let _ = std::fs::remove_file(&path);
    });
    (f, seen)
}

/// `sally manifest summary`'s output for `manifest`: (summary lines, the hash on its last line).
fn reviewed(f: &Fake, h: &Home, manifest: &Path) -> (String, String) {
    let o = h
        .apply(&mut f.command(&["manifest", "summary", manifest.to_str().unwrap()]))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = stdout(&o);
    let body = out.trim_end_matches('\n');
    let (summary, last) = body.rsplit_once('\n').unwrap();
    let hash = last.strip_prefix("sha256 ").unwrap();
    assert_eq!(hash.len(), 64, "{last}");
    (format!("{summary}\n"), hash.to_owned())
}

/// What `sally manifest summary` prints on stderr for `manifest`.
fn summary_err(f: &Fake, h: &Home, manifest: &Path) -> String {
    let o = h
        .apply(&mut f.command(&["manifest", "summary", manifest.to_str().unwrap()]))
        .output()
        .unwrap();
    stderr(&o)
}

/// The warning lines `sally manifest validate` prints for `manifest`.
fn warnings(f: &Fake, h: &Home, manifest: &Path) -> Vec<String> {
    let o = h
        .apply(&mut f.command(&["manifest", "validate", manifest.to_str().unwrap()]))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    let out = stdout(&o);
    let lines: Vec<String> = out.lines().map(ToOwned::to_owned).collect();
    let (_, warned) = lines.split_last().unwrap();
    assert!(!warned.is_empty(), "the fixture must warn: {out}");
    warned.to_vec()
}

fn mount(mode: &str) -> String {
    format!(
        "{HEAD}filesystem:\n  mounts:\n    - {{host: \"~/p\", guest: /workspace/p, mode: {mode}}}\n"
    )
}

// ---- the summary and the warnings come first ---------------------------------------------------

fn shows_the_summary_and_warnings_before_the_create(l: Launch, tag: &str) {
    let h = Home::new(tag);
    let text = format!("{HEAD}{RISKY}");
    let m = h.write("m.yaml", &text);
    let err_file = h.join("stderr");
    let (f, seen) = daemon_seeing(tag, &err_file);
    let (summary, hash) = reviewed(&f, &h, &m);
    let warned = warnings(&f, &h, &m);
    let o = launch_logged(&f, &h, l, &m, &["--accept-manifest", &hash], &err_file);
    assert_eq!(created(&f), [text], "{l:?}: {}", stdout(&o));
    // What was on stderr when the create arrived, not after the command ended.
    let shown = seen.lock().unwrap().clone().unwrap();
    assert!(shown.contains(&summary), "{l:?}: {shown}");
    for w in &warned {
        assert!(shown.contains(w.as_str()), "{l:?}: {w} not in {shown}");
    }
    assert!(shown.contains(ACKNOWLEDGED), "{l:?}: {shown}");
    assert!(
        !shown.contains(&hash),
        "{l:?}: the hash is never printed: {shown}"
    );
}

#[test]
fn rt_man_03_session_start_shows_the_summary_and_warnings_before_the_create() {
    shows_the_summary_and_warnings_before_the_create(Launch::Start, "sum-s");
}

#[test]
fn rt_man_03_sandbox_run_shows_the_summary_and_warnings_before_the_create() {
    shows_the_summary_and_warnings_before_the_create(Launch::Run, "sum-r");
}

// ---- every launch needs consent, whatever its warnings ------------------------------------------

/// Asserts `sally manifest validate` finds no warning in `manifest` (and accepts it).
fn assert_no_warning(f: &Fake, h: &Home, manifest: &Path) {
    let o = h
        .apply(&mut f.command(&["manifest", "validate", manifest.to_str().unwrap()]))
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o).lines().count(), 1, "a warning: {}", stdout(&o));
}

/// A manifest with no warning and no acknowledged risk needs consent too. Off a terminal, a
/// manifest of nothing but its header is sent only with its hash, its summary already on stderr
/// when the create arrives. The file rewritten after the review into another valid text with no
/// warning: no hash sends nothing, the reviewed text's hash refuses, the new text's hash sends
/// exactly the new text.
fn every_launch_needs_consent(l: Launch, tag: &str) {
    let h = Home::new(tag);
    let err_file = h.join("stderr");
    let (f, seen) = daemon_seeing(tag, &err_file);
    let m = h.write("m.yaml", HEAD);
    assert_no_warning(&f, &h, &m);
    let (summary, reviewed_hash) = reviewed(&f, &h, &m);
    let o = launch(&f, &h, l, &m, &[]);
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    assert!(stderr(&o).contains("--accept-manifest"), "{}", stderr(&o));
    // Control: the same launch with the text's hash is sent, after its summary was shown.
    let o = launch_logged(
        &f,
        &h,
        l,
        &m,
        &["--accept-manifest", &reviewed_hash],
        &err_file,
    );
    assert_eq!(created(&f), [HEAD], "{l:?}: {}", stdout(&o));
    let shown = seen.lock().unwrap().take().unwrap();
    assert!(shown.contains(&summary), "{l:?}: {shown}");

    // Rewritten after the review into another valid text with no warning: a folder mounted.
    let rewritten = mount("ro");
    std::fs::write(&m, &rewritten).unwrap();
    assert_no_warning(&f, &h, &m);
    let o = launch(&f, &h, l, &m, &[]);
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &reviewed_hash]);
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    assert!(
        stderr(&o).contains("not the text --accept-manifest names"),
        "{}",
        stderr(&o)
    );
    assert_eq!(created(&f), [HEAD], "{l:?}: nothing more sent");
    let (_, new) = reviewed(&f, &h, &m);
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &new]);
    assert_eq!(
        created(&f),
        [HEAD.to_owned(), rewritten],
        "{l:?}: {}",
        stderr(&o)
    );
}

#[test]
fn rt_man_03_session_start_needs_consent_for_a_manifest_with_no_warning() {
    every_launch_needs_consent(Launch::Start, "any-s");
}

#[test]
fn rt_man_03_sandbox_run_needs_consent_for_a_manifest_with_no_warning() {
    every_launch_needs_consent(Launch::Run, "any-r");
}

// ---- a manifest inside a folder it lets the session write ------------------------------------

fn refuses_a_manifest_inside_a_folder_it_mounts_writable(l: Launch, tag: &str) {
    let h = Home::new(tag);
    let f = daemon(tag, || {});
    // Each refusal leg launches with the hash of its own text, so consent is given and the exit
    // code and the empty create log are the place check's alone.
    for mode in ["rw", "brokered"] {
        let m = h.write("p/m.yaml", &mount(mode));
        let (_, hash) = reviewed(&f, &h, &m);
        let o = launch(&f, &h, l, &m, &["--accept-manifest", &hash]);
        assert_eq!(o.status.code(), Some(1), "{l:?} {mode}: {}", stderr(&o));
        assert!(
            stderr(&o).contains("inside filesystem.mounts[0]")
                && stderr(&o).contains("which the session can write"),
            "{l:?} {mode}: {}",
            stderr(&o)
        );
        assert!(f.methods().is_empty(), "{l:?} {mode}: {:?}", f.methods());
        // The same manifest reached through a name inside the folder: the session can re-point it.
        std::fs::remove_file(&m).unwrap();
        let outside = h.write("m.yaml", &mount(mode));
        let link = h.join("p/link.yaml");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let (_, hash) = reviewed(&f, &h, &link);
        let o = launch(&f, &h, l, &link, &["--accept-manifest", &hash]);
        assert_eq!(
            o.status.code(),
            Some(1),
            "{l:?} {mode} link: {}",
            stderr(&o)
        );
        assert!(
            stderr(&o).contains("which the session can write"),
            "{l:?} {mode} link: {}",
            stderr(&o)
        );
        assert!(f.methods().is_empty(), "{l:?} {mode}: {:?}", f.methods());
        std::fs::remove_file(&link).unwrap();
    }
    // Control: staged and read-only mounts never refuse; with its hash, the create is sent.
    for mode in ["staged", "ro"] {
        let text = mount(mode);
        let m = h.write("p/m.yaml", &text);
        let (_, hash) = reviewed(&f, &h, &m);
        let o = launch(&f, &h, l, &m, &["--accept-manifest", &hash]);
        assert_eq!(
            created(&f).last(),
            Some(&text),
            "{l:?} {mode}: {}",
            stderr(&o)
        );
    }
}

#[test]
fn rt_man_03_session_start_refuses_a_manifest_inside_a_folder_it_mounts_writable() {
    refuses_a_manifest_inside_a_folder_it_mounts_writable(Launch::Start, "in-s");
}

#[test]
fn rt_man_03_sandbox_run_refuses_a_manifest_inside_a_folder_it_mounts_writable() {
    refuses_a_manifest_inside_a_folder_it_mounts_writable(Launch::Run, "in-r");
}

// ---- off a terminal: the hash of the text sent ------------------------------------------------

fn off_a_terminal_needs_the_hash_of_the_text_it_sends(l: Launch, tag: &str) {
    let h = Home::new(tag);
    let f = daemon(tag, || {});
    let first = format!("{HEAD}{RISKY}");
    let m = h.write("m.yaml", &first);
    // No flag: refused, naming the flag and where to find the hash, never the hash.
    let (_, old) = reviewed(&f, &h, &m);
    let o = launch(&f, &h, l, &m, &[]);
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    assert!(stderr(&o).contains("--accept-manifest"), "{}", stderr(&o));
    assert!(
        stderr(&o).contains("sally manifest summary"),
        "{}",
        stderr(&o)
    );
    assert!(!stderr(&o).contains(&old) && !stdout(&o).contains(&old));
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // A malformed value: a fixed text that repeats nothing, before anything is sent.
    let o = launch(&f, &h, l, &m, &["--accept-manifest", "MARKq7zX"]);
    assert_eq!(o.status.code(), Some(2), "{l:?}: {}", stderr(&o));
    assert!(!stderr(&o).contains("MARKq7zX"), "{}", stderr(&o));
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // The file rewritten into another valid, wider manifest after the review: the old hash
    // refuses it, the new summary is shown, the new hash is not.
    let wider = format!("{}{RISKY}", mount("rw"));
    std::fs::write(&m, &wider).unwrap();
    let (summary, new) = reviewed(&f, &h, &m);
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &old]);
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    assert!(stderr(&o).contains(&summary), "{l:?}: {}", stderr(&o));
    assert!(!stderr(&o).contains(&new) && !stdout(&o).contains(&new));
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // Control: the hash of the text on disk sends exactly that text.
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &new]);
    assert_eq!(
        created(&f),
        std::slice::from_ref(&wider),
        "{l:?}: {}",
        stderr(&o)
    );

    // The hash names the text, not the folders: a host written through a link could mount
    // another folder later with the same text. Control first: the folder written as itself.
    std::fs::create_dir_all(h.join("real/sub")).unwrap();
    std::os::unix::fs::symlink(h.join("real"), h.join("link")).unwrap();
    let host = |written: &str| {
        format!(
            "{HEAD}filesystem:\n  mounts:\n    - {{host: \"{written}\", guest: /workspace/p, \
             mode: rw}}\n{RISKY}"
        )
    };
    let direct = host("~/real/sub");
    std::fs::write(&m, &direct).unwrap();
    let (_, hash) = reviewed(&f, &h, &m);
    let as_written = "filesystem.mounts[0].host is written";
    assert!(!summary_err(&f, &h, &m).contains(as_written));
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &hash]);
    assert_eq!(
        created(&f),
        [wider.clone(), direct.clone()],
        "{l:?}: {}",
        stderr(&o)
    );
    std::fs::write(&m, host("~/link/sub")).unwrap();
    // The review says so too, and still gives the hash (a terminal's yes can accept it).
    let (_, hash) = reviewed(&f, &h, &m);
    let said = summary_err(&f, &h, &m);
    assert!(
        said.contains(&format!("{as_written} \"~/link/sub\"")),
        "{said}"
    );
    let o = launch(&f, &h, l, &m, &["--accept-manifest", &hash]);
    assert_eq!(o.status.code(), Some(1), "{l:?}: {}", stderr(&o));
    assert!(
        stderr(&o).contains("filesystem.mounts[0].host is written \"~/link/sub\""),
        "{l:?}: {}",
        stderr(&o)
    );
    assert!(!stderr(&o).contains(&hash), "{}", stderr(&o));
    assert_eq!(created(&f), [wider, direct], "{l:?}: nothing more sent");
}

#[test]
fn rt_man_03_session_start_off_a_terminal_needs_the_hash_of_the_text_it_sends() {
    off_a_terminal_needs_the_hash_of_the_text_it_sends(Launch::Start, "off-s");
}

#[test]
fn rt_man_03_sandbox_run_off_a_terminal_needs_the_hash_of_the_text_it_sends() {
    off_a_terminal_needs_the_hash_of_the_text_it_sends(Launch::Run, "off-r");
}

// ---- on a terminal: a typed yes ---------------------------------------------------------------

/// A pseudo-terminal: (controller, terminal).
fn pty() -> (std::fs::File, std::fs::File) {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    use std::os::unix::fs::OpenOptionsExt;
    let controller = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
    grantpt(&controller).unwrap();
    unlockpt(&controller).unwrap();
    let name = ptsname(&controller, Vec::new()).unwrap();
    let terminal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::NOCTTY.bits().cast_signed())
        .open(name.to_str().unwrap())
        .unwrap();
    (std::fs::File::from(controller), terminal)
}

/// A launch whose stdin is a terminal that is also its controlling terminal (`setsid --ctty`),
/// with `typed_ahead` already waiting in the terminal's input before it starts.
struct OnTerminal {
    child: Child,
    controller: std::fs::File,
    screen: Arc<Mutex<Vec<u8>>>,
    /// Copies the terminal's output into `screen`; it ends once the launch's end closes the
    /// terminal's last descriptor.
    reader: std::thread::JoinHandle<()>,
}

impl OnTerminal {
    fn spawn(f: &Fake, h: &Home, l: Launch, manifest: &Path, extra: &[&str], ahead: &str) -> Self {
        let (mut controller, terminal) = pty();
        controller.write_all(ahead.as_bytes()).unwrap();
        let mut c = Command::new("setsid");
        c.arg("--ctty")
            .arg("--wait")
            .arg(env!("CARGO_BIN_EXE_sally"))
            .args(l.args(manifest, extra))
            .env("XDG_RUNTIME_DIR", &f.runtime)
            .stdin(terminal)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = h.apply(&mut c).spawn().unwrap();
        let screen: Arc<Mutex<Vec<u8>>> = Arc::default();
        let (mut reader, shown) = (controller.try_clone().unwrap(), Arc::clone(&screen));
        let copier = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok(n @ 1..) = reader.read(&mut buf) {
                shown.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self {
            child,
            controller,
            screen,
            reader: copier,
        }
    }

    /// What the terminal showed so far.
    fn screen(&self) -> String {
        String::from_utf8_lossy(&self.screen.lock().unwrap()).into_owned()
    }

    /// Waits until the question is on the terminal.
    fn asked(&self) -> String {
        let end = Instant::now() + WAIT;
        loop {
            let s = self.screen();
            if s.contains(QUESTION) {
                return s;
            }
            assert!(Instant::now() < end, "no question on the terminal: {s:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn answer(&mut self, line: &str) {
        self.controller.write_all(line.as_bytes()).unwrap();
    }

    /// The exit code and stderr, once the launch ends.
    fn end(self) -> (Option<i32>, String) {
        let (code, err, _) = self.end_seen();
        (code, err)
    }

    /// [`end`](Self::end), and what the terminal showed by then.
    fn end_seen(mut self) -> (Option<i32>, String, String) {
        let end = Instant::now() + WAIT;
        while self.child.try_wait().unwrap().is_none() {
            if Instant::now() >= end {
                let _ = self.child.kill();
                panic!("the launch did not end: {:?}", self.screen());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Everything the launch wrote is on the screen once the copier has seen the terminal
        // close (bounded: a copier still running after the wait leaves the screen as read).
        let end = Instant::now() + WAIT;
        while !self.reader.is_finished() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let screen = self.screen();
        let o = self.child.wait_with_output().unwrap();
        (o.status.code(), stderr(&o), screen)
    }
}

fn on_a_terminal_needs_a_typed_yes_or_the_hash(l: Launch, tag: &str) {
    let h = Home::new(tag);
    let f = daemon(tag, || {});
    let text = format!("{HEAD}{RISKY}");
    let m = h.write("m.yaml", &text);
    let (summary, hash) = reviewed(&f, &h, &m);
    // A yes typed ahead is discarded; the answer given after the question decides.
    let mut t = OnTerminal::spawn(&f, &h, l, &m, &[], "yes\n");
    let screen = t.asked();
    assert!(
        screen.contains(summary.lines().next().unwrap()),
        "{screen:?}"
    );
    assert!(screen.contains(ACKNOWLEDGED), "{screen:?}");
    t.answer("no\n");
    let (code, err) = t.end();
    assert_eq!(code, Some(1), "{l:?}: {err}");
    assert!(err.contains("not started"), "{l:?}: {err}");
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // The end of input refuses.
    let mut t = OnTerminal::spawn(&f, &h, l, &m, &[], "");
    t.asked();
    t.answer("\x04");
    let (code, err) = t.end();
    assert_eq!(code, Some(1), "{l:?}: {err}");
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // A hash of another text refuses on a terminal too, and nothing is asked.
    let other = h.write("other.yaml", HEAD);
    let (_, wrong) = reviewed(&f, &h, &other);
    let t = OnTerminal::spawn(&f, &h, l, &m, &["--accept-manifest", &wrong], "");
    let (code, err, screen) = t.end_seen();
    assert_eq!(code, Some(1), "{l:?}: {err}");
    assert!(
        err.contains("not the text --accept-manifest names"),
        "{l:?}: {err}"
    );
    assert!(!screen.contains(QUESTION), "{l:?}: {screen:?}");
    assert!(f.methods().is_empty(), "{l:?}: {:?}", f.methods());
    // The right hash replaces the yes: nothing is asked, the block is on stderr, and the text
    // is sent.
    let t = OnTerminal::spawn(&f, &h, l, &m, &["--accept-manifest", &hash], "");
    let (_, err, screen) = t.end_seen();
    assert_eq!(created(&f), std::slice::from_ref(&text), "{l:?}: {err}");
    assert!(err.contains(ACKNOWLEDGED), "{l:?}: {err}");
    assert!(!screen.contains(QUESTION), "{l:?}: {screen:?}");
    // The hash names the text, not the folders: on a terminal too, a host written through a
    // link refuses the hash, and nothing is asked.
    std::fs::create_dir_all(h.join("real/sub")).unwrap();
    std::os::unix::fs::symlink(h.join("real"), h.join("link")).unwrap();
    let linked = format!(
        "{HEAD}filesystem:\n  mounts:\n    - {{host: \"~/link/sub\", guest: /workspace/p, \
         mode: rw}}\n{RISKY}"
    );
    let via = h.write("via.yaml", &linked);
    let (_, via_hash) = reviewed(&f, &h, &via);
    let t = OnTerminal::spawn(&f, &h, l, &via, &["--accept-manifest", &via_hash], "");
    let (code, err, screen) = t.end_seen();
    assert_eq!(code, Some(1), "{l:?}: {err}");
    assert!(
        err.contains("filesystem.mounts[0].host is written \"~/link/sub\""),
        "{l:?}: {err}"
    );
    assert!(!screen.contains(QUESTION), "{l:?}: {screen:?}");
    assert_eq!(
        created(&f),
        std::slice::from_ref(&text),
        "{l:?}: nothing more sent"
    );
    // Control: yes, typed after the question, starts and sends the text shown.
    let mut t = OnTerminal::spawn(&f, &h, l, &m, &[], "");
    t.asked();
    t.answer("yes\n");
    let (_, err) = t.end();
    assert_eq!(created(&f), [text.clone(), text.clone()], "{l:?}: {err}");
    // A manifest with no warning is asked too.
    let mut t = OnTerminal::spawn(&f, &h, l, &other, &[], "");
    let screen = t.asked();
    assert!(screen.contains("This agent:"), "{l:?}: {screen:?}");
    t.answer("yes\n");
    let (_, err) = t.end();
    assert_eq!(
        created(&f),
        [text.clone(), text, HEAD.to_owned()],
        "{l:?}: {err}"
    );
}

/// The CLI reads `config.toml` as `sallyd` does: a binary it names makes that binary's folder a
/// denylist rule, and the refusal names the setting. Control: with no `config.toml` the same
/// manifest is valid and its hash starts it. A `config.toml` that cannot be read fails (2),
/// naming it, before anything is shown or sent, on the hash path too.
#[test]
fn the_cli_refuses_the_folder_of_a_binary_its_config_names() {
    let f = daemon("binf", || {});
    let h = Home::new("binf");
    std::fs::create_dir_all(h.join("tools/crun")).unwrap();
    let crun = h.write("tools/crun/crun", "#!/bin/sh\n");
    std::fs::set_permissions(&crun, std::fs::Permissions::from_mode(0o755)).unwrap();
    let text = format!(
        "{HEAD}filesystem:\n  mounts:\n    - {{host: \"~/tools\", guest: /workspace/t, mode: rw}}\n"
    );
    let m = h.write("m.yaml", &text);
    let validate = || {
        h.apply(&mut f.command(&["manifest", "validate", m.to_str().unwrap()]))
            .output()
            .unwrap()
    };
    let (_, hash) = reviewed(&f, &h, &m);
    let o = validate();
    assert_eq!(o.status.code(), Some(0), "control: {}", stderr(&o));
    std::fs::create_dir_all(h.join(".config/sallyport")).unwrap();
    let config = h.write(
        ".config/sallyport/config.toml",
        &format!("[sandbox]\nruntime_path = \"{}\"\n", crun.display()),
    );
    let o = validate();
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    let err = stderr(&o);
    assert!(
        err.contains("filesystem.mounts[0].host")
            && err.contains("(the folder of sandbox.runtime_path)")
            && err.contains("denylisted"),
        "{err}"
    );
    // Unreadable: a symlink is never followed.
    std::fs::remove_file(&config).unwrap();
    std::os::unix::fs::symlink(&crun, &config).unwrap();
    let o = validate();
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(stderr(&o).contains("config.toml: a symlink is not followed"));
    let o = launch(&f, &h, Launch::Start, &m, &["--accept-manifest", &hash]);
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    let err = stderr(&o);
    assert_eq!(err.lines().count(), 1, "nothing shown before: {err}");
    assert!(
        err.contains("config.toml: a symlink is not followed"),
        "{err}"
    );
    assert_eq!(created(&f), Vec::<String>::new());
    // Control: the config gone, the same hash starts the same text.
    std::fs::remove_file(&config).unwrap();
    let o = launch(&f, &h, Launch::Start, &m, &["--accept-manifest", &hash]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(created(&f), [text]);
}

#[test]
fn rt_man_03_session_start_on_a_terminal_needs_a_typed_yes_or_the_hash() {
    on_a_terminal_needs_a_typed_yes_or_the_hash(Launch::Start, "tty-s");
}

#[test]
fn rt_man_03_sandbox_run_on_a_terminal_needs_a_typed_yes_or_the_hash() {
    on_a_terminal_needs_a_typed_yes_or_the_hash(Launch::Run, "tty-r");
}
