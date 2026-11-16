//! Line mode over the real registry (architect Q100–Q102, Q144–Q153): `sessions.attach` runs
//! `podman exec -i` in the session's container, its output arrives as escaped `session.output`
//! notes, `sessions.input` reaches its stdin, and a stop or a dropped connection kills it. A
//! session created with `lifetime: "connection"` stops when its connection ends.

use super::*;
use common::egress::{canary, tls_upstream};
use common::forms::{basic_blob, basic_forms, forms_of};
use common::intercept::{self, body_and_length, filled, get_req, gh, header_values, rendered};
use common::search::{Plants, Scope, fixed_patterns, found, search_script};

/// Every terminal control the escaper must neutralize: CSI, OSC 52 (clipboard), OSC 8 (link)
/// ended by ST, a raw C1 CSI byte (0x9b, not UTF-8), U+009B, U+202E and `\r`. A `printf` format.
const HOSTILE: &str =
    r"a\033[31mb\033]52;c;eA==\007\033]8;;http://x\033\\l\233\302\233\342\200\256\rz\n";

/// [`HOSTILE`]'s output as `session.output` carries it (and as `sally sandbox run` prints it).
const HOSTILE_ESCAPED: &str =
    "a\\x1b[31mb\\x1b]52;c;eA==\\x07\\x1b]8;;http://x\\x1b\\\\l\\x9b\\u{9b}\\u{202e}\\x0dz\n";

/// How many bytes [`HOSTILE`] prints.
const HOSTILE_RAW_LEN: u64 = 44;

/// A command that waits until it is killed; its argument marks it in `ps`.
const SLEEP: [&str; 2] = ["sleep", "4123456"];

impl Wire {
    /// Sends a request and returns its id; the reply is read with [`Wire::until_reply`].
    async fn send(&mut self, method: &str, params: Value) -> i64 {
        let id = self.next;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.next += 1;
        self.w
            .write_all(format!("{req}\n").as_bytes())
            .await
            .unwrap();
        id
    }

    /// Reads frames until the reply to `id`; the `session.output` notes before it, in order.
    async fn until_reply(&mut self, id: i64) -> (Value, Vec<Value>) {
        let mut notes = Vec::new();
        loop {
            let f = self.frame().await;
            if f["id"] == json!(id) {
                return (f, notes);
            }
            assert_eq!(f["method"], "session.output", "{f}");
            notes.push(f["params"].clone());
        }
    }

    /// Reads `session.output` notes until their `stream` text holds `needle`.
    async fn until_output(&mut self, stream: &str, needle: &str) -> String {
        let mut text = String::new();
        while !text.contains(needle) {
            let f = self.frame().await;
            assert_eq!(f["method"], "session.output", "{f}");
            if f["params"]["stream"] == stream {
                text.push_str(f["params"]["text"].as_str().unwrap());
            }
        }
        text
    }
}

/// The text of `stream` in `notes`, joined.
fn joined(notes: &[Value], stream: &str) -> String {
    notes
        .iter()
        .filter(|n| n["stream"] == stream)
        .map(|n| n["text"].as_str().unwrap())
        .collect()
}

/// Creates a session over `w` (bound to it when `bound`): its id and container.
async fn create(c: &Cx, w: &mut Wire, dir: &str, bound: bool) -> (String, String) {
    std::fs::create_dir_all(c.x.f.root.join("home/code").join(dir)).unwrap();
    let text = format!(
        "{HEADER}{}",
        mounts(&[mount(&format!("~/code/{dir}"), "/workspace/p", "rw")])
    );
    let mut params = json!({"manifest": text});
    if bound {
        params["lifetime"] = json!("connection");
    }
    let r = w.call("sessions.create", params).await;
    let s = &r["result"];
    let id = s["id"].as_str().expect("created").to_owned();
    (id, s["container"].as_str().unwrap().to_owned())
}

/// The position of the first entry `event` whose args satisfy `f`.
fn at(c: &Cx, event: &str, f: impl Fn(&Value) -> bool) -> Option<usize> {
    c.x.events
        .all()
        .iter()
        .position(|(e, a)| e == event && f(a))
}

/// Waits until an entry `event` with args satisfying `f` is written; its position.
async fn until_entry(c: &Cx, event: &str, f: impl Fn(&Value) -> bool) -> usize {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        if let Some(i) = at(c, event, &f) {
            return i;
        }
        assert!(std::time::Instant::now() < end, "no {event}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How many `session.stop` entries were written.
fn stops(c: &Cx) -> usize {
    c.x.events
        .all()
        .iter()
        .filter(|(e, _)| e == "session.stop")
        .count()
}

/// `ps` in `container` shows the marked [`SLEEP`].
async fn sleeping(container: &str) -> bool {
    let c = container.to_owned();
    let (code, out) = tokio::task::spawn_blocking(move || exec_in(&c, &["ps"]))
        .await
        .unwrap();
    assert_eq!(code, 0, "{out}");
    out.contains(SLEEP[1])
}

/// What the RT-CLI-01 commands print on stderr: plain text, so stderr is compared by equality
/// against a stream that carries something (the allowed case), never only checked for absence.
const STDERR_MARK: &str = "cli01-stderr\n";
/// Prints the hostile `$1` on stdout, then [`STDERR_MARK`] on stderr.
const STDERR_SCRIPT: &str = "printf \"$1\"; echo cli01-stderr >&2";

/// RT-CLI-01, the notification half: every terminal control the command prints reaches the
/// client as printable text. Control: `sallyd`'s per-stream `StreamEscaper` (`tools/pipe.rs`);
/// without it the raw bytes (or their lossy UTF-8) arrive and the text comparison fails.
/// Allowed case: the command's plain stderr line arrives on stderr exactly, and nothing else.
#[test]
fn rt_cli_01_terminal_controls_reach_the_client_escaped() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, _) = create(&c, &mut w, "cli01", false).await;
        let argv = json!(["sh", "-c", STDERR_SCRIPT, "sh", HOSTILE]);
        let n = w
            .send("sessions.attach", json!({"id": id, "argv": argv}))
            .await;
        let (reply, notes) = w.until_reply(n).await;
        assert_eq!(reply["result"], json!({"exit_code": 0}), "{reply}");
        assert_eq!(joined(&notes, "stdout"), HOSTILE_ESCAPED);
        assert_eq!(joined(&notes, "stderr"), STDERR_MARK);
        for n in &notes {
            let t = n["text"].as_str().unwrap();
            assert!(
                t.bytes().all(|b| b == b'\n' || (0x20..0x7f).contains(&b)),
                "{t:?}"
            );
        }
        let result = until_entry(&c, "sandbox.exec_result", |_| true).await;
        let all = c.x.events.all();
        assert_eq!(all[result].1["exit_code"], 0);
        assert_eq!(all[result].1["stdout_bytes"], HOSTILE_RAW_LEN);
        w.call("sessions.stop", json!({"id": id})).await;
    });
}

/// RT-CLI-01, the CLI half: `sally sandbox run` over a real `control.sock` prints exactly the
/// escaped text, on stderr exactly the command's own plain line (the allowed case) and nothing
/// of its own, and exits with the command's code. Control: the `StreamEscaper` (as above);
/// without it the CLI's clean-check (`run::show`, through `clean::text`) still escapes, but
/// differently (`\u{fffd}`, `\x0a`), adds its not-clean line on stderr and exits 1, so the
/// stdout, stderr and code assertions all fail. The clean-check, the second layer, has its own
/// tests in sally-cli (`run_tests.rs`).
#[test]
fn rt_cli_01_sally_sandbox_run_prints_the_escaped_text() {
    let c = cx();
    std::fs::create_dir_all(c.x.f.root.join("home/code/cli01b")).unwrap();
    let manifest = c.x.f.root.join("cli01.yaml");
    std::fs::write(
        &manifest,
        format!(
            "{HEADER}{}",
            mounts(&[mount("~/code/cli01b", "/workspace/p", "rw")])
        ),
    )
    .unwrap();
    let served = Served::start(&c, "cli01");
    let mut client = sally_cli::client::Client::connect(&served.path).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let script = format!("{STDERR_SCRIPT}; exit 3");
    let argv: Vec<String> = ["sh", "-c", script.as_str(), "sh", HOSTILE]
        .map(str::to_owned)
        .to_vec();
    let code = {
        let mut o = sally_cli::commands::Out {
            out: &mut out,
            err: &mut err,
        };
        sally_cli::run::sandbox_run(&mut client, &manifest, &argv, std::io::empty(), &mut o)
    };
    let (out, err) = (
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    );
    assert_eq!((code, out.as_str()), (3, HOSTILE_ESCAPED), "{err}");
    assert_eq!(err, STDERR_MARK);
    drop(client);
    served.stop();
    // The run stopped its session; the request is the CLI's own `sessions.stop`.
    assert_eq!(
        c.x.events
            .all()
            .iter()
            .filter(|(e, a)| e == "session.stop" && a["reason"] == "request")
            .count(),
        1
    );
}

/// The control server on a Unix socket, on a runtime of its own.
struct Served {
    path: std::path::PathBuf,
    dir: std::path::PathBuf,
    stop: tokio::sync::oneshot::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl Served {
    fn start(c: &Cx, tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sp-ctl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("control.sock");
        let me = rustix::process::getuid().as_raw();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let (control, sock) = (Arc::clone(&c.control), path.clone());
        let thread = std::thread::spawn(move || {
            rt().block_on(async move {
                let (crash, _crashes) = sallyd::daemon::crash::CrashReporter::channel();
                let l = tokio::net::UnixListener::bind(&sock).unwrap();
                let h = control.listen(l, me, crash);
                ready_tx.send(()).unwrap();
                let _ = stop_rx.await;
                h.shutdown().await;
            });
        });
        ready_rx.recv().unwrap();
        Self {
            path,
            dir,
            stop,
            thread,
        }
    }

    fn stop(self) {
        self.stop.send(()).unwrap();
        self.thread.join().unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Input reaches a real `cat` while it runs (`-i` keeps its stdin open: its echo arrives before
/// any reply), `eof` ends it, and each stream keeps its own order.
#[test]
fn input_reaches_the_attached_command_and_eof_ends_it() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, _) = create(&c, &mut w, "cat", false).await;
        let n = w
            .send("sessions.attach", json!({"id": id, "argv": ["cat"]}))
            .await;
        // Ctrl-P Ctrl-Q (podman's default detach keys) are data, not a detach.
        let first = w
            .send(
                "sessions.input",
                json!({"id": id, "data": "one\u{10}\u{11}\ntwo\n", "eof": false}),
            )
            .await;
        let (input, early) = w.until_reply(first).await;
        assert_eq!(input["result"], json!({}), "{input}");
        let mut echoed = joined(&early, "stdout");
        if !echoed.contains("two\n") {
            echoed.push_str(&w.until_output("stdout", "two\n").await);
        }
        assert_eq!(echoed, "one\\x10\\x11\ntwo\n");
        let last = w
            .send(
                "sessions.input",
                json!({"id": id, "data": "three\n", "eof": true}),
            )
            .await;
        let (ack, before) = w.until_reply(last).await;
        assert_eq!(ack["result"], json!({}), "{ack}");
        let (reply, after) = w.until_reply(n).await;
        assert_eq!(reply["result"], json!({"exit_code": 0}), "{reply}");
        let rest = [before, after].concat();
        assert_eq!(joined(&rest, "stdout"), "three\n");
        let result = until_entry(&c, "sandbox.exec_result", |_| true).await;
        let args = c.x.events.all()[result].1.clone();
        assert_eq!(
            (args["stdin_bytes"].as_u64(), args["stdout_bytes"].as_u64()),
            (Some(16), Some(16)),
            "{args}"
        );
        // The two streams are kept apart, each in its own order.
        let n = w
            .send(
                "sessions.attach",
                json!({"id": id, "argv": ["sh", "-c", "echo 1; echo 2 >&2; echo 3; echo 4 >&2"]}),
            )
            .await;
        let (reply, notes) = w.until_reply(n).await;
        assert_eq!(reply["result"], json!({"exit_code": 0}), "{reply}");
        assert_eq!(
            (joined(&notes, "stdout"), joined(&notes, "stderr")),
            ("1\n3\n".to_owned(), "2\n4\n".to_owned())
        );
        w.call("sessions.stop", json!({"id": id})).await;
    });
}

/// Maintainer Q202: an attached command's bytes reach the audit log and the operational log only
/// as counts. A canary goes in through `sessions.input` (never argv, which is audited) and comes
/// back on both streams; the control is that the client sees it on each. No audit entry and no
/// oplog line carries it, and `sandbox.exec_result` counts every byte of it. The session runs at
/// the default `audit.level`, full (architect Q223), and the test sink keeps every entry's
/// arguments whatever the level, so no level could record more than is checked here.
#[test]
fn attached_bytes_reach_the_logs_only_as_counts() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, _) = create(&c, &mut w, "counts", false).await;
        let canary = format!("sp-output-canary-{}", "q".repeat(24));
        let argv = ["sh", "-c", "read l; echo \"$l\"; echo \"$l\" >&2"];
        let n = w
            .send("sessions.attach", json!({"id": id, "argv": argv}))
            .await;
        let input = w
            .send(
                "sessions.input",
                json!({"id": id, "data": format!("{canary}\n"), "eof": true}),
            )
            .await;
        let (ack, before) = w.until_reply(input).await;
        assert_eq!(ack["result"], json!({}), "{ack}");
        let (reply, after) = w.until_reply(n).await;
        assert_eq!(reply["result"], json!({"exit_code": 0}), "{reply}");
        let notes = [before, after].concat();
        let line = format!("{canary}\n");
        assert_eq!(
            (joined(&notes, "stdout"), joined(&notes, "stderr")),
            (line.clone(), line.clone()),
            "control: the canary came back on both streams"
        );
        let result = until_entry(&c, "sandbox.exec_result", |_| true).await;
        let args = c.x.events.all()[result].1.clone();
        let len = line.len() as u64;
        assert_eq!(
            (
                args["stdin_bytes"].as_u64(),
                args["stdout_bytes"].as_u64(),
                args["stderr_bytes"].as_u64()
            ),
            (Some(len), Some(len), Some(len)),
            "{args}"
        );
        w.call("sessions.stop", json!({"id": id})).await;
        let audited: Vec<String> =
            c.x.events
                .all()
                .iter()
                .map(|(e, a)| format!("{e} {a}"))
                .filter(|t| t.contains(&canary))
                .collect();
        assert_eq!(audited, Vec::<String>::new());
        assert!(c.oplog.flush(Duration::from_secs(10)), "the oplog drained");
        let logged = c.log.text();
        assert!(!logged.contains(&canary), "{logged}");
    });
}

/// Q102 (a): a bound session whose connection ends before any attach stops `disconnect`, and
/// its container is gone.
#[test]
fn a_bound_session_stops_when_its_connection_ends() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, container) = create(&c, &mut w, "bound", true).await;
        assert!(exists(&container));
        drop(w);
        // Each test has its own registry and log: `session.stop` names no id in its args.
        until_entry(&c, "session.stop", |a| a["reason"] == "disconnect").await;
        gone(&container).await;
        assert_eq!(at(&c, "session.refuse", |a| a["id"] == json!(id)), None);
        // An unbound session outlives its connection.
        let mut w = c.connect();
        let (free, container) = create(&c, &mut w, "unbound", false).await;
        drop(w);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(exists(&container));
        assert_eq!(stops(&c), 1, "the unbound session stopped");
        c.connect().call("sessions.stop", json!({"id": free})).await;
    });
}

/// Q102 (b): a connection dropped mid-exec kills the command (`killed: disconnect`), and then
/// its bound session stops; the result is written before the stop.
#[test]
fn a_bound_session_dropped_mid_exec_kills_the_command_then_stops() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, container) = create(&c, &mut w, "midexec", true).await;
        w.send("sessions.attach", json!({"id": id, "argv": SLEEP}))
            .await;
        until_entry(&c, "sandbox.exec", |_| true).await;
        let end = std::time::Instant::now() + Duration::from_secs(60);
        while !sleeping(&container).await {
            assert!(std::time::Instant::now() < end, "the command never ran");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        drop(w);
        let stop = until_entry(&c, "session.stop", |a| a["reason"] == "disconnect").await;
        let result = at(&c, "sandbox.exec_result", |a| a["killed"] == "disconnect")
            .expect("the exec's result");
        assert!(result < stop, "the result follows session.stop");
    });
}

/// Q102 (b), unbound: the dropped connection kills the command and leaves no exec process in
/// the container, which keeps running.
#[test]
fn a_dropped_connection_leaves_no_exec_process_behind() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, container) = create(&c, &mut w, "noproc", false).await;
        w.send("sessions.attach", json!({"id": id, "argv": SLEEP}))
            .await;
        let end = std::time::Instant::now() + Duration::from_secs(60);
        while !sleeping(&container).await {
            assert!(std::time::Instant::now() < end, "the command never ran");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        drop(w);
        until_entry(&c, "sandbox.exec_result", |a| a["killed"] == "disconnect").await;
        assert!(
            !sleeping(&container).await,
            "the exec process is still there"
        );
        assert!(exists(&container));
        assert_eq!(stops(&c), 0, "the session stopped");
        c.connect().call("sessions.stop", json!({"id": id})).await;
    });
}

/// Q101: a stop during an attach answers it `killed: session-stop`, and the exec's result is
/// written before `session.stop`.
#[test]
fn a_stop_during_an_attach_kills_it_before_session_stop() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, container) = create(&c, &mut w, "stopexec", false).await;
        let n = w
            .send("sessions.attach", json!({"id": id, "argv": SLEEP}))
            .await;
        let end = std::time::Instant::now() + Duration::from_secs(60);
        while !sleeping(&container).await {
            assert!(std::time::Instant::now() < end, "the command never ran");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let stopped = c.connect().call("sessions.stop", json!({"id": id})).await;
        assert_eq!(stopped["result"], json!({"id": id}), "{stopped}");
        let (reply, _) = w.until_reply(n).await;
        assert_eq!(
            reply["result"],
            json!({"killed": "session-stop"}),
            "{reply}"
        );
        let result = at(&c, "sandbox.exec_result", |a| a["killed"] == "session-stop")
            .expect("the exec's result");
        let stop = at(&c, "session.stop", |a| a["reason"] == "request").unwrap();
        assert!(result < stop, "the result follows session.stop");
        gone(&container).await;
    });
}

/// Waits until `container` no longer exists; panics after 60 s.
async fn gone(container: &str) {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while exists(container) {
        assert!(
            std::time::Instant::now() < end,
            "the container is still there"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `manifests/examples/coding-agent.yaml` as M1 Acceptance line 1 runs it (architect Q217):
/// read at test time, with exactly two lines replaced. `runtime.image` names the developer test
/// image (with the shim) by digest, since no product image exists (#88, Q199); `runtime.cpus`
/// drops from 6 to 2, since the validator refuses more CPUs than the host has and CI runners
/// have four. Every other line is the example's own, asserted.
fn line_1_manifest() -> String {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../manifests/examples/coding-agent.yaml");
    let example = std::fs::read_to_string(path).unwrap();
    let image = format!("  image: {}", net_image().as_str());
    let mut text = String::new();
    for line in example.lines() {
        let line = if line.trim_start().starts_with("image: ") {
            image.as_str()
        } else if line.trim_start().starts_with("cpus: ") {
            "  cpus: 2"
        } else {
            line
        };
        text.push_str(line);
        text.push('\n');
    }
    let differ: Vec<(&str, &str)> = example
        .lines()
        .zip(text.lines())
        .filter(|(a, b)| a != b)
        .collect();
    assert_eq!(
        differ.len(),
        2,
        "runtime.image and runtime.cpus only: {differ:?}"
    );
    assert_eq!(example.lines().count(), text.lines().count());
    text
}

/// The hosts the example allows; each resolves to the TLS mock upstream.
const LINE_1_HOSTS: [&str; 4] = [
    "pypi.org",
    "files.pythonhosted.org",
    "api.github.com",
    "github.com",
];

/// What the line 1 shell checks and prints, in order, once the shim listens; then it waits on
/// stdin until the host-side half is done. No secret value is in it, and none goes in on stdin.
/// The image's busybox has no client that sends `CONNECT` (its `wget` sends absolute-form
/// requests), so the proxy checks write one raw with `nc` (architect Q218).
const LINE_1_SCRIPT: &str = "\
i=0
until grep -q 'listening on 127.0.0.1:3128' /tmp/shim.log 2>/dev/null; do
  i=$((i+1)); [ $i -lt 60 ] || break; sleep 1
done
echo \"dns:$(nslookup pypi.org >/dev/null 2>&1 && echo ok || echo fail)\"
echo \"tcp:$(nc -w 2 192.0.2.10 443 </dev/null >/dev/null 2>&1 && echo ok || echo fail)\"
for h in pypi.org api.github.com example.org; do
  printf 'CONNECT %s:443 HTTP/1.1\\r\\nHost: %s:443\\r\\n\\r\\n' $h $h | nc -w 3 127.0.0.1 3128 \\
    | head -n 1 | tr -d '\\r' | sed \"s/^/connect $h: /\"
done
echo \"workspace:$(ls -A /workspace | tr '\\n' ' ')\"
echo \"ca:$(sha256sum /run/sallyport/session-ca.pem | cut -d ' ' -f 1)\"
echo \"gh_token:$GH_TOKEN\"
echo ready
read go
";

/// The forms of `GITHUB_TOKEN`'s canary the example's two grants make (raw and encodings, the
/// rendered `Bearer` value, the `x-access-token` `{basic}` forms), the marker, the search's own
/// mark and the planted blob: what RT-SEC-01/02's search looks for.
fn line_1_patterns(mark: &str, planted_blob: &str) -> Vec<String> {
    let gh = canary("GITHUB_TOKEN");
    let mut p = vec![
        mark.to_owned(),
        "SALLY_CANARY".to_owned(),
        planted_blob.to_owned(),
    ];
    p.extend(forms_of(&gh));
    p.push(format!("Bearer {gh}"));
    p.extend(basic_forms("x-access-token", &gh));
    p
}

/// RT-SEC-01/02's search of a live container, within 120 s: what it found.
async fn line_1_search(container: &str) -> Vec<String> {
    let mark = "sp-line-1-search";
    let planted = format!("SALLY_CANARY_PLANTED_{}", std::process::id());
    let blob = basic_blob("planted", &format!("{planted}/+?&= {}", "p".repeat(7)));
    let files = format!(
        "printf '%s' '{planted}' > /tmp/planted.txt\nprintf '%s' '{blob}' > /tmp/planted-blob.txt\n"
    );
    let plants = Plants {
        files: &files,
        shm: &planted,
        process: &blob,
    };
    let script = search_script(
        mark,
        &plants,
        &fixed_patterns(&line_1_patterns(mark, &blob)),
        Scope::All,
    );
    let container = container.to_owned();
    let search = tokio::task::spawn_blocking(move || exec_in(&container, &["sh", "-c", &script]));
    let (code, out) = tokio::time::timeout(Duration::from_secs(120), search)
        .await
        .expect("the search ended within 120 s")
        .unwrap();
    assert_eq!(code, 0, "{out}");
    found(&out)
}

/// M1 Acceptance line 1 through `sally sandbox run` in line mode (maintainer Q199, Q201;
/// architect Q217, Q218): the example manifest ([`line_1_manifest`]), a session made by
/// `sessions.create` with egress and the `GITHUB_TOKEN` grants, one `sh` attached. It is also
/// the proof that `sessions.create` starts egress when the manifest grants it (Q201).
///
/// In the shell: DNS and direct TCP fail; a raw `CONNECT` through `127.0.0.1:3128` is 200 for
/// `pypi.org` and `api.github.com` and 403 for `example.org`; `/workspace` holds only
/// `myproject`; `GH_TOKEN` is the placeholder. While the session lives, RT-SEC-01/02's search
/// finds no form of the canary in the container (only its planted controls), and the TLS leg
/// (Q47: the image has no TLS client) runs host-side over the same session's `net.sock`,
/// trusting the session CA whose hash the shell printed: the mock upstream gets
/// `Authorization: Bearer <canary>`, its echoes come back as filler of the same length, and
/// after the run the `egress.response` entry names `secret:GITHUB_TOKEN` and the bytes.
/// Controls: the 200s (the proxy works, so the 403 and the failures are policy), the planted
/// search hits, and the upstream receiving the credential (so the filler is redaction).
/// TODO(#88): the in-container `curl -x … https://…` form once an image with curl exists.
#[test]
fn m1_acceptance_line_1_through_sally_sandbox_run() {
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    rt().block_on(async {
        let c = cx();
        std::fs::create_dir_all(c.x.f.root.join("home/code/myproject")).unwrap();
        let manifest = c.x.f.root.join("coding-agent.yaml");
        std::fs::write(&manifest, line_1_manifest()).unwrap();
        for host in LINE_1_HOSTS {
            c.x.egress.resolver.set(host, vec![vec![tls_upstream()]]);
        }
        let served = Served::start(&c, "line1");
        let (go, stdin) = std::os::unix::net::UnixStream::pair().unwrap();
        let (out, err) = (Lines::default(), Lines::default());
        let run = {
            let path = served.path.clone();
            let manifest = manifest.clone();
            let (mut o_out, mut o_err) = (out.clone(), err.clone());
            std::thread::spawn(move || {
                let mut client = sally_cli::client::Client::connect(&path).unwrap();
                let argv = ["sh", "-c", LINE_1_SCRIPT].map(str::to_owned).to_vec();
                let mut o = sally_cli::commands::Out {
                    out: &mut o_out,
                    err: &mut o_err,
                };
                sally_cli::run::sandbox_run(&mut client, &manifest, &argv, stdin, &mut o)
            })
        };
        let end = std::time::Instant::now() + Duration::from_secs(120);
        while !out.text().contains("ready\n") {
            assert!(
                std::time::Instant::now() < end && !run.is_finished(),
                "no ready line: {} / {}",
                out.text(),
                err.text()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The live session, found over a second control connection.
        let listed = c.connect().call("sessions.list", json!({})).await;
        let s = &listed["result"]["sessions"][0];
        let id = s["id"].as_str().unwrap().to_owned();
        let container = s["container"].as_str().unwrap().to_owned();
        let tag = id
            .strip_prefix(&format!("{}-", c.x.scope))
            .unwrap()
            .to_owned();
        assert_eq!(
            line_1_search(&container).await,
            [
                "/proc/<planted>/cmdline",
                "/proc/<planted>/environ",
                "/tmp/planted-blob.txt",
                "/tmp/planted.txt",
            ]
        );
        // The TLS leg over this session's net.sock, trusting the session CA.
        let ca = std::fs::read(c.x.paths(&tag).workspace_sockets().join("session-ca.pem")).unwrap();
        let ca_hash: String = Sha256::digest(&ca)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let req = get_req("api.github.com", "/echo-headers", "");
        let resp = intercept::over(&c.x, &tag, "api.github.com", &req).await;
        let seen = c.x.egress.dialer.seen();
        let got = seen
            .iter()
            .find(|r| r.starts_with("GET /echo-headers"))
            .expect("the upstream got the request");
        assert_eq!(
            header_values(got, "authorization"),
            [rendered()],
            "control: the credential reached the upstream"
        );
        assert!(!resp.contains(&gh()), "{resp}");
        let (body, n) = body_and_length(&resp);
        assert_eq!((body, n), (filled(got).as_str(), got.len()));
        // Let the shell end; the run stops its session.
        (&go).write_all(b"go\n").unwrap();
        drop(go);
        let code = run.join().unwrap();
        assert_eq!((code, err.text().as_str()), (0, ""), "{}", out.text());
        let lines: Vec<String> = out.text().lines().map(str::to_owned).collect();
        assert_eq!(lines.len(), 9, "{lines:?}");
        assert_eq!(lines[..2], ["dns:fail", "tcp:fail"], "{lines:?}");
        assert!(
            lines[2].starts_with("connect pypi.org: HTTP/1.1 200 "),
            "{lines:?}"
        );
        assert!(
            lines[3].starts_with("connect api.github.com: HTTP/1.1 200 "),
            "{lines:?}"
        );
        assert!(
            lines[4].starts_with("connect example.org: HTTP/1.1 403 "),
            "{lines:?}"
        );
        assert_eq!(
            lines[5..],
            [
                "workspace:myproject ".to_owned(),
                format!("ca:{ca_hash}"),
                "gh_token:sallyport-placeholder".to_owned(),
                "ready".to_owned(),
            ]
        );
        served.stop();
        let entries = intercept::responses(&c.x, "api.github.com");
        assert_eq!(entries.len(), 1, "{entries:?}");
        let bytes = 2 * rendered().len();
        assert_eq!(
            entries[0]["redacted"],
            json!([{"secret": "secret:GITHUB_TOKEN", "bytes": bytes}])
        );
        assert_eq!(stops(&c), 1);
    });
}
