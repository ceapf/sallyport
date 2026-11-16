//! Line mode over the real registry (architect Q100–Q102, Q144–Q153): `sessions.attach` runs
//! `podman exec -i` in the session's container, its output arrives as escaped `session.output`
//! notes, `sessions.input` reaches its stdin, and a stop or a dropped connection kills it. A
//! session created with `lifetime: "connection"` stops when its connection ends.

use super::*;

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

/// RT-CLI-01, the notification half: every terminal control the command prints reaches the
/// client as printable text. Control: `sallyd`'s per-stream `StreamEscaper` (`tools/exec.rs`);
/// without it the raw bytes (or their lossy UTF-8) arrive and the text comparison fails.
#[test]
fn rt_cli_01_terminal_controls_reach_the_client_escaped() {
    rt().block_on(async {
        let c = cx();
        let mut w = c.connect();
        let (id, _) = create(&c, &mut w, "cli01", false).await;
        let argv = json!(["sh", "-c", "printf \"$1\"", "sh", HOSTILE]);
        let n = w
            .send("sessions.attach", json!({"id": id, "argv": argv}))
            .await;
        let (reply, notes) = w.until_reply(n).await;
        assert_eq!(reply["result"], json!({"exit_code": 0}), "{reply}");
        assert_eq!(joined(&notes, "stdout"), HOSTILE_ESCAPED);
        assert_eq!(joined(&notes, "stderr"), "");
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
/// escaped text and exits with the command's code. Control: the `StreamEscaper` (as above);
/// without it the CLI's clean-check (`run::show`, through `clean::text`) still escapes, but
/// differently (`\u{fffd}`, `\x0a`), and exits refused. The clean-check, the second layer, has
/// its own tests in sally-cli (`run_tests.rs`).
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
    let argv: Vec<String> = ["sh", "-c", "printf \"$1\"; exit 3", "sh", HOSTILE]
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
    assert_eq!(err, "");
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
        let input = w
            .call(
                "sessions.input",
                json!({"id": id, "data": "one\ntwo\n", "eof": false}),
            )
            .await;
        assert_eq!(input["result"], json!({}), "{input}");
        assert_eq!(w.until_output("stdout", "two\n").await, "one\ntwo\n");
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
            (Some(14), Some(14)),
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
