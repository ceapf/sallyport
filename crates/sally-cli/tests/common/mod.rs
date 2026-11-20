//! A fake `sallyd` for the `sally` binary's tests (architect Q79). The fake listens where the
//! binary looks, under a temporary `$XDG_RUNTIME_DIR`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    dead_code
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

/// A fake daemon answering each request with `reply(request)`, keeping every request.
pub struct Fake {
    pub runtime: PathBuf,
    pub requests: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    pub fn new(tag: &str, reply: impl Fn(&Value) -> String + Send + 'static) -> Self {
        // Short: the socket path below must fit SUN_LEN under a deep TMPDIR (the mutation runs'
        // target/mutants-tmp), so tags stay short too.
        let runtime = std::env::temp_dir().join(format!("sc-{tag}-{}", std::process::id()));
        assert!(tag.len() <= 8, "tag {tag:?}: keep it short");
        let _ = std::fs::remove_dir_all(&runtime);
        std::fs::create_dir_all(runtime.join("sallyport")).unwrap();
        let listener = UnixListener::bind(runtime.join("sallyport/control.sock")).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reqs = Arc::clone(&requests);
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(s) = conn else { return };
                let mut w = s.try_clone().unwrap();
                for l in BufReader::new(s).lines() {
                    let Ok(l) = l else { break };
                    let req: Value = serde_json::from_str(&l).unwrap();
                    reqs.lock().unwrap().push(req.clone());
                    let _ = w.write_all(reply(&req).as_bytes());
                }
            }
        });
        Self { runtime, requests }
    }

    /// The binary with `args`, pointed at this fake.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sally"));
        c.args(args).env("XDG_RUNTIME_DIR", &self.runtime);
        c
    }

    pub fn sally(&self, args: &[&str]) -> Output {
        self.command(args).output().unwrap()
    }

    pub fn methods(&self) -> Vec<String> {
        let reqs = self.requests.lock().unwrap();
        reqs.iter()
            .map(|r| r["method"].as_str().unwrap().to_owned())
            .collect()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.runtime);
    }
}

/// A result frame for `req`, as one line.
pub fn result(req: &Value, r: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": req["id"], "result": r})
    )
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}
