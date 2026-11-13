//! `control.sock`: the trusted clients' socket (the CLI, the UI bridge; ARCHITECTURE §4.1). Its
//! method table is separate from the session socket's and never shared with it (architect ruling
//! Q1). Task 7 builds the listener, the framing (1 MiB frames) and the peer-UID check; the table
//! is empty until Task 12 fills it, so every method is `-32601`.
//!
//! Every request is recorded before its reply, like the session socket's.

use std::future::Future;
use std::sync::Arc;

use sally_core::audit::Actor;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::watch;

use super::agent::{WRITE_TIMEOUT, error_object, failure};
use super::frame::{self, Frame};
use super::listen::{self, Server, until_true};
use super::mcp::CONTROL_METHODS;
use super::message::{self, INVALID_REQUEST, METHOD_NOT_FOUND, Message};
use super::record::{Recorder, escape};

/// Largest frame accepted (ARCHITECTURE §4: 1 MiB on the control socket).
pub const MAX_FRAME: usize = 1024 * 1024;
/// Control connections at once.
pub const MAX_CONNECTIONS: usize = 16;

/// The control socket's server.
pub struct Control {
    record: Recorder,
    stop: watch::Sender<bool>,
}

impl Control {
    /// A server recording into `record` (its entries carry no session).
    #[must_use]
    pub fn new(record: Recorder) -> Self {
        Self {
            record,
            stop: watch::Sender::new(false),
        }
    }

    /// Serves `listener` (`control.sock`) for peers with `uid`; a panicking connection is
    /// reported to the daemon's `crash` reporter (it stops every session).
    pub fn listen(
        self: Arc<Self>,
        listener: tokio::net::UnixListener,
        uid: u32,
        crash: listen::CrashReporter,
    ) -> listen::Handle {
        listen::spawn(listener, self, MAX_CONNECTIONS, uid, "control.sock", crash)
    }

    /// Serves one stream to its end.
    pub async fn serve_stream<S: AsyncRead + AsyncWrite + Send + 'static>(
        self: Arc<Self>,
        stream: S,
    ) {
        let (r, mut w) = tokio::io::split(stream);
        let mut reader = BufReader::new(r);
        let stopped = until_true(self.stop.subscribe());
        tokio::pin!(stopped);
        loop {
            let frame = tokio::select! {
                biased;
                () = &mut stopped => break,
                f = frame::read(&mut reader, MAX_FRAME) => f,
            };
            let reply = match frame {
                Ok(Frame::Line(line)) => match self.handle(&line).await {
                    Some(reply) => reply,
                    None => break,
                },
                Ok(Frame::TooLarge) => {
                    if self.deny(None, "frame-too-large").await {
                        let _ = write(
                            &mut w,
                            &failure(None, error_object(INVALID_REQUEST, "frame-too-large")),
                        )
                        .await;
                    }
                    break;
                }
                Ok(Frame::Eof) | Err(_) => break,
            };
            if !reply.is_empty() && !write(&mut w, &reply).await {
                break;
            }
        }
    }

    /// The reply to one frame (empty for none); `None` closes the connection (a failed append).
    async fn handle(&self, line: &[u8]) -> Option<Vec<u8>> {
        let (id, method, reason, code) = match message::parse(line) {
            Err(r) => (r.id, None, r.reason.as_str(), r.reason.code()),
            Ok(Message::Response) => {
                return self.deny(None, "unexpected-response").await.then(Vec::new);
            }
            Ok(Message::Notification { method, .. }) => {
                return self
                    .deny(Some(&method), "method-not-found")
                    .await
                    .then(Vec::new);
            }
            Ok(Message::Request { id, method, .. }) => {
                // Task 12 dispatches the methods of CONTROL_METHODS here.
                debug_assert!(!CONTROL_METHODS.contains(&method.as_str()));
                (Some(id), Some(method), "method-not-found", METHOD_NOT_FOUND)
            }
        };
        if !self.deny(method.as_deref(), reason).await {
            return None;
        }
        Some(failure(id.as_ref(), error_object(code, reason)))
    }

    async fn deny(&self, method: Option<&str>, reason: &str) -> bool {
        let mut args = json!({"socket": "control", "reason": reason});
        if let (Some(m), Some(a)) = (method, args.as_object_mut()) {
            a.insert("method".into(), Value::from(escape(m.as_bytes())));
        }
        let entry = self
            .record
            .entry(Actor::User, "rpc.deny", Some("deny"))
            .args(args);
        self.record.append(entry).await
    }
}

impl Server for Control {
    fn serve(self: Arc<Self>, stream: UnixStream) -> impl Future<Output = ()> + Send {
        self.serve_stream(stream)
    }

    async fn refuse_peer(self: Arc<Self>, uid: Option<u32>) {
        let entry = self
            .record
            .entry(Actor::Sallyd, "rpc.deny", Some("deny"))
            .args(json!({"socket": "control", "reason": "peer-uid", "uid": uid}));
        let _ = self.record.append(entry).await;
    }

    fn stop(&self) {
        self.stop.send_replace(true);
    }
}

/// Writes one reply within [`WRITE_TIMEOUT`]; whether it was written.
async fn write<W: AsyncWrite + Unpin>(w: &mut W, line: &[u8]) -> bool {
    matches!(
        tokio::time::timeout(WRITE_TIMEOUT, w.write_all(line)).await,
        Ok(Ok(()))
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::rpc::testkit::recorder;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};

    async fn exchange(lines: &[&[u8]]) -> (Vec<Value>, Vec<crate::rpc::testkit::Row>) {
        let (sink, rec) = recorder("");
        let control = Arc::new(Control::new(rec));
        let (client, server) = tokio::io::duplex(4 * MAX_FRAME);
        let task = tokio::spawn(Arc::clone(&control).serve_stream(server));
        let (r, mut w) = tokio::io::split(client);
        for l in lines {
            w.write_all(l).await.unwrap();
            w.write_all(b"\n").await.unwrap();
        }
        w.shutdown().await.unwrap();
        let mut replies = Vec::new();
        let mut r = BufReader::new(r);
        let mut line = String::new();
        while r.read_line(&mut line).await.unwrap() > 0 {
            replies.push(serde_json::from_str(&line).unwrap());
            line.clear();
        }
        task.await.unwrap();
        (replies, sink.rows())
    }

    #[test]
    fn the_control_table_is_empty_until_task_12() {
        assert!(CONTROL_METHODS.is_empty());
    }

    #[test]
    fn frames_are_capped_at_1_mib() {
        assert_eq!(MAX_FRAME, 1_048_576);
    }

    #[tokio::test]
    async fn stop_ends_a_live_connection() {
        let (_, rec) = recorder("");
        let control = Arc::new(Control::new(rec));
        let (_client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(Arc::clone(&control).serve_stream(server));
        tokio::task::yield_now().await;
        Server::stop(&*control);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("stop left the connection open")
            .unwrap();
    }

    #[tokio::test]
    async fn a_peer_with_another_uid_is_refused_and_recorded() {
        let dir = std::env::temp_dir().join(format!("sp-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (sink, rec) = recorder("");
        let me = rustix::process::getuid().as_raw();
        let (crash, _crashes) = crate::rpc::listen::CrashReporter::channel();
        let h = crate::rpc::listen::spawn(
            listener,
            Arc::new(Control::new(rec)),
            1,
            me.wrapping_add(1),
            "control.sock",
            crash,
        );
        let mut s = UnixStream::connect(&path).await.unwrap();
        let _ = s.write_all(b"{}\n").await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        assert!(out.is_empty());
        assert_eq!(
            sink.last("rpc.deny"),
            json!({"socket": "control", "reason": "peer-uid", "uid": me})
        );
        h.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn every_method_is_not_found_and_recorded() {
        let (replies, rows) = exchange(&[
            br#"{"jsonrpc":"2.0","id":1,"method":"secrets.set","params":{}}"#,
            br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","method":"sessions.stop"}"#,
            br#"{"jsonrpc":"2.0","id":3,"result":{}}"#,
            b"[1]",
        ])
        .await;
        let codes: Vec<_> = replies
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].clone()))
            .collect();
        assert_eq!(
            codes,
            [
                (json!(1), json!(-32601)),
                (json!(2), json!(-32601)),
                (Value::Null, json!(-32600)),
            ]
        );
        let reasons: Vec<_> = rows
            .iter()
            .map(|r| r.args["reason"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            reasons,
            [
                "method-not-found",
                "method-not-found",
                "method-not-found",
                "unexpected-response",
                "batch"
            ]
        );
        assert!(
            rows.iter()
                .all(|r| r.event == "rpc.deny" && r.args["socket"] == json!("control"))
        );
        assert!(rows.iter().all(|r| r.debug.contains("session: None")));
        assert_eq!(rows[0].args["method"], json!("secrets.set"));
    }

    #[tokio::test]
    async fn frames_up_to_one_mib_are_read() {
        let mut exact = br#"{"jsonrpc":"2.0","id":1,"method":"m"}"#.to_vec();
        exact.splice(1..1, std::iter::repeat_n(b' ', MAX_FRAME - exact.len()));
        let mut over = exact.clone();
        over.insert(1, b' ');
        let (replies, rows) = exchange(&[&exact, &over]).await;
        assert_eq!(
            replies[0]["error"]["data"]["reason"],
            json!("method-not-found")
        );
        assert_eq!(
            replies[1]["error"]["data"]["reason"],
            json!("frame-too-large")
        );
        assert_eq!(
            replies.len(),
            2,
            "the connection closes after an oversize frame"
        );
        assert_eq!(rows.len(), 2);
    }
}
