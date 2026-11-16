//! Shared fixture of the `sally-shim` relay tests: scratch socket directories, a counting UDS
//! server, an in-process shim and connection helpers.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use sally_shim::{Limiter, ListenSpec, bind, serve};

pub const T: Duration = Duration::from_secs(5);
/// A closed connection must be seen well inside this; a read timeout is a failure.
pub const PROMPT: Duration = Duration::from_secs(2);

pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Self {
        // Short: a Unix socket path is limited to 107 bytes.
        let d = std::env::temp_dir().join(format!("sh{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Self(d)
    }
    pub fn sock(&self) -> PathBuf {
        self.0.join("u.sock")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A UDS server running `handler` on every accepted connection; counts accepts.
pub fn uds_server(path: &Path, handler: fn(UnixStream)) -> Arc<AtomicUsize> {
    let listener = UnixListener::bind(path).unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            thread::spawn(move || handler(conn));
        }
    });
    accepts
}

pub fn echo(mut s: UnixStream) {
    let mut buf = [0u8; 4096];
    loop {
        match s.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if s.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
}

/// Starts a shim on an ephemeral loopback port forwarding to `sock`.
pub fn start_shim(sock: &Path, max: usize) -> SocketAddr {
    start_shim_with(sock, Limiter::new(max))
}

pub fn start_shim_with(sock: &Path, limiter: Arc<Limiter>) -> SocketAddr {
    let spec = ListenSpec {
        addr: "127.0.0.1:0".parse().unwrap(),
        socket: sock.to_owned(),
    };
    let listener = bind(&spec).unwrap();
    let addr = listener.local_addr().unwrap();
    let sock = sock.to_owned();
    thread::spawn(move || {
        let _ = serve(listener, &sock, &limiter);
    });
    addr
}

pub fn connect(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(T)).unwrap();
    s.set_write_timeout(Some(T)).unwrap();
    s
}

pub fn read_exact_vec(s: &mut TcpStream, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    s.read_exact(&mut v).unwrap();
    v
}

pub fn close_at_once(s: UnixStream) {
    drop(s);
}

pub fn read_exact_one(c: &mut TcpStream) -> Option<u8> {
    let mut b = [0u8; 1];
    c.read_exact(&mut b).ok().map(|()| b[0])
}
