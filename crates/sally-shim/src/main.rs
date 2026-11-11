//! `sally-shim` binary: see the library docs.
#![forbid(unsafe_code)]

use std::io::{Write, stderr, stdin, stdout};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;

use sally_shim::args::USAGE;
use sally_shim::{Limiter, Mode, bind, parse_args, serve, stdio};

/// Writes a line to stderr, ignoring failure: `eprintln!` panics on a closed stderr.
fn say(msg: &str) {
    let _ = writeln!(stderr(), "{msg}");
}

fn main() -> ExitCode {
    // Non-UTF-8 arguments are a usage error (exit 2), not a panic.
    let args: Option<Vec<String>> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().ok())
        .collect();
    let parsed = args
        .ok_or_else(|| sally_shim::ArgError("argument is not valid UTF-8".to_owned()))
        .and_then(parse_args);
    let mode = match parsed {
        Ok(m) => m,
        Err(e) => {
            say(&format!("sally-shim: {e}\n{USAGE}"));
            return ExitCode::from(2);
        }
    };
    match run(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            say(&format!("sally-shim: {e}"));
            ExitCode::from(1)
        }
    }
}

fn run(mode: Mode) -> std::io::Result<()> {
    match mode {
        Mode::Stdio(socket) => stdio(&socket, stdin(), stdout().lock()),
        Mode::Listen {
            specs,
            max_connections,
        } => {
            // Bind everything first so a bad port fails the whole start, not one listener.
            let mut bound = Vec::new();
            for spec in specs {
                bound.push((bind(&spec)?, spec.socket));
            }
            // Readiness, part of the binary's contract (crate docs): one line per listener, only
            // after every bind succeeded, giving the bound address and never the socket path.
            for (listener, _) in &bound {
                say(&format!(
                    "sally-shim: listening on {}",
                    listener.local_addr()?
                ));
            }
            let limiter = Limiter::new(max_connections);
            let (tx, rx) = mpsc::channel();
            for (listener, socket) in bound {
                let (tx, limiter) = (tx.clone(), limiter.clone());
                thread::spawn(move || {
                    let _ = tx.send(serve(listener, &socket, &limiter));
                });
            }
            drop(tx);
            // Any listener ending takes the whole process down: half a service is worse than a
            // visible failure the broker can see and act on.
            match rx.recv() {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::other("listener threads vanished")),
            }
        }
    }
}
