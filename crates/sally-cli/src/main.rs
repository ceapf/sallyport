//! `sally`: parse the arguments, run one command, exit with its code. Everything else is in the
//! library, where it is tested.
#![forbid(unsafe_code)]

use std::io::{BufReader, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sally_cli::approve::{Tty, approve};
use sally_cli::client::{Client, socket_path};
use sally_cli::commands::{self, Out, failed};
use sally_cli::{EXIT_FAILED, clean};

/// Talk to `sallyd`: start, list and stop sessions, see what they staged, answer approvals.
#[derive(Parser)]
#[command(name = "sally", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sessions.
    Session {
        #[command(subcommand)]
        cmd: SessionCmd,
    },
    /// List the prompts waiting for an answer.
    Approvals,
    /// Answer prompts as they come, on this terminal.
    Approve,
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Start a session from a manifest file.
    Start {
        /// The manifest.
        manifest: PathBuf,
    },
    /// List the live sessions.
    List,
    /// Stop a session.
    Stop {
        /// The session id.
        id: String,
    },
    /// List what a session staged (live or stopped).
    Changes {
        /// The session id.
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let text = clean::text(&e.render().to_string()).text;
            if e.use_stderr() {
                let _ = write!(std::io::stderr(), "{text}");
            } else {
                let _ = write!(std::io::stdout(), "{text}");
            }
            return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(EXIT_FAILED));
        }
    };
    ExitCode::from(run(cli.cmd))
}

fn run(cmd: Cmd) -> u8 {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    // The terminal first: without one, `approve` exits before it watches (architect Q80).
    let tty = match cmd {
        Cmd::Approve => match open_tty() {
            Ok(t) => Some(t),
            Err(e) => {
                let _ = writeln!(stderr, "sally: approve needs a terminal (/dev/tty): {e}");
                return EXIT_FAILED;
            }
        },
        _ => None,
    };
    let mut client = match socket_path().and_then(|p| Client::connect(&p)) {
        Ok(c) => c,
        Err(e) => return failed(&e, &mut stderr),
    };
    let mut o = Out {
        out: &mut stdout,
        err: &mut stderr,
    };
    match cmd {
        Cmd::Session { cmd } => match cmd {
            SessionCmd::Start { manifest } => {
                commands::session_start(&mut client, &manifest, &mut o)
            }
            SessionCmd::List => commands::session_list(&mut client, &mut o),
            SessionCmd::Stop { id } => commands::session_stop(&mut client, &id, &mut o),
            SessionCmd::Changes { id } => commands::session_changes(&mut client, &id, &mut o),
        },
        Cmd::Approvals => commands::approvals(&mut client, &mut o),
        Cmd::Approve => {
            let Some(tty) = tty else { return EXIT_FAILED };
            let (Ok(r), Ok(mut w)) = (tty.try_clone(), tty.try_clone()) else {
                return EXIT_FAILED;
            };
            // One byte at a time: a read never takes input past the answer's newline, so
            // nothing typed ahead waits in a buffer that tcflush cannot reach.
            let mut input = BufReader::with_capacity(1, r);
            let mut flush = || {
                let _ = rustix::termios::tcflush(&tty, rustix::termios::QueueSelector::IFlush);
            };
            let mut t = Tty {
                input: &mut input,
                output: &mut w,
                flush: &mut flush,
            };
            approve(&mut client, &mut t, o.err)
        }
    }
}

fn open_tty() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}
