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
use sally_cli::{EXIT_FAILED, clean, doctor, local, secrets};
use sally_core::paths::Paths;

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
    /// Check this host's facts (no container, no network).
    Doctor,
    /// Check a manifest here (sallyd checks again when a session starts).
    Manifest {
        #[command(subcommand)]
        cmd: ManifestCmd,
    },
    /// The audit log.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// The secrets store. Values are read from stdin or a prompt, never from arguments.
    Secrets {
        #[command(subcommand)]
        cmd: SecretsCmd,
    },
}

#[derive(Subcommand)]
enum ManifestCmd {
    /// Validate a manifest.
    Validate {
        /// The manifest.
        file: PathBuf,
    },
    /// Summarize a valid manifest in plain English.
    Summary {
        /// The manifest.
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Check the hash chain.
    Verify,
    /// Print the newest entries (does not verify them).
    Tail {
        /// How many (at most 1000).
        #[arg(short = 'n', default_value_t = sally_cli::local::TAIL_DEFAULT)]
        n: usize,
    },
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Store a secret: the value from stdin, or a prompt that does not echo. After Ctrl-C at
    /// the prompt, `stty echo` turns echo back on.
    Set {
        /// The name, A-Z, 0-9 and _.
        name: String,
    },
    /// List the names.
    List,
    /// Remove a secret.
    Rm {
        /// The name.
        name: String,
    },
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
    let paths = match Paths::from_env() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(stderr, "sally: {e}");
            return EXIT_FAILED;
        }
    };
    let cmd = match local(cmd, &paths, &mut stdout, &mut stderr) {
        Ok(code) => return code,
        Err(remote) => remote,
    };
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
    let mut client = match socket_path(&paths).and_then(|p| Client::connect(&p)) {
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
        Cmd::Doctor | Cmd::Manifest { .. } | Cmd::Audit { .. } | Cmd::Secrets { .. } => EXIT_FAILED,
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

/// The commands that need no daemon; any other comes back as `Err`.
fn local(
    cmd: Cmd,
    paths: &Paths,
    stdout: &mut std::io::Stdout,
    stderr: &mut std::io::Stderr,
) -> Result<u8, Cmd> {
    let mut o = Out {
        out: stdout,
        err: stderr,
    };
    Ok(match cmd {
        Cmd::Doctor => doctor::doctor(&doctor::facts(paths), &mut o),
        Cmd::Manifest { cmd } => match cmd {
            ManifestCmd::Validate { file } => local::manifest_validate(&file, &mut o),
            ManifestCmd::Summary { file } => local::manifest_summary(&file, &mut o),
        },
        Cmd::Audit { cmd } => match cmd {
            AuditCmd::Verify => local::audit_verify(&paths.audit(), &mut o),
            AuditCmd::Tail { n } => local::audit_tail(&paths.audit(), n, &mut o),
        },
        Cmd::Secrets { cmd } => {
            let store = paths.secrets_file();
            match cmd {
                SecretsCmd::Set { name } => {
                    if let Err(e) = secrets::harden() {
                        let _ = writeln!(o.err, "sally: core dumps could not be turned off: {e}");
                        return Ok(EXIT_FAILED);
                    }
                    let mut read = read_value;
                    secrets::set(&store, &name, &mut read, &mut o)
                }
                SecretsCmd::List => secrets::list(&store, &mut o),
                SecretsCmd::Rm { name } => secrets::rm(&store, &name, &mut o),
            }
        }
        remote => return Err(remote),
    })
}

/// The secret's value: a prompt with echo off when stdin is a terminal, else piped stdin.
fn read_value() -> Result<zeroize::Zeroizing<String>, secrets::ValueError> {
    let stdin = std::io::stdin();
    if rustix::termios::isatty(&stdin) {
        let tty = open_tty().map_err(|e| secrets::ValueError::Terminal(e.to_string()))?;
        secrets::read_terminal(&tty, "value (not shown): ", &mut std::io::stderr())
    } else {
        secrets::read_piped(&mut stdin.lock())
    }
}

fn open_tty() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}
