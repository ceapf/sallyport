//! `sally`: parse the arguments, run one command, exit with its code. Everything else is in the
//! library, where it is tested.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{BufReader, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sally_cli::approve::{Tty, approve};
use sally_cli::client::{Client, socket_path};
use sally_cli::commands::{self, Out, failed};
use sally_cli::{EXIT_FAILED, EXIT_OK, clean, doctor, local, secrets, usage};
use sally_core::paths::Paths;

/// Talk to `sallyd`: start, list and stop sessions, see what they staged, answer approvals.
/// Doctor, manifest, audit and secrets commands run here, without `sallyd`.
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
    /// Check this host's facts (no container, no network). Exit 1 when a check fails, 2 when
    /// a fact could not be read.
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
    /// Check the hash chain. Exit 0 verified, 1 the log failed verification, 2 the log could
    /// not be read; treat any non-zero as not verified.
    Verify,
    /// Print the newest entries (does not verify them).
    Tail {
        /// How many (larger values are cut to 1000).
        #[arg(short = 'n', default_value_t = sally_cli::local::TAIL_DEFAULT)]
        n: usize,
    },
}

#[derive(Subcommand)]
enum SecretsCmd {
    /// Store a secret. The value comes from stdin, or from a prompt that does not echo (up to
    /// 4094 bytes; longer values on stdin). Ctrl-C cancels the prompt; if the terminal is ever
    /// left without echo, `stty echo` turns it back on.
    Set {
        /// The name: 1-64 characters of A-Z, 0-9 and _, starting with a letter.
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

/// The commands that talk to `sallyd`.
enum Remote {
    Session(SessionCmd),
    Approvals,
    Approve,
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    let code = match Cli::try_parse_from(&args) {
        Ok(cli) => run(cli.cmd),
        Err(e) => parse_failed(&e, &args),
    };
    ExitCode::from(code)
}

/// Help and version print as usual; any other parse error prints fixed text that repeats no
/// argument (architect Q113).
fn parse_failed(e: &clap::Error, args: &[OsString]) -> u8 {
    use clap::error::ErrorKind::{DisplayHelp, DisplayVersion};
    if matches!(e.kind(), DisplayHelp | DisplayVersion) {
        let text = clean::text(&e.render().to_string()).text;
        let _ = write!(std::io::stdout(), "{text}");
        return EXIT_OK;
    }
    let names_secrets = secrets::names_secrets(args.get(1..).unwrap_or_default());
    let text = usage::parse_error(e.kind(), names_secrets);
    let _ = writeln!(std::io::stderr(), "{text}");
    EXIT_FAILED
}

fn run(cmd: Cmd) -> u8 {
    let paths = match Paths::from_env() {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "sally: {e}");
            return EXIT_FAILED;
        }
    };
    match local(cmd, &paths) {
        Ok(code) => code,
        Err(remote) => run_remote(remote, &paths),
    }
}

/// The commands that need no daemon; the others come back as `Err`.
fn local(cmd: Cmd, paths: &Paths) -> Result<u8, Remote> {
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let mut o = Out {
        out: &mut stdout,
        err: &mut stderr,
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
        Cmd::Secrets { cmd } => run_secrets(cmd, paths, &mut o),
        Cmd::Session { cmd } => return Err(Remote::Session(cmd)),
        Cmd::Approvals => return Err(Remote::Approvals),
        Cmd::Approve => return Err(Remote::Approve),
    })
}

fn run_secrets(cmd: SecretsCmd, paths: &Paths, o: &mut Out<'_>) -> u8 {
    // Every subcommand holds plaintext (set: the value; list and rm: the whole store), so core
    // dumps go off before any of it is read.
    if let Err(e) = secrets::harden() {
        let _ = writeln!(o.err, "sally: core dumps could not be turned off: {e}");
        return EXIT_FAILED;
    }
    let store = paths.secrets_file();
    match cmd {
        SecretsCmd::Set { name } => {
            let mut read = read_value;
            secrets::set(&store, &name, &mut read, o)
        }
        SecretsCmd::List => secrets::list(&store, o),
        SecretsCmd::Rm { name } => secrets::rm(&store, &name, o),
    }
}

fn run_remote(cmd: Remote, paths: &Paths) -> u8 {
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    // The terminal first: without one, `approve` exits before it watches (architect Q80).
    let tty = match cmd {
        Remote::Approve => match open_tty() {
            Ok(t) => Some(t),
            Err(e) => {
                let _ = writeln!(stderr, "sally: approve needs a terminal (/dev/tty): {e}");
                return EXIT_FAILED;
            }
        },
        Remote::Session(_) | Remote::Approvals => None,
    };
    let mut client = match socket_path(paths).and_then(|p| Client::connect(&p)) {
        Ok(c) => c,
        Err(e) => return failed(&e, &mut stderr),
    };
    let mut o = Out {
        out: &mut stdout,
        err: &mut stderr,
    };
    match (cmd, tty) {
        (Remote::Session(cmd), _) => match cmd {
            SessionCmd::Start { manifest } => {
                commands::session_start(&mut client, &manifest, &mut o)
            }
            SessionCmd::List => commands::session_list(&mut client, &mut o),
            SessionCmd::Stop { id } => commands::session_stop(&mut client, &id, &mut o),
            SessionCmd::Changes { id } => commands::session_changes(&mut client, &id, &mut o),
        },
        (Remote::Approvals, _) => commands::approvals(&mut client, &mut o),
        (Remote::Approve, Some(tty)) => approve_on(&tty, &mut client, o.err),
        (Remote::Approve, None) => EXIT_FAILED,
    }
}

fn approve_on(tty: &std::fs::File, client: &mut Client, err: &mut dyn std::io::Write) -> u8 {
    let (Ok(r), Ok(mut w)) = (tty.try_clone(), tty.try_clone()) else {
        return EXIT_FAILED;
    };
    // One byte at a time: a read never takes input past the answer's newline, so nothing
    // typed ahead waits in a buffer that tcflush cannot reach.
    let mut input = BufReader::with_capacity(1, r);
    let mut flush = || {
        let _ = rustix::termios::tcflush(tty, rustix::termios::QueueSelector::IFlush);
    };
    let mut t = Tty {
        input: &mut input,
        output: &mut w,
        flush: &mut flush,
    };
    approve(client, &mut t, err)
}

/// The secret's value: a prompt with echo off when stdin is a terminal, else piped stdin.
fn read_value() -> Result<zeroize::Zeroizing<String>, secrets::ValueError> {
    let stdin = std::io::stdin();
    if rustix::termios::isatty(&stdin) {
        let tty = open_tty().map_err(|e| secrets::ValueError::Terminal(e.to_string()))?;
        secrets::read_terminal(&tty, "value (not shown): ", &mut std::io::stderr())
    } else {
        // A duplicate of fd 0, read directly: std's own stdin buffer is never wiped.
        let fd = rustix::io::fcntl_dupfd_cloexec(&stdin, 0)
            .map_err(|e| secrets::ValueError::Read(e.to_string()))?;
        secrets::read_piped(&mut std::fs::File::from(fd))
    }
}

fn open_tty() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
}
