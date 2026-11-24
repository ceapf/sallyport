//! `sally`: parse the arguments, run one command, exit with its code. Everything else is in the
//! library, where it is tested.
#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::{BufReader, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sally_cli::approve::{Size, Tty, approve};
use sally_cli::client::{Client, socket_path};
use sally_cli::commands::{self, Out, failed};
use sally_cli::{EXIT_FAILED, EXIT_OK, clean, consent, doctor, drive, local, run, secrets, usage};
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
    /// Run commands in a sandbox.
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
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
        /// A model script (JSON Lines, at most 256 KiB): the session is driven by this
        /// terminal's `session drive`, with no harness and no model socket.
        #[arg(long)]
        script: Option<PathBuf>,
        /// The SHA-256 of the manifest's text, as `sally manifest summary` prints it last: the
        /// start's consent in place of a typed yes. Off a terminal, a start needs it. The hash
        /// says you have read this exact manifest. Never use a hash that came with the manifest.
        #[arg(long = "accept-manifest", value_name = "SHA256")]
        accept_manifest: Option<String>,
    },
    /// Run a driven session's script to its end, one turn at a time.
    Drive {
        /// The session id.
        id: String,
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

#[derive(Subcommand)]
enum SandboxCmd {
    /// Run a command in a new session's workspace, in line mode: its output is shown as
    /// printable ASCII and newlines, stdin is sent as UTF-8 text, and the session stops when
    /// the command ends or this command is interrupted. Exits with the command's code (137 if
    /// it was killed). Approvals are answered in another terminal (`sally approve`); anything
    /// prompt-like here is the command's output, and the exit status and `sally audit tail`
    /// are what to trust. A reader paused over 10 s gets the command killed.
    Run {
        /// The manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// The SHA-256 of the manifest's text, as `sally manifest summary` prints it last: the
        /// run's consent in place of a typed yes. Off a terminal, a run needs it. The hash says
        /// you have read this exact manifest. Never use a hash that came with the manifest.
        #[arg(long = "accept-manifest", value_name = "SHA256")]
        accept_manifest: Option<String>,
        /// The command and its arguments, after `--`.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
}

/// The commands that talk to `sallyd`.
enum Remote {
    Session(SessionCmd),
    Sandbox(SandboxCmd),
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
        Cmd::Manifest { cmd } => {
            // A manifest that names a secret has the store read for its names (its values are
            // dropped at once): core dumps go off first, as for `sally secrets`.
            if let Err(e) = secrets::harden() {
                let _ = writeln!(o.err, "sally: core dumps could not be turned off: {e}");
                return Ok(EXIT_FAILED);
            }
            let (store, config) = (paths.secrets_file(), paths.config_file());
            let files = local::Files {
                store: &store,
                config: &config,
            };
            match cmd {
                ManifestCmd::Validate { file } => local::manifest_validate(&file, files, &mut o),
                ManifestCmd::Summary { file } => local::manifest_summary(&file, files, &mut o),
            }
        }
        Cmd::Audit { cmd } => match cmd {
            AuditCmd::Verify => local::audit_verify(&paths.audit(), &mut o),
            AuditCmd::Tail { n } => local::audit_tail(&paths.audit(), n, &mut o),
        },
        Cmd::Secrets { cmd } => run_secrets(cmd, paths, &mut o),
        Cmd::Session { cmd } => return Err(Remote::Session(cmd)),
        Cmd::Sandbox { cmd } => return Err(Remote::Sandbox(cmd)),
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
        Remote::Session(_) | Remote::Sandbox(_) | Remote::Approvals => None,
    };
    // A launch's gate runs before the daemon is contacted: what it sends is the text it checked.
    let launch = match &cmd {
        Remote::Session(SessionCmd::Start {
            manifest,
            accept_manifest,
            ..
        })
        | Remote::Sandbox(SandboxCmd::Run {
            manifest,
            accept_manifest,
            ..
        }) => match gated(manifest, accept_manifest.as_deref(), paths, &mut stderr) {
            Ok(text) => Some(text),
            Err(code) => return code,
        },
        _ => None,
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
        (Remote::Session(cmd), _) => match (cmd, launch) {
            (SessionCmd::Start { script, .. }, Some(text)) => {
                commands::session_start(&mut client, &text, script.as_deref(), &mut o)
            }
            // The gate gave every launch its text above.
            (SessionCmd::Start { .. }, None) => {
                let _ = writeln!(o.err, "sally: internal: the launch has no checked text");
                EXIT_FAILED
            }
            (SessionCmd::Drive { id }, _) => drive::session_drive(&mut client, &id, &mut o),
            (SessionCmd::List, _) => commands::session_list(&mut client, &mut o),
            (SessionCmd::Stop { id }, _) => commands::session_stop(&mut client, &id, &mut o),
            (SessionCmd::Changes { id }, _) => commands::session_changes(&mut client, &id, &mut o),
        },
        (Remote::Sandbox(SandboxCmd::Run { argv, .. }), _) => match launch {
            Some(text) => run::sandbox_run(&mut client, &text, &argv, std::io::stdin(), &mut o),
            None => {
                let _ = writeln!(o.err, "sally: internal: the launch has no checked text");
                EXIT_FAILED
            }
        },
        (Remote::Approvals, _) => {
            let size = rustix::termios::isatty(std::io::stdout())
                .then(|| terminal_size(std::io::stdout()));
            commands::approvals(&mut client, size, &mut o)
        }
        (Remote::Approve, Some(tty)) => approve_on(&tty, &mut client, o.err),
        (Remote::Approve, None) => EXIT_FAILED,
    }
}

/// The launch gate for the manifest named `manifest` ([`consent::launch_text`]): core dumps off
/// first (the store's names are read), then the text to send, or the exit code. The terminal is
/// `/dev/tty`, opened only when stdin is a terminal too and no hash is given (the hash is the
/// consent then); nothing from stdin is ever an answer.
fn gated(
    manifest: &std::path::Path,
    accept: Option<&str>,
    paths: &Paths,
    err: &mut dyn std::io::Write,
) -> Result<String, u8> {
    if let Err(e) = secrets::harden() {
        let _ = writeln!(err, "sally: core dumps could not be turned off: {e}");
        return Err(EXIT_FAILED);
    }
    let (store, config) = (paths.secrets_file(), paths.config_file());
    let files = local::Files {
        store: &store,
        config: &config,
    };
    let ask = accept.is_none() && rustix::termios::isatty(std::io::stdin());
    let Some(tty) = ask.then(open_tty).and_then(Result::ok) else {
        let g = consent::Gate {
            files,
            accept,
            terminal: None,
        };
        return consent::launch_text(manifest, g, err);
    };
    let (Ok(r), Ok(mut w)) = (tty.try_clone(), tty.try_clone()) else {
        let _ = writeln!(
            err,
            "sally: the terminal (/dev/tty) could not be opened for the question"
        );
        return Err(EXIT_FAILED);
    };
    // One byte at a time, as `approve` reads: nothing typed ahead waits where tcflush cannot
    // reach it.
    let mut input = BufReader::with_capacity(1, r);
    let mut flush = || {
        rustix::termios::tcflush(&tty, rustix::termios::QueueSelector::IFlush).map_err(Into::into)
    };
    let mut size = || terminal_size(&tty);
    let mut t = Tty {
        input: &mut input,
        output: &mut w,
        flush: &mut flush,
        size: &mut size,
    };
    let g = consent::Gate {
        files,
        accept,
        terminal: Some(&mut t),
    };
    consent::launch_text(manifest, g, err)
}

fn approve_on(tty: &std::fs::File, client: &mut Client, err: &mut dyn std::io::Write) -> u8 {
    let (Ok(r), Ok(mut w)) = (tty.try_clone(), tty.try_clone()) else {
        return EXIT_FAILED;
    };
    // One byte at a time: a read never takes input past the answer's newline, so nothing
    // typed ahead waits in a buffer that tcflush cannot reach.
    let mut input = BufReader::with_capacity(1, r);
    let mut flush = || {
        rustix::termios::tcflush(tty, rustix::termios::QueueSelector::IFlush).map_err(Into::into)
    };
    let mut size = || terminal_size(tty);
    let mut t = Tty {
        input: &mut input,
        output: &mut w,
        flush: &mut flush,
        size: &mut size,
    };
    approve(client, &mut t, err)
}

/// `fd`'s terminal size; 0 by 0 (not known) when it cannot be read.
fn terminal_size(fd: impl rustix::fd::AsFd) -> Size {
    rustix::termios::tcgetwinsize(fd).map_or(
        Size {
            columns: 0,
            rows: 0,
        },
        |w| Size {
            columns: w.ws_col,
            rows: w.ws_row,
        },
    )
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
