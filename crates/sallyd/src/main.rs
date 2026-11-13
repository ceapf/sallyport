//! `sallyd` daemon entry point: the daemon's life is `sallyd::daemon::serve` (Task 12).
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use sallyd::daemon::serve;
use sallyd::oplog::Oplog;

/// How long the last log lines may take to reach stderr before the process exits.
const LOG_FLUSH: Duration = Duration::from_secs(2);

fn main() -> ExitCode {
    let log = Oplog::stderr();
    let code = match serve::run(&log) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log.error("daemon", "sallyd stopped", &[("error", &e.to_string())]);
            ExitCode::FAILURE
        }
    };
    log.flush(LOG_FLUSH);
    code
}
