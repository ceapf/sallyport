//! Noticing that a session's container ended on its own (architect Q57, reason `exited`).
//!
//! The launcher opens the container init's `/proc/<pid>` directory right after the mount check
//! on that pid; a lookup through that fd fails once the process is gone, even if the pid is
//! reused (architect Q29). So the registry asks it every [`EXIT_POLL`]: no `podman wait` child
//! per session and no extra podman state. (A pidfd would wake at once, but tokio 1.54 offers no
//! safe way left to register one: `AsyncFd::new` is deprecated for its `unsafe` replacement.)

use std::io;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::{AtFlags, statat};

/// How often a session's init is checked.
pub const EXIT_POLL: Duration = Duration::from_secs(1);

/// The init process of a running container, watched for its exit.
#[derive(Debug)]
pub struct Exit {
    init_dir: Arc<OwnedFd>,
}

/// The process `dir` (a `/proc/<pid>` directory) was opened for still exists.
#[must_use]
pub fn alive(dir: &OwnedFd) -> bool {
    statat(dir, "stat", AtFlags::empty()).is_ok()
}

impl Exit {
    /// Watches the process of `init_dir`.
    ///
    /// # Errors
    /// `ESRCH` when it is already gone.
    pub fn watch(init_dir: Arc<OwnedFd>) -> io::Result<Self> {
        if alive(&init_dir) {
            Ok(Self { init_dir })
        } else {
            Err(rustix::io::Errno::SRCH.into())
        }
    }

    /// Resolves once the process is gone, checking every `period`.
    pub async fn exited_every(&self, period: Duration) {
        let mut tick = tokio::time::interval(period);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if !alive(&self.init_dir) {
                return;
            }
        }
    }

    /// Resolves once the process is gone, checking every [`EXIT_POLL`].
    pub async fn exited(&self) {
        self.exited_every(EXIT_POLL).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    fn sleeper() -> (Child, Arc<OwnedFd>) {
        let child = Command::new("sleep").arg("30").spawn().unwrap();
        let dir = sally_core::fd::open(
            format!("/proc/{}", child.id()).as_str(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY,
            rustix::fs::Mode::empty(),
        )
        .unwrap();
        (child, Arc::new(dir))
    }

    #[test]
    fn the_poll_is_one_second() {
        assert_eq!(EXIT_POLL, Duration::from_secs(1));
    }

    #[tokio::test]
    async fn a_live_process_is_not_reported_until_it_exits() {
        let (mut child, dir) = sleeper();
        let exit = Exit::watch(dir).unwrap();
        let period = Duration::from_millis(20);
        let early = tokio::time::timeout(Duration::from_millis(200), exit.exited_every(period));
        assert!(early.await.is_err(), "reported a live process as exited");
        child.kill().unwrap();
        child.wait().unwrap();
        tokio::time::timeout(Duration::from_secs(5), exit.exited_every(period))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn the_default_poll_notices_an_exit() {
        let (mut child, dir) = sleeper();
        let exit = Exit::watch(dir).unwrap();
        let early = tokio::time::timeout(Duration::from_millis(300), exit.exited());
        assert!(early.await.is_err(), "reported a live process as exited");
        child.kill().unwrap();
        child.wait().unwrap();
        tokio::time::timeout(EXIT_POLL * 3, exit.exited())
            .await
            .unwrap();
    }

    #[test]
    fn a_process_already_gone_is_refused() {
        let (mut child, dir) = sleeper();
        assert!(alive(&dir));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!alive(&dir));
        let e = Exit::watch(dir).unwrap_err();
        assert_eq!(
            e.raw_os_error(),
            Some(rustix::io::Errno::SRCH.raw_os_error())
        );
    }
}
