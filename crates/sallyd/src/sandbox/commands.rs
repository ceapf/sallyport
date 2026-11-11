//! Running hermetic podman commands for the launcher: bounded output, a timeout per command,
//! container removal that confirms the container is gone, and `podman unshare rm`. Moved out of
//! `launch.rs` unchanged in Task 6c, to keep it under the file-size ceiling.

use std::ffi::OsString;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _};

use super::argv::path_arg;
use super::launch::{LaunchError, Launcher};

/// Bytes of podman's stdout and stderr kept per command; the rest is read and dropped.
const OUTPUT_CAP: usize = 64 * 1024;
/// A podman command that takes longer is killed.
const PODMAN_TIMEOUT: Duration = Duration::from_secs(120);

impl Launcher {
    /// `podman rm --force`, then confirms the container is gone.
    pub(super) async fn remove_container(&self, name: &str) -> Result<(), LaunchError> {
        let removed = self.run("rm", rm_args(name)).await;
        match self.container_exists(name).await? {
            false => Ok(()),
            true => Err(removed.err().unwrap_or(LaunchError::Command {
                verb: "rm",
                msg: format!("{name} still exists"),
            })),
        }
    }

    async fn container_exists(&self, name: &str) -> Result<bool, LaunchError> {
        let status = self
            .podman
            .command()
            .args(["container", "exists", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let status = tokio::time::timeout(PODMAN_TIMEOUT, status)
            .await
            .map_err(|_| LaunchError::Command {
                verb: "container exists",
                msg: "timed out".into(),
            })?
            .map_err(|e| LaunchError::Command {
                verb: "container exists",
                msg: e.to_string(),
            })?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(LaunchError::Command {
                verb: "container exists",
                msg: status.to_string(),
            }),
        }
    }

    /// `podman unshare rm -rf -- <t>`: overlay work directories belong to the container's user
    /// namespace.
    pub(super) async fn unshare_rm(&self, t: &std::path::Path) -> Result<(), LaunchError> {
        let t = path_arg(t, "session scratch")?;
        self.run(
            "unshare",
            [
                "unshare".into(),
                "rm".into(),
                "-rf".into(),
                "--".into(),
                t.into(),
            ],
        )
        .await
        .map(|_| ())
    }

    /// Runs one hermetic podman command; stdout on success.
    pub(super) async fn run(
        &self,
        verb: &'static str,
        args: impl IntoIterator<Item = OsString>,
    ) -> Result<String, LaunchError> {
        let fail = |msg: String| LaunchError::Command { verb, msg };
        let mut child = self
            .podman
            .command()
            .args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| fail(e.to_string()))?;
        let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
            return Err(fail("no pipes".into()));
        };
        let work = async {
            let (out, err) = tokio::join!(read_capped(out), read_capped(err));
            let status = child.wait().await;
            (out, err, status)
        };
        let (out, err, status) = tokio::time::timeout(PODMAN_TIMEOUT, work)
            .await
            .map_err(|_| fail(format!("timed out after {}s", PODMAN_TIMEOUT.as_secs())))?;
        let status = status.map_err(|e| fail(e.to_string()))?;
        if status.success() {
            Ok(String::from_utf8_lossy(&out).into_owned())
        } else {
            Err(fail(format!(
                "{status}: {}",
                String::from_utf8_lossy(&err).trim()
            )))
        }
    }
}

pub(super) fn rm_args(container: &str) -> [OsString; 5] {
    [
        "rm".into(),
        "--force".into(),
        "--time".into(),
        "0".into(),
        container.into(),
    ]
}

/// The id `podman create` prints: 64 lowercase hex digits on the last line.
pub(super) fn container_id(out: &str) -> Result<String, LaunchError> {
    let id = out.trim().lines().last().unwrap_or_default();
    if id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(id.to_owned())
    } else {
        Err(LaunchError::Command {
            verb: "create",
            msg: "did not print a container id".into(),
        })
    }
}

/// Reads until end of file, keeping the first [`OUTPUT_CAP`] bytes, so a chatty process never
/// blocks on a full pipe and never grows memory without bound. A read error ends the read; the
/// command's timeout then bounds the wait for the process.
async fn read_capped(mut r: impl AsyncRead + Unpin) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                let room = OUTPUT_CAP.saturating_sub(kept.len());
                kept.extend_from_slice(buf.get(..n.min(room)).unwrap_or_default());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn container_ids_are_exactly_64_lowercase_hex() {
        let id = "a".repeat(64);
        assert_eq!(container_id(&format!("{id}\n")).unwrap(), id);
        assert_eq!(container_id(&format!("warning\n{id}\n")).unwrap(), id);
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"a".repeat(65),
            &format!("{}-", "a".repeat(63)),
        ] {
            assert!(container_id(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn output_is_capped_but_fully_drained() {
        let data = vec![b'x'; OUTPUT_CAP * 3 + 17];
        let kept = read_capped(data.as_slice()).await;
        assert_eq!(kept.len(), OUTPUT_CAP);
    }
}
