//! Inputs of the argv builder. Every value that ends up in an argv is validated when it is
//! constructed, so the builder never has to trust a raw string.

use std::path::{Path, PathBuf};

use sally_core::config::{ConfigError, check_runtime_binary};
use sally_core::manifest::{ByteSize, Cpus, is_pinned_image_ref};

/// Why an argv could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArgvError {
    /// An input is malformed (a path that would break the `-v` syntax, a bad id, a git scan
    /// entry outside its mount).
    #[error("sandbox argv input: {0}")]
    Input(String),
    /// The argv contains a flag or value the sandbox must never run with (CLAUDE.md hard rules).
    /// From the builder this means a bug: it checks its own output and refuses to return it.
    #[error("sandbox argv refused: {0}")]
    Forbidden(String),
}

pub(crate) fn input<T>(msg: impl Into<String>) -> Result<T, ArgvError> {
    Err(ArgvError::Input(msg.into()))
}

/// The OCI runtime binary after `sally_core::config::check_runtime_binary`: a realpath that only
/// its owner or root can swap (AMENDMENTS-02 B5). Passed as `--runtime` on every `podman` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedRuntime(PathBuf);

impl CheckedRuntime {
    /// Runs the runtime binary checks and keeps the realpath. Performs blocking I/O.
    ///
    /// # Errors
    /// [`ConfigError::Binary`] naming the failed check.
    pub fn check(path: &Path) -> Result<Self, ConfigError> {
        check_runtime_binary(path).map(Self)
    }

    /// The checked realpath.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

/// A session or inference-instance id: `[a-z0-9][a-z0-9-]{0,63}`. It becomes part of container
/// names and host paths, so it is restricted to characters that are safe in both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    /// Validates an id.
    ///
    /// # Errors
    /// [`ArgvError::Input`] if it does not match the grammar.
    pub fn parse(s: &str) -> Result<Self, ArgvError> {
        let mut b = s.bytes();
        let ok = s.len() <= 64
            && b.next()
                .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            input("id must be 1-64 characters of a-z, 0-9 and -, starting with a letter or digit")
        }
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The container label naming the installation that created a container (architect Q64).
pub const INSTALLATION_LABEL: &str = "sallyport.installation";

/// The id of one Sallyport installation (one state directory): a random UUID v4 in its
/// lowercase hyphenated form. Every container the launcher creates carries it as
/// [`INSTALLATION_LABEL`], and the orphan sweeps remove only containers that carry this
/// installation's id (Q64), never another daemon's or a test run's. It never leaves the
/// machine and never reaches the audit log (SI-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation(String);

impl Installation {
    /// Validates an id: 36 characters, `xxxxxxxx-xxxx-4xxx-[89ab]xxx-xxxxxxxxxxxx`, lowercase
    /// hex.
    ///
    /// # Errors
    /// [`ArgvError::Input`] otherwise.
    pub fn parse(s: &str) -> Result<Self, ArgvError> {
        let b = s.as_bytes();
        let shape = b.len() == 36
            && b.iter().enumerate().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => *c == b'-',
                _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
            })
            && b.get(14) == Some(&b'4')
            && b.get(19).is_some_and(|c| b"89ab".contains(c));
        if shape {
            Ok(Self(s.to_owned()))
        } else {
            input("installation id must be a lowercase UUID v4")
        }
    }

    /// A fresh id from getrandom(2).
    ///
    /// # Errors
    /// The getrandom error, or a short read.
    pub fn fresh() -> std::io::Result<Self> {
        let mut r = [0u8; 16];
        let n = rustix::rand::getrandom(&mut r, rustix::rand::GetRandomFlags::empty())?;
        if n != r.len() {
            return Err(std::io::Error::other("getrandom returned a short read"));
        }
        Self::parse(&uuid_v4(r)).map_err(|e| std::io::Error::other(e.to_string()))
    }

    /// The id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `r` as a UUID v4: version nibble 4, variant bits 10. The bits are added to the masked byte
/// (its high bits are clear, so `+` cannot carry): unlike `|`, no operator swap gives the same
/// value.
fn uuid_v4(mut r: [u8; 16]) -> String {
    r[6] = 0x40 + (r[6] & 0x0f);
    r[8] = 0x80 + (r[8] & 0x3f);
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// An image pinned by digest (SI-11), in the grammar of
/// [`sally_core::manifest::is_pinned_image_ref`]: never a Podman transport such as `dir:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef(String);

impl ImageRef {
    /// Validates an image reference.
    ///
    /// # Errors
    /// [`ArgvError::Input`] unless it is a digest-pinned reference with a plain name.
    pub fn parse(s: &str) -> Result<Self, ArgvError> {
        if is_pinned_image_ref(s) {
            Ok(Self(s.to_owned()))
        } else {
            input(
                "image must be <registry/name>@sha256:<64 lowercase hex>, with no transport prefix",
            )
        }
    }

    /// The reference.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host user the container maps to (`--userns=keep-id --user <uid>:<gid>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserIds {
    /// Host uid.
    pub uid: u32,
    /// Host gid.
    pub gid: u32,
}

/// The three sandbox roles (AMENDMENTS-01 §2; SI-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Mounts, the egress socket and the toolchain.
    Workspace,
    /// The agent: model and tool sockets only.
    Harness,
    /// The model server: GPU and read-only weights.
    Inference,
}

impl Role {
    /// The role's seccomp profile file name under [`CommonArgs::profiles`].
    #[must_use]
    pub const fn profile(self) -> &'static str {
        match self {
            Self::Workspace => "seccomp-workspace.json",
            Self::Harness => "seccomp-harness.json",
            Self::Inference => "seccomp-inference.json",
        }
    }
}

/// Settings shared by every role.
#[derive(Debug, Clone)]
pub struct CommonArgs {
    /// Checked OCI runtime.
    pub runtime: CheckedRuntime,
    /// Host user.
    pub ids: UserIds,
    /// Directory holding `seccomp-{workspace,harness,inference}.json`.
    ///
    /// TODO(#10): check its ownership like [`CheckedRuntime`] (AMENDMENTS-02 B5).
    pub profiles: PathBuf,
    /// Sallyport's empty OCI hooks directory, passed as `--hooks-dir` so no host hook runs (#11).
    pub hooks_dir: PathBuf,
    /// Sallyport's empty mounts file, passed as `--default-mounts-file` so no system
    /// `mounts.conf` adds a mount (6b security review M4).
    pub mounts_file: PathBuf,
    /// This installation's id, the container's [`INSTALLATION_LABEL`] (Q64).
    pub installation: Installation,
}

/// Host directories of one session (ARCHITECTURE §3.1, AMENDMENTS-01 §2, AMENDMENTS-02 B2).
#[derive(Debug, Clone)]
pub struct SessionPaths {
    id: SessionId,
    sockets: PathBuf,
    data: PathBuf,
}

impl SessionPaths {
    /// `sockets` is `$XDG_RUNTIME_DIR/sallyport`, `data` is `~/.local/share/sallyport`; the
    /// session's directories are `sessions/<id>` under each.
    ///
    /// # Errors
    /// [`ArgvError::Input`] if a root is not absolute.
    pub fn new(id: SessionId, sockets: &Path, data: &Path) -> Result<Self, ArgvError> {
        if !sockets.is_absolute() || !data.is_absolute() {
            return input("session roots must be absolute paths");
        }
        let sockets = sockets.join("sessions").join(id.as_str());
        let data = data.join("sessions").join(id.as_str());
        Ok(Self { id, sockets, data })
    }

    /// The session id.
    #[must_use]
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    /// The session's socket root: one subdirectory per role, never shared.
    #[must_use]
    pub fn socket_root(&self) -> &Path {
        &self.sockets
    }

    /// Socket directory of the workspace role (`net.sock`, CA bundle).
    #[must_use]
    pub fn workspace_sockets(&self) -> PathBuf {
        self.sockets.join("workspace")
    }

    /// Socket directory of the harness role (`llm.sock`, `agent.sock`).
    #[must_use]
    pub fn harness_sockets(&self) -> PathBuf {
        self.sockets.join("harness")
    }

    /// The session's scratch root (stage and `.git` overlay directories).
    #[must_use]
    pub fn data_root(&self) -> &Path {
        &self.data
    }

    /// Upper and work directories of the staged mount at manifest index `mount`; kept after the
    /// session so `sally session changes` can read them.
    #[must_use]
    pub fn stage(&self, mount: usize) -> OverlayDirs {
        OverlayDirs::under(&self.data.join("stage").join(mount.to_string()))
    }

    /// Upper and work directories of the `k`-th `.git` overlay; discarded at teardown.
    #[must_use]
    pub fn git_overlay(&self, k: usize) -> OverlayDirs {
        OverlayDirs::under(&self.data.join("git").join(k.to_string()))
    }
}

/// The scratch directories of one overlay mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayDirs {
    /// Receives every change made through the overlay.
    pub upper: PathBuf,
    /// Overlayfs work directory (same filesystem as `upper`).
    pub work: PathBuf,
}

impl OverlayDirs {
    fn under(d: &Path) -> Self {
        Self {
            upper: d.join("upper"),
            work: d.join("work"),
        }
    }
}

/// One inference instance (ARCHITECTURE §3.2, AMENDMENTS-01 §6.2).
#[derive(Debug, Clone)]
pub struct InferenceSpec {
    /// Instance id.
    pub instance: SessionId,
    /// Host socket directory, `$XDG_RUNTIME_DIR/sallyport/infer/<id>`.
    pub socket_dir: PathBuf,
    /// The verified model blob (SI-6), mounted read-only.
    pub model: VerifiedModel,
    /// Inference image.
    pub image: ImageRef,
    /// Pass the GPU through (`--device nvidia.com/gpu=all`).
    pub gpu: bool,
    /// `-ngl`.
    pub gpu_layers: u32,
    /// `-c`.
    pub context: u32,
    /// `--cpus`.
    pub cpus: Cpus,
    /// `--memory`; optional because mmap'd weights count as page cache.
    pub memory: Option<ByteSize>,
}

/// A model blob in the library, pinned by identity (#10): `<blobs>/sha256/<64 lowercase hex>`, a
/// regular file owned by the current user with no write bit (the library stores blobs 0444),
/// opened without following a symlink. The SHA-256 itself is checked once, at import (SI-6,
/// M2); TODO(M2): the import in `sally-core::model` becomes the only constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedModel {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl VerifiedModel {
    /// Pins the blob named `sha256_hex` in `blobs`. Performs blocking I/O.
    ///
    /// # Errors
    /// [`ArgvError::Input`] naming the failed check.
    pub fn pin(blobs: &Path, sha256_hex: &str) -> Result<Self, ArgvError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags};
        if sha256_hex.len() != 64
            || !sha256_hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return input("model: the blob name must be 64 lowercase hex digits");
        }
        let path = blobs.join("sha256").join(sha256_hex);
        let fd = sally_core::fd::openat2(
            rustix::fs::CWD,
            &path,
            OFlags::PATH | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
        .or_else(|e| input(format!("model {}: {e}", path.display())))?;
        let st = rustix::fs::fstat(&fd).or_else(|e| input(format!("model: {e}")))?;
        let regular =
            rustix::fs::FileType::from_raw_mode(st.st_mode) == rustix::fs::FileType::RegularFile;
        if !regular || st.st_uid != rustix::process::geteuid().as_raw() || st.st_mode & 0o222 != 0 {
            return input(format!(
                "model {}: must be a regular file owned by the current user with no write bit",
                path.display()
            ));
        }
        Ok(Self {
            path,
            dev: st.st_dev,
            ino: st.st_ino,
        })
    }

    /// The blob's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `(st_dev, st_ino)` when pinned.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.dev, self.ino)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn uuid_v4_sets_the_version_and_variant_bits() {
        assert_eq!(uuid_v4([0; 16]), "00000000-0000-4000-8000-000000000000");
        assert_eq!(uuid_v4([0xff; 16]), "ffffffff-ffff-4fff-bfff-ffffffffffff");
        let r: [u8; 16] = std::array::from_fn(|i| u8::try_from(i).unwrap() * 17);
        assert_eq!(uuid_v4(r), "00112233-4455-4677-8899-aabbccddeeff");
    }

    // Whatever the random bytes, the version nibble is 4 and the variant bits are 10, and only
    // those bits change: the low nibble of byte 6 and the low six bits of byte 8 are kept.
    #[test]
    fn every_byte_value_gets_the_version_and_variant_bits_and_keeps_the_rest() {
        for b in 0..=u8::MAX {
            let id = uuid_v4([b; 16]);
            let byte = |at: usize| u8::from_str_radix(&id[at..at + 2], 16).unwrap();
            assert_eq!(byte(14), 0x40 | (b & 0x0f), "{id}");
            assert_eq!(byte(19), 0x80 | (b & 0x3f), "{id}");
            assert!(Installation::parse(&id).is_ok(), "{id}");
        }
        for _ in 0..64 {
            let id = Installation::fresh().unwrap();
            assert_eq!(&id.as_str()[14..15], "4", "{}", id.as_str());
            assert!("89ab".contains(&id.as_str()[19..20]), "{}", id.as_str());
        }
    }
}
