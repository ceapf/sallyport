//! Secret values and the 0600 secrets store (SI-3, DECISIONS D9).
//!
//! Everything outside this module and the proxy that injects credentials sees secrets **by name
//! only**: [`SecretStore::names`], [`SecretStore::contains`] and the manifest validator's
//! `SecretCatalog` never expose a value. A value is reachable solely through
//! [`SecretStore::get`] and [`Secret::expose`], so a grep for `expose(` finds every place that
//! can touch plaintext.
//!
//! The store is a plaintext TOML file (`name = "value"`, one per line) protected by its mode and
//! owner, not by encryption. It does not defend against an attacker who already has the user's
//! UID; it defends against a sandbox, a log line or a stray `cat`. One value per name: several
//! manifest grants may name the same secret with different hosts, and all of them read the same
//! entry.
//!
//! Concurrency: a `SecretStore` is a snapshot and `save` writes all of it, so two processes
//! editing the store can silently undo each other (a removed credential could come back).
//! `sallyd` is the single writer; the CLI edits through its RPC, never the file directly.
//!
//! Residuals: the TOML parser keeps a copy of the whole input inside its error value on a
//! malformed file, and the OS may leave pages of freed memory behind; the buffers this module
//! controls (file bytes, rendered text, stored values) are zeroized. The directory is checked by
//! path, not by directory fd, so a user able to write the parent's parent could race the check
//! (denial of service or a misplaced store, never disclosure: the file stays 0600).
//! TODO(issue#): pin the directory fd and use `openat`/`renameat` (SI-8 style) in a later hardening pass.
//!
//! Blocking I/O: [`SecretStore::open`] and [`SecretStore::save`] do file I/O; async callers use
//! `spawn_blocking`.

mod secret;
mod store;

pub use secret::Secret;
pub use store::{
    MAX_SECRETS, MAX_STORE_BYTES, MAX_VALUE_BYTES, SHORT_SECRET_BYTES, SecretStore, SecretsError,
    SetOutcome, is_secret_name,
};
