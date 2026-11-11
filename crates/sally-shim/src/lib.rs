//! `sally-shim`: a dumb, static, std-only relay that runs inside a sandbox and carries bytes
//! between a loopback TCP port and a Unix socket the broker bind-mounted in (AMENDMENTS-01 §3.3).
//!
//! * `--listen 127.0.0.1:3128=/run/sallyport/net.sock` (repeatable): every accepted TCP
//!   connection gets **its own** Unix connection; bytes are copied both ways, opaque, until
//!   either side closes. Half-close is propagated. Once every listener is bound, the shim writes
//!   one line per listener to stderr, `sally-shim: listening on <addr>` (the bound address only,
//!   never the socket path), so a caller can wait for readiness instead of polling.
//! * `--stdio /run/sallyport/agent.sock`: stdin → socket, socket → stdout, for clients that
//!   expect to spawn a stdio server.
//!
//! The shim holds no policy and parses nothing. It exists because the sandbox has no network at
//! all (SI-1): the only way out is this relay and the broker behind it. Buffers are fixed
//! ([`relay::BUF_BYTES`] per direction) and the number of live connections is bounded, so a
//! hostile client can only exhaust the shim's own small budget, never memory.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod args;
pub mod relay;

pub use args::{ArgError, ListenSpec, Mode, parse_args};
pub use relay::{BUF_BYTES, LINGER, Limiter, MAX_CONNECTIONS, bind, serve, stdio};
