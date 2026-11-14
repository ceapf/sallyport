//! The `control.sock` client (architect Q78): std, blocking. Before it sends a byte it checks
//! that the socket's owner is this user (a socket someone else bound gets nothing). A reader
//! thread reads every frame under [`MAX_FRAME`](sally_proto::MAX_FRAME); a longer one is fatal.
//! Replies come back to the call that sent the request; notifications wait in a queue.
//!
//! What the client holds unread is bounded (architect Q91). The reader hands frames over
//! through a queue of [`FRAME_QUEUE`] frames and stops reading when it is full, so at most
//! `FRAME_QUEUE + 1` frames (`(FRAME_QUEUE + 1) × MAX_FRAME` bytes) wait in the client. Then
//! the socket fills and sallyd drops a watcher that does not read (its watch channel is full,
//! or a write blocks past its timeout): its prompts end `no-approver` or by timeout, both
//! denials. The notifications a `call` passes on the way to its reply are held under
//! [`NOTES_BYTES`]; more is fatal ([`Error::Behind`]).

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};

use sally_core::paths::Paths;
use sally_proto::{ErrorData, MAX_FRAME};
use serde_json::{Value, json};

/// Frames read but not yet taken: the reader waits when this many are queued (architect Q91).
/// TODO(#112): fold requested/closed pairs instead, so a busy session cannot get a reading
/// approver dropped.
pub const FRAME_QUEUE: usize = 8;

/// Bytes of notifications a `call` may hold while it waits for its reply. Thousands of small
/// `approval.closed` frames fit, as do a few full prompts.
pub const NOTES_BYTES: usize = 16 << 20;

/// One frame from the reader: the frame and its length on the wire, or why reading ended.
pub(crate) type Frame = Result<(Value, usize), Error>;

/// Why a call did not get a result.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// `$XDG_RUNTIME_DIR` is unset or relative.
    #[error("XDG_RUNTIME_DIR is not set to an absolute path")]
    NoRuntimeDir,
    /// The socket could not be reached.
    #[error("{path}: {source}")]
    Connect {
        /// The socket.
        path: String,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The socket belongs to another user (or its owner could not be read).
    #[error("control.sock is owned by uid {owner:?}, not by this user; nothing was sent")]
    Owner {
        /// The owner's uid, if it could be read.
        owner: Option<u32>,
    },
    /// `sallyd` refused the request.
    #[error("{}", .0.reason)]
    Refused(ErrorData),
    /// The connection ended.
    #[error("sallyd closed the connection")]
    Closed,
    /// More notifications arrived before a reply than the client holds.
    #[error("over {NOTES_BYTES} bytes of notifications arrived before a reply")]
    Behind,
    /// A frame longer than the cap arrived.
    #[error("sallyd sent a frame over {MAX_FRAME} bytes")]
    TooLarge,
    /// A frame that is not what the protocol allows.
    #[error("sallyd sent an unexpected frame")]
    Unexpected,
    /// Reading or writing the socket failed.
    #[error("control.sock: {0}")]
    Io(#[from] std::io::Error),
}

/// `$XDG_RUNTIME_DIR/sallyport/control.sock`, derived as `sallyd` derives it (architect Q107).
///
/// # Errors
/// [`Error::NoRuntimeDir`].
pub fn socket_path(paths: &Paths) -> Result<PathBuf, Error> {
    paths.control_socket().map_err(|_| Error::NoRuntimeDir)
}

/// What one frame from `sallyd` is.
#[derive(Debug)]
pub enum Decoded {
    /// The reply to request `id`: its result or its refusal.
    Reply {
        /// The request's id.
        id: Value,
        /// The result, or why there is none.
        result: Result<Value, Error>,
    },
    /// A notification.
    Note(Value),
}

/// Splits a frame into a reply or a notification; anything else is [`Error::Unexpected`].
///
/// # Errors
/// [`Error::Unexpected`].
pub fn decode(frame: Value) -> Result<Decoded, Error> {
    match frame.get("id") {
        Some(id) => Ok(Decoded::Reply {
            id: id.clone(),
            result: reply(&frame),
        }),
        None if frame.get("method").is_some() => Ok(Decoded::Note(frame)),
        None => Err(Error::Unexpected),
    }
}

/// One connection to `sallyd`. Dropping it shuts the socket down, which also ends the reader
/// thread, so a dropped watcher stops counting as attached at once.
pub struct Client {
    w: UnixStream,
    frames: Receiver<Frame>,
    notes: VecDeque<(Value, usize)>,
    notes_bytes: usize,
    next: i64,
}

impl Client {
    /// Connects to `path` and checks the peer is this user's.
    ///
    /// # Errors
    /// [`Error::Connect`], [`Error::Owner`], or [`Error::Io`].
    pub fn connect(path: &Path) -> Result<Self, Error> {
        let s = UnixStream::connect(path).map_err(|source| Error::Connect {
            path: path.display().to_string(),
            source,
        })?;
        let owner = rustix::net::sockopt::socket_peercred(&s)
            .ok()
            .map(|c| c.uid.as_raw());
        check_owner(owner, rustix::process::getuid().as_raw())?;
        let (tx, rx) = mpsc::sync_channel(FRAME_QUEUE);
        spawn_reader(&s, tx)?;
        Ok(Self::from_parts(s, rx))
    }

    /// A client writing to `w` and taking frames from `frames` (tests feed it their own).
    pub(crate) fn from_parts(w: UnixStream, frames: Receiver<Frame>) -> Self {
        Self {
            w,
            frames,
            notes: VecDeque::new(),
            notes_bytes: 0,
            next: 1,
        }
    }

    /// Calls `method` and waits for its reply; notifications that arrive first are queued.
    ///
    /// # Errors
    /// [`Error::Refused`] for an error reply; [`Error::Behind`] when over [`NOTES_BYTES`] of
    /// notifications came first; the others when the connection fails.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, Error> {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_vec(&req).map_err(|_| Error::Unexpected)?;
        line.push(b'\n');
        self.w.write_all(&line)?;
        loop {
            let (frame, len) = self.frames.recv().map_err(|_| Error::Closed)??;
            match decode(frame)? {
                Decoded::Note(n) => self.hold(n, len)?,
                Decoded::Reply { id: got, result } if got == json!(id) => return result,
                Decoded::Reply { .. } => return Err(Error::Unexpected),
            }
        }
    }

    fn hold(&mut self, note: Value, len: usize) -> Result<(), Error> {
        let held = self.notes_bytes.saturating_add(len);
        if held > NOTES_BYTES {
            return Err(Error::Behind);
        }
        self.notes_bytes = held;
        self.notes.push_back((note, len));
        Ok(())
    }

    fn held(&mut self) -> Option<Value> {
        let (n, len) = self.notes.pop_front()?;
        self.notes_bytes = self.notes_bytes.saturating_sub(len);
        Some(n)
    }

    /// The next notification, waiting for one.
    ///
    /// # Errors
    /// The connection failed, or a reply arrived that no call asked for.
    pub fn next_note(&mut self) -> Result<Value, Error> {
        if let Some(n) = self.held() {
            return Ok(n);
        }
        let (frame, _) = self.frames.recv().map_err(|_| Error::Closed)??;
        only_note(frame)
    }

    /// The next notification if one has arrived.
    ///
    /// # Errors
    /// As [`Client::next_note`].
    pub fn try_note(&mut self) -> Result<Option<Value>, Error> {
        if let Some(n) = self.held() {
            return Ok(Some(n));
        }
        match self.frames.try_recv() {
            Ok(frame) => only_note(frame?.0).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(Error::Closed),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // The reader thread holds a clone of the socket: closing only this fd would leave the
        // connection open (and a watch attached) until sallyd ends it.
        let _ = self.w.shutdown(Shutdown::Both);
    }
}

/// Starts the thread that reads `s` into `tx`.
pub(crate) fn spawn_reader(s: &UnixStream, tx: SyncSender<Frame>) -> Result<(), Error> {
    let r = s.try_clone()?;
    std::thread::spawn(move || read_frames(BufReader::new(r), &tx));
    Ok(())
}

/// The socket's owner must be this user.
fn check_owner(owner: Option<u32>, me: u32) -> Result<(), Error> {
    if owner == Some(me) {
        Ok(())
    } else {
        Err(Error::Owner { owner })
    }
}

fn only_note(frame: Value) -> Result<Value, Error> {
    match decode(frame)? {
        Decoded::Note(n) => Ok(n),
        Decoded::Reply { .. } => Err(Error::Unexpected),
    }
}

fn reply(frame: &Value) -> Result<Value, Error> {
    if let Some(result) = frame.get("result") {
        return Ok(result.clone());
    }
    let data = frame
        .get("error")
        .and_then(|e| e.get("data"))
        .cloned()
        .and_then(|d| serde_json::from_value::<ErrorData>(d).ok())
        .ok_or(Error::Unexpected)?;
    Err(Error::Refused(data))
}

/// Reads frames until the stream ends or one fails, waiting while `tx` is full; the last item
/// sent says why reading ended (the end of the stream is [`Error::Closed`]). Returns once the
/// client is gone.
fn read_frames<R: BufRead>(mut r: R, tx: &SyncSender<Frame>) {
    loop {
        let item = match read_frame(&mut r, MAX_FRAME) {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                .map(|v| (v, bytes.len()))
                .map_err(|_| Error::Unexpected),
            Ok(None) => Err(Error::Closed),
            Err(e) => Err(e),
        };
        let last = item.is_err();
        if tx.send(item).is_err() || last {
            return;
        }
    }
}

/// The next frame of at most `max` bytes, without its newline; `None` at the end of the
/// stream. Bytes past the cap are never buffered.
///
/// # Errors
/// [`Error::TooLarge`], or the read error.
pub fn read_frame<R: BufRead>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, Error> {
    let mut line = Vec::new();
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err(Error::Closed)
            };
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let take = newline.unwrap_or(available.len());
        if line.len().saturating_add(take) > max {
            return Err(Error::TooLarge);
        }
        line.extend_from_slice(available.get(..take).unwrap_or_default());
        let used = newline.map_or(take, |n| n.saturating_add(1));
        r.consume(used);
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
