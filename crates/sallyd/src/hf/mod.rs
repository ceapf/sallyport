//! The Hugging Face client's transport: the sockets for the decisions `sally_core::hf` makes.
//!
//! Every hop is planned by the core ([`sally_core::hf::plan`]), connected by [`conn`] (resolve
//! on this host, refuse loopback, private, link-local and own addresses, dial a pinned address,
//! TLS verified against the anchors of a checked CA bundle, [`HfClient::with_roots`]), sent as [`wire`] builds it (the token only on a hop
//! to `huggingface.co` itself), and its head decided by the core ([`sally_core::hf::head`]).
//! File bytes go only into a [`sally_core::library::Download`]; its verify checks the listed
//! SHA-256 before anything else reads them, on a blocking thread without the library's lock,
//! and only then does the library promote it. Every connection's task is aborted when its
//! response is dropped.
//!
//! Bounds: the lookup, each connect and the TLS handshake as in [`conn`]; each response head
//! [`HEAD_TIMEOUT`]; each list exchange [`LIST_TIMEOUT`] in all; a file body may take as long as
//! it needs, but a wait for its next bytes longer than [`BODY_IDLE`] stops it (the partial is
//! kept for a resume).

// TODO(#209): the first caller (a user-initiated control method) writes model.import and
// model.refuse before their effect is visible, passes the daemon's free-space floor as the
// library's reserve, and reads the token from the secrets store.

pub mod conn;
pub mod error;
mod wire;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::BodyExt as _;
use hyper::body::{Bytes, Incoming};
use hyper_util::rt::TokioIo;
use sally_core::hf::head::{Body, Step, Tries, decide_file, decide_list};
use sally_core::hf::list::{FileList, Wanted, parse_list};
use sally_core::hf::names::{Commit, RepoId, RepoPath, Revision};
use sally_core::hf::plan::{Request, file_request, list_request, next_fetch};
use sally_core::hf::{HfError, MAX_LIST_BYTES};
use sally_core::library::{Download, Entry, Library, LibraryError};
use sally_core::secrets::Secret;

pub use error::PullError;
use wire::HeadValues;

use crate::egress::roots::BundleFiles;
use crate::egress::server::{Dialer, HostAddrs, Resolver, upstream_builder};

/// Longest wait for a response head after the request is sent.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest one file-list exchange may take, head and body.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for a file body's next bytes.
pub const BODY_IDLE: Duration = Duration::from_secs(60);
/// File bytes gathered before one blocking write to the partial.
const WRITE_BATCH: usize = 1 << 20;

/// The library a pull writes into: one owner at a time, used from blocking tasks only. A
/// mutex poisoned by a panic is refused ([`PullError::LibraryPoisoned`]) until sallyd
/// restarts, never recovered in place: the files survive a crash, the in-memory index
/// connection and counters may not.
pub type SharedLibrary = Arc<Mutex<Library>>;

/// The client: its resolver, dialer and own-address source (wired once, by the caller), the
/// TLS configuration built from a checked CA bundle, and the token, if any.
pub struct HfClient<R, D, H> {
    resolver: R,
    dialer: D,
    own: H,
    tls: Arc<rustls::ClientConfig>,
    token: Option<Secret<String>>,
}

impl<R: Resolver, D: Dialer, H: HostAddrs> HfClient<R, D, H> {
    /// A client over these seams whose TLS anchors are loaded from `roots` with the egress
    /// proxy's checks (the first bundle that exists, owned by the expected user, not group- or
    /// other-writable). Production passes [`BundleFiles::default`], the system bundle owned by
    /// root; the environment never chooses the anchors of this credential-carrying connection.
    /// Blocking (it reads the bundle): call it off the runtime.
    ///
    /// # Errors
    /// [`PullError::Roots`] when no bundle may be trusted.
    pub fn with_roots(
        resolver: R,
        dialer: D,
        own: H,
        roots: &BundleFiles,
        token: Option<Secret<String>>,
    ) -> Result<Self, PullError> {
        let loaded = roots.load()?;
        let tls = conn::client_config(loaded.store)?;
        Ok(Self::new(resolver, dialer, own, tls, token))
    }

    /// The fields as given; only [`HfClient::with_roots`] builds `tls`.
    const fn new(
        resolver: R,
        dialer: D,
        own: H,
        tls: Arc<rustls::ClientConfig>,
        token: Option<Secret<String>>,
    ) -> Self {
        Self {
            resolver,
            dialer,
            own,
            tls,
            token,
        }
    }

    /// The file list of `repo` at `rev`.
    ///
    /// # Errors
    /// The first refusal or failure.
    pub async fn files(&self, repo: &RepoId, rev: &Revision) -> Result<FileList, PullError> {
        let mut req = list_request(repo, rev);
        let mut tries = Tries::default();
        loop {
            let exchange = async {
                let answer = self.exchange(&req).await?;
                let head = answer.head()?;
                match decide_list(&head.head(), &req, &mut tries)? {
                    Step::Body(_) => read_list(answer.into_body()).await.map(Ok),
                    other => Ok(Err(other)),
                }
            };
            let step = tokio::time::timeout(LIST_TIMEOUT, exchange)
                .await
                .map_err(|_| PullError::Timeout("file list"))??;
            match step {
                Ok(body) => return Ok(parse_list(&body)?),
                Err(Step::Redirect(next)) => req = next,
                Err(Step::Wait(secs)) => tokio::time::sleep(Duration::from_secs(secs)).await,
                Err(Step::Body(_)) => return Err(PullError::Protocol),
            }
        }
    }

    /// Pulls the file at `path` of `list` into `lib`. A digest already stored (its blob
    /// passing the library's checks) is answered from the library with no request. Otherwise
    /// the download begins (or resumes), the rest of the file is fetched at the list's commit,
    /// the download is verified on a blocking thread without the library's lock, and the
    /// library promotes it.
    ///
    /// # Errors
    /// The first refusal or failure. A refusal whose bytes cannot be trusted deletes the
    /// partial; a stopped body keeps it for the next pull.
    pub async fn pull(
        &self,
        lib: &SharedLibrary,
        repo: &RepoId,
        list: &FileList,
        path: &RepoPath,
    ) -> Result<Entry, PullError> {
        let wanted = list.wanted(path)?;
        let w = wanted.clone();
        // One hold of the library: no pull can finish between the check and the begin.
        let start = with_library(lib, move |l| match l.stored(w.sha256())? {
            Some(entry) => Ok(Start::Stored(entry)),
            None => l
                .begin_download(w.path().file_name(), w.sha256(), w.size())
                .map(Start::Begun),
        })
        .await?;
        let d = match start {
            Start::Stored(entry) => return Ok(entry),
            Start::Begun(d) => d,
        };
        let d = match next_fetch(d.written(), d.size()) {
            Some(from) => self.fetch(d, repo, list.commit(), wanted, from).await?,
            None => d,
        };
        let verified = tokio::task::spawn_blocking(move || d.verify())
            .await
            .map_err(|_| PullError::Task)??;
        with_library(lib, move |l| l.promote(verified)).await
    }

    /// Fetches the rest of the file into `d`, following redirects and waits.
    async fn fetch(
        &self,
        d: Download,
        repo: &RepoId,
        commit: &Commit,
        wanted: &Wanted,
        from: u64,
    ) -> Result<Download, PullError> {
        let mut req = file_request(repo, commit, wanted.path(), from);
        let mut tries = Tries::default();
        loop {
            let answer = self.exchange(&req).await?;
            let head = answer.head()?;
            match decide_file(&head.head(), &req, &mut tries, d.written(), d.size()) {
                Ok(Step::Redirect(next)) => req = next,
                Ok(Step::Wait(secs)) => {
                    // The answer is done with: its connection ends before the wait.
                    drop(answer);
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                }
                Ok(Step::Body(how)) => return stream(d, how, answer.into_body()).await,
                Err(e) => return Err(refuse(d, e).await),
            }
        }
    }

    /// One request on a fresh connection, and its response head. The task driving the
    /// connection travels with the response and its body, and is aborted when they are
    /// dropped.
    async fn exchange(&self, req: &Request) -> Result<Answer, PullError> {
        let host = req.host();
        let addrs = conn::pinned(&self.resolver, &self.own, host).await?;
        let tcp = conn::dial(&self.dialer, &addrs, host).await?;
        let tls = conn::tls(&self.tls, tcp, host).await?;
        let request = wire::build(req, self.token.as_ref())?;
        let (mut sender, connection) = upstream_builder()
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| PullError::Protocol)?;
        let conn = ConnTask::spawn(async move {
            let _ = connection.await;
        });
        match tokio::time::timeout(HEAD_TIMEOUT, sender.send_request(request)).await {
            Ok(Ok(resp)) => Ok(Answer { resp, conn }),
            Ok(Err(_)) => Err(PullError::Protocol),
            Err(_) => Err(PullError::Timeout("response head")),
        }
    }
}

/// How a pull starts: from a stored row, or with a download begun.
enum Start {
    Stored(Entry),
    Begun(Download),
}

/// The task driving one exchange's connection. Dropping it aborts the task, so no connection
/// outlives the exchange that opened it (SI-12), whatever the HTTP layer does with a dropped
/// response.
struct ConnTask(tokio::task::JoinHandle<()>);

impl ConnTask {
    /// Runs `conn` on its own task, aborted when the returned guard is dropped.
    fn spawn(conn: impl Future<Output = ()> + Send + 'static) -> Self {
        Self(tokio::spawn(conn))
    }
}

impl Drop for ConnTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A response and the guard on its connection.
struct Answer {
    resp: hyper::Response<Incoming>,
    conn: ConnTask,
}

impl Answer {
    /// The response head's values for the decision layer.
    fn head(&self) -> Result<HeadValues, PullError> {
        HeadValues::of(self.resp.status().as_u16(), self.resp.headers())
    }

    /// The body, still holding the connection's guard.
    fn into_body(self) -> AnswerBody {
        AnswerBody {
            body: self.resp.into_body(),
            _conn: self.conn,
        }
    }
}

/// A response body and the guard on its connection: the connection lives while the body is
/// read, and no longer.
struct AnswerBody {
    body: Incoming,
    _conn: ConnTask,
}

/// The list body, at most [`MAX_LIST_BYTES`]; one byte more is the refusal.
async fn read_list(mut answer: AnswerBody) -> Result<Vec<u8>, PullError> {
    let body = &mut answer.body;
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| PullError::Protocol)?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > MAX_LIST_BYTES {
                return Err(HfError::ListTooLarge.into());
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// Writes the body into `d`: emptied first for [`Body::FromStart`], then appended in batches.
/// A body that stops or stalls keeps what arrived.
async fn stream(mut d: Download, how: Body, mut answer: AnswerBody) -> Result<Download, PullError> {
    let body = &mut answer.body;
    if how == Body::FromStart {
        d = blocking(d, |d| d.restart()).await?;
    }
    let mut batch: Vec<u8> = Vec::with_capacity(WRITE_BATCH);
    loop {
        let next = tokio::time::timeout(BODY_IDLE, body.frame()).await;
        let data = match next {
            Ok(Some(Ok(frame))) => frame.into_data().unwrap_or_else(|_| Bytes::new()),
            Ok(None) => break,
            Ok(Some(Err(_))) | Err(_) => {
                let _ = flush(d, batch).await;
                return Err(PullError::BodyFailed);
            }
        };
        batch.extend_from_slice(&data);
        if batch_full(batch.len()) {
            let full = std::mem::replace(&mut batch, Vec::with_capacity(WRITE_BATCH));
            d = flush(d, full).await?;
        }
    }
    flush(d, batch).await
}

/// Whether a batch of `len` bytes is written now.
const fn batch_full(len: usize) -> bool {
    len >= WRITE_BATCH
}

/// Appends `batch` to the partial on a blocking thread.
async fn flush(d: Download, batch: Vec<u8>) -> Result<Download, PullError> {
    blocking(d, move |d| d.append(&batch)).await
}

/// Runs `f` on `d` on a blocking thread and hands `d` back. A library refusal there drops it
/// (the partial is kept), except a too-long body, which discards it.
async fn blocking(
    d: Download,
    f: impl FnOnce(&mut Download) -> Result<(), LibraryError> + Send + 'static,
) -> Result<Download, PullError> {
    let (d, r) = tokio::task::spawn_blocking(move || {
        let mut d = d;
        let r = f(&mut d);
        (d, r)
    })
    .await
    .map_err(|_| PullError::Task)?;
    match r {
        Ok(()) => Ok(d),
        Err(LibraryError::DownloadTooLong) => {
            let _ = tokio::task::spawn_blocking(move || d.discard()).await;
            Err(LibraryError::DownloadTooLong.into())
        }
        Err(e) => Err(e.into()),
    }
}

/// The refusal `e`, after deleting the partial when its bytes can no longer be trusted.
async fn refuse(d: Download, e: HfError) -> PullError {
    if e.discards_partial() {
        let _ = tokio::task::spawn_blocking(move || d.discard()).await;
    }
    e.into()
}

/// Runs `f` on the library on a blocking thread.
async fn with_library<T: Send + 'static>(
    lib: &SharedLibrary,
    f: impl FnOnce(&mut Library) -> Result<T, LibraryError> + Send + 'static,
) -> Result<T, PullError> {
    let lib = Arc::clone(lib);
    tokio::task::spawn_blocking(move || {
        let mut guard = lib.lock().map_err(|_| PullError::LibraryPoisoned)?;
        f(&mut guard).map_err(PullError::from)
    })
    .await
    .map_err(|_| PullError::Task)?
}

#[cfg(test)]
#[path = "testkit.rs"]
mod testkit;

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "bounds_tests.rs"]
mod bounds_tests;
