//! The per-connection handler of the egress proxy. Its network effects go through the resolver
//! and dialer it is built with (Task 8 decision 10), so its decisions are tested without
//! containers; `net.rs` holds the real ones.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::head::{self, MAX_HEAD, Parsed};
use super::policy::Reason;

/// Time a client gets to send a complete request head (decision 8).
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Reads a request head from `client` into `buf`, within `limit`. Returns how many bytes of `buf`
/// are filled: the complete head, plus any bytes the client sent after it (they belong to the
/// tunnel).
///
/// # Errors
/// [`Reason::HeadTooLarge`] past 8 KiB or 100 header lines, [`Reason::HeadTimeout`] when `limit`
/// passes first, [`Reason::Malformed`] for a head that is not HTTP/1.x or a client that closes
/// or fails before completing one.
pub async fn read_head<S: AsyncRead + Unpin>(
    client: &mut S,
    buf: &mut [u8; MAX_HEAD],
    limit: Duration,
) -> Result<usize, Reason> {
    let mut filled = 0;
    let reading = async {
        loop {
            match head::parse(buf.get(..filled).unwrap_or_default()) {
                Parsed::Complete(_) => return Ok(filled),
                Parsed::TooLarge => return Err(Reason::HeadTooLarge),
                Parsed::Malformed => return Err(Reason::Malformed),
                Parsed::Partial => {}
            }
            let free = buf.get_mut(filled..).ok_or(Reason::HeadTooLarge)?;
            let n = client.read(free).await.map_err(|_| Reason::Malformed)?;
            if n == 0 {
                return Err(Reason::Malformed);
            }
            filled += n;
        }
    };
    tokio::time::timeout(limit, reading)
        .await
        .unwrap_or(Err(Reason::HeadTimeout))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex};

    const SHORT: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn a_head_sent_in_pieces_is_read_with_what_follows_it() {
        let (mut client, mut proxy) = duplex(64);
        let sender = tokio::spawn(async move {
            for part in [
                &b"CONNECT mock.te"[..],
                b"st:443 HTTP/1.1\r\n",
                b"\r\nhello",
            ] {
                client.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
            client
        });
        let mut buf = [0u8; MAX_HEAD];
        let filled = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await.unwrap();
        let _client = sender.await.unwrap();
        let head_len = b"CONNECT mock.test:443 HTTP/1.1\r\n\r\n".len();
        assert!(filled >= head_len);
        assert_eq!(&buf[..head_len], b"CONNECT mock.test:443 HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn a_head_over_8_kib_is_too_large() {
        let (mut client, mut proxy) = duplex(MAX_HEAD * 2);
        let mut req = b"CONNECT mock.test:443 HTTP/1.1\r\nX: ".to_vec();
        req.resize(MAX_HEAD + 100, b'a');
        client.write_all(&req).await.unwrap();
        let mut buf = [0u8; MAX_HEAD];
        let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
        assert_eq!(got, Err(Reason::HeadTooLarge));
    }

    #[tokio::test]
    async fn a_silent_or_slow_client_times_out() {
        let (mut client, mut proxy) = duplex(64);
        client
            .write_all(b"CONNECT mock.test:443 HTTP/1.1\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; MAX_HEAD];
        let got = read_head(&mut proxy, &mut buf, SHORT).await;
        assert_eq!(got, Err(Reason::HeadTimeout));
        drop(client);
    }

    #[tokio::test]
    async fn closing_before_a_complete_head_is_malformed() {
        let (mut client, mut proxy) = duplex(64);
        client
            .write_all(b"CONNECT mock.test:443 HTTP/1.1\r\n")
            .await
            .unwrap();
        drop(client);
        let mut buf = [0u8; MAX_HEAD];
        let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
        assert_eq!(got, Err(Reason::Malformed));
    }

    #[tokio::test]
    async fn garbage_is_malformed_at_once() {
        let (mut client, mut proxy) = duplex(64);
        client.write_all(b"\x16\x03\x01\x02\x00").await.unwrap();
        let mut buf = [0u8; MAX_HEAD];
        let got = read_head(&mut proxy, &mut buf, HEAD_TIMEOUT).await;
        assert_eq!(got, Err(Reason::Malformed));
        drop(client);
    }
}
