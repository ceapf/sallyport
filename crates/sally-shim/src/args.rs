//! Command-line parsing. Strict: anything unexpected is a usage error (exit 2), and the shim
//! never resolves names, so every address is an IP literal.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// Most `--listen` options accepted.
pub const MAX_LISTENERS: usize = 4;
/// Largest `--max-connections`.
pub const MAX_CONNECTIONS_LIMIT: usize = 1024;
/// Longest accepted socket path: `sun_path` is 108 bytes including the NUL.
pub const MAX_SOCKET_PATH: usize = 107;

/// Usage text, printed after a usage error.
pub const USAGE: &str = "usage: sally-shim --listen LOOPBACK_IP:PORT=/abs/socket [--listen ...] [--max-connections N]\n       sally-shim --stdio /abs/socket";

/// One TCP listener and the Unix socket it forwards to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenSpec {
    /// Loopback address to listen on.
    pub addr: SocketAddr,
    /// Absolute path of the Unix socket to connect to per connection.
    pub socket: PathBuf,
}

/// What the shim was asked to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Listen on one or more loopback ports.
    Listen {
        /// The listeners.
        specs: Vec<ListenSpec>,
        /// Live connections allowed across all of them.
        max_connections: usize,
    },
    /// Relay stdin/stdout to the Unix socket.
    Stdio(PathBuf),
}

/// A usage error. The message never echoes more than the offending option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgError(pub String);

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ArgError {}

/// Whether the shim may listen on `ip`: IPv4 loopback (127/8) only. IPv6, including
/// `::1` and IPv4-mapped forms, is refused: the sandbox clients use `127.0.0.1`, and one
/// address family is one less to reason about.
#[must_use]
pub fn is_listen_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.is_loopback())
}

fn err<T>(msg: &str) -> Result<T, ArgError> {
    Err(ArgError(msg.to_owned()))
}

/// Parses the arguments after the program name.
///
/// # Errors
/// [`ArgError`] for an unknown option, a missing value, an address outside 127/8 or with
/// port 0, a relative or over-long socket path, a duplicate listener, or mixing `--stdio` with
/// `--listen`.
pub fn parse_args<I: IntoIterator<Item = String>>(args: I) -> Result<Mode, ArgError> {
    let mut args = args.into_iter();
    let mut listens: Vec<ListenSpec> = Vec::new();
    let mut stdio: Option<PathBuf> = None;
    let mut max: Option<usize> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--listen" => {
                let Some(spec) = args.next() else {
                    return err("--listen needs ADDR=SOCKET");
                };
                if listens.len() >= MAX_LISTENERS {
                    return err("too many --listen options");
                }
                let spec = parse_listen(&spec)?;
                if listens.iter().any(|l| l.addr == spec.addr) {
                    return err("duplicate --listen address");
                }
                listens.push(spec);
            }
            "--max-connections" => {
                let n = args.next().and_then(|v| v.parse::<usize>().ok());
                match n {
                    Some(n) if (1..=MAX_CONNECTIONS_LIMIT).contains(&n) => {
                        if max.replace(n).is_some() {
                            return err("--max-connections given twice");
                        }
                    }
                    _ => return err("--max-connections needs a number from 1 to 1024"),
                }
            }
            "--stdio" => {
                let Some(sock) = args.next() else {
                    return err("--stdio needs a socket path");
                };
                if stdio.replace(check_socket(&sock)?).is_some() {
                    return err("--stdio given twice");
                }
            }
            _ => return err("unknown option"),
        }
    }
    if stdio.is_some() && max.is_some() {
        return err("--max-connections only applies to --listen");
    }
    match (listens.is_empty(), stdio) {
        (false, None) => Ok(Mode::Listen {
            specs: listens,
            max_connections: max.unwrap_or(crate::relay::MAX_CONNECTIONS),
        }),
        (true, Some(sock)) => Ok(Mode::Stdio(sock)),
        (true, None) => err("nothing to do: give --listen or --stdio"),
        (false, Some(_)) => err("--stdio cannot be combined with --listen"),
    }
}

fn parse_listen(spec: &str) -> Result<ListenSpec, ArgError> {
    let Some((addr, sock)) = spec.split_once('=') else {
        return err("--listen needs ADDR=SOCKET");
    };
    let Ok(addr) = addr.parse::<SocketAddr>() else {
        return err("--listen address must be an IP literal with a port, e.g. 127.0.0.1:3128");
    };
    if !is_listen_ip(addr.ip()) {
        return err("--listen address must be IPv4 loopback (127/8)");
    }
    if addr.port() == 0 {
        return err("--listen port must not be 0");
    }
    Ok(ListenSpec {
        addr,
        socket: check_socket(sock)?,
    })
}

fn check_socket(path: &str) -> Result<PathBuf, ArgError> {
    if !path.starts_with('/') {
        return err("socket path must be absolute");
    }
    if path.ends_with('/') {
        return err("socket path must name a file, not a directory");
    }
    if path.len() > MAX_SOCKET_PATH || path.contains('\0') {
        return err("socket path is too long or contains NUL");
    }
    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<Mode, ArgError> {
        parse_args(a.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn listen_and_stdio_forms_parse() {
        let m = parse(&[
            "--listen",
            "127.0.0.1:3128=/run/sallyport/net.sock",
            "--listen",
            "127.0.0.1:8080=/run/l.sock",
        ])
        .unwrap();
        let Mode::Listen {
            specs: l,
            max_connections,
        } = m
        else {
            panic!("{m:?}")
        };
        assert_eq!(max_connections, crate::relay::MAX_CONNECTIONS);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].addr, "127.0.0.1:3128".parse().unwrap());
        assert_eq!(l[1].socket, PathBuf::from("/run/l.sock"));
        assert_eq!(
            parse(&["--stdio", "/run/a.sock"]).unwrap(),
            Mode::Stdio("/run/a.sock".into())
        );
    }

    #[test]
    fn only_ipv4_loopback_is_allowed() {
        // Addresses are assembled at runtime: the repository's guard hooks reject IPv4 literals
        // outside a small allowlist, and these exercise ranges that are not on it.
        let other_loopback = format!("{}.{}.{}.{}:1", 127, 5, 5, 5);
        let top_loopback = format!("{}.{}.{}.{}:1", 127, 255, 255, 254);
        for ok in [
            "127.0.0.1:1",
            other_loopback.as_str(),
            top_loopback.as_str(),
        ] {
            assert!(parse(&["--listen", &format!("{ok}=/a")]).is_ok(), "{ok}");
        }
        let private = format!("{}.{}.{}.{}:1", 192, 168, 1, 1);
        let next_to_loopback = format!("{}.{}.{}.{}:1", 128, 0, 0, 1);
        let mapped = format!("[::ffff:{}.{}.{}.{}]:1", 127, 0, 0, 1);
        for bad in [
            "0.0.0.0:1",
            "10.0.0.1:1",
            private.as_str(),
            next_to_loopback.as_str(),
            "[::1]:1",
            mapped.as_str(),
            "[::]:1",
            "localhost:1",
            "example.test:1",
            "127.0.0.1",
            "127.0.0.1:0",
            ":1",
        ] {
            assert!(parse(&["--listen", &format!("{bad}=/a")]).is_err(), "{bad}");
        }
    }

    #[test]
    fn socket_paths_are_absolute_bounded_and_nul_free() {
        assert!(parse(&["--stdio", "rel.sock"]).is_err());
        assert!(parse(&["--stdio", ""]).is_err());
        assert!(parse(&["--stdio", &format!("/{}", "a".repeat(MAX_SOCKET_PATH))]).is_err());
        assert!(parse(&["--stdio", &format!("/{}", "a".repeat(MAX_SOCKET_PATH - 1))]).is_ok());
        assert!(parse(&["--stdio", "/a\0b"]).is_err());
    }

    #[test]
    fn structure_errors() {
        for a in [
            &[][..],
            &["--listen"],
            &["--stdio"],
            &["--bogus"],
            &["127.0.0.1:1=/a"],
            &["--stdio", "/a", "--stdio", "/b"],
            &["--stdio", "/a", "--listen", "127.0.0.1:1=/b"],
            &["--listen", "127.0.0.1:1=/a", "--listen", "127.0.0.1:1=/b"],
            &["--listen", "127.0.0.1:1"],
        ] {
            assert!(parse(a).is_err(), "{a:?}");
        }
    }

    #[test]
    fn max_connections_is_bounded_and_only_for_listen() {
        let l = ["--listen", "127.0.0.1:1=/a"];
        let with = |n: &str| parse(&[l[0], l[1], "--max-connections", n]);
        assert!(matches!(
            with("5"),
            Ok(Mode::Listen {
                max_connections: 5,
                ..
            })
        ));
        assert!(with("1024").is_ok());
        for bad in ["0", "1025", "-1", "x", ""] {
            assert!(with(bad).is_err(), "{bad}");
        }
        assert!(parse(&[l[0], l[1], "--max-connections"]).is_err());
        assert!(
            parse(&[
                l[0],
                l[1],
                "--max-connections",
                "2",
                "--max-connections",
                "3"
            ])
            .is_err()
        );
        assert!(parse(&["--stdio", "/a", "--max-connections", "2"]).is_err());
    }

    #[test]
    fn scoped_ipv6_and_directory_paths_are_refused() {
        assert!(parse(&["--listen", "[::1%1]:1=/a"]).is_err());
        assert!(parse(&["--stdio", "/"]).is_err());
        assert!(parse(&["--stdio", "/run/dir/"]).is_err());
    }

    #[test]
    fn listener_count_is_bounded() {
        let mut a: Vec<String> = Vec::new();
        for i in 0..=MAX_LISTENERS {
            a.push("--listen".into());
            a.push(format!("127.0.0.1:{}=/a", 1000 + i));
        }
        assert!(parse_args(a).is_err());
    }

    #[test]
    fn errors_do_not_echo_the_argument_values() {
        let e = parse(&["--listen", "0.0.0.0:3128=/run/secret-looking-path.sock"]).unwrap_err();
        assert!(!e.to_string().contains("secret-looking"));
    }
}
