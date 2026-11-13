//! Broker-originated connections (#75; architect rulings Q1, Q2 and Q7), without containers.

#![allow(clippy::unwrap_used)]

use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use rustls::RootCertStore;
use sally_core::audit::Actor;
use serde_json::json;

use super::*;
use crate::egress::ca::{SessionTls, Validity};
use crate::egress::inject::testing::credentials;

#[derive(Default)]
struct Rows(Mutex<Vec<Value>>);

impl AuditSink for Rows {
    fn append(&self, e: NewEntry, _: AuditLevel) -> Result<(), AuditError> {
        self.0.lock().unwrap().push(e.arguments().clone());
        Ok(())
    }
}

fn entry(args: Option<Value>) -> NewEntry {
    let e = NewEntry::new(Actor::Sallyd, "egress.allow");
    match args {
        Some(a) => e.args(a),
        None => e,
    }
}

#[tokio::test]
async fn entries_of_a_broker_originated_connection_carry_its_origin_and_no_others_do() {
    let rows = Arc::new(Rows::default());
    let inner: Arc<dyn AuditSink> = rows.clone();
    let origin = json!({"tool": "fetch", "call": 7});
    ORIGIN
        .scope(origin.clone(), async {
            let s = sink(&inner);
            s.append(
                entry(Some(json!({"host": "a.mock.test"}))),
                AuditLevel::default(),
            )
            .unwrap();
            s.append(entry(None), AuditLevel::default()).unwrap();
        })
        .await;
    let plain = sink(&inner);
    assert!(
        Arc::ptr_eq(&plain, &inner),
        "an accepted connection's sink is the proxy's own"
    );
    plain
        .append(
            entry(Some(json!({"host": "b.mock.test"}))),
            AuditLevel::default(),
        )
        .unwrap();
    assert_eq!(
        *rows.0.lock().unwrap(),
        vec![
            json!({"host": "a.mock.test", "origin": origin}),
            json!({"origin": origin}),
            json!({"host": "b.mock.test"}),
        ]
    );
}

fn roots() -> Roots {
    Roots {
        store: Arc::new(RootCertStore::empty()),
        pem: String::new(),
        skipped: 0,
        path: "/test-roots.pem".into(),
    }
}

fn interception(hosts: &[&str]) -> Interception {
    let v = Validity::for_session(SystemTime::now(), Duration::from_secs(600)).unwrap();
    let owned: Vec<String> = hosts.iter().map(|h| (*h).to_owned()).collect();
    let tls = SessionTls::mint(&owned, v).unwrap();
    Interception::new(tls, roots(), credentials(hosts)).unwrap()
}

#[test]
fn a_session_without_roots_has_no_client_tls() {
    assert!(ClientTls::of(None, None).unwrap().is_none());
}

#[test]
fn without_a_session_ca_every_host_is_verified_against_the_upstream_roots() {
    let t = ClientTls::of(None, Some(&roots())).unwrap().unwrap();
    assert!(t.session_ca.is_none());
    assert!(Arc::ptr_eq(&t.choose("a.mock.test"), &t.upstream));
    assert_eq!(t.upstream.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[test]
fn a_leaf_host_trusts_the_session_ca_only_and_any_other_host_the_proxys_upstream_config() {
    let i = interception(&["a.mock.test", "b.mock.test"]);
    // Roots given beside an interception are not used: the interception's own are.
    let t = ClientTls::of(Some(&i), Some(&roots())).unwrap().unwrap();
    assert!(
        Arc::ptr_eq(&t.upstream, i.upstream()),
        "one upstream configuration"
    );
    let (ca, hosts) = t.session_ca.clone().unwrap();
    assert_eq!(hosts, ["a.mock.test", "b.mock.test"]);
    for leaf in ["a.mock.test", "b.mock.test"] {
        assert!(Arc::ptr_eq(&t.choose(leaf), &ca), "{leaf}");
    }
    for other in ["c.mock.test", "x.a.mock.test", "mock.test", ""] {
        assert!(Arc::ptr_eq(&t.choose(other), i.upstream()), "{other}");
    }
    assert!(!Arc::ptr_eq(&ca, i.upstream()));
    assert_eq!(ca.alpn_protocols, vec![b"http/1.1".to_vec()]);
}

#[tokio::test]
async fn open_hands_the_proxys_half_and_the_origin_to_the_accept_loop() {
    let (tx, mut rx) = mpsc::channel::<Opened>(1);
    let grants = HostGrants {
        headers: vec!["x-key".into()],
        names: vec!["secret:K".into()],
    };
    let reach = Reach {
        tls: ClientTls::of(None, Some(&roots())).unwrap().unwrap(),
        grants: vec![("a.mock.test".into(), grants.clone())],
    };
    let c = Local::new(tx, reach);
    assert_eq!(c.grants("a.mock.test"), grants);
    assert_eq!(c.grants("b.mock.test"), HostGrants::default());
    let mut ours = c.open(json!({"call": 1})).unwrap();
    // The queue is full: the next one is refused, not queued.
    let full = c.open(json!({"call": 2})).unwrap_err();
    assert_eq!(full.kind(), io::ErrorKind::WouldBlock);
    let (mut theirs, origin) = rx.recv().await.unwrap();
    assert_eq!(origin, json!({"call": 1}));
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ours.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    theirs.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping");
    drop(rx);
    let closed = c.open(json!({"call": 3})).unwrap_err();
    assert_eq!(closed.kind(), io::ErrorKind::BrokenPipe);
    assert!(Arc::ptr_eq(
        &c.client_tls("a.mock.test"),
        &c.reach.tls.upstream
    ));
}

#[test]
fn host_grants_name_each_grant_hosts_headers_and_credentials_once() {
    use crate::egress::policy::Grant;
    let spec = |name: &str, host: &str, header: &str| Spec {
        name: name.into(),
        host: host.into(),
        header: header.into(),
        format: "{value}".into(),
        basic_user: None,
    };
    let specs = [
        spec("A", "a.mock.test", "X-Key"),
        spec("B", "b.mock.test", "Authorization"),
        spec("C", "a.mock.test", "X-Other"),
        spec("A", "a.mock.test", "X-Key"),
    ];
    let grants = specs
        .iter()
        .map(|s| Grant {
            host: s.host.clone(),
            header: s.header.clone(),
        })
        .collect();
    let policy = Policy::new(vec![], grants);
    let got = host_grants(&policy, &specs);
    let g = |headers: &[&str], names: &[&str]| HostGrants {
        headers: headers.iter().map(|s| (*s).to_owned()).collect(),
        names: names.iter().map(|s| (*s).to_owned()).collect(),
    };
    assert_eq!(
        got,
        vec![
            (
                "a.mock.test".to_owned(),
                g(&["x-key", "x-other"], &["secret:A", "secret:C"])
            ),
            (
                "b.mock.test".to_owned(),
                g(&["authorization"], &["secret:B"])
            ),
        ]
    );
}
