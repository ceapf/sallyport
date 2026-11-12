#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::os::unix::fs::{PermissionsExt, symlink};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

use super::*;

/// A fresh directory under `target/` for one test.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::current_dir()
        .unwrap()
        .join("../../target/roots-unit")
        .join(std::process::id().to_string())
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// A self-signed CA certificate, PEM.
fn ca_pem(cn: &str) -> String {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.self_signed(&key).unwrap().pem()
}

/// A well-formed PEM `CERTIFICATE` section that is no certificate.
fn junk_pem() -> String {
    encode(&CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01]))
}

fn write(path: &Path, body: &str, mode: u32) {
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn files(paths: &[&Path]) -> BundleFiles {
    BundleFiles {
        paths: paths.iter().map(|p| p.to_path_buf()).collect(),
        owner: uid(),
    }
}

fn why(r: Result<Roots, RootsError>) -> String {
    r.unwrap_err().to_string()
}

#[test]
fn production_reads_the_system_bundles_as_root_owned() {
    let d = BundleFiles::default();
    assert_eq!(d.owner, 0);
    assert_eq!(d.paths, SYSTEM_BUNDLES.map(PathBuf::from));
    assert_eq!(MAX_BUNDLE_BYTES, 4 * 1024 * 1024);
}

#[test]
fn usable_certificates_are_kept_reencoded_and_unusable_ones_counted() {
    let dir = scratch("usable");
    let (a, b) = (ca_pem("root a"), ca_pem("root b"));
    let crlf = a.replace('\n', "\r\n");
    let body = format!("# comment\n{crlf}{}\n{b}", junk_pem());
    let f = dir.join("bundle.pem");
    write(&f, &body, 0o644);
    let roots = files(&[&f]).load().unwrap();
    assert_eq!(roots.store.len(), 2);
    assert_eq!(roots.skipped, 1);
    assert_eq!(roots.path, f);
    assert_eq!(roots.pem, format!("{a}{b}"), "LF, accepted only, in order");
    assert!(!roots.pem.contains('\r') && !roots.pem.contains("comment"));
}

#[test]
fn the_first_existing_candidate_is_used_and_a_missing_one_skipped() {
    let dir = scratch("first");
    let (one, two) = (dir.join("one.pem"), dir.join("two.pem"));
    write(&one, &ca_pem("one"), 0o644);
    write(
        &two,
        &format!("{}{}", ca_pem("two"), ca_pem("three")),
        0o644,
    );
    let missing = dir.join("missing.pem");
    let under_missing = dir.join("nodir").join("x.pem");
    let roots = files(&[&missing, &under_missing, &one, &two])
        .load()
        .unwrap();
    assert_eq!((roots.path, roots.store.len()), (one, 1));
}

#[test]
fn no_candidate_at_all_names_every_path_tried() {
    let dir = scratch("none");
    let (a, b) = (dir.join("a.pem"), dir.join("b.pem"));
    let e = why(files(&[&a, &b]).load());
    assert!(e.contains("no CA bundle found"), "{e}");
    assert!(
        e.contains(&format!("{}, {}", a.display(), b.display())),
        "{e}"
    );
    assert!(why(files(&[]).load()).contains("no CA bundle found"));
}

#[test]
fn a_candidate_that_exists_but_fails_is_an_error_never_skipped() {
    let dir = scratch("fails");
    let good = dir.join("good.pem");
    write(&good, &ca_pem("good"), 0o644);
    let unreadable = dir.join("unreadable.pem");
    write(&unreadable, &ca_pem("x"), 0o000);
    let e = why(files(&[&unreadable, &good]).load());
    assert!(e.contains(&unreadable.display().to_string()), "{e}");
    let writable = dir.join("writable.pem");
    write(&writable, &ca_pem("x"), 0o666);
    assert!(why(files(&[&writable, &good]).load()).contains("writable"));
}

#[test]
fn the_owner_must_match() {
    let dir = scratch("owner");
    let f = dir.join("b.pem");
    write(&f, &ca_pem("x"), 0o644);
    assert!(files(&[&f]).load().is_ok());
    let other = BundleFiles {
        paths: vec![f.clone()],
        owner: uid().wrapping_add(1),
    };
    let e = why(other.load());
    assert!(e.contains("not owned by the expected user"), "{e}");
    assert!(e.contains(&f.display().to_string()), "{e}");
}

#[test]
fn group_or_other_write_is_refused_read_bits_are_not() {
    let dir = scratch("modes");
    let f = dir.join("b.pem");
    write(&f, &ca_pem("x"), 0o444);
    for ok in [0o400, 0o444, 0o644, 0o755] {
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(ok)).unwrap();
        assert!(files(&[&f]).load().is_ok(), "{ok:o}");
    }
    for bad in [0o664, 0o646, 0o620, 0o602] {
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(bad)).unwrap();
        assert!(
            why(files(&[&f]).load()).contains("group- or other-writable"),
            "{bad:o}"
        );
    }
}

#[test]
fn a_symlink_is_followed_to_a_regular_file() {
    let dir = scratch("link");
    let f = dir.join("real.pem");
    write(&f, &ca_pem("x"), 0o644);
    let l = dir.join("link.pem");
    symlink(&f, &l).unwrap();
    assert_eq!(files(&[&l]).load().unwrap().store.len(), 1);
}

#[test]
fn a_directory_or_a_fifo_is_refused_without_blocking() {
    let dir = scratch("special");
    let sub = dir.join("dir.pem");
    std::fs::create_dir(&sub).unwrap();
    assert!(why(files(&[&sub]).load()).contains("not a regular file"));
    let fifo = dir.join("fifo.pem");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &fifo,
        FileType::Fifo,
        Mode::from_raw_mode(0o644),
        0,
    )
    .unwrap();
    assert!(why(files(&[&fifo]).load()).contains("not a regular file"));
}

#[test]
fn the_size_cap_is_four_mib_inclusive() {
    let dir = scratch("size");
    let f = dir.join("b.pem");
    let cert = ca_pem("x");
    let pad = usize::try_from(MAX_BUNDLE_BYTES).unwrap() - cert.len();
    write(&f, &format!("{cert}{}", "\n".repeat(pad)), 0o644);
    assert_eq!(std::fs::metadata(&f).unwrap().len(), MAX_BUNDLE_BYTES);
    assert!(files(&[&f]).load().is_ok(), "exactly at the cap");
    write(&f, &format!("{cert}{}", "\n".repeat(pad + 1)), 0o644);
    assert!(why(files(&[&f]).load()).contains("larger than 4 MiB"));
}

#[test]
fn malformed_pem_or_no_usable_certificate_is_an_error() {
    let dir = scratch("bad");
    let f = dir.join("b.pem");
    let cut = ca_pem("x");
    let cut = cut.split("-----END").next().unwrap();
    write(&f, &format!("{}{cut}", ca_pem("y")), 0o644);
    let e = why(files(&[&f]).load());
    assert!(
        e.contains("malformed PEM") && e.contains(&f.display().to_string()),
        "{e}"
    );
    write(&f, &junk_pem(), 0o644);
    assert!(why(files(&[&f]).load()).contains("no usable certificate"));
    write(&f, "", 0o644);
    assert!(why(files(&[&f]).load()).contains("no usable certificate"));
}

#[test]
fn encode_writes_lf_pem_of_the_same_bytes() {
    let der = CertificateDer::from(vec![7u8; 100]);
    let text = encode(&der);
    assert!(text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert!(text.ends_with("-----END CERTIFICATE-----\n"));
    assert!(!text.contains('\r'));
    assert_eq!(pem::parse(&text).unwrap().contents(), der.as_ref());
}
