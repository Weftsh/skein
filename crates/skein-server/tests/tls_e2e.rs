//! An install on an enterprise network: PostgreSQL that accepts only TLS,
//! a bucket that speaks only HTTPS, and both presenting certificates from
//! the company's own CA, which no public root store has heard of.
//!
//! Until `skein-tls`, Skein could reach neither. It connected to
//! PostgreSQL with `NoTls` whatever the URL said, and it trusted only the
//! public roots compiled into it — no setting could add a CA, so a MinIO
//! or Ceph under a corporate CA failed every request with
//! `UnknownIssuer`. Nothing in the suite noticed, because every test ran
//! against plaintext on loopback.

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{get_bytes, publish_doc};
use skein_testkit::pg::Pg;
use skein_testkit::pki::Pki;
use skein_testkit::{Minio, Server};

#[test]
fn an_install_whose_database_and_bucket_both_need_the_companys_ca_serves() {
    let pki = Pki::new();
    let pg = Pg::start_tls(&pki.server("pg", &["127.0.0.1"])).unwrap();
    let minio = Minio::start_tls(&pki.server("minio", &["127.0.0.1"]), &pki.ca_pem).unwrap();
    let bucket = minio.bucket("tls-e2e");
    let ca = pki.ca_pem.display().to_string();
    let db_url = format!("{}?sslmode=verify-full", pg.database("tls_e2e"));

    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_url(&db_url)
        .env("SKEIN_CA_FILE", ca.clone())
        .start();
    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 503, "not set up yet: {}", r.text());
    let admin = server.bootstrap("acme");
    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 200, "the bucket over TLS: {}", r.text());

    // The whole loop, over TLS both ways: publish, resolve, and the same
    // bytes back from the bucket.
    let tarball = b"bytes that crossed two TLS connections";
    let (s, body) = server.req(
        "PUT",
        "/npm/@acme%2ftls",
        &admin,
        Some(publish_doc("@acme/tls", "1.0.0", tarball)),
    );
    assert_eq!(s, 201, "{body}");
    let (_, doc) = server.get("/npm/@acme%2ftls", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert_eq!(get_bytes(url, &admin), (200, tarball.to_vec()));
}

#[test]
fn without_the_ca_the_bucket_is_not_trusted_and_readiness_says_where_it_goes() {
    let pki = Pki::new();
    let minio = Minio::start_tls(&pki.server("minio", &["127.0.0.1"]), &pki.ca_pem).unwrap();
    let bucket = minio.bucket("tls-untrusted");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("tls_untrusted")
        .start();
    server.bootstrap("acme");
    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 503, "{}", r.text());
    assert!(
        r.text().contains("UnknownIssuer") && r.text().contains("SKEIN_CA_FILE"),
        "{}",
        r.text()
    );
    assert!(server.healthy(), "untrusted storage is not a dead process");
}

/// A CA file that is missing or holds no certificate refuses to start,
/// naming the variable — rather than starting and failing every TLS
/// connection one at a time.
#[test]
fn a_broken_ca_file_refuses_to_start() {
    let scratch = Pki::new();
    let empty = scratch.dir().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    for (ca, want) in [
        (empty.display().to_string(), "holds no PEM certificate"),
        ("/nonexistent/ca.pem".to_string(), "/nonexistent/ca.pem"),
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_skein"))
            .arg("serve")
            .env_clear()
            .env("SKEIN_CA_FILE", &ca)
            .env("SKEIN_DB_URL", "postgres://skein@127.0.0.1:9/none")
            .env("SKEIN_STORE_URL", "http://127.0.0.1:9/none")
            .env("SKEIN_BIND", "127.0.0.1:0")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(Instant::now() < deadline, "started with a broken CA file");
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut err = String::new();
        std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut err).unwrap();
        assert!(!status.success());
        assert!(err.contains("SKEIN_CA_FILE") && err.contains(want), "{err}");
    }
}
