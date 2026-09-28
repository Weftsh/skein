//! The commercial licence end to end: a real server, a real database, and
//! a licence endpoint on loopback standing in for Weft's.
//!
//! The property the rest exists for is the first test: **whatever the
//! licence says — none, invalid, lapsed, over its seats, revoked — every
//! install, publish and sign-in still works.** The rest pin what the
//! licence does do: exactly three fields leave the install, once a day
//! however many replicas run, never for an offline key, and a
//! configuration mistake is refused at start where a bad key is not.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{get_bytes, publish_doc};
use serde_json::{json, Value};
use skein_license::issue::{self, Signer};
use skein_testkit::{Minio, Server};

fn signer() -> Signer {
    Signer::from_seed("test-1", [11; 32])
}

/// A Skein key: Team, 25 seats, online, good until 2099 — with `edit`.
fn key(edit: impl FnOnce(&mut Value)) -> String {
    let mut p = issue::payload();
    p["iat"] = json!("2026-01-01T00:00:00.000Z");
    p["exp"] = json!("2099-01-01T00:00:00.000Z");
    edit(&mut p);
    signer().sign_unchecked(&p)
}

/// One request the fake endpoint received.
#[derive(Debug, Clone)]
struct Seen {
    request_line: String,
    headers: Vec<String>,
    body: String,
}

/// Weft's licence endpoint, on loopback: records every request and
/// answers with whatever `answer` holds.
struct FakeWeft {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<(u16, String)>>,
}

impl FakeWeft {
    fn start() -> FakeWeft {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/check", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new((200, r#"{"status":"active"}"#.to_string())));
        let (log, reply) = (seen.clone(), answer.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut headers = Vec::new();
                let mut len = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim_end().to_string();
                    if line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    headers.push(line);
                }
                let mut body = vec![0; len];
                let _ = reader.read_exact(&mut body);
                log.lock().unwrap().push(Seen {
                    request_line: request_line.trim_end().to_string(),
                    headers,
                    body: String::from_utf8_lossy(&body).into(),
                });
                let (code, text) = reply.lock().unwrap().clone();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        FakeWeft { url, seen, answer }
    }

    fn answer(&self, code: u16, body: Value) {
        *self.answer.lock().unwrap() = (code, body.to_string());
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn wait_for(&self, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.count() < n {
            assert!(
                Instant::now() < deadline,
                "the endpoint heard {} of {n}",
                self.count()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// A server that trusts `test-1` and checks against `weft`. `delay` is the
/// first check's delay; an hour means "not during this test".
fn licensed(
    bucket: &str,
    hint: &str,
    weft: &FakeWeft,
    delay: u64,
) -> skein_testkit::server::ServerBuilder {
    let keys = json!({ "test-1": signer().public_pem() }).to_string();
    Server::builder(env!("CARGO_BIN_EXE_skein"), bucket)
        .db_hint(hint)
        .env("SKEIN_DEV_MODE", "1")
        .env("SKEIN_DEV_LICENSE_PUBLIC_KEYS", keys)
        .env("SKEIN_LICENSE_ENDPOINT", weft.url.clone())
        .env("SKEIN_LICENSE_CHECK_DELAY_SECS", delay.to_string())
}

fn license(server: &Server, admin: &str) -> Value {
    let (s, body) = server.get("/api/v1/license", admin);
    assert_eq!(s, 200, "{body}");
    body
}

/// A person who can sign in: a seat.
fn seat(server: &Server, admin: &str, username: &str) -> String {
    let (s, u) = server.req(
        "POST",
        "/api/v1/users",
        admin,
        Some(json!({ "username": username, "role": "publisher", "password": format!("pw-{username}-long-enough") })),
    );
    assert_eq!(s, 201, "create {username}: {u}");
    u["id"].as_str().unwrap().to_string()
}

/// Everything a registry is for, and none of it refused: publish, resolve,
/// download the same bytes, sign in, add somebody, and be ready.
fn everything_still_works(server: &Server, admin: &str, round: &str) {
    let name = format!("@acme/w-{round}");
    let tarball = format!("the bytes of round {round}").into_bytes();
    let (s, body) = server.req(
        "PUT",
        &format!("/npm/{}", name.replace('/', "%2f")),
        admin,
        Some(publish_doc(&name, "1.0.0", &tarball)),
    );
    assert_eq!(s, 201, "{round}: publishing was refused: {body}");
    let (s, doc) = server.get(&format!("/npm/{}", name.replace('/', "%2f")), admin);
    assert_eq!(s, 200, "{round}: {doc}");
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .unwrap();
    assert_eq!(get_bytes(url, admin), (200, tarball), "{round}: install");

    let who = format!("p{round}");
    seat(server, admin, &who);
    let r = server.raw(
        "POST",
        "/api/v1/session",
        &[("Content-Type", "application/json"), ("x-skein-csrf", "1")],
        Some(
            json!({ "username": who, "password": format!("pw-{who}-long-enough") })
                .to_string()
                .as_bytes(),
        ),
    );
    assert_eq!(
        r.status,
        200,
        "{round}: signing in was refused: {}",
        r.text()
    );
    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 200, "{round}: not ready: {}", r.text());
}

#[test]
fn nothing_is_refused_whatever_the_licence_says() {
    let bucket = Minio::shared().bucket("lic-never");
    let weft = FakeWeft::start();
    // Starts with a key that verifies as nothing: a Weft Sandboxes key.
    let sandy_key = key(|p| {
        p.as_object_mut().unwrap().remove("product");
        p.as_object_mut().unwrap().remove("maxSeats");
    });
    let server = licensed(&bucket.base_url, "lic-never", &weft, 3600)
        .env("SKEIN_LICENSE_KEY", sandy_key)
        .start();
    let admin = server.bootstrap("acme");

    let l = license(&server, &admin);
    assert_eq!(l["state"], "invalid", "{l}");
    assert!(
        l["warnings"][0]
            .as_str()
            .unwrap()
            .contains("Weft Sandboxes"),
        "{l}"
    );
    everything_still_works(&server, &admin, "invalid");

    // Lapsed long enough ago that release access has gone.
    let lapsed = key(|p| {
        p["iat"] = json!("2020-01-01T00:00:00.000Z");
        p["exp"] = json!("2021-01-01T00:00:00.000Z");
    });
    let (s, l) = server.req(
        "PUT",
        "/api/v1/license",
        &admin,
        Some(json!({ "key": lapsed })),
    );
    assert_eq!(s, 200, "an expired key is still this customer's key: {l}");
    assert_eq!(l["state"], "lapsed");
    assert_eq!(l["release_access"], false);
    everything_still_works(&server, &admin, "lapsed");

    // One seat for a registry that already has several.
    let one = key(|p| p["maxSeats"] = json!(1));
    let (s, l) = server.req(
        "PUT",
        "/api/v1/license",
        &admin,
        Some(json!({ "key": one })),
    );
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["over_cap"], true, "{l}");
    assert!(l["seats"].as_u64().unwrap() > 1, "{l}");
    everything_still_works(&server, &admin, "overcap");
    assert_eq!(license(&server, &admin)["over_cap"], true);

    // Revoked, by Weft.
    let (s, _) = server.req(
        "PUT",
        "/api/v1/license",
        &admin,
        Some(json!({ "key": key(|_| {}) })),
    );
    assert_eq!(s, 200);
    weft.answer(
        200,
        json!({ "status": "revoked", "notice": "Contact billing." }),
    );
    let (s, l) = server.req("POST", "/api/v1/license/check", &admin, None);
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["last_check_status"], "revoked", "{l}");
    assert_eq!(l["release_access"], false, "{l}");
    assert_eq!(l["notice"], "Contact billing.");
    assert!(
        l["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("revoked")),
        "{l}"
    );
    everything_still_works(&server, &admin, "revoked");

    // And none at all: a fresh install with no key.
    let bare = common::spawn(&bucket.base_url, "lic-never-none");
    let admin = bare.bootstrap("acme");
    let l = license(&bare, &admin);
    assert_eq!(l["state"], "unlicensed", "{l}");
    assert_eq!(l["key_source"], Value::Null);
    everything_still_works(&bare, &admin, "none");
}

#[test]
fn the_check_sends_three_fields_and_the_peak_seats() {
    let bucket = Minio::shared().bucket("lic-fields");
    let weft = FakeWeft::start();
    weft.answer(
        200,
        json!({ "status": "active", "notice": "Renewal is due in March." }),
    );
    let server = licensed(&bucket.base_url, "lic-fields", &weft, 3600)
        .env("SKEIN_LICENSE_KEY", key(|_| {}))
        .start();
    let admin = server.bootstrap("acme");
    // Seats: the admin, two more people, a disabled person who does not
    // count, and a CI service account that cannot sign in and does not
    // count either.
    seat(&server, &admin, "ada");
    seat(&server, &admin, "bob");
    let gone = seat(&server, &admin, "cy");
    let (s, _) = server.req(
        "PATCH",
        &format!("/api/v1/users/{gone}"),
        &admin,
        Some(json!({ "disabled": true })),
    );
    assert_eq!(s, 200);
    server.person(&admin, "ci", "publisher", &["package:write"]);
    let l = license(&server, &admin);
    assert_eq!(l["seats"], 3, "{l}");
    assert_eq!(l["max_seats"], 25);
    assert_eq!(l["key_source"], "environment");

    let (s, l) = server.req("POST", "/api/v1/license/check", &admin, None);
    assert_eq!(s, 200, "{l}");
    let seen = weft.requests();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].request_line.starts_with("POST /v1/check "),
        "{:?}",
        seen[0]
    );
    let ua = format!("user-agent: skein/{}", env!("CARGO_PKG_VERSION"));
    assert!(
        seen[0].headers.iter().any(|h| h.eq_ignore_ascii_case(&ua)),
        "{:?}",
        seen[0].headers
    );
    let body: Value = serde_json::from_str(&seen[0].body).unwrap();
    let mut fields: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort();
    assert_eq!(
        fields,
        ["keyId", "peakSeats", "version"],
        "exactly these leave the install: {body}"
    );
    assert_eq!(body["keyId"], "lic_test_123");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["peakSeats"], 3);
    for name in ["ada", "bob", "acme", "admin"] {
        assert!(
            !seen[0].body.contains(name),
            "{name} left the install: {}",
            seen[0].body
        );
    }
    assert_eq!(l["last_check_status"], "active");
    assert_eq!(l["notice"], "Renewal is due in March.");
    assert!(l["last_check_at"].as_str().is_some(), "{l}");

    // The next check reports the most there were since this one, not how
    // many there are when it runs.
    seat(&server, &admin, "dee");
    let eve = seat(&server, &admin, "eve");
    assert_eq!(license(&server, &admin)["seats"], 5);
    let (s, _) = server.req("DELETE", &format!("/api/v1/users/{eve}"), &admin, None);
    assert_eq!(s, 204);
    let l = license(&server, &admin);
    assert_eq!(l["seats"], 4);
    assert_eq!(l["peak_seats_this_month"], 5, "{l}");
    let (s, _) = server.req("POST", "/api/v1/license/check", &admin, None);
    assert_eq!(s, 200);
    let body: Value = serde_json::from_str(&weft.requests()[1].body).unwrap();
    assert_eq!(body["peakSeats"], 5, "{body}");
}

/// Ten replicas, or one restarted ten times, still send one check a day.
#[test]
fn replicas_and_restarts_send_one_check_a_day() {
    let bucket = Minio::shared().bucket("lic-once");
    let weft = FakeWeft::start();
    let k = key(|_| {});
    let mut a = licensed(&bucket.base_url, "lic-once", &weft, 0)
        .env("SKEIN_LICENSE_KEY", k.clone())
        .start();
    let b = licensed(&bucket.base_url, "lic-once", &weft, 0)
        .db_url(&a.db_url)
        .env("SKEIN_LICENSE_KEY", k)
        .start();
    weft.wait_for(1);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(weft.count(), 1, "two replicas checked separately");
    a.restart();
    assert!(a.healthy());
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(weft.count(), 1, "a restart checked again");
    assert!(b.healthy());
    let admin = a.bootstrap("acme");
    assert_eq!(license(&a, &admin)["last_check_status"], "active");
}

#[test]
fn an_offline_licence_makes_no_calls_and_keeps_the_true_up() {
    let bucket = Minio::shared().bucket("lic-offline");
    let weft = FakeWeft::start();
    let offline = key(|p| {
        p["tier"] = json!("enterprise");
        p["mode"] = json!("offline");
        p["maxSeats"] = Value::Null;
    });
    let server = licensed(&bucket.base_url, "lic-offline", &weft, 0)
        .env("SKEIN_LICENSE_KEY", offline)
        .start();
    let admin = server.bootstrap("acme");
    seat(&server, &admin, "ada");
    std::thread::sleep(Duration::from_secs(2));
    let (s, body) = server.req("POST", "/api/v1/license/check", &admin, None);
    assert_eq!(s, 409, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("offline"),
        "{body}"
    );
    assert_eq!(weft.count(), 0, "an offline licence called out");

    let l = license(&server, &admin);
    assert_eq!(l["state"], "active", "{l}");
    assert_eq!(l["mode"], "offline");
    assert_eq!(l["check_overdue"], false);
    assert_eq!(l["warnings"], json!([]), "{l}");
    let peaks = l["monthly_peaks"].as_array().unwrap();
    assert_eq!(peaks.len(), 1, "{l}");
    assert_eq!(peaks[0]["peak"], 2);
    assert!(peaks[0]["month"].as_str().unwrap().len() == 7, "{l}");
}

#[test]
fn only_an_admin_reads_or_installs_the_licence_and_the_key_is_never_shown() {
    let bucket = Minio::shared().bucket("lic-admin");
    let weft = FakeWeft::start();
    let k1 = key(|p| p["lid"] = json!("lic_one"));
    let server = licensed(&bucket.base_url, "lic-admin", &weft, 3600)
        .env("SKEIN_LICENSE_KEY", k1.clone())
        .start();
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["org:read"]);
    let (_, publisher) = server.person(&admin, "pat", "publisher", &["package:write"]);

    let r = server.raw("GET", "/api/v1/license", &[], None);
    assert_eq!(r.status, 401);
    let (s, body) = server.get("/api/v1/license", &reader);
    assert_eq!(s, 403, "{body}");
    let k2 = key(|p| p["lid"] = json!("lic_two"));
    let (s, body) = server.req(
        "PUT",
        "/api/v1/license",
        &publisher,
        Some(json!({ "key": k2 })),
    );
    assert_eq!(s, 403, "{body}");
    let (s, body) = server.req("POST", "/api/v1/license/check", &publisher, None);
    assert_eq!(s, 403, "{body}");

    for (bad, needle) in [
        ("not a key".to_string(), "malformed"),
        (
            key(|p| {
                p.as_object_mut().unwrap().remove("product");
            }),
            "Weft Sandboxes",
        ),
        (
            Signer::from_seed("test-1", [99; 32]).sign_unchecked(&issue::payload()),
            "bad_signature",
        ),
    ] {
        let (s, body) = server.req(
            "PUT",
            "/api/v1/license",
            &admin,
            Some(json!({ "key": bad })),
        );
        assert_eq!(s, 400, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains(needle),
            "{needle}: {body}"
        );
    }
    assert_eq!(
        license(&server, &admin)["license_id"],
        "lic_one",
        "a refused key replaced one"
    );

    let (s, l) = server.req(
        "PUT",
        "/api/v1/license",
        &admin,
        Some(json!({ "key": k2.clone() })),
    );
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["license_id"], "lic_two");
    assert_eq!(l["key_source"], "api");
    let everything = l.to_string();
    assert!(!everything.contains(&k2[20..60]), "the key came back");
    let (_, log) = server.get("/api/v1/audit", &admin);
    let row = log["entries"]
        .as_array()
        .or_else(|| log.as_array())
        .expect("audit entries")
        .iter()
        .find(|e| e["action"] == "license.install")
        .unwrap_or_else(|| panic!("no license.install in {log}"))
        .clone();
    assert_eq!(row["context"]["license_id"], "lic_two", "{row}");
    assert!(
        !log.to_string().contains(&k2[20..60]),
        "the key is in the audit log"
    );

    // A restart with the same SKEIN_LICENSE_KEY leaves the admin's key
    // standing; a changed one replaces it.
    let db_url = server.db_url.clone();
    drop(server);
    let again = licensed(&bucket.base_url, "lic-admin", &weft, 3600)
        .db_url(&db_url)
        .env("SKEIN_LICENSE_KEY", k1)
        .start();
    assert_eq!(license(&again, &admin)["license_id"], "lic_two");
    drop(again);
    let k3 = key(|p| p["lid"] = json!("lic_three"));
    let changed = licensed(&bucket.base_url, "lic-admin", &weft, 3600)
        .db_url(&db_url)
        .env("SKEIN_LICENSE_KEY", k3)
        .start();
    let l = license(&changed, &admin);
    assert_eq!(l["license_id"], "lic_three");
    assert_eq!(l["key_source"], "environment");
}

/// Run `skein` with `env` and give it a few seconds: `(exit code, stderr)`,
/// or `None` if it was still running (it started).
fn run_briefly(args: &[&str], env: &[(&str, &str)], db_url: &str) -> Option<(i32, String)> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skein"));
    cmd.args(args)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("SKEIN_DB_URL", db_url)
        .env("SKEIN_STORE_URL", "http://127.0.0.1:9/nowhere")
        .env("SKEIN_BIND", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            let mut err = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut err)
                .unwrap();
            let mut out = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut out)
                .unwrap();
            return Some((status.code().unwrap_or(-1), err + &out));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    None
}

#[test]
fn a_configuration_mistake_refuses_to_start_and_a_bad_key_does_not() {
    let db_url = skein_testkit::pg::test_db_url("lic-config");
    let pem = signer().public_pem();
    let keys = json!({ "test-1": pem }).to_string();

    let (code, err) = run_briefly(
        &["serve"],
        &[("SKEIN_DEV_LICENSE_PUBLIC_KEYS", &keys)],
        &db_url,
    )
    .expect("started with development keys outside development");
    assert_ne!(code, 0);
    assert!(err.contains("requires SKEIN_DEV_MODE=1"), "{err}");

    let (code, err) = run_briefly(
        &["serve"],
        &[("SKEIN_LICENSE_ENDPOINT", "http://license.example/v1/check")],
        &db_url,
    )
    .expect("started with a plain-HTTP licence endpoint");
    assert_ne!(code, 0);
    assert!(err.contains("must be HTTPS"), "{err}");

    let (code, err) = run_briefly(
        &["serve"],
        &[
            ("SKEIN_DEV_MODE", "1"),
            ("SKEIN_DEV_LICENSE_PUBLIC_KEYS", r#"{"odd-1": "not a key"}"#),
        ],
        &db_url,
    )
    .expect("started with a trusted key that is not one");
    assert_ne!(code, 0);
    assert!(err.contains("odd-1") && err.contains("Ed25519"), "{err}");

    // A key that does not verify is the licence's problem, not the
    // registry's: it serves, and says so.
    let bucket = Minio::shared().bucket("lic-config");
    let weft = FakeWeft::start();
    let server = licensed(&bucket.base_url, "lic-config-bad-key", &weft, 3600)
        .env("SKEIN_LICENSE_KEY", "weft_lic_v1.garbage.garbage")
        .start();
    assert!(server.healthy());
    let admin = server.bootstrap("acme");
    let l = license(&server, &admin);
    assert_eq!(l["state"], "invalid", "{l}");
    assert!(
        l["warnings"][0]
            .as_str()
            .unwrap()
            .contains("serves normally"),
        "{l}"
    );

    // What the release workflow runs on the binary it publishes.
    let (code, out) = run_briefly(&["admin", "license", "keys", "--json"], &[], "unused").unwrap();
    assert_eq!(code, 0, "{out}");
    let listed: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(listed["trusted_key_ids"].is_array(), "{listed}");
    let (code, out) = run_briefly(
        &["admin", "license", "keys", "--json"],
        &[
            ("SKEIN_DEV_MODE", "1"),
            ("SKEIN_DEV_LICENSE_PUBLIC_KEYS", &keys),
        ],
        "unused",
    )
    .unwrap();
    assert_eq!(code, 0, "{out}");
    let listed: Value = serde_json::from_str(out.trim()).unwrap();
    assert!(
        listed["trusted_key_ids"]
            .as_array()
            .unwrap()
            .contains(&json!("test-1")),
        "{listed}"
    );
}
