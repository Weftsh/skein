//! The UI, walked in a real Chromium against a real server.
//!
//! `tests/ui/walk.mjs` does the walking; this starts the server, seeds
//! what a UI has to survive — metadata that is markup, a yanked version,
//! a display name that is a script — and hands it a licence key covering
//! one seat fewer than the install has. The walk fails on any console
//! error it did not provoke, any uncaught error, a page that scrolls
//! sideways, `null` rendered as text, or the licence flow not doing what
//! it says.
//!
//! It needs `node` and the pinned Playwright:
//!
//! ```sh
//! npm ci --prefix crates/skein-server/tests/ui
//! npx --prefix crates/skein-server/tests/ui playwright install chromium
//! ```
//!
//! Without them this is a **NOTE**, and fails instead when
//! `SKEIN_REQUIRE_CLIENTS` names `browser` — which the `ui` CI job does.
//! `SKEIN_UI_SHOTS=<dir>` keeps a screenshot of every page.

mod common;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::publish_doc;
use serde_json::json;
use skein_license::issue::{self, Signer};
use skein_testkit::{Minio, Server};

const ADMIN_PW: &str = "admin-walk-password";
const READER_PW: &str = "rita-walk-password";
const PAT_PW: &str = "pat-walk-password";
const TOM_PW: &str = "tom-walk-password";
/// Markup, where a UI that used `innerHTML` would run it.
const HOSTILE: &str = r#"<img src=x onerror="document.title='PWNED'">"#;

fn walk_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ui")
}

fn have_browser() -> bool {
    let node = Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    let playwright = walk_dir().join("node_modules/playwright").is_dir();
    let required = std::env::var("SKEIN_REQUIRE_CLIENTS")
        .unwrap_or_default()
        .split(',')
        .any(|c| c.trim() == "browser");
    if !(node && playwright) {
        assert!(
            !required,
            "the browser walk is required here: `npm ci --prefix crates/skein-server/tests/ui` \
             and `npx --prefix crates/skein-server/tests/ui playwright install chromium`"
        );
        eprintln!("NOTE: node or Playwright is not installed; the UI is not walked by this run");
    }
    node && playwright
}

#[test]
fn the_ui_walks_clean_in_a_real_browser() {
    if !have_browser() {
        return;
    }
    let signer = Signer::from_seed("walk-1", [21; 32]);
    // A licence endpoint that is not there: "Check now" must record the
    // failure and show it, not throw. Its path is one unbroken token
    // wider than a phone, because the error quotes the URL: a table cell
    // that cannot break it pushes the page sideways. Six characters more
    // in the real route once did exactly that, and the walk only noticed
    // because the old URL had happened to fit.
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let nowhere = format!(
        "http://{}/v1/skein/check-{}",
        closed.local_addr().unwrap(),
        "x".repeat(60)
    );
    drop(closed);
    let bucket = Minio::shared().bucket("ui-walk");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("ui-walk")
        .env("SKEIN_DEV_MODE", "1")
        .env(
            "SKEIN_DEV_LICENSE_PUBLIC_KEYS",
            json!({ "walk-1": signer.public_pem() }).to_string(),
        )
        .env("SKEIN_LICENSE_ENDPOINT", nowhere)
        .env("SKEIN_LICENSE_CHECK_DELAY_SECS", "3600")
        .start();
    let admin = server.bootstrap("acme");

    let (_, me) = server.get("/api/v1/me", &admin);
    let (s, body) = server.req(
        "PATCH",
        &format!("/api/v1/users/{}", me["id"].as_str().unwrap()),
        &admin,
        Some(json!({ "password": ADMIN_PW })),
    );
    assert_eq!(s, 200, "{body}");
    let (s, rita) = server.req(
        "POST",
        "/api/v1/users",
        &admin,
        Some(json!({ "username": "rita", "role": "reader", "password": READER_PW })),
    );
    assert_eq!(s, 201, "{rita}");
    let (s, body) = server.req(
        "PATCH",
        &format!("/api/v1/users/{}", rita["id"].as_str().unwrap()),
        &admin,
        Some(json!({ "display_name": HOSTILE })),
    );
    assert_eq!(s, 200, "{body}");
    server.person(&admin, "ci", "publisher", &["package:write"]);

    for version in ["1.0.0", "1.1.0"] {
        let mut doc = publish_doc("@acme/widget", version, version.as_bytes());
        doc["description"] = json!(HOSTILE);
        doc["versions"][version]["description"] = json!(HOSTILE);
        doc["versions"][version]["license"] = json!(HOSTILE);
        let (s, body) = server.req("PUT", "/npm/@acme%2fwidget", &admin, Some(doc));
        assert_eq!(s, 201, "{body}");
    }
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let id = listed["packages"][0]["id"].as_str().unwrap().to_string();
    let (s, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.0.0/yank"),
        &admin,
        Some(json!({ "yanked": true, "reason": HOSTILE })),
    );
    assert_eq!(s, 200, "{body}");

    // A publisher the walk removes: what they published keeps their name.
    let (pat, pat_token) = server.person(&admin, "pat", "publisher", &["package:write"]);
    let (s, body) = server.req(
        "PATCH",
        &format!("/api/v1/users/{pat}"),
        &admin,
        Some(json!({ "password": PAT_PW })),
    );
    assert_eq!(s, 200, "{body}");
    let (s, body) = server.req(
        "PUT",
        "/npm/@acme%2fpat-lib",
        &pat_token,
        Some(publish_doc("@acme/pat-lib", "1.0.0", b"pat's")),
    );
    assert_eq!(s, 201, "{body}");
    // Somebody the walk locks out.
    let (s, body) = server.req(
        "POST",
        "/api/v1/users",
        &admin,
        Some(json!({ "username": "tom", "role": "reader", "password": TOM_PW })),
    );
    assert_eq!(s, 201, "{body}");
    // A package whose newest version — the one `latest` names — is
    // yanked: nothing may recommend it.
    for version in ["1.0.0", "1.1.0"] {
        let (s, body) = server.req(
            "PUT",
            "/npm/@acme%2fgadget",
            &admin,
            Some(publish_doc("@acme/gadget", version, version.as_bytes())),
        );
        assert_eq!(s, 201, "{body}");
    }
    let (_, listed) = server.get("/api/v1/packages?q=gadget", &admin);
    let gadget = listed["packages"][0]["id"].as_str().unwrap().to_string();
    let (s, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{gadget}/versions/1.1.0/yank"),
        &admin,
        Some(json!({ "yanked": true, "reason": "broke the build" })),
    );
    assert_eq!(s, 200, "{body}");

    // Four people can sign in (the admin, rita, pat and tom; `ci`
    // cannot): a key for one is over its cap, and says so without
    // refusing anything.
    let mut p = issue::payload();
    p["kid"] = json!("walk-1");
    p["lid"] = json!("lic_walk_001");
    p["entity"] = json!("Walkthrough Ltd");
    p["maxSeats"] = json!(1);
    p["iat"] = json!("2026-01-01T00:00:00.000Z");
    p["exp"] = json!("2099-01-01T00:00:00.000Z");
    let key = signer.issue(&p).unwrap();

    let mut walk = Command::new("node");
    walk.arg("walk.mjs")
        .current_dir(walk_dir())
        .env("BASE", &server.base)
        .env("PW", ADMIN_PW)
        .env("READER_PW", READER_PW)
        .env("PAT_PW", PAT_PW)
        .env("TOM_PW", TOM_PW)
        .env("ADMIN_TOKEN", &admin)
        .env("LICENSE_KEY", key);
    if let Ok(dir) = std::env::var("SKEIN_UI_SHOTS") {
        walk.env("OUT", dir);
    }
    let out = walk.output().expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    eprintln!("{stdout}");
    assert!(
        out.status.success() && stdout.contains("0 problems"),
        "the walk found problems:\n{stdout}\n{stderr}"
    );
    assert!(server.healthy());
}
