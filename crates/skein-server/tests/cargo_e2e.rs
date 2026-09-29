//! Cargo end to end: the framed publish body, the sparse index, and
//! the download Cargo derives from `config.json`.
//!
//! `registry::cargo` is pure and is hammered in its own unit tests.
//! What those cannot show is the loop: that `config.json` names a `dl`
//! Cargo can build a URL from, that the index line's `cksum` is the
//! digest of the bytes at that URL, and that the bare `Authorization`
//! header Cargo sends is read as a credential at all.
//!
//! The publish bodies here are built the way `cargo publish` builds
//! them — [`publish_body`] is the metadata cargo 1.96 really sent,
//! captured from the wire. What a real `cargo` does against a real
//! server is `clients_e2e::cargo_publishes_and_builds_against_skein`'s
//! job; a body we built can only ever confirm what we already believe,
//! and one built from the wrong belief is how the index came to echo
//! the publish's `version_req` where Cargo reads `req`.

mod common;

use common::spawn;
use skein_testkit::server::{send, Reply};
use skein_testkit::{Minio, Server};

fn base(server: &Server) -> String {
    format!("{}/cargo", server.base)
}

/// `cargo publish`'s framed body, with the metadata in the shape cargo
/// really sends: every key it sends, a dependency renamed the way
/// `base = { package = "serde", … }` renames one, and — as for any
/// dependency on this same registry — no `registry` key at all.
fn publish_body(name: &str, vers: &str, license: Option<&str>, krate: &[u8]) -> Vec<u8> {
    let mut meta = serde_json::json!({
        "name": name,
        "vers": vers,
        "deps": [
            {
                "optional": false, "default_features": true, "name": "serde",
                "features": ["derive"], "version_req": "^1", "target": null,
                "kind": "normal", "explicit_name_in_toml": "ser"
            },
            {
                "optional": true, "default_features": false, "name": "log",
                "features": [], "version_req": "^0.4", "target": "cfg(unix)",
                "kind": "normal"
            }
        ],
        "features": { "default": ["std"], "std": [], "logging": ["dep:log"] },
        "authors": [], "description": null, "documentation": null, "homepage": null,
        "readme": null, "readme_file": null, "keywords": [], "categories": [],
        "license_file": null, "repository": null, "badges": {}, "links": null,
        "rust_version": "1.70",
    });
    meta["license"] = match license {
        Some(l) => serde_json::json!(l),
        None => serde_json::Value::Null,
    };
    frame(meta.to_string().as_bytes(), krate)
}

fn frame(json: &[u8], krate: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(json);
    out.extend_from_slice(&(krate.len() as u32).to_le_bytes());
    out.extend_from_slice(krate);
    out
}

/// Cargo sends its token **bare** — no scheme at all. Every request in
/// this file goes that way rather than with `Bearer`, so the suite
/// exercises the dialect the real client speaks.
fn cargo_req(method: &str, url: &str, token: &str, body: Option<&[u8]>) -> (u16, Vec<u8>) {
    let r = cargo_reply(method, url, token, body);
    (r.status, r.body)
}

fn cargo_reply(method: &str, url: &str, token: &str, body: Option<&[u8]>) -> Reply {
    send(method, url, &[("Authorization", token)], body)
}

/// The sentence Cargo would print: `errors[0].detail`.
fn detail(body: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(body)
        .unwrap_or_else(|e| panic!("not cargo's error shape ({e}): {body:?}"));
    v["errors"][0]["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("no detail in {v}"))
        .to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The one line of a crate's index file that names `version`.
fn index_line(server: &Server, token: &str, path: &str, version: &str) -> serde_json::Value {
    let (status, index) = cargo_req(
        "GET",
        &format!("{}/index/{path}", base(server)),
        token,
        None,
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&index));
    let index = String::from_utf8(index).expect("ndjson is utf-8");
    index
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("one object per line"))
        .find(|l| l["vers"] == version)
        .unwrap_or_else(|| panic!("no {version} in {index}"))
}

fn package_id(server: &Server, admin: &str, name: &str) -> String {
    let (_, listed) = server.get("/api/v1/packages?ecosystem=cargo", admin);
    listed["packages"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p["id"].as_str())
        .unwrap_or_else(|| panic!("no {name} in {listed}"))
        .to_string()
}

fn audit_actions(server: &Server, admin: &str) -> Vec<(String, String)> {
    let (status, log) = server.get("/api/v1/audit", admin);
    assert_eq!(status, 200, "{log}");
    log["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default().to_string(),
                e["username"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// The whole loop, in Cargo's own order: read `config.json`, fetch the
/// index, build the download URL the way Cargo builds it, and get bytes
/// whose digest is the one the index promised.
#[test]
fn a_crate_publishes_and_the_index_leads_to_its_bytes() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-roundtrip");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let b = base(&server);

    let krate = b"\x1f\x8b not really a .crate, near enough for a test";
    let (status, body) = cargo_req(
        "PUT",
        &format!("{b}/api/v1/crates/new"),
        &ci,
        Some(&publish_body(
            "acme-widget",
            "1.4.0",
            Some("MIT OR Apache-2.0"),
            krate,
        )),
    );
    assert_eq!(
        status,
        200,
        "publishing: {}",
        String::from_utf8_lossy(&body)
    );
    // Cargo prints whatever is in `warnings`, so the quiet success is
    // three empty lists.
    let ok: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert!(
        ok["warnings"]["other"].as_array().unwrap().is_empty(),
        "{ok}"
    );

    // 1. `config.json`, the first thing Cargo fetches.
    let (status, cfg) = cargo_req("GET", &format!("{b}/index/config.json"), &ci, None);
    assert_eq!(status, 200);
    let cfg: serde_json::Value = serde_json::from_slice(&cfg).expect("json");
    assert_eq!(
        cfg["auth-required"], true,
        "without this Cargo never sends its token and every index read 401s: {cfg}"
    );
    assert_eq!(cfg["api"], b, "{cfg}");
    let dl = cfg["dl"].as_str().expect("a dl url").to_string();
    assert_eq!(dl, format!("{b}/api/v1/crates"));

    // 2. The index, at the path Cargo's own length rule produces.
    let line = index_line(&server, &ci, "ac/me/acme-widget", "1.4.0");
    assert_eq!(line["name"], "acme-widget");
    assert_eq!(line["yanked"], false);
    // Hex and unprefixed, which is what Cargo compares the download
    // against — `sha256:` in front of it fails every install.
    assert_eq!(line["cksum"], sha256_hex(krate));
    // The publisher's own declarations, restated in the index's words.
    // A renamed dependency is named as the code uses it, with the crate
    // it really is in `package`; the requirement is `req`. Echoing the
    // publish instead gives Cargo a line with no `req`, which it reports
    // as "version 1.4.0's index entry is invalid".
    let ser = &line["deps"][0];
    assert_eq!(ser["name"], "ser", "{line}");
    assert_eq!(ser["package"], "serde", "{line}");
    assert_eq!(ser["req"], "^1", "{line}");
    assert_eq!(ser["features"][0], "derive");
    assert_eq!(ser["kind"], "normal");
    assert!(ser.get("registry").is_none(), "{line}");
    let log = &line["deps"][1];
    assert_eq!(log["name"], "log");
    assert!(log.get("package").is_none(), "not renamed: {line}");
    assert_eq!(log["req"], "^0.4");
    assert_eq!(log["optional"], true);
    assert_eq!(log["default_features"], false);
    assert_eq!(log["target"], "cfg(unix)");
    for dep in line["deps"].as_array().unwrap() {
        for publish_only in ["version_req", "explicit_name_in_toml"] {
            assert!(dep.get(publish_only).is_none(), "{publish_only}: {line}");
        }
    }
    assert_eq!(line["features"]["default"][0], "std");
    assert_eq!(line["features"]["logging"][0], "dep:log");
    assert_eq!(line["rust_version"], "1.70");
    assert!(line["links"].is_null());

    // 3. The download URL, built the way Cargo builds it: `dl` has no
    //    markers, so Cargo appends `/{crate}/{version}/download`.
    let url = format!("{dl}/acme-widget/1.4.0/download");
    let r = cargo_reply("GET", &url, &ci, None);
    assert_eq!(r.status, 200, "fetching {url}");
    assert_eq!(r.body, krate, "the bytes are not the ones we published");
    assert_eq!(sha256_hex(&r.body), line["cksum"].as_str().unwrap());
    // Immutable, and never `public`: an edge in front of this registry
    // must not hand one person's authorized download to the next.
    assert_eq!(
        r.header("cache-control"),
        Some("private, max-age=31536000, immutable")
    );

    // Cargo's `license` is already SPDX, so no mapping table is
    // involved and the expression survives whole — and the version
    // says who published it.
    let id = package_id(&server, &admin, "acme-widget");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    let v = &shown["versions"][0];
    assert_eq!(v["license"], "MIT OR Apache-2.0");
    assert_eq!(v["license_source"], "declared");
    assert_eq!(v["published_by_username"], "ci", "{v}");
    assert!(v["published_by_token"].is_string(), "{v}");
    assert_eq!(v["files"][0]["filename"], "acme-widget-1.4.0.crate");
    assert!(
        audit_actions(&server, &admin).contains(&("package.publish".into(), "ci".into())),
        "the publish left no audit row"
    );
    assert!(server.healthy());
}

/// A yank is visible in the index on the very next read, because the
/// index is assembled from rows rather than written to a file by
/// something that runs later.
#[test]
fn a_yank_shows_in_the_index_at_once_and_the_crate_still_downloads() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-yank");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let b = base(&server);

    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &ci,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"crate"))
        )
        .0,
        200
    );

    let (status, out) = cargo_req(
        "DELETE",
        &format!("{b}/api/v1/crates/acme-widget/1.0.0/yank"),
        &ci,
        None,
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
    let ok: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(ok["ok"], true);
    assert_eq!(
        index_line(&server, &ci, "ac/me/acme-widget", "1.0.0")["yanked"],
        true
    );

    // A yanked crate still downloads. Cargo's yank means "do not
    // resolve to this unless a lockfile already names it", and removing
    // the bytes would break every build that pinned it.
    let (status, bytes) = cargo_req(
        "GET",
        &format!("{b}/api/v1/crates/acme-widget/1.0.0/download"),
        &ci,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(bytes, b"crate");

    // …and unyanking puts it back.
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/acme-widget/1.0.0/unyank"),
            &ci,
            None
        )
        .0,
        200
    );
    assert_eq!(
        index_line(&server, &ci, "ac/me/acme-widget", "1.0.0")["yanked"],
        false
    );

    // Both are in the audit log under the person who did them, the same
    // record the REST door writes.
    let actions = audit_actions(&server, &admin);
    for want in ["package.yank", "package.unyank"] {
        assert!(
            actions.contains(&(want.into(), "ci".into())),
            "{want} not in {actions:?}"
        );
    }
    assert!(server.healthy());
}

/// Every negative case on this door, each ending by proving the server
/// is still serving.
#[test]
fn hostile_publishes_are_refused_and_the_server_keeps_serving() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-hostile");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let new = format!("{b}/api/v1/crates/new");

    assert_eq!(
        cargo_req(
            "PUT",
            &new,
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"ours"))
        )
        .0,
        200
    );

    // A published version never changes.
    let (status, err) = cargo_req(
        "PUT",
        &new,
        &admin,
        Some(&publish_body(
            "acme-widget",
            "1.0.0",
            Some("MIT"),
            b"theirs",
        )),
    );
    assert_eq!(status, 409);
    assert!(
        detail(&err).contains("already uploaded"),
        "{}",
        detail(&err)
    );

    // A frame that lies about its length is a 400, not an allocation.
    let mut huge = u32::to_le_bytes(2_000_000_000).to_vec();
    huge.extend_from_slice(b"{}");
    assert_eq!(cargo_req("PUT", &new, &admin, Some(&huge)).0, 400);
    assert_eq!(cargo_req("PUT", &new, &admin, Some(b"")).0, 400);
    assert_eq!(
        cargo_req("PUT", &new, &admin, Some(b"not framed at all")).0,
        400
    );

    // A dependency with no requirement would be an index line no Cargo
    // can read, so it is refused rather than stored.
    let (status, err) = cargo_req(
        "PUT",
        &new,
        &admin,
        Some(&frame(
            br#"{"name":"no-req","vers":"1.0.0","deps":[{"name":"serde"}]}"#,
            b"x",
        )),
    );
    assert_eq!(status, 400, "{}", String::from_utf8_lossy(&err));
    assert!(detail(&err).contains("version_req"), "{}", detail(&err));

    // A name that could escape its own path.
    for bad in ["../../etc/passwd", "a/b", "acme.widget", ""] {
        let (status, _) = cargo_req(
            "PUT",
            &new,
            &admin,
            Some(&publish_body(bad, "1.0.0", Some("MIT"), b"x")),
        );
        assert_eq!(status, 400, "{bad:?} was accepted as a crate name");
    }
    // A version that could never be stored is refused before anything
    // is written — not after the crate's row and its bytes already were.
    for bad in ["caf\u{e9}", "../1.0.0", ""] {
        let (status, err) = cargo_req(
            "PUT",
            &new,
            &admin,
            Some(&publish_body("stray", bad, Some("MIT"), b"x")),
        );
        assert_eq!(status, 400, "{bad:?}: {}", String::from_utf8_lossy(&err));
    }

    // An index path whose prefix is not the one Cargo's rule produces.
    // Serving a crate at any prefix ending in its name would give one
    // resource several URLs — a cache that never hits and a CDN holding
    // several copies of one file.
    for wrong in [
        "1/acme-widget",
        "ac/zz/acme-widget",
        "zz/me/acme-widget",
        "3/a/acme-widget",
    ] {
        let (status, _) = cargo_req("GET", &format!("{b}/index/{wrong}"), &admin, None);
        assert_eq!(status, 404, "{wrong} served the crate");
    }

    // Nobody who has not said who they are learns anything or writes
    // anything — not even whether the crate exists.
    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    for (method, url, body) in [
        ("GET", format!("{b}/index/ac/me/acme-widget"), None),
        ("GET", format!("{b}/index/gh/os/ghost"), None),
        (
            "GET",
            format!("{b}/api/v1/crates/acme-widget/1.0.0/download"),
            None,
        ),
        (
            "PUT",
            new.clone(),
            Some(publish_body("acme-widget", "2.0.0", Some("MIT"), b"x")),
        ),
        (
            "DELETE",
            format!("{b}/api/v1/crates/acme-widget/1.0.0/yank"),
            None,
        ),
    ] {
        for auth in [None, Some(forged)] {
            let headers: Vec<(&str, &str)> =
                auth.map(|a| vec![("Authorization", a)]).unwrap_or_default();
            let r = send(method, &url, &headers, body.as_deref());
            assert_eq!(r.status, 401, "{method} {url} with {auth:?}");
            assert!(
                r.header("www-authenticate")
                    .is_some_and(|v| v.starts_with("Basic")),
                "{method} {url}: no challenge"
            );
        }
    }

    // A reader reads, and may not publish or yank — told why, in the
    // body Cargo prints, rather than told the crate is not there.
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    assert_eq!(
        cargo_req(
            "GET",
            &format!("{b}/index/ac/me/acme-widget"),
            &reader,
            None
        )
        .0,
        200
    );
    // Each refused in the words of what was tried: a yank is not a
    // publish, and saying so sent a reader looking for the wrong thing.
    for (method, url, body, act) in [
        (
            "PUT",
            new.clone(),
            Some(publish_body("acme-widget", "2.0.0", Some("MIT"), b"x")),
            "publish to this registry",
        ),
        (
            "DELETE",
            format!("{b}/api/v1/crates/acme-widget/1.0.0/yank"),
            None,
            "yank a version in this registry",
        ),
    ] {
        let (status, err) = cargo_req(method, &url, &reader, body.as_deref());
        assert_eq!(status, 403, "{method} {url}");
        assert_eq!(
            detail(&err),
            format!("rita is a reader here, and a reader may not {act}")
        );
    }
    // A publisher whose *token* was minted read-only is told the token
    // is the limit, because the fix is different.
    let (_, narrow) = server.person(&admin, "ci", "publisher", &["package:read"]);
    let (status, err) = cargo_req(
        "PUT",
        &new,
        &narrow,
        Some(&publish_body("acme-widget", "2.0.0", Some("MIT"), b"x")),
    );
    assert_eq!(status, 403);
    assert!(
        detail(&err).contains("this token was not minted with package:write"),
        "{}",
        detail(&err)
    );

    // Nothing any of that tried was written: one crate, one version,
    // unyanked, and its bytes untouched.
    let (_, listed) = server.get("/api/v1/packages?ecosystem=cargo", &admin);
    let names: Vec<&str> = listed["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["acme-widget"], "a refused publish left a row");
    let line = index_line(&server, &admin, "ac/me/acme-widget", "1.0.0");
    assert_eq!(line["yanked"], false);
    let (status, bytes) = cargo_req(
        "GET",
        &format!("{b}/api/v1/crates/acme-widget/1.0.0/download"),
        &admin,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(bytes, b"ours");
    assert!(server.healthy());
}

/// A crate with no `license` at all. Cargo also sends `license_file`,
/// which points at a file inside the archive we do not open — so the
/// licence is honestly unknown rather than being invented, and the
/// organization's `unknown` disposition decides what happens to it.
#[test]
fn a_crate_that_declares_no_licence_is_unknown_rather_than_guessed() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-nolicence");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", None, b"crate"))
        )
        .0,
        200
    );
    let id = package_id(&server, &admin, "acme-widget");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert!(shown["versions"][0]["license"].is_null(), "{shown}");
    assert_eq!(shown["versions"][0]["license_source"], "unknown");
    assert!(server.healthy());
}

/// Cargo sends its token with no scheme, and has for its whole
/// history. A door that only read `Bearer` is one `cargo publish`
/// cannot authenticate to at all — and the failure is a 401 the client
/// reports as "token rejected", which sends somebody to regenerate a
/// perfectly good token.
#[test]
fn a_bare_token_is_a_credential_and_a_missing_one_is_challenged() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-auth");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    // Bare — which is what every other request in this file has used,
    // and this is the assertion that says so on purpose.
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"crate"))
        )
        .0,
        200
    );

    // A token in our shape that is not one of ours is refused, and one
    // in no shape of ours is no credential at all: both 401, with the
    // challenge that has Cargo look for a token.
    for token in ["skein_nonsense", "nonsense"] {
        let r = cargo_reply("GET", &format!("{b}/index/config.json"), token, None);
        assert_eq!(r.status, 401, "{token}");
        assert!(r.header("www-authenticate").is_some(), "{token}");
    }

    // None at all gets a challenge.
    let r = send("GET", &format!("{b}/index/config.json"), &[], None);
    assert_eq!(r.status, 401);
    assert!(r
        .header("www-authenticate")
        .is_some_and(|v| v.starts_with("Basic")));

    // The same token with a scheme works too: Cargo is the one client
    // that sends it bare, not the only one allowed to reach this door.
    let r = send(
        "GET",
        &format!("{b}/index/config.json"),
        &[("Authorization", &format!("Bearer {admin}"))],
        None,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(server.healthy());
}

/// The paths and absences Cargo meets that the happy path does not.
#[test]
fn absences_and_malformed_requests_answer_for_themselves() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-absent");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    // A path under the prefix that is none of the shapes it answers.
    assert_eq!(
        cargo_req("GET", &format!("{b}/nonsense"), &admin, None).0,
        404
    );
    assert_eq!(cargo_req("GET", &format!("{b}/index"), &admin, None).0, 404);
    // A crate nobody has published, in the index and at the download.
    let (status, body) = cargo_req("GET", &format!("{b}/index/gh/os/ghost"), &admin, None);
    assert_eq!(status, 404);
    assert_eq!(detail(&body), "no such crate");
    assert_eq!(
        cargo_req(
            "GET",
            &format!("{b}/api/v1/crates/ghost/1.0.0/download"),
            &admin,
            None
        )
        .0,
        404
    );

    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"crate"))
        )
        .0,
        200
    );
    // The crate exists; that version does not.
    assert_eq!(
        cargo_req(
            "GET",
            &format!("{b}/api/v1/crates/acme-widget/9.9.9/download"),
            &admin,
            None
        )
        .0,
        404
    );
    // …and a version string that could never have been stored is a 400
    // rather than a 404: the request is malformed, not absent.
    assert_eq!(
        cargo_req(
            "GET",
            &format!("{b}/api/v1/crates/acme-widget/caf%C3%A9/download"),
            &admin,
            None
        )
        .0,
        400
    );

    // A verb the `{name}/{version}/{verb}` shape does not answer. It
    // shares a route with yank and unyank, so the verb is checked here
    // rather than by the router.
    assert_eq!(
        cargo_req(
            "GET",
            &format!("{b}/api/v1/crates/acme-widget/1.0.0/nonsense"),
            &admin,
            None
        )
        .0,
        404
    );
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/acme-widget/1.0.0/nonsense"),
            &admin,
            None
        )
        .0,
        404
    );
    // Each of yank and unyank has exactly one method. `PUT …/yank` is
    // the method Cargo uses to put a version *back*, and reading the
    // direction from the verb alone let it yank.
    for (method, verb) in [("PUT", "yank"), ("DELETE", "unyank"), ("GET", "yank")] {
        assert_eq!(
            cargo_req(
                method,
                &format!("{b}/api/v1/crates/acme-widget/1.0.0/{verb}"),
                &admin,
                None
            )
            .0,
            404,
            "{method} {verb}"
        );
        assert_eq!(
            index_line(&server, &admin, "ac/me/acme-widget", "1.0.0")["yanked"],
            false,
            "{method} {verb} changed the version"
        );
    }
    // Yanking a crate and a version that are not there.
    assert_eq!(
        cargo_req(
            "DELETE",
            &format!("{b}/api/v1/crates/ghost/1.0.0/yank"),
            &admin,
            None
        )
        .0,
        404
    );
    assert_eq!(
        cargo_req(
            "DELETE",
            &format!("{b}/api/v1/crates/acme-widget/9.9.9/yank"),
            &admin,
            None
        )
        .0,
        404
    );
    // A crate whose `license` is empty is `unknown`, not an empty
    // expression a policy would then try to evaluate.
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body(
                "blank-licence",
                "1.0.0",
                Some("   "),
                b"crate"
            ))
        )
        .0,
        200
    );
    let id = package_id(&server, &admin, "blank-licence");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert!(shown["versions"][0]["license"].is_null(), "{shown}");
    assert!(server.healthy());
}

/// A registry that has switched Cargo off answers nothing at all to
/// somebody who has authenticated — the same 404 as a crate that is not
/// there — and still challenges somebody who has not, so the switch
/// cannot be read from outside.
#[test]
fn a_registry_nobody_enabled_answers_for_nothing() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-off");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let set = |mode: &str| {
        let (status, body) = server.req(
            "PUT",
            "/api/v1/ecosystems",
            &admin,
            Some(serde_json::json!({ "ecosystem": "cargo", "mode": mode })),
        );
        assert_eq!(status, 200, "{body}");
    };
    set("off");

    for url in [
        format!("{b}/index/config.json"),
        format!("{b}/index/ac/me/acme-widget"),
        format!("{b}/api/v1/crates/acme-widget/1.0.0/download"),
    ] {
        assert_eq!(cargo_req("GET", &url, &admin, None).0, 404, "{url}");
        let r = send("GET", &url, &[], None);
        assert_eq!(r.status, 401, "{url}");
        assert!(r.header("www-authenticate").is_some(), "{url}");
    }
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"crate"))
        )
        .0,
        404,
        "published into an ecosystem nobody switched on"
    );
    assert_eq!(
        cargo_req(
            "DELETE",
            &format!("{b}/api/v1/crates/acme-widget/1.0.0/yank"),
            &admin,
            None
        )
        .0,
        404
    );

    // Switched back on, the same publish lands.
    set("private");
    assert_eq!(
        cargo_req(
            "PUT",
            &format!("{b}/api/v1/crates/new"),
            &admin,
            Some(&publish_body("acme-widget", "1.0.0", Some("MIT"), b"crate"))
        )
        .0,
        200
    );
    assert!(server.healthy());
}

/// `config.json` tells Cargo where to fetch from and where to publish,
/// so it names the address this client actually used — but only an
/// address it can safely believe. A `Host` on loopback is the client's
/// own choice and is echoed; any other `Host` than the configured one
/// is attacker-supplied, and a registry that wrote it into the document
/// would send the next `cargo publish`, token and all, to somebody
/// else.
#[test]
fn the_index_names_the_address_the_client_used_and_only_a_safe_one() {
    use std::io::{Read, Write};
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-host");
    let admin = server.bootstrap("acme");

    let config = |host: &str| {
        let mut sock = std::net::TcpStream::connect(server.host()).unwrap();
        write!(
            sock,
            "GET /cargo/index/config.json HTTP/1.1\r\nHost: {host}\r\n\
             Authorization: {admin}\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        sock.read_to_string(&mut out).unwrap();
        let body = out
            .split_once("\r\n\r\n")
            .map(|(_, b)| b)
            .unwrap_or_default();
        serde_json::from_str::<serde_json::Value>(body)
            .unwrap_or_else(|e| panic!("config.json: {e}: {out}"))
    };

    let via = config("127.0.0.1:41234");
    assert_eq!(via["api"], "http://127.0.0.1:41234/cargo", "{via}");
    assert_eq!(
        via["dl"], "http://127.0.0.1:41234/cargo/api/v1/crates",
        "{via}"
    );
    // A name that is not loopback is not believed: the document falls
    // back to the configured URL rather than echoing a stranger's host.
    let hostile = config("evil.example");
    assert_eq!(
        hostile["api"],
        format!("{}/cargo", server.base),
        "{hostile}"
    );
    assert!(
        !hostile["dl"].as_str().unwrap_or_default().contains("evil"),
        "{hostile}"
    );
    assert!(server.healthy());
}

/// A crate bigger than axum's 2 MiB default body limit publishes and
/// comes back whole. The door raises the limit for its publish route; a
/// door that forgot would refuse an ordinary crate with a 413 that says
/// nothing about why.
#[test]
fn a_crate_over_the_default_body_limit_publishes() {
    let bucket = Minio::shared().bucket("cargo-e2e");
    let server = spawn(&bucket.base_url, "cargo-limit");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let krate = vec![7u8; 3 * 1024 * 1024];
    let (status, body) = cargo_req(
        "PUT",
        &format!("{b}/api/v1/crates/new"),
        &admin,
        Some(&publish_body("big", "1.0.0", Some("MIT"), &krate)),
    );
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (status, bytes) = cargo_req(
        "GET",
        &format!("{b}/api/v1/crates/big/1.0.0/download"),
        &admin,
        None,
    );
    assert_eq!(status, 200);
    assert_eq!(bytes.len(), krate.len());
    assert_eq!(sha256_hex(&bytes), sha256_hex(&krate));
    assert!(server.healthy());
}
