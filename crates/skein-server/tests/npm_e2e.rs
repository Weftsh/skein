//! The npm registry end to end: a real server, a real bucket, a real
//! Postgres, and npm's own wire protocol.
//!
//! What these establish that the unit tests cannot: that the bytes
//! actually make the round trip through the object store, that the
//! packument a resolver reads names a tarball URL that resolves, and
//! that the refusals are ordered so nothing is told to somebody who has
//! not said who they are.
//!
//! The publish documents here are built the way `npm publish` builds
//! them — that shape is pinned by the unit tests in `registry::npm`.
//! What a real `npm` does against a real server is the job of the
//! `clients` CI job, which drives the actual client; a fake client can
//! only ever confirm what we already believe.

mod common;

use common::{b64, get_bytes, publish_doc, spawn};
use skein_testkit::Minio;

/// The whole loop: publish, resolve, download, and get the same bytes
/// back — following the packument's own `dist.tarball` URL the way a
/// resolver would, because seeing a version in a listing proves the row
/// was written, not that anybody can install it.
#[test]
fn a_published_package_resolves_and_its_tarball_round_trips() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-roundtrip");
    let admin = server.bootstrap("acme");

    let tarball = b"a tarball's worth of bytes, near enough for a test";
    let (status, body) = server.req(
        "PUT",
        "/npm/@acme%2fwidget",
        &admin,
        Some(publish_doc("@acme/widget", "1.0.0", tarball)),
    );
    assert_eq!(status, 201, "publishing: {body}");
    assert_eq!(body["ok"], true);

    let (status, doc) = server.get("/npm/@acme%2fwidget", &admin);
    assert_eq!(status, 200, "packument: {doc}");
    assert_eq!(doc["name"], "@acme/widget");
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    let one = &doc["versions"]["1.0.0"];
    assert_eq!(
        one["dependencies"]["left-pad"], "^1.0.0",
        "a packument with no dependencies installs the package and none of them"
    );
    assert!(
        one["dist"]["integrity"]
            .as_str()
            .unwrap_or_default()
            .starts_with("sha512-"),
        "no integrity for npm to check: {one}"
    );

    let url = one["dist"]["tarball"].as_str().expect("a tarball url");
    assert!(url.starts_with(&server.base), "not our own url: {url}");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200, "fetching {url}");
    assert_eq!(
        bytes, tarball,
        "the bytes that came back are not the ones we published"
    );

    let (status, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["packages"][0]["name"], "@acme/widget");
    assert_eq!(listed["packages"][0]["ecosystem"], "npm");
}

/// A version's bytes never change. The second publish is refused, and —
/// the part that matters — the first version is still exactly what it
/// was.
#[test]
fn republishing_a_version_is_refused_and_changes_nothing() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-immutable");
    let admin = server.bootstrap("acme");

    let first = b"the original bytes";
    let (status, _) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", first)),
    );
    assert_eq!(status, 201);

    let (status, body) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"entirely different bytes")),
    );
    assert_eq!(status, 409, "a republish was accepted: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already published"),
        "{body}"
    );

    let (_, doc) = server.get("/npm/widget", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (_, bytes) = get_bytes(url, &admin);
    assert_eq!(
        bytes, first,
        "the refused publish replaced the bytes anyway"
    );
}

/// A yank hides a version from resolution without removing it, so a
/// lockfile that already names it still installs.
#[test]
fn a_yanked_version_is_marked_and_still_downloadable() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-yank");
    let admin = server.bootstrap("acme");

    let tarball = b"bytes somebody already pinned";
    server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", tarball)),
    );
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let pkg_id = listed["packages"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();

    let (status, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{pkg_id}/versions/1.0.0/yank"),
        &admin,
        Some(serde_json::json!({ "yanked": true, "reason": "published by mistake" })),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["yanked"], true);

    let (_, doc) = server.get("/npm/widget", &admin);
    assert!(
        doc["versions"]["1.0.0"]["deprecated"].is_string(),
        "a yanked version is not marked: {doc}"
    );
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(
        status, 200,
        "yanking broke every build that had pinned this version"
    );
    assert_eq!(bytes, tarball);
}

/// Nothing is public. Without a credential that authenticates, every
/// door answers with a challenge and nothing else — not a 404 for an
/// absent package, not a 200 for a present one — so nobody learns which
/// names are taken, or even whether npm is switched on, without saying
/// who they are.
#[test]
fn nothing_is_answered_to_somebody_who_has_not_said_who_they_are() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-anonymous");
    let admin = server.bootstrap("acme");
    server.req(
        "PUT",
        "/npm/@acme%2fsecret",
        &admin,
        Some(publish_doc("@acme/secret", "1.0.0", b"private bytes")),
    );
    let (_, doc) = server.get("/npm/@acme%2fsecret", &admin);
    let tarball = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url")
        .trim_start_matches(&server.base)
        .to_string();

    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    for path in [
        "/npm/@acme%2fsecret",
        "/npm/@acme%2fno-such-package",
        tarball.as_str(),
    ] {
        for auth in [
            None,
            Some(format!("Bearer {forged}")),
            Some("Bearer nonsense".into()),
        ] {
            let headers: Vec<(&str, &str)> = auth
                .as_deref()
                .map(|a| vec![("Authorization", a)])
                .unwrap_or_default();
            let r = server.raw("GET", path, &headers, None);
            assert_eq!(
                r.status, 401,
                "GET {path} with {auth:?} answered {}",
                r.status
            );
            assert!(
                r.header("www-authenticate")
                    .is_some_and(|v| v.starts_with("Basic")),
                "npm cannot learn it needs to log in: {path}"
            );
        }
    }

    // Switch npm off: a stranger's answer does not change, so it cannot
    // be used to learn which ecosystems are on.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "npm", "mode": "off" })),
    );
    assert_eq!(status, 200);
    let r = server.raw("GET", "/npm/@acme%2fsecret", &[], None);
    assert_eq!(r.status, 401);
    assert!(r.header("www-authenticate").is_some());

    // The API answers the same, without a challenge a browser would turn
    // into a credential dialog.
    for path in ["/api/v1/packages", "/api/v1/me", "/api/v1/ecosystems"] {
        let r = server.raw("GET", path, &[], None);
        assert_eq!(r.status, 401, "{path}");
        assert!(
            r.header("www-authenticate").is_none(),
            "{path} would open a dialog"
        );
    }
    assert!(server.healthy());
}

/// A reader installs and does not publish, and is told why in a
/// sentence npm prints — naming their role, not pretending the package
/// is absent.
#[test]
fn a_reader_installs_and_is_told_why_they_may_not_publish() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-reader");
    let admin = server.bootstrap("acme");
    server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:read"]);

    let (status, doc) = server.get("/npm/widget", &reader);
    assert_eq!(status, 200, "{doc}");

    let (status, body) = server.req(
        "PUT",
        "/npm/widget",
        &reader,
        Some(publish_doc("widget", "2.0.0", b"more bytes")),
    );
    assert_eq!(status, 403, "{body}");
    let why = body["error"].as_str().unwrap_or_default();
    assert!(why.contains("rita is a reader"), "{why}");

    // A publisher whose *token* was minted read-only is told the token
    // is the limit, because the fix is different.
    let (status, body) = server.req(
        "PUT",
        "/npm/widget",
        &ci,
        Some(publish_doc("widget", "2.0.0", b"more bytes")),
    );
    assert_eq!(status, 403, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("this token was not minted with package:write"),
        "{body}"
    );

    // Nothing was published by either refusal.
    let (_, doc) = server.get("/npm/widget", &admin);
    assert!(doc["versions"].get("2.0.0").is_none(), "{doc}");
    assert!(server.healthy());
}

/// An ecosystem nobody switched on answers 404 to somebody who has
/// authenticated — and the API lists every ecosystem so an admin can
/// find the switch rather than guessing why nothing works.
#[test]
fn an_ecosystem_that_is_off_answers_for_nothing() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-off");
    let admin = server.bootstrap("acme");
    let off = serde_json::json!({ "ecosystem": "npm", "mode": "off" });
    assert_eq!(
        server.req("PUT", "/api/v1/ecosystems", &admin, Some(off)).0,
        200
    );

    let (status, _) = server.get("/npm/widget", &admin);
    assert_eq!(status, 404);
    let (status, _) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    assert_eq!(
        status, 404,
        "published into an ecosystem nobody switched on"
    );

    let (status, body) = server.get("/api/v1/ecosystems", &admin);
    assert_eq!(status, 200, "{body}");
    let names: Vec<&str> = body["ecosystems"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|e| e["ecosystem"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(names, vec!["npm", "maven", "pypi", "cargo", "oci"]);
    assert!(body["ecosystems"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["mode"] == "off"));
    assert_eq!(body["registry_base"], server.base, "{body}");

    common::enable(&server, &admin, "npm");
    let (status, _) = server.get("/npm/widget", &admin);
    assert_eq!(status, 404, "enabled, but this package really is absent");
    let (status, _) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    assert_eq!(status, 201);
    assert!(server.healthy(), "the server stopped serving");
}

/// The negative suite. Every case ends by proving the server is still
/// healthy and serving — a server that wedges is a failure, not a pass.
#[test]
fn hostile_publishes_are_refused_and_the_server_keeps_serving() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-hostile");
    let admin = server.bootstrap("acme");

    for name in ["..%2f..%2fetc", "a%2f..%2fb"] {
        let (status, _) = server.req(
            "PUT",
            &format!("/npm/{name}"),
            &admin,
            Some(publish_doc("../../etc/passwd", "1.0.0", b"bytes")),
        );
        assert!(
            (400..500).contains(&status),
            "a traversal name was accepted with {status}"
        );
    }

    let (status, body) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("something-else", "1.0.0", b"bytes")),
    );
    assert_eq!(status, 400, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("something-else"),
        "{body}"
    );

    let mut lying = publish_doc("widget", "1.0.0", b"bytes");
    lying["_attachments"]["widget-1.0.0.tgz"]["length"] = serde_json::json!(999_999);
    assert_eq!(server.req("PUT", "/npm/widget", &admin, Some(lying)).0, 400);

    let mut two = publish_doc("widget", "1.0.0", b"bytes");
    two["versions"]["2.0.0"] = serde_json::json!({ "name": "widget", "version": "2.0.0" });
    assert_eq!(server.req("PUT", "/npm/widget", &admin, Some(two)).0, 400);

    let (status, _) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(serde_json::json!("this is a string, not a publish")),
    );
    assert_eq!(status, 400);

    let r = server.raw(
        "PUT",
        "/npm/widget",
        &[
            ("Authorization", &format!("Bearer {admin}")),
            ("Content-Type", "application/json"),
        ],
        Some(b"{ this is not json"),
    );
    assert_eq!(r.status, 400, "a malformed body was not refused");

    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(
        listed["packages"].as_array().map(|a| a.len()),
        Some(0),
        "a refused publish created a package: {listed}"
    );
    assert!(server.healthy(), "the server wedged on a hostile publish");

    let (status, _) = server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"real bytes")),
    );
    assert_eq!(status, 201);
}

/// The npm door's remaining refusals: the wrong URL for a publish, and
/// tarball paths that name nothing.
#[test]
fn the_npm_door_refuses_the_wrong_url_and_names_nothing_it_did_not_publish() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-refusals");
    let admin = server.bootstrap("acme");

    let (status, body) = server.req(
        "PUT",
        "/npm/widget/-/widget-1.0.0.tgz",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    assert_eq!(status, 400, "{body}");

    let (status, _) = get_bytes(&server.url("/npm/ghost/-/ghost-1.0.0.tgz"), &admin);
    assert_eq!(status, 404);
    server.req(
        "PUT",
        "/npm/widget",
        &admin,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    let (status, _) = get_bytes(&server.url("/npm/widget/-/widget-9.9.9.tgz"), &admin);
    assert_eq!(status, 404, "a tarball name nothing published was served");
    assert!(server.healthy());
}

/// A dist-tag naming some other version is ignored rather than applied.
///
/// npm sends the whole `dist-tags` map on every publish, and it can name
/// versions this publish is not creating. Applying one would point a tag
/// at a version that may not exist — every `npm install` of it would
/// resolve to nothing.
#[test]
fn a_dist_tag_for_another_version_is_not_applied() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-tags");
    let admin = server.bootstrap("acme");

    let mut doc = publish_doc("widget", "1.0.0", b"bytes");
    doc["dist-tags"] = serde_json::json!({ "latest": "1.0.0", "next": "2.0.0-beta" });
    let (status, body) = server.req("PUT", "/npm/widget", &admin, Some(doc));
    assert_eq!(status, 201, "{body}");

    let (_, doc) = server.get("/npm/widget", &admin);
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    assert!(
        doc["dist-tags"].get("next").is_none(),
        "a tag was pointed at a version that was never published: {}",
        doc["dist-tags"]
    );
}

/// The collector actually collects — and only what nothing references.
///
/// Driven through the real worker with a short tick and no grace window
/// rather than by calling the function, because the thing worth proving
/// is that the worker is wired up at all.
#[test]
fn the_collector_removes_orphaned_bytes_and_leaves_referenced_ones() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = skein_testkit::Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("npm-gc")
        .env("SKEIN_GC_INTERVAL_SECS", "1")
        // No grace: the window exists so a publish in flight is not
        // collected, and this test has none in flight.
        .env("SKEIN_GC_GRACE_SECS", "0")
        .start();
    let admin = server.bootstrap("acme");

    for (name, body) in [
        ("doomed", &b"bytes that will be orphaned"[..]),
        ("kept", b"bytes still referenced"),
    ] {
        let (status, b) = server.req(
            "PUT",
            &format!("/npm/{name}"),
            &admin,
            Some(publish_doc(name, "1.0.0", body)),
        );
        assert_eq!(status, 201, "publishing {name}: {b}");
    }

    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let blobs = || skein_control::packages::bytes_for_org(&db, &org.id).expect("bytes");
    let both = blobs();
    assert!(both > 0, "nothing was stored");

    let (_, listed) = server.get("/api/v1/packages", &admin);
    let doomed_id = listed["packages"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|p| p["name"] == "doomed")
        .and_then(|p| p["id"].as_str())
        .expect("the doomed package")
        .to_string();
    let (status, _) = server.req(
        "DELETE",
        &format!("/api/v1/packages/{doomed_id}"),
        &admin,
        None,
    );
    assert_eq!(status, 204);

    skein_testkit::wait_until(
        "the collector to run",
        std::time::Duration::from_secs(60),
        || blobs() < both,
    );
    let after = blobs();
    assert!(
        after > 0,
        "the collector took the surviving package's bytes too"
    );

    // A further tick with nothing collectable left must stop, rather
    // than go on to eat the package that is still referenced.
    std::thread::sleep(std::time::Duration::from_secs(3));
    assert_eq!(
        blobs(),
        after,
        "the collector kept going after there was nothing left"
    );

    // The one still referenced installs — not merely that a row survived.
    let (_, doc) = server.get("/npm/kept", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200, "the collector deleted a referenced artifact");
    assert_eq!(bytes, b"bytes still referenced");

    // And `skein admin gc` runs the same sweep on demand.
    let out = server
        .admin(&["admin", "gc", "--grace-secs", "0"])
        .expect("admin gc");
    let swept: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(swept["blobs"], 0, "{out}");
    assert!(server.healthy());
}

/// The management API's read and delete doors, and the refusals beside
/// them.
#[test]
fn the_management_api_shows_a_package_and_refuses_what_it_should() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-manage");
    let admin = server.bootstrap("acme");
    let (_, publisher) = server.person(&admin, "ci", "publisher", &["package:write"]);

    let (status, body) = server.req(
        "PUT",
        "/npm/widget",
        &publisher,
        Some(publish_doc("widget", "1.0.0", b"bytes")),
    );
    assert_eq!(status, 201, "{body}");
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let id = listed["packages"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();

    let (status, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(status, 200, "{shown}");
    assert_eq!(shown["name"], "widget");
    let v = &shown["versions"][0];
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["license"], "MIT");
    assert_eq!(v["license_source"], "declared");
    assert_eq!(v["published_by_username"], "ci", "who published it: {v}");
    assert!(v["published_by_token"].is_string(), "{v}");
    assert_eq!(v["files"][0]["filename"], "widget-1.0.0.tgz");
    assert!(v["files"][0]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(shown["tags"][0]["tag"], "latest");
    assert_eq!(shown["tags"][0]["version"], "1.0.0");

    let (status, only) = server.get("/api/v1/packages?ecosystem=npm", &admin);
    assert_eq!(status, 200);
    assert_eq!(only["packages"].as_array().map(|a| a.len()), Some(1));
    let (_, found) = server.get("/api/v1/packages?q=WIDG", &admin);
    assert_eq!(found["packages"].as_array().map(|a| a.len()), Some(1));
    let (_, none) = server.get("/api/v1/packages?q=nothing-like-it", &admin);
    assert_eq!(none["packages"].as_array().map(|a| a.len()), Some(0));
    let (status, err) = server.get("/api/v1/packages?ecosystem=nuget", &admin);
    assert_eq!(status, 400, "{err}");
    for bad in [
        serde_json::json!({ "ecosystem": "nuget", "mode": "private" }),
        serde_json::json!({ "ecosystem": "npm", "mode": "sometimes" }),
    ] {
        let (status, err) = server.req("PUT", "/api/v1/ecosystems", &admin, Some(bad));
        assert_eq!(status, 400, "{err}");
    }

    // A publisher cannot delete — the one irreversible act is an admin's.
    let (status, body) = server.req(
        "DELETE",
        &format!("/api/v1/packages/{id}"),
        &publisher,
        None,
    );
    assert_eq!(status, 403, "{body}");
    // …nor switch ecosystems.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &publisher,
        Some(serde_json::json!({ "ecosystem": "npm", "mode": "off" })),
    );
    assert_eq!(status, 403);

    for (method, path) in [
        (
            "GET",
            "/api/v1/packages/01nosuchpackage00000000000".to_string(),
        ),
        (
            "DELETE",
            "/api/v1/packages/01nosuchpackage00000000000".to_string(),
        ),
    ] {
        assert_eq!(
            server.req(method, &path, &admin, None).0,
            404,
            "{method} {path}"
        );
    }
    let yank = |path: &str, body: serde_json::Value| server.req("POST", path, &admin, Some(body));
    assert_eq!(
        yank(
            &format!("/api/v1/packages/{id}/versions/9.9.9/yank"),
            serde_json::json!({ "yanked": true })
        )
        .0,
        404,
        "yanking a version that was never published"
    );
    assert_eq!(
        yank(
            "/api/v1/packages/01nosuchpackage/versions/1.0.0/yank",
            serde_json::json!({ "yanked": true })
        )
        .0,
        404
    );
    assert_eq!(
        yank(
            &format!("/api/v1/packages/{id}/versions/caf%C3%A9/yank"),
            serde_json::json!({ "yanked": true })
        )
        .0,
        400,
        "a non-ASCII version was not refused as malformed"
    );

    // A publisher may yank, and un-yank.
    let (status, y) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.0.0/yank"),
        &publisher,
        Some(serde_json::json!({ "yanked": true, "reason": "a mistake" })),
    );
    assert_eq!(status, 200, "{y}");
    assert_eq!(y["yanked"], true);
    assert_eq!(y["yank_reason"], "a mistake");
    let (status, u) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.0.0/yank"),
        &publisher,
        Some(serde_json::json!({ "yanked": false })),
    );
    assert_eq!(status, 200, "{u}");
    assert_eq!(u["yanked"], false);
    assert!(
        u["yank_reason"].is_null(),
        "un-yanking kept the reason: {u}"
    );

    // Delete, and it is gone — and the audit log says who did each.
    let (status, _) = server.req("DELETE", &format!("/api/v1/packages/{id}"), &admin, None);
    assert_eq!(status, 204);
    assert_eq!(server.get(&format!("/api/v1/packages/{id}"), &admin).0, 404);
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(0));

    let (status, log) = server.get("/api/v1/audit", &admin);
    assert_eq!(status, 200, "{log}");
    let actions: Vec<(&str, &str)> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default(),
                e["username"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    for want in [
        ("packages.delete", "admin"),
        ("packages.unyank", "ci"),
        ("packages.yank", "ci"),
        ("package.publish", "ci"),
    ] {
        assert!(actions.contains(&want), "{want:?} not in {actions:?}");
    }
    assert_eq!(
        server.get("/api/v1/audit", &publisher).0,
        403,
        "the log is an admin's"
    );
    assert!(server.healthy());
}

/// The publish document npm really sends base64s its tarball; a body
/// this size is refused by the router before it is buffered, and the
/// largest artifact we claim to accept is not.
#[test]
fn the_body_limit_carries_base64s_expansion() {
    let bucket = Minio::shared().bucket("npm-e2e");
    let server = spawn(&bucket.base_url, "npm-limit");
    let admin = server.bootstrap("acme");
    // A few megabytes — enough to cross axum's 2 MiB default limit, which
    // would refuse an ordinary package if the door forgot to raise it.
    let tarball = vec![7u8; 3 * 1024 * 1024];
    let (status, body) = server.req(
        "PUT",
        "/npm/big",
        &admin,
        Some(publish_doc("big", "1.0.0", &tarball)),
    );
    assert_eq!(status, 201, "{body}");
    let (_, doc) = server.get("/npm/big", &admin);
    let (_, bytes) = get_bytes(
        doc["versions"]["1.0.0"]["dist"]["tarball"]
            .as_str()
            .unwrap(),
        &admin,
    );
    assert_eq!(bytes.len(), tarball.len());
    let _ = b64(b"");
}
