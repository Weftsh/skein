//! The admission policy and the pull-through proxy, end to end.
//!
//! `policy.rs` and `spdx.rs` are pure and are argued with exhaustively
//! in their own unit tests. What those cannot show is the thing this
//! slice is actually selling: that a build resolving a dependency gets
//! a *filtered* document, that the version the policy refused cannot be
//! reached by going straight at its URL with a lockfile, that a name
//! this organization has reserved is never so much as mentioned to the
//! upstream, and that audit mode really does serve the package while
//! writing the finding down.
//!
//! The upstream is `skein_testkit::fake_registry`, pointed at with
//! `SKEIN_UPSTREAM_NPM`. It encodes what we believe npmjs serves; the
//! `clients` CI job, which drives the real `npm`, is what checks that
//! belief against the real thing.

mod common;

use common::{get_bytes, publish_doc};
use skein_testkit::fake_registry::{FakeRegistry, Version};
use skein_testkit::{Minio, Server};

const DAY: i64 = 86_400_000;

/// A token in exactly the shape of ours that no database has ever
/// issued. The one a guess at the format produces.
const FORGED: &str = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// An ISO8601 timestamp `n` days ago, in the shape npm's `time` map
/// uses. Built from the civil-days algorithm rather than a date crate,
/// which the workspace does not carry.
fn days_ago(n: i64) -> String {
    let ms = now_ms() - n * DAY;
    let (mut days, rem) = (ms.div_euclid(DAY), ms.rem_euclid(DAY));
    let (h, m, s) = (rem / 3_600_000, (rem / 60_000) % 60, (rem / 1000) % 60);
    // Howard Hinnant's civil_from_days.
    days += 719_468;
    let era = days.div_euclid(146_097);
    let doe = days.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.000Z")
}

/// A server whose only route out is the fake.
fn spawn(store_url: &str, hint: &str, upstream: &FakeRegistry) -> Server {
    Server::builder(env!("CARGO_BIN_EXE_skein"), store_url)
        .db_hint(hint)
        // Plaintext on loopback, which `upstream::check_base` admits
        // deliberately: a mirror sidecar on the same host is a real
        // deployment and this is the same shape. Every URL fetched from
        // the document still has to name this origin.
        .env("SKEIN_UPSTREAM_NPM", upstream.base_url.clone())
        .start()
}

fn enable_proxy(server: &Server, admin: &str, unknown: &str) {
    let (status, body) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        admin,
        Some(serde_json::json!({
            "ecosystem": "npm",
            "mode": "proxy",
            "license_unknown": unknown,
        })),
    );
    assert_eq!(status, 200, "enabling the npm proxy: {body}");
}

fn set_policy(server: &Server, admin: &str, mode: &str, cooldown: i64) {
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy",
        admin,
        Some(serde_json::json!({
            "mode": mode,
            "cooldown_days": cooldown,
            "license_mode": "deny_list",
        })),
    );
    assert_eq!(status, 200, "setting the policy: {body}");
}

fn deny_licence(server: &Server, admin: &str, id: &str) {
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy/licenses",
        admin,
        Some(serde_json::json!({ "spdx_id": id, "disposition": "deny" })),
    );
    assert_eq!(status, 200, "denying {id}: {body}");
}

/// Send one API request as somebody who has not proved who they are:
/// `auth` is the `Authorization` value, or `None` for none at all.
///
/// A write with no `Authorization` carries the CSRF header, as the
/// signed-out UI would — without it the CSRF wall answers first, and
/// this is asking what *authentication* says.
fn unproved(
    server: &Server,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<&serde_json::Value>,
) -> skein_testkit::Reply {
    let bytes = body.map(|b| b.to_string().into_bytes());
    let mut headers: Vec<(&str, &str)> = Vec::new();
    match auth {
        Some(a) => headers.push(("Authorization", a)),
        None if method != "GET" => headers.push(("x-skein-csrf", "1")),
        None => {}
    }
    if bytes.is_some() {
        headers.push(("Content-Type", "application/json"));
    }
    server.raw(method, path, &headers, bytes.as_deref())
}

/// Three versions, one of each interesting kind.
fn lodash() -> Vec<Version> {
    vec![
        Version::new("1.0.0", Some("MIT"), Some(&days_ago(400))),
        Version::new("2.0.0", Some("GPL-3.0"), Some(&days_ago(300))),
        // Published this morning: the cooldown's case.
        Version::new("3.0.0", Some("MIT"), Some(&days_ago(0))),
    ]
}

/// The whole pull-through: the document is filtered to what the policy
/// admits, the tarball URL points back at us, the bytes are the
/// upstream's, and the *second* fetch does not touch the upstream at
/// all because the artifact is now ours.
#[test]
fn a_proxied_package_is_filtered_fetched_and_cached() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-proxy", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 7);
    deny_licence(&server, &admin, "GPL-3.0");

    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "packument: {doc}");
    let versions = doc["versions"].as_object().expect("a versions map");
    assert!(versions.contains_key("1.0.0"), "the admissible one is gone");
    assert!(
        !versions.contains_key("2.0.0"),
        "a GPL-3.0 version was served: {doc}"
    );
    assert!(
        !versions.contains_key("3.0.0"),
        "a version published today was served through a 7-day cooldown: {doc}"
    );

    // A dist-tag pointing at a version we withheld is dropped, not
    // repointed. Repointing would silently install something other than
    // what `latest` means upstream, which is a worse answer than "this
    // registry has no latest for you".
    assert!(
        doc["dist-tags"]["latest"].is_null(),
        "latest pointed at a refused version: {doc}"
    );

    // Follow the URL as npm would: it is ours, not npmjs's.
    let url = versions["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    assert_eq!(
        url,
        server.url("/npm/lodash/-/lodash-1.0.0.tgz"),
        "the document still points at the upstream"
    );
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200, "fetching {url}");
    assert_eq!(bytes, b"tarball of 1.0.0");

    // Cached: the second fetch is served from our own store. This is
    // half the value of a proxy — the build works when npmjs does not.
    let before = up.calls().len();
    let (status, again) = get_bytes(url, &admin);
    assert_eq!(status, 200);
    assert_eq!(again, bytes);
    assert_eq!(
        up.calls().len(),
        before,
        "the upstream was asked twice for the same artifact: {:?}",
        up.calls()
    );

    // And it is a real package now, visible to the management API with
    // its origin recorded — which is what stops anybody publishing over
    // a proxied name.
    let (status, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["packages"][0]["name"], "lodash");
    assert_eq!(listed["packages"][0]["origin"], "proxied");
    assert!(server.healthy());
}

/// Once a package is cached, the upstream is still the source of truth
/// for *which versions exist*.
///
/// The defect this pins: answering a cached package's packument from
/// our own rows freezes it at whatever the first install happened to
/// fetch, so `npm install lodash` would return the same version for
/// ever and no upgrade would ever be visible. Nothing about the first
/// install looks wrong, which is what makes it worth a test rather than
/// a comment.
#[test]
fn a_cached_package_still_sees_a_new_upstream_release() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add(
        "lodash",
        vec![Version::new("1.0.0", Some("MIT"), Some(&days_ago(400)))],
    );
    let server = spawn(&bucket.base_url, "registry-refresh", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    // Install once, which caches it.
    let (_, doc) = server.get("/npm/lodash", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    assert_eq!(get_bytes(url, &admin).0, 200);
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"][0]["origin"], "proxied", "not cached yet");

    // Upstream releases a new version.
    up.add(
        "lodash",
        vec![
            Version::new("1.0.0", Some("MIT"), Some(&days_ago(400))),
            Version::new("1.1.0", Some("MIT"), Some(&days_ago(390))),
        ],
    );
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"].as_object().unwrap().contains_key("1.1.0"),
        "the package froze at the version the first install fetched: {doc}"
    );
    assert_eq!(doc["dist-tags"]["latest"], "1.1.0");
    let url = doc["versions"]["1.1.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200);
    assert_eq!(bytes, b"tarball of 1.1.0");
    assert!(server.healthy());
}

/// A client with a lockfile never reads a packument. It goes straight
/// at the tarball URL, so that request meets the *only* gate it will
/// ever meet — and it has to be a real one.
#[test]
fn a_refused_version_cannot_be_reached_by_its_url() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-lockfile", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 7);
    deny_licence(&server, &admin, "GPL-3.0");

    let base = server.url("/npm/lodash/-/");
    for (version, why) in [("2.0.0", "a denied licence"), ("3.0.0", "the cooldown")] {
        let (status, body) = get_bytes(&format!("{base}lodash-{version}.tgz"), &admin);
        assert_eq!(
            status,
            403,
            "{why} was reachable by URL: {}",
            String::from_utf8_lossy(&body)
        );
        // In npm's own shape, because npm prints it and it is the whole
        // of what the developer whose install failed gets to read.
        let refusal: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        assert!(
            refusal["error"]
                .as_str()
                .is_some_and(|e| e.contains(&format!("lodash {version}"))),
            "the refusal for {why} does not say what was refused: {refusal}"
        );
        assert!(
            !up.calls()
                .iter()
                .any(|c| c.contains(&format!("lodash-{version}.tgz"))),
            "we fetched bytes we were never going to serve: {:?}",
            up.calls()
        );
    }
    // The admissible one still works, so this is a gate and not a wall.
    let (status, bytes) = get_bytes(&format!("{base}lodash-1.0.0.tgz"), &admin);
    assert_eq!(status, 200);
    assert_eq!(bytes, b"tarball of 1.0.0");
    assert!(server.healthy());
}

/// The dependency-confusion defence for a name we have *not* published
/// yet. "Private always wins" protects what already exists; this
/// protects `@acme/new-service` on the morning somebody registers it
/// upstream first.
///
/// The stronger assertion is the second one: we do not even ask. Asking
/// would be harmless to us and tells npmjs which internal names this
/// organization uses.
#[test]
fn a_reserved_namespace_is_never_mentioned_to_the_upstream() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    // A partner's scope this organization claims without publishing
    // under it. (Its own scope, `@acme`, is never fetched whether or not
    // anybody reserves it — see the test below.)
    up.add(
        "@partner/new-service",
        vec![Version::new("9.9.9", Some("MIT"), Some(&days_ago(400)))],
    );
    let server = spawn(&bucket.base_url, "registry-reserved", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    let (status, body) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        Some(serde_json::json!({ "ecosystem": "npm", "pattern": "@partner" })),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["reserved"][0], "@partner");

    let (status, doc) = server.get("/npm/@partner%2fnew-service", &admin);
    assert_eq!(status, 404, "a reserved name was proxied: {doc}");
    assert!(
        up.calls().is_empty(),
        "we told the upstream about an internal name: {:?}",
        up.calls()
    );

    // A neighbouring name is not covered — `@partner` must not quietly
    // reserve `@partnerco`.
    up.add(
        "@partnerco/thing",
        vec![Version::new("1.0.0", Some("MIT"), Some(&days_ago(400)))],
    );
    let (status, doc) = server.get("/npm/@partnerco%2fthing", &admin);
    assert_eq!(status, 200, "a neighbouring scope was reserved too: {doc}");

    // Releasing it opens the name again, which is the whole reason
    // release is an admin verb.
    let (status, _) = server.req(
        "DELETE",
        "/api/v1/policy/namespaces?ecosystem=npm&pattern=@partner",
        &admin,
        None,
    );
    assert_eq!(status, 204);
    let (status, doc) = server.get("/npm/@partner%2fnew-service", &admin);
    assert_eq!(status, 200, "releasing did not open the name: {doc}");
    assert!(server.healthy());
}

/// A name under one of the organization's npm scopes is never fetched
/// from the upstream — published or not, reserved or not, in audit mode
/// as in block mode.
///
/// Publishing is limited to those scopes, so a name under one of them is
/// ours whether or not anybody has published it yet; fetching it would
/// install whoever registered it upstream first — dependency confusion —
/// and asking at all tells the upstream which internal names exist. A
/// reservation alone did not close that: in audit mode, the default, a
/// reserved name was still fetched and served. Scopes are matched whole:
/// `@acme` is not `@acme-corp` or `@acmecorp`, which are somebody else's.
#[test]
fn a_name_under_the_organizations_scopes_is_never_fetched() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    for name in [
        "@acme/not-yet",
        "@vendor/sdk",
        "@acme-corp/tool",
        "@acmecorp/tool",
    ] {
        up.add(
            name,
            vec![Version::new("1.0.0", Some("MIT"), Some(&days_ago(400)))],
        );
    }
    let server = spawn(&bucket.base_url, "registry-scopes-never", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "allow");
    let b = server.url("/npm");

    for mode in ["audit", "block"] {
        set_policy(&server, &admin, mode, 0);
        let (status, doc) = server.get("/npm/@acme%2fnot-yet", &admin);
        assert_eq!(status, 404, "{mode}: our own scope was proxied: {doc}");
        let (status, _) = get_bytes(&format!("{b}/@acme%2fnot-yet/-/not-yet-1.0.0.tgz"), &admin);
        assert_eq!(status, 404, "{mode}: fetched through the tarball door");
    }
    assert!(
        up.calls().is_empty(),
        "we asked the upstream about a name under our own scope: {:?}",
        up.calls()
    );

    // A scope an admin adds is ours from that moment.
    set_policy(&server, &admin, "audit", 0);
    let (status, doc) = server.get("/npm/@vendor%2fsdk", &admin);
    assert_eq!(status, 200, "before it was ours: {doc}");
    let asked = up.calls().len();
    let (status, body) = server.req(
        "POST",
        "/api/v1/npm/scopes",
        &admin,
        Some(serde_json::json!({ "scope": "@vendor" })),
    );
    assert_eq!(status, 201, "{body}");
    let (status, doc) = server.get("/npm/@vendor%2fsdk", &admin);
    assert_eq!(status, 404, "a scope just added was still proxied: {doc}");
    assert_eq!(up.calls().len(), asked, "{:?}", up.calls());

    // Somebody else's scope, however alike its name, is fetched as usual.
    for name in ["@acme-corp/tool", "@acmecorp/tool"] {
        let (status, doc) = server.get(&format!("/npm/{}", name.replace('/', "%2f")), &admin);
        assert_eq!(status, 200, "{name} was taken for ours: {doc}");
    }
    assert!(server.healthy());
}

/// Private always wins. A public package with our own name must never
/// answer for the private one, and the upstream must not be asked —
/// which is also what stops the existence of a private package leaking.
#[test]
fn a_published_name_is_never_shadowed_by_the_upstream() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add(
        "@acme/widget",
        vec![Version::new("1.0.0", Some("MIT"), Some(&days_ago(400)))],
    );
    let server = spawn(&bucket.base_url, "registry-shadow", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    // Publish our own, with bytes that are unmistakably not theirs.
    let ours = b"our own widget, not a stranger's";
    let (status, body) = server.req(
        "PUT",
        "/npm/@acme%2fwidget",
        &admin,
        Some(publish_doc("@acme/widget", "1.0.0", ours)),
    );
    assert_eq!(status, 201, "publishing: {body}");

    let (status, doc) = server.get("/npm/@acme%2fwidget", &admin);
    assert_eq!(status, 200, "{doc}");
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200);
    assert_eq!(
        bytes, ours,
        "the upstream's bytes were served under our own name"
    );
    assert!(
        up.calls().is_empty(),
        "we asked the upstream about a name we publish: {:?}",
        up.calls()
    );
    assert!(server.healthy());
}

/// Audit mode is the reason anybody ever switches this on: it serves
/// the package *and* writes down what it would have refused. A week of
/// those rows is what an organization reads before moving to `block`.
#[test]
fn audit_mode_serves_the_package_and_records_the_finding() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-audit", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "audit", 0);
    deny_licence(&server, &admin, "GPL-3.0");

    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"].as_object().unwrap().contains_key("2.0.0"),
        "audit mode withheld a version: {doc}"
    );
    // …and the bytes really are served, not just listed.
    let url = doc["versions"]["2.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url");
    let (status, bytes) = get_bytes(url, &admin);
    assert_eq!(status, 200, "audit mode refused the bytes");
    assert_eq!(bytes, b"tarball of 2.0.0");

    let (status, f) = server.get("/api/v1/findings", &admin);
    assert_eq!(status, 200, "{f}");
    let found = f["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|e| e["version"] == "2.0.0")
        .cloned()
        .unwrap_or_else(|| panic!("no finding for the GPL version: {f}"));
    assert_eq!(found["disposition"], "would_block");
    assert_eq!(found["rule"], "license");
    assert_eq!(found["name"], "lodash");
    assert!(
        found["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("GPL-3.0"),
        "the reason does not name the licence: {found}"
    );
    assert!(
        found["hits"].as_i64().unwrap_or(0) >= 2,
        "the packument and the tarball both checked, so this should have counted twice: {found}"
    );

    // Switching to block changes the answer and the disposition, with
    // no other edit — which is the promise audit mode makes.
    set_policy(&server, &admin, "block", 0);
    let (status, _) = get_bytes(url, &admin);
    assert_eq!(status, 403, "block mode still served it");
    let (_, f) = server.get("/api/v1/findings", &admin);
    let found = f["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["version"] == "2.0.0")
        .cloned()
        .expect("the finding");
    assert_eq!(found["disposition"], "blocked");
    assert!(server.healthy());
}

/// "Allow this", inline on the findings screen: change the rule, then
/// clear the row. Forgetting alone must not admit anything — otherwise
/// tidying the screen would quietly widen the policy.
#[test]
fn allowing_a_licence_admits_it_and_forgetting_a_finding_does_not() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-allow", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);
    deny_licence(&server, &admin, "GPL-3.0");

    let url = server.url("/npm/lodash/-/lodash-2.0.0.tgz");
    assert_eq!(get_bytes(&url, &admin).0, 403);

    // Forgetting the row changes nothing about the decision.
    let (status, _) = server.req(
        "DELETE",
        "/api/v1/findings?ecosystem=npm&name=lodash&version=2.0.0",
        &admin,
        None,
    );
    assert_eq!(status, 204);
    let (_, f) = server.get("/api/v1/findings", &admin);
    assert!(
        !f["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["version"] == "2.0.0"),
        "the finding survived being forgotten: {f}"
    );
    assert_eq!(
        get_bytes(&url, &admin).0,
        403,
        "forgetting a finding admitted the package"
    );

    // Changing the rule is what admits it.
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy/licenses",
        &admin,
        Some(serde_json::json!({ "spdx_id": "GPL-3.0", "disposition": "allow" })),
    );
    assert_eq!(status, 200, "{body}");
    let (status, bytes) = get_bytes(&url, &admin);
    assert_eq!(status, 200, "the rule changed and it is still refused");
    assert_eq!(bytes, b"tarball of 2.0.0");

    // Removing the rule entirely is a third thing again: under a deny
    // list, absent means admitted.
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy/licenses",
        &admin,
        Some(serde_json::json!({ "spdx_id": "GPL-3.0" })),
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        body["license_rules"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false),
        "the rule was not removed: {body}"
    );
    assert!(server.healthy());
}

/// "We could not ask" and "it does not exist" are different answers,
/// and a resolver that caches the second on the first is one somebody
/// has to clear by hand.
#[test]
fn an_upstream_outage_is_a_bad_gateway_and_not_a_missing_package() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-outage", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    up.outage(true);
    let (status, body) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 502, "an outage read as a missing package: {body}");

    // A name the upstream genuinely does not have is still a 404.
    up.outage(false);
    let (status, _) = server.get("/npm/no-such-package-anywhere", &admin);
    assert_eq!(status, 404);

    // And the other half, which is most of why a pull-through cache is
    // worth running at all: a package we have already cached keeps
    // installing while the upstream is down.
    let (_, doc) = server.get("/npm/lodash", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url")
        .to_string();
    assert_eq!(get_bytes(&url, &admin).0, 200);
    up.outage(true);
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(
        status, 200,
        "a build stopped working because the upstream did: {doc}"
    );
    assert!(doc["versions"].as_object().unwrap().contains_key("1.0.0"));
    let (status, bytes) = get_bytes(&url, &admin);
    assert_eq!(status, 200, "the cached bytes were not served");
    assert_eq!(bytes, b"tarball of 1.0.0");
    assert!(server.healthy());
}

/// Reading the policy is `org:read` — a developer whose install was
/// refused has to be able to see why. Changing any of it is
/// `org:admin`, because every knob here widens what third-party code
/// may enter the organization's builds.
#[test]
fn the_policy_is_readable_by_a_member_and_writable_only_by_an_admin() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    let server = spawn(&bucket.base_url, "registry-policy-authz", &up);
    let admin = server.bootstrap("acme");
    let (_, viewer) = server.person(&admin, "rita", "reader", &["org:read"]);

    // Defaults, which a new install starts with: audit, no cooldown.
    let (status, p) = server.get("/api/v1/policy", &viewer);
    assert_eq!(status, 200, "{p}");
    assert_eq!(p["mode"], "audit");
    assert_eq!(p["cooldown_days"], 0);
    // A deny list with no rules admits everything, which is the right
    // thing for a new organization: the alternative is an allow list
    // with no rules, which admits nothing and reads as the registry
    // being broken rather than as a policy.
    assert_eq!(p["license_mode"], "deny_list");
    let (status, f) = server.get("/api/v1/findings", &viewer);
    assert_eq!(status, 200, "{f}");

    let writes: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
        (
            "PUT",
            "/api/v1/policy",
            Some(serde_json::json!({
                "mode": "block", "cooldown_days": 7, "license_mode": "deny_list"
            })),
        ),
        (
            "PUT",
            "/api/v1/policy/licenses",
            Some(serde_json::json!({ "spdx_id": "MIT", "disposition": "allow" })),
        ),
        (
            "POST",
            "/api/v1/policy/namespaces",
            Some(serde_json::json!({ "ecosystem": "npm", "pattern": "@acme" })),
        ),
        (
            "DELETE",
            "/api/v1/policy/namespaces?ecosystem=npm&pattern=@acme",
            None,
        ),
        (
            "DELETE",
            "/api/v1/findings?ecosystem=npm&name=x&version=1.0.0",
            None,
        ),
    ];
    for (method, path, body) in &writes {
        let (status, out) = server.req(method, path, &viewer, body.clone());
        // 403 with a sentence, not a masked 404: everybody who
        // authenticates here is already a member of the one
        // organization and can read this very policy, so pretending it
        // does not exist would hide nothing and help nobody. What they
        // need to be told is that their role is the limit.
        assert_eq!(status, 403, "a reader could {method} {path}: {out}");
        let why = out["error"].as_str().unwrap_or_default();
        assert!(
            why.contains("rita is a reader") && why.contains("administer this registry"),
            "{method} {path} did not say why: {out}"
        );
    }

    // Somebody who has not proved who they are is not told anything —
    // not the policy, not the findings, and not whether a write would
    // have been allowed. No credential, a token in our shape that no
    // database issued, and something that is not a token at all are all
    // the same 401, and without the challenge a browser would turn into
    // a credential dialog.
    let reads: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
        ("GET", "/api/v1/policy", None),
        ("GET", "/api/v1/findings", None),
    ];
    let forged = format!("Bearer {FORGED}");
    for (method, path, body) in writes.iter().chain(reads.iter()) {
        for auth in [None, Some(forged.as_str()), Some("Bearer nonsense")] {
            let r = unproved(&server, method, path, auth, body.as_ref());
            assert_eq!(
                r.status,
                401,
                "{method} {path} with {auth:?} answered: {}",
                r.text()
            );
            assert!(
                r.header("www-authenticate").is_none(),
                "{method} {path} would open a browser's credential dialog"
            );
        }
    }

    // None of those refusals changed anything.
    let (_, p) = server.get("/api/v1/policy", &admin);
    assert_eq!(p["mode"], "audit", "{p}");
    assert_eq!(p["cooldown_days"], 0, "{p}");
    assert_eq!(p["license_rules"], serde_json::json!([]), "{p}");
    assert_eq!(p["reserved"], serde_json::json!([]), "{p}");

    // And the refusals the policy API makes about its own input.
    for bad in [
        serde_json::json!({ "mode": "sometimes", "cooldown_days": 0, "license_mode": "deny_list" }),
        serde_json::json!({ "mode": "block", "cooldown_days": -1, "license_mode": "deny_list" }),
        serde_json::json!({ "mode": "block", "cooldown_days": 99999, "license_mode": "deny_list" }),
        serde_json::json!({ "mode": "block", "cooldown_days": 0, "license_mode": "whatever" }),
    ] {
        let (status, _) = server.req("PUT", "/api/v1/policy", &admin, Some(bad));
        assert_eq!(status, 400);
    }
    for bad in [
        serde_json::json!({ "spdx_id": "", "disposition": "allow" }),
        serde_json::json!({ "spdx_id": "MIT", "disposition": "maybe" }),
    ] {
        let (status, _) = server.req("PUT", "/api/v1/policy/licenses", &admin, Some(bad));
        assert_eq!(status, 400);
    }
    let (status, _) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        Some(serde_json::json!({ "ecosystem": "npm", "pattern": "   " })),
    );
    assert_eq!(status, 400);
    let (status, _) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        Some(serde_json::json!({ "ecosystem": "nuget", "pattern": "@acme" })),
    );
    assert_eq!(status, 400);
    // Releasing something never reserved, and forgetting a finding that
    // does not exist, are 404s rather than cheerful no-ops.
    let (status, _) = server.req(
        "DELETE",
        "/api/v1/policy/namespaces?ecosystem=npm&pattern=@nobody",
        &admin,
        None,
    );
    assert_eq!(status, 404);
    let (status, _) = server.req(
        "DELETE",
        "/api/v1/findings?ecosystem=npm&name=ghost&version=1.0.0",
        &admin,
        None,
    );
    assert_eq!(status, 404);
    assert!(server.healthy());
}

/// The audit log's actions, oldest first, as `(action, context)`.
fn audit_trail(server: &Server, admin: &str) -> Vec<(String, serde_json::Value)> {
    let (status, log) = server.get("/api/v1/audit?limit=500", admin);
    assert_eq!(status, 200, "{log}");
    let mut out: Vec<(String, serde_json::Value)> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default().to_string(),
                e["context"].clone(),
            )
        })
        .collect();
    out.reverse();
    out
}

/// Every change to the admission policy is recorded under a name that
/// says which change it was, in one vocabulary.
///
/// Adding a licence rule and removing one were both
/// `packages.license_rule`, told apart only by a `null` in the context —
/// so "who removed the GPL rule?" was a query over JSON rather than over
/// the action. And the names were `packages.*` beside `package.publish`,
/// for acts that are not about a package at all. Now a change to what
/// the registry admits is `policy.*`, and each verb is its own action.
#[test]
fn every_policy_change_is_audited_as_the_act_it_was() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add(
        "copyleft-thing",
        vec![Version::new("1.0.0", Some("GPL-3.0"), Some(&days_ago(400)))],
    );
    let server = spawn(&bucket.base_url, "registry-policy-audit", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "allow");
    set_policy(&server, &admin, "audit", 0);
    deny_licence(&server, &admin, "GPL-3.0");
    // Audit mode serves it and writes the finding down, which is the
    // finding dismissed below.
    let (status, doc) = server.get("/npm/copyleft-thing", &admin);
    assert_eq!(status, 200, "{doc}");
    for (method, path, body) in [
        (
            "PUT",
            "/api/v1/policy/licenses",
            Some(serde_json::json!({ "spdx_id": "GPL-3.0", "disposition": null })),
        ),
        (
            "POST",
            "/api/v1/policy/namespaces",
            Some(serde_json::json!({ "ecosystem": "npm", "pattern": "@partner" })),
        ),
        (
            "DELETE",
            "/api/v1/policy/namespaces?ecosystem=npm&pattern=@partner",
            None,
        ),
        (
            "DELETE",
            "/api/v1/findings?ecosystem=npm&name=copyleft-thing&version=1.0.0",
            None,
        ),
    ] {
        let (status, out) = server.req(method, path, &admin, body);
        assert!(status == 200 || status == 204, "{method} {path}: {out}");
    }

    let trail = audit_trail(&server, &admin);
    let acts: Vec<&str> = trail
        .iter()
        .map(|(a, _)| a.as_str())
        .filter(|a| a.starts_with("policy.") || a.starts_with("packages."))
        .collect();
    assert_eq!(
        acts,
        [
            "policy.ecosystem",
            "policy.rules",
            "policy.license_rule.set",
            "policy.license_rule.remove",
            "policy.reserve",
            "policy.release",
            "policy.dismiss_finding",
        ],
        "{trail:?}"
    );
    // Setting and removing a rule are two acts, and each says what it
    // was about.
    let set = &trail
        .iter()
        .find(|(a, _)| a == "policy.license_rule.set")
        .unwrap()
        .1;
    assert_eq!(set["spdx_id"], "GPL-3.0", "{set}");
    assert_eq!(set["disposition"], "deny", "{set}");
    let removed = &trail
        .iter()
        .find(|(a, _)| a == "policy.license_rule.remove")
        .unwrap()
        .1;
    assert_eq!(removed["spdx_id"], "GPL-3.0", "{removed}");
    assert!(server.healthy());
}

/// A licence rule names an SPDX licence, and reads back the way the admin
/// wrote it.
///
/// The rules API took anything: "Not A Licence!!" was saved as a deny
/// rule that could never match a package, and the policy screen showed
/// an admin a rule that did nothing. And every rule came back
/// lowercased — "WTFPL" typed, "wtfpl" shown, which reads as the
/// registry having misheard. Now an id is refused unless it is in SPDX's
/// shape, the refusal names it, and it is shown as typed; matching a
/// package's licence is as case-blind as it was.
#[test]
fn a_licence_rule_is_an_spdx_id_and_is_shown_as_typed() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add(
        "shouty",
        vec![Version::new("1.0.0", Some("wtfpl"), Some(&days_ago(400)))],
    );
    let server = spawn(&bucket.base_url, "registry-spdx-ids", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "allow");
    set_policy(&server, &admin, "block", 0);
    let rule = |id: &str, disposition: Option<&str>| {
        server.req(
            "PUT",
            "/api/v1/policy/licenses",
            &admin,
            Some(serde_json::json!({ "spdx_id": id, "disposition": disposition })),
        )
    };

    for bad in [
        "Not A Licence!!",
        "MIT OR Apache-2.0",
        "-MIT",
        ".MIT",
        "LicenseRef-",
        "caf\u{e9}",
        "MIT;",
        &"A".repeat(65),
    ] {
        let (status, out) = rule(bad, Some("deny"));
        assert_eq!(status, 400, "{bad:?} was saved: {out}");
        let said = out["error"].as_str().unwrap_or_default();
        assert!(
            said.contains(bad),
            "the refusal of {bad:?} does not name it: {out}"
        );
        assert!(said.contains("SPDX"), "{out}");
    }
    let (_, p) = server.get("/api/v1/policy", &admin);
    assert_eq!(p["license_rules"], serde_json::json!([]), "{p}");

    for good in [
        "WTFPL",
        "Apache-2.0",
        "GPL-2.0+",
        "LicenseRef-Acme-Internal.1",
    ] {
        let (status, out) = rule(good, Some("deny"));
        assert_eq!(status, 200, "{good:?}: {out}");
    }
    let (_, p) = server.get("/api/v1/policy", &admin);
    let mut ids: Vec<&str> = p["license_rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["spdx_id"].as_str().unwrap())
        .collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            "Apache-2.0",
            "GPL-2.0+",
            "LicenseRef-Acme-Internal.1",
            "WTFPL"
        ],
        "{p}"
    );

    // Matching is still blind to case: a package declaring "wtfpl" meets
    // the rule typed "WTFPL".
    let (status, doc) = server.get("/npm/shouty", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"].as_object().is_some_and(|v| v.is_empty()),
        "a rule typed in capitals missed a lowercase licence: {doc}"
    );

    // Another spelling of the same id is the same rule, shown the new way;
    // and a rule is removed whatever case the removal is typed in.
    let (status, out) = rule("wtfpl", Some("allow"));
    assert_eq!(status, 200, "{out}");
    let rules = out["license_rules"].as_array().unwrap().clone();
    assert_eq!(
        rules.len(),
        4,
        "a second spelling made a second rule: {out}"
    );
    assert!(
        rules
            .iter()
            .any(|r| r["spdx_id"] == "wtfpl" && r["disposition"] == "allow"),
        "{out}"
    );
    let (status, out) = rule("APACHE-2.0", None);
    assert_eq!(status, 200, "{out}");
    assert_eq!(out["license_rules"].as_array().unwrap().len(), 3, "{out}");
    assert!(server.healthy());
}

/// An upstream that answers 200 with something that is not a document.
///
/// A different failure from an outage, and it has to stay different:
/// both mean the proxy cannot serve, but only this one says the
/// upstream is broken rather than absent. A registry that read nonsense
/// as "no such package" would have every resolver cache that.
#[test]
fn an_upstream_that_answers_nonsense_is_a_bad_gateway_and_falls_back_to_the_cache() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-nonsense", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    // Nothing cached yet: the only honest answer is that we asked and
    // could not read what came back.
    up.garbage(true);
    let (status, body) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 502, "nonsense read as a missing package: {body}");
    // A lockfile client goes straight at the tarball and meets it too.
    let (status, _) = get_bytes(&server.url("/npm/lodash/-/lodash-1.0.0.tgz"), &admin);
    assert_eq!(status, 502);

    // Cache it while the upstream is well…
    up.garbage(false);
    let (_, doc) = server.get("/npm/lodash", &admin);
    let url = doc["versions"]["1.0.0"]["dist"]["tarball"]
        .as_str()
        .expect("a tarball url")
        .to_string();
    assert_eq!(get_bytes(&url, &admin).0, 200);

    // …and a package we already hold keeps installing when the upstream
    // starts answering rubbish, exactly as it does through an outage.
    up.garbage(true);
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(
        status, 200,
        "a build stopped because the upstream did: {doc}"
    );
    assert!(doc["versions"].as_object().unwrap().contains_key("1.0.0"));
    let (status, bytes) = get_bytes(&url, &admin);
    assert_eq!(status, 200);
    assert_eq!(bytes, b"tarball of 1.0.0");
    assert!(server.healthy());
}

/// A name the upstream does not have, reached straight at the tarball
/// URL — which is what a client with a lockfile does. It is a 404 and
/// not a 502: we asked and were told it is not there.
#[test]
fn a_tarball_the_upstream_does_not_have_is_absent_rather_than_broken() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-absent-tarball", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);
    let b = server.url("/npm");

    // A package the upstream has never heard of.
    assert_eq!(
        get_bytes(&format!("{b}/ghost/-/ghost-1.0.0.tgz"), &admin).0,
        404
    );
    // A package it has, at a version it does not. The filename is
    // matched against each version's *derived* name rather than parsed
    // back into a version, so this is "no such tarball" rather than a
    // guess at which version was meant.
    assert_eq!(
        get_bytes(&format!("{b}/lodash/-/lodash-9.9.9.tgz"), &admin).0,
        404
    );
    // …and a filename that is not one this package could ever produce.
    assert_eq!(
        get_bytes(&format!("{b}/lodash/-/something-else.tgz"), &admin).0,
        404
    );
    assert!(server.healthy());
}

/// The two refusals every screen in the packages settings can produce,
/// on every endpoint that can produce them.
///
/// Neither is exotic. A credential is whatever the caller presented —
/// none, a revoked one, one typed from memory — and `?ecosystem=` is a
/// query parameter a dashboard builds from a dropdown that a newer
/// build may have added a value to. They are checked endpoint by
/// endpoint rather than once, because each handler does its own
/// authentication and its own parse: a door that forgot one would
/// answer the caller it should have refused — or worse, act on the
/// default ecosystem — and a single-endpoint test would never see it.
#[test]
fn the_packages_settings_refuse_an_unauthenticated_caller_and_an_unknown_ecosystem() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    let server = spawn(&bucket.base_url, "registry-policy-refusals", &up);
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["org:read"]);

    let rules = serde_json::json!({ "spdx_id": "MIT", "disposition": "allow" });
    let ns = serde_json::json!({ "ecosystem": "npm", "pattern": "@acme/*" });
    let policy = serde_json::json!({
        "mode": "block", "cooldown_days": 0, "license_mode": "deny_list"
    });
    let every: Vec<(&str, &str, Option<serde_json::Value>)> = vec![
        ("GET", "/api/v1/policy", None),
        ("PUT", "/api/v1/policy", Some(policy)),
        ("PUT", "/api/v1/policy/licenses", Some(rules)),
        ("POST", "/api/v1/policy/namespaces", Some(ns)),
        ("DELETE", "/api/v1/policy/namespaces", None),
        ("GET", "/api/v1/findings", None),
        ("DELETE", "/api/v1/findings", None),
    ];
    let forged = format!("Bearer {FORGED}");
    for (method, path, body) in &every {
        for auth in [None, Some(forged.as_str()), Some("Bearer nonsense")] {
            let r = unproved(&server, method, path, auth, body.as_ref());
            assert_eq!(
                r.status,
                401,
                "{method} {path} answered somebody who had not said who they are ({auth:?}): {}",
                r.text()
            );
            assert!(
                r.header("www-authenticate").is_none(),
                "{method} {path} would open a browser's credential dialog"
            );
        }
        // A reader reads, and is refused every write in a sentence.
        let (status, out) = server.req(method, path, &reader, body.clone());
        if *method == "GET" {
            assert_eq!(status, 200, "a reader could not {method} {path}: {out}");
        } else {
            assert_eq!(status, 403, "a reader could {method} {path}: {out}");
            assert!(
                out["error"]
                    .as_str()
                    .is_some_and(|e| e.contains("rita is a reader")),
                "{method} {path} refused a reader without saying why: {out}"
            );
        }
    }

    // An ecosystem name this deployment does not serve. A 400 rather
    // than a silent fall back to npm: acting on a different ecosystem
    // than the caller named is how a rule lands on the wrong registry.
    for (method, path) in [
        ("GET", "/api/v1/policy?ecosystem=zzz"),
        ("DELETE", "/api/v1/policy/namespaces?ecosystem=zzz"),
        ("DELETE", "/api/v1/findings?ecosystem=zzz"),
    ] {
        let (status, out) = server.req(method, path, &admin, None);
        assert_eq!(
            status, 400,
            "{method} {path} accepted an unknown ecosystem: {out}"
        );
    }

    // A reserved prefix longer than a package name can be. It would
    // match nothing it was meant to protect, so accepting it would hand
    // an organization a reservation that silently covers nothing.
    let long = "@".to_string() + &"a".repeat(215);
    let (status, out) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        Some(serde_json::json!({ "ecosystem": "npm", "pattern": long })),
    );
    assert_eq!(
        status, 400,
        "an unstorable reserved prefix was accepted: {out}"
    );

    // Every one of those was refused, so the policy is the one a new
    // install starts with.
    let (_, p) = server.get("/api/v1/policy", &admin);
    assert_eq!(
        p["mode"], "audit",
        "a refused write changed the policy: {p}"
    );
    assert_eq!(p["license_rules"], serde_json::json!([]), "{p}");
    assert_eq!(p["reserved"], serde_json::json!([]), "{p}");

    assert!(server.healthy());
}

/// The tarball door enforces the same policy the packument door does,
/// and says the same thing when the upstream is down.
///
/// The two doors are separate handlers, and a lockfile client goes
/// straight to the tarball URL without ever reading a packument. So a
/// reserved namespace that is only enforced at metadata time is not
/// enforced at all for exactly the client most likely to be resolving
/// a name somebody else just registered upstream — which is the attack
/// the reservation exists to stop.
#[test]
fn the_tarball_door_honours_reservations_and_reports_an_outage() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-tarball-policy", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);
    let b = server.url("/npm");

    let (status, body) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        Some(serde_json::json!({ "ecosystem": "npm", "pattern": "@partner" })),
    );
    assert_eq!(status, 200, "{body}");

    // Straight at the tarball, the way a lockfile resolves.
    let before = up.calls().len();
    let (status, _) = get_bytes(
        &format!("{b}/@partner%2fnew-service/-/new-service-1.0.0.tgz"),
        &admin,
    );
    assert_eq!(
        status, 404,
        "a reserved name was fetched through the tarball door"
    );
    assert_eq!(
        up.calls().len(),
        before,
        "we told the upstream about an internal name: {:?}",
        up.calls()
    );

    // And an upstream that cannot be reached is a bad gateway on this
    // door too — not a 404, which a resolver would cache as "there is
    // no such package" and keep believing after the outage ended.
    up.outage(true);
    let (status, _) = get_bytes(&format!("{b}/lodash/-/lodash-4.17.21.tgz"), &admin);
    assert_eq!(status, 502, "an upstream outage read as an absent tarball");
    up.outage(false);

    assert!(server.healthy());
}

/// An allow list, an audit-mode reservation, and a version that
/// declares no licence at all.
///
/// These are the settings an organization actually arrives at, and none
/// of them had been driven end to end. An allow list is the stricter of
/// the two modes and the one a regulated shop turns on first; audit
/// mode is what makes any of this adoptable, and its whole promise is
/// that the package is *served* while the finding is recorded — a
/// reservation that refused in audit mode would be block mode wearing
/// the wrong name; and a version declaring nothing is the ordinary case
/// for a great deal of what is on npmjs, so whether it is admitted has
/// to follow the organization's `unknown` disposition rather than a
/// default nobody chose.
#[test]
fn an_allow_list_admits_what_it_lists_and_audit_mode_serves_what_it_records() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    // A package that declares no licence, which most of npmjs's older
    // corner does.
    up.add(
        "silent",
        vec![Version::new("1.0.0", None, Some(&days_ago(200)))],
    );
    let server = spawn(&bucket.base_url, "registry-allow-list", &up);
    let admin = server.bootstrap("acme");
    // `allow` for the unknown disposition, so a version declaring
    // nothing is admitted and cached rather than withheld.
    enable_proxy(&server, &admin, "allow");

    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy",
        &admin,
        Some(serde_json::json!({
            "mode": "block", "cooldown_days": 0, "license_mode": "allow_list"
        })),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy/licenses",
        &admin,
        Some(serde_json::json!({ "spdx_id": "MIT", "disposition": "allow" })),
    );
    assert_eq!(status, 200, "{body}");

    // An allow list naming MIT admits the MIT versions and withholds the
    // GPL one — the opposite way round from a deny list, and the
    // difference is the whole point of having both.
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    let versions = doc["versions"].as_object().expect("versions");
    assert!(
        versions.contains_key("1.0.0"),
        "an allowed licence was withheld: {doc}"
    );
    assert!(
        !versions.contains_key("2.0.0"),
        "an allow list served a licence it does not list: {doc}"
    );

    // A version declaring nothing, under `unknown = allow`.
    let (status, doc) = server.get("/npm/silent", &admin);
    assert_eq!(
        status, 200,
        "a licence-less version was withheld under unknown=allow: {doc}"
    );
    assert!(doc["versions"]["1.0.0"].is_object(), "{doc}");
    // …and through to the artifact, which is the fetch that caches it.
    // The packument alone records nothing, so stopping here would show
    // only that the version was listed, not that one declaring no
    // licence can be stored at all.
    let b = server.url("/npm");
    let (status, _) = get_bytes(&format!("{b}/silent/-/silent-1.0.0.tgz"), &admin);
    assert_eq!(status, 200, "a licence-less version could not be cached");

    // Now audit mode, and a reserved namespace: recorded, and still
    // served.
    // Blocking here would make audit mode indistinguishable from block
    // mode for the one rule most likely to be switched on first.
    let (status, body) = server.req(
        "PUT",
        "/api/v1/policy",
        &admin,
        Some(serde_json::json!({
            "mode": "audit", "cooldown_days": 0, "license_mode": "allow_list"
        })),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = server.req(
        "POST",
        "/api/v1/policy/namespaces",
        &admin,
        // The whole name. `namespace_covers` requires the next
        // character after the pattern to be a separator, so "lod" would
        // not cover "lodash" — and an earlier version of this test
        // reserved exactly that, matched nothing, and passed anyway on a
        // finding the licence rule had written.
        Some(serde_json::json!({ "ecosystem": "npm", "pattern": "lodash" })),
    );
    assert_eq!(status, 200, "{body}");
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(
        status, 200,
        "audit mode refused a reserved name instead of recording it: {doc}"
    );
    let (status, found) = server.get("/api/v1/findings", &admin);
    assert_eq!(status, 200, "{found}");
    let rows = found["findings"].as_array().expect("findings");
    assert!(
        rows.iter()
            .any(|f| f["disposition"] == "would_block" && f["rule"] == "reserved"),
        "audit mode served the package but recorded no reservation finding: {found}"
    );

    assert!(server.healthy());
}

/// A name this organization cached from upstream is not a name it may
/// publish over.
///
/// This is the dependency-confusion rule pointed the other way. The
/// documented one stops a public package shadowing a private one; this
/// stops a local publish landing under a name whose other versions came
/// from somebody else, which would leave one package whose versions
/// have two different origins and no way for a reader to tell which is
/// which.
#[test]
fn a_name_cached_from_upstream_cannot_be_published_over() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("@vendor/sdk", lodash());
    let server = spawn(&bucket.base_url, "registry-publish-over-proxied", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);

    // Cache it. The packument alone does not make the name proxied —
    // no artifact of ours exists yet — so this follows through to a
    // tarball, which is the fetch that writes the row.
    let (status, doc) = server.get("/npm/@vendor%2fsdk", &admin);
    assert_eq!(status, 200, "{doc}");
    let b = server.url("/npm");
    let (status, _) = get_bytes(&format!("{b}/@vendor%2fsdk/-/sdk-1.0.0.tgz"), &admin);
    assert_eq!(status, 200, "the upstream tarball did not cache");

    // The scope becomes the organization's afterwards — the only way a
    // name under one of its scopes can already be somebody else's here.
    let (status, body) = server.req(
        "POST",
        "/api/v1/npm/scopes",
        &admin,
        Some(serde_json::json!({ "scope": "@vendor" })),
    );
    assert_eq!(status, 201, "{body}");
    let (_, scopes) = server.get("/api/v1/npm/scopes", &admin);
    assert!(
        scopes["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["scope"] == "@vendor" && s["packages"] == 0),
        "a cached package counted as one this organization publishes: {scopes}"
    );

    let (status, body) = server.req(
        "PUT",
        "/npm/@vendor%2fsdk",
        &admin,
        Some(publish_doc("@vendor/sdk", "9.9.9", b"our own bytes")),
    );
    assert_eq!(status, 409, "a publish landed on a proxied name: {body}");

    // And the cached versions are untouched by the attempt.
    let (status, doc) = server.get("/npm/@vendor%2fsdk", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"]["9.9.9"].is_null(),
        "the refused publish left a version behind: {doc}"
    );
    assert!(server.healthy());
}

/// An upstream that is half up, a name npm would send and we cannot
/// store, and a cached version the policy has changed its mind about.
#[test]
fn the_proxy_answers_for_a_half_up_upstream_a_long_name_and_a_changed_rule() {
    let bucket = Minio::shared().bucket("npm-proxy-e2e");
    let up = FakeRegistry::start();
    up.add("lodash", lodash());
    let server = spawn(&bucket.base_url, "registry-half-up", &up);
    let admin = server.bootstrap("acme");
    enable_proxy(&server, &admin, "block");
    set_policy(&server, &admin, "block", 0);
    let b = server.url("/npm");

    // The registry API answers and the artifact does not — a CDN edge
    // failing behind a healthy metadata host. This is a different
    // refusal from a document we could not read: the version exists and
    // is admissible, and only the bytes are missing, so a 404 would have
    // a resolver record "no such version" for a package that has it.
    up.tarball_outage(true);
    let (status, _) = get_bytes(&format!("{b}/lodash/-/lodash-1.0.0.tgz"), &admin);
    assert_eq!(status, 502, "a half-up upstream read as an absent tarball");
    up.tarball_outage(false);

    // A name npm's own grammar allows and this registry cannot store.
    // Same answer as any other name we do not have: telling a caller
    // the difference between "malformed" and "absent" is not worth the
    // precision.
    let long = "a".repeat(300);
    assert_eq!(server.get(&format!("/npm/{long}"), &admin).0, 404);
    assert_eq!(
        get_bytes(&format!("{b}/{long}/-/{long}-1.0.0.tgz"), &admin).0,
        404
    );

    // A version cached while it was admissible, under a rule that has
    // since changed. The packument is re-decided on the way out rather
    // than served from what the policy said the day it was cached —
    // otherwise denying a licence would take effect for everybody
    // except the builds that had already fetched it.
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(doc["versions"]["1.0.0"].is_object(), "{doc}");
    let (status, _) = get_bytes(&format!("{b}/lodash/-/lodash-1.0.0.tgz"), &admin);
    assert_eq!(status, 200);

    deny_licence(&server, &admin, "MIT");
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"]["1.0.0"].is_null(),
        "a cached version outlived the rule that admitted it: {doc}"
    );

    // The same from the cache alone. With the upstream up, the answer
    // above could have come from re-filtering the upstream's document;
    // with it down, only our own rows answer — which is exactly where a
    // decision frozen at cache time would survive. And a lockfile client
    // going straight at the cached tarball meets the new rule too.
    up.outage(true);
    let (status, doc) = server.get("/npm/lodash", &admin);
    assert_eq!(status, 200, "{doc}");
    assert!(
        doc["versions"]["1.0.0"].is_null(),
        "the cache served a version the rule now refuses: {doc}"
    );
    let (status, body) = get_bytes(&format!("{b}/lodash/-/lodash-1.0.0.tgz"), &admin);
    assert_eq!(
        status,
        403,
        "a cached artifact outlived the rule that admitted it: {}",
        String::from_utf8_lossy(&body)
    );
    up.outage(false);

    assert!(server.healthy());
}
