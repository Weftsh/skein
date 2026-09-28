//! People and their credentials, end to end: setting an install up,
//! signing in, the tokens a person holds, and what an admin may change.
//!
//! The authority model is small and every piece of it is a security
//! property, so each is exercised through the real server rather than
//! only through the control-plane functions: a token narrowed by its
//! owner's role on its very next request, a disabled person's cookie
//! dying mid-session, a browser request refused without the CSRF header.

mod common;

use common::{publish_doc, spawn};
use skein_testkit::{Minio, Server};

fn bootstrap_json(server: &Server, extra: &[&str]) -> serde_json::Value {
    let mut args = vec!["admin", "bootstrap", "--org", "acme", "--json"];
    args.extend_from_slice(extra);
    let out = server.admin(&args).expect("bootstrap");
    serde_json::from_str(out.trim()).expect("bootstrap prints JSON")
}

/// The session cookie a sign-in set, as `name=value`.
fn session_cookie(r: &skein_testkit::Reply) -> String {
    let set = r
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.clone())
        .expect("a Set-Cookie");
    assert!(set.contains("HttpOnly"), "{set}");
    assert!(set.contains("SameSite=Lax"), "{set}");
    assert!(
        !set.contains("Secure"),
        "a plain-HTTP install must not set Secure: {set}"
    );
    set.split(';').next().unwrap().to_string()
}

fn login(server: &Server, username: &str, password: &str) -> skein_testkit::Reply {
    server.raw(
        "POST",
        "/api/v1/session",
        &[("Content-Type", "application/json"), ("x-skein-csrf", "1")],
        Some(
            serde_json::json!({ "username": username, "password": password })
                .to_string()
                .as_bytes(),
        ),
    )
}

/// An install that has not been bootstrapped says what to run, on every
/// door, and becomes ready the moment it is set up — without a restart.
#[test]
fn an_install_says_how_to_set_it_up_and_is_ready_once_it_is() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-setup");

    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 503);
    assert!(r.text().contains("skein admin bootstrap"), "{}", r.text());
    for path in ["/api/v1/me", "/npm/widget", "/api/v1/packages"] {
        let r = server.raw("GET", path, &[], None);
        assert_eq!(r.status, 503, "{path}");
        assert!(
            r.text().contains("skein admin bootstrap"),
            "{path}: {}",
            r.text()
        );
    }
    assert!(server.healthy(), "liveness does not depend on setup");

    let boot = bootstrap_json(&server, &[]);
    assert_eq!(boot["org"], "acme");
    assert_eq!(boot["username"], "admin");
    assert_eq!(boot["ecosystems"], serde_json::json!(["npm", "maven"]));
    let password = boot["password"].as_str().expect("a generated password");
    assert!(password.len() >= 20, "{password}");

    assert_eq!(server.raw("GET", "/readyz", &[], None).status, 200);
    let token = boot["token"].as_str().unwrap();
    let (status, me) = server.get("/api/v1/me", token);
    assert_eq!(status, 200, "{me}");
    assert_eq!(me["username"], "admin");
    assert_eq!(me["role"], "admin");
    assert_eq!(me["via"], "token");
    assert_eq!(me["org"]["name"], "acme");

    // Once, and only once.
    let again = server
        .admin(&["admin", "bootstrap", "--org", "other"])
        .expect_err("a second bootstrap");
    assert!(again.contains("already serves"), "{again}");

    // A name that is not a name is refused before anything is created.
    let fresh = spawn(&bucket.base_url, "people-badname");
    let err = fresh
        .admin(&["admin", "bootstrap", "--org", "Not A Name"])
        .expect_err("a bad name");
    assert!(err.contains("invalid organization name"), "{err}");
    assert_eq!(fresh.raw("GET", "/readyz", &[], None).status, 503);
}

/// Signing in, what a session may do, and the CSRF wall around it.
#[test]
fn a_browser_session_signs_in_acts_and_signs_out() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-session");
    let boot = bootstrap_json(&server, &[]);
    let password = boot["password"].as_str().unwrap();

    // Every failure looks the same.
    for (u, p) in [
        ("admin", "wrong password here"),
        ("nobody", password),
        ("", ""),
    ] {
        let r = login(&server, u, p);
        assert_eq!(r.status, 401, "{u}");
        assert_eq!(r.json()["error"], "invalid username or password");
    }

    let r = login(&server, "ADMIN", password);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["username"], "admin");
    assert_eq!(r.json()["via"], "session");
    let cookie = session_cookie(&r);

    let with_cookie = |method: &str, path: &str, csrf: bool, body: Option<serde_json::Value>| {
        let mut h = vec![
            ("Cookie", cookie.as_str()),
            ("Content-Type", "application/json"),
        ];
        if csrf {
            h.push(("x-skein-csrf", "1"));
        }
        let b = body.map(|b| b.to_string());
        server.raw(method, path, &h, b.as_deref().map(str::as_bytes))
    };

    let me = with_cookie("GET", "/api/v1/me", false, None);
    assert_eq!(me.status, 200, "a GET needs no CSRF header: {}", me.text());

    // A state change from the browser without the header is refused, and
    // with it goes through.
    let body = serde_json::json!({ "label": "laptop", "scopes": ["package:read"] });
    let refused = with_cookie("POST", "/api/v1/me/tokens", false, Some(body.clone()));
    assert_eq!(refused.status, 403, "{}", refused.text());
    assert!(
        refused.text().contains("x-skein-csrf"),
        "{}",
        refused.text()
    );
    // Signing in is guarded the same way: a page elsewhere must not be
    // able to sign a visitor in as the attacker.
    let r = server.raw(
        "POST",
        "/api/v1/session",
        &[("Content-Type", "application/json")],
        Some(br#"{"username":"admin","password":"x"}"#),
    );
    assert_eq!(r.status, 403);

    let minted = with_cookie("POST", "/api/v1/me/tokens", true, Some(body));
    assert_eq!(minted.status, 201, "{}", minted.text());
    let token = minted.json()["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("skein_"));
    // The token works on a registry door.
    assert_eq!(server.get("/npm/nothing-here", &token).0, 404);

    // A token-bearing request needs no CSRF header: a browser never
    // attaches one on its own.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        boot["token"].as_str().unwrap(),
        Some(serde_json::json!({ "ecosystem": "npm", "mode": "private" })),
    );
    assert_eq!(status, 200);

    // Sign out: the cookie is cleared and dead, and the token lives on.
    let out = with_cookie("DELETE", "/api/v1/session", true, None);
    assert_eq!(out.status, 204);
    assert!(out.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert_eq!(with_cookie("GET", "/api/v1/me", false, None).status, 401);
    assert_eq!(server.get("/api/v1/me", &token).0, 200);
    // Signing out without a session is not an error.
    let r = server.raw("DELETE", "/api/v1/session", &[("x-skein-csrf", "1")], None);
    assert_eq!(r.status, 204);
}

/// A token carries its owner's authority *now*: demote the owner and the
/// token loses the difference on its next request; disable them and it
/// stops working; revoke it and it is dead for good.
#[test]
fn a_token_is_narrowed_by_its_owners_role_on_its_next_request() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-narrow");
    let admin = server.bootstrap("acme");
    let (ci_id, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);

    let publish = |token: &str, v: &str| {
        server
            .req(
                "PUT",
                "/npm/widget",
                token,
                Some(publish_doc("widget", v, b"bytes")),
            )
            .0
    };
    assert_eq!(publish(&ci, "1.0.0"), 201);

    let set = |body: serde_json::Value| {
        server.req(
            "PATCH",
            &format!("/api/v1/users/{ci_id}"),
            &admin,
            Some(body),
        )
    };
    assert_eq!(set(serde_json::json!({ "role": "reader" })).0, 200);
    assert_eq!(
        publish(&ci, "2.0.0"),
        403,
        "a demoted publisher's token still publishes"
    );
    assert_eq!(
        server.get("/npm/widget", &ci).0,
        200,
        "but it still installs"
    );

    assert_eq!(set(serde_json::json!({ "role": "publisher" })).0, 200);
    assert_eq!(publish(&ci, "2.0.0"), 201);

    assert_eq!(set(serde_json::json!({ "disabled": true })).0, 200);
    assert_eq!(
        server.get("/npm/widget", &ci).0,
        401,
        "a disabled person's token works"
    );
    assert_eq!(set(serde_json::json!({ "disabled": false })).0, 200);
    assert_eq!(server.get("/npm/widget", &ci).0, 200);

    // Revoked by an admin: dead for good.
    let (_, tokens) = server.get(&format!("/api/v1/users/{ci_id}/tokens"), &admin);
    let tid = tokens["tokens"][0]["id"].as_str().unwrap().to_string();
    assert!(tokens["tokens"][0]["last_used_at"].is_i64(), "{tokens}");
    assert_eq!(
        server
            .req("DELETE", &format!("/api/v1/tokens/{tid}"), &admin, None)
            .0,
        204
    );
    assert_eq!(server.get("/npm/widget", &ci).0, 401);
    assert_eq!(
        server
            .req("DELETE", &format!("/api/v1/tokens/{tid}"), &admin, None)
            .0,
        404
    );
}

/// What an admin may change, what nobody may, and what a reader is told.
#[test]
fn people_are_managed_by_an_admin_and_the_last_admin_stays() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-admin");
    let admin = server.bootstrap("acme");
    let (_, me) = server.get("/api/v1/me", &admin);
    let admin_id = me["id"].as_str().unwrap().to_string();
    let (rita_id, rita) = server.person(&admin, "rita", "reader", &["org:read"]);

    // A reader sees who is here, and changes nothing.
    let (status, list) = server.get("/api/v1/users", &rita);
    assert_eq!(status, 200, "{list}");
    let names: Vec<&str> = list["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["admin", "rita"]);
    for (method, path, body) in [
        (
            "POST",
            "/api/v1/users".to_string(),
            Some(serde_json::json!({ "username": "x", "role": "admin" })),
        ),
        (
            "PATCH",
            format!("/api/v1/users/{rita_id}"),
            Some(serde_json::json!({ "role": "admin" })),
        ),
        ("DELETE", format!("/api/v1/users/{admin_id}"), None),
        ("GET", "/api/v1/tokens".to_string(), None),
        (
            "PUT",
            "/api/v1/org".to_string(),
            Some(serde_json::json!({ "name": "mine" })),
        ),
    ] {
        let (status, body) = server.req(method, &path, &rita, body);
        assert_eq!(status, 403, "{method} {path}: {body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("rita is a reader"),
            "{body}"
        );
    }
    // A reader's token cannot mint itself a successor.
    let (status, body) = server.req(
        "POST",
        "/api/v1/me/tokens",
        &rita,
        Some(serde_json::json!({ "label": "more", "scopes": ["package:read"] })),
    );
    assert_eq!(status, 403, "{body}");

    // The last admin cannot be demoted, disabled or deleted — by
    // themselves or anybody.
    for body in [
        serde_json::json!({ "role": "reader" }),
        serde_json::json!({ "disabled": true }),
    ] {
        let (status, err) = server.req(
            "PATCH",
            &format!("/api/v1/users/{admin_id}"),
            &admin,
            Some(body),
        );
        assert_eq!(status, 409, "{err}");
        assert!(
            err["error"].as_str().unwrap().contains("no active admin"),
            "{err}"
        );
    }
    assert_eq!(
        server
            .req("DELETE", &format!("/api/v1/users/{admin_id}"), &admin, None)
            .0,
        409
    );

    // Validation, in sentences.
    for (body, want) in [
        (
            serde_json::json!({ "username": "rita", "role": "reader" }),
            409,
        ),
        (
            serde_json::json!({ "username": "Bad Name", "role": "reader" }),
            400,
        ),
        (
            serde_json::json!({ "username": "sam", "role": "owner" }),
            400,
        ),
        (
            serde_json::json!({ "username": "sam", "role": "reader", "password": "short" }),
            400,
        ),
    ] {
        let (status, err) = server.req("POST", "/api/v1/users", &admin, Some(body.clone()));
        assert_eq!(status, want, "{body}: {err}");
    }
    let (status, err) = server.req(
        "POST",
        &format!("/api/v1/users/{rita_id}/tokens"),
        &admin,
        Some(serde_json::json!({ "label": "x", "scopes": ["package:write"] })),
    );
    assert_eq!(status, 400, "a reader cannot hold a write token: {err}");
    let (status, _) = server.req(
        "POST",
        &format!("/api/v1/users/{rita_id}/tokens"),
        &admin,
        Some(serde_json::json!({ "label": "x", "scopes": ["package:everything"] })),
    );
    assert_eq!(status, 400);
    let (status, _) = server.req(
        "POST",
        &format!("/api/v1/users/{rita_id}/tokens"),
        &admin,
        Some(serde_json::json!({ "label": "x", "scopes": ["package:read"], "expires_in_days": 0 })),
    );
    assert_eq!(status, 400);

    // A person with a password can sign in; a service account cannot.
    let (status, sam) = server.req(
        "POST",
        "/api/v1/users",
        &admin,
        Some(serde_json::json!({ "username": "sam", "role": "publisher", "password": "a long enough password" })),
    );
    assert_eq!(status, 201, "{sam}");
    assert_eq!(sam["can_sign_in"], true);
    assert_eq!(login(&server, "sam", "a long enough password").status, 200);
    let (_, rita_row) = server.get("/api/v1/users", &admin);
    assert!(rita_row["users"]
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["username"] == "rita" && u["can_sign_in"] == false));

    // Rename the organization; the id, and so every key, stays.
    let (status, body) = server.req(
        "PUT",
        "/api/v1/org",
        &admin,
        Some(serde_json::json!({ "name": "acme-corp" })),
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        server.get("/api/v1/me", &admin).1["org"]["name"],
        "acme-corp"
    );
    assert_eq!(
        server
            .req(
                "PUT",
                "/api/v1/org",
                &admin,
                Some(serde_json::json!({ "name": "Nope" }))
            )
            .0,
        400
    );

    // Delete a person: their tokens go with them.
    assert_eq!(
        server
            .req("DELETE", &format!("/api/v1/users/{rita_id}"), &admin, None)
            .0,
        204
    );
    assert_eq!(server.get("/api/v1/me", &rita).0, 401);
    assert_eq!(
        server
            .req("DELETE", &format!("/api/v1/users/{rita_id}"), &admin, None)
            .0,
        404
    );

    let (_, overview) = server.get("/api/v1/overview", &admin);
    assert_eq!(overview["org"]["name"], "acme-corp");
    assert_eq!(overview["ecosystems"][0]["ecosystem"], "npm");
    assert_eq!(overview["ecosystems"][0]["served"], true);
    assert!(server.healthy());
}

/// The admin CLI: the way back in when nobody can sign in.
#[test]
fn the_admin_cli_creates_people_mints_tokens_and_gets_you_back_in() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-cli");
    server.bootstrap("acme");

    let out = server
        .admin(&[
            "admin",
            "create-user",
            "ci",
            "--role",
            "publisher",
            "--no-password",
            "--json",
        ])
        .expect("create-user");
    let ci: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(ci["role"], "publisher");
    assert!(ci["password"].is_null());

    let token = server
        .admin(&[
            "admin",
            "mint-token",
            "ci",
            "--label",
            "release",
            "--scope",
            "package:write",
        ])
        .expect("mint-token")
        .trim()
        .to_string();
    assert_eq!(
        server
            .req(
                "PUT",
                "/npm/widget",
                &token,
                Some(publish_doc("widget", "1.0.0", b"b"))
            )
            .0,
        201
    );
    assert!(
        server
            .admin(&["admin", "mint-token", "ci", "--scope", "org:admin"])
            .is_err(),
        "a publisher cannot hold an admin token"
    );

    server
        .admin(&["admin", "set-role", "ci", "reader"])
        .expect("set-role");
    assert_eq!(
        server
            .req(
                "PUT",
                "/npm/widget",
                &token,
                Some(publish_doc("widget", "2.0.0", b"b"))
            )
            .0,
        403
    );
    assert!(server
        .admin(&["admin", "set-role", "admin", "reader"])
        .unwrap_err()
        .contains("no active admin"));
    assert!(server
        .admin(&["admin", "set-role", "ghost", "reader"])
        .unwrap_err()
        .contains("no user"));

    let pw = server
        .admin(&["admin", "reset-password", "admin"])
        .expect("reset")
        .trim()
        .to_string();
    assert_eq!(login(&server, "admin", &pw).status, 200);

    let out = server
        .admin(&["admin", "create-user", "ada", "--role", "admin"])
        .expect("create-user");
    let generated = out
        .lines()
        .find_map(|l| l.strip_prefix("password: "))
        .expect("a password");
    assert_eq!(login(&server, "ada", generated).status, 200);
}

/// Every answer carries the headers a browser needs to be safe.
#[test]
fn every_answer_carries_the_safety_headers() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-headers");
    for path in ["/healthz", "/api/v1/me", "/npm/x"] {
        let r = server.raw("GET", path, &[], None);
        assert_eq!(
            r.header("x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        assert_eq!(r.header("x-frame-options"), Some("DENY"), "{path}");
    }
}

/// Readiness is about the bucket existing, not merely answering: a
/// missing bucket answers 404 to a GET just as a missing key does, and
/// passing it would leave the first publish to discover the problem.
/// `SKEIN_STORE_CREATE_BUCKET` creates it on start, for MinIO.
#[test]
fn readiness_needs_the_bucket_and_the_server_can_create_it() {
    let minio = Minio::shared();
    let url = format!(
        "{}/t-people-nobucket-{}",
        minio.endpoint,
        std::process::id()
    );
    let server = spawn(&url, "people-nobucket");
    server.bootstrap("acme");
    let r = server.raw("GET", "/readyz", &[], None);
    assert_eq!(r.status, 503, "{}", r.text());
    assert!(r.text().contains("not usable"), "{}", r.text());

    let url = format!(
        "{}/t-people-mkbucket-{}",
        minio.endpoint,
        std::process::id()
    );
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &url)
        .db_hint("people-mkbucket")
        .env("SKEIN_STORE_CREATE_BUCKET", "true")
        .start();
    let admin = server.bootstrap("acme");
    assert_eq!(server.raw("GET", "/readyz", &[], None).status, 200);
    assert_eq!(
        server
            .req(
                "PUT",
                "/npm/widget",
                &admin,
                Some(publish_doc("widget", "1.0.0", b"b"))
            )
            .0,
        201
    );
}

/// `GET /api/v1/session` answers 200 whether or not anybody is signed
/// in — the UI asks on every first load — and says who when somebody is.
/// A bad token is still a 401: a credential that does not verify is
/// never quietly treated as none.
#[test]
fn the_session_probe_answers_either_way() {
    let bucket = Minio::shared().bucket("people-e2e");
    let server = spawn(&bucket.base_url, "people-probe");
    let admin = server.bootstrap("acme");
    let r = server.raw("GET", "/api/v1/session", &[], None);
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["signed_in"], false);
    let (status, me) = server.get("/api/v1/session", &admin);
    assert_eq!(status, 200);
    assert_eq!(me["signed_in"], true);
    assert_eq!(me["username"], "admin");
    assert_eq!(server.get("/api/v1/session", "skein_bad_token").0, 401);
}

/// The audit log records what a change *changed*. A field the request did
/// not touch is not written down as `null` — which reads as "cleared" —
/// a display name is recorded when it is the change, and a password is
/// recorded as changed, never as itself.
#[test]
fn an_update_is_audited_as_what_it_changed() {
    let bucket = Minio::shared().bucket("people-audit");
    let server = spawn(&bucket.base_url, "people-audit");
    let admin = server.bootstrap("acme");
    let (id, _) = server.person(&admin, "rita", "reader", &["org:read"]);
    let path = format!("/api/v1/users/{id}");
    for body in [
        serde_json::json!({ "display_name": "Rita R." }),
        serde_json::json!({ "role": "publisher" }),
        serde_json::json!({ "password": "a-long-enough-password" }),
    ] {
        let (s, out) = server.req("PATCH", &path, &admin, Some(body));
        assert_eq!(s, 200, "{out}");
    }
    let (_, log) = server.get("/api/v1/audit", &admin);
    let updates: Vec<&serde_json::Value> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "user.update")
        .map(|e| &e["context"])
        .collect();
    // Newest first.
    let keys = |c: &serde_json::Value| {
        let mut k: Vec<String> = c.as_object().unwrap().keys().cloned().collect();
        k.retain(|k| k != "token_id");
        k.sort();
        k
    };
    assert_eq!(updates.len(), 3, "{log}");
    assert_eq!(keys(updates[0]), ["password", "user"], "{}", updates[0]);
    assert_eq!(updates[0]["password"], "changed");
    assert!(!log.to_string().contains("a-long-enough-password"));
    assert_eq!(keys(updates[1]), ["role", "user"], "{}", updates[1]);
    assert_eq!(updates[1]["role"], "publisher");
    assert_eq!(keys(updates[2]), ["display_name", "user"], "{}", updates[2]);
    assert_eq!(updates[2]["display_name"], "Rita R.");
}
