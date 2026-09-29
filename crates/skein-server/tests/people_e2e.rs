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
    for path in [
        "/api/v1/me",
        "/npm/widget",
        "/pypi/simple/widget/",
        "/api/v1/packages",
    ] {
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
    let password = boot["password"].as_str().expect("a generated password");
    assert!(password.len() >= 20, "{password}");

    assert_eq!(server.raw("GET", "/readyz", &[], None).status, 200);
    let token = boot["token"].as_str().unwrap();

    // The bootstrap switched on exactly what this build serves, in
    // private mode, and said so.
    let (status, overview) = server.get("/api/v1/overview", token);
    assert_eq!(status, 200, "{overview}");
    let ecos = overview["ecosystems"].as_array().expect("a list");
    let served: Vec<&serde_json::Value> = ecos
        .iter()
        .filter(|e| e["served"] == true)
        .map(|e| &e["ecosystem"])
        .collect();
    assert_eq!(
        boot["ecosystems"]
            .as_array()
            .expect("a list")
            .iter()
            .collect::<Vec<_>>(),
        served,
        "{boot} {overview}"
    );
    assert!(served.contains(&&serde_json::json!("npm")), "{overview}");
    for e in ecos {
        let want = if e["served"] == true {
            "private"
        } else {
            "off"
        };
        assert_eq!(e["mode"], want, "{e}");
    }
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
                "/npm/@acme%2fwidget",
                token,
                Some(publish_doc("@acme/widget", v, b"bytes")),
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
        server.get("/npm/@acme%2fwidget", &ci).0,
        200,
        "but it still installs"
    );

    assert_eq!(set(serde_json::json!({ "role": "publisher" })).0, 200);
    assert_eq!(publish(&ci, "2.0.0"), 201);

    assert_eq!(set(serde_json::json!({ "disabled": true })).0, 200);
    assert_eq!(
        server.get("/npm/@acme%2fwidget", &ci).0,
        401,
        "a disabled person's token works"
    );
    assert_eq!(set(serde_json::json!({ "disabled": false })).0, 200);
    assert_eq!(server.get("/npm/@acme%2fwidget", &ci).0, 200);

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
    assert_eq!(server.get("/npm/@acme%2fwidget", &ci).0, 401);
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
                "/npm/@acme%2fwidget",
                &token,
                Some(publish_doc("@acme/widget", "1.0.0", b"b"))
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
                "/npm/@acme%2fwidget",
                &token,
                Some(publish_doc("@acme/widget", "2.0.0", b"b"))
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
                "/npm/@acme%2fwidget",
                &admin,
                Some(publish_doc("@acme/widget", "1.0.0", b"b"))
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

/// A refusal names what was attempted. `package:write` covers a publish
/// and a yank, and every refusal of it used to say "may not publish" —
/// so a reader's `cargo yank` sent them looking for a publish they never
/// tried. The class, across every door where the act is not a publish.
#[test]
fn a_refusal_names_what_was_attempted() {
    let bucket = Minio::shared().bucket("people-verbs");
    let server = spawn(&bucket.base_url, "people-verbs");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["org:read"]);
    let (_, narrow) = server.person(&admin, "pat", "publisher", &["package:read"]);
    let basic = |t: &str| format!("Basic {}", common::b64(format!("skein:{t}").as_bytes()));
    let cases: Vec<(&str, String, String, &str)> = vec![
        (
            "DELETE",
            "/cargo/api/v1/crates/widget/1.0.0/yank".into(),
            reader.clone(),
            "may not yank a version",
        ),
        (
            "PUT",
            "/cargo/api/v1/crates/widget/1.0.0/unyank".into(),
            reader.clone(),
            "may not unyank a version",
        ),
        (
            "DELETE",
            "/v2/acme/app/manifests/v1".into(),
            basic(&reader),
            "may not delete tags",
        ),
        (
            "PUT",
            "/v2/acme/app/manifests/v1".into(),
            basic(&reader),
            "may not push to this registry",
        ),
        (
            "POST",
            "/api/v1/packages/01aaaaaaaaaaaaaaaaaaaaaaaa/versions/1.0.0/yank".into(),
            format!("Bearer {reader}"),
            "may not yank or unyank a version",
        ),
        // The token, not the role, is the limit: said so, with the act.
        (
            "DELETE",
            "/cargo/api/v1/crates/widget/1.0.0/yank".into(),
            narrow.clone(),
            "not minted with package:write and so may not yank",
        ),
    ];
    for (method, path, auth, want) in cases {
        let r = server.raw(
            method,
            &path,
            &[
                ("Authorization", auth.as_str()),
                ("Content-Type", "application/json"),
            ],
            Some(br#"{"yanked": true}"#),
        );
        assert_eq!(r.status, 403, "{method} {path}: {}", r.text());
        assert!(r.text().contains(want), "{method} {path}: {}", r.text());
        assert!(
            !r.text().contains("publish"),
            "{method} {path}: {}",
            r.text()
        );
    }
    // A publish is still called one.
    let r = server.raw(
        "PUT",
        "/npm/widget",
        &[
            ("Authorization", &format!("Bearer {reader}")),
            ("Content-Type", "application/json"),
        ],
        Some(b"{}"),
    );
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(
        r.text().contains("may not publish to this registry"),
        "{}",
        r.text()
    );
    assert!(server.healthy());
}

/// Removing a person does not erase who published what, or who did what.
///
/// A version's publisher was a link to the person's row, `SET NULL` when
/// the row went, so the package page showed "—" for everything they had
/// ever shipped; and the audit log named its actor by joining the same
/// row, so Activity showed a bare `user:<id>`. The names are now written
/// down when the act happens. Two doors, because every door records its
/// publisher through one function and a second proves it is that one.
#[test]
fn removing_a_person_keeps_their_name_on_what_they_did() {
    let bucket = Minio::shared().bucket("people-remove-names");
    let server = spawn(&bucket.base_url, "people-remove-names");
    let admin = server.bootstrap("acme");
    let (xavier_id, xavier) = server.person(&admin, "xavier", "publisher", &["package:write"]);

    let (s, body) = server.req(
        "PUT",
        "/npm/@acme%2fwidget",
        &xavier,
        Some(publish_doc("@acme/widget", "1.0.0", b"bytes")),
    );
    assert_eq!(s, 201, "{body}");
    let jar = skein_testkit::server::send(
        "PUT",
        &server.url("/maven/com/acme/tool/1.0.0/tool-1.0.0.jar"),
        &[("Authorization", &format!("Bearer {xavier}"))],
        Some(b"PK\x03\x04 near enough"),
    );
    assert_eq!(jar.status, 201, "{}", jar.text());
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let ids: Vec<(String, String)> = listed["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p["name"].as_str().unwrap().to_string(),
                p["id"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    assert_eq!(ids.len(), 2, "{listed}");
    let widget = &ids.iter().find(|(n, _)| n == "@acme/widget").unwrap().1;
    let (s, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{widget}/versions/1.0.0/yank"),
        &xavier,
        Some(serde_json::json!({ "yanked": true })),
    );
    assert_eq!(s, 200, "{body}");

    let (s, body) = server.req(
        "DELETE",
        &format!("/api/v1/users/{xavier_id}"),
        &admin,
        None,
    );
    assert_eq!(s, 204, "{body}");
    assert_eq!(server.get("/api/v1/me", &xavier).0, 401, "their token went");

    for (name, id) in &ids {
        let (s, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
        assert_eq!(s, 200, "{shown}");
        let v = &shown["versions"][0];
        assert_eq!(
            v["published_by_username"], "xavier",
            "{name} forgot who published it: {v}"
        );
    }

    let (s, log) = server.get("/api/v1/audit", &admin);
    assert_eq!(s, 200, "{log}");
    let by: Vec<(&str, &str)> = log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["principal"] != "system:bootstrap")
        .map(|e| {
            (
                e["action"].as_str().unwrap_or_default(),
                e["username"].as_str().unwrap_or("<nobody>"),
            )
        })
        .collect();
    for want in [
        ("package.publish", "xavier"),
        ("package.yank", "xavier"),
        ("user.delete", "admin"),
        ("user.create", "admin"),
    ] {
        assert!(by.contains(&want), "{want:?} not in {by:?}");
    }
    assert!(
        by.iter().all(|(_, who)| *who != "<nobody>"),
        "an entry lost its actor: {by:?}"
    );
    assert_eq!(
        by.iter()
            .filter(|(a, w)| *a == "package.publish" && *w == "xavier")
            .count(),
        2,
        "{by:?}"
    );
    assert!(server.healthy());
}

/// Every refusal the REST API gives is `{"error": <a sentence>}`, which
/// is the one thing the UI shows. A missing package used to answer the
/// registry doors' bare-text `not found`, and the UI, finding no
/// `error` in it, showed the person `404 Not Found`. The class, not the
/// one route: a missing thing of each kind, a request with no
/// credential, a body that is not JSON, a method a route does not take
/// and a route that does not exist — each a JSON sentence, and none of
/// them a Basic challenge a browser would answer with a dialog.
#[test]
fn every_api_refusal_is_a_sentence_in_json() {
    let bucket = Minio::shared().bucket("people-json-errors");
    let server = spawn(&bucket.base_url, "people-json-errors");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["org:read"]);
    let (s, body) = server.req(
        "PUT",
        "/npm/@acme%2fwidget",
        &admin,
        Some(publish_doc("@acme/widget", "1.0.0", b"bytes")),
    );
    assert_eq!(s, 201, "{body}");
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let id = listed["packages"][0]["id"].as_str().unwrap().to_string();
    let nobody = "01nosuchthing0000000000000";
    let bearer = format!("Bearer {admin}");
    let as_admin: &[(&str, &str)] = &[
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
    ];
    let yank = br#"{"yanked": true}"#.as_slice();
    /// Method, path, headers, body, the status, and the sentence — or
    /// `""` where the words are the framework's and only their shape is
    /// ours.
    type Case<'a> = (
        &'a str,
        String,
        &'a [(&'a str, &'a str)],
        Option<&'a [u8]>,
        u16,
        &'a str,
    );
    let cases: Vec<Case> = vec![
        (
            "GET",
            format!("/api/v1/packages/{nobody}"),
            as_admin,
            None,
            404,
            "no such package",
        ),
        (
            "DELETE",
            format!("/api/v1/packages/{nobody}"),
            as_admin,
            None,
            404,
            "no such package",
        ),
        (
            "POST",
            format!("/api/v1/packages/{nobody}/versions/1.0.0/yank"),
            as_admin,
            Some(yank),
            404,
            "no such package",
        ),
        (
            "POST",
            format!("/api/v1/packages/{id}/versions/9.9.9/yank"),
            as_admin,
            Some(yank),
            404,
            "no such version",
        ),
        (
            "PATCH",
            format!("/api/v1/users/{nobody}"),
            as_admin,
            Some(br#"{"role": "reader"}"#),
            404,
            "no such person",
        ),
        (
            "DELETE",
            format!("/api/v1/users/{nobody}"),
            as_admin,
            None,
            404,
            "no such person",
        ),
        (
            "POST",
            format!("/api/v1/users/{nobody}/tokens"),
            as_admin,
            Some(br#"{"label": "x", "scopes": ["package:read"]}"#),
            404,
            "no such person",
        ),
        (
            "DELETE",
            format!("/api/v1/tokens/{nobody}"),
            as_admin,
            None,
            404,
            "no such token",
        ),
        (
            "DELETE",
            "/api/v1/policy/namespaces?ecosystem=npm&pattern=@never".into(),
            as_admin,
            None,
            404,
            "no such reserved namespace",
        ),
        (
            "DELETE",
            "/api/v1/findings?ecosystem=npm&name=never&version=1.0.0".into(),
            as_admin,
            None,
            404,
            "no such finding",
        ),
        (
            "GET",
            "/api/v1/no-such-route".into(),
            as_admin,
            None,
            404,
            "no such API route",
        ),
        // No credential at all: a sentence, and no Basic challenge.
        (
            "GET",
            "/api/v1/packages".into(),
            &[],
            None,
            401,
            "authentication required",
        ),
        // A body that is not JSON, and a method the route does not take:
        // the framework's own refusals, which are not ours to word but
        // are ours to wrap.
        (
            "POST",
            "/api/v1/users".into(),
            as_admin,
            Some(b"{not json"),
            400,
            "",
        ),
        ("PATCH", "/api/v1/packages".into(), as_admin, None, 405, ""),
    ];
    for (method, path, headers, body, status, want) in cases {
        let r = server.raw(method, &path, headers, body);
        assert_eq!(r.status, status, "{method} {path}: {}", r.text());
        assert!(
            r.header("content-type")
                .is_some_and(|c| c.starts_with("application/json")),
            "{method} {path} answered {:?}: {}",
            r.header("content-type"),
            r.text()
        );
        let said = r.json()["error"].as_str().unwrap_or_default().to_string();
        assert!(
            !said.trim().is_empty(),
            "{method} {path}: no sentence in {}",
            r.text()
        );
        if !want.is_empty() {
            assert_eq!(said, want, "{method} {path}");
        }
        assert!(
            r.header("www-authenticate").is_none(),
            "{method} {path}: the API challenged a browser"
        );
    }
    // A registry door keeps its own dialect: a bare 404 to a client that
    // authenticated, and a Basic challenge to one that did not.
    let r = server.raw(
        "GET",
        "/v2/acme/nothing/tags/list",
        &[("Authorization", &format!("Bearer {reader}"))],
        None,
    );
    assert_eq!(r.status, 404, "{}", r.text());
    let r = server.raw("GET", "/npm/@acme%2fwidget", &[], None);
    assert_eq!(r.status, 401);
    assert!(r.header("www-authenticate").is_some());
    assert!(server.healthy());
    assert_eq!(server.get("/api/v1/me", &reader).0, 200);
}

// ------------------------------------------------------ sign-in throttle

/// `Retry-After` on a throttled sign-in, as seconds, checked to be a
/// number inside the window.
fn retry_after(r: &skein_testkit::Reply) -> u64 {
    let v = r
        .header("retry-after")
        .unwrap_or_else(|| panic!("a 429 without Retry-After: {}", r.text()));
    let secs: u64 = v
        .parse()
        .unwrap_or_else(|_| panic!("Retry-After is not seconds: {v:?}"));
    assert!(
        (1..=900).contains(&secs),
        "Retry-After {secs} is outside the 15-minute window"
    );
    secs
}

/// Assert `r` is the throttle's refusal `who` (`for ada`, `from
/// 127.0.0.1`), naming the same wait as its `Retry-After`, and that it
/// signed nobody in.
fn assert_throttled(r: &skein_testkit::Reply, who: &str) {
    assert_eq!(r.status, 429, "{who}: {}", r.text());
    let secs = retry_after(r);
    // Seconds under a minute and a half, whole minutes rounded up past
    // it: a person is told a wait in the unit they would count it in.
    let wait = match secs {
        1 => "1 second".to_string(),
        s if s < 90 => format!("{s} seconds"),
        s => format!("{} minutes", s.div_ceil(60)),
    };
    assert_eq!(
        r.json()["error"],
        format!("too many failed sign-ins {who}; try again in {wait}"),
        "{}",
        r.text()
    );
    assert!(r.header("set-cookie").is_none(), "a refusal set a cookie");
}

/// `npm login`'s CouchDB exchange, as npm sends it.
fn npm_login(server: &Server, name: &str, password: &str) -> skein_testkit::Reply {
    server.raw(
        "PUT",
        &format!("/npm/-/user/org.couchdb.user:{name}"),
        &[("Content-Type", "application/json")],
        Some(
            serde_json::json!({
                "_id": format!("org.couchdb.user:{name}"),
                "name": name,
                "password": password,
                "type": "user",
            })
            .to_string()
            .as_bytes(),
        ),
    )
}

/// A sign-in from `xff`, if given, as a proxy would forward it.
fn login_via(
    server: &Server,
    xff: Option<&str>,
    username: &str,
    password: &str,
) -> skein_testkit::Reply {
    let mut h = vec![("Content-Type", "application/json"), ("x-skein-csrf", "1")];
    if let Some(x) = xff {
        h.push(("X-Forwarded-For", x));
    }
    server.raw(
        "POST",
        "/api/v1/session",
        &h,
        Some(
            serde_json::json!({ "username": username, "password": password })
                .to_string()
                .as_bytes(),
        ),
    )
}

/// Add a person who can sign in, and hand back an API token of theirs.
fn with_password(server: &Server, admin: &str, username: &str, password: &str) -> String {
    let (s, u) = server.req(
        "POST",
        "/api/v1/users",
        admin,
        Some(
            serde_json::json!({ "username": username, "role": "publisher", "password": password }),
        ),
    );
    assert_eq!(s, 201, "create {username}: {u}");
    let (s, t) = server.req(
        "POST",
        &format!("/api/v1/users/{}/tokens", u["id"].as_str().unwrap()),
        admin,
        Some(serde_json::json!({ "label": "ci", "scopes": ["package:read"] })),
    );
    assert_eq!(s, 201, "token for {username}: {t}");
    t["token"].as_str().unwrap().to_string()
}

/// The `session.throttled` entries in the audit log, newest first.
fn lockouts(server: &Server, admin: &str) -> Vec<serde_json::Value> {
    let (status, log) = server.get("/api/v1/audit", admin);
    assert_eq!(status, 200, "{log}");
    log["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "session.throttled")
        .map(|e| e["context"].clone())
        .collect()
}

const ADA_PW: &str = "ada's long password";
const BOB_PW: &str = "bob's long password";

/// Password sign-in is throttled by name. Each attempt costs an Argon2
/// hash, so without this anybody who can reach the sign-in form can
/// guess passwords at full speed and burn the server's CPU doing it.
///
/// Five wrong passwords for a name in fifteen minutes, and the next
/// attempt is refused **before** the password is looked at — the right
/// one included, which is the point: a guesser who lands on it while
/// locked must not be told. A name nobody holds locks the same way and
/// answers in the same words, so the lock says nothing about who has an
/// account. Both doors that take a password share one counter, so a
/// guesser cannot split their attempts between the UI and `npm login`.
/// A lockout is audited once, not once per refusal, and tokens — what
/// CI and every package manager use — are not touched by it.
#[test]
fn failed_sign_ins_lock_a_name_on_every_password_door() {
    let bucket = Minio::shared().bucket("people-throttle");
    let server = spawn(&bucket.base_url, "people-throttle");
    let admin = server.bootstrap("acme");
    let ada_token = with_password(&server, &admin, "ada", ADA_PW);
    with_password(&server, &admin, "bob", BOB_PW);
    with_password(&server, &admin, "carol", "carol's long password");
    // Every failure here is also one for 127.0.0.1, and twenty lock the
    // address: this test spends fifteen. A case added here that takes
    // it to twenty is testing the address limit, not the name.

    // Five ordinary refusals…
    for _ in 0..5 {
        let r = login(&server, "ada", "not ada's password");
        assert_eq!(r.status, 401, "{}", r.text());
        assert_eq!(r.json()["error"], "invalid username or password");
    }
    // …and then nothing is checked: a wrong password and the right one
    // get the same refusal, however the name is spelled, on either door.
    // Refusals do not count, so they do not stretch the lock either.
    //
    // A fresh lock is the full fifteen minutes, and says so in minutes:
    // "try again in 900 seconds" left a person doing arithmetic.
    let fresh = login(&server, "ada", ADA_PW);
    assert_eq!(
        fresh.json()["error"],
        "too many failed sign-ins for ada; try again in 15 minutes",
        "{}",
        fresh.text()
    );
    assert_throttled(&fresh, "for ada");
    for (name, pw) in [
        ("ada", "not ada's password"),
        ("ada", ADA_PW),
        ("ADA", ADA_PW),
        (" Ada ", ADA_PW),
    ] {
        assert_throttled(&login(&server, name, pw), "for ada");
    }
    assert_throttled(&npm_login(&server, "ada", ADA_PW), "for ada");

    // Somebody else signs in as usual, and ada's token still works.
    assert_eq!(login(&server, "bob", BOB_PW).status, 200);
    assert_eq!(server.get("/api/v1/me", &ada_token).0, 200);

    // A name nobody holds: the same five refusals, the same lock, the
    // same words.
    for _ in 0..5 {
        let r = login(&server, "nobody", ADA_PW);
        assert_eq!(r.status, 401, "{}", r.text());
        assert_eq!(r.json()["error"], "invalid username or password");
    }
    assert_throttled(&login(&server, "nobody", ADA_PW), "for nobody");
    assert_throttled(&npm_login(&server, "nobody", ADA_PW), "for nobody");

    // One counter across both doors: failures on either count on both.
    for door in ["ui", "npm", "ui", "npm", "npm"] {
        let r = match door {
            "ui" => login(&server, "carol", "a wrong password!!"),
            _ => npm_login(&server, "carol", "a wrong password!!"),
        };
        assert_eq!(r.status, 401, "carol via {door}: {}", r.text());
    }
    assert_throttled(
        &login(&server, "carol", "carol's long password"),
        "for carol",
    );
    assert_throttled(
        &npm_login(&server, "carol", "carol's long password"),
        "for carol",
    );

    // One audit entry per lockout, not one per refusal, and no password
    // in any of them.
    let locked = lockouts(&server, &admin);
    let mut names: Vec<&str> = locked
        .iter()
        .map(|c| c["username"].as_str().unwrap_or("?"))
        .collect();
    names.sort();
    assert_eq!(names, ["ada", "carol", "nobody"], "{locked:?}");
    assert!(locked.iter().all(|c| c["failures"] == 5), "{locked:?}");
    let (_, log) = server.get("/api/v1/audit", &admin);
    assert!(!log.to_string().contains(ADA_PW), "a password was audited");

    // The storm left the server serving, and an untouched person signs in.
    assert!(server.healthy());
    let r = login(&server, "bob", BOB_PW);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["username"], "bob");
}

/// Guesses sent all at once get no more tries than guesses sent one by
/// one. A limiter that checks the count, runs Argon2, and only then
/// records the failure admits every request that arrives while the
/// first few are still hashing — as many free guesses as the server can
/// hash in parallel. An attempt is counted when it is let in.
#[test]
fn guesses_sent_at_once_get_no_more_tries_than_guesses_sent_in_turn() {
    let bucket = Minio::shared().bucket("people-throttle");
    let server = spawn(&bucket.base_url, "people-throttle-burst");
    let admin = server.bootstrap("acme");
    with_password(&server, &admin, "ada", ADA_PW);
    let gate = std::sync::Barrier::new(16);
    let statuses: Vec<u16> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                let (server, gate) = (&server, &gate);
                s.spawn(move || {
                    gate.wait();
                    login(server, "ada", &format!("guess number {i:02}")).status
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let checked = statuses.iter().filter(|s| **s == 401).count();
    let refused = statuses.iter().filter(|s| **s == 429).count();
    assert_eq!(
        (checked, refused),
        (5, 11),
        "sixteen guesses at once: {statuses:?}"
    );
    let locked = lockouts(&server, &admin);
    assert_eq!(locked.len(), 1, "one lockout, one entry: {locked:?}");
    assert_eq!(locked[0]["username"], "ada", "{locked:?}");
    assert!(server.healthy());
    assert_eq!(server.get("/api/v1/me", &admin).0, 200);
}

/// Changing your password checks the current one — the same Argon2, and
/// a guess somebody holding a stolen session could otherwise make at
/// full speed. It counts on the same name as signing in.
#[test]
fn a_wrong_current_password_counts_towards_the_lock() {
    let bucket = Minio::shared().bucket("people-throttle");
    let server = spawn(&bucket.base_url, "people-throttle-pw");
    let admin = server.bootstrap("acme");
    with_password(&server, &admin, "ada", ADA_PW);
    let r = login(&server, "ada", ADA_PW);
    assert_eq!(r.status, 200, "{}", r.text());
    let cookie = session_cookie(&r);
    let change = |current: &str| {
        server.raw(
            "PUT",
            "/api/v1/me/password",
            &[
                ("Cookie", cookie.as_str()),
                ("Content-Type", "application/json"),
                ("x-skein-csrf", "1"),
            ],
            Some(
                serde_json::json!({ "current": current, "new": "a brand new password" })
                    .to_string()
                    .as_bytes(),
            ),
        )
    };
    for _ in 0..5 {
        let r = change("not ada's password");
        assert_eq!(r.status, 403, "{}", r.text());
        assert_eq!(r.json()["error"], "the current password is wrong");
    }
    assert_throttled(&change(ADA_PW), "for ada");
    assert_throttled(&login(&server, "ada", ADA_PW), "for ada");
    // The lock refuses password checks; it does not end the session.
    let me = server.raw("GET", "/api/v1/me", &[("Cookie", cookie.as_str())], None);
    assert_eq!(me.status, 200, "{}", me.text());
    assert!(server.healthy());
}

/// The address limit catches the other shape of guessing: one password
/// tried against many names. By default the address is the TCP peer's,
/// and an `X-Forwarded-For` a client wrote itself is ignored — or an
/// attacker could spread their attempts over as many made-up addresses
/// as they liked.
#[test]
fn the_address_limit_counts_the_peer_and_ignores_a_forged_forwarded_for() {
    let bucket = Minio::shared().bucket("people-throttle");
    let server = spawn(&bucket.base_url, "people-throttle-peer");
    let admin = server.bootstrap("acme");
    with_password(&server, &admin, "ada", ADA_PW);
    // Twenty names, each tried once, each "from" a different address.
    for i in 0..20 {
        let xff = format!("203.0.113.{i}");
        let r = login_via(&server, Some(&xff), &format!("guess{i}"), ADA_PW);
        assert_eq!(r.status, 401, "attempt {i}: {}", r.text());
    }
    // The peer is what was counted: the next sign-in from it is refused,
    // whoever it names and wherever it claims to come from.
    assert_throttled(
        &login_via(&server, Some("198.51.100.1"), "ada", ADA_PW),
        "from 127.0.0.1",
    );
    assert_throttled(&npm_login(&server, "ada", ADA_PW), "from 127.0.0.1");
    let locked = lockouts(&server, &admin);
    assert_eq!(locked.len(), 1, "{locked:?}");
    assert_eq!(locked[0]["address"], "127.0.0.1", "{locked:?}");
    assert_eq!(locked[0]["failures"], 20, "{locked:?}");
    assert!(server.healthy());
    assert_eq!(server.get("/api/v1/me", &admin).0, 200);
}

/// Behind a reverse proxy every request arrives from the proxy, so the
/// operator says so with `SKEIN_TRUST_PROXY_HEADERS=true`, and the
/// address is the **right-most** `X-Forwarded-For` entry: the one the
/// proxy appended. Everything to its left the client wrote, and changing
/// it buys nothing.
#[test]
fn behind_a_trusted_proxy_the_address_is_the_one_the_proxy_appended() {
    let bucket = Minio::shared().bucket("people-throttle");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("people-throttle-proxy")
        .env("SKEIN_TRUST_PROXY_HEADERS", "true")
        .start();
    let admin = server.bootstrap("acme");
    with_password(&server, &admin, "ada", ADA_PW);
    for i in 0..20 {
        let xff = format!("10.0.{i}.1, 192.0.2.{i}, 198.51.100.7");
        let r = login_via(&server, Some(&xff), &format!("guess{i}"), ADA_PW);
        assert_eq!(r.status, 401, "attempt {i}: {}", r.text());
    }
    assert_throttled(
        &login_via(&server, Some("10.9.9.9, 198.51.100.7"), "ada", ADA_PW),
        "from 198.51.100.7",
    );
    // Another client of the same proxy is untouched, and so is a
    // request that reached Skein without passing through it.
    let r = login_via(&server, Some("198.51.100.8"), "ada", ADA_PW);
    assert_eq!(r.status, 200, "{}", r.text());
    let r = login_via(&server, None, "ada", ADA_PW);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(server.healthy());
}
