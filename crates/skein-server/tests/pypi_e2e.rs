//! PyPI end to end: twine's form post and pip's Simple API against a
//! real server, a real bucket and a real Postgres.
//!
//! `pypi.rs` is pure and is hammered in its own unit tests. What those
//! cannot show is the loop that actually matters: that the page pip
//! reads names links pip can *follow*, that the digest on each link is
//! the digest of the bytes behind it, and that `twine upload dist/*` —
//! two requests, one version — lands as one release.
//!
//! The body below is twine's, built from the fields it sends, and the
//! credentials are sent the way twine and pip send them: HTTP Basic,
//! with the token as the password. What a real `twine` and a real `pip`
//! do against a real server is the job of `clients_e2e.rs`, which drives
//! the actual clients; a body built here can only ever confirm what we
//! already believe.

mod common;

use common::{b64, spawn};
use skein_testkit::{Minio, Server};

fn base(server: &Server) -> String {
    format!("{}/pypi", server.base)
}

const BOUNDARY: &str = "----SkeinBoundary";

/// twine's own upload body, field for field.
fn twine_body(
    name: &str,
    version: &str,
    filename: &str,
    content: &[u8],
    classifiers: &[&str],
    sha256: Option<&str>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |k: &str, v: &[u8]| {
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        out.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{k}\"\r\n\r\n").as_bytes(),
        );
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    };
    field(":action", b"file_upload");
    field("protocol_version", b"1");
    field("name", name.as_bytes());
    field("version", version.as_bytes());
    field("filetype", b"bdist_wheel");
    field("metadata_version", b"2.1");
    for c in classifiers {
        field("classifiers", c.as_bytes());
    }
    if let Some(s) = sha256 {
        field("sha256_digest", s.as_bytes());
    }
    out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
    out.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"content\"; filename=\"{filename}\"\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(content);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    out
}

/// What twine sends: `__token__` and the token as the password.
fn twine_auth(token: &str) -> String {
    format!("Basic {}", b64(format!("__token__:{token}").as_bytes()))
}

/// What pip sends for the `skein:<token>@` in its index URL.
fn pip_auth(token: &str) -> String {
    format!("Basic {}", b64(format!("skein:{token}").as_bytes()))
}

/// What came back from an upload, reason phrase included — the reason
/// phrase is the part twine prints.
struct Answer {
    status: u16,
    reason: String,
    body: String,
}

fn post(url: &str, auth: Option<&str>, content_type: &str, body: &[u8]) -> Answer {
    let mut req = ureq::post(url).set("Content-Type", content_type);
    if let Some(a) = auth {
        req = req.set("Authorization", a);
    }
    match req.send_bytes(body) {
        Ok(r) | Err(ureq::Error::Status(_, r)) => Answer {
            status: r.status(),
            reason: r.status_text().to_string(),
            body: r.into_string().unwrap_or_default(),
        },
        Err(e) => panic!("transport {url}: {e}"),
    }
}

fn upload_as(url: &str, auth: &str, body: &[u8]) -> Answer {
    post(
        url,
        Some(auth),
        &format!("multipart/form-data; boundary={BOUNDARY}"),
        body,
    )
}

fn upload(url: &str, token: &str, body: &[u8]) -> (u16, String) {
    let a = upload_as(url, &twine_auth(token), body);
    (a.status, a.body)
}

fn get_raw(url: &str, token: &str) -> (u16, Vec<u8>) {
    let r = skein_testkit::server::send("GET", url, &[("Authorization", &pip_auth(token))], None);
    (r.status, r.body)
}

fn fetch_page(url: &str, token: &str) -> String {
    let (status, body) = get_raw(url, token);
    assert_eq!(status, 200, "{url}");
    String::from_utf8(body).expect("html is utf-8")
}

/// Resolve `href` against `page`, the way a client does. Enough of RFC
/// 3986 for the three shapes a simple index can carry: absolute,
/// path-absolute, and relative.
fn resolve(page: &str, href: &str) -> String {
    if href.starts_with("http://") || href.starts_with("https://") {
        return href.to_string();
    }
    let (scheme, rest) = page.split_once("://").expect("an absolute page url");
    let authority = rest.split('/').next().unwrap_or_default();
    if let Some(path) = href.strip_prefix('/') {
        return format!("{scheme}://{authority}/{path}");
    }
    let dir = page.rsplit_once('/').map(|(d, _)| d).unwrap_or(page);
    format!("{dir}/{href}")
}

/// Every `href` on a page, in order.
fn hrefs(page: &str) -> Vec<String> {
    page.split("<a href=\"")
        .skip(1)
        .filter_map(|s| s.split('"').next())
        .map(str::to_string)
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn package_id(server: &Server, admin: &str) -> String {
    let (_, listed) = server.get("/api/v1/packages?ecosystem=pypi", admin);
    listed["packages"][0]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("no package: {listed}"))
        .to_string()
}

/// The whole loop: twine uploads, pip reads the index, follows a link
/// it found there, and gets the bytes the fragment promised.
#[test]
fn a_wheel_uploads_and_the_index_names_a_link_that_resolves() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-roundtrip");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let wheel = b"PK not really a wheel, near enough for a test";
    // twine sends the name as the author wrote it; PEP 503 folds it.
    let (status, body) = upload(
        &format!("{b}/"),
        &admin,
        &twine_body(
            "Acme.Widget",
            "1.4.0",
            "acme_widget-1.4.0-py3-none-any.whl",
            wheel,
            &["License :: OSI Approved :: MIT License"],
            Some(&sha256_hex(wheel)),
        ),
    );
    assert_eq!(status, 200, "uploading: {body}");

    // pip asks for the folded name, which is the only name it knows.
    let page_url = format!("{b}/simple/acme-widget/");
    let page = fetch_page(&page_url, &admin);
    assert!(
        page.contains("acme_widget-1.4.0-py3-none-any.whl"),
        "{page}"
    );
    // The fragment is what pip verifies the download against. An index
    // without it is one where a corrupted download installs.
    assert!(
        page.contains(&format!("#sha256={}", sha256_hex(wheel))),
        "{page}"
    );

    // Follow the link the way pip does: resolve the `href` against the
    // page's own URL, rather than rebuilding the file URL by hand.
    // Building it by hand is what made an earlier version of this test
    // pass against a page whose links pip could not have followed at
    // all — the href was a bare filename, which resolves inside
    // `/simple/<name>/` and 404s.
    let links = hrefs(&page);
    assert_eq!(links.len(), 1, "{page}");
    let url = resolve(&page_url, &links[0]);
    let (status, got) = get_raw(url.split('#').next().unwrap(), &admin);
    assert_eq!(status, 200, "following {}", links[0]);
    assert_eq!(
        got, wheel,
        "the bytes behind the link are not the ones we sent"
    );

    // And the root index lists the project under its folded name.
    let root = fetch_page(&format!("{b}/simple/"), &admin);
    assert!(
        root.contains("<a href=\"acme-widget/\">acme-widget</a>"),
        "{root}"
    );

    // The licence came off the trove classifier, which is a fixed
    // vocabulary and therefore an exact mapping rather than a guess —
    // and the version remembers who published it, and with what.
    let id = package_id(&server, &admin);
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(shown["ecosystem"], "pypi", "{shown}");
    let v = &shown["versions"][0];
    assert_eq!(v["license"], "MIT", "{shown}");
    assert_eq!(v["license_source"], "declared", "{shown}");
    assert_eq!(v["published_by_username"], "admin", "{v}");
    assert!(v["published_by_token"].is_string(), "{v}");

    let (_, log) = server.get("/api/v1/audit", &admin);
    assert!(
        log["entries"].as_array().unwrap().iter().any(|e| {
            e["action"] == "package.publish"
                && e["context"]["ecosystem"] == "pypi"
                && e["context"]["filename"] == "acme_widget-1.4.0-py3-none-any.whl"
        }),
        "the upload is not in the audit log: {log}"
    );
    assert!(server.healthy());
}

/// pip resolves a link relative to the page it read. Served at
/// `…/simple/name` without the slash, every filename would resolve one
/// directory up and every download would 404 — so the slash-less form
/// redirects rather than serving a page whose links do not work. The
/// root index links to projects relatively too, and `/simple` redirects
/// for the same reason: served there, `acme-widget/` resolves to
/// `/pypi/acme-widget/`, which is nothing.
#[test]
fn the_project_page_redirects_to_its_trailing_slash() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-slash");
    let admin = server.bootstrap("acme");

    // `raw` never follows a redirect, because the *redirect itself* is
    // the thing under test: following it would make this pass against a
    // door that served the page at both addresses and broke every
    // relative link at one of them.
    for (from, to) in [
        ("/pypi/simple/acme-widget", "/pypi/simple/acme-widget/"),
        ("/pypi/simple", "/pypi/simple/"),
    ] {
        let r = server.raw("GET", from, &[("Authorization", &pip_auth(&admin))], None);
        assert_eq!(r.status, 301, "{from} is not a redirect");
        assert_eq!(r.header("location"), Some(to), "{from}");
    }
}

/// `twine upload dist/*` posts the sdist and the wheel separately. Two
/// requests, one release — and a second upload of the same filename is
/// refused rather than overwriting bytes somebody has installed.
#[test]
fn an_sdist_and_a_wheel_are_one_release_and_neither_can_be_replaced() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-two-files");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    for (filename, body) in [
        ("acme_widget-1.4.0.tar.gz", b"the sdist" as &[u8]),
        ("acme_widget-1.4.0-py3-none-any.whl", b"the wheel"),
    ] {
        let (status, err) = upload(
            &b,
            &admin,
            &twine_body("acme-widget", "1.4.0", filename, body, &[], None),
        );
        assert_eq!(status, 200, "uploading {filename}: {err}");
    }

    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(1));
    let id = package_id(&server, &admin);
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(
        shown["versions"].as_array().map(|a| a.len()),
        Some(1),
        "two files became two versions: {shown}"
    );
    let page = fetch_page(&format!("{b}/simple/acme-widget/"), &admin);
    assert_eq!(page.matches("<a href=").count(), 2, "{page}");

    // Re-uploading one of them is refused, and the original is intact.
    let (status, err) = upload(
        &b,
        &admin,
        &twine_body(
            "acme-widget",
            "1.4.0",
            "acme_widget-1.4.0.tar.gz",
            b"something else",
            &[],
            None,
        ),
    );
    assert_eq!(status, 409, "a re-upload was accepted: {err}");
    let (status, got) = get_raw(
        &format!("{b}/files/acme-widget/acme_widget-1.4.0.tar.gz"),
        &admin,
    );
    assert_eq!(status, 200);
    assert_eq!(got, b"the sdist");
    assert!(server.healthy());
}

/// A file is fetched by project and filename — `/files/<name>/<file>`,
/// no version in the URL — so a filename names one file across the
/// whole project, not one per version.
///
/// It did not: the database holds a filename unique only within a
/// version, and a `2.0.0` upload carrying `1.0.0`'s wheel filename was
/// accepted, listed beside the original with a different digest, and
/// served *instead of* the original at the original's URL. A published
/// file's bytes changed, and every lockfile pinning its digest broke.
#[test]
fn a_filename_names_one_file_across_every_version() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-one-name");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let original = b"the 1.0.0 wheel somebody reviewed";
    let (status, err) = upload(
        &b,
        &admin,
        &twine_body(
            "acme-widget",
            "1.0.0",
            "acme_widget-1.0.0-py3-none-any.whl",
            original,
            &[],
            None,
        ),
    );
    assert_eq!(status, 200, "{err}");

    let a = upload_as(
        &b,
        &twine_auth(&admin),
        &twine_body(
            "acme-widget",
            "2.0.0",
            "acme_widget-1.0.0-py3-none-any.whl",
            b"different bytes under the same name",
            &[],
            None,
        ),
    );
    assert_eq!(a.status, 409, "a second file took the name: {}", a.body);
    assert!(a.reason.contains("already uploaded"), "{}", a.reason);

    // The URL still answers with the original, the page names it once,
    // and the refusal left no empty 2.0.0 behind for a resolver to meet.
    let (status, got) = get_raw(
        &format!("{b}/files/acme-widget/acme_widget-1.0.0-py3-none-any.whl"),
        &admin,
    );
    assert_eq!(status, 200);
    assert_eq!(got, original, "the original's URL serves other bytes");
    let page = fetch_page(&format!("{b}/simple/acme-widget/"), &admin);
    assert_eq!(page.matches("<a href=").count(), 1, "{page}");
    assert!(
        page.contains(&format!("#sha256={}", sha256_hex(original))),
        "{page}"
    );
    let id = package_id(&server, &admin);
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(
        shown["versions"].as_array().map(|a| a.len()),
        Some(1),
        "{shown}"
    );
    assert!(server.healthy());
}

/// twine sends its own SHA-256 of the bytes it meant to send. A
/// mismatch is a truncated or altered upload, and storing it anyway
/// would mean the index advertises a digest for bytes nobody chose.
#[test]
fn an_upload_that_does_not_match_its_own_digest_is_refused() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-digest");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let a = upload_as(
        &b,
        &twine_auth(&admin),
        &twine_body(
            "acme-widget",
            "1.4.0",
            "acme_widget-1.4.0-py3-none-any.whl",
            b"the actual bytes",
            &[],
            Some(&sha256_hex(b"quite different bytes")),
        ),
    );
    assert_eq!(a.status, 400, "{}", a.body);
    assert!(a.body.contains("SHA-256"), "{}", a.body);
    assert!(a.reason.contains("SHA-256"), "{}", a.reason);
    // Nothing was created on the way to refusing.
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(0));
    assert!(server.healthy());
}

/// twine prints the **reason phrase** of a refusal and shows the body
/// only under `--verbose`; pip does the same for an index it cannot
/// read. So the sentence has to be in the status line, or a person who
/// may not publish is told "Forbidden" and nothing else.
///
/// It was not: the refusals were written as a body under the canonical
/// phrase, and a reader's `twine upload` printed `403 Forbidden` twice.
#[test]
fn a_refusal_carries_its_sentence_in_the_reason_phrase_twine_prints() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-reason");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:read"]);
    let b = base(&server);
    let body = twine_body(
        "acme-widget",
        "1.0.0",
        "acme_widget-1.0.0-py3-none-any.whl",
        b"wheel",
        &[],
        None,
    );

    // A reader: their role is the limit.
    let a = upload_as(&b, &twine_auth(&reader), &body);
    assert_eq!(a.status, 403, "{}", a.body);
    assert!(
        a.reason.contains("rita is a reader"),
        "twine would print {:?}",
        a.reason
    );
    assert!(a.body.contains("rita is a reader"), "{}", a.body);

    // A publisher with a read-only token: the token is the limit, and
    // the fix is different, so the sentence says which.
    let a = upload_as(&b, &twine_auth(&ci), &body);
    assert_eq!(a.status, 403, "{}", a.body);
    assert!(
        a.reason
            .contains("this token was not minted with package:write"),
        "twine would print {:?}",
        a.reason
    );

    // An upload twine made wrong, and one that is already there.
    let a = post(&b, Some(&twine_auth(&admin)), "application/json", b"{}");
    assert_eq!(a.status, 400);
    assert!(a.reason.contains("multipart/form-data"), "{}", a.reason);
    assert_eq!(upload(&b, &admin, &body).0, 200);
    let a = upload_as(&b, &twine_auth(&admin), &body);
    assert_eq!(a.status, 409);
    assert!(
        a.reason
            .contains("acme_widget-1.0.0-py3-none-any.whl is already uploaded"),
        "{}",
        a.reason
    );
    assert!(server.healthy());
}

/// Nothing is public. Without a credential that authenticates, every
/// path under the door answers with a challenge and nothing else — not
/// an empty page for an absent project, not a page for a present one —
/// so nobody learns which names are taken, or even whether PyPI is
/// switched on, without saying who they are.
#[test]
fn nothing_is_answered_to_somebody_who_has_not_said_who_they_are() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-anonymous");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    assert_eq!(
        upload(
            &b,
            &admin,
            &twine_body(
                "acme-secret",
                "1.0.0",
                "acme_secret-1.0.0.whl",
                b"private",
                &[],
                None
            )
        )
        .0,
        200
    );

    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    let credentials = [
        None,
        Some(twine_auth(forged)),
        Some(format!("Bearer {forged}")),
        Some("Bearer nonsense".to_string()),
        Some("Basic bm90IGJhc2U2NA==".to_string()),
    ];
    let check = |server: &Server| {
        for path in [
            "/pypi/simple/",
            "/pypi/simple/acme-secret/",
            "/pypi/simple/never-published/",
            "/pypi/files/acme-secret/acme_secret-1.0.0.whl",
            "/pypi/nonsense",
        ] {
            for auth in &credentials {
                let headers: Vec<(&str, &str)> = auth
                    .as_deref()
                    .map(|a| vec![("Authorization", a)])
                    .unwrap_or_default();
                let r = server.raw("GET", path, &headers, None);
                assert_eq!(r.status, 401, "GET {path} with {auth:?}");
                assert!(
                    r.header("www-authenticate")
                        .is_some_and(|v| v.starts_with("Basic")),
                    "pip cannot learn it needs credentials: {path}"
                );
            }
        }
        for path in ["/pypi", "/pypi/"] {
            for auth in &credentials {
                let a = post(
                    &server.url(path),
                    auth.as_deref(),
                    &format!("multipart/form-data; boundary={BOUNDARY}"),
                    &twine_body(
                        "acme-secret",
                        "2.0.0",
                        "acme_secret-2.0.0.whl",
                        b"x",
                        &[],
                        None,
                    ),
                );
                assert_eq!(a.status, 401, "POST {path} with {auth:?}: {}", a.body);
            }
        }
    };
    check(&server);

    // Switch PyPI off: a stranger's answer does not change, so it cannot
    // be used to learn which ecosystems are on.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "pypi", "mode": "off" })),
    );
    assert_eq!(status, 200);
    check(&server);
    assert!(server.healthy());
}

/// Every negative case on this door, each ending by proving the server
/// is still serving and what was published is untouched.
#[test]
fn hostile_uploads_are_refused_and_the_server_keeps_serving() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-hostile");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let b = base(&server);

    let ours = b"ours";
    assert_eq!(
        upload(
            &b,
            &admin,
            &twine_body(
                "acme-widget",
                "1.0.0",
                "acme_widget-1.0.0.whl",
                ours,
                &[],
                None
            )
        )
        .0,
        200
    );

    // A filename that could escape its own path, be read as markup in a
    // page other people's tools parse, or break the link pip follows.
    for bad in [
        "../../etc/passwd",
        "a/b.whl",
        "<script>.whl",
        ".hidden",
        "x#y.whl",
        "x%2e.whl",
        "x?y.whl",
    ] {
        let (status, _) = upload(
            &b,
            &admin,
            &twine_body("acme-widget", "9.9.9", bad, b"x", &[], None),
        );
        assert_eq!(status, 400, "{bad:?} was accepted");
    }

    // Not multipart at all.
    let a = post(&b, Some(&twine_auth(&admin)), "application/json", b"{}");
    assert_eq!(a.status, 400, "{}", a.body);

    // A reader reads, and cannot write — told so, not shown a 404.
    let (status, _) = get_raw(&format!("{b}/simple/acme-widget/"), &reader);
    assert_eq!(status, 200);
    let a = upload_as(
        &b,
        &twine_auth(&reader),
        &twine_body(
            "acme-widget",
            "2.0.0",
            "acme_widget-2.0.0.whl",
            b"theirs",
            &[],
            None,
        ),
    );
    assert_eq!(a.status, 403, "{}", a.body);
    assert!(a.body.contains("rita is a reader"), "{}", a.body);

    // A forged token is a 401 with a challenge, not a 404 and not a 403:
    // it proved nothing, so it learns nothing.
    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    let a = upload_as(
        &b,
        &twine_auth(forged),
        &twine_body(
            "acme-widget",
            "2.0.0",
            "acme_widget-2.0.0.whl",
            b"x",
            &[],
            None,
        ),
    );
    assert_eq!(a.status, 401);

    // No credential gets a challenge, not a 404: a client that reads
    // "not found" never tries to authenticate.
    let r = server.raw("GET", "/pypi/simple/", &[], None);
    assert_eq!(r.status, 401);
    assert!(r.header("www-authenticate").is_some());

    // …and ours is untouched by any of it.
    let (status, got) = get_raw(
        &format!("{b}/files/acme-widget/acme_widget-1.0.0.whl"),
        &admin,
    );
    assert_eq!(status, 200);
    assert_eq!(got, ours);
    let page = fetch_page(&format!("{b}/simple/acme-widget/"), &admin);
    assert_eq!(page.matches("<a href=").count(), 1, "{page}");
    assert!(server.healthy());
}

/// An index for a project nobody has published is an **empty page**,
/// not a 404. PEP 503 permits either, and pip has read a 404 from an
/// index as "this index is broken" — which sends somebody to debug
/// their `pip.conf` over a package that simply is not there.
#[test]
fn an_unknown_project_is_an_empty_page_rather_than_a_404() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-empty");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let page = fetch_page(&format!("{b}/simple/never-published/"), &admin);
    assert!(page.contains("never-published"), "{page}");
    assert!(!page.contains("<a href="), "{page}");
    // A file under it is a plain 404, which is what pip expects when a
    // link it followed has gone.
    assert_eq!(
        get_raw(&format!("{b}/files/never-published/x.whl"), &admin).0,
        404
    );
    assert!(server.healthy());
}

/// The paths and absences pip meets that the happy path does not, and
/// the two refusals an upload can earn on its own input.
#[test]
fn absences_and_malformed_uploads_answer_for_themselves() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-absent");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    // A path under the prefix that is none of the three shapes.
    assert_eq!(get_raw(&format!("{b}/nonsense"), &admin).0, 404);
    assert_eq!(get_raw(&format!("{b}/simple/a/b/c"), &admin).0, 404);

    assert_eq!(
        upload(
            &b,
            &admin,
            &twine_body(
                "acme-widget",
                "1.0.0",
                "acme_widget-1.0.0.whl",
                b"wheel",
                &[],
                None
            )
        )
        .0,
        200
    );
    // The project exists; that file does not. A 404 here is what pip
    // expects when a link it followed has gone.
    assert_eq!(
        get_raw(&format!("{b}/files/acme-widget/never-uploaded.whl"), &admin).0,
        404
    );

    // A version that cannot be stored. twine reports the sentence.
    let long_version = "1.".to_string() + &"0".repeat(200);
    let (status, body) = upload(
        &b,
        &admin,
        &twine_body(
            "acme-widget",
            &long_version,
            "acme_widget-x.whl",
            b"x",
            &[],
            None,
        ),
    );
    assert_eq!(status, 400, "an unstorable version was accepted: {body}");
    assert!(body.contains("version"), "{body}");

    // A project name that cannot be stored at all.
    let (status, body) = upload(
        &b,
        &admin,
        &twine_body("../escape", "1.0.0", "escape-1.0.0.whl", b"x", &[], None),
    );
    assert_eq!(
        status, 400,
        "a traversing project name was accepted: {body}"
    );

    // The root index lists what is there and nothing that is not.
    let root = fetch_page(&format!("{b}/simple/"), &admin);
    assert!(root.contains("acme-widget"), "{root}");
    assert!(
        !root.contains("escape"),
        "a refused upload was listed: {root}"
    );
    assert!(server.healthy());
}

/// A registry that has not switched PyPI on answers nothing at all to
/// somebody who has authenticated: 404 everywhere, the same answer as a
/// project that is not there, and no upload lands.
#[test]
fn a_registry_nobody_enabled_answers_for_nothing() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-off");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    // The bootstrap switched it on; switch it off.
    let (_, ecos) = server.get("/api/v1/ecosystems", &admin);
    assert!(
        ecos["ecosystems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["ecosystem"] == "pypi" && e["mode"] == "private"),
        "the bootstrap did not switch PyPI on: {ecos}"
    );
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "pypi", "mode": "off" })),
    );
    assert_eq!(status, 200);

    for url in [
        format!("{b}/simple/"),
        format!("{b}/simple/acme-widget/"),
        format!("{b}/files/acme-widget/x.whl"),
    ] {
        assert_eq!(get_raw(&url, &admin).0, 404, "{url}");
    }
    for url in [b.clone(), format!("{b}/")] {
        let (status, _) = upload(
            &url,
            &admin,
            &twine_body(
                "acme-widget",
                "1.0.0",
                "acme_widget-1.0.0.whl",
                b"x",
                &[],
                None,
            ),
        );
        assert_eq!(status, 404, "uploaded into an ecosystem nobody switched on");
    }
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(0));
    assert!(server.healthy());
}

/// PEP 592. A yanked release stays on the page — a lockfile that pins
/// it must keep installing — and carries `data-yanked`, which is the
/// only thing that stops pip choosing it for an unpinned install.
///
/// The page used to list a yanked release exactly like any other, so
/// yanking did nothing at all to pip: the newest release is the one it
/// picks, and the release somebody yanked because it was broken went on
/// being installed everywhere.
#[test]
fn a_yanked_release_is_marked_on_the_index_and_still_downloads() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-yank");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    for v in ["1.0.0", "1.1.0"] {
        let (status, err) = upload(
            &b,
            &admin,
            &twine_body(
                "acme-widget",
                v,
                &format!("acme_widget-{v}-py3-none-any.whl"),
                v.as_bytes(),
                &[],
                None,
            ),
        );
        assert_eq!(status, 200, "{err}");
    }
    let id = package_id(&server, &admin);
    let (status, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.1.0/yank"),
        &admin,
        Some(serde_json::json!({ "yanked": true, "reason": "breaks <imports> & more" })),
    );
    assert_eq!(status, 200, "{body}");

    let page_url = format!("{b}/simple/acme-widget/");
    let page = fetch_page(&page_url, &admin);
    let line = |f: &str| {
        page.lines()
            .find(|l| l.contains(&format!(">{f}</a>")))
            .unwrap_or_else(|| panic!("{f} is not on the page: {page}"))
            .to_string()
    };
    assert!(
        line("acme_widget-1.1.0-py3-none-any.whl")
            .contains("data-yanked=\"breaks &lt;imports&gt; &amp; more\""),
        "pip cannot tell 1.1.0 is yanked: {page}"
    );
    assert!(
        !line("acme_widget-1.0.0-py3-none-any.whl").contains("data-yanked"),
        "{page}"
    );

    // Still there for whoever pinned it.
    let href = hrefs(&page)
        .into_iter()
        .find(|h| h.contains("1.1.0"))
        .expect("the yanked file's link");
    let (status, got) = get_raw(resolve(&page_url, &href).split('#').next().unwrap(), &admin);
    assert_eq!(status, 200, "yanking broke every pinned install");
    assert_eq!(got, b"1.1.0");

    // Un-yanking takes the mark away again.
    let (status, _) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/1.1.0/yank"),
        &admin,
        Some(serde_json::json!({ "yanked": false })),
    );
    assert_eq!(status, 200);
    let after = fetch_page(&page_url, &admin);
    assert!(!after.contains("data-yanked"), "{after}");
}

/// The root index is every project, not the first page of them.
///
/// `packages::list` answers a page of at most two hundred and clamps a
/// larger ask without saying so; the root index asked for a thousand in
/// one call and so stopped, silently, at two hundred.
#[test]
fn the_root_index_lists_every_project_not_just_the_first_page() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-root-pages");
    let admin = server.bootstrap("acme");

    // Rows straight into the database: what is under test is the
    // listing, and 450 uploads would be a slow way to write them.
    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let now = skein_control::ids::now_ms();
    let names: Vec<String> = (0..450).map(|i| format!("proj-{i:04}")).collect();
    for n in &names {
        skein_control::packages::ensure(
            &db,
            &org.id,
            skein_control::packages::Ecosystem::Pypi,
            n,
            skein_control::packages::ORIGIN_LOCAL,
            now,
        )
        .expect("a package row");
    }

    let root = fetch_page(&format!("{}/simple/", base(&server)), &admin);
    let listed = hrefs(&root);
    let want: Vec<String> = names.iter().map(|n| format!("{n}/")).collect();
    assert_eq!(listed.len(), names.len(), "{} listed", listed.len());
    assert_eq!(
        listed, want,
        "the root is not every project, once, in order"
    );
    assert!(server.healthy());
}

/// A wheel larger than axum's 2 MiB default body limit uploads: the
/// route raises the limit to the artifact ceiling, and a door that
/// forgot would refuse an ordinary package with a message about
/// nothing we wrote.
#[test]
fn a_wheel_larger_than_the_default_body_limit_uploads() {
    let bucket = Minio::shared().bucket("pypi-e2e");
    let server = spawn(&bucket.base_url, "pypi-limit");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let wheel = vec![7u8; 3 * 1024 * 1024];
    for (url, v) in [(b.clone(), "1.0.0"), (format!("{b}/"), "1.0.1")] {
        let (status, body) = upload(
            &url,
            &admin,
            &twine_body(
                "big",
                v,
                &format!("big-{v}-py3-none-any.whl"),
                &wheel,
                &[],
                Some(&sha256_hex(&wheel)),
            ),
        );
        assert_eq!(status, 200, "{url}: {body}");
        let (status, got) = get_raw(&format!("{b}/files/big/big-{v}-py3-none-any.whl"), &admin);
        assert_eq!(status, 200);
        assert_eq!(got.len(), wheel.len());
    }
    assert!(server.healthy());
}
