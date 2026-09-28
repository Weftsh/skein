//! Maven end to end: `mvn deploy`'s request sequence against a real
//! server, a real bucket and a real Postgres.
//!
//! `maven.rs` is pure and is argued with in its own unit tests. What
//! those cannot show is the thing Maven's protocol makes easy to get
//! wrong: a release is **many requests**, in an order nobody promises,
//! and each of them has to accrete onto one version without ever
//! overwriting a file that is already there.
//!
//! The request sequence below is `mvn deploy`'s, taken from what the
//! wagon actually sends. What a real `mvn` does against a real server
//! is the job of `clients_e2e.rs`, which drives the actual client; a
//! hand-built sequence can only ever confirm what we already believe —
//! and did: every refusal here was checked by reading the body, which
//! is the one part of a response Maven never prints.

mod common;

use common::{b64, spawn};
use skein_testkit::server::{send, Reply};
use skein_testkit::{Minio, Server};

const POM: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId>
  <artifactId>widget</artifactId>
  <version>1.4.0</version>
  <licenses>
    <license>
      <name>Apache License, Version 2.0</name>
      <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
    </license>
  </licenses>
</project>
"#;

/// A raw PUT with a bearer token, because `Server::req` sends JSON and
/// a jar is not JSON.
fn put_raw(url: &str, token: &str, body: &[u8]) -> (u16, String) {
    let r = send(
        "PUT",
        url,
        &[
            ("Authorization", &format!("Bearer {token}")),
            ("Content-Type", "application/octet-stream"),
        ],
        Some(body),
    );
    (r.status, r.text())
}

fn get_raw(url: &str, token: &str) -> (u16, Vec<u8>) {
    let r = send(
        "GET",
        url,
        &[("Authorization", &format!("Bearer {token}"))],
        None,
    );
    (r.status, r.body)
}

/// A PUT answered with its status, its **reason phrase** and its body.
///
/// The reason phrase is the part that matters: it is the only piece of
/// a refusal Maven prints (`status code: 403, reason phrase: …`), so a
/// sentence that is only in the body reaches nobody using `mvn`.
fn put_status_line(url: &str, token: &str, body: &[u8]) -> (u16, String, String) {
    let r = ureq::put(url)
        .set("Authorization", &format!("Bearer {token}"))
        .send_bytes(body);
    match r {
        Ok(r) | Err(ureq::Error::Status(_, r)) => {
            let status = r.status();
            let reason = r.status_text().to_string();
            (status, reason, r.into_string().unwrap_or_default())
        }
        Err(e) => panic!("transport {url}: {e}"),
    }
}

/// A request sent byte for byte, path and all.
///
/// Every HTTP client in this workspace normalises `..` out of a URL
/// before it is sent — and so does every URL parser a hostile client
/// does not have to use. So a traversal test through `ureq` tests the
/// client's normaliser, not our door.
fn raw_http(server: &Server, request_line: &str, headers: &[(&str, &str)], body: &[u8]) -> u16 {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(server.host()).expect("connect");
    let mut req = format!(
        "{request_line} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        server.host(),
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).expect("write");
    s.write_all(body).expect("write body");
    let mut out = Vec::new();
    s.read_to_end(&mut out).expect("read");
    let head = String::from_utf8_lossy(&out);
    head.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("no status line in {head:?}"))
}

fn base(server: &Server) -> String {
    format!("{}/maven", server.base)
}

/// The id of the one package called `name`.
fn package_id(server: &Server, admin: &str, name: &str) -> String {
    let (status, listed) = server.get("/api/v1/packages", admin);
    assert_eq!(status, 200, "{listed}");
    listed["packages"]
        .as_array()
        .expect("a list")
        .iter()
        .find(|p| p["name"] == name)
        .and_then(|p| p["id"].as_str())
        .unwrap_or_else(|| panic!("no package {name}: {listed}"))
        .to_string()
}

/// The whole of `mvn deploy` and then `mvn install`: every file of a
/// release accretes onto one version, and every one of them comes back.
#[test]
fn a_release_deploys_file_by_file_and_every_file_comes_back() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-deploy");
    let admin = server.bootstrap("acme");
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:write"]);
    let b = base(&server);
    let dir = format!("{b}/com/acme/widget/1.4.0");

    // The order the wagon actually uses: the main artifact, its
    // checksums, then the POM and its checksums.
    let jar = b"PK\x03\x04 not really a jar, near enough for a test";
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("widget-1.4.0.jar", jar.to_vec()),
        ("widget-1.4.0.jar.sha1", b"aaaa".to_vec()),
        ("widget-1.4.0.jar.md5", b"bbbb".to_vec()),
        ("widget-1.4.0.pom", POM.as_bytes().to_vec()),
        ("widget-1.4.0.pom.sha1", b"cccc".to_vec()),
        ("widget-1.4.0-sources.jar", b"sources".to_vec()),
    ];
    for (name, body) in &files {
        let (status, err) = put_raw(&format!("{dir}/{name}"), &ci, body);
        assert_eq!(status, 201, "deploying {name}: {err}");
    }

    // …and `mvn install` gets every one of them back, byte for byte.
    for (name, body) in &files {
        let (status, got) = get_raw(&format!("{dir}/{name}"), &admin);
        assert_eq!(status, 200, "fetching {name}");
        assert_eq!(&got, body, "{name} came back different");
    }

    // One package, one version, six files — not six versions, and not
    // six packages. Reading the coordinate from the left rather than
    // the right is how that goes wrong, and it goes wrong quietly.
    let (status, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(status, 200, "{listed}");
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(listed["packages"][0]["name"], "com.acme:widget");
    assert_eq!(listed["packages"][0]["ecosystem"], "maven");
    let id = package_id(&server, &admin, "com.acme:widget");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(shown["versions"].as_array().map(|a| a.len()), Some(1));
    let v = &shown["versions"][0];
    assert_eq!(v["version"], "1.4.0");
    assert_eq!(v["files"].as_array().map(|a| a.len()), Some(6), "{v}");
    // The POM arrived fourth, and the licence it declared is on the
    // version the jar created.
    assert_eq!(v["license"], "Apache-2.0");
    assert_eq!(v["license_source"], "declared");
    // Who made it: the person whose token deployed the first file.
    assert_eq!(v["published_by_username"], "ci", "{v}");

    // One entry in the audit log for the release — not one per file,
    // which would bury everything else an admin reads there under
    // checksums.
    let (status, log) = server.get("/api/v1/audit", &admin);
    assert_eq!(status, 200, "{log}");
    let publishes: Vec<&serde_json::Value> = log["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|e| e["action"] == "package.publish")
        .collect();
    assert_eq!(publishes.len(), 1, "{log}");
    assert_eq!(publishes[0]["username"], "ci", "{log}");
    let entry = publishes[0].to_string();
    assert!(
        entry.contains("com.acme:widget") && entry.contains("1.4.0") && entry.contains("maven"),
        "{entry}"
    );
    assert!(server.healthy());
}

/// The POM can arrive *before* the jar, and nothing promises which. A
/// licence that only lands when the POM happens to be second would be a
/// policy that worked on Tuesdays.
#[test]
fn the_licence_lands_whichever_order_the_files_arrive_in() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-order");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    let dir = format!("{b}/com/acme/first-pom/2.0.0");
    let pom = POM.replace("widget", "first-pom").replace("1.4.0", "2.0.0");
    assert_eq!(
        put_raw(
            &format!("{dir}/first-pom-2.0.0.pom"),
            &admin,
            pom.as_bytes()
        )
        .0,
        201
    );
    assert_eq!(
        put_raw(&format!("{dir}/first-pom-2.0.0.jar"), &admin, b"jar").0,
        201
    );

    let id = package_id(&server, &admin, "com.acme:first-pom");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(shown["versions"][0]["license"], "Apache-2.0");
    // …and the size is the whole release, not whichever file was first.
    assert!(
        shown["versions"][0]["size_bytes"].as_i64().unwrap_or(0) > pom.len() as i64,
        "the jar's bytes were not counted: {shown}"
    );
    assert!(server.healthy());
}

/// Immutability, per file — which is where Maven puts the pressure on
/// it. A re-run of a release job, or `-Dmaven.deploy.overwrite`, must
/// not replace bytes somebody has already built against.
#[test]
fn redeploying_a_file_is_refused_and_changes_nothing() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-immutable");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let url = format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.jar");

    assert_eq!(put_raw(&url, &admin, b"the original bytes").0, 201);
    let (status, body) = put_raw(&url, &admin, b"something else entirely");
    assert_eq!(status, 409, "a redeploy was accepted: {body}");
    assert!(body.contains("never changes"), "{body}");

    // The part that matters: the original is still exactly itself.
    let (status, got) = get_raw(&url, &admin);
    assert_eq!(status, 200);
    assert_eq!(got, b"the original bytes");

    // A *different* file of the same version is still fine — the
    // refusal is about one filename, not about the version being sealed
    // after its first upload.
    assert_eq!(
        put_raw(
            &format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.pom"),
            &admin,
            POM.as_bytes()
        )
        .0,
        201
    );
    assert!(server.healthy());
}

/// A snapshot is a version whose bytes are meant to change, which is
/// the one thing this registry does not do. Refused with a sentence
/// that says why, because for a team that publishes snapshots on every
/// merge this is the difference between usable and not.
#[test]
fn a_snapshot_is_refused_with_a_reason() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-snapshot");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    for version in ["1.0-SNAPSHOT", "1.0-snapshot"] {
        let (status, body) = put_raw(
            &format!("{b}/com/acme/widget/{version}/widget-{version}.jar"),
            &admin,
            b"bytes",
        );
        assert_eq!(status, 400, "{version} was accepted: {body}");
        // The sentence, not the word: the version itself says
        // "snapshot", so finding that word proves nothing.
        assert!(body.contains("does not hold snapshots"), "{body}");
    }
    // Nothing was created on the way to refusing.
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"].as_array().map(|a| a.len()), Some(0));
    assert!(server.healthy());
}

/// Maven prints the status line of a refusal and never its body, so the
/// sentence has to be **in the status line**. Every refusal a person
/// can meet on a deploy is checked here, because each one was a bare
/// `Forbidden`, `Bad Request` or `Conflict` in `mvn`'s output until the
/// real client was run against this door.
#[test]
fn a_refusal_is_in_the_status_line_because_that_is_all_maven_prints() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-reason");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:read"]);
    let b = base(&server);
    let jar = format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.jar");
    assert_eq!(put_raw(&jar, &admin, b"ours").0, 201);

    for (what, url, token, status, sentence) in [
        (
            "a reader deploying",
            format!("{b}/com/acme/widget/2.0.0/widget-2.0.0.jar"),
            reader.as_str(),
            403,
            "rita is a reader here, and a reader may not publish to this registry",
        ),
        (
            "a read-only token deploying",
            format!("{b}/com/acme/widget/2.0.0/widget-2.0.0.jar"),
            ci.as_str(),
            403,
            "this token was not minted with package:write",
        ),
        (
            "a redeploy",
            jar.clone(),
            admin.as_str(),
            409,
            "widget-1.0.0.jar is already deployed at com.acme:widget 1.0.0, and a published \
             file never changes here",
        ),
        (
            "a snapshot",
            format!("{b}/com/acme/widget/1.0-SNAPSHOT/widget-1.0-SNAPSHOT.jar"),
            admin.as_str(),
            400,
            "1.0-SNAPSHOT is a snapshot, and this registry does not hold snapshots",
        ),
        (
            "a path that is not a coordinate",
            format!("{b}/widget/1.0/widget-1.0.jar"),
            admin.as_str(),
            400,
            "that is not a Maven coordinate",
        ),
    ] {
        let (got, reason, body) = put_status_line(&url, token, b"x");
        assert_eq!(got, status, "{what}: {reason} / {body}");
        assert!(
            reason.contains(sentence),
            "{what}: Maven would print only {reason:?}, and the sentence was {body:?}"
        );
        assert!(body.contains(sentence), "{what}: {body}");
        // One line of ASCII: nothing that could end the status line, and
        // nothing that arrives in a build log as mojibake.
        assert!(
            reason.bytes().all(|c| c == b' ' || c.is_ascii_graphic()),
            "{what}: {reason:?}"
        );
    }

    // Ours is untouched by any of it.
    assert_eq!(get_raw(&jar, &admin).1, b"ours");
    assert!(server.healthy());
}

/// `maven-metadata.xml` is generated, never stored — and its checksum
/// is computed over the document being served in the same request. A
/// stored checksum would drift from a regenerated document and make
/// Maven fail the build with a corruption error pointing at the
/// developer's own `~/.m2`.
#[test]
fn the_metadata_document_is_generated_and_its_checksum_matches_it() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-metadata");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    for v in ["1.0.0", "1.1.0", "2.0.0"] {
        assert_eq!(
            put_raw(
                &format!("{b}/com/acme/widget/{v}/widget-{v}.jar"),
                &admin,
                format!("jar {v}").as_bytes()
            )
            .0,
            201
        );
    }

    // `mvn deploy` uploads its own copy. We generate ours, so the
    // client's is accepted and discarded rather than failing the whole
    // deploy over a file we do not need.
    assert_eq!(
        put_raw(
            &format!("{b}/com/acme/widget/maven-metadata.xml"),
            &admin,
            b"<metadata>whatever the client thought</metadata>"
        )
        .0,
        200
    );

    let (status, doc) = get_raw(&format!("{b}/com/acme/widget/maven-metadata.xml"), &admin);
    assert_eq!(status, 200);
    let doc = String::from_utf8(doc).expect("xml is utf-8");
    assert!(doc.contains("<groupId>com.acme</groupId>"), "{doc}");
    assert!(doc.contains("<artifactId>widget</artifactId>"), "{doc}");
    assert!(doc.contains("<latest>2.0.0</latest>"), "{doc}");
    assert_eq!(doc.matches("<version>").count(), 3, "{doc}");
    assert!(
        !doc.contains("whatever the client thought"),
        "the client's upload was served back: {doc}"
    );

    // The checksum covers the document we just read.
    let (status, sha) = get_raw(
        &format!("{b}/com/acme/widget/maven-metadata.xml.sha1"),
        &admin,
    );
    assert_eq!(status, 200);
    let sha = String::from_utf8(sha).expect("hex");
    assert_eq!(
        sha,
        sha1_hex(doc.as_bytes()),
        "the checksum is not the document's"
    );

    // An algorithm we do not compute is absent rather than wrong.
    // Maven warns and carries on; a wrong one fails the build.
    assert_eq!(
        get_raw(
            &format!("{b}/com/acme/widget/maven-metadata.xml.md5"),
            &admin
        )
        .0,
        404
    );

    // A yank takes a version out of what a range or `RELEASE` resolves
    // to, and leaves it downloadable by its exact coordinate — so a
    // build that pinned it keeps building.
    let id = package_id(&server, &admin, "com.acme:widget");
    let (status, body) = server.req(
        "POST",
        &format!("/api/v1/packages/{id}/versions/2.0.0/yank"),
        &admin,
        Some(serde_json::json!({ "yanked": true, "reason": "broken" })),
    );
    assert_eq!(status, 200, "{body}");
    let (_, doc) = get_raw(&format!("{b}/com/acme/widget/maven-metadata.xml"), &admin);
    let doc = String::from_utf8(doc).unwrap();
    assert!(!doc.contains("<version>2.0.0</version>"), "{doc}");
    assert!(doc.contains("<latest>1.1.0</latest>"), "{doc}");
    assert!(doc.contains("<release>1.1.0</release>"), "{doc}");
    let (status, bytes) = get_raw(
        &format!("{b}/com/acme/widget/2.0.0/widget-2.0.0.jar"),
        &admin,
    );
    assert_eq!(status, 200, "a yank broke a build that pinned 2.0.0");
    assert_eq!(bytes, b"jar 2.0.0");
    assert!(server.healthy());
}

/// Every negative case on this door, each ending by proving the server
/// is still serving.
#[test]
fn hostile_and_malformed_requests_are_refused_and_the_server_keeps_serving() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-hostile");
    let admin = server.bootstrap("acme");
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let b = base(&server);
    let url = format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.jar");
    assert_eq!(put_raw(&url, &admin, b"ours").0, 201);

    // A path that is not a coordinate. Refused rather than cleaned up:
    // a cleaned path is a second way to address one stored object. Sent
    // byte for byte, because any URL library would have taken the `..`
    // out before our door ever saw it.
    let auth = format!("Bearer {admin}");
    for bad in [
        "/maven/com/acme/../../../etc/passwd/1.0/x.jar",
        "/maven/com/acme/widget/../1.0.0/widget-1.0.0.jar",
        "/maven/com/acme/widget/./1.0.0/widget-1.0.0.jar",
        "/maven/com/acme//widget/1.0.0/widget-1.0.0.jar",
        "/maven/widget/1.0/widget-1.0.jar",
        "/maven/com/acme/widget",
        "/maven/com/acme/widget/1.0/",
    ] {
        let status = raw_http(
            &server,
            &format!("PUT {bad}"),
            &[("Authorization", &auth)],
            b"x",
        );
        assert_eq!(status, 400, "PUT {bad} was answered {status}");
        let status = raw_http(
            &server,
            &format!("GET {bad}"),
            &[("Authorization", &auth)],
            b"",
        );
        assert_eq!(status, 404, "GET {bad} was answered {status}");
    }

    // No credential at all gets a challenge, not a 404 — a client that
    // reads "not found" never tries to authenticate, and Maven does not
    // offer the `<server>` password until it is asked. A token-shaped
    // string that does not verify is no credential either.
    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    let absent = format!("{b}/com/acme/ghost/1.0/ghost-1.0.jar");
    for target in [&url, &absent] {
        for method in ["GET", "PUT"] {
            for auth in [
                None,
                Some(format!("Bearer {forged}")),
                Some(format!(
                    "Basic {}",
                    b64(format!("skein:{forged}").as_bytes())
                )),
            ] {
                let headers: Vec<(&str, &str)> = auth
                    .as_deref()
                    .map(|a| vec![("Authorization", a)])
                    .unwrap_or_default();
                let body = (method == "PUT").then_some(&b"theirs"[..]);
                let r: Reply = send(method, target, &headers, body);
                assert_eq!(r.status, 401, "{method} {target} with {auth:?}");
                assert!(
                    r.header("www-authenticate")
                        .is_some_and(|v| v.starts_with("Basic")),
                    "a 401 with no challenge tells Maven nothing: {method} {target}"
                );
            }
        }
    }

    // A reader reads, and may not write — and is told so in a sentence
    // naming their role, not answered as if the artifact were absent.
    let (status, got) = get_raw(&url, &reader);
    assert_eq!(status, 200);
    assert_eq!(got, b"ours");
    for target in [
        url.clone(),
        format!("{b}/com/acme/widget/9.9.9/widget-9.9.9.jar"),
    ] {
        let (status, body) = put_raw(&target, &reader, b"theirs");
        assert_eq!(status, 403, "{target}: {body}");
        assert!(body.contains("rita is a reader"), "{body}");
    }

    // …and ours is untouched by any of it, and nothing new was created.
    let (status, got) = get_raw(&url, &admin);
    assert_eq!(status, 200);
    assert_eq!(got, b"ours");
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(
        listed["packages"].as_array().map(|a| a.len()),
        Some(1),
        "{listed}"
    );
    let id = package_id(&server, &admin, "com.acme:widget");
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    assert_eq!(
        shown["versions"].as_array().map(|a| a.len()),
        Some(1),
        "{shown}"
    );
    assert!(server.healthy());
}

/// Maven and twine both send Basic, and the token goes in the password
/// field. A door that only read `Bearer` would be one `mvn` could never
/// authenticate to.
#[test]
fn a_basic_credential_is_read_the_way_maven_sends_it() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-basic");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let url = format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.jar");

    let basic = format!("Basic {}", b64(format!("skein:{admin}").as_bytes()));
    let r = send(
        "PUT",
        &url,
        &[("Authorization", &basic)],
        Some(b"deployed with basic"),
    );
    assert_eq!(r.status, 201, "basic auth refused: {}", r.text());

    let r = send("GET", &url, &[("Authorization", &basic)], None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"deployed with basic");
    assert!(server.healthy());
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn sha1_hex(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The answers a resolver gets for things that are not there, and the
/// two refusals a deploy can meet on its own input.
///
/// Each is a separate sentence in somebody's build log, so each is
/// checked separately rather than as one "it 404s".
#[test]
fn absences_and_malformed_deploys_answer_for_themselves() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-absent");
    let admin = server.bootstrap("acme");
    let b = base(&server);

    // Nothing published at all: an artifact, and the metadata document
    // for an artifact that does not exist.
    assert_eq!(
        get_raw(&format!("{b}/com/acme/ghost/1.0/ghost-1.0.jar"), &admin).0,
        404
    );
    assert_eq!(
        get_raw(&format!("{b}/com/acme/ghost/maven-metadata.xml"), &admin).0,
        404
    );

    assert_eq!(
        put_raw(
            &format!("{b}/com/acme/widget/1.0.0/widget-1.0.0.jar"),
            &admin,
            b"a jar"
        )
        .0,
        201
    );
    // The artifact exists; this version and this filename do not.
    assert_eq!(
        get_raw(
            &format!("{b}/com/acme/widget/9.9.9/widget-9.9.9.jar"),
            &admin
        )
        .0,
        404
    );
    assert_eq!(
        get_raw(
            &format!("{b}/com/acme/widget/1.0.0/widget-1.0.0-sources.jar"),
            &admin
        )
        .0,
        404
    );

    // The SHA-256 of the generated metadata, which Maven asks for when
    // it is configured to.
    let (status, doc) = get_raw(&format!("{b}/com/acme/widget/maven-metadata.xml"), &admin);
    assert_eq!(status, 200);
    let (status, hex) = get_raw(
        &format!("{b}/com/acme/widget/maven-metadata.xml.sha256"),
        &admin,
    );
    assert_eq!(status, 200);
    assert_eq!(
        String::from_utf8(hex).unwrap(),
        sha256_hex(&doc),
        "the sha256 does not cover the document served beside it"
    );

    // A path that is not a coordinate at all is a 400 on a deploy: the
    // caller's request is malformed, not merely absent, and `mvn`
    // prints the sentence.
    let (status, body) = put_raw(
        &format!("{b}/com/acme/widget/caf%C3%A9/widget-1.0.jar"),
        &admin,
        b"x",
    );
    assert_eq!(status, 400, "a non-ASCII version was accepted: {body}");
    assert!(body.contains("coordinate"), "{body}");

    // A version that *is* a legal path component and still cannot be
    // stored. This is refused on every file of the release rather than
    // only the first: the later ones reach `add_file`, which checks
    // neither name nor version, so a version that was fine on the jar
    // and a 400 on the POM would be a refusal nobody could explain.
    let long_version = "1.".to_string() + &"0".repeat(200);
    for file in ["widget.jar", "widget.pom"] {
        let (status, body) = put_raw(
            &format!("{b}/com/acme/widget/{long_version}/{file}"),
            &admin,
            b"x",
        );
        assert_eq!(status, 400, "{file}: an unstorable version was accepted");
        assert!(body.contains("version"), "{file}: {body}");
    }

    // A groupId long enough to be no name at all.
    let long = vec!["averylongsegment"; 30].join("/");
    let (status, body) = put_raw(
        &format!("{b}/{long}/widget/1.0/widget-1.0.jar"),
        &admin,
        b"x",
    );
    assert_eq!(status, 400, "an over-long name was accepted: {body}");

    // A POM that is not UTF-8 declares no licence rather than failing
    // the deploy: the bytes are still a file somebody asked us to hold.
    assert_eq!(
        put_raw(
            &format!("{b}/com/acme/binary/1.0.0/binary-1.0.0.pom"),
            &admin,
            &[0xff, 0xfe, 0x00]
        )
        .0,
        201
    );
    // …and one whose licence name is not in the curated table is
    // `unknown`, never guessed.
    let odd = POM
        .replace("widget", "odd")
        .replace("Apache License, Version 2.0", "Weird Corporate Licence v3");
    assert_eq!(
        put_raw(
            &format!("{b}/com/acme/odd/1.4.0/odd-1.4.0.pom"),
            &admin,
            odd.as_bytes()
        )
        .0,
        201
    );
    let odd_id = package_id(&server, &admin, "com.acme:odd");
    let (_, shown) = server.get(&format!("/api/v1/packages/{odd_id}"), &admin);
    assert!(
        shown["versions"][0]["license"].is_null(),
        "an unmapped licence name was guessed at: {shown}"
    );
    assert_eq!(shown["versions"][0]["license_source"], "unknown");
    assert!(server.healthy());
}

/// A registry that has switched Maven off answers nothing at all: 404
/// to somebody who has authenticated, for an artifact that exists as
/// much as for one that does not — and to somebody who has not, the
/// same challenge as every other door, so a stranger cannot learn
/// which ecosystems are on.
#[test]
fn a_registry_that_switched_maven_off_answers_for_nothing() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-off");
    let admin = server.bootstrap("acme");
    let b = base(&server);
    let jar = format!("{b}/com/acme/widget/1.0/widget-1.0.jar");
    assert_eq!(put_raw(&jar, &admin, b"deployed while on").0, 201);

    let (status, body) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "maven", "mode": "off" })),
    );
    assert_eq!(status, 200, "{body}");

    for url in [
        jar.clone(),
        format!("{b}/com/acme/widget/maven-metadata.xml"),
        format!("{b}/com/acme/ghost/1.0/ghost-1.0.jar"),
    ] {
        assert_eq!(get_raw(&url, &admin).0, 404, "{url}");
        assert_eq!(put_raw(&url, &admin, b"x").0, 404, "{url}");
        let r = send("GET", &url, &[], None);
        assert_eq!(r.status, 401, "{url}");
        assert!(r.header("www-authenticate").is_some(), "{url}");
    }

    // Switched back on, what was deployed is still exactly there: off
    // hides, it does not delete.
    common::enable(&server, &admin, "maven");
    let (status, got) = get_raw(&jar, &admin);
    assert_eq!(status, 200);
    assert_eq!(got, b"deployed while on");
    assert!(server.healthy());
}

/// Before the install is set up, the Maven door says what to run — the
/// same 503 as every other door — rather than reaching a handler that
/// has no organization to look anything up in.
#[test]
fn before_setup_the_maven_door_says_what_to_run() {
    let bucket = Minio::shared().bucket("maven-e2e");
    let server = spawn(&bucket.base_url, "maven-setup");
    let b = base(&server);
    for (method, url) in [
        ("GET", format!("{b}/com/acme/widget/maven-metadata.xml")),
        ("PUT", format!("{b}/com/acme/widget/1.0/widget-1.0.jar")),
    ] {
        let body = (method == "PUT").then_some(&b"x"[..]);
        let r = send(method, &url, &[], body);
        assert_eq!(r.status, 503, "{method} {url}");
        assert!(r.text().contains("skein admin bootstrap"), "{}", r.text());
    }
    assert!(server.healthy());
}
