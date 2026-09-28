//! OCI end to end: `docker push` and `docker pull`'s request sequence
//! against a real server, a real bucket and a real PostgreSQL.
//!
//! `registry::oci` is pure and is hammered in its own unit tests. What
//! those cannot show is the part this door exists for: that a layer
//! larger than one object round-trips through the block scheme byte for
//! byte, that a manifest naming a layer nobody pushed is refused rather
//! than stored, and that the whole sequence a container client actually
//! makes — probe, HEAD each blob, open a session, stream, finish, push
//! the manifest — works in that order.
//!
//! What the real `docker` does against a real server is
//! `clients_e2e.rs`'s job: every request here is one we built from what
//! we believe a client sends.

mod common;

use common::spawn;
use skein_testkit::{Minio, Reply, Server};

fn v2(server: &Server) -> String {
    format!("{}/v2", server.base)
}

/// One request with a bearer token, answered whatever its status.
fn req(method: &str, url: &str, token: &str, body: Option<&[u8]>) -> Reply {
    skein_testkit::server::send(
        method,
        url,
        &[("Authorization", &format!("Bearer {token}"))],
        body,
    )
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!(
        "sha256:{}",
        h.finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// The first error code of an OCI error body.
fn code(r: &Reply) -> String {
    r.json()["errors"][0]["code"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Push one blob the way a client does: open a session, stream the
/// bytes, finish with the digest.
fn push_blob(server: &Server, repo: &str, token: &str, bytes: &[u8]) -> String {
    let r = req(
        "POST",
        &format!("{}/{repo}/blobs/uploads/", v2(server)),
        token,
        Some(b""),
    );
    assert_eq!(r.status, 202, "opening a session: {}", r.text());
    let location = r.header("location").expect("a Location to write to");
    let url = format!("{}{location}", server.base);

    let r = req("PATCH", &url, token, Some(bytes));
    assert_eq!(r.status, 202, "streaming: {}", r.text());

    let digest = sha256(bytes);
    let r = req("PUT", &format!("{url}?digest={digest}"), token, Some(b""));
    assert_eq!(r.status, 201, "finishing: {}", r.text());
    assert_eq!(r.header("docker-content-digest"), Some(digest.as_str()));
    digest
}

fn manifest(config: &str, layers: &[(&str, usize)]) -> Vec<u8> {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config,
            "size": 0
        },
        "layers": layers.iter().map(|(d, n)| serde_json::json!({
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": d,
            "size": n
        })).collect::<Vec<_>>(),
        "annotations": { "org.opencontainers.image.licenses": "Apache-2.0" }
    })
    .to_string()
    .into_bytes()
}

fn index(members: &[(&str, usize)]) -> Vec<u8> {
    serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": members.iter().map(|(d, n)| serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": d,
            "size": n,
            "platform": { "architecture": "amd64", "os": "linux" }
        })).collect::<Vec<_>>()
    })
    .to_string()
    .into_bytes()
}

/// Bootstrap, with containers on — which the bootstrap does already for
/// every ecosystem this build serves; said again here so the suite does
/// not depend on it.
fn acme(server: &Server) -> String {
    let admin = server.bootstrap("acme");
    common::enable(server, &admin, "oci");
    admin
}

/// The probe every client makes first. It is what tells a client this
/// is a v2 registry and how to authenticate; without the challenge,
/// `docker login` has nothing to go on.
#[test]
fn the_version_probe_answers_and_challenges_an_anonymous_caller() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-probe");

    // Before the install is set up, the container door says what to
    // run, like every other door — it never reaches a handler that
    // needs the organization.
    for path in ["/v2/", "/v2/acme/service/tags/list"] {
        let r = server.raw("GET", path, &[], None);
        assert_eq!(r.status, 503, "{path}");
        assert!(
            r.text().contains("skein admin bootstrap"),
            "{path}: {}",
            r.text()
        );
    }

    let admin = acme(&server);

    let r = req("GET", &format!("{}/", v2(&server)), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(
        r.header("docker-distribution-api-version"),
        Some("registry/2.0")
    );

    // The way `docker login` sends it: Basic, with the token as the
    // password and any username.
    let basic = format!("Basic {}", common::b64(format!("skein:{admin}").as_bytes()));
    let r = server.raw("GET", "/v2/", &[("Authorization", &basic)], None);
    assert_eq!(r.status, 200, "docker login's own credential was refused");

    let r = server.raw("GET", "/v2/", &[], None);
    assert_eq!(r.status, 401);
    assert!(
        r.header("www-authenticate")
            .is_some_and(|v| v.starts_with("Basic")),
        "a 401 with no challenge tells docker login nothing"
    );
    assert!(server.healthy());
}

/// The whole of `docker push` and then `docker pull`, in the order a
/// client makes the requests.
#[test]
fn an_image_pushes_and_pulls_back_byte_for_byte() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-roundtrip");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    let config = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
    let layer_one = b"a layer's worth of bytes".repeat(100);
    let layer_two = b"another layer entirely".repeat(50);

    // A client HEADs each blob before pushing it, so it can skip the
    // ones the registry already has.
    let cd = sha256(config);
    let r = req("HEAD", &format!("{b}/{repo}/blobs/{cd}"), &admin, None);
    assert_eq!(
        r.status, 404,
        "a blob nobody pushed was reported as present"
    );

    let config_digest = push_blob(&server, repo, &admin, config);
    let one = push_blob(&server, repo, &admin, &layer_one);
    let two = push_blob(&server, repo, &admin, &layer_two);
    assert_eq!(config_digest, cd);

    // …and now the HEAD says so, which is what makes the second push of
    // a shared base layer free.
    let r = req("HEAD", &format!("{b}/{repo}/blobs/{one}"), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.header("docker-content-digest"), Some(one.as_str()));

    let doc = manifest(
        &config_digest,
        &[(&one, layer_one.len()), (&two, layer_two.len())],
    );
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/v1"),
        &admin,
        Some(&doc),
    );
    assert_eq!(r.status, 201, "pushing the manifest: {}", r.text());
    let manifest_digest = r
        .header("docker-content-digest")
        .expect("a content digest")
        .to_string();
    assert_eq!(manifest_digest, sha256(&doc));
    assert_eq!(
        r.header("location"),
        Some(format!("/v2/{repo}/manifests/{manifest_digest}").as_str()),
        "the Location names the repository as it was pushed, whole"
    );

    // Pull: the manifest by tag, then every layer it names.
    let r = req("GET", &format!("{b}/{repo}/manifests/v1"), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, doc, "the manifest came back different");
    assert_eq!(
        r.header("docker-content-digest"),
        Some(manifest_digest.as_str())
    );
    assert_eq!(
        r.header("content-type"),
        Some("application/vnd.oci.image.manifest.v1+json"),
        "the type the document itself declares is the only one that cannot \
         disagree with the bytes"
    );

    for (digest, bytes) in [(&one, &layer_one), (&two, &layer_two)] {
        let r = req("GET", &format!("{b}/{repo}/blobs/{digest}"), &admin, None);
        assert_eq!(r.status, 200, "pulling {digest}");
        assert_eq!(&r.body, bytes, "{digest} came back different");
    }

    // The manifest is a blob too, which is how an index's members are
    // pulled — and it is what `docker pull …/acme/service@sha256:…` asks
    // for.
    let r = req(
        "GET",
        &format!("{b}/{repo}/manifests/{manifest_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, doc);

    // The tag list, and the management API's view of it: the repository
    // is the whole path, with no organization peeled off it.
    let r = req("GET", &format!("{b}/{repo}/tags/list"), &admin, None);
    assert_eq!(r.status, 200);
    let tags = r.json();
    assert_eq!(tags["name"], "acme/service");
    assert_eq!(tags["tags"][0], "v1");

    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(listed["packages"][0]["name"], "acme/service");
    assert_eq!(listed["packages"][0]["ecosystem"], "oci");
    let id = listed["packages"][0]["id"]
        .as_str()
        .expect("id")
        .to_string();
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    // `org.opencontainers.image.licenses` is defined to be an SPDX
    // expression, so it needs no mapping.
    assert_eq!(shown["versions"][0]["license"], "Apache-2.0");
    // Who pushed it, as for every other ecosystem.
    assert_eq!(shown["versions"][0]["published_by_username"], "admin");

    // …and the push is in the audit log, as a publish.
    let (_, log) = server.get("/api/v1/audit", &admin);
    assert!(
        log["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["action"] == "package.publish"),
        "{log}"
    );
    assert!(server.healthy());
}

/// A repository of one component is a repository — there is no
/// organization in the name to be missing.
#[test]
fn a_single_component_repository_pushes_and_pulls() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-single");
    let admin = acme(&server);
    let b = v2(&server);

    let config = push_blob(&server, "app", &admin, b"{}");
    let layer = push_blob(&server, "app", &admin, b"the whole app");
    let doc = manifest(&config, &[(&layer, 13)]);
    let r = req("PUT", &format!("{b}/app/manifests/1"), &admin, Some(&doc));
    assert_eq!(r.status, 201, "{}", r.text());

    let r = req("GET", &format!("{b}/app/manifests/1"), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, doc);
    let r = req("GET", &format!("{b}/app/blobs/{layer}"), &admin, None);
    assert_eq!(r.body, b"the whole app");
    let r = req("GET", &format!("{b}/app/tags/list"), &admin, None);
    assert_eq!(r.json()["name"], "app");

    let (_, listed) = server.get("/api/v1/packages?ecosystem=oci", &admin);
    assert_eq!(listed["packages"][0]["name"], "app");
    assert!(server.healthy());
}

/// The reason the block scheme exists. A layer larger than one object
/// has to round-trip byte for byte, in and out, without ever becoming
/// resident — and the digest has to be the digest of the whole thing
/// rather than of whichever piece arrived last.
#[test]
fn a_layer_larger_than_one_block_round_trips_whole() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-big");
    let admin = acme(&server);
    let repo = "acme/big";

    // Deliberately not a round multiple of the block size: a final
    // partial block is where an off-by-one in the cutting shows up, and
    // it shows up as a digest mismatch rather than as corruption.
    const SIZE: usize = 16 * 1024 * 1024 + 4096 + 7;
    let mut layer = vec![0u8; SIZE];
    for (i, b) in layer.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let digest = push_blob(&server, repo, &admin, &layer);
    assert_eq!(digest, sha256(&layer));

    let r = req(
        "GET",
        &format!("{}/{repo}/blobs/{digest}", v2(&server)),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body.len(), SIZE, "the layer came back a different length");
    assert_eq!(sha256(&r.body), digest, "the layer came back different");
    assert_eq!(
        r.header("content-length"),
        Some(SIZE.to_string().as_str()),
        "a streamed layer must still say how long it is"
    );

    // It really was cut: two blocks, the whole and the tail.
    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let blocks = skein_control::packages::blocks_of(&db, &org.id, &digest).expect("blocks");
    assert_eq!(
        blocks.iter().map(|b| b.size_bytes).collect::<Vec<_>>(),
        vec![16 * 1024 * 1024, 4096 + 7]
    );

    // And the bytes are accounted.
    assert!(skein_control::packages::bytes_for_org(&db, &org.id).expect("bytes") >= SIZE as i64);
    assert!(server.healthy());
}

/// Nothing is public. Without a credential that authenticates, every
/// path answers with a challenge and nothing else — not a 404 for an
/// absent repository, not a 200 for a present one, not even a 404 for a
/// path that is not one of the five shapes.
#[test]
fn nothing_is_answered_to_somebody_who_has_not_said_who_they_are() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-anonymous");
    let admin = acme(&server);
    let b = v2(&server);
    let config = push_blob(&server, "acme/secret", &admin, b"{}");
    let layer = push_blob(&server, "acme/secret", &admin, b"private bytes");
    assert_eq!(
        req(
            "PUT",
            &format!("{b}/acme/secret/manifests/v1"),
            &admin,
            Some(&manifest(&config, &[(&layer, 13)]))
        )
        .status,
        201
    );

    let forged = "skein_01aaaaaaaaaaaaaaaaaaaaaaaa_notarealsecretnotarealsecretnotarealsecret";
    for (method, path) in [
        ("GET", "/v2/".to_string()),
        ("GET", "/v2/acme/secret/tags/list".to_string()),
        ("GET", "/v2/acme/secret/manifests/v1".to_string()),
        ("HEAD", format!("/v2/acme/secret/blobs/{layer}")),
        ("GET", format!("/v2/acme/secret/blobs/{layer}")),
        ("GET", "/v2/acme/no-such-thing/tags/list".to_string()),
        ("GET", "/v2/not/a/shape".to_string()),
        ("POST", "/v2/acme/secret/blobs/uploads/".to_string()),
        ("PUT", "/v2/acme/secret/manifests/v2".to_string()),
        ("DELETE", "/v2/acme/secret/manifests/v1".to_string()),
    ] {
        for auth in [
            None,
            Some(format!("Bearer {forged}")),
            Some("Bearer nonsense".into()),
            Some(format!(
                "Basic {}",
                common::b64(format!("skein:{forged}").as_bytes())
            )),
        ] {
            let headers: Vec<(&str, &str)> = auth
                .as_deref()
                .map(|a| vec![("Authorization", a)])
                .unwrap_or_default();
            let r = server.raw(method, &path, &headers, Some(b""));
            assert_eq!(r.status, 401, "{method} {path} with {auth:?}");
            assert!(
                r.header("www-authenticate")
                    .is_some_and(|v| v.starts_with("Basic")),
                "docker cannot learn it needs to log in: {method} {path}"
            );
            assert!(
                !r.text().contains("secret") && !r.text().contains(&layer),
                "a refusal said something about what is here: {}",
                r.text()
            );
        }
    }

    // Switch containers off: a stranger's answer does not change, so it
    // cannot be used to learn which ecosystems are on.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "oci", "mode": "off" })),
    );
    assert_eq!(status, 200);
    for path in ["/v2/", "/v2/acme/secret/tags/list"] {
        let r = server.raw("GET", path, &[], None);
        assert_eq!(r.status, 401, "{path}");
        assert!(r.header("www-authenticate").is_some(), "{path}");
    }

    // Nothing was pushed by any of it.
    common::enable(&server, &admin, "oci");
    let r = req("GET", &format!("{b}/acme/secret/tags/list"), &admin, None);
    assert_eq!(r.json()["tags"], serde_json::json!(["v1"]));
    assert!(server.healthy());
}

/// A reader pulls and does not push, and is told why in a sentence
/// docker prints — `denied: …` naming their role — rather than being
/// told the repository they can see does not exist.
#[test]
fn a_reader_pulls_and_is_told_why_they_may_not_push() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-reader");
    let admin = acme(&server);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let (_, ci) = server.person(&admin, "ci", "publisher", &["package:read"]);
    let b = v2(&server);
    let repo = "acme/service";

    let config = push_blob(&server, repo, &admin, b"{}");
    let layer = push_blob(&server, repo, &admin, b"a layer");
    let doc = manifest(&config, &[(&layer, 7)]);
    assert_eq!(
        req(
            "PUT",
            &format!("{b}/{repo}/manifests/v1"),
            &admin,
            Some(&doc)
        )
        .status,
        201
    );

    // Everything a pull does.
    let r = req("GET", &format!("{b}/"), &reader, None);
    assert_eq!(r.status, 200);
    let r = req("GET", &format!("{b}/{repo}/manifests/v1"), &reader, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, doc);
    let r = req("GET", &format!("{b}/{repo}/blobs/{layer}"), &reader, None);
    assert_eq!(r.body, b"a layer");
    assert_eq!(
        req("GET", &format!("{b}/{repo}/tags/list"), &reader, None).status,
        200
    );

    // Everything a push does, refused with the reason.
    for (method, path, body) in [
        ("POST", format!("{b}/{repo}/blobs/uploads/"), &b""[..]),
        ("PUT", format!("{b}/{repo}/manifests/v2"), &doc[..]),
        ("DELETE", format!("{b}/{repo}/manifests/v1"), &b""[..]),
    ] {
        let r = req(method, &path, &reader, Some(body));
        assert_eq!(r.status, 403, "{method} {path}: {}", r.text());
        assert_eq!(code(&r), "DENIED", "{}", r.text());
        let why = r.json()["errors"][0]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(why.contains("rita is a reader"), "{why}");
    }

    // A publisher whose *token* was minted read-only is told the token
    // is the limit, because the fix is different.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &ci,
        Some(b""),
    );
    assert_eq!(r.status, 403);
    assert!(
        r.text()
            .contains("this token was not minted with package:write"),
        "{}",
        r.text()
    );

    // Nothing moved.
    let r = req("GET", &format!("{b}/{repo}/tags/list"), &admin, None);
    assert_eq!(r.json()["tags"], serde_json::json!(["v1"]));
    assert!(server.healthy());
}

/// Every negative case on this door, each ending by proving the server
/// is still serving.
#[test]
fn hostile_pushes_are_refused_and_the_server_keeps_serving() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-hostile");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    let config = push_blob(&server, repo, &admin, b"config");
    let layer = push_blob(&server, repo, &admin, b"layer");

    // A manifest naming a layer nobody pushed. Storing it would make
    // this registry serve an image that cannot be pulled, and the
    // client's error would be about the layer rather than about the
    // push that was wrong.
    let ghost = format!("sha256:{}", "e".repeat(64));
    let doc = manifest(&config, &[(&ghost, 10)]);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/broken"),
        &admin,
        Some(&doc),
    );
    assert_eq!(
        r.status, 404,
        "a manifest naming a missing layer was stored"
    );
    assert_eq!(code(&r), "BLOB_UNKNOWN");

    // Finishing an upload with a digest that is not the bytes'.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    let url = format!("{}{}", server.base, r.header("location").unwrap());
    req("PATCH", &url, &admin, Some(b"some bytes"));
    let lie = format!("sha256:{}", "f".repeat(64));
    let r = req("PUT", &format!("{url}?digest={lie}"), &admin, Some(b""));
    assert_eq!(r.status, 400, "a lie about the digest was accepted");
    assert_eq!(code(&r), "DIGEST_INVALID");
    // …and the blob is not there under either name.
    assert_eq!(
        req("HEAD", &format!("{b}/{repo}/blobs/{lie}"), &admin, None).status,
        404
    );
    assert_eq!(
        req(
            "HEAD",
            &format!("{b}/{repo}/blobs/{}", sha256(b"some bytes")),
            &admin,
            None
        )
        .status,
        404
    );

    // A manifest pushed by digest must be that digest.
    let real = manifest(&config, &[(&layer, 5)]);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/{lie}"),
        &admin,
        Some(&real),
    );
    assert_eq!(r.status, 400);
    assert_eq!(code(&r), "DIGEST_INVALID");

    // Not a manifest at all.
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/nonsense"),
        &admin,
        Some(b"not json"),
    );
    assert_eq!(r.status, 400);
    assert_eq!(code(&r), "MANIFEST_INVALID");

    // Paths that are not one of the five shapes.
    for bad in [
        "acme/service/blobs/not-a-digest",
        "Acme/service/manifests/latest",
        "acme/service/manifests/.leading",
        "acme/service/tags",
    ] {
        let r = req("GET", &format!("{b}/{bad}"), &admin, None);
        assert_eq!(r.status, 404, "{bad} was served");
        assert_eq!(code(&r), "NAME_UNKNOWN", "{bad}");
    }
    // A traversal, sent as written: an HTTP client would resolve the
    // `..` itself and ask for something else entirely.
    {
        use std::io::{Read, Write};
        let mut sock = std::net::TcpStream::connect(server.host()).expect("connect");
        write!(
            sock,
            "GET /v2/acme/../etc/manifests/latest HTTP/1.1\r\nHost: {}\r\n\
             Authorization: Bearer {admin}\r\nConnection: close\r\n\r\n",
            server.host()
        )
        .unwrap();
        let mut said = String::new();
        let _ = sock.read_to_string(&mut said);
        assert!(
            said.starts_with("HTTP/1.1 404 "),
            "a traversal was served: {said}"
        );
        assert!(said.contains("NAME_UNKNOWN"), "{said}");
    }

    // An upload session is a bearer capability. Finishing one against a
    // repository it was not opened for would be a way to write bytes
    // into a name the opener did not open a session for.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    let session = r
        .header("location")
        .unwrap()
        .rsplit('/')
        .next()
        .expect("a session id")
        .to_string();
    let digest = sha256(b"");
    let r = req(
        "PUT",
        &format!("{b}/acme/elsewhere/blobs/uploads/{session}?digest={digest}"),
        &admin,
        Some(b""),
    );
    assert_eq!(
        r.status, 404,
        "a session opened against one repository finished against another"
    );
    assert_eq!(code(&r), "BLOB_UPLOAD_UNKNOWN");

    // A repository name a container client will happily send and this
    // registry cannot store. OCI's grammar admits 255 bytes; a package
    // name here is capped at 214, so the gap between the two is a real
    // `docker push` that has to be refused rather than truncated — on
    // the upload door *and* on the manifest door, because a client that
    // got past the first would otherwise write a manifest for a package
    // row that does not exist.
    let over = format!("acme/{}", "a".repeat(215));
    let r = req("POST", &format!("{b}/{over}/blobs/uploads/"), &admin, None);
    assert_eq!(
        r.status, 400,
        "an unstorable repository name opened a session"
    );
    assert_eq!(code(&r), "NAME_INVALID", "{}", r.text());
    let doc = manifest(&config, &[(&layer, 5)]);
    let r = req(
        "PUT",
        &format!("{b}/{over}/manifests/v1"),
        &admin,
        Some(&doc),
    );
    assert_eq!(
        r.status, 400,
        "an unstorable repository name took a manifest"
    );
    assert_eq!(code(&r), "NAME_INVALID", "{}", r.text());

    // …and the real image is untouched by any of it.
    let r = req("GET", &format!("{b}/{repo}/blobs/{layer}"), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"layer");
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert!(
        listed["packages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["name"] == "acme/service"),
        "a refused push created a repository: {listed}"
    );
    assert!(server.healthy());
}

/// An image may name the same blob twice — two build steps that produce
/// an identical layer, or the empty layer an image carries more than
/// once — and that is an ordinary image, not a malformed one.
///
/// A version holds each file once, so recording each descriptor as it
/// came made the second one a duplicate row, and the push answered 500.
#[test]
fn a_manifest_that_names_one_layer_twice_is_an_image_like_any_other() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-duplicate");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    let config = push_blob(&server, repo, &admin, b"{}");
    let layer = push_blob(&server, repo, &admin, b"the same layer");
    let doc = manifest(&config, &[(&layer, 14), (&layer, 14)]);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/v1"),
        &admin,
        Some(&doc),
    );
    assert_eq!(r.status, 201, "{}", r.text());

    let r = req("GET", &format!("{b}/{repo}/manifests/v1"), &admin, None);
    assert_eq!(r.body, doc, "the manifest was stored as something else");
    let (_, listed) = server.get("/api/v1/packages", &admin);
    let id = listed["packages"][0]["id"].as_str().unwrap().to_string();
    let (_, shown) = server.get(&format!("/api/v1/packages/{id}"), &admin);
    let files: Vec<&str> = shown["versions"][0]["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["filename"].as_str().unwrap())
        .collect();
    assert_eq!(
        files.iter().filter(|f| **f == layer).count(),
        1,
        "{files:?}"
    );
    assert!(files.contains(&"manifest.json"), "{files:?}");
    assert!(files.contains(&config.as_str()), "{files:?}");
    assert!(server.healthy());
}

/// A tag moves, and that is what a tag is for. It is the one place this
/// registry's "a version never changes" rule does not apply — what
/// never changes is the *manifest*, which is addressed by its digest,
/// and both remain pullable by digest after the tag has moved on.
#[test]
fn a_tag_moves_and_the_manifest_it_left_is_still_there() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-retag");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    let config = push_blob(&server, repo, &admin, b"config");
    let first_layer = push_blob(&server, repo, &admin, b"first");
    let second_layer = push_blob(&server, repo, &admin, b"second");

    let first = manifest(&config, &[(&first_layer, 5)]);
    let second = manifest(&config, &[(&second_layer, 6)]);
    assert_ne!(first, second);

    assert_eq!(
        req(
            "PUT",
            &format!("{b}/{repo}/manifests/latest"),
            &admin,
            Some(&first)
        )
        .status,
        201
    );
    assert_eq!(
        req(
            "PUT",
            &format!("{b}/{repo}/manifests/latest"),
            &admin,
            Some(&second)
        )
        .status,
        201,
        "re-tagging was refused, and a tag that cannot move is not a tag"
    );

    let r = req("GET", &format!("{b}/{repo}/manifests/latest"), &admin, None);
    assert_eq!(r.body, second, "the tag did not move");

    // The manifest the tag left is still addressable by its digest,
    // which is what a lockfile-shaped deployment pins.
    let r = req(
        "GET",
        &format!("{b}/{repo}/manifests/{}", sha256(&first)),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, first);

    // Exactly one tag, not two.
    let r = req("GET", &format!("{b}/{repo}/tags/list"), &admin, None);
    let tags = r.json();
    assert_eq!(tags["tags"].as_array().map(|a| a.len()), Some(1), "{tags}");

    // Deleting the tag is allowed; deleting a manifest by digest is
    // not, because it may be referenced by tags the caller cannot see.
    assert_eq!(
        req(
            "DELETE",
            &format!("{b}/{repo}/manifests/latest"),
            &admin,
            None
        )
        .status,
        202
    );
    assert_eq!(
        req("GET", &format!("{b}/{repo}/manifests/latest"), &admin, None).status,
        404
    );
    let r = req(
        "DELETE",
        &format!("{b}/{repo}/manifests/{}", sha256(&second)),
        &admin,
        None,
    );
    assert_eq!(r.status, 405);
    assert_eq!(code(&r), "UNSUPPORTED");
    assert!(server.healthy());
}

/// A tag is case-sensitive, as the distribution spec and every client
/// say: `V1` and `v1` are two tags. Every other ecosystem's versions are
/// matched case-insensitively here, and the OCI door inherited that, so
/// pushing `app:V1` silently moved `app:v1` — somebody's deployment
/// pinned to `v1` then pulled a different image.
#[test]
fn tags_that_differ_only_in_case_are_two_tags() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-tag-case");
    let admin = acme(&server);
    let repo = "acme/cased";
    let b = v2(&server);
    let config = push_blob(&server, repo, &admin, b"config");
    let lower_layer = push_blob(&server, repo, &admin, b"lower");
    let upper_layer = push_blob(&server, repo, &admin, b"UPPER");
    let lower = manifest(&config, &[(&lower_layer, 5)]);
    let upper = manifest(&config, &[(&upper_layer, 5)]);

    for (tag, body) in [("v1", &lower), ("V1", &upper)] {
        let r = req(
            "PUT",
            &format!("{b}/{repo}/manifests/{tag}"),
            &admin,
            Some(body),
        );
        assert_eq!(r.status, 201, "{tag}: {}", r.text());
    }
    let r = req("GET", &format!("{b}/{repo}/manifests/v1"), &admin, None);
    assert_eq!(r.body, lower, "pushing V1 moved v1");
    let r = req("GET", &format!("{b}/{repo}/manifests/V1"), &admin, None);
    assert_eq!(r.body, upper);
    let r = req("GET", &format!("{b}/{repo}/tags/list"), &admin, None);
    let mut tags: Vec<String> = r.json()["tags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_string())
        .collect();
    tags.sort();
    assert_eq!(tags, ["V1", "v1"]);
    // A tag nobody pushed, differing only in case, is not found.
    let r = req("GET", &format!("{b}/{repo}/manifests/V2"), &admin, None);
    assert_eq!(r.status, 404);
    assert!(server.healthy());
}

/// Containers switched off answer 404 to somebody who has authenticated,
/// for everything — the same answer as a repository that is not there.
#[test]
fn a_registry_nobody_enabled_answers_for_nothing() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-off");
    let admin = server.bootstrap("acme");
    // The bootstrap switched it on; this is the install that switched it
    // off again.
    let (status, _) = server.req(
        "PUT",
        "/api/v1/ecosystems",
        &admin,
        Some(serde_json::json!({ "ecosystem": "oci", "mode": "off" })),
    );
    assert_eq!(status, 200);
    let b = v2(&server);

    for (method, path) in [
        ("GET", "acme/service/tags/list"),
        ("GET", "acme/service/manifests/latest"),
        ("POST", "acme/service/blobs/uploads/"),
        ("GET", "service/tags/list"),
        ("GET", "not/a/shape"),
    ] {
        let r = req(method, &format!("{b}/{path}"), &admin, Some(b""));
        assert_eq!(r.status, 404, "{method} {path} answered while oci was off");
    }
    let (_, listed) = server.get("/api/v1/packages", &admin);
    assert_eq!(
        listed["packages"].as_array().map(|a| a.len()),
        Some(0),
        "a push reached a registry that was off: {listed}"
    );

    common::enable(&server, &admin, "oci");
    let r = req(
        "POST",
        &format!("{b}/acme/service/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 202, "switched on, and still refusing");
    assert!(server.healthy());
}

/// An abandoned upload leaves blocks nothing references, and they are
/// **invisible** to the ordinary blob sweep: a session's blocks have no
/// `package_blobs` row, and that table is what the sweep walks. Without
/// this collector they would sit in the bucket for ever — uncounted by
/// the storage figure, which counts blobs, and unfound by the sweep,
/// which counts the same.
///
/// The second half is the one that needs the care. Content-addressing
/// means a block a dead session wrote may be *exactly* the block a
/// finished blob deduped against, so each is re-read immediately before
/// it goes.
#[test]
fn an_abandoned_upload_is_collected_and_a_block_somebody_shares_is_not() {
    use skein_store::ObjectStore;

    let bucket = Minio::shared().bucket("oci-e2e");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("oci-upload-gc")
        .env("SKEIN_GC_INTERVAL_SECS", "1")
        // Only the session sweep is under test, and its window is its
        // own. An ordinary blob window of zero would let a tick land
        // between the kept layer's upload and the manifest that names
        // it, and take a publish in flight.
        .env("SKEIN_GC_GRACE_SECS", "3600")
        .start();
    let admin = acme(&server);
    let b = v2(&server);

    // One layer that becomes a real blob, and one that is only ever a
    // dead session's.
    let shared = b"a base layer two things want".to_vec();
    let orphan = b"bytes nobody ever finished uploading".to_vec();
    let shared_digest = push_blob(&server, "acme/kept", &admin, &shared);
    // …and *tagged*, which is what makes it a blob somebody is using
    // rather than a layer nobody ever referenced. A pushed layer with
    // no manifest is abandoned, and the ordinary blob sweep is right to
    // take it — which this test found out, in stratum-core, by leaving
    // it untagged.
    let config = push_blob(&server, "acme/kept", &admin, b"{}");
    assert_eq!(
        req(
            "PUT",
            &format!("{b}/acme/kept/manifests/v1"),
            &admin,
            Some(&manifest(&config, &[(&shared_digest, shared.len())]))
        )
        .status,
        201
    );

    // Two abandoned sessions: one carrying bytes nobody else has, one
    // carrying the very bytes the finished blob is made of.
    for bytes in [&orphan, &shared] {
        let r = req(
            "POST",
            &format!("{b}/acme/abandoned/blobs/uploads/"),
            &admin,
            Some(b""),
        );
        assert_eq!(r.status, 202);
        let url = format!(
            "{}{}",
            server.base,
            r.header("location").expect("a location")
        );
        assert_eq!(req("PATCH", &url, &admin, Some(bytes)).status, 202);
    }

    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let prefix = org.package_prefix();
    let store = ObjectStore::new(&bucket.base_url);
    // A layer under the block size is one block, so the block's own
    // digest is the layer's.
    let orphan_key = prefix.blob(&sha256(&orphan));
    let shared_key = prefix.blob(&shared_digest);
    assert!(store.get(&orphan_key).is_ok(), "the session wrote nothing");
    assert!(store.get(&shared_key).is_ok());

    // Age the sessions past the window. The window is a day, and a test
    // that waited one would not be a test.
    let mut pg = postgres::Client::connect(&server.db_url, postgres::NoTls).expect("connect");
    pg.execute(
        "UPDATE package_uploads SET updated_at = 0 WHERE org_id = $1",
        &[&org.id],
    )
    .expect("age the sessions");

    skein_testkit::wait_until(
        "the collector to take the abandoned session's block",
        std::time::Duration::from_secs(60),
        || store.get(&orphan_key).is_err(),
    );

    // …and the block the finished blob is made of is untouched, even
    // though a dead session had written the identical bytes.
    assert!(
        store.get(&shared_key).is_ok(),
        "a block a finished blob deduped against was taken by the sweep"
    );
    let r = req(
        "GET",
        &format!("{b}/acme/kept/blobs/{shared_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, shared);

    // The session rows are gone too, so the table does not grow with
    // every interrupted push.
    let left: i64 = pg
        .query_one(
            "SELECT COUNT(*) FROM package_uploads WHERE org_id = $1",
            &[&org.id],
        )
        .expect("count")
        .get(0);
    assert_eq!(left, 0, "{left} stale sessions were left");
    assert!(server.healthy());
}

/// A push that dies part-way through a layer **after** a whole block of
/// it has reached the bucket.
///
/// The block is in the store the moment it is cut, but in stratum-core
/// it was written into the session only when the request ended — so a
/// request that did not end well left a 16 MiB object that no session
/// and no blob named. The collector finds blocks through one or the
/// other, so it would never have found this one: every interrupted
/// `docker push` of a large layer leaked a block for ever.
#[test]
fn a_push_that_dies_after_a_whole_block_leaves_nothing_the_collector_cannot_find() {
    use skein_store::ObjectStore;
    use std::io::{Read, Write};

    let bucket = Minio::shared().bucket("oci-e2e");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("oci-partial-block")
        .env("SKEIN_GC_INTERVAL_SECS", "1")
        .start();
    let admin = acme(&server);
    let b = v2(&server);

    let r = req(
        "POST",
        &format!("{b}/acme/service/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 202);
    let location = r.header("location").expect("a location").to_string();

    // A whole block and then some, of a body that promised more still.
    const BLOCK: usize = 16 * 1024 * 1024;
    let sent: Vec<u8> = (0..BLOCK + 1024 * 1024)
        .map(|i| (i % 253) as u8 ^ 0x5a)
        .collect();
    let mut sock = std::net::TcpStream::connect(server.host()).expect("connect");
    write!(
        sock,
        "PATCH {location} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {admin}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        server.host(),
        sent.len() * 2
    )
    .unwrap();
    sock.write_all(&sent).unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut said = Vec::new();
    let _ = sock.read_to_end(&mut said);
    let said = String::from_utf8_lossy(&said);
    assert!(
        said.is_empty() || !said.starts_with("HTTP/1.1 2"),
        "a body that stopped part-way was accepted: {said}"
    );

    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let store = ObjectStore::new(&bucket.base_url);
    let block_key = org.package_prefix().blob(&sha256(&sent[..BLOCK]));
    assert!(
        store.get(&block_key).is_ok(),
        "the whole block never reached the bucket, so this test tests nothing"
    );

    // Abandon the session, as a client that gave up does.
    let mut pg = postgres::Client::connect(&server.db_url, postgres::NoTls).expect("connect");
    pg.execute(
        "UPDATE package_uploads SET updated_at = 0 WHERE org_id = $1",
        &[&org.id],
    )
    .expect("age the sessions");
    skein_testkit::wait_until(
        "the collector to take the dead push's block",
        std::time::Duration::from_secs(60),
        || store.get(&block_key).is_err(),
    );
    assert!(server.healthy());
}

/// A multi-platform image is an index naming platform manifests, each
/// pushed **by digest** and so with no tag of its own — which is how
/// `docker buildx` and `docker manifest push` both push one. Its layers
/// are named by the platform manifests and by nothing else.
///
/// Recording only what the index names directly left every one of
/// those layers referenced by nothing, and the collector took them: the
/// image went on listing and resolving, and every pull of it failed at
/// the first layer.
#[test]
fn a_multi_platform_images_layers_live_as_long_as_its_tag() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-index-gc");
    let admin = acme(&server);
    let repo = "acme/multi";
    let b = v2(&server);

    let config = push_blob(&server, repo, &admin, b"{\"os\":\"linux\"}");
    let layer = push_blob(&server, repo, &admin, b"the only platform's layer");
    let child = manifest(&config, &[(&layer, 25)]);
    let child_digest = sha256(&child);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/{child_digest}"),
        &admin,
        Some(&child),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    let idx = index(&[(&child_digest, child.len())]);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/1"),
        &admin,
        Some(&idx),
    );
    assert_eq!(r.status, 201, "{}", r.text());

    let gc = || {
        let out = server
            .admin(&["admin", "gc", "--grace-secs", "0"])
            .expect("admin gc");
        serde_json::from_str::<serde_json::Value>(out.trim()).expect("json")
    };
    let swept = gc();
    assert_eq!(
        swept["blobs"], 0,
        "the collector took part of a tagged image: {swept}"
    );

    // Pulled the way a client pulls an index: the index by tag, the
    // platform manifest by digest, then its layers.
    let r = req("GET", &format!("{b}/{repo}/manifests/1"), &admin, None);
    assert_eq!(r.body, idx);
    assert_eq!(
        r.header("content-type"),
        Some("application/vnd.oci.image.index.v1+json")
    );
    let r = req(
        "GET",
        &format!("{b}/{repo}/manifests/{child_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.body, child);
    for (d, want) in [
        (&layer, &b"the only platform's layer"[..]),
        (&config, &b"{\"os\":\"linux\"}"[..]),
    ] {
        let r = req("GET", &format!("{b}/{repo}/blobs/{d}"), &admin, None);
        assert_eq!(r.status, 200, "the collector took {d} from a tagged image");
        assert_eq!(r.body, want);
    }

    // And the tag is what kept them: untagged, they go.
    assert_eq!(
        req("DELETE", &format!("{b}/{repo}/manifests/1"), &admin, None).status,
        202
    );
    let swept = gc();
    assert_eq!(
        swept["blobs"], 4,
        "the index, the platform manifest, its config and its layer: {swept}"
    );
    let r = req("HEAD", &format!("{b}/{repo}/blobs/{layer}"), &admin, None);
    assert_eq!(r.status, 404);
    assert!(server.healthy());
}

/// The verbs and shapes a client reaches that the happy path does not:
/// cancelling an upload, asking for a session that is not there, and
/// using a method a path does not answer.
///
/// Each of these is a real thing `docker` does — it cancels a session
/// when a push is interrupted, and it retries against a session id it
/// may have lost — and each has to answer in the shape a client reads
/// rather than falling through to something generic.
#[test]
fn the_session_verbs_answer_and_an_unknown_session_is_not_a_server_error() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-sessions");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    // Open one and cancel it, which is what an interrupted push does.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 202);
    assert_eq!(r.header("range"), Some("0-0"));
    let url = format!(
        "{}{}",
        server.base,
        r.header("location").expect("a location")
    );
    assert_eq!(req("DELETE", &url, &admin, None).status, 204);
    // …and cancelling it twice is a 404, not a 204: the second caller
    // is being told something different from the first.
    let r = req("DELETE", &url, &admin, None);
    assert_eq!(r.status, 404);
    assert_eq!(code(&r), "BLOB_UPLOAD_UNKNOWN");

    // A session id that was never issued, on each verb that takes one.
    let ghost = format!("{b}/{repo}/blobs/uploads/01NOSUCHSESSION");
    for (method, body) in [
        ("PATCH", Some(&b"bytes"[..])),
        ("PUT", Some(&b""[..])),
        ("DELETE", None),
    ] {
        let r = req(method, &ghost, &admin, body);
        assert_eq!(r.status, 404, "{method} on an unknown session");
        assert_eq!(code(&r), "BLOB_UPLOAD_UNKNOWN", "{method}");
    }

    // A verb a path does not answer. 405 and not 404: the path is real
    // and the method is wrong, and a client that read "not found" would
    // go looking for the repository.
    let r = req("POST", &format!("{b}/{repo}/tags/list"), &admin, Some(b""));
    assert_eq!(r.status, 405);
    assert_eq!(code(&r), "UNSUPPORTED");

    // A repository name that is not a legal one is refused on the name,
    // rather than answered as an absent repository.
    let r = req(
        "POST",
        &format!("{b}/acme/Service/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 404, "an uppercase repository name was accepted");
    assert_eq!(code(&r), "NAME_UNKNOWN");

    // A repository nobody pushed, one component or several.
    for name in ["service", "acme/nobody"] {
        let r = req("GET", &format!("{b}/{name}/tags/list"), &admin, None);
        assert_eq!(r.status, 404, "{name}");
        assert_eq!(code(&r), "NAME_UNKNOWN", "{name}");
    }

    // A PATCH reports how much the session holds, which is where a
    // client that resumes would resume from.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    let url = format!("{}{}", server.base, r.header("location").unwrap());
    let r = req("PATCH", &url, &admin, Some(b"0123456789"));
    assert_eq!(r.status, 202);
    assert_eq!(r.header("range"), Some("0-9"));
    let r = req("PATCH", &url, &admin, Some(b"abcde"));
    assert_eq!(r.header("range"), Some("0-14"));
    let r = req(
        "PUT",
        &format!("{url}?digest={}", sha256(b"0123456789abcde")),
        &admin,
        Some(b""),
    );
    assert_eq!(
        r.status,
        201,
        "two chunks did not make one blob: {}",
        r.text()
    );

    assert!(server.healthy());
}

/// A manifest pushed by digest alone has no tag: it is a blob, which is
/// how an index's platform members arrive. It is pullable by digest and
/// appears in no tag list, and the index that names it is accepted
/// because its members are already here.
#[test]
fn an_index_and_its_members_push_by_digest_and_leave_no_tag() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-index");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    let config = push_blob(&server, repo, &admin, b"{}");
    let layer = push_blob(&server, repo, &admin, b"a layer");
    let child = manifest(&config, &[(&layer, 7)]);
    let child_digest = sha256(&child);

    // By digest, so it gets no tag — exactly how a client pushes the
    // per-platform manifests of a multi-arch image.
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/{child_digest}"),
        &admin,
        Some(&child),
    );
    assert_eq!(r.status, 201, "pushing by digest: {}", r.text());
    assert_eq!(
        r.header("docker-content-digest"),
        Some(child_digest.as_str())
    );

    let idx = index(&[(&child_digest, child.len())]);
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/multi"),
        &admin,
        Some(&idx),
    );
    assert_eq!(
        r.status,
        201,
        "the index was refused though its member is here: {}",
        r.text()
    );

    // Only the index is tagged. The member is reachable by digest and
    // by nothing else, which is what "no tag" means.
    let r = req("GET", &format!("{b}/{repo}/tags/list"), &admin, None);
    let tags = r.json();
    assert_eq!(tags["tags"].as_array().map(|a| a.len()), Some(1), "{tags}");
    assert_eq!(tags["tags"][0], "multi");
    let r = req(
        "GET",
        &format!("{b}/{repo}/manifests/{child_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, child);

    // An index naming a member nobody pushed says MANIFEST_UNKNOWN, not
    // BLOB_UNKNOWN. A client that read the second goes looking for a
    // layer, and there is no layer to find.
    let ghost = format!("sha256:{}", "d".repeat(64));
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/broken"),
        &admin,
        Some(&index(&[(&ghost, 10)])),
    );
    assert_eq!(r.status, 404);
    assert_eq!(code(&r), "MANIFEST_UNKNOWN");

    // An index naming, as a member, a blob that is not a manifest at
    // all. It is here, so it is not *unknown*; it is simply not what
    // the index says it is.
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/confused"),
        &admin,
        Some(&index(&[(&layer, 7)])),
    );
    assert_eq!(r.status, 400, "{}", r.text());
    assert_eq!(code(&r), "MANIFEST_INVALID");

    // A manifest naming a digest this registry could never have written
    // is malformed rather than absent.
    let nonsense = serde_json::json!({
        "schemaVersion": 2,
        "config": { "digest": "md5:short", "size": 1 },
        "layers": []
    })
    .to_string()
    .into_bytes();
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/nonsense2"),
        &admin,
        Some(&nonsense),
    );
    assert_eq!(r.status, 400);
    assert_eq!(code(&r), "MANIFEST_INVALID");

    // Deleting a tag that was never there, and a repository that was
    // never there — both 404, neither a 500.
    for (method, path) in [
        ("DELETE", format!("{b}/{repo}/manifests/never")),
        ("GET", format!("{b}/acme/ghost/tags/list")),
        ("GET", format!("{b}/acme/ghost/manifests/latest")),
        ("DELETE", format!("{b}/acme/ghost/manifests/latest")),
    ] {
        assert_eq!(
            req(method, &path, &admin, None).status,
            404,
            "{method} {path}"
        );
    }
    assert!(server.healthy());
}

/// A cross-repository mount: "you hold these bytes under another name;
/// hold them under this one too".
///
/// `docker manifest push` builds a multi-platform index in one
/// repository out of images pushed to others, mounts every blob first,
/// and treats the spec's 202 fallback as a failure — so a registry that
/// never mounts cannot take a `docker manifest push` into a new
/// repository at all.
#[test]
fn a_blob_the_registry_holds_mounts_into_another_repository() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-mount");
    let admin = acme(&server);
    let (_, reader) = server.person(&admin, "rita", "reader", &["package:read"]);
    let b = v2(&server);

    let layer = push_blob(&server, "team/app", &admin, b"a layer to share");
    let r = req(
        "POST",
        &format!("{b}/team/other/blobs/uploads/?mount={layer}&from=team/app"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    assert_eq!(r.header("docker-content-digest"), Some(layer.as_str()));
    assert_eq!(
        r.header("location"),
        Some(format!("/v2/team/other/blobs/{layer}").as_str())
    );
    let r = req(
        "GET",
        &format!("{b}/team/other/blobs/{layer}"),
        &admin,
        None,
    );
    assert_eq!(r.body, b"a layer to share");

    // Encoded the way some clients send it.
    let enc = layer.replace(':', "%3A");
    let r = req(
        "POST",
        &format!("{b}/team/other/blobs/uploads/?from=team/app&mount={enc}"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 201, "{}", r.text());

    // Something we do not hold is the spec's fallback, an ordinary
    // session — never a mount of nothing.
    let absent = format!("sha256:{}", "c".repeat(64));
    for q in [
        format!("mount={absent}&from=team/app"),
        "mount=not-a-digest&from=team/app".to_string(),
    ] {
        let r = req(
            "POST",
            &format!("{b}/team/other/blobs/uploads/?{q}"),
            &admin,
            Some(b""),
        );
        assert_eq!(r.status, 202, "{q}: {}", r.text());
        assert!(r.header("location").unwrap().contains("/blobs/uploads/"));
    }

    // A mount is a write, and a reader may not make one.
    let r = req(
        "POST",
        &format!("{b}/team/other/blobs/uploads/?mount={layer}&from=team/app"),
        &reader,
        Some(b""),
    );
    assert_eq!(r.status, 403);
    assert_eq!(code(&r), "DENIED");
    assert!(server.healthy());
}

/// Paths a client reaches that the happy path does not, each answering
/// in its own shape rather than falling through to something generic —
/// and what an edge may keep of any of it.
#[test]
fn the_remaining_doors_answer_for_themselves() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-edges");
    let admin = acme(&server);
    let repo = "acme/service";
    let b = v2(&server);

    // Finishing an upload with no `?digest=` at all. The spec puts the
    // digest there and a session cannot be closed without one; saying
    // so beats a 500 or a silent success on bytes nobody named.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    let url = format!(
        "{}{}",
        server.base,
        r.header("location").expect("a location")
    );
    assert_eq!(req("PATCH", &url, &admin, Some(b"bytes")).status, 202);
    for query in ["", "?other=1", "?digest=not-a-digest"] {
        let r = req("PUT", &format!("{url}{query}"), &admin, Some(b""));
        assert_eq!(r.status, 400, "finishing with {query:?}");
        assert_eq!(code(&r), "DIGEST_INVALID", "{query:?}");
    }

    // A manifest is a blob too, and it is stored as **one object**
    // rather than in blocks — so fetching one through the blobs route
    // is the only thing that exercises the single-object read path. A
    // client does exactly this when it resolves an index's member.
    let config = push_blob(&server, repo, &admin, b"{}");
    let layer = push_blob(&server, repo, &admin, b"a layer");
    let doc = manifest(&config, &[(&layer, 7)]);
    assert_eq!(
        req(
            "PUT",
            &format!("{b}/{repo}/manifests/v1"),
            &admin,
            Some(&doc)
        )
        .status,
        201
    );
    let manifest_digest = sha256(&doc);
    let r = req(
        "GET",
        &format!("{b}/{repo}/blobs/{manifest_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200, "a manifest was not readable as a blob");
    assert_eq!(r.body, doc);
    assert_eq!(
        r.header("docker-content-digest"),
        Some(manifest_digest.as_str())
    );

    // HEAD on a manifest by tag: the headers without the body, which is
    // how a client decides whether it already has the image.
    let r = req("HEAD", &format!("{b}/{repo}/manifests/v1"), &admin, None);
    assert_eq!(r.status, 200);
    assert!(r.body.is_empty(), "a HEAD carried a body");
    assert_eq!(
        r.header("docker-content-digest"),
        Some(manifest_digest.as_str())
    );
    assert_eq!(
        r.header("content-type"),
        Some("application/vnd.oci.image.manifest.v1+json")
    );
    assert_eq!(
        r.header("content-length"),
        Some(doc.len().to_string().as_str()),
        "a HEAD must say how long the GET would be"
    );
    // …and HEAD on a tag that is not there.
    assert_eq!(
        req("HEAD", &format!("{b}/{repo}/manifests/never"), &admin, None).status,
        404
    );

    // Nothing here is for an edge to keep. A shared cache in front of
    // Skein that keys without the credential would serve an answer
    // marked `public` to the next person who asked, and a held 404
    // would answer docker's HEAD after an upload with the absence from
    // before it.
    let absent = format!("sha256:{}", "0".repeat(64));
    let r = req("HEAD", &format!("{b}/{repo}/blobs/{absent}"), &admin, None);
    assert_eq!(
        (r.status, r.header("cache-control")),
        (404, Some("no-store"))
    );
    let r = req("GET", &format!("{b}/{repo}/manifests/v1"), &admin, None);
    assert_eq!(
        (r.status, r.header("cache-control")),
        (200, Some("private, no-cache"))
    );
    let r = req("HEAD", &format!("{b}/{repo}/blobs/{layer}"), &admin, None);
    assert_eq!(
        (r.status, r.header("cache-control")),
        (200, Some("private, max-age=31536000, immutable"))
    );
    assert_eq!(r.header("content-length"), Some("7"));
    let r = req("GET", &format!("{b}/"), &admin, None);
    assert_eq!(r.header("cache-control"), Some("private, no-cache"));

    // A body larger than any manifest is. The limit is the artifact
    // ceiling, and a document that big is not a manifest whatever it
    // parses as.
    //
    // Sent over a raw socket rather than through the HTTP client, and
    // the reason is the failure this replaced in stratum-core. The
    // server answers 413 and closes its read half while the client is
    // still writing, so the client's next write fails — and an HTTP
    // client treats that as a transport error and throws away the
    // perfectly good response it has already received. The test then
    // passed or failed depending on how loaded the machine was.
    //
    // Writing by hand, a failed write is simply where we stop writing;
    // the 413 is already in the receive buffer and is still there to be
    // read.
    {
        use std::io::{Read, Write};
        let mut sock = std::net::TcpStream::connect(server.host()).expect("connect");
        const HUGE: usize = 129 * 1024 * 1024;
        write!(
            sock,
            "PUT /v2/{repo}/manifests/huge HTTP/1.1\r\nHost: {}\r\n\
             Authorization: Bearer {admin}\r\nContent-Type: application/json\r\n\
             Content-Length: {HUGE}\r\nConnection: close\r\n\r\n",
            server.host()
        )
        .unwrap();
        let chunk = vec![b' '; 1024 * 1024];
        let mut sent = 0;
        while sent < HUGE {
            match sock.write(&chunk[..chunk.len().min(HUGE - sent)]) {
                Ok(0) => break,
                Ok(n) => sent += n,
                Err(_) => break,
            }
        }
        let _ = sock.shutdown(std::net::Shutdown::Write);
        let mut said = String::new();
        let _ = sock.read_to_string(&mut said);
        assert!(
            said.starts_with("HTTP/1.1 413 "),
            "an oversized manifest was not refused: {said}"
        );
    }
    assert!(server.healthy());
}

/// Collecting a blob that was stored as **blocks**, and keeping the one
/// block another image is still made of.
///
/// The abandoned-session test above covers a dead session's blocks.
/// This is the other half and the one that runs far more often: an
/// image is deleted, its layer is no longer referenced by any manifest,
/// and the ordinary package sweep has to take it. A layer over the block
/// size is not one object, so deleting the blob's own key would remove
/// something that was never written and leave the real bytes in the
/// bucket for ever.
///
/// The care is in the sharing. Two images built on one base layer share
/// that layer's blocks byte for byte, so the collector re-reads each
/// block's references immediately before deleting it. Without that,
/// deleting either image would silently break the other.
#[test]
fn a_deleted_images_blocks_are_collected_and_a_shared_one_survives() {
    use skein_store::ObjectStore;

    let bucket = Minio::shared().bucket("oci-e2e");
    let server = Server::builder(env!("CARGO_BIN_EXE_skein"), &bucket.base_url)
        .db_hint("oci-package-gc")
        .env("SKEIN_GC_INTERVAL_SECS", "1")
        // Longer than the pushes below take, and no longer. At zero, a
        // layer uploaded and not yet named by a manifest is exactly what
        // the sweep collects — a publish in flight, which the grace
        // window exists to protect — so on a slow CI runner the sweep
        // took the first image's layer between its upload and its
        // manifest, and the manifest was refused as naming a blob never
        // pushed. The deleted image's blocks are still collected well
        // inside the deadline below.
        .env("SKEIN_GC_GRACE_SECS", "20")
        .start();
    let admin = acme(&server);
    let b = v2(&server);

    // A base layer exactly one block long, so the two images' first
    // block is the identical object, and a tail each that is its own.
    const BLOCK: usize = 16 * 1024 * 1024;
    let base = vec![0xA5u8; BLOCK];
    let mut going = base.clone();
    going.extend_from_slice(b"the tail of the image that goes");
    let mut staying = base.clone();
    staying.extend_from_slice(b"the tail of the image that stays");

    for (repo, layer) in [("acme/going", &going), ("acme/staying", &staying)] {
        let digest = push_blob(&server, repo, &admin, layer);
        let config = push_blob(&server, repo, &admin, b"{}");
        let r = req(
            "PUT",
            &format!("{b}/{repo}/manifests/v1"),
            &admin,
            Some(&manifest(&config, &[(&digest, layer.len())])),
        );
        assert_eq!(r.status, 201, "{}", r.text());
    }

    let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
    let org = skein_control::registry::the_org(&db)
        .expect("lookup")
        .expect("org");
    let prefix = org.package_prefix();
    let store = ObjectStore::new(&bucket.base_url);
    let shared_key = prefix.blob(&sha256(&base));
    let going_tail = prefix.blob(&sha256(&going[BLOCK..]));
    let staying_tail = prefix.blob(&sha256(&staying[BLOCK..]));
    for (what, key) in [
        ("the shared base block", &shared_key),
        ("the going image's tail", &going_tail),
        ("the staying image's tail", &staying_tail),
    ] {
        assert!(store.get(key).is_ok(), "{what} was never written");
    }

    // Delete one image. Its layer is now referenced by no manifest.
    let (status, list) = server.get("/api/v1/packages?ecosystem=oci", &admin);
    assert_eq!(status, 200, "{list}");
    let going_id = list["packages"]
        .as_array()
        .expect("a package list")
        .iter()
        .find(|p| p["name"] == "acme/going")
        .and_then(|p| p["id"].as_str())
        .unwrap_or_else(|| panic!("no package named acme/going: {list}"))
        .to_string();
    let (status, out) = server.req(
        "DELETE",
        &format!("/api/v1/packages/{going_id}"),
        &admin,
        None,
    );
    assert_eq!(status, 204, "deleting the package: {out}");

    skein_testkit::wait_until(
        "the collector to take the deleted image's blocks",
        std::time::Duration::from_secs(60),
        || store.get(&going_tail).is_err(),
    );
    assert!(
        store.get(&shared_key).is_ok(),
        "the block the other image is made of went with it"
    );
    assert!(store.get(&staying_tail).is_ok());

    // The proof that matters: the image nobody deleted still pulls, all
    // the way down to its bytes.
    let r = req(
        "GET",
        &format!("{b}/acme/staying/blobs/{}", sha256(&staying)),
        &admin,
        None,
    );
    assert_eq!(r.status, 200, "the surviving image lost its layer");
    assert_eq!(r.body.len(), staying.len());
    assert_eq!(r.body, staying, "the surviving image's bytes changed");

    assert!(server.healthy());
}

/// A blob a push is building on is not collected under it, however long
/// ago it was first stored.
///
/// `docker push` asks `HEAD /v2/<repo>/blobs/<digest>` for every layer,
/// skips each one answered 200, and PUTs the manifest last. Content
/// addressing means the layer it skips may be one an untagged image left
/// behind long ago — and the collector's grace used to run from when
/// those bytes were *first* stored, so a layer stored a week ago and
/// unreferenced since was collectable at the very moment a push was
/// relying on it. A sweep between the HEAD and the manifest took it: the
/// push failed, or, if the manifest's own check had already passed, was
/// accepted naming a layer that was no longer there.
///
/// Every way a client builds on bytes it did not send this time is here:
/// a HEAD of a blob, a cross-repository mount, a HEAD of a manifest by
/// digest (how a multi-platform push checks an index's members), and an
/// upload that finishes on a digest already stored. What nobody touched
/// is collected by the same pass, which is what proves the pass ran.
#[test]
fn a_blob_a_push_is_building_on_is_not_collected_however_old_it_is() {
    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-gc-touch");
    let admin = acme(&server);
    let b = v2(&server);
    let old = "acme/old";
    let new = "acme/new";

    let config_bytes = &b"{\"os\":\"linux\"}"[..];
    let headed_bytes = &b"a layer the next push asks about"[..];
    let mounted_bytes = &b"a layer the next push mounts"[..];
    let resent_bytes = &b"a layer the next push sends again"[..];
    let config = push_blob(&server, old, &admin, config_bytes);
    let headed = push_blob(&server, old, &admin, headed_bytes);
    let mounted = push_blob(&server, old, &admin, mounted_bytes);
    let resent = push_blob(&server, old, &admin, resent_bytes);
    let forgotten = push_blob(&server, old, &admin, b"a layer nobody asks about again");
    let image = manifest(
        &config,
        &[
            (&headed, 32),
            (&mounted, 28),
            (&resent, 33),
            (&forgotten, 31),
        ],
    );
    let r = req(
        "PUT",
        &format!("{b}/{old}/manifests/v1"),
        &admin,
        Some(&image),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    // A platform manifest pushed by digest alone, the way a
    // multi-platform push sends an index's members.
    let member = manifest(&config, &[(&headed, 32)]);
    let member_digest = sha256(&member);
    let r = req(
        "PUT",
        &format!("{b}/{old}/manifests/{member_digest}"),
        &admin,
        Some(&member),
    );
    assert_eq!(r.status, 201, "{}", r.text());

    // Untag the image: every one of those blobs is now referenced by
    // nothing — and make them old, stored two hours ago.
    assert_eq!(
        req("DELETE", &format!("{b}/{old}/manifests/v1"), &admin, None).status,
        202
    );
    let org = {
        let db = skein_control::ControlDb::open(&server.db_url).expect("open control db");
        skein_control::registry::the_org(&db)
            .expect("lookup")
            .expect("org")
    };
    let mut pg = postgres::Client::connect(&server.db_url, postgres::NoTls).expect("connect");
    let aged = pg
        .execute(
            "UPDATE package_blobs SET created_at = created_at - $2, \
                                      touched_at = touched_at - $2 \
             WHERE org_id = $1",
            &[&org.id, &(2 * 3600 * 1000i64)],
        )
        .expect("age the blobs");
    assert_eq!(
        aged, 7,
        "the config, four layers, the image and the member manifest"
    );

    // The next push, as a client makes it: it asks about what it could
    // skip, mounts what another repository holds, sends one layer again,
    // and checks the index's member by digest.
    for d in [&config, &headed] {
        let r = req("HEAD", &format!("{b}/{old}/blobs/{d}"), &admin, None);
        assert_eq!(r.status, 200, "HEAD {d}");
    }
    let r = req(
        "POST",
        &format!("{b}/{new}/blobs/uploads/?mount={mounted}&from={old}"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 201, "mounting: {}", r.text());
    assert_eq!(push_blob(&server, new, &admin, resent_bytes), resent);
    let r = req(
        "HEAD",
        &format!("{b}/{old}/manifests/{member_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200, "HEAD the member by digest");

    // The collector runs between those answers and the manifest, with
    // an hour's grace.
    let out = server
        .admin(&["admin", "gc", "--grace-secs", "3600"])
        .expect("admin gc");
    let swept: serde_json::Value = serde_json::from_str(out.trim()).expect("json");
    assert_eq!(
        swept["blobs"], 2,
        "only the layer nobody asked about and the untagged image's manifest \
         were idle for the grace; the rest were in use a moment ago: {swept}"
    );
    let r = req(
        "HEAD",
        &format!("{b}/{old}/blobs/{forgotten}"),
        &admin,
        None,
    );
    assert_eq!(r.status, 404, "the pass collected nothing at all");

    // The push finishes: an image and an index naming only what the
    // client was told was here.
    let image2 = manifest(&config, &[(&headed, 32), (&mounted, 28), (&resent, 33)]);
    let r = req(
        "PUT",
        &format!("{b}/{new}/manifests/v2"),
        &admin,
        Some(&image2),
    );
    assert_eq!(
        r.status,
        201,
        "the manifest names a layer the registry said it held: {}",
        r.text()
    );
    let idx = index(&[(&member_digest, member.len())]);
    let r = req(
        "PUT",
        &format!("{b}/{new}/manifests/multi"),
        &admin,
        Some(&idx),
    );
    assert_eq!(r.status, 201, "{}", r.text());

    // …and pulls back byte for byte, every blob of it.
    let r = req("GET", &format!("{b}/{new}/manifests/v2"), &admin, None);
    assert_eq!(r.body, image2);
    let r = req(
        "GET",
        &format!("{b}/{new}/manifests/{member_digest}"),
        &admin,
        None,
    );
    assert_eq!(r.body, member);
    for (d, want) in [
        (&config, config_bytes),
        (&headed, headed_bytes),
        (&mounted, mounted_bytes),
        (&resent, resent_bytes),
    ] {
        let r = req("GET", &format!("{b}/{new}/blobs/{d}"), &admin, None);
        assert_eq!(r.status, 200, "{d} was collected under the push");
        assert_eq!(r.body, want, "{d} came back different");
    }
    assert!(server.healthy());
}

/// An upload that stops part-way through its own declared body.
///
/// A `docker push` over a dropped connection is exactly this: the
/// headers promise N bytes and fewer arrive. The door has to refuse it
/// rather than store what it got — a short layer written as if it were
/// whole is a blob whose digest will never match, and the client would
/// be told its own bytes were wrong.
///
/// Raw sockets rather than an HTTP client, because every client worth
/// the name refuses to send a body shorter than the length it
/// announced, which is precisely the request being tested.
#[test]
fn an_upload_that_stops_part_way_is_refused_and_the_registry_keeps_serving() {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let bucket = Minio::shared().bucket("oci-e2e");
    let server = spawn(&bucket.base_url, "oci-truncated");
    let admin = acme(&server);
    let b = v2(&server);
    let repo = "acme/service";

    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 202);
    let location = r
        .header("location")
        .expect("a Location to write to")
        .to_string();

    let mut sock = TcpStream::connect(server.host()).expect("connect");
    write!(
        sock,
        "PATCH {location} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {admin}\r\n\
         Content-Length: 4096\r\nConnection: close\r\n\r\n",
        server.host()
    )
    .unwrap();
    sock.write_all(b"only these few bytes, not four thousand")
        .unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut said = Vec::new();
    let _ = sock.read_to_end(&mut said);
    let said = String::from_utf8_lossy(&said);
    assert!(
        said.is_empty() || !said.starts_with("HTTP/1.1 2"),
        "a body that stopped part-way was accepted: {said}"
    );

    // The same truncation on the *final* PUT, which is a different call
    // site: a monolithic push carries the whole layer on the PUT rather
    // than on a PATCH, so a client that dies there reaches the other
    // half of the same drain.
    let r = req(
        "POST",
        &format!("{b}/{repo}/blobs/uploads/"),
        &admin,
        Some(b""),
    );
    assert_eq!(r.status, 202);
    let location = r
        .header("location")
        .expect("a Location to write to")
        .to_string();
    let mut sock = TcpStream::connect(server.host()).expect("connect");
    write!(
        sock,
        "PUT {location}?digest=sha256:{} HTTP/1.1\r\nHost: {}\r\n\
         Authorization: Bearer {admin}\r\nContent-Length: 4096\r\n\
         Connection: close\r\n\r\n",
        "0".repeat(64),
        server.host()
    )
    .unwrap();
    sock.write_all(b"again, fewer bytes than promised").unwrap();
    sock.shutdown(std::net::Shutdown::Write).unwrap();
    let mut said = Vec::new();
    let _ = sock.read_to_end(&mut said);
    let said = String::from_utf8_lossy(&said);
    assert!(
        said.is_empty() || !said.starts_with("HTTP/1.1 2"),
        "a final PUT that stopped part-way was accepted: {said}"
    );

    // Nothing of it was kept, and the registry is still a registry: a
    // whole push through the same door still works.
    let layer = b"a layer that arrives in full".to_vec();
    let digest = push_blob(&server, repo, &admin, &layer);
    let config = push_blob(&server, repo, &admin, b"{}");
    let r = req(
        "PUT",
        &format!("{b}/{repo}/manifests/v1"),
        &admin,
        Some(&manifest(&config, &[(&digest, layer.len())])),
    );
    assert_eq!(r.status, 201, "{}", r.text());
    let r = req("GET", &format!("{b}/{repo}/blobs/{digest}"), &admin, None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body, layer);
    assert!(server.healthy());
}
