//! The OCI distribution door, at `/v2/`.
//!
//! ## It cannot live under a prefix
//!
//! A container client parses `host/path/image` as registry `host` and
//! repository `path/image`, then talks to `https://host/v2/…`. There is
//! nowhere to put a base path, so `/v2/` is a reserved top-level segment
//! and Skein has to be served at the root of a host. The organization is
//! the install, so the repository is the **whole path**: `docker push
//! skein.example.com/team/service:1.0` pushes repository `team/service`.
//!
//! ## The refusals are ordered, and the order is the point
//!
//! See [`registry_door`]: no credential that authenticates is a 401 with
//! a `Basic` challenge before anything else is looked at — which is what
//! makes `docker login` work — then a person whose role or token does
//! not reach is a 403 in OCI's own shape (`DENIED`, which docker prints
//! as `denied: <the sentence>`), then containers being switched off is a
//! 404, and only then is the path read.
//!
//! ## A layer never becomes resident
//!
//! `docker push` sends a layer as one request body, and a layer is
//! routinely hundreds of megabytes — far past `blobs::MAX_ARTIFACT`,
//! which exists because `ObjectStore::put` takes a slice. So the body is
//! read as a **stream** and cut into blocks of `blobs::BLOCK` as it
//! arrives; nothing larger than one block is ever held, on the way in or
//! on the way out.
//!
//! Each block is written into the upload session as soon as it is in
//! the store, so a push that dies part-way leaves blocks the collector
//! can find — through the session, once it is abandoned — rather than
//! objects nothing anywhere remembers.
//!
//! The digest is checked by re-reading the blocks at finalise rather
//! than by carrying a hasher across requests. A session may be written
//! to over several requests and finished by a different `skein` process
//! behind the same load balancer — the state lives in PostgreSQL, not in
//! this process — and `sha2` does not serialise a partial hash. One
//! extra read of the layer is the price, and it is paid once per push
//! rather than per pull.
//!
//! ## What is checked before a manifest is accepted
//!
//! Every blob it names must already be here — and, for an index, every
//! blob its member manifests name. A registry that took a manifest
//! naming a layer nobody uploaded would serve an image that cannot be
//! pulled, and the client's error would be about the layer rather than
//! about the push that was wrong.

use crate::api::{internal, registry_door};
use crate::app::SharedState;
use crate::authx;
use crate::registry::{blobs, oci};
use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use futures_util::StreamExt;
use skein_control::auth::{Principal, Scope};
use skein_control::packages::{self, Block, Ecosystem, License, PackageFile};
use skein_control::registry::Org;

/// A container client reads `errors[0].code` and prints
/// `errors[0].message`.
fn oci_error(status: StatusCode, code: &str, msg: impl Into<String>) -> Response {
    (status, Json(oci::error_body(code, &msg.into()))).into_response()
}

/// OCI's shape of refusal, as [`registry_door::Refusal`] wants it. The
/// one the shared door makes is a 403 for a role or token that does not
/// reach, and docker prints `DENIED` as `denied: <message>`.
fn refusal(status: StatusCode, msg: String) -> Response {
    let code = match status {
        StatusCode::FORBIDDEN => "DENIED",
        _ => "UNSUPPORTED",
    };
    oci_error(status, code, msg)
}

/// `GET /v2/` — the version probe every client makes first.
///
/// Its whole purpose is to tell a client this is a v2 registry and how
/// to authenticate. A 401 with a `WWW-Authenticate: Basic` challenge is
/// what makes `docker login` work at all; a credential that verifies
/// gets the 200. Nothing is public, so nothing — not even whether
/// containers are switched on — is said to somebody who has not said who
/// they are.
pub async fn root(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    match authx::principal(&state.db, &headers, authx::Challenge::Basic) {
        Ok(Some(_)) => (
            StatusCode::OK,
            [
                ("docker-distribution-api-version", "registry/2.0"),
                (header::CONTENT_TYPE.as_str(), "application/json"),
            ],
            "{}",
        )
            .into_response(),
        // No credential at all, and a credential that does not verify,
        // both get the challenge — `docker login` reads it and asks
        // again, where a 200 would have it believe it was in.
        Ok(None) => authx::unauthorized(authx::Challenge::Basic),
        Err(r) => r,
    }
}

/// Every `/v2/*` request except the root probe.
pub async fn any(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    method: Method,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // Who is asking, before anything about the path is read: an
    // anonymous caller learns nothing, not even which paths are shaped
    // like a repository.
    let writing = matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    let need = if writing {
        Scope::PackageWrite
    } else {
        Scope::PackageRead
    };
    // A push is a publish in docker's words; a DELETE here removes a tag.
    let what = match (writing, &method) {
        (true, &Method::DELETE) => Some("delete tags in this registry"),
        (true, _) => Some("push to this registry"),
        _ => None,
    };
    let principal = match registry_door::authorize_to(&state, &headers, need, what, refusal) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let org = match registry_door::eco_org(&state, &headers, Ecosystem::Oci) {
        Ok(o) => o,
        Err(r) => return r,
    };
    let Some(target) = oci::parse_path(&path) else {
        return oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "no such path");
    };
    let name = match &target {
        oci::Target::StartUpload { name }
        | oci::Target::Upload { name, .. }
        | oci::Target::Blob { name, .. }
        | oci::Target::Manifest { name, .. }
        | oci::Target::Tags { name } => name.clone(),
    };

    let head_only = method == Method::HEAD;
    match (target, method) {
        (oci::Target::StartUpload { .. }, Method::POST) => {
            start_upload(state, org, name, query.as_deref()).await
        }
        (oci::Target::Upload { session, .. }, Method::PATCH) => {
            patch_upload(state, org, session, body).await
        }
        (oci::Target::Upload { session, .. }, Method::PUT) => {
            finish_upload(state, org, name, session, query.as_deref(), body).await
        }
        (oci::Target::Upload { session, .. }, Method::DELETE) => {
            match packages::finish_upload(&state.db, &org.id, &session) {
                Ok(true) => StatusCode::NO_CONTENT.into_response(),
                Ok(false) => oci_error(
                    StatusCode::NOT_FOUND,
                    "BLOB_UPLOAD_UNKNOWN",
                    "no such upload",
                ),
                Err(e) => internal(e),
            }
        }
        (oci::Target::Blob { digest, .. }, Method::GET | Method::HEAD) => {
            get_blob(state, org, digest, head_only).await
        }
        (oci::Target::Manifest { reference, .. }, Method::GET | Method::HEAD) => {
            get_manifest(state, org, name, reference, head_only).await
        }
        (oci::Target::Manifest { reference, .. }, Method::PUT) => {
            put_manifest(state, org, principal, name, reference, body).await
        }
        (oci::Target::Manifest { reference, .. }, Method::DELETE) => {
            delete_manifest(state, org, principal, name, reference).await
        }
        (oci::Target::Tags { .. }, Method::GET) => tags(state, org, name).await,
        _ => oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "that verb is not one this path answers",
        ),
    }
}

fn upload_location(name: &str, session: &str) -> String {
    format!("/v2/{name}/blobs/uploads/{session}")
}

/// `?<key>=…` from a raw query string, with the one percent-encoding a
/// client applies to a digest undone.
///
/// The colon is the only character a client percent-encodes in a
/// digest, and both spellings appear in the wild; nothing else is
/// decoded, because a digest is hex and a colon and anything else in it
/// is not a digest.
fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    for pair in query?.split('&') {
        if let Some(v) = pair
            .strip_prefix(key)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some(v.replace("%3A", ":").replace("%3a", ":"));
        }
    }
    None
}

/// `?digest=…`, which is where the spec puts the digest on the PUT that
/// finishes an upload.
fn query_digest(query: Option<&str>) -> Option<String> {
    query_param(query, "digest").filter(|v| oci::valid_digest(v))
}

async fn start_upload(state: SharedState, org: Org, name: String, query: Option<&str>) -> Response {
    // The repository row is created here rather than at the manifest,
    // so a push against a name this registry cannot store is refused
    // before a single byte moves.
    let now = skein_control::ids::now_ms();
    let existing = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Oci,
        &name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return oci_error(StatusCode::BAD_REQUEST, "NAME_INVALID", e),
    };
    if existing.is_proxied() {
        return oci_error(
            StatusCode::CONFLICT,
            "DENIED",
            format!("{name:?} is cached from an upstream registry and cannot be pushed to"),
        );
    }

    // A cross-repository mount: "you already hold these bytes under
    // another name; hold them under this one too". Every repository of
    // an install reads from the organization's one store of blobs, so a
    // blob the organization holds is already readable here and the
    // mount is simply a yes. Anything else — a digest we do not hold, or
    // not a digest at all — falls through to an ordinary session, which
    // is the spec's own answer for a mount a registry will not do.
    //
    // Not decoration: `docker manifest push` assembles a multi-platform
    // index in one repository out of images pushed to others, mounts
    // every blob first, and treats the 202 fallback as a failure.
    if let Some(digest) = query_param(query, "mount").filter(|d| oci::valid_digest(d)) {
        match packages::blob_exists(&state.db, &org.id, &digest) {
            Ok(Some(_)) => {
                return (
                    StatusCode::CREATED,
                    [
                        (header::LOCATION, format!("/v2/{name}/blobs/{digest}")),
                        (HeaderName::from_static("docker-content-digest"), digest),
                    ],
                )
                    .into_response()
            }
            Ok(None) => {}
            Err(e) => return internal(e),
        }
    }

    match packages::start_upload(&state.db, &org.id, &name, now) {
        Ok(up) => (
            StatusCode::ACCEPTED,
            [
                (header::LOCATION, upload_location(&name, &up.id)),
                (
                    header::RANGE,
                    // The spec's own spelling for an empty session.
                    "0-0".to_string(),
                ),
                (HeaderName::from_static("docker-upload-uuid"), up.id.clone()),
            ],
        )
            .into_response(),
        Err(e) => internal(e),
    }
}

/// Write one block to the store and record it in the session at once.
///
/// Recorded as soon as it is written, not when the request ends: a
/// `docker push` over a connection that drops part-way through a layer
/// has already put whole blocks in the bucket, and a block no session
/// and no blob names is one the collector can never find.
async fn put_block(
    state: &SharedState,
    org: &Org,
    session: &str,
    bytes: Vec<u8>,
) -> Result<Block, Response> {
    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    let size = bytes.len() as i64;
    let written =
        tokio::task::spawn_blocking(move || blobs::put_block(&store_url, &prefix, &bytes))
            .await
            .unwrap_or_else(|e| Err(blobs::BlobError::Store(format!("join: {e}"))));
    let block = match written {
        Ok(digest) => Block {
            block: digest,
            size_bytes: size,
        },
        Err(e @ blobs::BlobError::TooLarge { .. }) => {
            return Err(oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                e.to_string(),
            ))
        }
        Err(e) => return Err(internal(skein_store::diagnose(e.to_string()))),
    };
    let now = skein_control::ids::now_ms();
    if let Err(e) = packages::extend_upload(
        &state.db,
        &org.id,
        session,
        std::slice::from_ref(&block),
        now,
    ) {
        return Err(internal(e));
    }
    Ok(block)
}

/// Read a request body straight into blocks, without ever holding more
/// than one.
///
/// This is the whole reason the block scheme exists. `docker push` sends
/// a layer as one body; buffering it would mean a 500 MB allocation per
/// concurrent push, and `docker push` of a twenty-layer image pushes
/// several at once.
async fn drain_into_blocks(
    state: &SharedState,
    org: &Org,
    session: &str,
    body: Body,
    already: i64,
) -> Result<Vec<Block>, Response> {
    let mut out: Vec<Block> = Vec::new();
    let mut buf: Vec<u8> = Vec::with_capacity(blobs::BLOCK);
    let mut total = already;
    let mut stream = body.into_data_stream();

    loop {
        let chunk = match stream.next().await {
            None => break,
            Some(Ok(d)) => d,
            Some(Err(e)) => {
                return Err(oci_error(
                    StatusCode::BAD_REQUEST,
                    "BLOB_UPLOAD_INVALID",
                    format!("the upload stopped part-way: {e}"),
                ))
            }
        };
        total += chunk.len() as i64;
        if total > blobs::MAX_BLOB {
            return Err(oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "TOOBIG",
                format!("that layer is over {} bytes", blobs::MAX_BLOB),
            ));
        }
        let mut rest: &[u8] = &chunk;
        while !rest.is_empty() {
            let room = blobs::BLOCK - buf.len();
            let take = room.min(rest.len());
            buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if buf.len() == blobs::BLOCK {
                let full = std::mem::replace(&mut buf, Vec::with_capacity(blobs::BLOCK));
                out.push(put_block(state, org, session, full).await?);
            }
        }
    }
    if !buf.is_empty() {
        out.push(put_block(state, org, session, buf).await?);
    }
    Ok(out)
}

async fn patch_upload(state: SharedState, org: Org, session: String, body: Body) -> Response {
    let Some(up) = (match packages::upload(&state.db, &org.id, &session) {
        Ok(u) => u,
        Err(e) => return internal(e),
    }) else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "no such upload",
        );
    };
    let blocks = match drain_into_blocks(&state, &org, &session, body, up.size_bytes).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let size = up.size_bytes + blocks.iter().map(|b| b.size_bytes).sum::<i64>();
    (
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, upload_location(&up.package, &session)),
            (header::RANGE, format!("0-{}", size.saturating_sub(1))),
            (HeaderName::from_static("docker-upload-uuid"), session),
        ],
    )
        .into_response()
}

async fn finish_upload(
    state: SharedState,
    org: Org,
    name: String,
    session: String,
    query: Option<&str>,
    body: Body,
) -> Response {
    let Some(up) = (match packages::upload(&state.db, &org.id, &session) {
        Ok(u) => u,
        Err(e) => return internal(e),
    }) else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "no such upload",
        );
    };
    // A session is a bearer capability: finishing one against a
    // repository it was not opened for would be a way to write bytes
    // into a name the opener did not open a session for.
    if up.package != name {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "that upload belongs to another repository",
        );
    }
    let Some(claimed) = query_digest(query) else {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "finishing an upload needs ?digest=sha256:…",
        );
    };
    // The final PUT may carry the last chunk, and a monolithic push
    // carries the whole layer.
    let tail = match drain_into_blocks(&state, &org, &session, body, up.size_bytes).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    let mut all = up.blocks.clone();
    all.extend(tail);

    // Re-read to hash. The alternative is carrying a partial SHA-256
    // across requests, which `sha2` does not serialise and which would
    // in any case be wrong the moment a session is finished by another
    // process.
    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    let for_hash = all.clone();
    let digest = match tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for b in &for_hash {
            let bytes = blobs::get_block(&store_url, &prefix, &b.block)?;
            h.update(&bytes);
        }
        Ok::<String, String>(format!(
            "sha256:{}",
            h.finalize()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {e}")))
    {
        Ok(d) => d,
        Err(e) => return internal(skein_store::diagnose(e)),
    };
    if digest != claimed {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            format!("the upload is {digest} and was pushed as {claimed}"),
        );
    }

    let now = skein_control::ids::now_ms();
    if let Err(e) = packages::note_blocked_blob(&state.db, &org.id, &digest, &all, now) {
        return internal(e);
    }
    let _ = packages::finish_upload(&state.db, &org.id, &session);
    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{name}/blobs/{digest}")),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

async fn get_blob(state: SharedState, org: Org, digest: String, head_only: bool) -> Response {
    let blocks = match packages::blocks_of(&state.db, &org.id, &digest) {
        Ok(b) => b,
        Err(e) => return internal(e),
    };
    let size: i64 = if blocks.is_empty() {
        match packages::blob_exists(&state.db, &org.id, &digest) {
            Ok(Some(n)) => n,
            Ok(None) => return oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "no such blob"),
            Err(e) => return internal(e),
        }
    } else {
        blocks.iter().map(|b| b.size_bytes).sum()
    };

    let common = [
        (header::CONTENT_TYPE, "application/octet-stream".to_string()),
        (header::CONTENT_LENGTH, size.to_string()),
        (
            HeaderName::from_static("docker-content-digest"),
            digest.clone(),
        ),
        (
            header::CACHE_CONTROL,
            "private, max-age=31536000, immutable".to_string(),
        ),
    ];
    if head_only {
        return (StatusCode::OK, common).into_response();
    }

    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    if blocks.is_empty() {
        let d = digest.clone();
        return match tokio::task::spawn_blocking(move || blobs::get(&store_url, &prefix, &d))
            .await
            .unwrap_or_else(|e| Err(format!("join: {e}")))
        {
            Ok(bytes) => (StatusCode::OK, common, bytes).into_response(),
            Err(e) if skein_store::is_absent(&e) => {
                oci_error(StatusCode::NOT_FOUND, "BLOB_UNKNOWN", "no such blob")
            }
            Err(e) => internal(skein_store::diagnose(e)),
        };
    }

    // Block by block, down a channel, so a 500 MB layer is served with
    // one block resident rather than five hundred megabytes.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(2);
    tokio::task::spawn_blocking(move || {
        for b in &blocks {
            match blobs::get_block(&store_url, &prefix, &b.block) {
                Ok(bytes) => {
                    if tx.blocking_send(Ok(bytes.into())).is_err() {
                        // The client hung up. Stop reading rather than
                        // pulling the rest of a layer nobody wants.
                        return;
                    }
                }
                Err(e) => {
                    // Mid-body: the response has already started, so
                    // the only honest signal left is an error on the
                    // stream, which the client reads as a truncated
                    // download rather than as a complete one.
                    eprintln!("skein: oci blob {digest}: {e}");
                    let _ = tx.blocking_send(Err(std::io::Error::other(e)));
                    return;
                }
            }
        }
    });
    (
        StatusCode::OK,
        common,
        Body::from_stream(futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx))),
    )
        .into_response()
}

async fn get_manifest(
    state: SharedState,
    org: Org,
    name: String,
    reference: String,
    head_only: bool,
) -> Response {
    // A name that is not a legal repository name is the same answer as
    // one nobody pushed: the client asked for something this registry
    // does not have.
    let Some(p) = packages::by_name(&state.db, &org.id, Ecosystem::Oci, &name).unwrap_or_default()
    else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            "no such repository",
        );
    };
    // A reference is a tag or a digest. A tag is a version row; a
    // digest addresses the manifest blob directly, which is how a
    // client pulls an index's member.
    //
    // Always the wire spelling, `sha256:…`, whichever way it was found.
    // The rows hold bare hex — that is what the collector compares — and
    // a `Docker-Content-Digest` header without the algorithm is one a
    // client compares against its own digest and finds different, on
    // every pull.
    let digest = if oci::valid_digest(&reference) {
        reference.clone()
    } else {
        match packages::version_by_number(&state.db, &p.id, &reference) {
            Ok(Some(v)) => match packages::files(&state.db, &v.id) {
                Ok(fs) => match fs.iter().find(|f| f.filename == MANIFEST_FILE) {
                    Some(f) => format!("sha256:{}", f.digest.trim_start_matches("sha256:")),
                    None => {
                        return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "no such tag")
                    }
                },
                Err(e) => return internal(e),
            },
            Ok(None) => return oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "no such tag"),
            Err(e) => return oci_error(StatusCode::BAD_REQUEST, "MANIFEST_INVALID", e),
        }
    };

    let bytes = match read_blob(&state, &org, &digest).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "MANIFEST_UNKNOWN",
                "no such manifest",
            )
        }
        Err(r) => return r,
    };
    // The type the document itself declares, which is the only answer
    // that cannot disagree with the bytes — and the bytes are what the
    // digest covers.
    let media = serde_json::from_slice::<oci::Manifest>(&bytes)
        .ok()
        .and_then(|m| m.media_type)
        .unwrap_or_else(|| oci::DEFAULT_MANIFEST_TYPE.to_string());
    let head = [
        (header::CONTENT_TYPE, media),
        (header::CONTENT_LENGTH, bytes.len().to_string()),
        (HeaderName::from_static("docker-content-digest"), digest),
    ];
    if head_only {
        return (StatusCode::OK, head).into_response();
    }
    (StatusCode::OK, head, bytes).into_response()
}

/// A single-object blob — a manifest — read whole. `Ok(None)` when the
/// store does not have it.
async fn read_blob(
    state: &SharedState,
    org: &Org,
    digest: &str,
) -> Result<Option<Vec<u8>>, Response> {
    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    let d = digest.to_string();
    match tokio::task::spawn_blocking(move || blobs::get(&store_url, &prefix, &d))
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")))
    {
        Ok(b) => Ok(Some(b)),
        Err(e) if skein_store::is_absent(&e) => Ok(None),
        Err(e) => Err(internal(skein_store::diagnose(e))),
    }
}

/// The filename a manifest is stored under on its version row.
const MANIFEST_FILE: &str = "manifest.json";

/// How deep an index may nest other indexes. One level is every
/// multi-platform image there is; the bound is only there so a document
/// cannot make the door walk for ever.
const MAX_INDEX_DEPTH: usize = 4;

/// Every blob a manifest needs, **transitively**, each digest once — or
/// the refusal a client should read if one of them is not here.
///
/// Transitively because an index names its platform manifests and not
/// their layers, and a platform manifest pushed by digest has no tag of
/// its own. Recording only what the index names directly would leave
/// every layer of every multi-platform image referenced by nothing, and
/// the collector would take them an hour after the push.
///
/// Each digest once because an image may name the same blob twice — an
/// identical layer produced by two build steps, or the empty layer — and
/// a version holds each file once.
async fn needs(
    state: &SharedState,
    org: &Org,
    manifest: &oci::Manifest,
) -> Result<Vec<oci::Descriptor>, Response> {
    let mut out: Vec<oci::Descriptor> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut pending: Vec<(oci::Manifest, usize)> = vec![(manifest.clone(), 0)];
    while let Some((m, depth)) = pending.pop() {
        // An index's members are *manifests*, which live here too and
        // are stored as blobs — so the lookup is the same and only the
        // error code differs. It differs for a reason: a client that
        // reads `BLOB_UNKNOWN` for a missing platform manifest goes
        // looking for a layer, and there is no layer to find.
        let index = m.is_index();
        let missing_code = if index {
            "MANIFEST_UNKNOWN"
        } else {
            "BLOB_UNKNOWN"
        };
        for d in m.referenced() {
            if !oci::valid_digest(&d.digest) {
                return Err(oci_error(
                    StatusCode::BAD_REQUEST,
                    "MANIFEST_INVALID",
                    format!("{} is not a digest this registry could hold", d.digest),
                ));
            }
            let size = match packages::blob_exists(&state.db, &org.id, &d.digest) {
                Ok(Some(n)) => n,
                Ok(None) => {
                    return Err(oci_error(
                        StatusCode::NOT_FOUND,
                        missing_code,
                        format!("{} has not been pushed to this registry", d.digest),
                    ))
                }
                Err(e) => return Err(internal(e)),
            };
            if !seen.insert(d.digest.clone()) {
                continue;
            }
            out.push(oci::Descriptor {
                media_type: d.media_type.clone(),
                digest: d.digest.clone(),
                // What we hold, not what the document claims: this is
                // the number a person reads as the image's size.
                size,
            });
            if index && m.manifests.iter().any(|x| x.digest == d.digest) {
                if depth + 1 > MAX_INDEX_DEPTH {
                    return Err(oci_error(
                        StatusCode::BAD_REQUEST,
                        "MANIFEST_INVALID",
                        "that index nests other indexes deeper than any image does",
                    ));
                }
                let bytes = match read_blob(state, org, &d.digest).await? {
                    Some(b) => b,
                    None => {
                        return Err(oci_error(
                            StatusCode::NOT_FOUND,
                            "MANIFEST_UNKNOWN",
                            format!("{} has not been pushed to this registry", d.digest),
                        ))
                    }
                };
                let member: oci::Manifest = match serde_json::from_slice(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        return Err(oci_error(
                            StatusCode::BAD_REQUEST,
                            "MANIFEST_INVALID",
                            format!("{} is named as a manifest and is not one: {e}", d.digest),
                        ))
                    }
                };
                pending.push((member, depth + 1));
            }
        }
    }
    Ok(out)
}

async fn put_manifest(
    state: SharedState,
    org: Org,
    principal: Principal,
    name: String,
    reference: String,
    body: Body,
) -> Response {
    use axum::body::to_bytes;

    let bytes = match to_bytes(body, blobs::MAX_ARTIFACT).await {
        Ok(b) => b,
        Err(_) => {
            return oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "MANIFEST_INVALID",
                "that manifest is larger than any manifest is",
            )
        }
    };
    let manifest: oci::Manifest = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            return oci_error(
                StatusCode::BAD_REQUEST,
                "MANIFEST_INVALID",
                format!("that is not a manifest: {e}"),
            )
        }
    };

    // Every blob it names must already be here, and every blob its
    // members name. Otherwise this registry serves an image that cannot
    // be pulled, and the client's error is about the missing layer
    // rather than about the push that was wrong.
    let needed = match needs(&state, &org, &manifest).await {
        Ok(n) => n,
        Err(r) => return r,
    };

    let bare = blobs::digest_of(&bytes);
    let digest = format!("sha256:{bare}");
    if oci::valid_digest(&reference) && reference != digest {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            format!("the manifest is {digest} and was pushed as {reference}"),
        );
    }

    let now = skein_control::ids::now_ms();
    let pkg_row = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Oci,
        &name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return oci_error(StatusCode::BAD_REQUEST, "NAME_INVALID", e),
    };
    if pkg_row.is_proxied() {
        return oci_error(
            StatusCode::CONFLICT,
            "DENIED",
            format!("{name:?} is cached from an upstream registry and cannot be pushed to"),
        );
    }

    // The manifest is itself a blob, addressed by its own digest, so a
    // client may pull it by digest as well as by tag — which is exactly
    // what an index's members are pulled by.
    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    let owned = bytes.to_vec();
    let expected = bare.clone();
    let written =
        tokio::task::spawn_blocking(move || blobs::put(&store_url, &prefix, &expected, &owned))
            .await
            .unwrap_or_else(|e| Err(blobs::BlobError::Store(format!("join: {e}"))));
    if let Err(e) = written {
        return internal(skein_store::diagnose(e.to_string()));
    }
    if let Err(e) = packages::note_blob(&state.db, &org.id, &digest, bytes.len() as i64, now) {
        return internal(e);
    }

    // A tag is a version row; a manifest pushed by digest alone has no
    // tag and lives as a blob, which is how an index's members arrive.
    if oci::valid_tag(&reference) {
        let mut files = vec![PackageFile {
            filename: MANIFEST_FILE.to_string(),
            // Bare hex, which is the one spelling `package_blobs`
            // holds. A `sha256:`-prefixed value here would compare
            // unequal in the collector's reference check, and every
            // layer of every image would be swept as unreferenced.
            digest: bare.clone(),
            size_bytes: bytes.len() as i64,
            content_type: manifest
                .media_type
                .clone()
                .unwrap_or_else(|| oci::DEFAULT_MANIFEST_TYPE.to_string()),
            digests: "{}".to_string(),
        }];
        // Every blob the image needs, recorded against the tag — this
        // is what keeps the collector from taking a layer out from
        // under an image that is still tagged.
        for d in &needed {
            files.push(PackageFile {
                // The filename keeps the wire spelling, because that is
                // what a person reading the version's files expects to
                // see; the digest is bare hex, which is what the
                // collector compares.
                filename: d.digest.clone(),
                digest: d.digest.trim_start_matches("sha256:").to_string(),
                size_bytes: d.size,
                content_type: d
                    .media_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                digests: "{}".to_string(),
            });
        }
        let licence = match manifest.license() {
            Some(l) => License::Declared(l.to_string()),
            None => License::Unknown,
        };
        // A tag moves. That is what a tag is for, and it is the one
        // place this registry's "a version never changes" rule does not
        // apply — what never changes is the *manifest*, which is
        // addressed by its digest. So a re-push of `latest` replaces the
        // row rather than being refused.
        if let Ok(Some(old)) = packages::version_by_number(&state.db, &pkg_row.id, &reference) {
            let _ = packages::remove_version(&state.db, &old.id);
        }
        match packages::publish_version(
            &state.db,
            &pkg_row.id,
            &reference,
            &licence,
            "{}",
            &files,
            &registry_door::provenance(&principal),
            now,
        ) {
            Ok(_) | Err(packages::PublishError::Exists) => {}
            Err(packages::PublishError::Other(e)) => return internal(e),
        }
        crate::api::audit(
            &state,
            &principal,
            "package.publish",
            serde_json::json!({
                "ecosystem": "oci",
                "name": name,
                "version": reference,
                "digest": digest,
            }),
        );
    }

    (
        StatusCode::CREATED,
        [
            (header::LOCATION, format!("/v2/{name}/manifests/{digest}")),
            (HeaderName::from_static("docker-content-digest"), digest),
        ],
    )
        .into_response()
}

async fn delete_manifest(
    state: SharedState,
    org: Org,
    principal: Principal,
    name: String,
    reference: String,
) -> Response {
    // A name that is not a legal repository name is the same answer as
    // one nobody pushed: the client asked for something this registry
    // does not have.
    let Some(p) = packages::by_name(&state.db, &org.id, Ecosystem::Oci, &name).unwrap_or_default()
    else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "MANIFEST_UNKNOWN",
            "no such repository",
        );
    };
    // Only a tag is deletable here. Deleting by digest would have to
    // remove a manifest several tags may point at, and the spec allows
    // a registry to refuse it — refusing is the answer that cannot
    // silently break a tag somebody else is using.
    if !oci::valid_tag(&reference) {
        return oci_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "UNSUPPORTED",
            "delete a tag; a manifest by digest may be referenced by tags you cannot see",
        );
    }
    match packages::version_by_number(&state.db, &p.id, &reference) {
        Ok(Some(v)) => match packages::remove_version(&state.db, &v.id) {
            Ok(_) => {
                crate::api::audit(
                    &state,
                    &principal,
                    "package.untag",
                    serde_json::json!({ "ecosystem": "oci", "name": name, "version": reference }),
                );
                StatusCode::ACCEPTED.into_response()
            }
            Err(e) => internal(e),
        },
        Ok(None) => oci_error(StatusCode::NOT_FOUND, "MANIFEST_UNKNOWN", "no such tag"),
        Err(e) => oci_error(StatusCode::BAD_REQUEST, "MANIFEST_INVALID", e),
    }
}

async fn tags(state: SharedState, org: Org, name: String) -> Response {
    // A name that is not a legal repository name is the same answer as
    // one nobody pushed: the client asked for something this registry
    // does not have.
    let Some(p) = packages::by_name(&state.db, &org.id, Ecosystem::Oci, &name).unwrap_or_default()
    else {
        return oci_error(StatusCode::NOT_FOUND, "NAME_UNKNOWN", "no such repository");
    };
    match packages::versions(&state.db, &p.id) {
        Ok(vs) => {
            let mut tags: Vec<String> = vs.into_iter().map(|v| v.version).collect();
            tags.sort();
            Json(oci::tags_body(&name, &tags)).into_response()
        }
        Err(e) => internal(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both spellings of the colon a client may send, and nothing that
    /// is not a digest.
    #[test]
    fn a_digest_in_the_query_is_read_in_either_spelling_and_nothing_else() {
        let d = format!("sha256:{}", "a".repeat(64));
        let enc = format!("sha256%3A{}", "a".repeat(64));
        let low = format!("sha256%3a{}", "a".repeat(64));
        for q in [
            format!("digest={d}"),
            format!("digest={enc}"),
            format!("digest={low}"),
            format!("other=1&digest={d}"),
        ] {
            assert_eq!(query_digest(Some(&q)).as_deref(), Some(d.as_str()), "{q}");
        }
        for q in ["", "digest=", "digest=not-a-digest", "digests=x", "other=1"] {
            assert_eq!(query_digest(Some(q)), None, "{q:?}");
        }
        assert_eq!(query_digest(None), None);
        // A key that merely starts with another key's name is not it.
        assert_eq!(query_param(Some(&format!("digestx={d}")), "digest"), None);
        assert_eq!(
            query_param(Some(&format!("mount={d}&from=team/app")), "mount").as_deref(),
            Some(d.as_str())
        );
        assert_eq!(
            query_param(Some("mount=x&from=team/app"), "from").as_deref(),
            Some("team/app")
        );
    }
}
