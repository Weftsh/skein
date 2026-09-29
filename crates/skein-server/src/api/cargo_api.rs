//! Cargo's door: a sparse index, a download URL and three API calls.
//!
//! ```text
//! GET    /cargo/index/config.json
//! GET    /cargo/index/<prefix>/<name>              one crate, NDJSON
//! GET    /cargo/api/v1/crates/<name>/<v>/download
//! PUT    /cargo/api/v1/crates/new
//! DELETE /cargo/api/v1/crates/<name>/<v>/yank
//! PUT    /cargo/api/v1/crates/<name>/<v>/unyank
//! ```
//!
//! ## The credential arrives with no scheme
//!
//! Cargo sends `Authorization: <token>` — bare, no `Bearer`, and it has
//! for its whole history. `registry_door::bare_token` reads that shape
//! and nothing else does, because a bare `Authorization` value is
//! indistinguishable from a malformed one and admitting it on doors no
//! Cargo client reaches would widen what counts as a credential for no
//! reason.
//!
//! ## The refusals are ordered
//!
//! As on every door — see [`registry_door`]: no credential that
//! authenticates is a 401 with a `Basic` challenge before anything else
//! is looked at, which is also what makes Cargo send its token at all
//! (it asks for `config.json` without one first, and only a 401 makes it
//! retry with one). Then a person whose role or token does not reach is
//! a 403 with a sentence, in the body Cargo prints; then Cargo being
//! switched off, or the crate being absent, is a 404.
//!
//! ## The index is generated per request
//!
//! crates.io serves a git repository or static files; we serve rows.
//! A crate's index file is one line per version, assembled on read — so
//! a yank takes effect at once instead of after a publish job somewhere
//! rewrites a file.

use crate::api::{internal, registry_door};
use crate::app::SharedState;
use crate::registry::cargo;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use skein_control::auth::{Principal, Scope};
use skein_control::packages::{self, Ecosystem, License, PackageFile};
use skein_control::registry::Org;

/// The body limit for a publish: the crate file, its metadata, and the
/// two four-byte lengths that frame them.
///
/// The frame is counted because the router refuses a body over its
/// limit before any of our own checks run, with a message that says
/// nothing about size — so a limit that forgot the eight bytes would
/// refuse the largest publish the two ceilings claim to admit.
pub const PUBLISH_BODY_LIMIT: usize =
    crate::registry::blobs::MAX_ARTIFACT + cargo::MAX_METADATA + 8;

/// The largest publish the parser and the store both admit — a full
/// metadata frame and a full crate, each behind its four-byte length —
/// must get past the router. Checked at compile time: it is a property
/// of three constants and there is no run in which it could differ.
const _: () = assert!(
    PUBLISH_BODY_LIMIT >= 4 + cargo::MAX_METADATA + 4 + crate::registry::blobs::MAX_ARTIFACT
);

/// Cargo prints `errors[0].detail` and nothing else, so the sentence
/// has to carry the whole explanation.
fn cargo_error(status: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    (status, Json(cargo::error_body(&msg))).into_response()
}

/// Cargo's error shape, as [`registry_door::Refusal`] wants it.
fn refusal(status: StatusCode, msg: String) -> Response {
    cargo_error(status, msg)
}

/// Authorize, in Cargo's dialect of refusal, and only then check Cargo
/// is switched on — the same order as every other door.
fn open(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
) -> Result<(Org, Principal), Response> {
    open_to(state, headers, need, None)
}

fn open_to(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
    what: Option<&str>,
) -> Result<(Org, Principal), Response> {
    let p = registry_door::authorize_to(state, headers, need, what, refusal)?;
    let org = registry_door::eco_org(state, headers, Ecosystem::Cargo)?;
    Ok((org, p))
}

/// `GET /cargo/*path` — the index.
pub async fn get(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let org = match open(&state, &headers, Scope::PackageRead) {
        Ok((o, _)) => o,
        Err(r) => return r,
    };
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["index", "config.json"] => config(&state, &headers),
        // `1/a`, `2/ab`, `3/a/abc`, `ab/cd/abcd` — four shapes, and the
        // crate's name is always the last segment. The prefix is
        // *checked* rather than ignored: Cargo always computes the
        // right one, so serving a crate at any prefix that ends in its
        // name would give one resource several URLs, which is a cache
        // that never hits and a CDN holding four copies of the same
        // file.
        ["index", .., name]
            if parts.len() >= 3
                && parts.len() <= 4
                && parts[1..].join("/") == cargo::index_prefix(name) =>
        {
            index(state, org, (*name).to_string()).await
        }
        _ => cargo_error(StatusCode::NOT_FOUND, "no such path"),
    }
}

fn config(state: &SharedState, headers: &HeaderMap) -> Response {
    // Built from the address this client used, not the deployment's own
    // — see `registry_door::self_base`. A client that reached us on
    // loopback would otherwise be told to fetch every crate from an
    // address it may not be able to reach.
    let base = format!("{}/cargo", registry_door::self_base(state, headers));
    (
        [(header::CONTENT_TYPE, "application/json")],
        cargo::config_json(&format!("{base}/api/v1/crates"), &base).into_bytes(),
    )
        .into_response()
}

async fn index(state: SharedState, org: Org, name: String) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Cargo, &name) {
        Ok(Some(p)) => p,
        // A crate nobody has published is a 404, which is what Cargo
        // expects and reports as "no matching package named `x`".
        Ok(None) | Err(_) => return cargo_error(StatusCode::NOT_FOUND, "no such crate"),
    };
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    // Oldest first, and by id within one millisecond, so the file reads
    // the same on every request.
    let mut rows: Vec<_> = versions.iter().collect();
    rows.sort_by(|a, b| (a.published_at, &a.id).cmp(&(b.published_at, &b.id)));

    let mut body = String::new();
    for v in rows {
        let files = match packages::files(&state.db, &v.id) {
            Ok(f) => f,
            Err(e) => return internal(e),
        };
        // A version with no artifact is a version Cargo would fail to
        // download after resolving to it, which reads as a corrupt
        // registry rather than as an absent crate.
        let Some(file) = files.first() else { continue };
        // Written by `publish` below, from a body already parsed into
        // this shape — so a row that does not read back is ours to
        // explain, not something to paper over with an empty line that
        // would resolve as a crate with no dependencies.
        let declared: cargo::Declared = match serde_json::from_str(&v.metadata) {
            Ok(d) => d,
            Err(e) => {
                return internal(format!(
                    "the index entry for {} {} does not read back: {e}",
                    pkg.name, v.version
                ))
            }
        };
        body.push_str(&cargo::index_line(
            &pkg.name,
            &v.version,
            &file.digest,
            v.yanked,
            &declared,
        ));
        body.push('\n');
    }
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.into_bytes(),
    )
        .into_response()
}

/// `GET /cargo/api/v1/crates/:name/:version/download`
///
/// Shares its route with `yank` and `unyank` — three verbs on one path
/// shape — so the verb is checked here rather than by the router.
pub async fn download(
    State(state): State<SharedState>,
    Path((name, version, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let org = match open(&state, &headers, Scope::PackageRead) {
        Ok((o, _)) => o,
        Err(r) => return r,
    };
    if verb != "download" {
        return cargo_error(StatusCode::NOT_FOUND, "no such path");
    }
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Cargo, &name) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return cargo_error(StatusCode::NOT_FOUND, "no such crate"),
    };
    let ver = match packages::version_by_number(&state.db, &pkg.id, &version) {
        Ok(Some(v)) => v,
        Ok(None) => return cargo_error(StatusCode::NOT_FOUND, "no such version"),
        Err(e) => return cargo_error(StatusCode::BAD_REQUEST, e),
    };
    let files = match packages::files(&state.db, &ver.id) {
        Ok(f) => f,
        Err(e) => return internal(e),
    };
    let Some(file) = files.first() else {
        return cargo_error(StatusCode::NOT_FOUND, "no such version");
    };
    match registry_door::read_artifact(&state, &file.digest).await {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/gzip"),
                (
                    header::CACHE_CONTROL,
                    "private, max-age=31536000, immutable",
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => cargo_error(StatusCode::NOT_FOUND, "no such crate file"),
        Err(r) => r,
    }
}

/// `PUT /cargo/api/v1/crates/new`
pub async fn publish(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (org, principal) = match open(&state, &headers, Scope::PackageWrite) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let parsed = match cargo::parse_publish(&body) {
        Ok(p) => p,
        Err(e) => return cargo_error(StatusCode::BAD_REQUEST, e),
    };
    let meta = parsed.metadata;

    // The version is checked before anything is written. Left to
    // `publish_version`, a version that could never be stored would
    // arrive there after the package row and the bytes already had.
    if let Err(e) = packages::normalize_version(&meta.vers) {
        return cargo_error(StatusCode::BAD_REQUEST, e);
    }
    let now = skein_control::ids::now_ms();
    let pkg = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Cargo,
        &meta.name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return cargo_error(StatusCode::BAD_REQUEST, e),
    };
    if pkg.is_proxied() {
        return cargo_error(
            StatusCode::CONFLICT,
            format!(
                "{:?} is cached from an upstream registry here and cannot be published to",
                pkg.name
            ),
        );
    }

    // Bytes first, row second — see `registry_door::store_artifact`.
    let digest = match registry_door::store_artifact(&state, &parsed.crate_file, now, refusal).await
    {
        Ok(d) => d,
        Err(r) => return r,
    };
    let file = PackageFile {
        filename: cargo::crate_filename(&pkg.name, &meta.vers),
        digest,
        size_bytes: parsed.crate_file.len() as i64,
        content_type: "application/gzip".into(),
        digests: "{}".to_string(),
    };

    // Cargo's `license` is documented to be an SPDX expression, which
    // makes this the one ecosystem of the five that needs no mapping
    // table at all. `license_file` says "the licence is in the archive"
    // — which is honestly unknown to a policy that has not opened it,
    // and opening it is a fingerprinter this door does not have.
    let licence = match meta
        .license
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty())
    {
        Some(l) => License::Declared(l.to_string()),
        None => License::Unknown,
    };
    // What the publisher declared that a resolver needs — dependencies,
    // features, `links`, `rust_version` — kept in the publish's own
    // words. The index restates it on every read (`cargo::index_line`);
    // keeping the words Cargo sent, rather than the index's, is what
    // lets that restatement be corrected without rewriting a row.
    let stored = match serde_json::to_string(&meta.declared) {
        Ok(s) => s,
        Err(e) => return internal(format!("store the publish metadata: {e}")),
    };

    let prov = registry_door::provenance(&principal);
    let version = match packages::publish_version(
        &state.db,
        &pkg.id,
        &meta.vers,
        &licence,
        &stored,
        std::slice::from_ref(&file),
        &prov,
        now,
    ) {
        Ok(v) => v,
        Err(packages::PublishError::Exists) => {
            return cargo_error(
                StatusCode::CONFLICT,
                format!(
                    "crate version `{} {}` is already uploaded, and a published version \
                     never changes here",
                    pkg.name, meta.vers
                ),
            )
        }
        Err(packages::PublishError::Other(e)) => return internal(e),
    };
    crate::api::audit(
        &state,
        &principal,
        "package.publish",
        serde_json::json!({ "ecosystem": "cargo", "name": pkg.name, "version": version.version }),
    );
    Json(cargo::publish_ok()).into_response()
}

/// `DELETE /cargo/api/v1/crates/:name/:version/yank` and
/// `PUT …/unyank`.
///
/// Each verb has exactly one method. Reading the direction from the
/// verb alone would let a `PUT …/yank` — a request Cargo never sends —
/// yank a version with the method Cargo uses to put one back.
pub async fn yank(
    State(state): State<SharedState>,
    method: Method,
    Path((name, version, verb)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let what = if verb == "unyank" {
        "unyank a version in this registry"
    } else {
        "yank a version in this registry"
    };
    let (org, principal) = match open_to(&state, &headers, Scope::PackageWrite, Some(what)) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let yanked = match (&method, verb.as_str()) {
        (&Method::DELETE, "yank") => true,
        (&Method::PUT, "unyank") => false,
        _ => return cargo_error(StatusCode::NOT_FOUND, "no such path"),
    };
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Cargo, &name) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return cargo_error(StatusCode::NOT_FOUND, "no such crate"),
    };
    let ver = match packages::version_by_number(&state.db, &pkg.id, &version) {
        Ok(Some(v)) => v,
        Ok(None) => return cargo_error(StatusCode::NOT_FOUND, "no such version"),
        Err(e) => return cargo_error(StatusCode::BAD_REQUEST, e),
    };
    match packages::yank(&state.db, &ver.id, None, yanked) {
        Ok(true) => {}
        Ok(false) => return cargo_error(StatusCode::NOT_FOUND, "no such version"),
        Err(e) => return internal(e),
    }
    // The same record the REST door writes, so "who yanked this?" has
    // one answer whichever way it was done.
    crate::api::audit(
        &state,
        &principal,
        if yanked {
            "package.yank"
        } else {
            "package.unyank"
        },
        serde_json::json!({ "package": pkg.name, "version": ver.version, "reason": null }),
    );
    Json(serde_json::json!({ "ok": true })).into_response()
}
