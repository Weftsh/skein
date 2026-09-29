//! The npm registry's doors: a packument, a publish, and a tarball.
//!
//! Three routes behind two path patterns, because that is what the
//! client's URLs are. npm addresses a package at `/<name>` and its
//! tarball at `/<name>/-/<file>.tgz`, and a scoped name is two path
//! segments — so the path after `/npm/` is a **wildcard**, and
//! [`split_path`] decides which of the two it is. Splitting them into
//! separate routes is not available: `@acme/widget` and
//! `@acme/widget/-/widget-1.0.0.tgz` differ only in a segment that a
//! router cannot tell from part of the name.
//!
//! ## The refusals are ordered, and the order is the point
//!
//! See [`registry_door`]: no credential is a 401 with a `Basic`
//! challenge before anything else is looked at, which is what makes
//! `npm login` work and what keeps the name of any package from being
//! told to somebody who has not said who they are. Only then does npm
//! being off, or the package being absent, get a 404.
//!
//! ## Why a `Basic` challenge
//!
//! npm sends `Authorization: Bearer <_authToken>` once it has one, but
//! it only learns it needs one from a 401. The REST API must not send a
//! Basic challenge — a browser meeting one puts up a credential dialog
//! nobody can use — so the distinction is [`crate::authx::Challenge`].

use crate::api::internal;
use crate::api::{people_api, registry_door};
use crate::app::SharedState;
use crate::registry::{blobs, npm};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use skein_control::auth::{Principal, Scope};
use skein_control::packages::{self, Ecosystem, Package, PackageFile, PackageVersion, Provenance};
use skein_control::registry::Org;
use std::net::SocketAddr;

/// The body limit for a publish. An npm publish carries its tarball
/// base64-encoded, which is four bytes on the wire for every three
/// stored, so the limit has to be the artifact ceiling plus that
/// expansion and a little room for the manifest around it.
pub const PUBLISH_BODY_LIMIT: usize = blobs::MAX_ARTIFACT / 3 * 4 + 1024 * 1024;

/// A publish is base64, so the body limit has to carry the expansion —
/// otherwise the largest artifact we claim to accept is refused by the
/// router before any of our own checks run, with a message that says
/// nothing about size. Checked at compile time: it is a property of two
/// constants and there is no run in which it could differ.
const _: () = assert!(PUBLISH_BODY_LIMIT > blobs::MAX_ARTIFACT / 3 * 4);

/// npm's own error shape: `{"error": "…"}`. The client prints it, so it
/// is the whole of what a person sees when a publish fails.
fn npm_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

/// What the wildcard after `/npm/` was.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// The package itself: a packument, or a publish.
    Package(String),
    /// A tarball: `<name>/-/<filename>`.
    Tarball { name: String, filename: String },
}

/// Split npm's wildcard path into a package and, if there is one, the
/// tarball it names.
///
/// `/-/` is npm's marker and cannot occur inside a name: a scoped name
/// has exactly one slash and `-` alone is not a legal scope. Splitting
/// on the **last** occurrence rather than the first is deliberate, so a
/// package that manages to contain the marker earlier still resolves its
/// tarball rather than silently addressing a different package.
pub fn split_path(path: &str) -> Target {
    let path = npm::decode_name(path.trim_matches('/'));
    match path.rfind("/-/") {
        Some(at) => {
            let (name, rest) = path.split_at(at);
            Target::Tarball {
                name: name.to_string(),
                filename: rest.trim_start_matches("/-/").to_string(),
            }
        }
        None => Target::Package(path),
    }
}

/// Authorize, in npm's dialect of refusal, and only then check npm is
/// switched on.
///
/// The decision is [`registry_door`]'s and is shared with every other
/// ecosystem; all this adds is the body npm reads.
fn open(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
) -> Result<(Org, Principal), Response> {
    let p = registry_door::authorize(state, headers, need, npm_refusal)?;
    let org = registry_door::eco_org(state, headers, Ecosystem::Npm)?;
    Ok((org, p))
}

/// npm's error shape, as [`registry_door::Refusal`] wants it.
fn npm_refusal(status: StatusCode, msg: String) -> Response {
    npm_error(status, msg)
}

/// `GET /npm/*path` — a packument, or a tarball.
pub async fn get(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (org, principal) = match open(&state, &headers, Scope::PackageRead) {
        Ok(x) => x,
        Err(r) => return r,
    };
    // npm's own endpoints live under `-/`, a prefix no package name can
    // have. `npm whoami` and `npm ping` are what somebody runs first to
    // check a new `.npmrc`, and answering them as "no such package"
    // sends that person looking for a problem in the wrong place.
    match path.trim_matches('/') {
        "-/whoami" => {
            return Json(serde_json::json!({ "username": principal.username })).into_response()
        }
        "-/ping" => return Json(serde_json::json!({})).into_response(),
        _ => {}
    }
    // The base a *packument's* tarball URLs are built from is the one
    // this client reached us on — see `registry_door::self_base`.
    let base = registry_door::self_base(&state, &headers);
    match split_path(&path) {
        Target::Package(name) => packument(state, org, name, base).await,
        Target::Tarball { name, filename } => tarball(state, org, name, filename).await,
    }
}

async fn packument(state: SharedState, org: Org, name: String, base: String) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Npm, &name) {
        Ok(p) => p,
        // A name that is not a legal npm name is the same answer: npm
        // asked for something we do not have. A 400 would be
        // technically truer and would also tell an anonymous caller the
        // difference between "malformed" and "private", which is not
        // worth the precision.
        Err(_) => return npm_error(StatusCode::NOT_FOUND, "no such package"),
    };
    match pkg {
        // The organization's own package. The local lookup comes first,
        // always, and it is final: a public `@acme/widget` answering
        // for a private one is dependency confusion built into the
        // product.
        Some(p) if !p.is_proxied() => local_packument(state, org, p, None, base).await,
        // Either nothing local, or a name we have only ever cached from
        // upstream. Both go through the proxy, and for the same reason:
        // the upstream is the source of truth for *which versions
        // exist*. Answering a cached package's packument from our own
        // rows would freeze it at whatever the first install happened
        // to fetch, so `npm install lodash@latest` would return the
        // same version for ever.
        other => proxied_packument(state, org, name, other, base).await,
    }
}

/// The packument for a package whose rows we hold.
///
/// `gate` is `Some` only for a cached *proxied* package, where the
/// admission policy has to be applied again on the way out — see
/// [`Gate`].
async fn local_packument(
    state: SharedState,
    org: Org,
    pkg: Package,
    gate: Option<Gate>,
    base: String,
) -> Response {
    let name = pkg.name.clone();
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let tags = match packages::tags(&state.db, &pkg.id) {
        Ok(t) => t,
        Err(e) => return internal(e),
    };

    // One query per version for its files. A packument is read far more
    // often than it is written, so this is the thing to watch as
    // packages grow a long version history — but a join returning one
    // row per (version, file) would have to be regrouped here anyway,
    // and correctness first.
    let mut views = Vec::with_capacity(versions.len());
    for v in &versions {
        if let Some(g) = &gate {
            if g.record(&state, &org, &name, v).withholds() {
                continue;
            }
        }
        let files = match packages::files(&state.db, &v.id) {
            Ok(f) => f,
            Err(e) => return internal(e),
        };
        let Some(file) = files.first() else { continue };
        views.push(npm::VersionView {
            version: v.version.clone(),
            metadata: v.metadata.clone(),
            digests: file.digests.clone(),
            filename: file.filename.clone(),
            yanked: v.yanked,
        });
    }

    let pkg_name = pkg.name.clone();
    let doc = npm::packument(
        &pkg.name,
        &views,
        &tags,
        |v| format!("{base}/npm/{pkg_name}/-/{}", v.filename),
        // The digests npm verifies against are recomputed from the bytes
        // we hold rather than remembered from the publish, so the
        // packument can never advertise a hash the tarball does not have.
        // They are stored on the file row at publish time; see `publish`.
        digests_of,
    );
    Json(doc).into_response()
}

/// `(shasum, integrity)` for one version, read off the row.
///
/// **Not** recomputed from the stored bytes. Doing that would mean one
/// object GET per version on every packument read — the hottest read a
/// registry has — so a package with two hundred versions would make two
/// hundred store round trips to answer one `npm install`, on a thread
/// that is supposed to be running the async runtime.
///
/// They cannot drift from the object: they are computed at publish from
/// bytes that had just been verified against their SHA-256, the object
/// is addressed by that SHA-256, and a published version is immutable.
fn digests_of(v: &npm::VersionView) -> (String, String) {
    let parsed: serde_json::Value =
        serde_json::from_str(&v.digests).unwrap_or(serde_json::Value::Null);
    let pick = |k: &str| {
        parsed
            .get(k)
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string()
    };
    // Empty rather than a guess when a row predates this: npm reads a
    // missing integrity as "do not check" and still installs, where a
    // wrong one fails every install with a corruption error pointing at
    // the user's own cache.
    (pick("sha1"), pick("sha512"))
}

async fn tarball(state: SharedState, org: Org, name: String, filename: String) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Npm, &name) {
        Ok(Some(p)) => p,
        Ok(None) => return proxied_tarball(state, org, name, filename).await,
        Err(_) => return npm_error(StatusCode::NOT_FOUND, "no such package"),
    };
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };

    // The filename is npm's convention, so it is derivable — but it is
    // matched against what was actually stored rather than parsed back
    // into a version. Parsing `widget-1.0.0-beta.1.tgz` into a name and
    // a version is ambiguous (a hyphen is legal in both), and guessing
    // wrong serves one version's bytes under another's name.
    let mut found = None;
    for v in &versions {
        let files = match packages::files(&state.db, &v.id) {
            Ok(f) => f,
            Err(e) => return internal(e),
        };
        if let Some(f) = files.into_iter().find(|f| f.filename == filename) {
            found = Some((v, f));
            break;
        }
    }
    let Some((version, file)) = found else {
        // Nothing local under that filename. It may be a version this
        // organization proxies and has not cached yet.
        return proxied_tarball(state, org, name, filename).await;
    };

    // A cached proxied artifact meets the policy again on the way out.
    // This is the request that matters: a client with a lockfile asks
    // for the tarball and reads no packument at all, so the filtering
    // done there is not a gate this request ever meets.
    match Gate::for_package(&state, &org, &pkg) {
        Ok(Some(g)) => {
            let d = g.record(&state, &org, &name, version);
            if let crate::registry::policy::Decision::Refuse { reason, .. } = &d {
                if d.withholds() {
                    return npm_error(StatusCode::FORBIDDEN, reason.clone());
                }
            }
        }
        Ok(None) => {}
        Err(e) => return internal(e),
    }

    match registry_door::read_artifact(&state, &file.digest).await {
        Ok(Some(b)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CACHE_CONTROL,
                    "private, max-age=31536000, immutable",
                ),
            ],
            b,
        )
            .into_response(),
        Ok(None) => npm_error(StatusCode::NOT_FOUND, "no such tarball"),
        Err(r) => r,
    }
}

/// The prefix `npm login` PUTs a username and password to, once the
/// registry has declined its web login (any 4xx on `POST /-/v1/login`).
const COUCH_USER: &str = "-/user/org.couchdb.user:";

/// `npm login`: a username and password, exchanged for a token.
///
/// The one door here that takes a password rather than a token, and so
/// the one that answers before `open` — the person has no token yet;
/// that is why they are here. It is `users::authenticate`, the same
/// check the UI's sign-in makes, and fails the same way for every reason
/// so it cannot be used to discover who has an account.
///
/// The token is scoped to the role's *registry* authority — install for
/// a reader, publish for a publisher or an admin — never `org:admin`. A
/// credential written into a file by a package manager is the one most
/// likely to be copied somewhere it should not be, and it has no use for
/// administering the registry.
///
/// The password goes through the same throttle as the UI's sign-in
/// (`people_api::check_password`), on the same counters: a guesser gains
/// nothing by moving between the two.
async fn couch_login(
    state: SharedState,
    peer: SocketAddr,
    headers: &HeaderMap,
    url_user: String,
    body: Bytes,
) -> Response {
    match packages::ecosystem_policy(&state.db, &state.org().id, Ecosystem::Npm) {
        Ok(p) if p.enabled() => {}
        Ok(_) => return npm_error(StatusCode::NOT_FOUND, "npm is not switched on here"),
        Err(e) => return internal(e),
    }
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let (Some(name), Some(password)) = (doc["name"].as_str(), doc["password"].as_str()) else {
        return npm_error(
            StatusCode::BAD_REQUEST,
            "a login needs a name and a password",
        );
    };
    // The name in the URL is the one npm prompted for; the body must
    // agree, or the token would be minted for somebody else.
    if !name.eq_ignore_ascii_case(&url_user) {
        return npm_error(
            StatusCode::BAD_REQUEST,
            "the name in the URL and the body differ",
        );
    }
    let checked = people_api::check_password(
        &state,
        peer,
        headers,
        people_api::PasswordDoor::NpmLogin,
        name,
        password,
    );
    let user = match checked {
        Ok(Some(u)) => u,
        Ok(None) => return npm_error(StatusCode::UNAUTHORIZED, "invalid username or password"),
        Err(r) => return r,
    };
    let scope = if user.role == skein_control::users::Role::Reader {
        Scope::PackageRead
    } else {
        Scope::PackageWrite
    };
    let (info, token) =
        match skein_control::auth::mint(&state.db, &user, "npm login", &[scope], None) {
            Ok(x) => x,
            Err(e) => return internal(e),
        };
    crate::api::audit(
        &state,
        &Principal::for_user(&user),
        "token.create",
        serde_json::json!({ "token": info.id, "owner": user.username, "label": info.label, "scopes": [scope.as_str()] }),
    );
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "id": format!("org.couchdb.user:{}", user.username),
            "token": token,
        })),
    )
        .into_response()
}

/// `DELETE /npm/-/user/token/<token>` — `npm logout`: revoke the token
/// this request carries. Only that one — naming somebody else's token in
/// the URL revokes nothing.
pub async fn delete(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let (_, principal) = match open(&state, &headers, Scope::PackageRead) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(named) = path.trim_matches('/').strip_prefix("-/user/token/") else {
        return npm_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "a package is removed from the Skein UI or API, not with npm",
        );
    };
    let presented = crate::authx::token_from_headers(&headers).unwrap_or_default();
    let (Some(id), true) = (principal.token_id.as_deref(), named == presented) else {
        return npm_error(
            StatusCode::NOT_FOUND,
            "that is not the token this request carries",
        );
    };
    match skein_control::auth::revoke(&state.db, id) {
        Ok(_) => {
            crate::api::audit(
                &state,
                &principal,
                "token.revoke",
                serde_json::json!({ "token": id, "via": "npm logout" }),
            );
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => internal(e),
    }
}

/// `PUT /npm/*path` — publish one version, or `npm login`.
pub async fn put(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(user) = path.trim_matches('/').strip_prefix(COUCH_USER) {
        let user = npm::decode_name(user);
        return couch_login(state, peer, &headers, user, body).await;
    }
    let (org, principal) = match open(&state, &headers, Scope::PackageWrite) {
        Ok(x) => x,
        Err(r) => return r,
    };

    let Target::Package(url_name) = split_path(&path) else {
        return npm_error(
            StatusCode::BAD_REQUEST,
            "a publish is a PUT to the package, not to a tarball",
        );
    };

    let doc: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return npm_error(
                StatusCode::BAD_REQUEST,
                format!("this publish is not JSON: {e}"),
            )
        }
    };
    let publish = match npm::parse_publish(&doc) {
        Ok(p) => p,
        Err(e) => return npm_error(StatusCode::BAD_REQUEST, e),
    };

    // The name in the URL and the name in the body must agree. They can
    // differ — `npm publish` builds both from `package.json` — and if
    // they ever do, taking either one silently publishes under a name
    // the publisher did not mean.
    let normalized_url = packages::normalize_name(Ecosystem::Npm, &url_name);
    let normalized_body = packages::normalize_name(Ecosystem::Npm, &publish.name);
    match (&normalized_url, &normalized_body) {
        (Ok(a), Ok(b)) if a == b => {}
        (Err(e), _) | (_, Err(e)) => return npm_error(StatusCode::BAD_REQUEST, e.clone()),
        _ => {
            return npm_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "this publish is addressed to {url_name:?} and names {:?}",
                    publish.name
                ),
            )
        }
    }

    // Only under the organization's own scopes, and before anything is
    // written — `ensure` would create the package row. The `.npmrc`
    // every client is handed routes those scopes here and nothing else,
    // so a name outside them is one `npm install` sends to public npmjs,
    // where anybody can own it: an internal package published unscoped
    // was one a stranger could shadow for every build that installed it.
    // Every new version, including of a package from before this rule.
    let scopes = match packages::npm_scopes(&state.db, &org.id) {
        Ok(s) => s,
        Err(e) => return internal(e),
    };
    let own = skein_control::registry::own_npm_scope(&state.org_name());
    if let Some(sentence) = npm::scope_refusal(&publish.name, &scopes, &own) {
        return npm_error(StatusCode::FORBIDDEN, sentence);
    }

    let now = skein_control::ids::now_ms();
    let pkg = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Npm,
        &publish.name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return npm_error(StatusCode::BAD_REQUEST, e),
    };

    // A name this organization cached from upstream is not a name it may
    // publish over: the versions under it came from somewhere else, and
    // mixing the two is how a local publish silently shadows — or is
    // shadowed by — a public package.
    if pkg.is_proxied() {
        return npm_error(
            StatusCode::CONFLICT,
            format!(
                "{:?} is cached from an upstream registry here and cannot be published to",
                pkg.name
            ),
        );
    }

    // Bytes first, row second. The reverse would make a version visible
    // that has no tarball, and a resolver that met it would cache the
    // broken answer.
    let digest =
        match registry_door::store_artifact(&state, &publish.tarball, now, npm_refusal).await {
            Ok(d) => d,
            Err(r) => return r,
        };
    let prov = registry_door::provenance(&principal);

    let filename = npm::tarball_name(&pkg.name, &publish.version);
    let metadata = publish.metadata.to_string();
    let file = PackageFile {
        filename: filename.clone(),
        digest: digest.clone(),
        size_bytes: publish.tarball.len() as i64,
        content_type: "application/octet-stream".into(),
        // Computed here, from bytes already proved to match their
        // SHA-256, so the packument can serve them without touching the
        // store. These are what npm checks on install.
        digests: serde_json::json!({
            "sha1": npm::shasum_of(&publish.tarball),
            "sha512": npm::integrity_of(&publish.tarball),
        })
        .to_string(),
    };
    let version = match packages::publish_version(
        &state.db,
        &pkg.id,
        &publish.version,
        &publish.license,
        &metadata,
        std::slice::from_ref(&file),
        &prov,
        now,
    ) {
        Ok(v) => v,
        Err(packages::PublishError::Exists) => {
            return npm_error(
                StatusCode::CONFLICT,
                format!(
                    "{} {} is already published, and a published version never changes",
                    pkg.name, publish.version
                ),
            )
        }
        Err(packages::PublishError::Other(e)) => return internal(e),
    };

    // Tags last: a tag pointing at a version that failed to land would
    // send every `npm install` to a version that is not there.
    for (tag, v) in &publish.tags {
        if v != &publish.version {
            continue;
        }
        if let Err(e) = packages::set_tag(&state.db, &pkg.id, tag, &version.id, now) {
            return internal(e);
        }
    }

    crate::api::audit(
        &state,
        &principal,
        "package.publish",
        serde_json::json!({ "ecosystem": "npm", "name": pkg.name, "version": version.version }),
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "ok": true,
            "id": pkg.name,
            "rev": version.id,
        })),
    )
        .into_response()
}

/// A name this organization does not publish, fetched from upstream if
/// it proxies and if the policy admits it.
///
/// Ordered so the existence of a private package is never disclosed and
/// a reserved name is never fetched:
///
/// 1. the ecosystem is not in `proxy` mode → the ordinary 404;
/// 2. the name is under one of the organization's npm scopes → **not**
///    fetched, in any mode: what is cached is served, and otherwise it
///    is the ordinary 404. Publishing is held to those scopes, so such
///    a name is ours whether or not anybody has published it yet, and
///    asking would install whoever registered it upstream first;
/// 3. the name is inside a reserved namespace → refused, and not
///    fetched, in block mode — audit mode records it and goes on;
/// 4. the upstream does not have it → 404;
/// 5. otherwise the document is filtered to the versions the policy
///    admits, with every tarball pointed back at us.
async fn proxied_packument(
    state: SharedState,
    org: Org,
    name: String,
    cached: Option<Package>,
    base: String,
) -> Response {
    use crate::registry::{policy, upstream::Upstream};

    let eco = Ecosystem::Npm;
    let mode = match packages::ecosystem_policy(&state.db, &org.id, eco) {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    // What we already hold, filtered by today's policy. This is the
    // answer whenever we cannot or must not ask the upstream — the
    // proxy having been switched off, or npmjs being down — and it is
    // half of why a pull-through is worth having at all.
    let from_cache = |state: SharedState, org: Org, cached: Option<Package>, base: String| async move {
        match cached {
            Some(p) => match Gate::for_package(&state, &org, &p) {
                Ok(g) => local_packument(state, org, p, g, base).await,
                Err(e) => internal(e),
            },
            None => npm_error(StatusCode::NOT_FOUND, "no such package"),
        }
    };
    if !mode.proxies() {
        return from_cache(state, org, cached, base).await;
    }
    let admission = match packages::admission_policy(&state.db, &org.id, eco) {
        Ok(a) => a,
        Err(e) => return internal(e),
    };
    // Ours, published or not: never asked about, whatever the mode.
    if npm::under_scopes(&name, &admission.npm_scopes) {
        return from_cache(state, org, cached, base).await;
    }
    let licences = licence_policy(&admission);
    let now = skein_control::ids::now_ms();

    // A reserved namespace is refused without asking upstream at all.
    // Asking would be harmless in itself and is still wrong: it tells
    // the upstream which internal names this organization uses.
    if let Some(p) = admission
        .reserved
        .iter()
        .find(|p| policy::namespace_covers(p, &name))
    {
        let reason = format!(
            "{name:?} is inside {p:?}, a namespace this organization has reserved — it is \
             never fetched from an upstream registry."
        );
        let blocked = admission.blocking();
        let _ = packages::record_policy_event(
            &state.db,
            &org.id,
            eco,
            &name,
            "*",
            if blocked { "blocked" } else { "would_block" },
            policy::Rule::Reserved.as_str(),
            &reason,
            now,
        );
        if blocked {
            return npm_error(StatusCode::NOT_FOUND, reason);
        }
    }

    let Some(up) = crate::registry::upstream::Http::for_ecosystem(eco.as_str()) else {
        return from_cache(state, org, cached, base).await;
    };
    let fetch_name = name.clone();
    let body = tokio::task::spawn_blocking(move || up.metadata(&fetch_name))
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));
    let raw = match body {
        Ok(Some(b)) => b,
        Ok(None) => return npm_error(StatusCode::NOT_FOUND, "no such package"),
        // The upstream is unreachable. If we have cached this package
        // before, that is the answer — a build that got lodash
        // yesterday must not stop working because npmjs is having a
        // morning, and surviving that is most of why a pull-through
        // cache is worth running.
        //
        // With nothing cached it is a 502 and not a 404: "we could not
        // ask" and "it does not exist" are different answers, and a
        // resolver that caches the second on the first is one somebody
        // has to clear by hand.
        Err(e) => {
            eprintln!("skein: registry proxy {name}: {e}");
            if cached.is_some() {
                return from_cache(state, org, cached, base).await;
            }
            return npm_error(
                StatusCode::BAD_GATEWAY,
                "the upstream registry could not be reached",
            );
        }
    };
    let doc: serde_json::Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("skein: registry proxy {name}: unreadable upstream document: {e}");
            if cached.is_some() {
                return from_cache(state, org, cached, base).await;
            }
            return npm_error(
                StatusCode::BAD_GATEWAY,
                "the upstream registry answered nonsense",
            );
        }
    };

    // Per version, at metadata time. A client handed the whole document
    // would resolve to a version refused at tarball fetch, and that
    // reads as a broken registry rather than a policy decision.
    let mut admitted: std::collections::BTreeMap<String, bool> = Default::default();
    for v in npm::upstream_versions(&doc) {
        let d = policy::decide(
            &policy::Admission {
                blocking: admission.blocking(),
                cooldown_days: admission.cooldown_days,
                reserved: &admission.reserved,
                licences: &licences,
                unknown_allowed: mode.license_unknown == "allow",
            },
            &policy::Candidate {
                name: &name,
                version: &v.version,
                licence: v.licence.as_deref(),
                published_at: v.published_at,
            },
            now,
        );
        match &d {
            policy::Decision::Admit => {
                admitted.insert(v.version.clone(), true);
            }
            policy::Decision::Refuse {
                blocked,
                rule,
                reason,
            } => {
                let _ = packages::record_policy_event(
                    &state.db,
                    &org.id,
                    eco,
                    &name,
                    &v.version,
                    if *blocked { "blocked" } else { "would_block" },
                    rule.as_str(),
                    reason,
                    now,
                );
                // Audit mode records and serves. That is what makes the
                // policy adoptable rather than a thing switched off
                // after the first red build.
                admitted.insert(v.version.clone(), !*blocked);
            }
        }
    }

    let pkg_name = name.clone();
    let filtered =
        npm::filter_packument(&doc, &|v| admitted.get(v).copied().unwrap_or(false), |v| {
            format!(
                "{base}/npm/{pkg_name}/-/{}",
                npm::tarball_name(&pkg_name, v)
            )
        });
    Json(filtered).into_response()
}

/// Fetch one artifact from upstream, check it, cache it, serve it.
///
/// The cache is the point: the second build asking for `lodash@4.17.21`
/// gets it from our own store, at our own latency, whether or not npmjs
/// is up that morning. It is also why the bytes are stored under the
/// same content-addressed scheme as a published package — a proxied
/// artifact is an artifact.
///
/// The policy is re-checked here even though the packument already
/// filtered it. Defence in depth, and not theoretical: a client with a
/// lockfile goes straight to the tarball URL without reading a
/// packument at all, so this is the only gate that request meets.
async fn proxied_tarball(state: SharedState, org: Org, name: String, filename: String) -> Response {
    use crate::registry::{policy, upstream::Upstream};

    let eco = Ecosystem::Npm;
    let mode = match packages::ecosystem_policy(&state.db, &org.id, eco) {
        Ok(p) if p.proxies() => p,
        Ok(_) => return npm_error(StatusCode::NOT_FOUND, "no such tarball"),
        Err(e) => return internal(e),
    };
    let admission = match packages::admission_policy(&state.db, &org.id, eco) {
        Ok(a) => a,
        Err(e) => return internal(e),
    };
    // Under the organization's own scopes: never fetched, in any mode —
    // see `proxied_packument`. A lockfile goes straight here.
    if npm::under_scopes(&name, &admission.npm_scopes) {
        return npm_error(StatusCode::NOT_FOUND, "no such tarball");
    }
    if admission
        .reserved
        .iter()
        .any(|p| policy::namespace_covers(p, &name))
        && admission.blocking()
    {
        return npm_error(StatusCode::NOT_FOUND, "no such tarball");
    }
    let Some(up) = crate::registry::upstream::Http::for_ecosystem(eco.as_str()) else {
        return npm_error(StatusCode::NOT_FOUND, "no such tarball");
    };

    let fetch_name = name.clone();
    let doc = tokio::task::spawn_blocking(move || up.metadata(&fetch_name))
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));
    let doc: serde_json::Value = match doc {
        Ok(Some(b)) => match serde_json::from_slice(&b) {
            Ok(v) => v,
            Err(_) => return npm_error(StatusCode::BAD_GATEWAY, "the upstream answered nonsense"),
        },
        Ok(None) => return npm_error(StatusCode::NOT_FOUND, "no such tarball"),
        Err(e) => {
            eprintln!("skein: registry proxy {name}: {e}");
            return npm_error(
                StatusCode::BAD_GATEWAY,
                "the upstream registry could not be reached",
            );
        }
    };

    // Match the filename against each version's *derived* name rather
    // than parsing a version out of it. `widget-1.0.0-beta.1.tgz` is
    // ambiguous — a hyphen is legal in both halves — and guessing wrong
    // serves one version's bytes under another's name.
    let versions = npm::upstream_versions(&doc);
    let Some(want) = versions
        .iter()
        .find(|v| npm::tarball_name(&name, &v.version) == filename)
    else {
        return npm_error(StatusCode::NOT_FOUND, "no such tarball");
    };

    let licences = licence_policy(&admission);
    let now = skein_control::ids::now_ms();
    let decision = policy::decide(
        &policy::Admission {
            blocking: admission.blocking(),
            cooldown_days: admission.cooldown_days,
            reserved: &admission.reserved,
            licences: &licences,
            unknown_allowed: mode.license_unknown == "allow",
        },
        &policy::Candidate {
            name: &name,
            version: &want.version,
            licence: want.licence.as_deref(),
            published_at: want.published_at,
        },
        now,
    );
    if let policy::Decision::Refuse {
        blocked,
        rule,
        reason,
    } = &decision
    {
        let _ = packages::record_policy_event(
            &state.db,
            &org.id,
            eco,
            &name,
            &want.version,
            if *blocked { "blocked" } else { "would_block" },
            rule.as_str(),
            reason,
            now,
        );
    }
    if decision.withholds() {
        let reason = match &decision {
            policy::Decision::Refuse { reason, .. } => reason.clone(),
            policy::Decision::Admit => unreachable!("withholds() is false for Admit"),
        };
        return npm_error(StatusCode::FORBIDDEN, reason);
    }

    let Some(url) = want.tarball.clone() else {
        return npm_error(StatusCode::BAD_GATEWAY, "the upstream named no tarball");
    };
    let up2 = match crate::registry::upstream::Http::for_ecosystem(eco.as_str()) {
        Some(u) => u,
        None => return npm_error(StatusCode::NOT_FOUND, "no such tarball"),
    };
    let bytes = tokio::task::spawn_blocking(move || up2.fetch(&url))
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) => {
            eprintln!("skein: registry proxy {name} {}: {e}", want.version);
            return npm_error(
                StatusCode::BAD_GATEWAY,
                "the upstream artifact could not be fetched",
            );
        }
    };

    // Cache it, so the next build does not depend on the upstream being
    // up. Best-effort: a caching failure must not fail the install that
    // triggered it, which is already holding the bytes it asked for.
    cache_proxied(&state, &org, &name, want, &bytes, now);

    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CACHE_CONTROL,
                "private, max-age=31536000, immutable",
            ),
        ],
        bytes,
    )
        .into_response()
}

/// Store a proxied artifact as a package of this organization, marked
/// `proxied` so it can never be published over and is always
/// distinguishable from what the organization wrote itself.
fn cache_proxied(
    state: &SharedState,
    org: &Org,
    name: &str,
    v: &npm::UpstreamVersion,
    bytes: &[u8],
    now: i64,
) {
    let digest = blobs::digest_of(bytes);
    let store_url = state.store_url.clone();
    let prefix = org.package_prefix();
    if let Err(e) = blobs::put(&store_url, &prefix, &digest, bytes) {
        eprintln!("skein: registry cache {name} {}: {e}", v.version);
        return;
    }
    if let Err(e) = packages::note_blob(&state.db, &org.id, &digest, bytes.len() as i64, now) {
        eprintln!("skein: registry cache {name} {}: {e}", v.version);
        return;
    }
    let pkg = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Npm,
        name,
        packages::ORIGIN_PROXIED,
        now,
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("skein: registry cache {name}: {e}");
            return;
        }
    };
    let file = PackageFile {
        filename: npm::tarball_name(name, &v.version),
        digest,
        size_bytes: bytes.len() as i64,
        content_type: "application/octet-stream".into(),
        digests: serde_json::json!({
            "sha1": npm::shasum_of(bytes),
            "sha512": npm::integrity_of(bytes),
        })
        .to_string(),
    };
    let licence = match v.licence.as_deref() {
        Some(l) => skein_control::packages::License::Declared(l.to_string()),
        None => skein_control::packages::License::Unknown,
    };
    match packages::publish_version(
        &state.db,
        &pkg.id,
        &v.version,
        &licence,
        "{}",
        std::slice::from_ref(&file),
        &Provenance {
            // The upstream's own date, kept because the cooldown is a
            // claim about how long a release has been in the world. Ours
            // would make every freshly cached version zero days old.
            upstream_published_at: v.published_at,
            ..Provenance::default()
        },
        now,
    ) {
        // Two builds asking for the same version at once: one wins and
        // the other finds it already cached, which is the right answer
        // for both.
        Ok(_) | Err(packages::PublishError::Exists) => {}
        Err(e) => eprintln!("skein: registry cache {name} {}: {e}", v.version),
    }
}

/// The facts needed to re-decide a **cached proxied** version on the way
/// out, and the reason that has to happen at all.
///
/// A proxied artifact is somebody else's code that this organization's
/// policy admitted at the moment it was fetched. Policies change — and
/// the adoption path this feature recommends changes them in exactly
/// the way that makes this matter. An organization runs `audit` for a
/// week, which serves *and caches* every package it flags, and then
/// switches to `block`. Without re-deciding here, that switch would be
/// a no-op for precisely the packages audit mode found, which is the
/// entire population that mattered. The same goes for denying a licence
/// that was allowed yesterday: the artifacts already in the cache are
/// the ones somebody is worried about.
///
/// A package this organization **published** is never gated. Admission
/// policy is about what enters from outside, and applying it to our own
/// code would mean an org could lock itself out of its own registry by
/// tightening a licence rule.
struct Gate {
    admission: packages::AdmissionPolicy,
    licences: crate::registry::spdx::Policy,
    unknown_allowed: bool,
    now: i64,
}

impl Gate {
    /// `None` for a package this organization published itself.
    fn for_package(state: &SharedState, org: &Org, pkg: &Package) -> Result<Option<Gate>, String> {
        if !pkg.is_proxied() {
            return Ok(None);
        }
        let eco = Ecosystem::Npm;
        let mode = packages::ecosystem_policy(&state.db, &org.id, eco)?;
        let admission = packages::admission_policy(&state.db, &org.id, eco)?;
        let licences = licence_policy(&admission);
        Ok(Some(Gate {
            admission,
            licences,
            unknown_allowed: mode.license_unknown == "allow",
            now: skein_control::ids::now_ms(),
        }))
    }

    fn decide(&self, name: &str, v: &PackageVersion) -> crate::registry::policy::Decision {
        use crate::registry::policy;
        policy::decide(
            &policy::Admission {
                blocking: self.admission.blocking(),
                cooldown_days: self.admission.cooldown_days,
                reserved: &self.admission.reserved,
                licences: &self.licences,
                unknown_allowed: self.unknown_allowed,
            },
            &policy::Candidate {
                name,
                version: &v.version,
                licence: v.license_expr.as_deref(),
                // The upstream's date, kept at cache time. Falling back
                // to ours would be wrong in the direction that breaks
                // builds: a cached artifact is always zero days old by
                // our clock, so the cooldown would refuse every version
                // for N days *after* somebody successfully installed
                // it. `None` — an upstream that never said — is not
                // held, exactly as at fetch time.
                published_at: v.upstream_published_at,
            },
            self.now,
        )
    }

    /// Decide, and write the finding down. Same shape as the fetch
    /// path, so an artifact that is refused from the cache appears on
    /// the findings screen exactly as one refused at the upstream does.
    fn record(
        &self,
        state: &SharedState,
        org: &Org,
        name: &str,
        v: &PackageVersion,
    ) -> crate::registry::policy::Decision {
        use crate::registry::policy::Decision;
        let d = self.decide(name, v);
        if let Decision::Refuse {
            blocked,
            rule,
            reason,
        } = &d
        {
            let _ = packages::record_policy_event(
                &state.db,
                &org.id,
                Ecosystem::Npm,
                name,
                &v.version,
                if *blocked { "blocked" } else { "would_block" },
                rule.as_str(),
                reason,
                self.now,
            );
        }
        d
    }
}

/// The organization's licence rules, in the shape the evaluator takes.
fn licence_policy(a: &packages::AdmissionPolicy) -> crate::registry::spdx::Policy {
    use crate::registry::spdx::{Policy, Rule};
    let rules: Vec<(&str, Rule)> = a
        .license_rules
        .iter()
        .map(|(id, d)| {
            (
                id.as_str(),
                if d == "allow" {
                    Rule::Allow
                } else {
                    Rule::Deny
                },
            )
        })
        .collect();
    if a.license_mode == "allow_list" {
        Policy::allow_list(&rules)
    } else {
        Policy::deny_list(&rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(digests: &str) -> npm::VersionView {
        npm::VersionView {
            version: "1.0.0".into(),
            metadata: "{}".into(),
            digests: digests.into(),
            filename: "widget-1.0.0.tgz".into(),
            yanked: false,
        }
    }

    /// The digests npm checks come off the row, and a row that has
    /// neither yields empty strings rather than a guess.
    ///
    /// The direction matters: npm reads a *missing* integrity as "do not
    /// check" and installs anyway, where a *wrong* one fails the install
    /// with a corruption error that points at the user's own cache —
    /// days later, on their machine, nowhere near this code.
    #[test]
    fn the_digests_come_off_the_row_and_a_missing_one_is_empty_not_wrong() {
        assert_eq!(
            digests_of(&view(r#"{"sha1":"abc","sha512":"sha512-xyz"}"#)),
            ("abc".to_string(), "sha512-xyz".to_string())
        );
        for absent in ["{}", "", "not json", "null", r#"{"sha1":123}"#] {
            assert_eq!(
                digests_of(&view(absent)),
                (String::new(), String::new()),
                "{absent:?} produced a digest out of nothing"
            );
        }
        // One present and one not is not an error either.
        assert_eq!(
            digests_of(&view(r#"{"sha1":"abc"}"#)),
            ("abc".to_string(), String::new())
        );
    }

    /// npm's two URL shapes, told apart by the marker it puts between
    /// them — including for a scoped name, which is itself two segments.
    #[test]
    fn a_tarball_url_is_told_from_a_package_url() {
        assert_eq!(split_path("lodash"), Target::Package("lodash".into()));
        assert_eq!(
            split_path("@acme/widget"),
            Target::Package("@acme/widget".into())
        );
        assert_eq!(
            split_path("@acme%2fwidget"),
            Target::Package("@acme/widget".into()),
            "npm sends a scoped name encoded"
        );
        assert_eq!(
            split_path("@acme/widget/-/widget-1.0.0.tgz"),
            Target::Tarball {
                name: "@acme/widget".into(),
                filename: "widget-1.0.0.tgz".into()
            }
        );
        assert_eq!(
            split_path("lodash/-/lodash-4.17.21.tgz"),
            Target::Tarball {
                name: "lodash".into(),
                filename: "lodash-4.17.21.tgz".into()
            }
        );
        // Leading and trailing slashes are the router's, not the name's.
        assert_eq!(split_path("/lodash/"), Target::Package("lodash".into()));
    }

    /// The marker is split on from the right, so a name that contains it
    /// still addresses its own tarball rather than a different package.
    #[test]
    fn the_tarball_marker_is_found_from_the_right() {
        assert_eq!(
            split_path("@acme/widget/-/inner/-/widget-1.0.0.tgz"),
            Target::Tarball {
                name: "@acme/widget/-/inner".into(),
                filename: "widget-1.0.0.tgz".into()
            }
        );
    }
}
