//! What every ecosystem's door has in common: who is asking, whether
//! this registry admits that ecosystem, and where the bytes go.
//!
//! Five protocols, one authorization story. Each adapter knows the shape
//! of one wire format and nothing else; an adapter that decided for
//! itself who may publish would be a fifth chance to get that wrong.
//!
//! ## Why the error body is the caller's
//!
//! The *decision* is shared; the *rendering* is not. npm reads
//! `{"error": …}`, Cargo reads `{"errors":[{"detail": …}]}`, Maven prints
//! the status line and never the body, and PyPI's clients
//! read the reason phrase. So each door passes in how to render a
//! refusal — [`Refusal`] — and the shared code never invents a body.
//!
//! ## The order of refusals
//!
//! 1. no credential that authenticates → 401 with a `Basic` challenge,
//!    whatever was asked for. Nothing here is public, so nothing about
//!    the registry — not even which ecosystems are switched on — is
//!    told to somebody who has not said who they are;
//! 2. the ecosystem is off → 404, the same answer as a package that is
//!    not there;
//! 3. the person's role or token does not reach the operation → 403,
//!    with a sentence saying which;
//! 4. only then, whether the package exists.

use crate::api::internal;
use crate::app::SharedState;
use crate::authx;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use skein_control::auth::{Principal, Scope};
use skein_control::packages::{self, Ecosystem};
use skein_control::registry::Org;

/// How one ecosystem's client wants to be told "no".
pub type Refusal = fn(StatusCode, String) -> Response;

/// The organization, if this ecosystem is switched on for it.
///
/// An ecosystem nobody switched on is indistinguishable from a package
/// that is not there: 404 to somebody who has authenticated, and the
/// same 401 challenge as everything else to somebody who has not.
pub fn eco_org(state: &SharedState, headers: &HeaderMap, eco: Ecosystem) -> Result<Org, Response> {
    match packages::ecosystem_policy(&state.db, &state.org().id, eco) {
        Ok(p) if p.enabled() => Ok(state.org().clone()),
        // `masked` asks whether a *credential* was presented, and asks
        // `token_from_headers` — which does not know Cargo's bare
        // `Authorization` value. Without the rewrite a `cargo` client
        // against a registry that has not switched Cargo on is
        // challenged rather than told there is no such crate, and it
        // retries the same perfectly good token for ever.
        Ok(_) => Err(authx::masked(
            &state.db,
            &with_scheme(headers),
            authx::Challenge::Basic,
        )),
        Err(e) => Err(internal(e)),
    }
}

/// Headers with Cargo's bare token spelled the way every other reader
/// in this tree expects.
fn with_scheme(headers: &HeaderMap) -> HeaderMap {
    match bare_token(headers) {
        Some(t) if authx::token_from_headers(headers).is_none() => {
            let mut h = headers.clone();
            h.insert(
                "authorization",
                format!("Bearer {t}")
                    .parse()
                    .expect("a token is header-safe"),
            );
            h
        }
        _ => headers.clone(),
    }
}

/// Cargo's bare `Authorization: <token>`.
///
/// Every other client names a scheme. Cargo does not, and has not for
/// its whole history, so a registry that only reads `Bearer` simply
/// cannot be published to with `cargo publish`. A bare value is
/// admitted only in the shape of a Skein token, so a malformed header of
/// some other scheme does not quietly become a credential.
pub fn bare_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("authorization")?.to_str().ok()?.trim();
    if raw.is_empty() || raw.contains(' ') || !raw.starts_with(skein_control::auth::PREFIX) {
        return None;
    }
    Some(raw.to_string())
}

/// Authorize, answering a registry client the way one expects to be
/// answered: a challenge when there is no credential, because a 401
/// with nothing in `WWW-Authenticate` tells a registry client nothing
/// about how to authenticate; and the ecosystem's own refusal body when
/// there is one that does not reach.
pub fn authorize(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
    refuse: Refusal,
) -> Result<Principal, Response> {
    let headers = &with_scheme(headers);
    let Some(p) = authx::principal(&state.db, headers, authx::Challenge::Basic)? else {
        return Err(authx::unauthorized(authx::Challenge::Basic));
    };
    if !p.allows(need) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            authx::refusal_sentence(&p, need),
        ));
    }
    Ok(p)
}

/// What a publish records about who made it.
pub fn provenance(p: &Principal) -> packages::Provenance<'_> {
    packages::Provenance {
        user_id: Some(&p.user_id),
        token_id: p.token_id.as_deref(),
        // Ours, not somebody else's: admission policy never runs against
        // a package this organization published.
        upstream_published_at: None,
    }
}

/// The base URL this client actually used to reach us.
///
/// Three of the five protocols make the registry tell the client where
/// to fetch from — npm's `dist.tarball`, Cargo's `dl` and `api` — and a
/// registry that always answers with its own configured public URL is
/// wrong for a client that reached it another way.
///
/// Narrow on purpose. A `Host` header is attacker-supplied, and a
/// registry that echoed it into a document other people fetch from is
/// one that can be made to serve somebody else's URL. So exactly two
/// answers:
///
/// * the configured public URL, whenever `Host` is the one it names —
///   which keeps the scheme the deployment chose, TLS and all;
/// * `http://<host>` when `Host` is **loopback**, where the only client
///   that could be misdirected is the one that chose the address.
///
/// Anything else falls back to the configured URL rather than trusting
/// it.
pub fn self_base(state: &SharedState, headers: &HeaderMap) -> String {
    base_for(&state.public_url, headers)
}

fn base_for(public_url: &str, headers: &HeaderMap) -> String {
    let configured = public_url.trim_end_matches('/').to_string();
    let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|h| !h.is_empty() && h.len() <= 255)
    else {
        return configured;
    };
    // Only the characters an authority may contain. A slash, a space or
    // a control character here is an attempt to write a second URL into
    // the document.
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b":.-[]".contains(&b))
    {
        return configured;
    }
    if configured
        .split_once("://")
        .map(|(_, rest)| rest.split('/').next().unwrap_or_default() == host)
        .unwrap_or(false)
    {
        return configured;
    }
    if is_loopback_authority(host) {
        return format!("http://{host}");
    }
    configured
}

/// `host[:port]` on loopback.
fn is_loopback_authority(host: &str) -> bool {
    let bare = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host);
    matches!(bare, "127.0.0.1" | "localhost" | "[::1]" | "::1") || bare.starts_with("127.")
}

/// Put an artifact's bytes in the store and record the blob, answering
/// in this ecosystem's dialect if it will not go.
///
/// Bytes first, row second, everywhere — the reverse makes a version
/// visible that has no artifact, and a resolver that meets one caches
/// the broken answer.
pub async fn store_artifact(
    state: &SharedState,
    bytes: &[u8],
    now: i64,
    refuse: Refusal,
) -> Result<String, Response> {
    use crate::registry::blobs;

    let digest = blobs::digest_of(bytes);
    let store_url = state.store_url.clone();
    let prefix = state.org().package_prefix();
    let owned = bytes.to_vec();
    let expected = digest.clone();
    let written =
        tokio::task::spawn_blocking(move || blobs::put(&store_url, &prefix, &expected, &owned))
            .await
            .unwrap_or_else(|e| Err(blobs::BlobError::Store(format!("join: {e}"))));
    if let Err(e) = written {
        return Err(match e {
            blobs::BlobError::TooLarge { .. } => {
                refuse(StatusCode::PAYLOAD_TOO_LARGE, e.to_string())
            }
            blobs::BlobError::DigestMismatch { .. } => {
                refuse(StatusCode::BAD_REQUEST, e.to_string())
            }
            blobs::BlobError::Store(msg) => internal(skein_store::diagnose(msg)),
        });
    }
    if let Err(e) =
        packages::note_blob(&state.db, &state.org().id, &digest, bytes.len() as i64, now)
    {
        return Err(internal(e));
    }
    Ok(digest)
}

/// Read an artifact's bytes back out. An object the store does not have
/// is `Ok(None)`: the caller decides how its client is told.
pub async fn read_artifact(state: &SharedState, digest: &str) -> Result<Option<Vec<u8>>, Response> {
    use crate::registry::blobs;

    let store_url = state.store_url.clone();
    let prefix = state.org().package_prefix();
    let digest = digest.to_string();
    match tokio::task::spawn_blocking(move || blobs::get(&store_url, &prefix, &digest))
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")))
    {
        Ok(b) => Ok(Some(b)),
        Err(e) if skein_store::is_absent(&e) => Ok(None),
        Err(e) => Err(internal(skein_store::diagnose(e))),
    }
}

/// Is this a registry door's path — one of the ecosystem prefixes, or
/// the container API at the host root?
fn is_registry_path(path: &str) -> bool {
    path == "/v2"
        || ["/v2/", "/npm/", "/maven/", "/pypi/", "/cargo/"]
            .iter()
            .any(|p| path.starts_with(p))
}

/// What a registry answer may be cached as, on its way out.
///
/// Everything a registry door serves is the organization's private
/// bytes, fetched with a credential — and a Skein install is often
/// behind a caching proxy or CDN whose cache key does not include
/// `Authorization`. So nothing here may be `public`: that word is the
/// one thing that lets a shared cache store an answer to an authorized
/// request (RFC 9111 §3.5), after which the next person to ask for the
/// URL gets it, credential or not. An immutable artifact keeps its
/// year-long `max-age` as `private`, which a client's own cache honours
/// and an edge does not.
///
/// An answer with no header of its own gets one: `no-store` for a
/// refusal, because an edge that held a 404 would answer `docker push`'s
/// HEAD after the upload with the 404 from before it, and
/// `private, no-cache` for anything else, because a packument, a tag and
/// an index all change when somebody publishes.
pub fn cache_policy(status: StatusCode, headers: &mut HeaderMap) {
    use axum::http::header::CACHE_CONTROL;
    use axum::http::HeaderValue;
    let fixed = match headers.get(CACHE_CONTROL).and_then(|v| v.to_str().ok()) {
        Some(v)
            if v.split(',')
                .any(|d| d.trim().eq_ignore_ascii_case("public")) =>
        {
            let rest: Vec<&str> = v
                .split(',')
                .map(str::trim)
                .filter(|d| !d.eq_ignore_ascii_case("public"))
                .collect();
            Some(
                format!("private, {}", rest.join(", "))
                    .trim_end_matches(", ")
                    .to_string(),
            )
        }
        Some(_) => None,
        None if status.is_client_error() || status.is_server_error() => Some("no-store".into()),
        None => Some("private, no-cache".into()),
    };
    if let Some(v) = fixed.and_then(|v| HeaderValue::from_str(&v).ok()) {
        headers.insert(CACHE_CONTROL, v);
    }
}

/// [`cache_policy`] as a layer over the whole router: the registry doors
/// are five adapters and a shared helper, and a header one of them
/// forgot is exactly the one that leaks.
pub async fn cache_layer(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let registry = is_registry_path(req.uri().path());
    let mut res = next.run(req).await;
    if registry {
        let status = res.status();
        cache_policy(status, res.headers_mut());
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_a_registry_door_answers_may_be_cached_by_an_edge() {
        use axum::http::header::CACHE_CONTROL;
        let run = |status: u16, have: Option<&str>| {
            let mut h = HeaderMap::new();
            if let Some(v) = have {
                h.insert(CACHE_CONTROL, v.parse().unwrap());
            }
            cache_policy(StatusCode::from_u16(status).unwrap(), &mut h);
            h.get(CACHE_CONTROL).unwrap().to_str().unwrap().to_string()
        };
        assert_eq!(
            run(200, Some("public, max-age=31536000, immutable")),
            "private, max-age=31536000, immutable"
        );
        assert_eq!(run(200, Some("PUBLIC")), "private");
        assert_eq!(run(200, Some("no-store")), "no-store");
        assert_eq!(run(404, None), "no-store");
        assert_eq!(run(502, None), "no-store");
        assert_eq!(run(200, None), "private, no-cache");

        for p in [
            "/v2",
            "/v2/",
            "/v2/app/blobs/sha256:00",
            "/npm/x",
            "/maven/a",
            "/pypi/simple/",
            "/cargo/index/config.json",
        ] {
            assert!(is_registry_path(p), "{p}");
        }
        for p in ["/v2x", "/api/v1/packages", "/", "/npmx", "/assets/app.js"] {
            assert!(!is_registry_path(p), "{p}");
        }
    }

    fn with_host(host: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Ok(v) = host.parse() {
            h.insert(axum::http::header::HOST, v);
        }
        h
    }

    /// Getting this wrong fails in two opposite ways: too strict and a
    /// client that reached us on localhost is sent to a URL it cannot
    /// use; too loose and a `Host` header decides what URL this registry
    /// writes into a document other people fetch from.
    #[test]
    fn a_self_referencing_url_trusts_the_host_only_when_it_is_ours_or_loopback() {
        let configured = "https://skein.example";
        let base = |host: &str| base_for(configured, &with_host(host));
        assert_eq!(base("skein.example"), "https://skein.example");
        assert_eq!(base("127.0.0.1:41234"), "http://127.0.0.1:41234");
        assert_eq!(base("localhost:8080"), "http://localhost:8080");
        assert_eq!(base("[::1]:8080"), "http://[::1]:8080");
        for hostile in [
            "evil.example",
            "skein.example.evil.test",
            "10.0.0.5:9000",
            "skein.example/../evil",
            "skein.example\r\nX-Injected: 1",
            "",
        ] {
            assert_eq!(base(hostile), configured, "{hostile:?} was trusted");
        }
        assert_eq!(base_for(configured, &HeaderMap::new()), configured);
    }

    /// Cargo sends its token with no scheme at all. Admitted only in the
    /// shape of our own tokens, so a malformed header of another scheme
    /// never becomes a credential.
    #[test]
    fn a_bare_authorization_value_is_a_cargo_token() {
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert("authorization", v.parse().unwrap());
            h
        };
        assert_eq!(
            bare_token(&headers("skein_abc_123")).as_deref(),
            Some("skein_abc_123")
        );
        assert_eq!(bare_token(&headers("Bearer skein_abc_123")), None);
        assert_eq!(bare_token(&headers("Basic dXNlcjpwdw==")), None);
        assert_eq!(bare_token(&headers("sometoken")), None);
        assert_eq!(bare_token(&headers("  ")), None);
        assert_eq!(bare_token(&HeaderMap::new()), None);

        let h = with_scheme(&headers("skein_abc_123"));
        assert_eq!(
            authx::token_from_headers(&h).as_deref(),
            Some("skein_abc_123")
        );
        let untouched = with_scheme(&headers("Bearer skein_x_y"));
        assert_eq!(untouched.get("authorization").unwrap(), "Bearer skein_x_y");
    }
}
