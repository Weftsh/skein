//! The server: its state, its routes, and the layers every request
//! passes through.
//!
//! ## One organization, found once
//!
//! A Skein install serves one organization, created by `skein admin
//! bootstrap`. The server starts without one — so `docker compose up`
//! works before anybody has run the bootstrap — and answers every
//! registry and API request with a 503 that says what to run, until the
//! organization exists. From then on it is read once and kept: its id is
//! the store prefix, and ids do not change.

use crate::api::{npm_api, oci_api, packages_api, people_api, registry_door};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Router;
use skein_control::packages::Ecosystem;
use skein_control::registry::Org;
use skein_control::ControlDb;
use std::sync::{Arc, OnceLock};

pub struct AppState {
    pub db: ControlDb,
    /// The bucket, e.g. `http://127.0.0.1:9000/skein` or
    /// `https://skein.s3.eu-west-1.amazonaws.com`.
    pub store_url: String,
    /// Where clients reach this server — written into the documents a
    /// registry hands out (an npm tarball URL, a Cargo `dl`).
    pub public_url: String,
    /// Echoed on `/healthz`, so a test harness can prove the server on a
    /// port is the one it started.
    pub instance: Option<String>,
    org: OnceLock<Org>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(db: ControlDb, store_url: String, public_url: String) -> AppState {
        AppState {
            db,
            store_url,
            public_url,
            instance: std::env::var("SKEIN_INSTANCE_ID").ok(),
            org: OnceLock::new(),
        }
    }

    /// The organization. Only reachable behind [`setup_layer`], which
    /// refuses every request before the install is bootstrapped — so a
    /// handler that runs has one.
    pub fn org(&self) -> &Org {
        self.org
            .get()
            .expect("the setup layer refuses requests until the organization exists")
    }

    /// Its current name. Read from the database rather than the cached
    /// row, because an admin may rename it while the server runs.
    pub fn org_name(&self) -> String {
        skein_control::registry::the_org(&self.db)
            .ok()
            .flatten()
            .map(|o| o.name)
            .unwrap_or_else(|| self.org().name.clone())
    }

    /// Whether the organization exists yet, loading it the first time.
    pub fn ready(&self) -> Result<bool, String> {
        if self.org.get().is_some() {
            return Ok(true);
        }
        match skein_control::registry::the_org(&self.db)? {
            Some(o) => {
                let _ = self.org.set(o);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// The ecosystems this build has a door for. Enabling one that is not
/// here would answer 404 for everything, which reads as a broken
/// registry rather than a missing feature.
pub fn served(eco: Ecosystem) -> bool {
    matches!(eco, Ecosystem::Npm | Ecosystem::Oci)
}

pub fn router(state: SharedState) -> Router {
    let api = Router::new()
        .route(
            "/session",
            get(people_api::session)
                .post(people_api::login)
                .delete(people_api::logout),
        )
        .route("/me", get(people_api::me))
        .route("/me/password", put(people_api::change_password))
        .route(
            "/me/tokens",
            get(people_api::my_tokens).post(people_api::mint_mine),
        )
        .route("/tokens", get(people_api::all_tokens))
        .route(
            "/tokens/:id",
            axum::routing::delete(people_api::revoke_token),
        )
        .route(
            "/users",
            get(people_api::list_users).post(people_api::create_user),
        )
        .route(
            "/users/:id",
            axum::routing::patch(people_api::update_user).delete(people_api::delete_user),
        )
        .route(
            "/users/:id/tokens",
            get(people_api::user_tokens).post(people_api::mint_for_user),
        )
        .route("/overview", get(people_api::overview))
        .route("/org", put(people_api::rename_org))
        .route("/audit", get(people_api::audit_log))
        .route(
            "/ecosystems",
            get(packages_api::ecosystems).put(packages_api::set_ecosystem),
        )
        .route("/packages", get(packages_api::list))
        .route(
            "/packages/:id",
            get(packages_api::show).delete(packages_api::remove),
        )
        .route(
            "/packages/:id/versions/:version/yank",
            post(packages_api::yank),
        )
        .route(
            "/policy",
            get(packages_api::policy).put(packages_api::set_policy),
        )
        .route("/policy/licenses", put(packages_api::set_license))
        .route(
            "/policy/namespaces",
            post(packages_api::reserve).delete(packages_api::release),
        )
        .route(
            "/findings",
            get(packages_api::findings).delete(packages_api::forget_finding),
        )
        .fallback(|| async { crate::api::json_error(StatusCode::NOT_FOUND, "no such API route") });

    let registry = Router::new()
        // npm addresses a package at `/<name>` and a tarball at
        // `/<name>/-/<file>`, and a scoped name is two segments — so one
        // wildcard, and `npm_api::split_path` tells the two apart.
        .route(
            "/npm/*path",
            get(npm_api::get)
                .put(npm_api::put)
                .layer(axum::extract::DefaultBodyLimit::max(
                    npm_api::PUBLISH_BODY_LIMIT,
                )),
        )
        // The OCI distribution API, which **cannot** live under a prefix.
        // A container client parses `host/path/image` as registry `host`
        // and repository `path/image` and then talks to
        // `https://host/v2/…`; there is nowhere to put a base path. So
        // `/v2/` is a reserved top-level segment, and the repository is
        // the whole path after it.
        //
        // One wildcard and one root, because a repository name contains
        // slashes and the markers that end it (`/blobs/`, `/manifests/`)
        // are found from the right — see `registry::oci::parse_path`.
        //
        // **No body limit.** A layer arrives as one request body and is
        // read as a stream straight into blocks; a limit here would cap
        // an image at whatever number somebody wrote, and the failure
        // would be a push that dies part-way with no explanation. The
        // blob ceiling is `blobs::MAX_BLOB`, counted as the body streams.
        .route("/v2/", get(oci_api::root))
        .route(
            "/v2/*path",
            get(oci_api::any)
                .head(oci_api::any)
                .post(oci_api::any)
                .put(oci_api::any)
                .patch(oci_api::any)
                .delete(oci_api::any)
                .layer(axum::extract::DefaultBodyLimit::disable()),
        )
        .nest("/api/v1", api)
        .layer(middleware::from_fn_with_state(state.clone(), setup_layer))
        .layer(middleware::from_fn(csrf_layer))
        .layer(middleware::from_fn(registry_door::cache_layer));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .merge(registry)
        .merge(crate::ui::routes())
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Liveness: the process is serving. Echoes the instance id, so a test
/// harness can prove the server on a port is the one it started.
async fn healthz(State(state): State<SharedState>) -> Response {
    let mut r = "ok\n".into_response();
    if let Some(v) = state
        .instance
        .as_deref()
        .and_then(|i| HeaderValue::from_str(i).ok())
    {
        r.headers_mut().insert("x-skein-instance", v);
    }
    r
}

/// Readiness: the database answers, the bucket exists and answers 404
/// for what it does not hold, and the install has been set up — see
/// `ObjectStore::probe` for why the bucket takes two requests. This is
/// where an operator should hear about a missing bucket or a policy
/// without `s3:ListBucket`: before the first `npm install`, not during
/// it.
async fn readyz(State(state): State<SharedState>) -> Response {
    let db = state.db.clone();
    let store_url = state.store_url.clone();
    let checked = tokio::task::spawn_blocking(move || {
        skein_control::registry::ping(&db)?;
        skein_store::ObjectStore::with_timeout(&store_url, std::time::Duration::from_secs(3))
            .probe()
    })
    .await
    .unwrap_or_else(|e| Err(format!("join: {e}")));
    if let Err(e) = checked {
        return (StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n")).into_response();
    }
    match state.ready() {
        Ok(true) => "ready\n".into_response(),
        Ok(false) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "not set up yet: run `skein admin bootstrap --org <name>`\n",
        )
            .into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, format!("{e}\n")).into_response(),
    }
}

/// Refuse every registry and API request until the install has an
/// organization.
async fn setup_layer(State(state): State<SharedState>, req: Request, next: Next) -> Response {
    if state.org.get().is_some() {
        return next.run(req).await;
    }
    let db_state = state.clone();
    let ready = tokio::task::spawn_blocking(move || db_state.ready())
        .await
        .unwrap_or_else(|e| Err(format!("join: {e}")));
    match ready {
        Ok(true) => next.run(req).await,
        Ok(false) => crate::api::json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "this Skein has not been set up yet: run `skein admin bootstrap --org <name>` \
             on the server",
        ),
        Err(e) => crate::api::internal(e),
    }
}

/// The header a browser cannot send across origins without asking.
pub const CSRF_HEADER: &str = "x-skein-csrf";

/// A state-changing API request that does not carry a token must carry
/// [`CSRF_HEADER`].
///
/// The session cookie is `SameSite=Lax`, which already keeps it off a
/// cross-site POST. This is the second wall, and the one that holds when
/// the first does not — an older browser, or an attacker on a sibling
/// subdomain, which counts as the same *site*. A custom header cannot be
/// attached to a cross-origin request without a CORS preflight, which
/// this server never answers, so a page elsewhere cannot forge one.
///
/// A request that carries `Authorization` is exempt: a browser never
/// attaches one on its own, so a request that has one was written by
/// somebody holding the token. Sign-in is included — without it a page
/// elsewhere could sign a visitor in as the attacker.
async fn csrf_layer(req: Request, next: Next) -> Response {
    let unsafe_method = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if unsafe_method
        && req.uri().path().starts_with("/api/")
        && !req.headers().contains_key(header::AUTHORIZATION)
        && !req.headers().contains_key(CSRF_HEADER)
    {
        return crate::api::json_error(
            StatusCode::FORBIDDEN,
            format!("a request from the browser must carry the {CSRF_HEADER} header"),
        );
    }
    next.run(req).await
}

/// Headers every answer carries.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    res
}

/// Serve until SIGINT or SIGTERM, then finish what is in flight.
pub async fn serve(state: SharedState, bind: &str) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    eprintln!("skein: serving on {bind} (public URL {})", state.public_url);
    crate::gc::spawn(state.clone());
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| format!("serve: {e}"))
}

async fn shutdown() {
    let int = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = int => {},
        _ = term => {},
    }
    eprintln!("skein: shutting down");
}
