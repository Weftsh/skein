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

use crate::api::{
    cargo_api, license_api, maven_api, npm_api, packages_api, people_api, pypi_api, registry_door,
};
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
    /// The commercial licence: warnings only, never a refusal.
    pub license: crate::license::Licensing,
    org: OnceLock<Org>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(
        db: ControlDb,
        store_url: String,
        public_url: String,
        license: crate::license::Licensing,
    ) -> AppState {
        AppState {
            db,
            store_url,
            public_url,
            instance: std::env::var("SKEIN_INSTANCE_ID").ok(),
            license,
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
    matches!(
        eco,
        Ecosystem::Npm | Ecosystem::Maven | Ecosystem::Pypi | Ecosystem::Cargo
    )
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
        .route("/license", get(license_api::show).put(license_api::install))
        .route("/license/check", post(license_api::check_now))
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
                .delete(npm_api::delete)
                .layer(axum::extract::DefaultBodyLimit::max(
                    npm_api::PUBLISH_BODY_LIMIT,
                )),
        )
        // Maven `PUT`s each file of a release at a path derived from its
        // coordinate and `GET`s it back. One wildcard, because a groupId
        // has any number of segments: `maven::parse_path` reads the
        // coordinate from the right, the only way it is unambiguous.
        .route(
            "/maven/*path",
            get(maven_api::get)
                .put(maven_api::put)
                .layer(axum::extract::DefaultBodyLimit::max(maven_api::BODY_LIMIT)),
        )
        // PyPI. Two doors on one prefix: pip reads the Simple API
        // under `/pypi/simple/`, and twine POSTs its form to the
        // repository URL itself — which is the bare `/pypi`, with or
        // without a trailing slash depending on what somebody wrote in
        // their `.pypirc`, so both are registered rather than one being
        // a redirect twine refuses to follow for a POST.
        .route(
            "/pypi",
            post(pypi_api::upload).layer(axum::extract::DefaultBodyLimit::max(
                pypi_api::UPLOAD_BODY_LIMIT,
            )),
        )
        .route(
            "/pypi/",
            post(pypi_api::upload).layer(axum::extract::DefaultBodyLimit::max(
                pypi_api::UPLOAD_BODY_LIMIT,
            )),
        )
        .route("/pypi/*path", get(pypi_api::get))
        // Cargo. The sparse index is one wildcard; the three API calls
        // are their own routes because `cargo publish` PUTs and `cargo
        // yank` DELETEs at fixed paths, and a wildcard that swallowed
        // them would have to re-parse a method the router already knows.
        // The publish carries the whole `.crate` in one framed body, so
        // it has its own limit — axum's 2 MiB default would refuse an
        // ordinary crate before any of our own checks ran.
        .route(
            "/cargo/api/v1/crates/new",
            put(cargo_api::publish).layer(axum::extract::DefaultBodyLimit::max(
                cargo_api::PUBLISH_BODY_LIMIT,
            )),
        )
        // `…/:name/:version/:verb` carries three verbs on one shape —
        // `download`, `yank` and `unyank` — so all three methods hang
        // off one route. Registering the download under the wildcard
        // below instead would never be reached: a router prefers the
        // more specific path and answers 405, which reads as "cargo is
        // sending the wrong method" rather than as a routing mistake.
        .route(
            "/cargo/api/v1/crates/:name/:version/:verb",
            get(cargo_api::download)
                .delete(cargo_api::yank)
                .put(cargo_api::yank),
        )
        .route("/cargo/*path", get(cargo_api::get))
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
    crate::license::spawn(state.clone());
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
