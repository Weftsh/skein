//! The HTTP surface: the five ecosystem doors, which speak each
//! client's own wire protocol, and the REST API the UI and an operator's
//! scripts use.

pub mod cargo_api;
pub mod license_api;
pub mod maven_api;
pub mod npm_api;
pub mod oci_api;
pub mod packages_api;
pub mod people_api;
pub mod pypi_api;
pub mod registry_door;

use crate::app::SharedState;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use skein_control::audit::AuditCtx;
use skein_control::auth::Principal;

pub fn json_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": msg.into() })),
    )
        .into_response()
}

/// A REST 404, naming what is not there: `no such package`, `no such
/// person`. Not [`crate::authx::not_found`], which is the registry
/// doors' bare `not found` — right for a package manager, which prints
/// the status line, and wrong here, where the UI shows `error` and
/// nothing else.
pub fn not_found(what: &str) -> Response {
    json_error(StatusCode::NOT_FOUND, what)
}

/// The largest refusal body [`json_refusals`] will read to re-wrap. Every
/// one of ours is a sentence; anything longer is cut, not buffered.
const MAX_REFUSAL: usize = 64 * 1024;

/// Every refusal under `/api/v1` is `{"error": <a sentence>}`, whoever
/// wrote it.
///
/// A layer rather than a rule each handler keeps, because the handlers
/// are not the only authors. The shared 401 is text, written for the
/// registry doors; axum's own refusals — a body that is not JSON, a
/// method a route does not take — are text or nothing at all. And the
/// UI shows `error` and only `error`: a missing package once answered
/// the doors' bare `not found`, and the person was shown `404 Not
/// Found`. Here a text body becomes the sentence, an empty one the
/// status's own name, and a body that is already JSON is left alone.
/// The status and every other header — `Retry-After` on a 429 — stay.
pub async fn json_refusals(req: Request, next: Next) -> Response {
    let res = next.run(req).await;
    let status = res.status();
    if !(status.is_client_error() || status.is_server_error()) {
        return res;
    }
    let is_json = res
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|c| c.starts_with("application/json"));
    if is_json {
        return res;
    }
    let (mut parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_REFUSAL)
        .await
        .unwrap_or_default();
    let said = String::from_utf8_lossy(&bytes).trim().to_string();
    let sentence = if said.is_empty() {
        status
            .canonical_reason()
            .unwrap_or("refused")
            .to_ascii_lowercase()
    } else {
        said
    };
    parts.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(
        parts,
        Body::from(serde_json::json!({ "error": sentence }).to_string()),
    )
}

/// A failure that is ours, not the caller's: logged in full, and
/// answered as a 500 that says so.
///
/// The detail goes to the log *and* the body. A self-hosted registry's
/// operator is the person reading both, and "internal error" with the
/// reason held back only sends them to the log to find what the body
/// could have said.
pub fn internal(e: String) -> Response {
    eprintln!("skein: internal error: {e}");
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("internal error: {e}"),
    )
}

/// Record a change in the audit log. A failed write is logged rather
/// than failing the request: the change it describes already happened,
/// and telling the client to retry it would be worse than the missing
/// row.
pub fn audit(state: &SharedState, p: &Principal, action: &str, context: serde_json::Value) {
    let ctx = AuditCtx::of(&state.org().id, p);
    if let Err(e) = skein_control::audit::record(&state.db, &ctx, action, Some(&context)) {
        eprintln!("skein: audit {action}: {e}");
    }
}
