//! The HTTP surface: the five ecosystem doors, which speak each
//! client's own wire protocol, and the REST API the UI and an operator's
//! scripts use.

pub mod npm_api;
pub mod oci_api;
pub mod packages_api;
pub mod people_api;
pub mod registry_door;

use crate::app::SharedState;
use axum::http::StatusCode;
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
