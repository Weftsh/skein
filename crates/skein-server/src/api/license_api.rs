//! `/api/v1/license` — what the licence says, for admins, and where one
//! installs a key. Nothing here is consulted by anything that serves.

use crate::api::{audit, internal, json_error};
use crate::app::SharedState;
use crate::authx::{self, Challenge};
use crate::license::CheckRun;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use skein_control::auth::Scope;

async fn report(state: &SharedState) -> Response {
    let st = state.clone();
    let now = skein_control::ids::now_ms();
    match tokio::task::spawn_blocking(move || st.license.report(&st.db, now)).await {
        Ok(Ok(r)) => Json(r).into_response(),
        Ok(Err(e)) => internal(e),
        Err(e) => internal(format!("join: {e}")),
    }
}

pub async fn show(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        return r;
    }
    report(&state).await
}

#[derive(Deserialize)]
pub struct Install {
    key: String,
}

pub async fn install(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<Install>,
) -> Response {
    let p = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if body.key.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "paste a licence key");
    }
    match state.license.install(&state.db, &body.key) {
        Ok(Ok(lic)) => {
            // Which licence, never the key: the audit log is readable by
            // more people than the key should be.
            audit(
                &state,
                &p,
                "license.install",
                serde_json::json!({ "license_id": lic.lid, "tier": lic.tier.as_str(), "entity": lic.entity }),
            );
            report(&state).await
        }
        Ok(Err(rejected)) => json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "that licence key was not installed ({}): {}",
                rejected.reason.as_str(),
                rejected.detail
            ),
        ),
        Err(e) => internal(e),
    }
}

/// Runs the daily check now — after fixing outbound access, say — and
/// answers what the licence says afterwards.
pub async fn check_now(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        return r;
    }
    let st = state.clone();
    let run = tokio::task::spawn_blocking(move || {
        st.license.run_check(&st.db, std::time::Duration::ZERO)
    })
    .await;
    match run {
        Ok(Ok(CheckRun::NoValidKey)) => json_error(
            StatusCode::CONFLICT,
            "there is no valid licence key to check; install one first",
        ),
        Ok(Ok(CheckRun::Offline)) => json_error(
            StatusCode::CONFLICT,
            "this is an offline licence: Skein makes no calls to Weft for it",
        ),
        Ok(Ok(_)) => report(&state).await,
        Ok(Err(e)) => internal(e),
        Err(e) => internal(format!("join: {e}")),
    }
}
