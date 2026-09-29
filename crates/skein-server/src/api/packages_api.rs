//! Managing the registry: which ecosystems are on, what is published,
//! and taking something down.
//!
//! The protocol doors (`npm_api` and its siblings) speak each
//! ecosystem's own wire format to its own client. This is the other
//! half — the REST the UI uses, and the one an operator scripts against.
//!
//! **Switching an ecosystem on is `org:admin`, and deliberately not a
//! publisher's decision.** It changes what the organization's builds may
//! reach and, with proxying, what third-party code may enter them.
//! Reading the list is `org:read`, because somebody who is about to
//! publish needs to know whether they can.

use crate::api::{audit, internal, json_error, not_found};
use crate::app::SharedState;
use crate::authx::{self, Challenge};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use skein_control::auth::Scope;
use skein_control::packages::{self, Ecosystem, EcosystemPolicy, Package, PackageVersion};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct PolicyBody {
    pub ecosystem: String,
    pub mode: String,
    /// What to do with a package whose licence we cannot determine.
    /// Absent leaves it as it was, so switching an ecosystem on does not
    /// silently reset a policy somebody set.
    pub license_unknown: Option<String>,
}

fn policy_json(p: &EcosystemPolicy) -> serde_json::Value {
    serde_json::json!({
        "ecosystem": p.ecosystem.as_str(),
        "label": p.ecosystem.label(),
        "mode": p.mode,
        "license_unknown": p.license_unknown,
    })
}

fn package_json(p: &Package) -> serde_json::Value {
    serde_json::json!({
        "id": p.id,
        "ecosystem": p.ecosystem.as_str(),
        "name": p.name,
        "origin": p.origin,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
    })
}

fn version_json(v: &PackageVersion) -> serde_json::Value {
    serde_json::json!({
        "id": v.id,
        "version": v.version,
        "yanked": v.yanked,
        "yank_reason": v.yank_reason,
        "license": v.license_expr,
        "license_source": v.license_source,
        "size_bytes": v.size_bytes,
        "published_by": v.published_by_user_id,
        // Who published it, by name — the id alone is not something a
        // person reading the page can act on. The name written down at
        // publish, not a lookup of the person's row: it used to be the
        // lookup, and a removed person's every release read "—". A
        // username never changes, so while they are here the two agree.
        "published_by_username": v.published_by_name,
        "published_by_token": v.published_by_token_id,
        "published_at": v.published_at,
        "upstream_published_at": v.upstream_published_at,
    })
}

fn parse_ecosystem(s: &str) -> Result<Ecosystem, Response> {
    Ecosystem::parse(s).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown ecosystem {s:?} ({})",
                Ecosystem::ALL
                    .iter()
                    .map(|e| e.as_str())
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        )
    })
}

/// `GET /api/v1/ecosystems` — every ecosystem and its
/// mode, including the ones nobody has configured.
pub async fn ecosystems(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgRead, Challenge::None) {
        return r;
    }
    match packages::ecosystem_policies(&state.db, &org.id) {
        Ok(ps) => Json(serde_json::json!({
            "ecosystems": ps.iter().map(policy_json).collect::<Vec<_>>(),
            // What a client needs to build the configuration snippet
            // without knowing our URL scheme.
            "registry_base": state.public_url.trim_end_matches('/'),
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// `PUT /api/v1/ecosystems` — switch one on or off.
pub async fn set_ecosystem(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<PolicyBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let eco = match parse_ecosystem(&body.ecosystem) {
        Ok(e) => e,
        Err(r) => return r,
    };

    // Absent leaves the existing disposition alone, so switching an
    // ecosystem on does not quietly reset a licence policy.
    let existing = match packages::ecosystem_policy(&state.db, &org.id, eco) {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let unknown = body
        .license_unknown
        .unwrap_or_else(|| existing.license_unknown.clone());

    let now = skein_control::ids::now_ms();
    if let Err(e) =
        packages::set_ecosystem_policy(&state.db, &org.id, eco, &body.mode, &unknown, now)
    {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    audit(
        &state,
        &caller,
        "policy.ecosystem",
        serde_json::json!({
            "ecosystem": eco.as_str(),
            "mode": body.mode,
            "license_unknown": unknown,
        }),
    );
    match packages::ecosystem_policy(&state.db, &org.id, eco) {
        Ok(p) => Json(policy_json(&p)).into_response(),
        Err(e) => internal(e),
    }
}

/// `GET /api/v1/packages` — what this organization holds.
pub async fn list(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::PackageRead, Challenge::None) {
        return r;
    }
    let eco = match q.get("ecosystem").map(|s| parse_ecosystem(s)) {
        Some(Ok(e)) => Some(e),
        Some(Err(r)) => return r,
        None => None,
    };
    let limit = q
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(50);
    let offset = q
        .get("offset")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    let query = q.get("q").map(String::as_str);
    match packages::list(&state.db, &org.id, eco, query, limit, offset) {
        Ok(ps) => Json(serde_json::json!({
            "packages": ps.iter().map(package_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// `GET /api/v1/packages/:package` — one package and its versions.
pub async fn show(
    State(state): State<SharedState>,
    Path(package_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::PackageRead, Challenge::None) {
        return r;
    }
    let pkg = match packages::by_id(&state.db, &org.id, &package_id) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("no such package"),
        Err(e) => return internal(e),
    };
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let tags = match packages::tags(&state.db, &pkg.id) {
        Ok(t) => t,
        Err(e) => return internal(e),
    };
    let mut rendered = Vec::with_capacity(versions.len());
    for v in &versions {
        let mut j = version_json(v);
        let files = match packages::files(&state.db, &v.id) {
            Ok(f) => f,
            Err(e) => return internal(e),
        };
        j["files"] = serde_json::json!(files
            .iter()
            .map(|f| serde_json::json!({
                "filename": f.filename,
                "digest": format!("sha256:{}", f.digest),
                "size_bytes": f.size_bytes,
                "content_type": f.content_type,
            }))
            .collect::<Vec<_>>());
        rendered.push(j);
    }
    let mut out = package_json(&pkg);
    out["versions"] = serde_json::json!(rendered);
    out["tags"] = serde_json::json!(tags
        .iter()
        .map(|(t, v)| serde_json::json!({ "tag": t, "version": v }))
        .collect::<Vec<_>>());
    Json(out).into_response()
}

#[derive(Deserialize)]
pub struct YankBody {
    pub yanked: bool,
    pub reason: Option<String>,
}

/// `POST /api/v1/packages/:package/versions/:version/yank` — hide
/// a version from resolution, or put it back.
///
/// Not a delete, and there is no delete. A version's bytes never change
/// and it never disappears: a lockfile that already names it must keep
/// building, or yanking one bad release breaks every pipeline that
/// pinned it — which is how the left-pad afternoon went.
pub async fn yank(
    State(state): State<SharedState>,
    Path((package_id, version)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<YankBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require_to(
        &state.db,
        &headers,
        Scope::PackageWrite,
        Challenge::None,
        "yank or unyank a version",
    ) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let pkg = match packages::by_id(&state.db, &org.id, &package_id) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("no such package"),
        Err(e) => return internal(e),
    };
    let v = match packages::version_by_number(&state.db, &pkg.id, &version) {
        Ok(Some(v)) => v,
        Ok(None) => return not_found("no such version"),
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    match packages::yank(&state.db, &v.id, body.reason.as_deref(), body.yanked) {
        Ok(true) => {}
        Ok(false) => return not_found("no such version"),
        Err(e) => return internal(e),
    }
    audit(
        &state,
        &caller,
        if body.yanked {
            "package.yank"
        } else {
            "package.unyank"
        },
        serde_json::json!({
            "package": pkg.name,
            "version": v.version,
            "reason": body.reason,
        }),
    );
    match packages::version_by_number(&state.db, &pkg.id, &version) {
        Ok(Some(v)) => Json(version_json(&v)).into_response(),
        Ok(None) => not_found("no such version"),
        Err(e) => internal(e),
    }
}

/// `DELETE /api/v1/packages/:package` — take the whole package
/// down.
///
/// `org:admin`, not `package:write`. Unpublishing a package everybody
/// depends on is the one irreversible act this feature has, and it is
/// not something a CI token that can publish should also be able to do.
pub async fn remove(
    State(state): State<SharedState>,
    Path(package_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let pkg = match packages::by_id(&state.db, &org.id, &package_id) {
        Ok(Some(p)) => p,
        Ok(None) => return not_found("no such package"),
        Err(e) => return internal(e),
    };
    match packages::remove(&state.db, &org.id, &package_id) {
        Ok(true) => {}
        Ok(false) => return not_found("no such package"),
        Err(e) => return internal(e),
    }
    // The blobs stay until the collector proves nothing else references
    // them; the row's disappearance is what makes them collectable.
    audit(
        &state,
        &caller,
        "package.delete",
        serde_json::json!({
            "package": pkg.name,
            "ecosystem": pkg.ecosystem.as_str(),
        }),
    );
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------
// The admission policy, and the findings it produces.
//
// One screen's worth of REST. Reading is `org:read` — a developer whose
// install was refused needs to be able to see *why* without an admin in
// the room, and the refusal sentence is already in the error the client
// printed. Changing anything is `org:admin`, because every one of these
// widens what third-party code may enter the organization's builds.
// ---------------------------------------------------------------------

fn policy_event_json(e: &packages::PolicyEvent) -> serde_json::Value {
    serde_json::json!({
        "ecosystem": e.ecosystem,
        "name": e.name,
        "version": e.version,
        // `blocked` — refused; `would_block` — audit mode served it and
        // wrote this down. The screen leans on the difference: a
        // would_block list is what an org reads before switching on.
        "disposition": e.disposition,
        "rule": e.rule,
        "reason": e.reason,
        "hits": e.hits,
        "first_at": e.first_at,
        "last_at": e.last_at,
    })
}

fn admission_json(a: &packages::AdmissionPolicy) -> serde_json::Value {
    serde_json::json!({
        "mode": a.mode,
        "cooldown_days": a.cooldown_days,
        "license_mode": a.license_mode,
        "license_rules": a
            .license_rules
            .iter()
            .map(|(id, d)| serde_json::json!({ "spdx_id": id, "disposition": d }))
            .collect::<Vec<_>>(),
        "reserved": a.reserved,
    })
}

#[derive(Deserialize)]
pub struct AdmissionBody {
    pub mode: String,
    pub cooldown_days: i64,
    pub license_mode: String,
}

#[derive(Deserialize)]
pub struct LicenseRuleBody {
    pub spdx_id: String,
    /// `allow`, `deny`, or absent to remove the rule entirely. Removing
    /// is not the same as denying: under `deny_list` an absent rule
    /// admits, and under `allow_list` it refuses.
    pub disposition: Option<String>,
}

#[derive(Deserialize)]
pub struct NamespaceBody {
    pub ecosystem: String,
    pub pattern: String,
}

/// `GET /api/v1/policy` — the whole admission policy.
///
/// The reserved list is per ecosystem, so this takes `?ecosystem=` and
/// defaults to npm, which is the only one with a proxy today.
pub async fn policy(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgRead, Challenge::None) {
        return r;
    }
    let eco = match parse_ecosystem(q.get("ecosystem").map(String::as_str).unwrap_or("npm")) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match packages::admission_policy(&state.db, &org.id, eco) {
        Ok(a) => {
            let mut out = admission_json(&a);
            out["ecosystem"] = serde_json::json!(eco.as_str());
            Json(out).into_response()
        }
        Err(e) => internal(e),
    }
}

/// `PUT /api/v1/policy` — mode, cooldown, licence mode.
pub async fn set_policy(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AdmissionBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = packages::set_admission_policy(
        &state.db,
        &org.id,
        &body.mode,
        body.cooldown_days,
        &body.license_mode,
    ) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    audit(
        &state,
        &caller,
        "policy.rules",
        serde_json::json!({
            "mode": body.mode,
            "cooldown_days": body.cooldown_days,
            "license_mode": body.license_mode,
        }),
    );
    match packages::admission_policy(&state.db, &org.id, Ecosystem::Npm) {
        Ok(a) => Json(admission_json(&a)).into_response(),
        Err(e) => internal(e),
    }
}

/// `PUT /api/v1/policy/licenses` — one licence rule.
pub async fn set_license(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<LicenseRuleBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let now = skein_control::ids::now_ms();
    if let Err(e) = packages::set_license_rule(
        &state.db,
        &org.id,
        &body.spdx_id,
        body.disposition.as_deref(),
        now,
    ) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    // Two acts, two actions: a rule set and a rule removed differ by
    // more than a `null`, and "who removed the GPL rule?" is a question
    // about the action rather than a query over its context.
    audit(
        &state,
        &caller,
        if body.disposition.is_some() {
            "policy.license_rule.set"
        } else {
            "policy.license_rule.remove"
        },
        serde_json::json!({
            "spdx_id": body.spdx_id,
            "disposition": body.disposition,
        }),
    );
    match packages::admission_policy(&state.db, &org.id, Ecosystem::Npm) {
        Ok(a) => Json(admission_json(&a)).into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /api/v1/policy/namespaces` — claim a prefix.
pub async fn reserve(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<NamespaceBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let eco = match parse_ecosystem(&body.ecosystem) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let now = skein_control::ids::now_ms();
    if let Err(e) = packages::reserve_namespace(&state.db, &org.id, eco, &body.pattern, now) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    audit(
        &state,
        &caller,
        "policy.reserve",
        serde_json::json!({
            "ecosystem": eco.as_str(),
            "pattern": body.pattern,
        }),
    );
    match packages::admission_policy(&state.db, &org.id, eco) {
        Ok(a) => Json(admission_json(&a)).into_response(),
        Err(e) => internal(e),
    }
}

/// `DELETE /api/v1/policy/namespaces?ecosystem=&pattern=`
///
/// Releasing is the widening direction — the name becomes proxyable —
/// so it is `org:admin` like every other change here.
pub async fn release(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let eco = match parse_ecosystem(q.get("ecosystem").map(String::as_str).unwrap_or("npm")) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let pattern = q.get("pattern").map(String::as_str).unwrap_or("");
    match packages::release_namespace(&state.db, &org.id, eco, pattern) {
        Ok(true) => {}
        Ok(false) => return not_found("no such reserved namespace"),
        Err(e) => return internal(e),
    }
    audit(
        &state,
        &caller,
        "policy.release",
        serde_json::json!({ "ecosystem": eco.as_str(), "pattern": pattern }),
    );
    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------
// npm scopes: the only ones npm packages are published under, and never
// fetched from an upstream. Reading is `org:read` — the Connect page
// routes every one of them in its `.npmrc` — and changing them is
// `org:admin`, like everything else about what the registry admits.
// ---------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScopeBody {
    pub scope: String,
}

/// `GET /api/v1/npm/scopes` — `{"scopes": [{"scope", "packages"}]}`,
/// sorted; `packages` counts what was published here under each.
pub async fn npm_scopes(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgRead, Challenge::None) {
        return r;
    }
    match packages::npm_scope_counts(&state.db, &org.id) {
        Ok(scopes) => Json(serde_json::json!({ "scopes": scopes })).into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /api/v1/npm/scopes` `{"scope"}` — 201 when added, 200 when it
/// was already there (adding is idempotent), 400 for what npm would not
/// take as a scope.
pub async fn add_npm_scope(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<ScopeBody>,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let now = skein_control::ids::now_ms();
    let (scope, added) = match packages::add_npm_scope(&state.db, &org.id, &body.scope, now) {
        Ok(x) => x,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    if !added {
        return Json(scope).into_response();
    }
    audit(
        &state,
        &caller,
        "policy.npm_scope.add",
        serde_json::json!({ "scope": scope.scope }),
    );
    (StatusCode::CREATED, Json(scope)).into_response()
}

/// `DELETE /api/v1/npm/scopes?scope=` — 204; 409 while packages are
/// published under it; 404 when it is not one of the organization's.
pub async fn remove_npm_scope(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let asked = q.get("scope").map(String::as_str).unwrap_or("");
    match packages::remove_npm_scope(&state.db, &org.id, asked) {
        Ok(packages::ScopeRemoval::Removed(scope)) => {
            audit(
                &state,
                &caller,
                "policy.npm_scope.remove",
                serde_json::json!({ "scope": scope }),
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(packages::ScopeRemoval::Absent) => not_found("no such npm scope"),
        Ok(packages::ScopeRemoval::Holds(scope, n)) => json_error(
            StatusCode::CONFLICT,
            if n == 1 {
                format!("{scope} holds 1 package; delete it before removing the scope")
            } else {
                format!("{scope} holds {n} packages; delete them before removing the scope")
            },
        ),
        Err(e) => internal(e),
    }
}

/// `GET /api/v1/findings` — what the policy has caught.
///
/// This is the screen that makes audit mode worth having: a week of
/// `would_block` rows is what an organization reads before deciding
/// whether switching to `block` costs it anything.
pub async fn findings(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    if let Err(r) = authx::require(&state.db, &headers, Scope::OrgRead, Challenge::None) {
        return r;
    }
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100);
    match packages::policy_events(&state.db, &org.id, limit) {
        Ok(es) => Json(serde_json::json!({
            "findings": es.iter().map(policy_event_json).collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// `DELETE /api/v1/findings?ecosystem=&name=&version=`
///
/// Forgetting a finding is not allowing the package — the rule that
/// produced it is still in force, and the next fetch writes the row
/// again. That is deliberate: "allow this" in the UI changes the rule
/// *and then* clears the row, so a cleared row means somebody acted
/// rather than somebody tidied.
pub async fn forget_finding(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let org = state.org();
    let caller = match authx::require(&state.db, &headers, Scope::OrgAdmin, Challenge::None) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let eco = match parse_ecosystem(q.get("ecosystem").map(String::as_str).unwrap_or("npm")) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let name = q.get("name").map(String::as_str).unwrap_or("");
    let version = q.get("version").map(String::as_str).unwrap_or("*");
    match packages::forget_policy_event(&state.db, &org.id, eco, name, version) {
        Ok(true) => {}
        Ok(false) => return not_found("no such finding"),
        Err(e) => return internal(e),
    }
    audit(
        &state,
        &caller,
        "policy.dismiss_finding",
        serde_json::json!({
            "ecosystem": eco.as_str(),
            "package": name,
            "version": version,
        }),
    );
    StatusCode::NO_CONTENT.into_response()
}
