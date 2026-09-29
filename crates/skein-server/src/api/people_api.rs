//! People, their credentials, and the organization: signing in, the
//! tokens a person holds, and the admin screens.
//!
//! Every route here needs a person. Reading who else is here is
//! `org:read` — a reader can see who publishes, which is the same
//! question the package page answers. Changing anybody but yourself is
//! `org:admin`.

use crate::api::{audit, internal, json_error, not_found};
use crate::app::SharedState;
use crate::authx::{self, Challenge};
use crate::throttle::{Key, Lockout, Refusal};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use skein_control::auth::{self, Principal, Scope};
use skein_control::users::{self, ChangeError, Role, User};
use skein_control::{packages, sessions};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

fn user_json(u: &User) -> serde_json::Value {
    serde_json::json!({
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "role": u.role.as_str(),
        "can_sign_in": u.has_password,
        "disabled": u.disabled_at.is_some(),
        "created_at": u.created_at,
    })
}

fn token_json(t: &auth::TokenInfo) -> serde_json::Value {
    serde_json::json!({
        "id": t.id,
        "user_id": t.user_id,
        "username": t.username,
        "label": t.label,
        "scopes": t.scopes.iter().map(Scope::as_str).collect::<Vec<_>>(),
        "created_at": t.created_at,
        "expires_at": t.expires_at,
        "last_used_at": t.last_used_at,
    })
}

fn change_error(e: ChangeError) -> Response {
    match e {
        ChangeError::NotFound => not_found("no such person"),
        ChangeError::LastAdmin => json_error(StatusCode::CONFLICT, e.to_string()),
        ChangeError::Other(e) => internal(e),
    }
}

fn need(headers: &HeaderMap, state: &SharedState, scope: Scope) -> Result<Principal, Response> {
    authx::require(&state.db, headers, scope, Challenge::None)
}

// ------------------------------------------------------------ sessions

/// The cookie carrying a session.
///
/// `HttpOnly` so no script can read it, `SameSite=Lax` so it does not
/// ride cross-site form posts, `Path=/` because the API and the UI share
/// an origin. `Secure` only when the deployment is HTTPS: a registry on a
/// private network is often plain HTTP, and a Secure cookie there is
/// simply never stored — which reads as "sign-in is broken" with nothing
/// in any log.
fn cookie(state: &SharedState, value: &str, ttl_secs: i64) -> String {
    let secure = if state.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    format!(
        "{}={value}; HttpOnly; SameSite=Lax; Path=/; Max-Age={ttl_secs}{secure}",
        sessions::COOKIE
    )
}

/// Where a password is being checked, for the audit entry a lockout
/// writes.
#[derive(Clone, Copy)]
pub enum PasswordDoor {
    SignIn,
    NpmLogin,
    PasswordChange,
}

impl PasswordDoor {
    fn as_str(self) -> &'static str {
        match self {
            PasswordDoor::SignIn => "sign-in",
            PasswordDoor::NpmLogin => "npm login",
            PasswordDoor::PasswordChange => "password change",
        }
    }
}

/// Check a username and password, through the sign-in throttle.
///
/// The only way any door checks a password, so every door counts on the
/// same name and address — see [`crate::throttle`]. `Ok(None)` is a
/// wrong password, whatever the reason, and each door answers it in its
/// own words; `Err` is the throttle's 429, or a 500.
pub fn check_password(
    state: &SharedState,
    peer: SocketAddr,
    headers: &HeaderMap,
    door: PasswordDoor,
    username: &str,
    password: &str,
) -> Result<Option<User>, Response> {
    // The last line: a proxy that appends a line of its own rather than
    // extending the client's puts its entry there.
    let forwarded_for = headers
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .map(|v| v.as_bytes());
    let address = state
        .sign_ins
        .policy()
        .client_address(peer.ip(), forwarded_for);
    // The name first: somebody who mistyped their own password should
    // hear about their name, not about the address they share.
    let keys = [Key::name(username), Key::address(address)];
    if let Err(refused) = state.sign_ins.admit(&keys, Instant::now()) {
        return Err(too_many(&refused));
    }
    match users::authenticate(&state.db, username, password) {
        Ok(Some(u)) => {
            state.sign_ins.succeeded(&keys);
            Ok(Some(u))
        }
        Ok(None) => {
            for lock in state.sign_ins.failed(&keys, Instant::now()) {
                audit_lockout(state, door, &lock);
            }
            Ok(None)
        }
        Err(e) => {
            state.sign_ins.release(&keys);
            Err(internal(e))
        }
    }
}

/// The throttle's refusal: 429, when to come back, and a sentence the UI
/// and npm both print.
fn too_many(r: &Refusal) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, r.retry_after_secs().to_string())],
        Json(serde_json::json!({ "error": r.sentence() })),
    )
        .into_response()
}

/// One entry per lock, so an admin can see an attack without a row per
/// refused guess. Nobody authenticated, so the principal is the server.
fn audit_lockout(state: &SharedState, door: PasswordDoor, lock: &Lockout) {
    let mut context = serde_json::json!({
        "door": door.as_str(),
        "failures": lock.failures,
        "locked_for_secs": crate::throttle::whole_secs(lock.locked_for),
    });
    match &lock.key {
        Key::Name(n) => context["username"] = serde_json::json!(n),
        Key::Address(a) => context["address"] = serde_json::json!(Key::address_text(a)),
    }
    let ctx = skein_control::audit::AuditCtx::system(&state.org().id, "sign-in");
    if let Err(e) =
        skein_control::audit::record(&state.db, &ctx, "session.throttled", Some(&context))
    {
        eprintln!("skein: audit session.throttled: {e}");
    }
}

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

/// `POST /api/v1/session` — sign in.
pub async fn login(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Response {
    let checked = check_password(
        &state,
        peer,
        &headers,
        PasswordDoor::SignIn,
        &body.username,
        &body.password,
    );
    let user = match checked {
        Ok(Some(u)) => u,
        // One answer for every failure — unknown name, wrong password,
        // disabled account, a service account with no password — so this
        // cannot be used to discover who has an account.
        Ok(None) => return json_error(StatusCode::UNAUTHORIZED, "invalid username or password"),
        Err(r) => return r,
    };
    let (_, token) = match sessions::create(&state.db, &user.id, sessions::DEFAULT_TTL_SECS) {
        Ok(x) => x,
        Err(e) => return internal(e),
    };
    audit(
        &state,
        &Principal::for_user(&user),
        "session.create",
        serde_json::json!({}),
    );
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            cookie(&state, &token, sessions::DEFAULT_TTL_SECS),
        )],
        Json(me_json(&state, &Principal::for_user(&user), &user)),
    )
        .into_response()
}

/// `DELETE /api/v1/session` — sign out. Always succeeds and always
/// clears the cookie: a browser that is told it signed out must be
/// signed out, whatever state the session row was in.
pub async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Some(presented) = authx::session_from_headers(&headers) {
        if let Ok(Some(s)) = sessions::verify(&state.db, presented) {
            let _ = sessions::revoke(&state.db, &s.id);
        }
    }
    (
        StatusCode::NO_CONTENT,
        [(header::SET_COOKIE, cookie(&state, "", 0))],
    )
        .into_response()
}

fn me_json(state: &SharedState, p: &Principal, u: &User) -> serde_json::Value {
    let mut j = user_json(u);
    j["scopes"] = serde_json::json!(p.scopes.iter().map(Scope::as_str).collect::<Vec<_>>());
    j["via"] = serde_json::json!(if p.token_id.is_some() {
        "token"
    } else {
        "session"
    });
    j["org"] = serde_json::json!({ "name": state.org_name() });
    j["public_url"] = serde_json::json!(state.public_url.trim_end_matches('/'));
    j
}

/// `GET /api/v1/session` — whether this browser is signed in, and as
/// whom. 200 either way: the UI asks on every first load, and "not
/// signed in" is an answer, not an error to log in the console.
pub async fn session(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let p = match authx::principal(&state.db, &headers, Challenge::None) {
        Ok(Some(p)) => p,
        Ok(None) => return Json(serde_json::json!({ "signed_in": false })).into_response(),
        Err(r) => return r,
    };
    match users::by_id(&state.db, &p.user_id) {
        Ok(Some(u)) => {
            let mut j = me_json(&state, &p, &u);
            j["signed_in"] = serde_json::json!(true);
            Json(j).into_response()
        }
        Ok(None) => Json(serde_json::json!({ "signed_in": false })).into_response(),
        Err(e) => internal(e),
    }
}

/// `GET /api/v1/me` — who this request is.
pub async fn me(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let p = match need(&headers, &state, Scope::PackageRead) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match users::by_id(&state.db, &p.user_id) {
        Ok(Some(u)) => Json(me_json(&state, &p, &u)).into_response(),
        Ok(None) => authx::unauthorized(Challenge::None),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct PasswordBody {
    pub current: String,
    pub new: String,
}

/// `PUT /api/v1/me/password` — change your own password. Every session
/// but the one asking is signed out: a password change is what somebody
/// does when they think another session is not theirs.
///
/// The current password is checked through the throttle like a sign-in:
/// it is the same Argon2, and somebody holding a stolen session could
/// otherwise guess it at full speed.
pub async fn change_password(
    State(state): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    let p = match need(&headers, &state, Scope::PackageRead) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let checked = check_password(
        &state,
        peer,
        &headers,
        PasswordDoor::PasswordChange,
        &p.username,
        &body.current,
    );
    match checked {
        Ok(Some(_)) => {}
        Ok(None) => return json_error(StatusCode::FORBIDDEN, "the current password is wrong"),
        Err(r) => return r,
    }
    if let Err(e) = users::set_password(&state.db, &p.user_id, &body.new) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    let _ = sessions::revoke_all_for_user(&state.db, &p.user_id);
    let (_, token) = match sessions::create(&state.db, &p.user_id, sessions::DEFAULT_TTL_SECS) {
        Ok(x) => x,
        Err(e) => return internal(e),
    };
    audit(&state, &p, "user.password", serde_json::json!({}));
    (
        StatusCode::NO_CONTENT,
        [(
            header::SET_COOKIE,
            cookie(&state, &token, sessions::DEFAULT_TTL_SECS),
        )],
    )
        .into_response()
}

// -------------------------------------------------------------- tokens

#[derive(Deserialize)]
pub struct MintBody {
    pub label: String,
    pub scopes: Vec<String>,
    /// Days until it stops working. Absent means it does not expire.
    pub expires_in_days: Option<i64>,
}

fn mint_for(state: &SharedState, caller: &Principal, owner: &User, body: MintBody) -> Response {
    let mut scopes = Vec::with_capacity(body.scopes.len());
    for s in &body.scopes {
        match Scope::parse(s) {
            Some(x) => scopes.push(x),
            None => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "unknown scope {s:?} ({})",
                        Scope::ALL.map(|s| s.as_str()).join(" | ")
                    ),
                )
            }
        }
    }
    let expires_at = match body.expires_in_days {
        None => None,
        Some(d) if (1..=3650).contains(&d) => {
            Some(skein_control::ids::now_ms() + d * 24 * 60 * 60 * 1000)
        }
        Some(_) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "a token expires in between 1 and 3650 days",
            )
        }
    };
    let (info, secret) = match auth::mint(&state.db, owner, &body.label, &scopes, expires_at) {
        Ok(x) => x,
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    audit(
        state,
        caller,
        "token.create",
        serde_json::json!({
            "token": info.id,
            "owner": owner.username,
            "label": info.label,
            "scopes": body.scopes,
        }),
    );
    let mut j = token_json(&info);
    // Shown once. Only its hash is stored, so there is no second chance
    // to read it.
    j["token"] = serde_json::json!(secret);
    (StatusCode::CREATED, Json(j)).into_response()
}

/// `GET /api/v1/me/tokens`
pub async fn my_tokens(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let p = match need(&headers, &state, Scope::PackageRead) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match auth::list(&state.db, Some(&p.user_id)) {
        Ok(ts) => Json(serde_json::json!({
            "tokens": ts.iter().map(token_json).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /api/v1/me/tokens` — mint yourself a token.
///
/// Minted through a session, not through another token: a token that
/// could mint tokens is a credential that never really expires, since it
/// can always make its own successor.
pub async fn mint_mine(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<MintBody>,
) -> Response {
    let p = match need(&headers, &state, Scope::PackageRead) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if p.token_id.is_some() && !p.allows(Scope::OrgAdmin) {
        return json_error(
            StatusCode::FORBIDDEN,
            "a token cannot mint tokens — sign in to the UI to make one",
        );
    }
    let owner = match users::by_id(&state.db, &p.user_id) {
        Ok(Some(u)) => u,
        Ok(None) => return authx::unauthorized(Challenge::None),
        Err(e) => return internal(e),
    };
    mint_for(&state, &p, &owner, body)
}

/// `DELETE /api/v1/tokens/:id` — revoke one. Your own, or anybody's for
/// an admin; somebody else's is not found, which for a non-admin is the
/// truth about what they can see.
pub async fn revoke_token(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let p = match need(&headers, &state, Scope::PackageRead) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let t = match auth::by_id(&state.db, &id) {
        Ok(Some(t)) if t.user_id == p.user_id || p.allows(Scope::OrgAdmin) => t,
        Ok(_) => return not_found("no such token"),
        Err(e) => return internal(e),
    };
    match auth::revoke(&state.db, &t.id) {
        Ok(true) => {}
        Ok(false) => return not_found("no such token"),
        Err(e) => return internal(e),
    }
    audit(
        &state,
        &p,
        "token.revoke",
        serde_json::json!({ "token": t.id, "owner": t.username, "label": t.label }),
    );
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /api/v1/tokens` — every live token, for an admin.
pub async fn all_tokens(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = need(&headers, &state, Scope::OrgAdmin) {
        return r;
    }
    match auth::list(&state.db, None) {
        Ok(ts) => Json(serde_json::json!({
            "tokens": ts.iter().map(token_json).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

// --------------------------------------------------------------- users

/// `GET /api/v1/users`
pub async fn list_users(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = need(&headers, &state, Scope::OrgRead) {
        return r;
    }
    match users::list(&state.db) {
        Ok(us) => Json(serde_json::json!({
            "users": us.iter().map(user_json).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub struct NewUserBody {
    pub username: String,
    pub role: String,
    /// Absent for a service account, which holds tokens and cannot sign
    /// in to the UI.
    pub password: Option<String>,
}

fn parse_role(s: &str) -> Result<Role, Response> {
    Role::parse(s).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown role {s:?} ({})",
                Role::ALL.map(|r| r.as_str()).join(" | ")
            ),
        )
    })
}

/// `POST /api/v1/users` — add a person, or a service account for CI.
pub async fn create_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<NewUserBody>,
) -> Response {
    let caller = match need(&headers, &state, Scope::OrgAdmin) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let role = match parse_role(&body.role) {
        Ok(r) => r,
        Err(r) => return r,
    };
    let user = match users::create(&state.db, &body.username, role, body.password.as_deref()) {
        Ok(u) => u,
        Err(e) if e.contains("taken") => return json_error(StatusCode::CONFLICT, e),
        Err(e) => return json_error(StatusCode::BAD_REQUEST, e),
    };
    audit(
        &state,
        &caller,
        "user.create",
        serde_json::json!({ "user": user.username, "role": role.as_str() }),
    );
    (StatusCode::CREATED, Json(user_json(&user))).into_response()
}

#[derive(Deserialize)]
pub struct UserChange {
    pub role: Option<String>,
    pub disabled: Option<bool>,
    pub password: Option<String>,
    pub display_name: Option<String>,
}

/// `PATCH /api/v1/users/:id` — role, disabled, password, display name.
pub async fn update_user(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UserChange>,
) -> Response {
    let caller = match need(&headers, &state, Scope::OrgAdmin) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let target = match users::by_id(&state.db, &id) {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("no such person"),
        Err(e) => return internal(e),
    };
    if let Some(r) = &body.role {
        let role = match parse_role(r) {
            Ok(r) => r,
            Err(r) => return r,
        };
        if let Err(e) = users::set_role(&state.db, &target.id, role) {
            return change_error(e);
        }
    }
    if let Some(d) = body.disabled {
        if let Err(e) = users::set_disabled(&state.db, &target.id, d) {
            return change_error(e);
        }
        if d {
            let _ = sessions::revoke_all_for_user(&state.db, &target.id);
        }
    }
    if let Some(pw) = &body.password {
        if let Err(e) = users::set_password(&state.db, &target.id, pw) {
            return json_error(StatusCode::BAD_REQUEST, e);
        }
        let _ = sessions::revoke_all_for_user(&state.db, &target.id);
    }
    if let Some(n) = &body.display_name {
        if let Err(e) = users::set_display_name(&state.db, &target.id, n) {
            return json_error(StatusCode::BAD_REQUEST, e);
        }
    }
    // What this request changed, and only that: a field it did not touch
    // recorded as `null` reads as "cleared" to whoever audits it later.
    // A password is recorded as having changed, never as what it is.
    let mut changed = serde_json::json!({ "user": target.username });
    if let Some(r) = &body.role {
        changed["role"] = serde_json::json!(r);
    }
    if let Some(d) = body.disabled {
        changed["disabled"] = serde_json::json!(d);
    }
    if body.password.is_some() {
        changed["password"] = serde_json::json!("changed");
    }
    if let Some(n) = &body.display_name {
        changed["display_name"] = serde_json::json!(n);
    }
    audit(&state, &caller, "user.update", changed);
    match users::by_id(&state.db, &target.id) {
        Ok(Some(u)) => Json(user_json(&u)).into_response(),
        Ok(None) => not_found("no such person"),
        Err(e) => internal(e),
    }
}

/// `DELETE /api/v1/users/:id` — remove a person. What they published
/// stays.
pub async fn delete_user(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let caller = match need(&headers, &state, Scope::OrgAdmin) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let target = match users::by_id(&state.db, &id) {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("no such person"),
        Err(e) => return internal(e),
    };
    if let Err(e) = users::delete(&state.db, &target.id) {
        return change_error(e);
    }
    audit(
        &state,
        &caller,
        "user.delete",
        serde_json::json!({ "user": target.username }),
    );
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /api/v1/users/:id/tokens`
pub async fn user_tokens(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = need(&headers, &state, Scope::OrgAdmin) {
        return r;
    }
    match auth::list(&state.db, Some(&id)) {
        Ok(ts) => Json(serde_json::json!({
            "tokens": ts.iter().map(token_json).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => internal(e),
    }
}

/// `POST /api/v1/users/:id/tokens` — mint a token for somebody else.
///
/// What an admin does for a CI service account, which has no password
/// and so cannot mint its own. The ceiling is still the owner's role.
pub async fn mint_for_user(
    State(state): State<SharedState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<MintBody>,
) -> Response {
    let caller = match need(&headers, &state, Scope::OrgAdmin) {
        Ok(p) => p,
        Err(r) => return r,
    };
    let owner = match users::by_id(&state.db, &id) {
        Ok(Some(u)) => u,
        Ok(None) => return not_found("no such person"),
        Err(e) => return internal(e),
    };
    if owner.disabled_at.is_some() {
        return json_error(
            StatusCode::CONFLICT,
            format!(
                "{} is disabled, and a token for them would not work",
                owner.username
            ),
        );
    }
    mint_for(&state, &caller, &owner, body)
}

// --------------------------------------------------------- organization

/// `GET /api/v1/overview` — what the front page shows.
pub async fn overview(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Err(r) = need(&headers, &state, Scope::OrgRead) {
        return r;
    }
    let org = state.org();
    let counts = match packages::counts(&state.db, &org.id) {
        Ok(c) => c,
        Err(e) => return internal(e),
    };
    let policies = match packages::ecosystem_policies(&state.db, &org.id) {
        Ok(p) => p,
        Err(e) => return internal(e),
    };
    let bytes = match packages::bytes_for_org(&state.db, &org.id) {
        Ok(b) => b,
        Err(e) => return internal(e),
    };
    let findings = match packages::policy_events(&state.db, &org.id, 500) {
        Ok(f) => f.len(),
        Err(e) => return internal(e),
    };
    Json(serde_json::json!({
        "org": { "name": state.org_name(), "created_at": org.created_at },
        "public_url": state.public_url.trim_end_matches('/'),
        "stored_bytes": bytes,
        "findings": findings,
        "ecosystems": policies.iter().map(|p| {
            let n = counts.iter().find(|(e, _)| *e == p.ecosystem).map(|(_, n)| *n).unwrap_or(0);
            serde_json::json!({
                "ecosystem": p.ecosystem.as_str(),
                "label": p.ecosystem.label(),
                "mode": p.mode,
                "served": crate::app::served(p.ecosystem),
                "packages": n,
            })
        }).collect::<Vec<_>>(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct OrgBody {
    pub name: String,
}

/// `PUT /api/v1/org` — rename the organization. The id, and so every
/// stored key, stays.
pub async fn rename_org(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<OrgBody>,
) -> Response {
    let caller = match need(&headers, &state, Scope::OrgAdmin) {
        Ok(p) => p,
        Err(r) => return r,
    };
    if let Err(e) = skein_control::registry::rename_org(&state.db, &state.org().id, &body.name) {
        return json_error(StatusCode::BAD_REQUEST, e);
    }
    audit(
        &state,
        &caller,
        "org.rename",
        serde_json::json!({ "name": body.name }),
    );
    Json(serde_json::json!({ "name": body.name })).into_response()
}

/// `GET /api/v1/audit?before=` — what changed, newest first.
pub async fn audit_log(
    State(state): State<SharedState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = need(&headers, &state, Scope::OrgAdmin) {
        return r;
    }
    let before = q.get("before").and_then(|v| v.parse::<i64>().ok());
    let limit = q
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(100);
    match skein_control::audit::recent(&state.db, &state.org().id, before, limit) {
        Ok(es) => Json(serde_json::json!({ "entries": es })).into_response(),
        Err(e) => internal(e),
    }
}
