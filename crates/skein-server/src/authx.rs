//! Request authentication: find the credential a request carries, verify
//! it against the database on every request (revocation is instant), and
//! answer scope questions.
//!
//! Every request to Skein is a person. There is no anonymous reader and
//! nothing public, so the first question every route asks is "who is
//! this?", and a request that cannot answer it is refused before
//! anything about the registry's contents is looked at.
//!
//! Three shapes of credential arrive, and all of them land on one
//! [`Principal`]:
//!
//! | Client | Sends |
//! |---|---|
//! | npm, the REST API | `Authorization: Bearer <token>` |
//! | twine, Maven, docker | `Authorization: Basic base64(user:token)` |
//! | Cargo | `Authorization: <token>` — bare, read by the Cargo door only |
//! | the UI | a `skein_session` cookie |

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use skein_control::auth::{Principal, Scope};
use skein_control::ControlDb;

/// The API token a request carries, if any: a Bearer token, or a Basic
/// credential with a Skein token in either field.
///
/// Either field, because clients disagree about which one is the
/// secret: twine and Maven put it in the password, and some CI helpers
/// put it in the username with an empty password.
pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(t) = v.strip_prefix("Bearer ") {
        return Some(t.trim().to_string());
    }
    if let Some(b64) = v.strip_prefix("Basic ") {
        let decoded = base64_decode(b64.trim())?;
        let s = String::from_utf8(decoded).ok()?;
        let (user, pass) = s.split_once(':')?;
        if pass.starts_with(skein_control::auth::PREFIX) {
            return Some(pass.to_string());
        }
        if user.starts_with(skein_control::auth::PREFIX) {
            return Some(user.to_string());
        }
    }
    None
}

/// Whether a 401 carries a challenge.
///
/// Not a style choice, and both answers are load-bearing:
///
/// * **registry clients** need `WWW-Authenticate: Basic` — it is what
///   makes `npm login`, Maven and pip retry with credentials instead of
///   failing outright;
/// * **the REST API and the UI must not get it.** A browser that sees a
///   Basic challenge on a same-origin `fetch()` opens its own credential
///   dialog and never settles the promise, so a sign-in button sticks on
///   "Checking…" for ever. Measured against a real browser in
///   stratum-core; a mocked 401 cannot reproduce it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Challenge {
    Basic,
    None,
}

pub fn unauthorized(challenge: Challenge) -> Response {
    let body = "authentication required\n";
    match challenge {
        Challenge::Basic => (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"skein\"")],
            body,
        )
            .into_response(),
        Challenge::None => (StatusCode::UNAUTHORIZED, body).into_response(),
    }
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

/// The session cookie on this request, if any.
pub fn session_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(skein_control::sessions::from_cookie_header)
}

/// Who this request is, if it says.
///
/// A token wins over a cookie: a script that reuses a browser's cookie
/// jar and also sends a token means the token. A token that does not
/// verify is a 401 **even when a valid cookie is present** — the caller
/// may have a typo'd or revoked token and must be told so rather than
/// quietly acting as somebody else.
pub fn principal(
    db: &ControlDb,
    headers: &HeaderMap,
    challenge: Challenge,
) -> Result<Option<Principal>, Response> {
    if let Some(tok) = token_from_headers(headers) {
        return match skein_control::auth::verify(db, &tok) {
            Ok(Some(p)) => Ok(Some(p)),
            Ok(None) => Err(unauthorized(challenge)),
            Err(e) => Err(crate::api::internal(e)),
        };
    }
    let Some(cookie) = session_from_headers(headers) else {
        return Ok(None);
    };
    let session = match skein_control::sessions::verify(db, cookie) {
        Ok(Some(s)) => s,
        // An expired or revoked cookie is not an error: the browser is
        // simply not signed in any more.
        Ok(None) => return Ok(None),
        Err(e) => return Err(crate::api::internal(e)),
    };
    skein_control::sessions::touch(db, &session.id);
    match skein_control::users::by_id(db, &session.user_id) {
        Ok(Some(u)) if u.disabled_at.is_none() => Ok(Some(Principal::for_user(&u))),
        Ok(_) => Ok(None),
        Err(e) => Err(crate::api::internal(e)),
    }
}

/// Require a person holding `need`.
///
/// No credential is a 401. A person without the scope is a **403 with a
/// sentence**, and that is a deliberate difference from stratum-core,
/// which answers 404 there: masking exists so one tenant cannot learn
/// what another has, and a Skein install serves one organization, so
/// anybody who authenticates is already a member and may already read
/// the whole registry. Telling a reader "your role does not allow this"
/// is more useful than telling them the thing they can see does not
/// exist.
pub fn require(
    db: &ControlDb,
    headers: &HeaderMap,
    need: Scope,
    challenge: Challenge,
) -> Result<Principal, Response> {
    let Some(p) = principal(db, headers, challenge)? else {
        return Err(unauthorized(challenge));
    };
    if !p.allows(need) {
        return Err(forbidden(&p, need));
    }
    Ok(p)
}

/// The refusal for a person whose role or token does not reach `need`.
pub fn forbidden(p: &Principal, need: Scope) -> Response {
    crate::api::json_error(StatusCode::FORBIDDEN, refusal_sentence(p, need))
}

/// [`require`], refusing in words that name what was attempted.
pub fn require_to(
    db: &ControlDb,
    headers: &HeaderMap,
    need: Scope,
    challenge: Challenge,
    what: &str,
) -> Result<Principal, Response> {
    let Some(p) = principal(db, headers, challenge)? else {
        return Err(unauthorized(challenge));
    };
    if !p.allows(need) {
        return Err(crate::api::json_error(
            StatusCode::FORBIDDEN,
            refusal_sentence_to(&p, need, what),
        ));
    }
    Ok(p)
}

/// What to say to somebody who may not do this — naming which of their
/// role and their token is the limit, because the fix differs.
pub fn refusal_sentence(p: &Principal, need: Scope) -> String {
    let what = match need {
        Scope::OrgAdmin => "administer this registry",
        Scope::PackageWrite => "publish to this registry",
        Scope::PackageRead | Scope::OrgRead => "read this registry",
    };
    refusal_sentence_to(p, need, what)
}

/// [`refusal_sentence`], naming what was attempted. A scope covers more
/// than one act — `package:write` is a publish *and* a yank — and a
/// reader's `cargo yank` refused with "may not publish" sent them looking
/// for a publish they never tried.
pub fn refusal_sentence_to(p: &Principal, need: Scope, what: &str) -> String {
    let role_allows = p
        .role
        .scopes()
        .iter()
        .any(|s| skein_control::auth::grants(*s, need));
    if role_allows {
        format!(
            "this token was not minted with {} and so may not {what}; mint one that is",
            need.as_str()
        )
    } else {
        format!(
            "{} is a {} here, and a {} may not {what}",
            p.username,
            p.role.as_str(),
            p.role.as_str()
        )
    }
}

/// "You may not have this", said so that it cannot be read as "this
/// does not exist".
///
/// Chosen by what the caller **proved**, not by what they presented: a
/// credential that authenticates gets 404, anything else gets 401. Keyed
/// off a *verified* credential rather than a present one because a
/// token-shaped string anybody can type must not buy the 404 — in
/// stratum-core that difference was an existence oracle over every
/// private repository.
pub fn masked(db: &ControlDb, headers: &HeaderMap, challenge: Challenge) -> Response {
    match principal(db, headers, challenge) {
        Ok(Some(_)) => not_found(),
        Ok(None) => unauthorized(challenge),
        Err(r) => r,
    }
}

/// Standard base64, padding optional. `pub(crate)` because the registry
/// needs it too: an npm publish carries its tarball base64 in
/// `_attachments`. One decoder, so the two cannot disagree about what is
/// valid.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut nbits = 0;
    for &c in s {
        acc = (acc << 6) | val(c)? as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// Standard base64 with padding.
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skein_control::users::Role;

    #[test]
    fn base64_round_trips_and_refuses_what_is_not_base64() {
        assert_eq!(base64_decode("dXNlcjpwYXNz").unwrap(), b"user:pass");
        assert!(base64_decode("!!!").is_none());
        for data in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            &[0xff, 0x00, 0x7f][..],
        ] {
            assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        }
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn a_token_is_read_from_bearer_or_from_either_basic_field() {
        let h = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert_eq!(
            token_from_headers(&h("Bearer skein_a_b")).unwrap(),
            "skein_a_b"
        );
        let pass = format!("Basic {}", base64_encode(b"x:skein_a_b"));
        assert_eq!(token_from_headers(&h(&pass)).unwrap(), "skein_a_b");
        let user = format!("Basic {}", base64_encode(b"skein_a_b:"));
        assert_eq!(token_from_headers(&h(&user)).unwrap(), "skein_a_b");
        // A Basic credential with no token in it is a password, which no
        // registry door accepts.
        let pw = format!("Basic {}", base64_encode(b"ada:hunter2"));
        assert_eq!(token_from_headers(&h(&pw)), None);
        assert_eq!(token_from_headers(&h("Basic !!!")), None);
        assert_eq!(
            token_from_headers(&h("skein_a_b")),
            None,
            "bare is Cargo's, not here"
        );
        assert_eq!(token_from_headers(&HeaderMap::new()), None);
    }

    /// Which 401 carries a Basic challenge is a correctness property of
    /// each transport, not a style choice.
    #[test]
    fn the_basic_challenge_is_carried_only_when_asked_for() {
        let reg = unauthorized(Challenge::Basic);
        assert_eq!(reg.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            reg.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            "Basic realm=\"skein\""
        );
        let rest = unauthorized(Challenge::None);
        assert_eq!(rest.status(), StatusCode::UNAUTHORIZED);
        assert!(rest.headers().get(header::WWW_AUTHENTICATE).is_none());
    }

    /// The refusal names which limit was hit — the role, or the token —
    /// because the fix for each is different.
    #[test]
    fn a_refusal_says_whether_the_role_or_the_token_is_the_limit() {
        let p = |role: Role, scopes: Vec<Scope>| Principal {
            user_id: "u".into(),
            username: "rita".into(),
            role,
            token_id: Some("t".into()),
            scopes,
        };
        let by_role = refusal_sentence(&p(Role::Reader, vec![Scope::OrgRead]), Scope::PackageWrite);
        assert!(by_role.contains("rita is a reader"), "{by_role}");
        let by_token = refusal_sentence(
            &p(Role::Publisher, vec![Scope::PackageRead]),
            Scope::PackageWrite,
        );
        assert!(
            by_token.contains("this token was not minted with package:write"),
            "{by_token}"
        );
        let admin = refusal_sentence(&p(Role::Reader, vec![Scope::OrgRead]), Scope::OrgAdmin);
        assert!(admin.contains("administer"), "{admin}");
        let read = refusal_sentence(&p(Role::Reader, vec![]), Scope::PackageRead);
        assert!(read.contains("read this registry"), "{read}");
    }
}
