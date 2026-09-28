//! Browser sessions.
//!
//! A session token is a bearer credential like an API token, so it is
//! stored the same way — 256 bits of OS randomness, only the SHA-256 kept
//! — and verified against the database on every request, which is what
//! makes revocation instant rather than "within the TTL".
//!
//! It is deliberately *not* a JWT. A self-validating token cannot be
//! revoked without a denylist, and a denylist is a database round trip,
//! which is the thing a JWT was supposed to avoid.

use crate::db::ControlDb;
use crate::ids::{now_ms, token_secret, ulid};
use sha2::{Digest, Sha256};

/// Two weeks. Long enough not to nag, short enough that a stolen cookie
/// from a shared machine expires on its own.
pub const DEFAULT_TTL_SECS: i64 = 14 * 24 * 3600;

/// Cookie name. `__Host-` is not used: it mandates Secure, and a
/// registry on a private network is often plain HTTP.
pub const COOKIE: &str = "skein_session";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_seen_at: i64,
}

fn hash(secret: &str) -> String {
    crate::hex(&Sha256::digest(secret.as_bytes()))
}

/// Mint a session. The returned plaintext is shown once, to the browser,
/// and never stored.
pub fn create(db: &ControlDb, user_id: &str, ttl_secs: i64) -> Result<(Session, String), String> {
    let id = ulid();
    let secret = token_secret();
    let now = now_ms();
    let session = Session {
        id: id.clone(),
        user_id: user_id.to_string(),
        created_at: now,
        expires_at: now + ttl_secs * 1000,
        last_seen_at: now,
    };
    db.lock()
        .execute(
            "INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_seen_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &session.id,
                &session.user_id,
                &hash(&secret),
                &session.created_at,
                &session.expires_at,
                &session.last_seen_at,
            ],
        )
        .map_err(|e| format!("create session: {e}"))?;
    // Same shape as an API token so the two are never confused on sight,
    // and so a session cookie pasted into an Authorization header is
    // obviously not a token.
    Ok((session, format!("skses_{id}_{secret}")))
}

/// Resolve a presented cookie to its user, or `None`.
///
/// Every failure is the same answer — malformed, unknown, revoked,
/// expired, or belonging to a disabled user — so a cookie cannot be used
/// to probe which sessions exist.
pub fn verify(db: &ControlDb, presented: &str) -> Result<Option<Session>, String> {
    let Some(rest) = presented.strip_prefix("skses_") else {
        return Ok(None);
    };
    let Some((id, secret)) = rest.split_once('_') else {
        return Ok(None);
    };
    if !crate::ids::valid_id(id) {
        return Ok(None);
    }
    let row = db
        .lock()
        .query_opt(
            "SELECT s.id, s.user_id, s.token_hash, s.created_at, s.expires_at, s.last_seen_at, \
                    s.revoked_at, u.disabled_at \
             FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1",
            &[&id],
        )
        .map_err(|e| format!("verify session: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.get::<_, Option<i64>>("revoked_at").is_some()
        || row.get::<_, Option<i64>>("disabled_at").is_some()
    {
        return Ok(None);
    }
    let expires_at: i64 = row.get("expires_at");
    if expires_at <= now_ms() {
        return Ok(None);
    }
    let stored: String = row.get("token_hash");
    if !constant_time_eq(stored.as_bytes(), hash(secret).as_bytes()) {
        return Ok(None);
    }
    Ok(Some(Session {
        id: row.get("id"),
        user_id: row.get("user_id"),
        created_at: row.get("created_at"),
        expires_at,
        last_seen_at: row.get("last_seen_at"),
    }))
}

/// Note activity. Best-effort: a failure here must never fail a request
/// the user was otherwise entitled to make.
pub fn touch(db: &ControlDb, session_id: &str) {
    let _ = db.lock().execute(
        "UPDATE sessions SET last_seen_at = $2 WHERE id = $1",
        &[&session_id, &now_ms()],
    );
}

pub fn revoke(db: &ControlDb, session_id: &str) -> Result<bool, String> {
    db.lock()
        .execute(
            "UPDATE sessions SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
            &[&session_id, &now_ms()],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("revoke session: {e}"))
}

/// Revoke every session for a user — what "sign out everywhere" and a
/// password change both need.
pub fn revoke_all_for_user(db: &ControlDb, user_id: &str) -> Result<u64, String> {
    db.lock()
        .execute(
            "UPDATE sessions SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL",
            &[&user_id, &now_ms()],
        )
        .map_err(|e| format!("revoke sessions: {e}"))
}

/// Compare two secrets without letting the clock say where they differ.
///
/// Public because tokens are compared the same way, and a second copy
/// of four lines of security primitive is a second place for one of them
/// to be got wrong.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Parse a `Cookie:` header for our session value. Hand-rolled because
/// the alternative is a cookie-parsing dependency for one field.
pub fn from_cookie_header(header: &str) -> Option<&str> {
    header.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k.trim() == COOKIE).then(|| v.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (ControlDb, String) {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url("sessions")).unwrap();
        crate::registry::create_org(&db, "acme").unwrap();
        crate::users::create(&db, "admin", crate::users::Role::Admin, None).unwrap();
        let u = crate::users::create(
            &db,
            "sam",
            crate::users::Role::Reader,
            Some("a long enough password"),
        )
        .unwrap();
        (db, u.id)
    }

    /// The comparator's length guard: both operands are hex digests on
    /// every real call path, so this is only reachable directly — but a
    /// comparator that indexed past a short operand would be a bug worth
    /// catching here rather than in production.
    #[test]
    fn constant_time_eq_rejects_unequal_lengths() {
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn cookie_header_parsing() {
        assert_eq!(from_cookie_header("skein_session=abc"), Some("abc"));
        assert_eq!(
            from_cookie_header("other=1; skein_session=abc; third=3"),
            Some("abc")
        );
        assert_eq!(
            from_cookie_header(" skein_session = spaced "),
            Some("spaced")
        );
        assert_eq!(from_cookie_header("other=1"), None);
        assert_eq!(from_cookie_header(""), None);
        assert_eq!(from_cookie_header("novalue"), None);
        // A cookie whose *name* merely contains ours must not match.
        assert_eq!(from_cookie_header("xskein_session=abc"), None);
    }

    #[test]
    fn a_session_verifies_only_with_its_own_secret() {
        let (db, user) = setup();
        let (s, token) = create(&db, &user, DEFAULT_TTL_SECS).unwrap();
        assert!(token.starts_with("skses_"));
        assert_eq!(verify(&db, &token).unwrap().unwrap().user_id, user);

        // Only the hash is stored: the plaintext cannot be read back out.
        let stored: String = db
            .lock()
            .query_one("SELECT token_hash FROM sessions WHERE id = $1", &[&s.id])
            .unwrap()
            .get(0);
        assert!(!token.contains(&stored));
        assert_ne!(stored, token);

        // Every malformed shape is a refusal, not a panic.
        for bad in [
            "",
            "nonsense",
            "skses_",
            "skses_onlyid",
            "skses__",
            token.trim_end_matches(|c| c != '_'),
            &format!("skses_{}_wrongsecret", s.id),
            &format!("skses_nosuchid_{}", "x".repeat(52)),
        ] {
            assert!(verify(&db, bad).unwrap().is_none(), "{bad:?} verified");
        }
    }

    #[test]
    fn revocation_and_expiry_are_immediate() {
        let (db, user) = setup();
        let (s, token) = create(&db, &user, DEFAULT_TTL_SECS).unwrap();
        assert!(verify(&db, &token).unwrap().is_some());

        assert!(revoke(&db, &s.id).unwrap());
        assert!(verify(&db, &token).unwrap().is_none());
        assert!(!revoke(&db, &s.id).unwrap(), "revoke is idempotent");

        // An already-expired session never verifies, even unrevoked.
        let (_, expired) = create(&db, &user, -1).unwrap();
        assert!(verify(&db, &expired).unwrap().is_none());

        // Sign out everywhere. Expiry and revocation are different
        // states: the expired session above is still *unrevoked*, so it
        // is swept too — three rows, not the two just created.
        let (_, a) = create(&db, &user, DEFAULT_TTL_SECS).unwrap();
        let (_, b) = create(&db, &user, DEFAULT_TTL_SECS).unwrap();
        assert_eq!(revoke_all_for_user(&db, &user).unwrap(), 3);
        assert!(verify(&db, &a).unwrap().is_none());
        assert!(verify(&db, &b).unwrap().is_none());
        // Nothing left to sweep, and another user's sessions are untouched.
        assert_eq!(revoke_all_for_user(&db, &user).unwrap(), 0);
        assert_eq!(revoke_all_for_user(&db, "ghost").unwrap(), 0);
    }

    /// Disabling a person must cut their live browser sessions, not just
    /// stop them signing in again.
    #[test]
    fn disabling_a_user_kills_their_live_sessions() {
        let (db, user) = setup();
        let (s, token) = create(&db, &user, DEFAULT_TTL_SECS).unwrap();
        assert!(verify(&db, &token).unwrap().is_some());

        crate::users::set_disabled(&db, &user, true).unwrap();
        assert!(verify(&db, &token).unwrap().is_none());

        crate::users::set_disabled(&db, &user, false).unwrap();
        assert!(verify(&db, &token).unwrap().is_some());

        touch(&db, &s.id);
        let after = verify(&db, &token).unwrap().unwrap();
        assert!(after.last_seen_at >= s.last_seen_at);
        // Touching a session that does not exist is a no-op, not an error.
        touch(&db, "ghost");
    }
}
