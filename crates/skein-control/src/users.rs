//! The people who may reach this registry.
//!
//! There is no anonymous reader and nothing public: every request to
//! Skein is one of these people, through an API token or a browser
//! session. A person's [`Role`] is the whole of their authority, and a
//! token they hold is narrowed by it on every request (see
//! `auth::verify`), so demoting somebody takes effect on the very next
//! request their `.npmrc` makes.
//!
//! Password hashing is stratum-core's, unchanged: argon2id, salted from
//! the OS CSPRNG, with equal work spent on an unknown account so sign-in
//! timing does not say who exists.

use crate::auth::Scope;
use crate::db::{is_unique_violation, ControlDb};
use crate::ids::{now_ms, ulid};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::Serialize;

/// What a person may do here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Everything: settings, the admission policy, people, deleting a
    /// package.
    Admin,
    /// Install, publish and yank. What a CI service account is.
    Publisher,
    /// Install, and read what is here and why.
    Reader,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Admin, Role::Publisher, Role::Reader];

    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Publisher => "publisher",
            Role::Reader => "reader",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// The scopes this role holds. A token's ceiling is intersected with
    /// these on every request.
    pub fn scopes(&self) -> Vec<Scope> {
        match self {
            Role::Admin => vec![Scope::OrgAdmin],
            Role::Publisher => vec![Scope::OrgRead, Scope::PackageWrite],
            Role::Reader => vec![Scope::OrgRead],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: Role,
    /// Whether this account can sign in to the UI. A service account for
    /// CI has no password: it holds tokens and nothing else.
    pub has_password: bool,
    pub created_at: i64,
    pub disabled_at: Option<i64>,
}

const COLS: &str = "id, username, display_name, role, password_hash IS NOT NULL AS has_password, \
                    created_at, disabled_at";

fn row_to_user(r: &postgres::Row) -> User {
    User {
        id: r.get("id"),
        username: r.get("username"),
        display_name: r.get("display_name"),
        // The CHECK constraint admits exactly the three; anything else is
        // a row this build did not write, and reading it as the least
        // authority is the direction that fails safe.
        role: Role::parse(r.get("role")).unwrap_or(Role::Reader),
        has_password: r.get("has_password"),
        created_at: r.get("created_at"),
        disabled_at: r.get("disabled_at"),
    }
}

/// The username a lookup matches on, or a refusal naming what is wrong.
///
/// Lowercase letters, digits, `.`, `_` and `-`, starting with a letter or
/// digit, at most 39 characters (GitHub's limit, which is what most
/// people's handles already fit). Refused rather than cleaned: two
/// spellings mapped onto one account is how a sign-in reaches the wrong
/// person.
pub fn normalize_username(name: &str) -> Result<String, String> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return Err("a username cannot be empty".into());
    }
    if n.len() > 39 {
        return Err("a username is at most 39 characters".into());
    }
    if !n.as_bytes()[0].is_ascii_alphanumeric() {
        return Err("a username starts with a letter or a digit".into());
    }
    if !n
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("a username is letters, digits, '.', '_' and '-'".into());
    }
    Ok(n)
}

pub const MIN_PASSWORD_LEN: usize = 12;

/// What makes a password acceptable, separately from hashing one, so a
/// form can say so before anything is committed.
pub fn check_password_strength(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        ));
    }
    // 4096 bytes is far past any reasonable passphrase and well short of
    // what would make hashing a denial-of-service vector.
    if password.len() > 4096 {
        return Err("password is too long".into());
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, String> {
    check_password_strength(password)?;
    let salt = SaltString::encode_b64(&crate::ids::random(16)).map_err(|e| format!("salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("hash password: {e}"))
}

/// Constant-time within Argon2's own verification. A stored hash that
/// fails to parse verifies as `false` rather than erroring, so a corrupt
/// row cannot be told apart from a wrong password.
pub fn verify_password(hash: &str, password: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A real Argon2id hash of a value nobody knows, used to equalize the
/// cost of authenticating a nonexistent account.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3RyYXR1bWR1bW15c2FsdA$\
                          RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

/// Create a person. `password` is `None` for a service account.
pub fn create(
    db: &ControlDb,
    username: &str,
    role: Role,
    password: Option<&str>,
) -> Result<User, String> {
    let username = normalize_username(username)?;
    let hash = password.map(hash_password).transpose()?;
    let id = ulid();
    let now = now_ms();
    let row = db
        .lock()
        .query_one(
            &format!(
                "INSERT INTO users (id, username, display_name, password_hash, role, created_at) \
                 VALUES ($1, $2, '', $3, $4, $5) RETURNING {COLS}"
            ),
            &[&id, &username, &hash, &role.as_str(), &now],
        )
        .map_err(|e| {
            if is_unique_violation(&e) {
                format!("the username {username:?} is taken")
            } else {
                format!("create user: {e}")
            }
        })?;
    Ok(row_to_user(&row))
}

pub fn by_id(db: &ControlDb, id: &str) -> Result<Option<User>, String> {
    if !crate::ids::valid_id(id) {
        return Ok(None);
    }
    Ok(db
        .lock()
        .query_opt(&format!("SELECT {COLS} FROM users WHERE id = $1"), &[&id])
        .map_err(|e| format!("user by id: {e}"))?
        .as_ref()
        .map(row_to_user))
}

pub fn by_username(db: &ControlDb, username: &str) -> Result<Option<User>, String> {
    let Ok(username) = normalize_username(username) else {
        return Ok(None);
    };
    Ok(db
        .lock()
        .query_opt(
            &format!("SELECT {COLS} FROM users WHERE username = $1"),
            &[&username],
        )
        .map_err(|e| format!("user by name: {e}"))?
        .as_ref()
        .map(row_to_user))
}

/// Everybody, admins first, then alphabetically.
pub fn list(db: &ControlDb) -> Result<Vec<User>, String> {
    Ok(db
        .lock()
        .query(
            &format!(
                "SELECT {COLS} FROM users ORDER BY \
                 CASE role WHEN 'admin' THEN 0 WHEN 'publisher' THEN 1 ELSE 2 END, username"
            ),
            &[],
        )
        .map_err(|e| format!("list users: {e}"))?
        .iter()
        .map(row_to_user)
        .collect())
}

pub fn count(db: &ControlDb) -> Result<i64, String> {
    db.lock()
        .query_one("SELECT COUNT(*) FROM users", &[])
        .map(|r| r.get(0))
        .map_err(|e| format!("count users: {e}"))
}

/// Seats: people who can sign in — a password, and not disabled. What a
/// licence caps. A CI service account has no password and cannot sign
/// in, so it is not a seat; nor is somebody disabled, until re-enabled.
/// This is the one definition; the licence reads nothing else.
pub fn seat_count(db: &ControlDb) -> Result<i64, String> {
    db.lock()
        .query_one(
            "SELECT COUNT(*) FROM users \
             WHERE password_hash IS NOT NULL AND disabled_at IS NULL",
            &[],
        )
        .map(|r| r.get(0))
        .map_err(|e| format!("count seats: {e}"))
}

/// Verify a username/password pair. `None` for every failure shape —
/// unknown name, wrong password, disabled account, an account with no
/// password — so sign-in cannot be used to discover who has an account.
pub fn authenticate(
    db: &ControlDb,
    username: &str,
    password: &str,
) -> Result<Option<User>, String> {
    let Ok(username) = normalize_username(username) else {
        let _ = verify_password(DUMMY_HASH, password);
        return Ok(None);
    };
    let row = db
        .lock()
        .query_opt(
            &format!("SELECT {COLS}, password_hash FROM users WHERE username = $1"),
            &[&username],
        )
        .map_err(|e| format!("authenticate: {e}"))?;
    let Some(row) = row else {
        let _ = verify_password(DUMMY_HASH, password);
        return Ok(None);
    };
    let hash: Option<String> = row.get("password_hash");
    let user = row_to_user(&row);
    match hash {
        Some(h) => {
            Ok((verify_password(&h, password) && user.disabled_at.is_none()).then_some(user))
        }
        None => {
            let _ = verify_password(DUMMY_HASH, password);
            Ok(None)
        }
    }
}

pub fn set_password(db: &ControlDb, user_id: &str, password: &str) -> Result<(), String> {
    let hash = hash_password(password)?;
    let n = db
        .lock()
        .execute(
            "UPDATE users SET password_hash = $2 WHERE id = $1",
            &[&user_id, &hash],
        )
        .map_err(|e| format!("set password: {e}"))?;
    if n == 0 {
        return Err("no such user".into());
    }
    Ok(())
}

pub fn set_display_name(db: &ControlDb, user_id: &str, name: &str) -> Result<(), String> {
    let name = name.trim();
    if name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err("a display name is at most 100 characters, with no control characters".into());
    }
    db.lock()
        .execute(
            "UPDATE users SET display_name = $2 WHERE id = $1",
            &[&user_id, &name],
        )
        .map(|_| ())
        .map_err(|e| format!("set display name: {e}"))
}

/// Why a change to a person was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum ChangeError {
    NotFound,
    /// It would leave nobody able to administer the registry.
    LastAdmin,
    Other(String),
}

impl std::fmt::Display for ChangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeError::NotFound => write!(f, "no such user"),
            ChangeError::LastAdmin => write!(
                f,
                "that would leave no active admin — make somebody else an admin first"
            ),
            ChangeError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// Change a person's role.
///
/// Refuses to demote the last active admin. A self-hosted registry has
/// no support desk to call: an install with no admin can only be
/// recovered from the command line, so the question "would anybody be
/// left?" is asked inside the same transaction as the change.
pub fn set_role(db: &ControlDb, user_id: &str, role: Role) -> Result<(), ChangeError> {
    let demotes = role != Role::Admin;
    change_guarded(db, user_id, demotes, move |tx| {
        tx.execute(
            "UPDATE users SET role = $2 WHERE id = $1",
            &[&user_id, &role.as_str()],
        )
        .map(|_| ())
    })
}

/// Disable or re-enable a person. A disabled person's tokens and
/// sessions stop working at once — `auth::verify` and
/// `sessions::verify` both join on `disabled_at` — without deleting the
/// record of what they published.
pub fn set_disabled(db: &ControlDb, user_id: &str, disabled: bool) -> Result<(), ChangeError> {
    let at = disabled.then(now_ms);
    change_guarded(db, user_id, disabled, move |tx| {
        tx.execute(
            "UPDATE users SET disabled_at = $2 WHERE id = $1",
            &[&user_id, &at],
        )
        .map(|_| ())
    })
}

/// Remove a person. Their tokens and sessions go with them (CASCADE).
/// What they published stays, and so does who they were: a version
/// keeps the name it was published under (`published_by_name`) and every
/// audit entry the name it was written by (`actor_name`). Only the link
/// to this row goes — `published_by_user_id` is set to NULL — so a
/// person made later under the same name is not mistaken for them.
pub fn delete(db: &ControlDb, user_id: &str) -> Result<(), ChangeError> {
    change_guarded(db, user_id, true, move |tx| {
        tx.execute("DELETE FROM users WHERE id = $1", &[&user_id])
            .map(|_| ())
    })
}

/// Apply `f` to one person, unless `removes_admin` and they are the last
/// active admin.
///
/// The check comes before the change rather than after it, because a
/// refusal has to leave nothing behind and `transaction` only rolls back
/// on a driver error — which a refusal is not.
fn change_guarded<F>(
    db: &ControlDb,
    user_id: &str,
    removes_admin: bool,
    f: F,
) -> Result<(), ChangeError>
where
    F: FnOnce(&mut postgres::Transaction) -> Result<(), postgres::Error> + Send,
{
    if !crate::ids::valid_id(user_id) {
        return Err(ChangeError::NotFound);
    }
    db.lock()
        .transaction(|tx| {
            // Serialise every guarded change behind one row lock, so two
            // admins demoting each other at the same moment cannot both
            // see the other still standing.
            tx.execute("SELECT id FROM orgs FOR UPDATE", &[])?;
            let Some(target) = tx.query_opt(
                "SELECT role, disabled_at FROM users WHERE id = $1 FOR UPDATE",
                &[&user_id],
            )?
            else {
                return Ok(Err(ChangeError::NotFound));
            };
            let active_admin = target.get::<_, String>("role") == "admin"
                && target.get::<_, Option<i64>>("disabled_at").is_none();
            if removes_admin && active_admin {
                let others: i64 = tx
                    .query_one(
                        "SELECT COUNT(*) FROM users \
                         WHERE role = 'admin' AND disabled_at IS NULL AND id <> $1",
                        &[&user_id],
                    )?
                    .get(0);
                if others == 0 {
                    return Ok(Err(ChangeError::LastAdmin));
                }
            }
            f(tx)?;
            Ok(Ok(()))
        })
        .map_err(|e| ChangeError::Other(format!("change user: {}", crate::db::detail(&e))))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_are_lowercase_handles_and_refused_rather_than_cleaned() {
        assert_eq!(normalize_username(" Ada ").unwrap(), "ada");
        assert_eq!(normalize_username("ci-bot_2.x").unwrap(), "ci-bot_2.x");
        for bad in ["", "-ada", ".ada", "a da", "ada/b", "ädä", &"a".repeat(40)] {
            assert!(normalize_username(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn roles_round_trip_and_carry_their_scopes() {
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
        assert_eq!(Role::parse("owner"), None);
        assert_eq!(Role::Admin.scopes(), vec![Scope::OrgAdmin]);
        assert!(Role::Publisher.scopes().contains(&Scope::PackageWrite));
        assert!(!Role::Reader.scopes().contains(&Scope::PackageWrite));
    }

    fn db(hint: &str) -> ControlDb {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url(hint)).unwrap();
        crate::registry::create_org(&db, "acme").unwrap();
        db
    }

    /// Nobody can leave the registry without an admin — by demotion, by
    /// disabling, or by deletion — and the refusal leaves nothing behind.
    #[test]
    fn the_last_active_admin_cannot_be_removed_by_any_route() {
        let db = db("users_last_admin");
        let ada = create(&db, "ada", Role::Admin, Some("a long enough password")).unwrap();
        let bob = create(&db, "bob", Role::Reader, None).unwrap();

        assert_eq!(
            set_role(&db, &ada.id, Role::Reader),
            Err(ChangeError::LastAdmin)
        );
        assert_eq!(
            set_disabled(&db, &ada.id, true),
            Err(ChangeError::LastAdmin)
        );
        assert_eq!(delete(&db, &ada.id), Err(ChangeError::LastAdmin));
        let still = by_id(&db, &ada.id).unwrap().unwrap();
        assert_eq!(still.role, Role::Admin);
        assert!(still.disabled_at.is_none());

        // Promote a second, and the first may go.
        set_role(&db, &bob.id, Role::Admin).unwrap();
        set_role(&db, &ada.id, Role::Publisher).unwrap();
        // A disabled admin does not count as somebody left.
        set_role(&db, &ada.id, Role::Admin).unwrap();
        set_disabled(&db, &ada.id, true).unwrap();
        assert_eq!(
            set_role(&db, &bob.id, Role::Reader),
            Err(ChangeError::LastAdmin)
        );

        // Changes that add authority never trip the guard, and a
        // non-admin can always be changed.
        set_disabled(&db, &ada.id, false).unwrap();
        let carol = create(&db, "carol", Role::Reader, None).unwrap();
        set_disabled(&db, &carol.id, true).unwrap();
        delete(&db, &carol.id).unwrap();
        assert!(by_id(&db, &carol.id).unwrap().is_none());

        assert_eq!(
            set_role(&db, &carol.id, Role::Admin),
            Err(ChangeError::NotFound)
        );
        assert_eq!(delete(&db, "not-an-id"), Err(ChangeError::NotFound));
        assert!(ChangeError::LastAdmin
            .to_string()
            .contains("no active admin"));
    }

    /// Every failure to sign in looks the same, and a service account
    /// with no password cannot sign in at all.
    #[test]
    fn sign_in_fails_the_same_way_for_every_reason() {
        let db = db("users_signin");
        let ada = create(&db, "Ada", Role::Admin, Some("a long enough password")).unwrap();
        assert_eq!(ada.username, "ada", "stored lowercase");
        assert!(ada.has_password);
        let ci = create(&db, "ci", Role::Publisher, None).unwrap();
        assert!(!ci.has_password);

        assert_eq!(
            authenticate(&db, "ADA", "a long enough password")
                .unwrap()
                .unwrap()
                .id,
            ada.id
        );
        assert!(authenticate(&db, "ada", "the wrong password!!")
            .unwrap()
            .is_none());
        assert!(authenticate(&db, "nobody", "a long enough password")
            .unwrap()
            .is_none());
        assert!(authenticate(&db, "no/such", "a long enough password")
            .unwrap()
            .is_none());
        assert!(authenticate(&db, "ci", "anything at all here")
            .unwrap()
            .is_none());

        create(&db, "bob", Role::Admin, None).unwrap();
        set_disabled(&db, &ada.id, true).unwrap();
        assert!(authenticate(&db, "ada", "a long enough password")
            .unwrap()
            .is_none());

        let err = create(&db, "ADA", Role::Reader, None).unwrap_err();
        assert!(err.contains("taken"), "{err}");

        set_password(&db, &ci.id, "now it has a password").unwrap();
        assert!(authenticate(&db, "ci", "now it has a password")
            .unwrap()
            .is_some());
        assert!(set_password(&db, &ulid(), "a long enough password").is_err());
        set_display_name(&db, &ci.id, "Build robot").unwrap();
        assert!(set_display_name(&db, &ci.id, "bad\u{7}name").is_err());
        let ci = by_username(&db, "CI").unwrap().unwrap();
        assert_eq!(ci.display_name, "Build robot");
        assert!(by_username(&db, "not a name").unwrap().is_none());
        assert!(by_id(&db, "not-an-id").unwrap().is_none());

        let names: Vec<_> = list(&db).unwrap().into_iter().map(|u| u.username).collect();
        assert_eq!(names, ["ada", "bob", "ci"], "admins first, then by name");
        assert_eq!(count(&db).unwrap(), 3);
    }

    #[test]
    fn a_password_is_hashed_with_argon2id_and_verified() {
        let hash = hash_password("a long enough password").unwrap();
        assert!(hash.starts_with("$argon2id$"), "{hash}");
        assert!(verify_password(&hash, "a long enough password"));
        assert!(!verify_password(&hash, "a long enough passworD"));
        assert!(!verify_password("$argon2id$garbage", "anything"));
        assert!(hash_password("short").is_err());
        assert!(hash_password(&"x".repeat(4097)).is_err());
    }
}
