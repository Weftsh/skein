//! Tokens: `skein_<id>_<secret>`, SHA-256 of the secret at rest.
//!
//! SHA-256 rather than a password KDF is deliberate: secrets are 256-bit
//! random strings, not human passwords, so brute force is hopeless, and
//! a per-request KDF would put Argon2 on every `npm install` or force a
//! token cache that would break instant revocation. Every request hits
//! the database; revocation is one UPDATE.
//!
//! ## A token carries its owner's authority *now*
//!
//! A token is minted with a ceiling — `package:read` for a laptop's
//! `.npmrc`, `package:write` for a release job — and what it may do on a
//! given request is that ceiling **intersected with its owner's role at
//! that moment**. Demote a publisher to reader and the token in their CI
//! stops publishing on its next request; disable them and it stops
//! working at all. There is no cached authority to outlive the decision.
//!
//! The model is stratum-core's personal access tokens, without the forge
//! around it: there are no repositories, no per-repository grants, and
//! no organization-level service tokens — a CI credential is a token
//! held by a service account with no password.

use crate::db::ControlDb;
use crate::ids::{now_ms, token_secret, ulid};
use crate::users::Role;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The prefix every token starts with. What the header readers look for
/// in a Basic credential's either field, and what makes a leaked token
/// greppable by a secret scanner.
pub const PREFIX: &str = "skein_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Scope {
    /// Everything: settings, the admission policy, people, deleting a
    /// package. Grants every other scope.
    #[serde(rename = "org:admin")]
    OrgAdmin,
    /// Read the registry and its settings: what is here, what the policy
    /// caught and why. Carries `package:read`, because somebody whose
    /// install was refused has to be able to install the rest.
    #[serde(rename = "org:read")]
    OrgRead,
    /// Install. What a developer's `.npmrc` holds.
    #[serde(rename = "package:read")]
    PackageRead,
    /// Publish and yank. Carries `package:read` — nobody publishes to a
    /// registry they cannot resolve against.
    #[serde(rename = "package:write")]
    PackageWrite,
}

impl Scope {
    /// Every scope, for computing intersections capability by capability.
    pub const ALL: [Scope; 4] = [
        Scope::OrgAdmin,
        Scope::OrgRead,
        Scope::PackageRead,
        Scope::PackageWrite,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::OrgAdmin => "org:admin",
            Scope::OrgRead => "org:read",
            Scope::PackageRead => "package:read",
            Scope::PackageWrite => "package:write",
        }
    }

    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

/// Whether holding `have` is enough for `need`.
pub fn grants(have: Scope, need: Scope) -> bool {
    match have {
        Scope::OrgAdmin => true,
        Scope::OrgRead => matches!(need, Scope::OrgRead | Scope::PackageRead),
        Scope::PackageWrite => matches!(need, Scope::PackageWrite | Scope::PackageRead),
        Scope::PackageRead => need == Scope::PackageRead,
    }
}

/// The authority two scope sets both allow.
///
/// Computed capability by capability rather than by matching names,
/// because scopes imply one another: a `package:write` ceiling held by
/// somebody whose role is `org:read` should still install, and name
/// intersection would leave it granting nothing at all.
pub fn intersect(a: &[Scope], b: &[Scope]) -> Vec<Scope> {
    Scope::ALL
        .into_iter()
        .filter(|need| a.iter().any(|s| grants(*s, *need)) && b.iter().any(|s| grants(*s, *need)))
        .collect()
}

/// The verified identity attached to a request: a person, reached
/// through a token or a browser session.
#[derive(Debug, Clone, Serialize)]
pub struct Principal {
    pub user_id: String,
    pub username: String,
    pub role: Role,
    /// The token this request presented. `None` for a browser session.
    pub token_id: Option<String>,
    /// What this request may do: the role, narrowed by the token's
    /// ceiling when there is one.
    pub scopes: Vec<Scope>,
}

impl Principal {
    /// A person acting through a browser session: their role, whole.
    pub fn for_user(user: &crate::users::User) -> Principal {
        Principal {
            user_id: user.id.clone(),
            username: user.username.clone(),
            role: user.role,
            token_id: None,
            scopes: user.role.scopes(),
        }
    }

    pub fn allows(&self, need: Scope) -> bool {
        self.scopes.iter().any(|s| grants(*s, need))
    }

    /// Audit identity: always the person, so the trail reads `user:…`
    /// whichever credential they used; the token is in the context.
    pub fn audit_id(&self) -> String {
        format!("user:{}", self.user_id)
    }
}

/// A token as its owner and an admin see it. Never the secret.
#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub label: String,
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub last_used_at: Option<i64>,
    pub revoked_at: Option<i64>,
}

fn hash_secret(secret: &str) -> String {
    crate::hex(&Sha256::digest(secret.as_bytes()))
}

fn parse_scopes(s: &str) -> Vec<Scope> {
    s.split(',').filter_map(Scope::parse).collect()
}

fn join_scopes(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(Scope::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// The longest label a token may carry.
pub const MAX_LABEL: usize = 100;

/// Mint a token for `user_id`. The plaintext is returned once and never
/// stored.
///
/// The ceiling may not exceed the owner's role: a reader cannot mint a
/// `package:write` token, even one that would be narrowed on use. That
/// is not redundant with the narrowing — a token whose label says
/// "publish" and which cannot publish is a confusing thing to hand
/// somebody, and refusing it at mint says so while they are looking.
pub fn mint(
    db: &ControlDb,
    user: &crate::users::User,
    label: &str,
    scopes: &[Scope],
    expires_at: Option<i64>,
) -> Result<(TokenInfo, String), String> {
    let label = label.trim();
    if label.is_empty() {
        return Err("a token needs a label, so you can tell it apart later".into());
    }
    if label.chars().count() > MAX_LABEL || label.chars().any(char::is_control) {
        return Err(format!(
            "a token label is at most {MAX_LABEL} characters, with no control characters"
        ));
    }
    if scopes.is_empty() {
        return Err("a token needs at least one scope".into());
    }
    let role = user.role.scopes();
    if let Some(over) = scopes
        .iter()
        .find(|s| !role.iter().any(|r| grants(*r, **s)))
    {
        return Err(format!(
            "a {} cannot mint a token with {}",
            user.role.as_str(),
            over.as_str()
        ));
    }
    let now = now_ms();
    if expires_at.is_some_and(|e| e <= now) {
        return Err("that expiry is in the past".into());
    }
    let id = ulid();
    let secret = token_secret();
    db.lock()
        .execute(
            "INSERT INTO tokens (id, user_id, hash, scopes, label, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            &[
                &id,
                &user.id,
                &hash_secret(&secret),
                &join_scopes(scopes),
                &label,
                &now,
                &expires_at,
            ],
        )
        .map_err(|e| format!("mint token: {e}"))?;
    Ok((
        TokenInfo {
            id: id.clone(),
            user_id: user.id.clone(),
            username: user.username.clone(),
            label: label.to_string(),
            scopes: scopes.to_vec(),
            created_at: now,
            expires_at,
            last_used_at: None,
            revoked_at: None,
        },
        format!("{PREFIX}{id}_{secret}"),
    ))
}

/// How often `last_used_at` is written. Every request verifies against
/// the database; not every request needs to write to it.
const LAST_USED_GRANULARITY_MS: i64 = 60_000;

/// Resolve a presented token to a principal, or `None`.
///
/// Every failure is the same answer — malformed, unknown, revoked,
/// expired, wrong secret, or owned by a disabled person — so a token
/// cannot be used to probe which tokens exist.
pub fn verify(db: &ControlDb, presented: &str) -> Result<Option<Principal>, String> {
    let Some(rest) = presented.strip_prefix(PREFIX) else {
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
            "SELECT t.hash, t.scopes, t.revoked_at, t.expires_at, t.last_used_at, \
                    u.id AS user_id, u.username, u.role, u.disabled_at \
             FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.id = $1",
            &[&id],
        )
        .map_err(|e| format!("verify token: {e}"))?;
    let Some(row) = row else {
        return Ok(None);
    };
    let now = now_ms();
    if row.get::<_, Option<i64>>("revoked_at").is_some()
        || row
            .get::<_, Option<i64>>("expires_at")
            .is_some_and(|e| e <= now)
        || row.get::<_, Option<i64>>("disabled_at").is_some()
    {
        return Ok(None);
    }
    let stored: String = row.get("hash");
    if !crate::sessions::constant_time_eq(hash_secret(secret).as_bytes(), stored.as_bytes()) {
        return Ok(None);
    }
    let role = Role::parse(row.get("role")).unwrap_or(Role::Reader);
    let scopes = intersect(&parse_scopes(row.get("scopes")), &role.scopes());
    if scopes.is_empty() {
        return Ok(None);
    }
    if row
        .get::<_, Option<i64>>("last_used_at")
        .is_none_or(|t| now - t >= LAST_USED_GRANULARITY_MS)
    {
        // Best-effort: a failure to note use must never fail a request
        // the token was otherwise entitled to make.
        let _ = db.lock().execute(
            "UPDATE tokens SET last_used_at = $2 WHERE id = $1",
            &[&id, &now],
        );
    }
    Ok(Some(Principal {
        user_id: row.get("user_id"),
        username: row.get("username"),
        role,
        token_id: Some(id.to_string()),
        scopes,
    }))
}

const INFO_SQL: &str = "SELECT t.id, t.user_id, u.username, t.label, t.scopes, t.created_at, \
                        t.expires_at, t.last_used_at, t.revoked_at \
                        FROM tokens t JOIN users u ON u.id = t.user_id";

fn row_to_info(r: &postgres::Row) -> TokenInfo {
    TokenInfo {
        id: r.get("id"),
        user_id: r.get("user_id"),
        username: r.get("username"),
        label: r.get("label"),
        scopes: parse_scopes(r.get("scopes")),
        created_at: r.get("created_at"),
        expires_at: r.get("expires_at"),
        last_used_at: r.get("last_used_at"),
        revoked_at: r.get("revoked_at"),
    }
}

/// Live tokens, newest first: one person's, or everybody's for an admin.
pub fn list(db: &ControlDb, user_id: Option<&str>) -> Result<Vec<TokenInfo>, String> {
    let rows = match user_id {
        Some(u) => db.lock().query(
            &format!(
                "{INFO_SQL} WHERE t.user_id = $1 AND t.revoked_at IS NULL \
                 ORDER BY t.created_at DESC"
            ),
            &[&u],
        ),
        None => db.lock().query(
            &format!("{INFO_SQL} WHERE t.revoked_at IS NULL ORDER BY t.created_at DESC"),
            &[],
        ),
    }
    .map_err(|e| format!("list tokens: {e}"))?;
    Ok(rows.iter().map(row_to_info).collect())
}

pub fn by_id(db: &ControlDb, id: &str) -> Result<Option<TokenInfo>, String> {
    if !crate::ids::valid_id(id) {
        return Ok(None);
    }
    Ok(db
        .lock()
        .query_opt(&format!("{INFO_SQL} WHERE t.id = $1"), &[&id])
        .map_err(|e| format!("token by id: {e}"))?
        .as_ref()
        .map(row_to_info))
}

/// Revoke one token. Idempotent: revoking a revoked token is `false`,
/// not an error.
pub fn revoke(db: &ControlDb, id: &str) -> Result<bool, String> {
    if !crate::ids::valid_id(id) {
        return Ok(false);
    }
    db.lock()
        .execute(
            "UPDATE tokens SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL",
            &[&id, &now_ms()],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("revoke token: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users;

    #[test]
    fn scopes_imply_what_they_should_and_nothing_more() {
        use Scope::*;
        for s in Scope::ALL {
            assert_eq!(Scope::parse(s.as_str()), Some(s));
            assert!(grants(OrgAdmin, s), "admin grants {s:?}");
            assert!(grants(s, s));
        }
        assert!(grants(OrgRead, PackageRead));
        assert!(grants(PackageWrite, PackageRead));
        assert!(!grants(OrgRead, PackageWrite));
        assert!(!grants(PackageWrite, OrgRead));
        assert!(!grants(PackageRead, OrgRead));
        assert!(!grants(PackageWrite, OrgAdmin));
        assert_eq!(Scope::parse("repo:write"), None);
    }

    #[test]
    fn intersection_is_by_capability_not_by_name() {
        use Scope::*;
        // A write ceiling held by a reader still installs.
        assert_eq!(intersect(&[PackageWrite], &[OrgRead]), vec![PackageRead]);
        assert_eq!(intersect(&[OrgAdmin], &[OrgRead, PackageWrite]).len(), 3);
        assert!(intersect(&[PackageRead], &[]).is_empty());
    }

    fn world(hint: &str) -> (ControlDb, users::User) {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url(hint)).unwrap();
        crate::registry::create_org(&db, "acme").unwrap();
        let u = users::create(&db, "ada", Role::Admin, None).unwrap();
        (db, u)
    }

    /// The whole life of a token: minted, verified, narrowed by a
    /// demotion on its very next use, dead when its owner is disabled,
    /// and dead for good when revoked.
    #[test]
    fn a_token_carries_its_owners_authority_now() {
        let (db, admin) = world("auth_life");
        let pub_user = users::create(&db, "ci", Role::Publisher, None).unwrap();
        let (info, tok) = mint(&db, &pub_user, "release", &[Scope::PackageWrite], None).unwrap();
        assert!(tok.starts_with("skein_"));
        assert_eq!(info.scopes, vec![Scope::PackageWrite]);

        let p = verify(&db, &tok).unwrap().expect("a fresh token verifies");
        assert_eq!(p.user_id, pub_user.id);
        assert_eq!(p.token_id.as_deref(), Some(info.id.as_str()));
        assert!(p.allows(Scope::PackageWrite));
        assert!(p.allows(Scope::PackageRead));
        assert!(!p.allows(Scope::OrgAdmin));
        assert_eq!(p.audit_id(), format!("user:{}", pub_user.id));
        assert!(
            by_id(&db, &info.id)
                .unwrap()
                .unwrap()
                .last_used_at
                .is_some(),
            "use is noted"
        );

        // Demoted: the same token installs and no longer publishes.
        users::set_role(&db, &pub_user.id, Role::Reader).unwrap();
        let p = verify(&db, &tok).unwrap().unwrap();
        assert!(p.allows(Scope::PackageRead));
        assert!(!p.allows(Scope::PackageWrite));

        // Disabled: nothing.
        users::set_disabled(&db, &pub_user.id, true).unwrap();
        assert!(verify(&db, &tok).unwrap().is_none());
        users::set_disabled(&db, &pub_user.id, false).unwrap();
        assert!(verify(&db, &tok).unwrap().is_some());

        // Revoked: nothing, and revoking again is not an error.
        assert!(revoke(&db, &info.id).unwrap());
        assert!(!revoke(&db, &info.id).unwrap());
        assert!(verify(&db, &tok).unwrap().is_none());
        assert!(list(&db, Some(&pub_user.id)).unwrap().is_empty());

        // An admin's list is everybody's live tokens.
        let (_, _t) = mint(&db, &admin, "laptop", &[Scope::PackageRead], None).unwrap();
        assert_eq!(list(&db, None).unwrap().len(), 1);
        assert!(!revoke(&db, "not-an-id").unwrap());
        assert!(by_id(&db, "not-an-id").unwrap().is_none());
    }

    #[test]
    fn every_malformed_or_forged_token_is_simply_not_a_token() {
        let (db, admin) = world("auth_forged");
        let (info, tok) = mint(&db, &admin, "x", &[Scope::OrgAdmin], None).unwrap();
        let secret = tok.rsplit('_').next().unwrap();
        for bad in [
            "".to_string(),
            "weft_abc_def".to_string(),
            "skein_".to_string(),
            "skein_nounderscore".to_string(),
            format!("skein_{}_", info.id),
            format!("skein_{}_{}x", info.id, secret),
            format!("skein_{}_{}", crate::ids::ulid(), secret),
            format!("skein_../../etc_{secret}"),
        ] {
            assert!(verify(&db, &bad).unwrap().is_none(), "{bad:?}");
        }
    }

    #[test]
    fn minting_refuses_what_the_owner_could_never_use() {
        let (db, _) = world("auth_mint");
        let reader = users::create(&db, "rita", Role::Reader, None).unwrap();
        let err = mint(&db, &reader, "x", &[Scope::PackageWrite], None).unwrap_err();
        assert!(err.contains("reader cannot mint"), "{err}");
        assert!(mint(&db, &reader, "x", &[Scope::PackageRead], None).is_ok());
        assert!(mint(&db, &reader, "  ", &[Scope::PackageRead], None).is_err());
        assert!(mint(&db, &reader, &"x".repeat(101), &[Scope::PackageRead], None).is_err());
        assert!(mint(&db, &reader, "x", &[], None).is_err());
        assert!(mint(&db, &reader, "x", &[Scope::PackageRead], Some(1)).is_err());

        // An expiry in the future is honoured when it passes.
        let soon = now_ms() + 200;
        let (_, tok) = mint(&db, &reader, "short", &[Scope::PackageRead], Some(soon)).unwrap();
        assert!(verify(&db, &tok).unwrap().is_some());
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(verify(&db, &tok).unwrap().is_none());
    }
}
