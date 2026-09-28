//! Append-only audit log. No UPDATE or DELETE statement for this table
//! exists anywhere in the codebase — immutability by construction at the
//! application layer.
//!
//! What is recorded: every change to what the registry holds (publish,
//! yank, delete, tag), to who may reach it (people, roles, tokens), and
//! to what it admits (ecosystems, the admission policy). Reads are not
//! audited: an `npm install` of eight hundred packages is not eight
//! hundred events anybody wants to read.

use crate::auth::Principal;
use crate::db::ControlDb;
use crate::ids::now_ms;
use serde::Serialize;

/// Passed into every mutating operation so recording can't be forgotten
/// at call sites.
#[derive(Debug, Clone)]
pub struct AuditCtx {
    /// Acting principal: `user:<id>` for a person, `system:<worker>` for
    /// work the server does on its own behalf.
    pub principal: String,
    /// The person, when one acted — so "what did Ada do?" is an indexed
    /// query that joins to her name rather than a prefix match on text.
    pub user_id: Option<String>,
    /// The token they used, when they used one. Recorded in the context
    /// rather than as the principal: the trail reads as people.
    pub token_id: Option<String>,
    pub org_id: String,
}

impl AuditCtx {
    /// The context for a request, from whoever it authenticated as. The
    /// single producer, so no call site spells "who acted" differently.
    pub fn of(org_id: &str, p: &Principal) -> AuditCtx {
        AuditCtx {
            principal: p.audit_id(),
            user_id: Some(p.user_id.clone()),
            token_id: p.token_id.clone(),
            org_id: org_id.to_string(),
        }
    }

    /// Work the server does on its own behalf: the collector, a sweep,
    /// the command line. `who` names it.
    pub fn system(org_id: &str, who: &str) -> AuditCtx {
        AuditCtx {
            principal: format!("system:{who}"),
            user_id: None,
            token_id: None,
            org_id: org_id.to_string(),
        }
    }

    fn context(&self, context: Option<&serde_json::Value>) -> Option<String> {
        match (&self.token_id, context) {
            (None, c) => c.map(|c| c.to_string()),
            (Some(t), Some(serde_json::Value::Object(m))) => {
                let mut m = m.clone();
                m.insert("token_id".into(), t.clone().into());
                Some(serde_json::Value::Object(m).to_string())
            }
            (Some(t), Some(other)) => {
                Some(serde_json::json!({ "token_id": t, "detail": other }).to_string())
            }
            (Some(t), None) => Some(serde_json::json!({ "token_id": t }).to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub seq: i64,
    pub at: i64,
    pub principal: String,
    pub user_id: Option<String>,
    /// Resolved by join at read time, never copied into the row: an
    /// audit entry records what happened, and a person's current name is
    /// not part of what happened.
    pub username: Option<String>,
    pub action: String,
    pub context: Option<serde_json::Value>,
}

const INSERT: &str = "INSERT INTO audit_log (at, org_id, principal, user_id, action, context) \
                      VALUES ($1, $2, $3, $4, $5, $6)";

pub fn record(
    db: &ControlDb,
    ctx: &AuditCtx,
    action: &str,
    context: Option<&serde_json::Value>,
) -> Result<(), String> {
    let context = ctx.context(context);
    db.lock()
        .execute(
            INSERT,
            &[
                &now_ms(),
                &ctx.org_id,
                &ctx.principal,
                &ctx.user_id,
                &action,
                &context,
            ],
        )
        .map(|_| ())
        .map_err(|e| format!("record audit entry: {e}"))
}

/// The most recent entries, newest first, strictly older than `before`
/// when paging.
pub fn recent(
    db: &ControlDb,
    org_id: &str,
    before: Option<i64>,
    limit: i64,
) -> Result<Vec<AuditEntry>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT a.seq, a.at, a.principal, a.user_id, a.action, a.context, u.username \
             FROM audit_log a LEFT JOIN users u ON u.id = a.user_id \
             WHERE a.org_id = $1 AND ($2::int8 IS NULL OR a.seq < $2) \
             ORDER BY a.seq DESC LIMIT $3",
            &[&org_id, &before, &limit.clamp(1, 500)],
        )
        .map_err(|e| format!("audit log: {e}"))?
        .iter()
        .map(|r| AuditEntry {
            seq: r.get("seq"),
            at: r.get("at"),
            principal: r.get("principal"),
            user_id: r.get("user_id"),
            username: r.get("username"),
            action: r.get("action"),
            context: r
                .get::<_, Option<String>>("context")
                .and_then(|c| serde_json::from_str(&c).ok()),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_person_is_the_principal_and_their_token_is_in_the_context() {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url("audit")).unwrap();
        let org = crate::registry::create_org(&db, "acme").unwrap();
        let ada = crate::users::create(&db, "ada", crate::users::Role::Admin, None).unwrap();
        let (_, tok) =
            crate::auth::mint(&db, &ada, "laptop", &[crate::auth::Scope::OrgAdmin], None).unwrap();
        let via_token = crate::auth::verify(&db, &tok).unwrap().unwrap();
        let via_session = Principal::for_user(&ada);

        let ctx = AuditCtx::of(&org.id, &via_token);
        record(
            &db,
            &ctx,
            "package.publish",
            Some(&serde_json::json!({"name": "w"})),
        )
        .unwrap();
        record(&db, &ctx, "token.use", Some(&serde_json::json!("bare"))).unwrap();
        record(&db, &ctx, "token.none", None).unwrap();
        record(
            &db,
            &AuditCtx::of(&org.id, &via_session),
            "session.thing",
            None,
        )
        .unwrap();
        record(&db, &AuditCtx::system(&org.id, "gc"), "blob.collect", None).unwrap();

        let all = recent(&db, &org.id, None, 50).unwrap();
        let actions: Vec<_> = all.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(
            actions,
            [
                "blob.collect",
                "session.thing",
                "token.none",
                "token.use",
                "package.publish"
            ],
            "newest first"
        );
        let publish = &all[4];
        assert_eq!(publish.principal, format!("user:{}", ada.id));
        assert_eq!(publish.username.as_deref(), Some("ada"));
        let c = publish.context.as_ref().unwrap();
        assert_eq!(c["name"], "w");
        assert_eq!(c["token_id"], via_token.token_id.clone().unwrap());
        assert_eq!(all[3].context.as_ref().unwrap()["detail"], "bare");
        assert!(all[2].context.as_ref().unwrap()["token_id"].is_string());
        assert!(all[1].context.is_none(), "a session has no token");
        assert_eq!(all[0].principal, "system:gc");
        assert!(all[0].username.is_none());

        let older = recent(&db, &org.id, Some(all[1].seq), 50).unwrap();
        assert_eq!(older.len(), 3);
        assert!(recent(&db, "someone-else", None, 50).unwrap().is_empty());
    }
}
