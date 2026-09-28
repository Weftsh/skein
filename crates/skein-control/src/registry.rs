//! The organization this install serves, and the one place a request can
//! become an object-store key.
//!
//! A self-hosted Skein serves exactly one organization, and everything in
//! it is private to that organization's people. The organization is
//! still a row with an id rather than a constant, because the id is the
//! store prefix every blob lives under and the scope every package
//! lookup is written against — so a second namespace later is a new row,
//! not a rewrite of every query and every stored key. The database holds
//! it to one row (`orgs_singleton`).
//!
//! [`PackagePrefix`] is the only way to build a package key. It can only
//! be made from an [`Org`], so there is no code path from a request
//! string to a store key that does not go through the organization.

use crate::db::{is_unique_violation, ControlDb};
use crate::ids::{now_ms, ulid};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Org {
    pub id: String,
    pub name: String,
    pub created_at: i64,
}

/// The object-store prefix a package blob lives under:
/// `o/<org>/pkg/<sha256>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackagePrefix(String);

impl PackagePrefix {
    /// The key one blob lives at. Takes the digest as `sha256:<hex>` or
    /// bare hex and stores it bare, so the key is a path segment in
    /// every store: a colon is legal in an S3 key but is percent-encoded
    /// by some clients and not others, and a key that round-trips
    /// differently depending on who wrote it is a key you cannot delete.
    pub fn blob(&self, digest: &str) -> String {
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        format!("{}/{hex}", self.0)
    }
}

impl Org {
    pub fn package_prefix(&self) -> PackagePrefix {
        PackagePrefix(format!("o/{}/pkg", self.id))
    }
}

/// A valid organization name: what the UI shows and what `.npmrc` scope
/// examples are written with. DNS-label-ish, because people put it in
/// hostnames.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

/// The organization, if the install has been bootstrapped.
pub fn the_org(db: &ControlDb) -> Result<Option<Org>, String> {
    Ok(db
        .lock()
        .query_opt("SELECT id, name, created_at FROM orgs", &[])
        .map_err(|e| format!("read organization: {e}"))?
        .map(|r| Org {
            id: r.get("id"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        }))
}

/// Create the organization. Refused if one already exists: an install
/// serves one, and the database enforces it.
pub fn create_org(db: &ControlDb, name: &str) -> Result<Org, String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid organization name {name:?}: lowercase letters, digits and dashes, \
             at most 64 characters"
        ));
    }
    let org = Org {
        id: ulid(),
        name: name.to_string(),
        created_at: now_ms(),
    };
    db.lock()
        .execute(
            "INSERT INTO orgs (id, name, created_at) VALUES ($1, $2, $3)",
            &[&org.id, &org.name, &org.created_at],
        )
        .map_err(|e| {
            if is_unique_violation(&e) {
                "this install already serves an organization".to_string()
            } else {
                format!("create organization: {e}")
            }
        })?;
    Ok(org)
}

/// Rename the organization. The id — and so every stored key — stays.
pub fn rename_org(db: &ControlDb, org_id: &str, name: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!(
            "invalid organization name {name:?}: lowercase letters, digits and dashes, \
             at most 64 characters"
        ));
    }
    db.lock()
        .execute("UPDATE orgs SET name = $2 WHERE id = $1", &[&org_id, &name])
        .map(|_| ())
        .map_err(|e| format!("rename organization: {e}"))
}

/// A round trip to the database, for `readyz`.
pub fn ping(db: &ControlDb) -> Result<(), String> {
    db.lock()
        .query_one("SELECT 1", &[])
        .map(|_| ())
        .map_err(|e| format!("database: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_dns_label_shaped() {
        for ok in ["acme", "acme-corp", "a", "x9"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in [
            "",
            "Acme",
            "-acme",
            "acme-",
            "ac me",
            "ac/me",
            "ac.me",
            &"a".repeat(65),
        ] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_blob_key_is_the_bare_digest_under_the_org() {
        let org = Org {
            id: "01j0000000000000000000000".into(),
            name: "acme".into(),
            created_at: 0,
        };
        let p = org.package_prefix();
        assert_eq!(
            p.blob("sha256:ab12"),
            "o/01j0000000000000000000000/pkg/ab12"
        );
        assert_eq!(p.blob("ab12"), p.blob("sha256:ab12"));
    }

    /// One organization per install, held by the database rather than
    /// by callers remembering.
    #[test]
    fn an_install_serves_exactly_one_organization() {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url("registry_one")).unwrap();
        assert!(the_org(&db).unwrap().is_none());
        let org = create_org(&db, "acme").unwrap();
        let err = create_org(&db, "other").unwrap_err();
        assert!(err.contains("already serves"), "{err}");
        assert_eq!(the_org(&db).unwrap().unwrap().id, org.id);
        rename_org(&db, &org.id, "acme-corp").unwrap();
        let again = the_org(&db).unwrap().unwrap();
        assert_eq!(
            (again.id.as_str(), again.name.as_str()),
            (org.id.as_str(), "acme-corp")
        );
        assert!(create_org(&db, "Bad Name").is_err());
        assert!(rename_org(&db, &again.id, "Bad Name").is_err());
        ping(&db).unwrap();
    }
}
