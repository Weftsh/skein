//! The package registry's control plane: what the organization publishes,
//! what it cached from upstream, and who published each version.
//!
//! Carried over from stratum-core's `packages` module nearly line for
//! line. Every package is private to the organization: there is no
//! public package and no anonymous read anywhere in Skein.
//!
//! ## Names are normalised here, not at the door
//!
//! Several ecosystems fold names: PEP 503 makes `.`, `_` and `-`
//! equivalent, npm and OCI lowercase. `normalized_name` carries the
//! unique index, and [`normalize_name`] is the only thing that produces
//! it. That matters more than it looks: two spellings admitted as two
//! rows are not merely a duplicate, they are an **authorization
//! bypass** — the second row answers for a name whose grants and
//! ownership live on the first. So normalisation is a pure function in
//! the same module as the table it keys, exhaustively tested, rather
//! than something each protocol adapter does on its way past.
//!
//! [`normalize_name`] also *validates*, and refuses rather than
//! sanitising. A name is on its way to becoming part of an object-store
//! key and a URL path, so `..`, a leading `/`, a control character or an
//! overlong string is refused by name. Quietly stripping them would map
//! two different requests onto one stored object, which is the shape of
//! every path-traversal bug that ever mattered.
//!
//! ## A version is immutable
//!
//! [`publish_version`] refuses a version that already exists. npm, PyPI,
//! Maven and Cargo all cache on the assumption that a resolved version
//! is stable, and a mutable one is a supply-chain hole: the bytes a
//! lockfile was reviewed against stop being the bytes it installs.
//! [`yank`] hides a version from resolution without removing it, so a
//! lockfile that already names it still builds.
//!
//! ## Blobs are content-addressed
//!
//! Keyed `(org_id, digest)`: identical bytes published twice are one
//! object, and a re-push of an unchanged layer is free.
//!
//! Nothing here carries a refcount. A blob is live iff some
//! `package_files` row names its digest, which the collector answers
//! with one query ([`unreferenced_blobs`]); a refcount that drifts is a
//! silently deleted layer, and the drift is invisible until a pull
//! fails.
//!
//! What a blob does carry is when it was last **used** (`touched_at`):
//! stored, stored again, or answered for to a client that will build on
//! it without sending it. Content addressing is what makes that
//! necessary — the bytes a publish is relying on may be bytes somebody
//! else stored long ago — and the collector's grace is measured from it.

use crate::db::{is_unique_violation, ControlDb};
use crate::ids::ulid;
use serde::{Deserialize, Serialize};

/// The longest package name we store. npm's own limit, and comfortably
/// above what the other four admit; a name is a URL path segment and a
/// database key, and an unbounded one is somebody's input.
pub const MAX_NAME: usize = 214;
/// The longest version string. Generous for every ecosystem's grammar —
/// the point is a ceiling, not a parser.
pub const MAX_VERSION: usize = 128;
/// The longest tag (`latest`, `next`, an OCI tag).
pub const MAX_TAG: usize = 128;

pub const ORIGIN_LOCAL: &str = "local";
pub const ORIGIN_PROXIED: &str = "proxied";

pub const MODE_OFF: &str = "off";
pub const MODE_PRIVATE: &str = "private";
pub const MODE_PROXY: &str = "proxy";

// ---------------------------------------------------------------- kinds

/// The ecosystems the registry speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Npm,
    Maven,
    Pypi,
    Cargo,
    Oci,
}

impl Ecosystem {
    /// Every ecosystem, in the order they are presented.
    pub const ALL: [Ecosystem; 5] = [
        Ecosystem::Npm,
        Ecosystem::Maven,
        Ecosystem::Pypi,
        Ecosystem::Cargo,
        Ecosystem::Oci,
    ];

    /// The name stored in `packages.ecosystem` and named in a URL.
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Maven => "maven",
            Ecosystem::Pypi => "pypi",
            Ecosystem::Cargo => "cargo",
            Ecosystem::Oci => "oci",
        }
    }

    /// What a person calls it, for a refusal somebody has to read.
    pub fn label(&self) -> &'static str {
        match self {
            Ecosystem::Npm => "npm",
            Ecosystem::Maven => "Maven",
            Ecosystem::Pypi => "PyPI",
            Ecosystem::Cargo => "Cargo",
            Ecosystem::Oci => "OCI",
        }
    }

    pub fn parse(s: &str) -> Option<Ecosystem> {
        Ecosystem::ALL.into_iter().find(|e| e.as_str() == s)
    }
}

fn eco_of(s: &str) -> Result<Ecosystem, String> {
    Ecosystem::parse(s).ok_or_else(|| format!("unknown ecosystem {s:?}"))
}

// -------------------------------------------------------- normalisation

/// Characters no package name may contain in any ecosystem, whatever
/// its own grammar admits.
///
/// This is the security floor, checked before the per-ecosystem rules
/// and never relaxed by them. A name becomes a URL path segment and part
/// of a store key lookup, so a path separator it did not earn, a `..`,
/// a backslash, a NUL or any other control character is refused rather
/// than stripped. Stripping maps two different requests onto one stored
/// object; refusing does not.
fn reject_dangerous(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("invalid package name: it is empty".into());
    }
    if name.len() > MAX_NAME {
        return Err(format!(
            "invalid package name: {} bytes, and the limit is {MAX_NAME}",
            name.len()
        ));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err("invalid package name: it contains a control character".into());
    }
    if name.contains('\\') {
        return Err("invalid package name: it contains a backslash".into());
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err("invalid package name: it starts or ends with a slash".into());
    }
    if name.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("invalid package name: it contains a path segment of \".\" or \"..\"".into());
    }
    if name.contains("//") {
        return Err("invalid package name: it contains an empty path segment".into());
    }
    if !name.is_ascii() {
        return Err("invalid package name: it contains a non-ASCII character".into());
    }
    Ok(())
}

/// Fold `.`, `_` and runs of `-` together and lowercase: PEP 503's rule,
/// which Cargo also applies for the purpose of deciding that two names
/// are the same crate.
fn fold_separators(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut sep = false;
    for c in s.chars() {
        if c == '.' || c == '_' || c == '-' {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// The name a lookup matches on, or a refusal naming what is wrong.
///
/// Per ecosystem, because they genuinely differ:
///
/// * **npm** lowercases. A scoped name is `@scope/name` — the one place
///   a slash is legal, and exactly one.
/// * **PyPI** folds `.`, `_` and `-` and lowercases (PEP 503).
/// * **Cargo** folds `-` and `_` and lowercases: crates.io will not
///   register two names differing only there, so treating them as one
///   package is what matches the ecosystem people actually use.
/// * **Maven** is `groupId:artifactId`, case-sensitive in principle but
///   folded here for the same reason npm is — two artifacts differing
///   only in case are a mistake, not a design.
/// * **OCI** is already required to be lowercase by the distribution
///   spec, and is a `/`-separated path.
pub fn normalize_name(eco: Ecosystem, name: &str) -> Result<String, String> {
    let name = name.trim();
    reject_dangerous(name)?;
    match eco {
        Ecosystem::Npm => {
            let slashes = name.matches('/').count();
            if slashes > 1 {
                return Err(
                    "invalid package name: an npm name has at most one slash, in \"@scope/name\""
                        .into(),
                );
            }
            if slashes == 1 && !name.starts_with('@') {
                return Err(
                    "invalid package name: an npm name with a slash must be scoped, \"@scope/name\""
                        .into(),
                );
            }
            if name.starts_with('@') && slashes == 0 {
                return Err(
                    "invalid package name: a scoped npm name needs a slash, \"@scope/name\"".into(),
                );
            }
            if name.contains('@') && !name.starts_with('@') {
                return Err("invalid package name: \"@\" is only legal as a scope marker".into());
            }
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::Pypi => {
            if name.contains('/') {
                return Err("invalid package name: a PyPI name has no slash".into());
            }
            let folded = fold_separators(name);
            if folded.is_empty() {
                return Err("invalid package name: it is only separators".into());
            }
            Ok(folded)
        }
        Ecosystem::Cargo => {
            if name.contains('/') {
                return Err("invalid package name: a crate name has no slash".into());
            }
            if name.contains('.') {
                return Err("invalid package name: a crate name has no dot".into());
            }
            let folded = fold_separators(name);
            if folded.is_empty() {
                return Err("invalid package name: it is only separators".into());
            }
            Ok(folded)
        }
        Ecosystem::Maven => {
            if name.contains('/') {
                return Err(
                    "invalid package name: a Maven name is \"groupId:artifactId\", with no slash"
                        .into(),
                );
            }
            let mut parts = name.split(':');
            let (Some(group), Some(artifact), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err("invalid package name: a Maven name is \"groupId:artifactId\"".into());
            };
            if group.is_empty() || artifact.is_empty() {
                return Err(
                    "invalid package name: a Maven name needs both a groupId and an artifactId"
                        .into(),
                );
            }
            Ok(name.to_ascii_lowercase())
        }
        Ecosystem::Oci => {
            if name.chars().any(|c| c.is_ascii_uppercase()) {
                return Err("invalid package name: an OCI repository name is lowercase".to_string());
            }
            Ok(name.to_string())
        }
    }
}

/// The version a lookup matches on, or a refusal.
///
/// Trimmed and lowercased, and **nothing else**. It is tempting to
/// canonicalise — PEP 440 would make `1.0` and `1.0.0` one version — but
/// that is a decision about which release a lockfile gets, and getting it
/// wrong silently installs different bytes than were reviewed. npm
/// treats `1.0` and `1.0.0` as distinct, and so do we. What this refuses
/// is only what cannot be stored or addressed safely.
/// The key a version is matched on within its package: what
/// [`normalize_version`] makes of it, except that an OCI tag keeps its
/// case. The distribution spec, docker and every other registry treat
/// `V1` and `v1` as two tags; matching them as one made `docker push
/// app:V1` silently move `app:v1`, and a deployment pinned to `v1` pulled
/// an image nobody tagged `v1`.
pub fn version_key(eco: Ecosystem, version: &str) -> Result<String, String> {
    let lowered = normalize_version(version)?;
    Ok(match eco {
        Ecosystem::Oci => version.trim().to_string(),
        _ => lowered,
    })
}

fn package_ecosystem(db: &ControlDb, package_id: &str) -> Result<Ecosystem, String> {
    let row = db
        .lock()
        .query_opt(
            "SELECT ecosystem FROM packages WHERE id = $1",
            &[&package_id],
        )
        .map_err(|e| format!("package ecosystem: {e}"))?
        .ok_or_else(|| format!("no package {package_id}"))?;
    eco_of(&row.get::<_, String>(0))
}

pub fn normalize_version(version: &str) -> Result<String, String> {
    let v = version.trim();
    if v.is_empty() {
        return Err("invalid version: it is empty".into());
    }
    if v.len() > MAX_VERSION {
        return Err(format!(
            "invalid version: {} bytes, and the limit is {MAX_VERSION}",
            v.len()
        ));
    }
    if v.chars().any(|c| c.is_control()) {
        return Err("invalid version: it contains a control character".into());
    }
    if !v.is_ascii() {
        return Err("invalid version: it contains a non-ASCII character".into());
    }
    if v.contains('/') || v.contains('\\') || v == "." || v == ".." {
        return Err("invalid version: it contains a path separator".into());
    }
    Ok(v.to_ascii_lowercase())
}

/// A tag name, or a refusal. Same argument as a version: a tag reaches a
/// URL path and a database key.
pub fn normalize_tag(tag: &str) -> Result<String, String> {
    let t = tag.trim();
    if t.is_empty() {
        return Err("invalid tag: it is empty".into());
    }
    if t.len() > MAX_TAG {
        return Err(format!(
            "invalid tag: {} bytes, and the limit is {MAX_TAG}",
            t.len()
        ));
    }
    if t.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return Err("invalid tag: it contains a control or non-ASCII character".into());
    }
    if t.contains('/') || t.contains('\\') || t == "." || t == ".." {
        return Err("invalid tag: it contains a path separator".into());
    }
    Ok(t.to_ascii_lowercase())
}

/// A `sha256:<64 hex>` digest reduced to its bare hex, or a refusal.
///
/// Both spellings are accepted because the ecosystems disagree — OCI
/// writes `sha256:…` everywhere, npm writes bare hex in `dist.shasum`
/// and base64 in `dist.integrity` — and both are stored bare, so one
/// blob is one key however it was named on the way in.
pub fn normalize_digest(digest: &str) -> Result<String, String> {
    let d = digest.trim();
    let hex = d.strip_prefix("sha256:").unwrap_or(d);
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid digest: expected sha256 as 64 hex characters".into());
    }
    Ok(hex.to_ascii_lowercase())
}

// --------------------------------------------------------------- rows

#[derive(Debug, Clone, Serialize)]
pub struct Package {
    pub id: String,
    pub org_id: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub normalized_name: String,
    pub origin: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Package {
    /// Whether this row was cached from an upstream registry rather than
    /// published here. The distinction decides who may write it.
    pub fn is_proxied(&self) -> bool {
        self.origin == ORIGIN_PROXIED
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageVersion {
    pub id: String,
    pub package_id: String,
    pub version: String,
    pub normalized_version: String,
    pub yanked: bool,
    pub yank_reason: Option<String>,
    pub license_expr: Option<String>,
    pub license_source: String,
    /// The ecosystem's own version document, as published — npm's
    /// version manifest, a POM, an OCI config. Opaque here: this module
    /// stores and returns it and never reads inside it, because what is
    /// in it is the protocol adapter's business and not the registry's.
    pub metadata: String,
    pub size_bytes: i64,
    /// Who published it, and with which token. `None` for a proxied
    /// artifact, which nobody here published, and for a publisher who
    /// has since been removed — the version outlives them.
    pub published_by_user_id: Option<String>,
    pub published_by_token_id: Option<String>,
    pub published_at: i64,
    /// When the upstream published it, for a proxied artifact. `None`
    /// for one this organization published — see [`Provenance`].
    pub upstream_published_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageFile {
    pub filename: String,
    /// The SHA-256 this artifact is stored under.
    pub digest: String,
    pub size_bytes: i64,
    pub content_type: String,
    /// The other digests the ecosystem's clients check, as a JSON
    /// object — `{"sha1": "…", "sha512": "…"}` for npm. Opaque here:
    /// which ones matter is the protocol adapter's business.
    pub digests: String,
}

const PKG_COLS: &str = "id, org_id, ecosystem, name, normalized_name, origin, \
                        created_at, updated_at";

fn row_to_package(r: &postgres::Row) -> Result<Package, String> {
    Ok(Package {
        id: r.get("id"),
        org_id: r.get("org_id"),
        ecosystem: eco_of(r.get("ecosystem"))?,
        name: r.get("name"),
        normalized_name: r.get("normalized_name"),
        origin: r.get("origin"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    })
}

const VER_COLS: &str = "id, package_id, version, normalized_version, yanked, yank_reason, \
                        license_expr, license_source, metadata, size_bytes, \
                        published_by_user_id, published_by_token_id, published_at, \
                        upstream_published_at";

fn row_to_version(r: &postgres::Row) -> PackageVersion {
    PackageVersion {
        id: r.get("id"),
        package_id: r.get("package_id"),
        version: r.get("version"),
        normalized_version: r.get("normalized_version"),
        yanked: r.get("yanked"),
        yank_reason: r.get("yank_reason"),
        license_expr: r.get("license_expr"),
        license_source: r.get("license_source"),
        metadata: r.get("metadata"),
        size_bytes: r.get("size_bytes"),
        published_by_user_id: r.get("published_by_user_id"),
        published_by_token_id: r.get("published_by_token_id"),
        published_at: r.get("published_at"),
        upstream_published_at: r.get("upstream_published_at"),
    }
}

// ------------------------------------------------------------ packages

/// The package this org knows by that name, if any.
///
/// Always scoped `WHERE org_id = $1`: this is the lookup a request's
/// strings arrive at, and the org scope is what stands between a name
/// and another tenant's row.
pub fn by_name(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    name: &str,
) -> Result<Option<Package>, String> {
    let normalized = normalize_name(eco, name)?;
    db.lock()
        .query_opt(
            &format!(
                "SELECT {PKG_COLS} FROM packages \
                 WHERE org_id = $1 AND ecosystem = $2 AND normalized_name = $3"
            ),
            &[&org_id, &eco.as_str(), &normalized],
        )
        .map_err(|e| format!("package by name: {e}"))?
        .as_ref()
        .map(row_to_package)
        .transpose()
}

pub fn by_id(db: &ControlDb, org_id: &str, id: &str) -> Result<Option<Package>, String> {
    db.lock()
        .query_opt(
            &format!("SELECT {PKG_COLS} FROM packages WHERE org_id = $1 AND id = $2"),
            &[&org_id, &id],
        )
        .map_err(|e| format!("package by id: {e}"))?
        .as_ref()
        .map(row_to_package)
        .transpose()
}

/// Create the package row if this org has never seen the name, and hand
/// back whichever row is now there.
///
/// `origin` is only honoured on creation. A name that exists locally
/// **stays** local however it is asked for again — that is what makes
/// "private always wins" a property of the data rather than of every
/// call site remembering to check, and it is the whole defence against
/// dependency confusion: an upstream `@acme/foo` can never take over the
/// row a local `@acme/foo` already owns.
pub fn ensure(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    name: &str,
    origin: &str,
    now: i64,
) -> Result<Package, String> {
    if origin != ORIGIN_LOCAL && origin != ORIGIN_PROXIED {
        return Err(format!("unknown package origin {origin:?}"));
    }
    let normalized = normalize_name(eco, name)?;
    let id = ulid();
    let inserted = db
        .lock()
        .query_opt(
            &format!(
                "INSERT INTO packages \
                     (id, org_id, ecosystem, name, normalized_name, origin, \
                      created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $7) \
                 ON CONFLICT (org_id, ecosystem, normalized_name) DO NOTHING \
                 RETURNING {PKG_COLS}"
            ),
            &[
                &id,
                &org_id,
                &eco.as_str(),
                &name.trim(),
                &normalized,
                &origin,
                &now,
            ],
        )
        .map_err(|e| format!("ensure package: {e}"))?;
    match inserted.as_ref().map(row_to_package).transpose()? {
        Some(p) => Ok(p),
        // Somebody else created it between our INSERT and now, or it was
        // always there. Either way the existing row is the answer, and
        // its `origin` is not ours to change.
        None => by_name(db, org_id, eco, name)?
            .ok_or_else(|| "ensure package: the row vanished between write and read".to_string()),
    }
}

/// Every package in the org, most recently active first, optionally one
/// ecosystem and optionally only names containing `query`.
///
/// `query` is matched against the normalised name, case-insensitively,
/// with `LIKE`'s own wildcards escaped: somebody searching for `left_pad`
/// means the underscore, not "any character".
pub fn list(
    db: &ControlDb,
    org_id: &str,
    eco: Option<Ecosystem>,
    query: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Package>, String> {
    let limit = limit.clamp(1, 200);
    let offset = offset.max(0);
    let eco = eco.map(|e| e.as_str());
    let pattern = query.map(str::trim).filter(|q| !q.is_empty()).map(|q| {
        let escaped = q
            .to_ascii_lowercase()
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        format!("%{escaped}%")
    });
    let rows = db
        .lock()
        .query(
            &format!(
                "SELECT {PKG_COLS} FROM packages WHERE org_id = $1 \
                 AND ($2::text IS NULL OR ecosystem = $2) \
                 AND ($3::text IS NULL OR normalized_name LIKE $3 ESCAPE '\\') \
                 ORDER BY updated_at DESC, id DESC LIMIT $4 OFFSET $5"
            ),
            &[&org_id, &eco, &pattern, &limit, &offset],
        )
        .map_err(|e| format!("list packages: {e}"))?;
    rows.iter().map(row_to_package).collect()
}

/// How many packages the org holds, per ecosystem, for the overview.
pub fn counts(db: &ControlDb, org_id: &str) -> Result<Vec<(Ecosystem, i64)>, String> {
    let rows = db
        .lock()
        .query(
            "SELECT ecosystem, COUNT(*) AS n FROM packages WHERE org_id = $1 GROUP BY ecosystem",
            &[&org_id],
        )
        .map_err(|e| format!("count packages: {e}"))?;
    Ok(Ecosystem::ALL
        .into_iter()
        .map(|e| {
            let n = rows
                .iter()
                .find(|r| r.get::<_, String>("ecosystem") == e.as_str())
                .map(|r| r.get::<_, i64>("n"))
                .unwrap_or(0);
            (e, n)
        })
        .collect())
}

/// Drop a package and everything under it. The blobs it referenced are
/// left to the collector — deleting them here would race a sibling
/// version that deduped against the same digest.
pub fn remove(db: &ControlDb, org_id: &str, id: &str) -> Result<bool, String> {
    db.lock()
        .execute(
            "DELETE FROM packages WHERE org_id = $1 AND id = $2",
            &[&org_id, &id],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("remove package: {e}"))
}

/// Re-stamp `updated_at`, so the listing orders by activity rather than
/// by when the name was first claimed.
fn touch(db: &ControlDb, package_id: &str, now: i64) -> Result<(), String> {
    db.lock()
        .execute(
            "UPDATE packages SET updated_at = $2 WHERE id = $1",
            &[&package_id, &now],
        )
        .map(|_| ())
        .map_err(|e| format!("touch package: {e}"))
}

// ------------------------------------------------------------ versions

/// What a publish carries besides its bytes.
#[derive(Debug, Clone, Default)]
pub struct Provenance<'a> {
    /// The person who published it.
    pub user_id: Option<&'a str>,
    /// The token they published with, so "which credential shipped
    /// this?" has an answer when a token leaks.
    pub token_id: Option<&'a str>,
    /// For a **proxied** artifact, when the upstream published it.
    ///
    /// Not `published_at`, which is when this registry wrote the row —
    /// for a cached artifact, the moment somebody first installed it.
    /// The cooldown is a claim about how long a release has been in the
    /// world, so measuring it from our own clock would make every
    /// freshly cached version zero days old and refuse it for the next
    /// N days. `None` for anything this organization published itself.
    pub upstream_published_at: Option<i64>,
}

/// What we know about a version's licence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum License {
    /// The ecosystem's own metadata said so.
    Declared(String),
    /// A LICENSE file in the artifact fingerprinted to this.
    Detected(String),
    /// Neither. A disposition the policy has to answer for, not an error.
    Unknown,
}

impl License {
    pub fn expr(&self) -> Option<&str> {
        match self {
            License::Declared(s) | License::Detected(s) => Some(s),
            License::Unknown => None,
        }
    }

    pub fn source(&self) -> &'static str {
        match self {
            License::Declared(_) => "declared",
            License::Detected(_) => "detected",
            License::Unknown => "unknown",
        }
    }
}

/// The refusal [`publish_version`] answers when the version is there.
///
/// Its own error rather than a string the caller matches on, because
/// every protocol adapter has to turn it into that ecosystem's own
/// conflict — npm wants 409 with a particular body, OCI wants 409 with
/// a `BLOB_UPLOAD_INVALID`-shaped error — and a caller that has to
/// string-match to tell "already published" from "the database is down"
/// will eventually get it wrong in the direction of overwriting.
#[derive(Debug)]
pub enum PublishError {
    /// This version already exists. Immutability, not a race.
    Exists,
    Other(String),
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublishError::Exists => write!(f, "that version is already published"),
            PublishError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// Record a new version. Refuses one that already exists.
///
/// The files are written in the same transaction as the version row, so
/// a version is never visible holding none of its bytes — a resolver
/// that met that would cache the empty answer.
#[allow(clippy::too_many_arguments)]
pub fn publish_version(
    db: &ControlDb,
    package_id: &str,
    version: &str,
    license: &License,
    metadata: &str,
    files: &[PackageFile],
    prov: &Provenance<'_>,
    now: i64,
) -> Result<PackageVersion, PublishError> {
    let eco = package_ecosystem(db, package_id).map_err(PublishError::Other)?;
    let normalized = version_key(eco, version).map_err(PublishError::Other)?;
    let metadata = metadata.to_string();
    let size: i64 = files.iter().map(|f| f.size_bytes).sum();
    let id = ulid();
    let version = version.trim().to_string();
    let expr = license.expr().map(str::to_string);
    let source = license.source().to_string();
    let package_id = package_id.to_string();
    let user_id = prov.user_id.map(str::to_string);
    let token_id = prov.token_id.map(str::to_string);
    let upstream_at = prov.upstream_published_at;

    // The closure's error type is the driver's, so "already published"
    // cannot travel out as itself: it comes back as `Ok(None)` and is
    // turned into `Exists` here. Rolling back by returning an error
    // would be wrong anyway — there is nothing to undo, the conflicting
    // row was somebody else's successful publish.
    let out = db
        .lock()
        .transaction(|tx| {
            let Some(row) = tx.query_opt(
                &format!(
                    "INSERT INTO package_versions \
                         (id, package_id, version, normalized_version, yanked, yank_reason, \
                          license_expr, license_source, metadata, size_bytes, \
                          published_by_user_id, published_by_token_id, published_at, \
                          upstream_published_at) \
                     VALUES ($1, $2, $3, $4, FALSE, NULL, $5, $6, $7, $8, $9, $10, $11, $12) \
                     ON CONFLICT (package_id, normalized_version) DO NOTHING \
                     RETURNING {VER_COLS}"
                ),
                &[
                    &id,
                    &package_id,
                    &version,
                    &normalized,
                    &expr,
                    &source,
                    &metadata,
                    &size,
                    &user_id,
                    &token_id,
                    &now,
                    &upstream_at,
                ],
            )?
            else {
                return Ok(None);
            };
            let out = row_to_version(&row);
            for f in files {
                tx.execute(
                    "INSERT INTO package_files \
                         (version_id, filename, digest, size_bytes, content_type, digests) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                    &[
                        &out.id,
                        &f.filename,
                        &f.digest,
                        &f.size_bytes,
                        &f.content_type,
                        &f.digests,
                    ],
                )?;
            }
            tx.execute(
                "UPDATE packages SET updated_at = $2 WHERE id = $1",
                &[&package_id, &now],
            )?;
            Ok(Some(out))
        })
        .map_err(|e| {
            if is_unique_violation(&e) {
                // Two files named the same thing in one version. The
                // version row is gone with the transaction.
                PublishError::Other("two files in that version share a name".to_string())
            } else {
                PublishError::Other(format!("publish version: {e}"))
            }
        })?;

    out.ok_or(PublishError::Exists)
}

/// Add one file to a version that already exists.
///
/// npm and Cargo publish a version in one request; **Maven and PyPI do
/// not**. Maven `PUT`s the jar, the pom, the sources jar and a checksum
/// beside each of them, one request at a time, and twine uploads a
/// wheel and an sdist as two separate calls. So a version accretes
/// files, and immutability has to hold per *file*: a second upload of a
/// filename that is already there is [`PublishError::Exists`], never an
/// overwrite.
///
/// `size_bytes` on the version grows with it, so the number a person
/// reads on the screen is the whole release rather than whichever file
/// happened to arrive first.
pub fn add_file(db: &ControlDb, version_id: &str, f: &PackageFile) -> Result<(), PublishError> {
    add_file_inner(db, version_id, f, false)
}

/// [`add_file`], for an ecosystem that fetches a file by package and
/// filename with no version in the URL — PyPI's `/files/<name>/<file>`
/// — where a filename has to name one file across **every** version, or
/// a second upload of it would change the bytes at the first one's URL.
///
/// The check and the insert happen under a lock on the package's row,
/// so two uploads racing one filename into two versions — two replicas,
/// or one `twine upload` retried — cannot both pass. Not a unique index:
/// other ecosystems legitimately repeat a filename across versions (an
/// OCI layer two tags share is one file named by its digest).
pub fn add_file_unique_in_package(
    db: &ControlDb,
    version_id: &str,
    f: &PackageFile,
) -> Result<(), PublishError> {
    add_file_inner(db, version_id, f, true)
}

fn add_file_inner(
    db: &ControlDb,
    version_id: &str,
    f: &PackageFile,
    package_wide: bool,
) -> Result<(), PublishError> {
    let added = db
        .lock()
        .transaction(|tx| {
            if package_wide {
                // Two statements, not one: under READ COMMITTED a
                // statement reads the snapshot taken when it *started*,
                // so a check in the same statement as the lock reads
                // from before the wait and misses the file the holder
                // just committed. That version let 7 of 8 racers land.
                let pkg: String = tx
                    .query_one(
                        "SELECT p.id FROM packages p \
                         JOIN package_versions v ON v.package_id = p.id \
                         WHERE v.id = $1 FOR UPDATE OF p",
                        &[&version_id],
                    )?
                    .get(0);
                let taken: bool = tx
                    .query_one(
                        "SELECT EXISTS (SELECT 1 FROM package_files f \
                             JOIN package_versions v ON v.id = f.version_id \
                             WHERE v.package_id = $1 AND f.filename = $2)",
                        &[&pkg, &f.filename],
                    )?
                    .get(0);
                if taken {
                    return Ok(0);
                }
            }
            let n = tx.execute(
                "INSERT INTO package_files \
                     (version_id, filename, digest, size_bytes, content_type, digests) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                &[
                    &version_id,
                    &f.filename,
                    &f.digest,
                    &f.size_bytes,
                    &f.content_type,
                    &f.digests,
                ],
            )?;
            if n > 0 {
                tx.execute(
                    "UPDATE package_versions SET size_bytes = size_bytes + $2 WHERE id = $1",
                    &[&version_id, &f.size_bytes],
                )?;
            }
            Ok(n)
        })
        .map_err(|e| PublishError::Other(format!("add file: {e}")))?;
    if added == 0 {
        return Err(PublishError::Exists);
    }
    Ok(())
}

/// Record the licence of a version that was created before it was
/// known.
///
/// Maven deploys a version's files one request at a time and does not
/// promise an order, so the jar can arrive before the POM that declares
/// the licence. The version has to exist to hang the jar on, which
/// means it exists for a moment with no licence — and the admission
/// policy must not see that moment as "declares nothing".
///
/// Only fills a licence in; it never replaces one. A second POM for a
/// version that already has a licence is either the same answer or an
/// attempt to relabel a published artifact, and the second is exactly
/// what immutability exists to refuse.
pub fn set_license(db: &ControlDb, version_id: &str, license: &License) -> Result<bool, String> {
    let expr = license.expr().map(str::to_string);
    let source = license.source().to_string();
    db.lock()
        .execute(
            "UPDATE package_versions SET license_expr = $2, license_source = $3 \
             WHERE id = $1 AND license_expr IS NULL",
            &[&version_id, &expr, &source],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("set licence: {e}"))
}

pub fn version_by_number(
    db: &ControlDb,
    package_id: &str,
    version: &str,
) -> Result<Option<PackageVersion>, String> {
    let normalized = version_key(package_ecosystem(db, package_id)?, version)?;
    Ok(db
        .lock()
        .query_opt(
            &format!(
                "SELECT {VER_COLS} FROM package_versions \
                 WHERE package_id = $1 AND normalized_version = $2"
            ),
            &[&package_id, &normalized],
        )
        .map_err(|e| format!("version by number: {e}"))?
        .as_ref()
        .map(row_to_version))
}

/// Every version of a package, newest first.
pub fn versions(db: &ControlDb, package_id: &str) -> Result<Vec<PackageVersion>, String> {
    Ok(db
        .lock()
        .query(
            &format!(
                "SELECT {VER_COLS} FROM package_versions WHERE package_id = $1 \
                 ORDER BY published_at DESC, id DESC"
            ),
            &[&package_id],
        )
        .map_err(|e| format!("versions: {e}"))?
        .iter()
        .map(row_to_version)
        .collect())
}

/// The files one version is made of, in a stable order.
pub fn files(db: &ControlDb, version_id: &str) -> Result<Vec<PackageFile>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT filename, digest, size_bytes, content_type, digests FROM package_files \
             WHERE version_id = $1 ORDER BY filename",
            &[&version_id],
        )
        .map_err(|e| format!("version files: {e}"))?
        .iter()
        .map(|r| PackageFile {
            filename: r.get("filename"),
            digest: r.get("digest"),
            size_bytes: r.get("size_bytes"),
            content_type: r.get("content_type"),
            digests: r.get("digests"),
        })
        .collect())
}

/// Hide a version from resolution without removing it. `None` un-yanks.
pub fn yank(
    db: &ControlDb,
    version_id: &str,
    reason: Option<&str>,
    yanked: bool,
) -> Result<bool, String> {
    db.lock()
        .execute(
            "UPDATE package_versions SET yanked = $2, yank_reason = $3 WHERE id = $1",
            &[&version_id, &yanked, &reason],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("yank version: {e}"))
}

// ---------------------------------------------------------------- tags

/// Point a tag at a version. Tags move; versions do not.
pub fn set_tag(
    db: &ControlDb,
    package_id: &str,
    tag: &str,
    version_id: &str,
    now: i64,
) -> Result<(), String> {
    let tag = normalize_tag(tag)?;
    db.lock()
        .execute(
            "INSERT INTO package_tags (package_id, tag, version_id, updated_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (package_id, tag) DO UPDATE SET version_id = $3, updated_at = $4",
            &[&package_id, &tag, &version_id, &now],
        )
        .map_err(|e| format!("set tag: {e}"))?;
    touch(db, package_id, now)
}

/// Every tag of a package as `(tag, version)`, using the version string
/// a client reads rather than the row id.
pub fn tags(db: &ControlDb, package_id: &str) -> Result<Vec<(String, String)>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT t.tag, v.version FROM package_tags t \
             JOIN package_versions v ON v.id = t.version_id \
             WHERE t.package_id = $1 ORDER BY t.tag",
            &[&package_id],
        )
        .map_err(|e| format!("tags: {e}"))?
        .iter()
        .map(|r| (r.get("tag"), r.get("version")))
        .collect())
}

/// Remove one version and its file rows.
///
/// Not the same thing as a yank, and the difference is the whole reason
/// both exist. A yank hides a version from resolution and keeps serving
/// it by exact version, so a lockfile that names it keeps building.
/// This *forgets* it — which is right for an OCI tag, where a tag is a
/// moving pointer rather than a release, and wrong for everything else.
///
/// The bytes stay until the collector proves nothing else references
/// them: the row's disappearance is what makes them collectable, and a
/// layer two images share is still referenced by the other one.
pub fn remove_version(db: &ControlDb, version_id: &str) -> Result<bool, String> {
    db.lock()
        .execute("DELETE FROM package_versions WHERE id = $1", &[&version_id])
        .map(|n| n > 0)
        .map_err(|e| format!("remove version: {e}"))
}

pub fn remove_tag(db: &ControlDb, package_id: &str, tag: &str) -> Result<bool, String> {
    let tag = normalize_tag(tag)?;
    db.lock()
        .execute(
            "DELETE FROM package_tags WHERE package_id = $1 AND tag = $2",
            &[&package_id, &tag],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("remove tag: {e}"))
}

// --------------------------------------------------------------- blobs

/// Record that these bytes are in the store under this org's prefix,
/// and that they were used at `now`.
///
/// Idempotent: the same digest twice is one row and one object. But
/// storing a digest that is already here is a **use** of it — a publish
/// deduping against bytes a deleted package or an untagged image left
/// behind — so it moves `touched_at`. It used to be `DO NOTHING`, which
/// left the grace running from the first storage: bytes first stored a
/// week ago were collectable the instant they were stored again, in the
/// gap before the row that names them, and the version went live with
/// nothing behind it.
///
/// `GREATEST`, so a node whose clock is behind cannot move it back.
pub fn note_blob(
    db: &ControlDb,
    org_id: &str,
    digest: &str,
    size_bytes: i64,
    now: i64,
) -> Result<(), String> {
    let digest = normalize_digest(digest)?;
    db.lock()
        .execute(
            "INSERT INTO package_blobs (org_id, digest, size_bytes, created_at, touched_at) \
             VALUES ($1, $2, $3, $4, $4) ON CONFLICT (org_id, digest) DO UPDATE \
             SET touched_at = GREATEST(package_blobs.touched_at, EXCLUDED.touched_at)",
            &[&org_id, &digest, &size_bytes, &now],
        )
        .map(|_| ())
        .map_err(|e| format!("note blob: {e}"))
}

/// Whether this org holds these bytes, and how many there are — without
/// marking them used. What a download asks: handing somebody bytes
/// promises nothing about keeping them.
pub fn blob_exists(db: &ControlDb, org_id: &str, digest: &str) -> Result<Option<i64>, String> {
    let digest = normalize_digest(digest)?;
    Ok(db
        .lock()
        .query_opt(
            "SELECT size_bytes FROM package_blobs WHERE org_id = $1 AND digest = $2",
            &[&org_id, &digest],
        )
        .map_err(|e| format!("blob exists: {e}"))?
        .map(|r| r.get("size_bytes")))
}

/// Whether this org holds these bytes, **and** mark them used at `now`
/// — one statement, one row.
///
/// What every answer asks that lets a client build on bytes it will not
/// send: a `HEAD` answered 200 (after which `docker push` skips the
/// layer), a cross-repository mount, a manifest's check of the blobs it
/// names. Each of those is a promise that the bytes will still be here
/// when the manifest arrives, and the promise is kept by the collector's
/// grace — which is measured from this.
///
/// Without it a layer an untagged image left behind a week ago was
/// collectable at the very moment a push had been told it was here:
/// a sweep between the HEAD and the manifest took it, and the push
/// failed, or was accepted naming a layer that was gone.
pub fn touch_blob(
    db: &ControlDb,
    org_id: &str,
    digest: &str,
    now: i64,
) -> Result<Option<i64>, String> {
    let digest = normalize_digest(digest)?;
    Ok(db
        .lock()
        .query_opt(
            "UPDATE package_blobs SET touched_at = GREATEST(touched_at, $3) \
             WHERE org_id = $1 AND digest = $2 RETURNING size_bytes",
            &[&org_id, &digest, &now],
        )
        .map_err(|e| format!("touch blob: {e}"))?
        .map(|r| r.get("size_bytes")))
}

/// Blobs of this org that no version's file names and nobody has used
/// since `before`.
///
/// The collector's mark phase. The age floor is not politeness: an
/// upload writes its object and *then* its `package_files` row, and a
/// push is told a layer is here and *then* sends the manifest naming
/// it — so a blob used seconds ago and not yet referenced is a publish
/// in flight, not garbage. The age is `touched_at`, the last use, and
/// not `created_at`, the first storage: content addressing means the
/// bytes a publish is relying on may have been stored long ago. The
/// caller asks [`collectable`] again immediately before deleting each
/// key, because this listing is a snapshot.
pub fn unreferenced_blobs(
    db: &ControlDb,
    org_id: &str,
    before: i64,
    limit: i64,
) -> Result<Vec<(String, i64)>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT b.digest, b.size_bytes FROM package_blobs b \
             WHERE b.org_id = $1 AND b.touched_at < $2 \
               AND NOT EXISTS ( \
                   SELECT 1 FROM package_files f \
                   JOIN package_versions v ON v.id = f.version_id \
                   JOIN packages p ON p.id = v.package_id \
                   WHERE p.org_id = $1 AND f.digest = b.digest) \
             ORDER BY b.touched_at LIMIT $3",
            &[&org_id, &before, &limit.clamp(1, 1000)],
        )
        .map_err(|e| format!("unreferenced blobs: {e}"))?
        .iter()
        .map(|r| (r.get("digest"), r.get("size_bytes")))
        .collect())
}

/// Whether the collector may still take this blob: nothing references
/// it **and** nobody has used it since `before`.
///
/// Asked again immediately before the delete, because the listing is a
/// snapshot and both halves can change under it — a publish can name
/// the digest, and a client can be told it is here and start building
/// on it. Re-reading only the reference, as this once did, lost the
/// second: the HEAD a `docker push` made a moment ago counted for
/// nothing.
pub fn collectable(
    db: &ControlDb,
    org_id: &str,
    digest: &str,
    before: i64,
) -> Result<bool, String> {
    let digest = normalize_digest(digest)?;
    db.lock()
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM package_blobs b \
                 WHERE b.org_id = $1 AND b.digest = $2 AND b.touched_at < $3 \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM package_files f \
                       JOIN package_versions v ON v.id = f.version_id \
                       JOIN packages p ON p.id = v.package_id \
                       WHERE p.org_id = $1 AND f.digest = $2))",
            &[&org_id, &digest, &before],
        )
        .map(|r| r.get(0))
        .map_err(|e| format!("collectable: {e}"))
}

pub fn forget_blob(db: &ControlDb, org_id: &str, digest: &str) -> Result<(), String> {
    let digest = normalize_digest(digest)?;
    db.lock()
        .execute(
            "DELETE FROM package_blobs WHERE org_id = $1 AND digest = $2",
            &[&org_id, &digest],
        )
        .map(|_| ())
        .map_err(|e| format!("forget blob: {e}"))
}

// ------------------------------------------------------- large blobs

/// One block of a blob too large to be one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The block's own digest, which is its key in the store.
    pub block: String,
    pub size_bytes: i64,
}

/// Record a blob's blocks, in order.
///
/// Written in one transaction with the `package_blobs` row, so a blob
/// is never visible with a partial block list — a reader that met one
/// would serve a truncated layer and the digest would not tell it
/// apart, because the digest names the whole blob and not the list.
///
/// An upload that finishes on a digest already stored is a use of it,
/// exactly as in [`note_blob`], and moves `touched_at` the same way.
pub fn note_blocked_blob(
    db: &ControlDb,
    org_id: &str,
    digest: &str,
    blocks: &[Block],
    now: i64,
) -> Result<(), String> {
    let digest = normalize_digest(digest)?;
    let total: i64 = blocks.iter().map(|b| b.size_bytes).sum();
    db.lock()
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO package_blobs (org_id, digest, size_bytes, created_at, touched_at) \
                 VALUES ($1, $2, $3, $4, $4) ON CONFLICT (org_id, digest) DO UPDATE \
                 SET touched_at = GREATEST(package_blobs.touched_at, EXCLUDED.touched_at)",
                &[&org_id, &digest, &total, &now],
            )?;
            // Replace rather than append: a second upload of identical
            // bytes cuts them into identical blocks, so this is the
            // same list — and if it somehow is not, the newest write
            // wins whole rather than interleaving with an older one.
            tx.execute(
                "DELETE FROM package_blocks WHERE org_id = $1 AND digest = $2",
                &[&org_id, &digest],
            )?;
            for (i, b) in blocks.iter().enumerate() {
                tx.execute(
                    "INSERT INTO package_blocks (org_id, digest, seq, block, size_bytes) \
                     VALUES ($1, $2, $3, $4, $5)",
                    &[&org_id, &digest, &(i as i32), &b.block, &b.size_bytes],
                )?;
            }
            Ok(())
        })
        .map_err(|e| format!("note blocked blob: {e}"))
}

/// A blob's blocks, in order. Empty for a blob stored as one object,
/// which is every artifact the four tarball ecosystems hold.
pub fn blocks_of(db: &ControlDb, org_id: &str, digest: &str) -> Result<Vec<Block>, String> {
    let digest = normalize_digest(digest)?;
    Ok(db
        .lock()
        .query(
            "SELECT block, size_bytes FROM package_blocks \
             WHERE org_id = $1 AND digest = $2 ORDER BY seq",
            &[&org_id, &digest],
        )
        .map_err(|e| format!("blocks of {digest}: {e}"))?
        .iter()
        .map(|r| Block {
            block: r.get("block"),
            size_bytes: r.get("size_bytes"),
        })
        .collect())
}

/// Forget a blob's block list. Called by the collector **after** the
/// blocks themselves are gone, so a crash between the two leaves
/// orphaned objects the next sweep finds rather than a block list
/// pointing at nothing.
pub fn forget_blocks(db: &ControlDb, org_id: &str, digest: &str) -> Result<(), String> {
    let digest = normalize_digest(digest)?;
    db.lock()
        .execute(
            "DELETE FROM package_blocks WHERE org_id = $1 AND digest = $2",
            &[&org_id, &digest],
        )
        .map(|_| ())
        .map_err(|e| format!("forget blocks: {e}"))
}

/// Whether **any** blob references this block.
///
/// Asked when an abandoned upload session is swept: its blocks are
/// objects with no `package_blobs` row, so `unreferenced_blobs` — which
/// walks that table — will never see them, and without this they would
/// stay in the bucket for ever. Invisible to the meter, which counts
/// blobs, and invisible to the sweep, which counts the same.
///
/// It has to be asked rather than assumed, because a block a dead
/// session wrote may be *exactly* the block a finished blob deduped
/// against: content-addressing means two pushes of the same layer write
/// the same key.
pub fn block_referenced(
    db: &ControlDb,
    org_id: &str,
    block: &str,
    except_upload: &str,
) -> Result<bool, String> {
    db.lock()
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM package_blocks WHERE org_id = $1 AND block = $2) \
                 OR EXISTS (SELECT 1 FROM package_uploads WHERE org_id = $1 AND id <> $3 \
                     AND blocks::jsonb @> jsonb_build_array(jsonb_build_object('block', $2::text)))",
            &[&org_id, &block, &except_upload],
        )
        .map(|r| r.get(0))
        .map_err(|e| format!("block referenced: {e}"))
}

/// Whether any *other* blob — or any upload still in flight — uses this
/// block.
///
/// Blocks dedupe across blobs: two images sharing a base layer share
/// its blocks. Deleting a blob must not take a block a neighbour is
/// still using, so the collector asks this immediately before deleting
/// — the same re-read-before-delete shape the epoch collector uses, and
/// for the same reason.
///
/// An upload session's blocks live only in its own row until it
/// finishes, and this used to look at `package_blocks` alone. So a large
/// layer re-pushed while its old, unreferenced blob was being collected
/// had its freshly written blocks deleted under it — same bytes, same
/// block keys — and the push finished into an image nobody could pull.
pub fn block_referenced_elsewhere(
    db: &ControlDb,
    org_id: &str,
    block: &str,
    except_digest: &str,
) -> Result<bool, String> {
    db.lock()
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM package_blocks \
                 WHERE org_id = $1 AND block = $2 AND digest <> $3) \
                 OR EXISTS (SELECT 1 FROM package_uploads WHERE org_id = $1 \
                     AND blocks::jsonb @> jsonb_build_array(jsonb_build_object('block', $2::text)))",
            &[&org_id, &block, &except_digest],
        )
        .map(|r| r.get(0))
        .map_err(|e| format!("block referenced: {e}"))
}

// ---------------------------------------------------- upload sessions

/// An in-flight upload.
#[derive(Debug, Clone)]
pub struct Upload {
    pub id: String,
    pub org_id: String,
    /// The repository the session was opened against.
    pub package: String,
    pub blocks: Vec<Block>,
    pub size_bytes: i64,
}

/// Open a session against one repository.
pub fn start_upload(
    db: &ControlDb,
    org_id: &str,
    package: &str,
    now: i64,
) -> Result<Upload, String> {
    let id = ulid();
    db.lock()
        .execute(
            "INSERT INTO package_uploads (id, org_id, package, blocks, size_bytes, \
                 started_at, updated_at) VALUES ($1, $2, $3, '[]', 0, $4, $4)",
            &[&id, &org_id, &package, &now],
        )
        .map_err(|e| format!("start upload: {e}"))?;
    Ok(Upload {
        id,
        org_id: org_id.to_string(),
        package: package.to_string(),
        blocks: Vec::new(),
        size_bytes: 0,
    })
}

/// Read a session, scoped to its organization.
///
/// A session id is a bearer capability. Scoping the lookup by `org_id`
/// is what stops one organization finishing another's upload — the same
/// argument as every other `WHERE org_id = $1` in this module, and the
/// one place where forgetting it would let a stranger write bytes into
/// somebody else's key-space.
pub fn upload(db: &ControlDb, org_id: &str, id: &str) -> Result<Option<Upload>, String> {
    Ok(db
        .lock()
        .query_opt(
            "SELECT id, org_id, package, blocks, size_bytes FROM package_uploads \
             WHERE id = $1 AND org_id = $2",
            &[&id, &org_id],
        )
        .map_err(|e| format!("upload {id}: {e}"))?
        .map(|r| {
            let raw: String = r.get("blocks");
            Upload {
                id: r.get("id"),
                org_id: r.get("org_id"),
                package: r.get("package"),
                blocks: serde_json::from_str(&raw).unwrap_or_default(),
                size_bytes: r.get("size_bytes"),
            }
        }))
}

/// Append blocks to a session.
pub fn extend_upload(
    db: &ControlDb,
    org_id: &str,
    id: &str,
    blocks: &[Block],
    now: i64,
) -> Result<i64, String> {
    let mut guard = db.lock();
    let row = guard
        .query_opt(
            "SELECT blocks, size_bytes FROM package_uploads WHERE id = $1 AND org_id = $2 \
             FOR UPDATE",
            &[&id, &org_id],
        )
        .map_err(|e| format!("extend upload: {e}"))?
        .ok_or_else(|| "no such upload".to_string())?;
    let raw: String = row.get("blocks");
    let mut all: Vec<Block> = serde_json::from_str(&raw).unwrap_or_default();
    all.extend_from_slice(blocks);
    let size: i64 = all.iter().map(|b| b.size_bytes).sum();
    let json = serde_json::to_string(&all).map_err(|e| e.to_string())?;
    guard
        .execute(
            "UPDATE package_uploads SET blocks = $3, size_bytes = $4, updated_at = $5 \
             WHERE id = $1 AND org_id = $2",
            &[&id, &org_id, &json, &size, &now],
        )
        .map_err(|e| format!("extend upload: {e}"))?;
    Ok(size)
}

/// Close a session. Its blocks are **not** deleted: a finished upload
/// has just handed them to a blob, and an abandoned one leaves blocks
/// nothing references, which is exactly what the collector sweeps.
pub fn finish_upload(db: &ControlDb, org_id: &str, id: &str) -> Result<bool, String> {
    db.lock()
        .execute(
            "DELETE FROM package_uploads WHERE id = $1 AND org_id = $2",
            &[&id, &org_id],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("finish upload: {e}"))
}

/// Sessions nobody has touched since `before`. A `docker push` that was
/// interrupted leaves one, and a table that only grew would eventually
/// be the largest thing in the database.
pub fn stale_uploads(db: &ControlDb, before: i64, limit: i64) -> Result<Vec<Upload>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT id, org_id, package, blocks, size_bytes FROM package_uploads \
             WHERE updated_at < $1 ORDER BY updated_at LIMIT $2",
            &[&before, &limit.clamp(1, 1000)],
        )
        .map_err(|e| format!("stale uploads: {e}"))?
        .iter()
        .map(|r| {
            let raw: String = r.get("blocks");
            Upload {
                id: r.get("id"),
                org_id: r.get("org_id"),
                package: r.get("package"),
                blocks: serde_json::from_str(&raw).unwrap_or_default(),
                size_bytes: r.get("size_bytes"),
            }
        })
        .collect())
}

/// Bytes this org's packages hold, for the storage meter.
///
/// Summed over **blobs**, not over versions: two versions naming one
/// digest are one object and must be billed once. `package_versions.
/// size_bytes` is the logical size a person reads on the page, and the
/// two numbers legitimately differ.
pub fn bytes_for_org(db: &ControlDb, org_id: &str) -> Result<i64, String> {
    db.lock()
        .query_one(
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM package_blobs WHERE org_id = $1",
            &[&org_id],
        )
        .map(|r| r.get(0))
        .map_err(|e| format!("package bytes for org: {e}"))
}

// -------------------------------------------------------------- policy

/// How an org treats one ecosystem, and what it does with a package
/// whose licence it cannot determine.
#[derive(Debug, Clone, Serialize)]
pub struct EcosystemPolicy {
    pub ecosystem: Ecosystem,
    pub mode: String,
    pub license_unknown: String,
}

impl EcosystemPolicy {
    /// The default for an ecosystem nobody has configured: off.
    ///
    /// Absent means off rather than on, so a registry nobody switched on
    /// answers 404 everywhere and enabling one is a deliberate act with
    /// an audit row behind it.
    pub fn off(ecosystem: Ecosystem) -> EcosystemPolicy {
        EcosystemPolicy {
            ecosystem,
            mode: MODE_OFF.into(),
            license_unknown: "block".into(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.mode != MODE_OFF
    }

    pub fn proxies(&self) -> bool {
        self.mode == MODE_PROXY
    }
}

pub fn ecosystem_policy(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
) -> Result<EcosystemPolicy, String> {
    Ok(db
        .lock()
        .query_opt(
            "SELECT mode, license_unknown FROM org_ecosystems \
             WHERE org_id = $1 AND ecosystem = $2",
            &[&org_id, &eco.as_str()],
        )
        .map_err(|e| format!("ecosystem policy: {e}"))?
        .map(|r| EcosystemPolicy {
            ecosystem: eco,
            mode: r.get("mode"),
            license_unknown: r.get("license_unknown"),
        })
        .unwrap_or_else(|| EcosystemPolicy::off(eco)))
}

/// Every ecosystem's policy, in [`Ecosystem::ALL`] order, with the
/// unconfigured ones filled in as off — so the settings page renders
/// five rows on an org that has never touched it.
pub fn ecosystem_policies(db: &ControlDb, org_id: &str) -> Result<Vec<EcosystemPolicy>, String> {
    let rows = db
        .lock()
        .query(
            "SELECT ecosystem, mode, license_unknown FROM org_ecosystems WHERE org_id = $1",
            &[&org_id],
        )
        .map_err(|e| format!("ecosystem policies: {e}"))?;
    let mut out = Vec::with_capacity(Ecosystem::ALL.len());
    for eco in Ecosystem::ALL {
        let found = rows
            .iter()
            .find(|r| r.get::<_, String>("ecosystem") == eco.as_str())
            .map(|r| EcosystemPolicy {
                ecosystem: eco,
                mode: r.get("mode"),
                license_unknown: r.get("license_unknown"),
            });
        out.push(found.unwrap_or_else(|| EcosystemPolicy::off(eco)));
    }
    Ok(out)
}

pub fn set_ecosystem_policy(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    mode: &str,
    license_unknown: &str,
    now: i64,
) -> Result<(), String> {
    if !matches!(mode, MODE_OFF | MODE_PRIVATE | MODE_PROXY) {
        return Err(format!("unknown registry mode {mode:?}"));
    }
    if !matches!(license_unknown, "block" | "allow") {
        return Err(format!(
            "unknown disposition for an unrecognised licence: {license_unknown:?}"
        ));
    }
    db.lock()
        .execute(
            "INSERT INTO org_ecosystems (org_id, ecosystem, mode, license_unknown, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (org_id, ecosystem) DO UPDATE SET \
                 mode = $3, license_unknown = $4, updated_at = $5",
            &[&org_id, &eco.as_str(), &mode, &license_unknown, &now],
        )
        .map(|_| ())
        .map_err(|e| format!("set ecosystem policy: {e}"))
}

// -------------------------------------------------- admission policy

/// An organization's admission policy, as the gate reads it.
#[derive(Debug, Clone, Serialize)]
pub struct AdmissionPolicy {
    /// `audit` records what it would have refused and serves anyway;
    /// `block` refuses. Audit is the default and is the reason the
    /// feature is adoptable: a policy that blocks from day one meets a
    /// deadline in week one and gets switched off.
    pub mode: String,
    /// Upstream releases younger than this are held. `0` disables.
    pub cooldown_days: i64,
    /// `allow_list` admits only what is listed; `deny_list` admits
    /// everything except.
    pub license_mode: String,
    /// Case-folded SPDX id → `allow` | `deny`.
    pub license_rules: Vec<(String, String)>,
    /// Normalised name prefixes this organization has claimed. Never
    /// proxied, published or not.
    pub reserved: Vec<String>,
}

impl AdmissionPolicy {
    pub fn blocking(&self) -> bool {
        self.mode == "block"
    }
}

/// The whole policy for one ecosystem, in one read.
///
/// One function rather than four because the gate needs all of it on
/// every proxied fetch, and four round trips per dependency is the
/// difference between a resolve that feels instant and one that does
/// not.
pub fn admission_policy(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
) -> Result<AdmissionPolicy, String> {
    let mut guard = db.lock();
    let org = guard
        .query_one(
            "SELECT registry_policy_mode, registry_cooldown_days, license_mode \
             FROM orgs WHERE id = $1",
            &[&org_id],
        )
        .map_err(|e| format!("admission policy: {e}"))?;
    let rules = guard
        .query(
            "SELECT spdx_id, disposition FROM org_license_rules WHERE org_id = $1",
            &[&org_id],
        )
        .map_err(|e| format!("licence rules: {e}"))?
        .iter()
        .map(|r| (r.get("spdx_id"), r.get("disposition")))
        .collect();
    let reserved = guard
        .query(
            "SELECT pattern FROM org_reserved_namespaces \
             WHERE org_id = $1 AND ecosystem = $2 ORDER BY pattern",
            &[&org_id, &eco.as_str()],
        )
        .map_err(|e| format!("reserved namespaces: {e}"))?
        .iter()
        .map(|r| r.get("pattern"))
        .collect();
    Ok(AdmissionPolicy {
        mode: org.get("registry_policy_mode"),
        cooldown_days: i64::from(org.get::<_, i32>("registry_cooldown_days")),
        license_mode: org.get("license_mode"),
        license_rules: rules,
        reserved,
    })
}

pub fn set_admission_policy(
    db: &ControlDb,
    org_id: &str,
    mode: &str,
    cooldown_days: i64,
    license_mode: &str,
) -> Result<(), String> {
    if !matches!(mode, "audit" | "block") {
        return Err(format!("unknown policy mode {mode:?} (audit | block)"));
    }
    if !matches!(license_mode, "allow_list" | "deny_list") {
        return Err(format!(
            "unknown licence mode {license_mode:?} (allow_list | deny_list)"
        ));
    }
    if !(0..=3650).contains(&cooldown_days) {
        return Err("a cooldown is between 0 and 3650 days".to_string());
    }
    db.lock()
        .execute(
            "UPDATE orgs SET registry_policy_mode = $2, registry_cooldown_days = $3, \
                 license_mode = $4 WHERE id = $1",
            &[&org_id, &mode, &(cooldown_days as i32), &license_mode],
        )
        .map(|_| ())
        .map_err(|e| format!("set admission policy: {e}"))
}

/// Add or replace one licence rule. `None` removes it.
pub fn set_license_rule(
    db: &ControlDb,
    org_id: &str,
    spdx_id: &str,
    disposition: Option<&str>,
    now: i64,
) -> Result<(), String> {
    // Case-folded, because SPDX ids compare case-insensitively and a
    // rule that catches one spelling catches nothing.
    let id = spdx_id.trim().to_ascii_lowercase();
    if id.is_empty() {
        return Err("a licence rule needs an SPDX identifier".into());
    }
    match disposition {
        None => db
            .lock()
            .execute(
                "DELETE FROM org_license_rules WHERE org_id = $1 AND spdx_id = $2",
                &[&org_id, &id],
            )
            .map(|_| ())
            .map_err(|e| format!("remove licence rule: {e}")),
        Some(d) if d == "allow" || d == "deny" => db
            .lock()
            .execute(
                "INSERT INTO org_license_rules (org_id, spdx_id, disposition, updated_at) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (org_id, spdx_id) DO UPDATE SET disposition = $3, updated_at = $4",
                &[&org_id, &id, &d, &now],
            )
            .map(|_| ())
            .map_err(|e| format!("set licence rule: {e}")),
        Some(d) => Err(format!("unknown disposition {d:?} (allow | deny)")),
    }
}

pub fn reserve_namespace(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    pattern: &str,
    now: i64,
) -> Result<(), String> {
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty() {
        return Err("a reserved namespace needs a prefix".into());
    }
    if p.len() > MAX_NAME {
        return Err(format!("that prefix is longer than {MAX_NAME} bytes"));
    }
    db.lock()
        .execute(
            "INSERT INTO org_reserved_namespaces (org_id, ecosystem, pattern, created_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            &[&org_id, &eco.as_str(), &p, &now],
        )
        .map(|_| ())
        .map_err(|e| format!("reserve namespace: {e}"))
}

pub fn release_namespace(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    pattern: &str,
) -> Result<bool, String> {
    let p = pattern.trim().to_ascii_lowercase();
    db.lock()
        .execute(
            "DELETE FROM org_reserved_namespaces \
             WHERE org_id = $1 AND ecosystem = $2 AND pattern = $3",
            &[&org_id, &eco.as_str(), &p],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("release namespace: {e}"))
}

/// One finding, as the screen shows it.
#[derive(Debug, Clone, Serialize)]
pub struct PolicyEvent {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub disposition: String,
    pub rule: String,
    pub reason: String,
    pub hits: i64,
    pub first_at: i64,
    pub last_at: i64,
}

/// Record that the policy decided against something.
///
/// Deduplicated to one row per `(org, ecosystem, name, version)` with a
/// hit count. A CI run resolving eight hundred dependencies must not
/// write eight hundred rows, and "how many times did this come up" is
/// the number that decides whether a rule earns its keep.
#[allow(clippy::too_many_arguments)]
pub fn record_policy_event(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    name: &str,
    version: &str,
    disposition: &str,
    rule: &str,
    reason: &str,
    now: i64,
) -> Result<(), String> {
    db.lock()
        .execute(
            "INSERT INTO package_policy_events \
                 (org_id, ecosystem, name, version, disposition, rule, reason, \
                  hits, first_at, last_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $8) \
             ON CONFLICT (org_id, ecosystem, name, version) DO UPDATE SET \
                 hits = package_policy_events.hits + 1, \
                 disposition = $5, rule = $6, reason = $7, last_at = $8",
            &[
                &org_id,
                &eco.as_str(),
                &name,
                &version,
                &disposition,
                &rule,
                &reason,
                &now,
            ],
        )
        .map(|_| ())
        .map_err(|e| format!("record policy event: {e}"))
}

/// The findings, most recent first.
pub fn policy_events(db: &ControlDb, org_id: &str, limit: i64) -> Result<Vec<PolicyEvent>, String> {
    Ok(db
        .lock()
        .query(
            "SELECT ecosystem, name, version, disposition, rule, reason, hits, \
                    first_at, last_at \
             FROM package_policy_events WHERE org_id = $1 \
             ORDER BY last_at DESC LIMIT $2",
            &[&org_id, &limit.clamp(1, 500)],
        )
        .map_err(|e| format!("policy events: {e}"))?
        .iter()
        .map(|r| PolicyEvent {
            ecosystem: r.get("ecosystem"),
            name: r.get("name"),
            version: r.get("version"),
            disposition: r.get("disposition"),
            rule: r.get("rule"),
            reason: r.get("reason"),
            hits: r.get("hits"),
            first_at: r.get("first_at"),
            last_at: r.get("last_at"),
        })
        .collect())
}

/// Forget one finding — what "allow this" does after the rule that
/// caused it has been changed.
pub fn forget_policy_event(
    db: &ControlDb,
    org_id: &str,
    eco: Ecosystem,
    name: &str,
    version: &str,
) -> Result<bool, String> {
    db.lock()
        .execute(
            "DELETE FROM package_policy_events \
             WHERE org_id = $1 AND ecosystem = $2 AND name = $3 AND version = $4",
            &[&org_id, &eco.as_str(), &name, &version],
        )
        .map(|n| n > 0)
        .map_err(|e| format!("forget policy event: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;

    fn world(hint: &str) -> (ControlDb, String) {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url(hint)).unwrap();
        let org = registry::create_org(&db, "acme").unwrap();
        (db, org.id)
    }

    fn file(name: &str, size: i64) -> PackageFile {
        PackageFile {
            filename: name.into(),
            digest: format!("{:0>64}", name.len()),
            size_bytes: size,
            content_type: "application/octet-stream".into(),
            digests: r#"{"sha1":"abc"}"#.into(),
        }
    }

    /// Where a filename is fetched without a version, it names one file
    /// across the whole package: a second version cannot carry it, and
    /// two uploads racing it into two versions from two connections —
    /// two replicas — land exactly one.
    #[test]
    fn a_filename_can_be_unique_across_a_package_even_under_a_race() {
        let (db, org) = world("pkg_file_race");
        let p = ensure(&db, &org, Ecosystem::Pypi, "widget", ORIGIN_LOCAL, 1).unwrap();
        let version = |v: &str| {
            publish_version(
                &db,
                &p.id,
                v,
                &License::Unknown,
                "{}",
                &[],
                &Provenance::default(),
                10,
            )
            .unwrap()
            .id
        };
        let one = version("1.0.0");
        let two = version("2.0.0");
        let wheel = file("widget-1.0.0-py3-none-any.whl", 10);
        add_file_unique_in_package(&db, &one, &wheel).unwrap();
        assert!(matches!(
            add_file_unique_in_package(&db, &two, &wheel),
            Err(PublishError::Exists)
        ));
        // The plain form is per version, as other ecosystems need.
        add_file(&db, &two, &file("layer", 1)).unwrap();
        add_file(&db, &one, &file("layer", 1)).unwrap();

        let url = skein_testkit::pg::test_db_url("pkg_file_race_conns");
        let setup = ControlDb::open(&url).unwrap();
        let org = registry::create_org(&setup, "acme").unwrap().id;
        let p = ensure(&setup, &org, Ecosystem::Pypi, "racer", ORIGIN_LOCAL, 1).unwrap();
        let mut versions = Vec::new();
        for i in 0..8 {
            versions.push(
                publish_version(
                    &setup,
                    &p.id,
                    &format!("{i}.0.0"),
                    &License::Unknown,
                    "{}",
                    &[],
                    &Provenance::default(),
                    10,
                )
                .unwrap()
                .id,
            );
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(versions.len()));
        let handles: Vec<_> = versions
            .into_iter()
            .map(|v| {
                let (url, barrier) = (url.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let conn = ControlDb::open(&url).unwrap();
                    barrier.wait();
                    add_file_unique_in_package(&conn, &v, &file("racer-0.0.0.tar.gz", 5)).is_ok()
                })
            })
            .collect();
        let landed = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count();
        assert_eq!(landed, 1, "one filename, one file");
    }

    /// An OCI tag is matched exactly; every other ecosystem's versions
    /// case-insensitively, as before — `1.0.0-Beta` after `1.0.0-beta` is
    /// still the same npm version, refused as a republish.
    #[test]
    fn an_oci_tag_keeps_its_case_and_other_versions_do_not() {
        assert_eq!(version_key(Ecosystem::Oci, " V1 ").unwrap(), "V1");
        assert_eq!(
            version_key(Ecosystem::Npm, "1.0.0-Beta").unwrap(),
            "1.0.0-beta"
        );
        assert!(
            version_key(Ecosystem::Oci, "a/b").is_err(),
            "still validated"
        );

        let (db, org) = world("pkg_tag_case");
        let publish = |pkg: &str, v: &str| {
            publish_version(
                &db,
                pkg,
                v,
                &License::Unknown,
                "{}",
                &[file(&format!("{v}.json"), 1)],
                &Provenance::default(),
                10,
            )
        };
        let image = ensure(&db, &org, Ecosystem::Oci, "acme/app", ORIGIN_LOCAL, 1).unwrap();
        publish(&image.id, "v1").unwrap();
        publish(&image.id, "V1").expect("V1 is another tag");
        assert_eq!(
            version_by_number(&db, &image.id, "V1")
                .unwrap()
                .unwrap()
                .version,
            "V1"
        );
        assert_eq!(
            version_by_number(&db, &image.id, "v1")
                .unwrap()
                .unwrap()
                .version,
            "v1"
        );
        assert!(version_by_number(&db, &image.id, "V2").unwrap().is_none());

        let widget = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        publish(&widget.id, "1.0.0-beta").unwrap();
        assert!(matches!(
            publish(&widget.id, "1.0.0-Beta"),
            Err(PublishError::Exists)
        ));
        assert!(version_by_number(&db, &widget.id, "1.0.0-BETA")
            .unwrap()
            .is_some());

        // Migration 0003 re-keys a tag stored lowercased by an older
        // build — which could hold only one of `latest` and `Latest` —
        // and leaves every other ecosystem's rows alone.
        let old = ensure(&db, &org, Ecosystem::Oci, "acme/old", ORIGIN_LOCAL, 1).unwrap();
        publish(&old.id, "Latest").unwrap();
        db.lock()
            .execute(
                "UPDATE package_versions SET normalized_version = lower(version) \
                 WHERE package_id = $1",
                &[&old.id],
            )
            .unwrap();
        assert!(
            version_by_number(&db, &old.id, "Latest").unwrap().is_none(),
            "simulated old row"
        );
        db.lock().execute(crate::db::MIGRATIONS[2], &[]).unwrap();
        assert_eq!(
            version_by_number(&db, &old.id, "Latest")
                .unwrap()
                .unwrap()
                .version,
            "Latest"
        );
        assert!(version_by_number(&db, &old.id, "latest").unwrap().is_none());
        assert_eq!(
            version_by_number(&db, &widget.id, "1.0.0-Beta")
                .unwrap()
                .unwrap()
                .version,
            "1.0.0-beta",
            "an npm row was re-keyed"
        );
    }

    #[test]
    fn ecosystem_names_round_trip_and_nothing_else_parses() {
        for e in Ecosystem::ALL {
            assert_eq!(Ecosystem::parse(e.as_str()), Some(e));
            assert!(!e.label().is_empty());
        }
        assert_eq!(Ecosystem::parse("nuget"), None);
        assert_eq!(Ecosystem::parse("NPM"), None, "the stored name is exact");
        assert!(eco_of("rubygems").is_err());
    }

    /// The security floor, checked before any ecosystem's own grammar.
    ///
    /// Every one of these is a name that could reach an object-store key
    /// or a URL path, and the rule is that it is **refused**, never
    /// sanitised: stripping `..` maps two different requests onto one
    /// stored object, and that is the shape of the bug.
    #[test]
    fn a_dangerous_name_is_refused_in_every_ecosystem() {
        let hostile = [
            "../etc/passwd",
            "a/../../b",
            "..",
            ".",
            "/leading",
            "trailing/",
            "double//slash",
            "back\\slash",
            "nul\0byte",
            "new\nline",
            "tab\there",
            "café",
            "",
            "   ",
        ];
        for eco in Ecosystem::ALL {
            for name in hostile {
                assert!(
                    normalize_name(eco, name).is_err(),
                    "{eco:?} admitted {name:?}"
                );
            }
            let long = "a".repeat(MAX_NAME + 1);
            assert!(
                normalize_name(eco, &long).is_err(),
                "{eco:?} admitted {} bytes",
                long.len()
            );
        }
    }

    #[test]
    fn npm_lowercases_and_admits_exactly_one_scope_slash() {
        assert_eq!(
            normalize_name(Ecosystem::Npm, "Express").unwrap(),
            "express"
        );
        assert_eq!(
            normalize_name(Ecosystem::Npm, "@Acme/Widget").unwrap(),
            "@acme/widget"
        );
        assert_eq!(
            normalize_name(Ecosystem::Npm, "  lodash  ").unwrap(),
            "lodash",
            "trimmed"
        );
        for bad in ["@acme", "a/b", "@a/b/c", "pkg@1.0.0"] {
            assert!(
                normalize_name(Ecosystem::Npm, bad).is_err(),
                "admitted {bad:?}"
            );
        }
    }

    /// PEP 503: `.`, `_` and `-` are one separator, and case does not
    /// matter. Four spellings of one distribution must be one row, or
    /// the second row answers for a name the first one owns.
    #[test]
    fn pypi_folds_every_separator_spelling_together() {
        let one = normalize_name(Ecosystem::Pypi, "Zope.Interface").unwrap();
        for spelling in [
            "zope-interface",
            "zope_interface",
            "ZOPE.INTERFACE",
            "zope--interface",
            "zope._-interface",
        ] {
            assert_eq!(
                normalize_name(Ecosystem::Pypi, spelling).unwrap(),
                one,
                "{spelling:?} is a different row from Zope.Interface"
            );
        }
        assert_eq!(one, "zope-interface");
        assert!(normalize_name(Ecosystem::Pypi, "a/b").is_err());
        assert!(normalize_name(Ecosystem::Pypi, "___").is_err());
    }

    #[test]
    fn cargo_folds_dash_and_underscore_but_refuses_a_dot() {
        assert_eq!(
            normalize_name(Ecosystem::Cargo, "serde_json").unwrap(),
            "serde-json"
        );
        assert_eq!(
            normalize_name(Ecosystem::Cargo, "Serde-Json").unwrap(),
            "serde-json"
        );
        assert!(normalize_name(Ecosystem::Cargo, "serde.json").is_err());
        assert!(normalize_name(Ecosystem::Cargo, "serde/json").is_err());
        assert!(normalize_name(Ecosystem::Cargo, "___").is_err());
    }

    #[test]
    fn maven_needs_a_group_and_an_artifact() {
        assert_eq!(
            normalize_name(Ecosystem::Maven, "com.Acme:Widget").unwrap(),
            "com.acme:widget"
        );
        for bad in ["nogroup", ":artifact", "group:", "a:b:c", "a/b"] {
            assert!(
                normalize_name(Ecosystem::Maven, bad).is_err(),
                "admitted {bad:?}"
            );
        }
    }

    /// The distribution spec requires a lowercase repository name. We
    /// refuse rather than lowercase, because `docker push` would then
    /// report success for a name the registry stored under something
    /// else and the next `docker pull` of what the user typed would
    /// 404 — a silent rename is worse than a refusal at the door.
    #[test]
    fn oci_refuses_uppercase_rather_than_folding_it() {
        assert_eq!(
            normalize_name(Ecosystem::Oci, "acme/service").unwrap(),
            "acme/service"
        );
        assert!(normalize_name(Ecosystem::Oci, "Acme/Service").is_err());
    }

    /// Deliberately *not* PEP 440 canonicalisation. `1.0` and `1.0.0`
    /// stay different versions, because collapsing them decides which
    /// release a lockfile resolves to and getting that wrong installs
    /// bytes nobody reviewed.
    #[test]
    fn versions_are_lowercased_and_never_canonicalised() {
        assert_eq!(normalize_version("1.0.0-Beta.1").unwrap(), "1.0.0-beta.1");
        assert_ne!(
            normalize_version("1.0").unwrap(),
            normalize_version("1.0.0").unwrap()
        );
        for bad in [
            "",
            "  ",
            "1.0/2",
            "..",
            "a\0b",
            "1.0.0-caf\u{00e9}",
            &"9".repeat(MAX_VERSION + 1),
        ] {
            assert!(normalize_version(bad).is_err(), "admitted {bad:?}");
        }
    }

    /// Surrounding whitespace is trimmed, an *interior* control
    /// character is refused.
    ///
    /// The two are not the same mistake. A trailing newline is what you
    /// get from `version=$(cat VERSION)` and refusing it would be
    /// pedantry about the client's shell; a newline in the middle is
    /// either a header-splitting attempt or a corrupt manifest, and
    /// trimming cannot make it safe. The same split holds for names.
    #[test]
    fn a_version_is_trimmed_at_the_edges_and_refused_in_the_middle() {
        assert_eq!(normalize_version("1.0.0\n").unwrap(), "1.0.0");
        assert_eq!(normalize_version("  1.0.0\t").unwrap(), "1.0.0");
        for interior in ["1.\n0", "1.\r0", "1.\t0", "1.\u{0}0"] {
            assert!(
                normalize_version(interior).is_err(),
                "admitted an interior control character in {interior:?}"
            );
        }
        assert_eq!(
            normalize_name(Ecosystem::Npm, "lodash\n").unwrap(),
            "lodash"
        );
        assert!(normalize_name(Ecosystem::Npm, "lo\ndash").is_err());
    }

    #[test]
    fn tags_refuse_a_path_separator() {
        assert_eq!(normalize_tag("Latest").unwrap(), "latest");
        for bad in [
            "",
            "a/b",
            "..",
            "x\\y",
            "latest\u{00e9}",
            "la\ttest",
            &"t".repeat(MAX_TAG + 1),
        ] {
            assert!(normalize_tag(bad).is_err(), "admitted {bad:?}");
        }
    }

    /// Both spellings in, one spelling stored — so a blob named
    /// `sha256:…` by a container client and bare hex by an npm client
    /// is one key, not two objects with the same bytes.
    #[test]
    fn a_digest_is_stored_bare_however_it_arrived() {
        let hex = "a".repeat(64);
        assert_eq!(normalize_digest(&hex).unwrap(), hex);
        assert_eq!(
            normalize_digest(&format!("sha256:{}", hex.to_uppercase())).unwrap(),
            hex
        );
        for bad in [
            "",
            "sha256:",
            "sha512:abc",
            &"a".repeat(63),
            &"g".repeat(64),
        ] {
            assert!(normalize_digest(bad).is_err(), "admitted {bad:?}");
        }
    }

    #[test]
    fn a_license_reports_its_own_source() {
        assert_eq!(License::Declared("MIT".into()).expr(), Some("MIT"));
        assert_eq!(License::Declared("MIT".into()).source(), "declared");
        assert_eq!(License::Detected("MIT".into()).source(), "detected");
        assert_eq!(License::Unknown.expr(), None);
        assert_eq!(License::Unknown.source(), "unknown");
    }

    #[test]
    fn an_unconfigured_ecosystem_is_off_and_proxies_nothing() {
        let p = EcosystemPolicy::off(Ecosystem::Npm);
        assert!(!p.enabled());
        assert!(!p.proxies());
        assert_eq!(p.license_unknown, "block");
    }

    #[test]
    fn a_proxied_package_says_so() {
        let mut p = Package {
            id: "p".into(),
            org_id: "o".into(),
            ecosystem: Ecosystem::Npm,
            name: "x".into(),
            normalized_name: "x".into(),
            origin: ORIGIN_LOCAL.into(),
            created_at: 0,
            updated_at: 0,
        };
        assert!(!p.is_proxied());
        p.origin = ORIGIN_PROXIED.into();
        assert!(p.is_proxied());
    }

    #[test]
    fn publish_error_says_which_it_was() {
        assert_eq!(
            PublishError::Exists.to_string(),
            "that version is already published"
        );
        assert_eq!(PublishError::Other("db down".into()).to_string(), "db down");
    }

    // ---------------------------------------------------- against Postgres

    /// Ensure is idempotent, and the normalised name is what decides
    /// identity: four spellings of one PyPI distribution are one row.
    #[test]
    fn one_distribution_under_four_spellings_is_one_package() {
        let (db, org) = world("pkg-ensure");
        let first = ensure(
            &db,
            &org,
            Ecosystem::Pypi,
            "Zope.Interface",
            ORIGIN_LOCAL,
            1,
        )
        .unwrap();
        for spelling in ["zope-interface", "zope_interface", "ZOPE.INTERFACE"] {
            let again = ensure(&db, &org, Ecosystem::Pypi, spelling, ORIGIN_LOCAL, 2).unwrap();
            assert_eq!(again.id, first.id, "{spelling:?} made a second row");
        }
        assert_eq!(
            first.name, "Zope.Interface",
            "the display name is as published"
        );
        assert_eq!(first.normalized_name, "zope-interface");
        assert_eq!(
            list(&db, &org, Some(Ecosystem::Pypi), None, 50, 0)
                .unwrap()
                .len(),
            1
        );
    }

    /// The same name in two ecosystems is two packages — `lodash` the
    /// npm package and `lodash` the crate are unrelated things.
    #[test]
    fn a_name_is_scoped_to_its_ecosystem() {
        let (db, org) = world("pkg-eco-scope");
        let a = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let b = ensure(&db, &org, Ecosystem::Cargo, "widget", ORIGIN_LOCAL, 1).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(list(&db, &org, None, None, 50, 0).unwrap().len(), 2);
        assert_eq!(
            list(&db, &org, Some(Ecosystem::Npm), None, 50, 0)
                .unwrap()
                .len(),
            1
        );
    }

    /// Every lookup is scoped to the organization. An install serves
    /// one, but the scope is what stands between a request's strings and
    /// a row, and it is what keeps a second namespace possible later
    /// without a rewrite — so it is pinned rather than assumed.
    #[test]
    fn a_package_is_only_found_under_its_own_organization() {
        let (db, acme) = world("pkg-isolation");
        let mine = ensure(&db, &acme, Ecosystem::Npm, "@acme/secret", ORIGIN_LOCAL, 1).unwrap();
        let elsewhere = crate::ids::ulid();
        assert!(by_name(&db, &elsewhere, Ecosystem::Npm, "@acme/secret")
            .unwrap()
            .is_none());
        assert!(by_id(&db, &elsewhere, &mine.id).unwrap().is_none());
        assert!(list(&db, &elsewhere, None, None, 50, 0).unwrap().is_empty());
        assert!(by_id(&db, &acme, &mine.id).unwrap().is_some());
    }

    /// Dependency confusion, refused by the data rather than by every
    /// call site remembering to check.
    ///
    /// A name this organization publishes locally stays local however
    /// the proxy asks for it again. Without this, an upstream package of
    /// the same name could take over the row — and the next resolve of
    /// `@acme/widget` would get somebody else's bytes.
    #[test]
    fn a_proxied_fetch_never_takes_over_a_locally_published_name() {
        let (db, org) = world("pkg-confusion");
        let local = ensure(&db, &org, Ecosystem::Npm, "@acme/widget", ORIGIN_LOCAL, 1).unwrap();
        assert!(!local.is_proxied());

        let asked_again =
            ensure(&db, &org, Ecosystem::Npm, "@acme/widget", ORIGIN_PROXIED, 2).unwrap();
        assert_eq!(asked_again.id, local.id);
        assert_eq!(
            asked_again.origin, ORIGIN_LOCAL,
            "an upstream fetch relabelled a package this org publishes"
        );
    }

    #[test]
    fn an_unknown_origin_is_refused() {
        let (db, org) = world("pkg-origin");
        assert!(ensure(&db, &org, Ecosystem::Npm, "w", "vendored", 1).is_err());
    }

    /// A version's bytes never change. The second publish of a version
    /// is refused as `Exists`, distinguishably from a database failure,
    /// because each protocol has to answer its own conflict for it.
    #[test]
    fn a_published_version_cannot_be_republished() {
        let (db, org) = world("pkg-immutable");
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let files = vec![file("widget-1.0.0.tgz", 120)];

        let v = publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Declared("MIT".into()),
            "{}",
            &files,
            &Provenance::default(),
            10,
        )
        .unwrap();
        assert_eq!(v.size_bytes, 120);
        assert!(!v.yanked);

        let again = publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Declared("Apache-2.0".into()),
            "{}",
            &[file("widget-1.0.0.tgz", 999)],
            &Provenance::default(),
            11,
        );
        assert!(matches!(again, Err(PublishError::Exists)), "{again:?}");

        // …and nothing about the first one moved.
        let stored = version_by_number(&db, &p.id, "1.0.0").unwrap().unwrap();
        assert_eq!(stored.size_bytes, 120);
        assert_eq!(stored.license_expr.as_deref(), Some("MIT"));
        assert_eq!(versions(&db, &p.id).unwrap().len(), 1);
    }

    /// The version row and its files land together or not at all: a
    /// resolver that met a version holding no files would cache the
    /// empty answer.
    #[test]
    fn a_version_and_its_files_are_one_write() {
        let (db, org) = world("pkg-atomic");
        let p = ensure(
            &db,
            &org,
            Ecosystem::Maven,
            "com.acme:widget",
            ORIGIN_LOCAL,
            1,
        )
        .unwrap();
        let v = publish_version(
            &db,
            &p.id,
            "2.1.0",
            &License::Unknown,
            "{}",
            &[file("widget.jar", 400), file("widget.pom", 20)],
            &Provenance::default(),
            10,
        )
        .unwrap();
        assert_eq!(v.size_bytes, 420, "the version's size is its files' sum");
        let fs = files(&db, &v.id).unwrap();
        assert_eq!(fs.len(), 2);
        assert_eq!(fs[0].filename, "widget.jar", "ordered by name");

        // Two files of one name is refused, and takes the version with it.
        let bad = publish_version(
            &db,
            &p.id,
            "2.2.0",
            &License::Unknown,
            "{}",
            &[file("dup.jar", 1), file("dup.jar", 2)],
            &Provenance::default(),
            11,
        );
        assert!(bad.is_err());
        assert!(
            version_by_number(&db, &p.id, "2.2.0").unwrap().is_none(),
            "the refused version left a row behind"
        );
    }

    /// The published document round-trips verbatim.
    ///
    /// Load-bearing, not cosmetic: npm's packument must carry each
    /// version's `dependencies` for a resolver to do anything useful,
    /// and a registry that dropped them would install the package and
    /// none of its dependencies — a failure that reads as the package
    /// being broken rather than as the registry losing a field.
    #[test]
    fn the_published_document_is_returned_exactly_as_it_arrived() {
        let (db, org) = world("pkg-metadata");
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let doc = r#"{"dependencies":{"left-pad":"^1.0.0"},"bin":{"w":"./cli.js"}}"#;
        publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Unknown,
            doc,
            &[file("w.tgz", 1)],
            &Provenance::default(),
            10,
        )
        .unwrap();
        let back = version_by_number(&db, &p.id, "1.0.0").unwrap().unwrap();
        assert_eq!(back.metadata, doc);
        let parsed: serde_json::Value = serde_json::from_str(&back.metadata).unwrap();
        assert_eq!(parsed["dependencies"]["left-pad"], "^1.0.0");
    }

    /// A version remembers who published it and with which token, so a
    /// leaked token's blast radius is a query rather than a guess.
    #[test]
    fn a_version_remembers_who_published_it_and_with_what() {
        let (db, org) = world("pkg-provenance");
        let ada = crate::users::create(&db, "ada", crate::users::Role::Publisher, None).unwrap();
        let (tok, _) =
            crate::auth::mint(&db, &ada, "ci", &[crate::auth::Scope::PackageWrite], None).unwrap();
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let v = publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Declared("MIT".into()),
            "{}",
            &[file("w.tgz", 10)],
            &Provenance {
                user_id: Some(&ada.id),
                token_id: Some(&tok.id),
                upstream_published_at: None,
            },
            10,
        )
        .unwrap();
        assert_eq!(v.published_by_user_id.as_deref(), Some(ada.id.as_str()));
        assert_eq!(v.published_by_token_id.as_deref(), Some(tok.id.as_str()));

        // Removing the person keeps what they shipped.
        crate::users::create(&db, "root", crate::users::Role::Admin, None).unwrap();
        crate::users::delete(&db, &ada.id).unwrap();
        let after = version_by_number(&db, &p.id, "1.0.0").unwrap().unwrap();
        assert_eq!(after.id, v.id);
        assert!(after.published_by_user_id.is_none());
        assert!(after.published_by_token_id.is_none());
    }

    /// Yank hides a version; it does not remove it. A lockfile that
    /// already names it still resolves by exact version.
    #[test]
    fn a_yanked_version_is_still_there() {
        let (db, org) = world("pkg-yank");
        let p = ensure(&db, &org, Ecosystem::Cargo, "widget", ORIGIN_LOCAL, 1).unwrap();
        let v = publish_version(
            &db,
            &p.id,
            "0.1.0",
            &License::Unknown,
            "{}",
            &[file("w.crate", 5)],
            &Provenance::default(),
            10,
        )
        .unwrap();
        assert!(yank(&db, &v.id, Some("published by mistake"), true).unwrap());
        let after = version_by_number(&db, &p.id, "0.1.0").unwrap().unwrap();
        assert!(after.yanked);
        assert_eq!(after.yank_reason.as_deref(), Some("published by mistake"));

        assert!(yank(&db, &v.id, None, false).unwrap());
        assert!(
            !version_by_number(&db, &p.id, "0.1.0")
                .unwrap()
                .unwrap()
                .yanked
        );
        assert!(!yank(&db, "no-such-version", None, true).unwrap());
    }

    #[test]
    fn a_tag_moves_and_a_version_does_not() {
        let (db, org) = world("pkg-tags");
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let mk = |v: &str, at: i64| {
            publish_version(
                &db,
                &p.id,
                v,
                &License::Unknown,
                "{}",
                &[file("w.tgz", 1)],
                &Provenance::default(),
                at,
            )
            .unwrap()
        };
        let one = mk("1.0.0", 10);
        let two = mk("2.0.0", 20);

        set_tag(&db, &p.id, "Latest", &one.id, 30).unwrap();
        assert_eq!(
            tags(&db, &p.id).unwrap(),
            vec![("latest".into(), "1.0.0".into())]
        );
        set_tag(&db, &p.id, "latest", &two.id, 40).unwrap();
        assert_eq!(
            tags(&db, &p.id).unwrap(),
            vec![("latest".into(), "2.0.0".into())]
        );

        assert!(remove_tag(&db, &p.id, "latest").unwrap());
        assert!(tags(&db, &p.id).unwrap().is_empty());
        assert!(!remove_tag(&db, &p.id, "latest").unwrap());
        // The versions are untouched by any of it.
        assert_eq!(versions(&db, &p.id).unwrap().len(), 2);
    }

    /// Storage bills blobs, not versions: two versions naming one digest
    /// are one object and must be counted once.
    #[test]
    fn storage_counts_a_shared_blob_once() {
        let (db, org) = world("pkg-bytes");
        let digest = "a".repeat(64);
        assert_eq!(bytes_for_org(&db, &org).unwrap(), 0);

        note_blob(&db, &org, &digest, 500, 1).unwrap();
        note_blob(
            &db,
            &org,
            &format!("sha256:{}", digest.to_uppercase()),
            500,
            2,
        )
        .unwrap();
        assert_eq!(
            bytes_for_org(&db, &org).unwrap(),
            500,
            "the same bytes under two spellings were billed twice"
        );
        assert_eq!(blob_exists(&db, &org, &digest).unwrap(), Some(500));

        note_blob(&db, &org, &"b".repeat(64), 250, 3).unwrap();
        assert_eq!(bytes_for_org(&db, &org).unwrap(), 750);

        // And the count is scoped to the organization.
        let other = crate::ids::ulid();
        assert_eq!(bytes_for_org(&db, &other).unwrap(), 0);
        assert!(blob_exists(&db, &other, &digest).unwrap().is_none());
    }

    /// The collector's mark phase: a blob no file names is garbage, a
    /// blob some file names is not, and a blob written seconds ago is a
    /// publish in flight rather than either.
    #[test]
    fn only_an_old_unreferenced_blob_is_collectable() {
        let (db, org) = world("pkg-gc");
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let used = file("w.tgz", 10);
        publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Unknown,
            "{}",
            std::slice::from_ref(&used),
            &Provenance::default(),
            10,
        )
        .unwrap();
        note_blob(&db, &org, &used.digest, 10, 10).unwrap();

        let orphan = "c".repeat(64);
        note_blob(&db, &org, &orphan, 99, 10).unwrap();
        let in_flight = "d".repeat(64);
        note_blob(&db, &org, &in_flight, 99, 5_000).unwrap();

        let found = unreferenced_blobs(&db, &org, 1_000, 100).unwrap();
        let digests: Vec<&str> = found.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(digests, vec![orphan.as_str()], "found {found:?}");

        // Referenced is never collectable, however old; unreferenced and
        // idle is; unreferenced and used a moment ago is not yet.
        assert!(!collectable(&db, &org, &used.digest, i64::MAX).unwrap());
        assert!(collectable(&db, &org, &orphan, 1_000).unwrap());
        assert!(!collectable(&db, &org, &in_flight, 1_000).unwrap());
        // …and a digest nobody stored is not "collectable" either.
        assert!(!collectable(&db, &org, &"9".repeat(64), i64::MAX).unwrap());

        forget_blob(&db, &org, &orphan).unwrap();
        assert!(unreferenced_blobs(&db, &org, 1_000, 100)
            .unwrap()
            .is_empty());
        assert_eq!(bytes_for_org(&db, &org).unwrap(), 10 + 99);
    }

    /// Storing bytes the store already holds restarts their grace.
    ///
    /// Content addressing means a publish can land on a digest that is
    /// already here: a tarball a deleted package left behind, a layer an
    /// untagged image left behind. The grace used to run from when the
    /// digest was *first* stored, and storing it again changed nothing,
    /// so a blob first stored a week ago was collectable at the very
    /// moment a publish had just written it again and not yet written
    /// the row that names it — and the version went live with nothing
    /// behind it. Both shapes of blob, because both are written through
    /// their own statement.
    #[test]
    fn storing_a_blob_again_restarts_its_grace() {
        let (db, org) = world("pkg-gc-again");
        let single = "e".repeat(64);
        let blocked = "f".repeat(64);
        let blocks = [
            Block {
                block: "1".repeat(64),
                size_bytes: 16,
            },
            Block {
                block: "2".repeat(64),
                size_bytes: 3,
            },
        ];
        note_blob(&db, &org, &single, 7, 10).unwrap();
        note_blocked_blob(&db, &org, &blocked, &blocks, 10).unwrap();
        let listed = |before: i64| {
            let mut d: Vec<String> = unreferenced_blobs(&db, &org, before, 100)
                .unwrap()
                .into_iter()
                .map(|(d, _)| d)
                .collect();
            d.sort();
            d
        };
        assert_eq!(listed(1_000), vec![single.clone(), blocked.clone()]);

        // Stored again at 5 000 — a publish deduping against them.
        note_blob(&db, &org, &single, 7, 5_000).unwrap();
        note_blocked_blob(&db, &org, &blocked, &blocks, 5_000).unwrap();
        assert!(
            listed(1_000).is_empty(),
            "bytes stored again a moment ago were collectable by their first storage: {:?}",
            listed(1_000)
        );
        // And once the grace has run from the last use, they go.
        assert_eq!(listed(6_000), vec![single.clone(), blocked.clone()]);
        // Stored twice is still one blob, billed once.
        assert_eq!(bytes_for_org(&db, &org).unwrap(), 7 + 19);
    }

    /// Telling a client a blob is here restarts its grace, and nothing
    /// else about the blob changes.
    ///
    /// A HEAD answered 200, a mount, a manifest's check of what it names:
    /// each is a promise the bytes will still be here when the manifest
    /// arrives. The collector — its listing and its re-check both — has
    /// to see that promise, or a layer an untagged image left behind a
    /// week ago is taken between the answer and the manifest.
    #[test]
    fn telling_a_client_a_blob_is_here_restarts_its_grace() {
        let (db, org) = world("pkg-gc-touch");
        let digest = "7a".repeat(32);
        note_blob(&db, &org, &digest, 42, 10).unwrap();
        let listed = |before: i64| unreferenced_blobs(&db, &org, before, 100).unwrap();
        assert_eq!(listed(1_000), vec![(digest.clone(), 42)]);
        assert!(collectable(&db, &org, &digest, 1_000).unwrap());

        // A download is not a promise and changes nothing.
        assert_eq!(blob_exists(&db, &org, &digest).unwrap(), Some(42));
        assert_eq!(listed(1_000).len(), 1);

        // Asked about at 5 000, in the wire's spelling: it answers the
        // size, and the grace now runs from 5 000.
        let wire = format!("sha256:{}", digest.to_uppercase());
        assert_eq!(touch_blob(&db, &org, &wire, 5_000).unwrap(), Some(42));
        assert!(listed(1_000).is_empty(), "{:?}", listed(1_000));
        assert!(
            !collectable(&db, &org, &digest, 1_000).unwrap(),
            "the re-check before the delete did not see the answer a client was given"
        );

        // A node whose clock is behind cannot move it back.
        assert_eq!(touch_blob(&db, &org, &digest, 3_000).unwrap(), Some(42));
        assert!(listed(4_000).is_empty());

        // Once the grace has run from the last answer, it goes.
        assert_eq!(listed(6_000), vec![(digest.clone(), 42)]);
        assert!(collectable(&db, &org, &digest, 6_000).unwrap());

        // Bytes nobody stored are not conjured by being asked about, and
        // another organization's question touches nothing here.
        assert_eq!(touch_blob(&db, &org, &"8".repeat(64), 9_000).unwrap(), None);
        assert!(blob_exists(&db, &org, &"8".repeat(64)).unwrap().is_none());
        let other = crate::ids::ulid();
        assert_eq!(touch_blob(&db, &other, &digest, 9_000).unwrap(), None);
        assert_eq!(listed(6_000), vec![(digest.clone(), 42)]);
        assert_eq!(bytes_for_org(&db, &org).unwrap(), 42);
        assert!(touch_blob(&db, &org, "not a digest", 9_000).is_err());
    }

    /// Deleting the package takes its versions, files and tags with it —
    /// and leaves the blobs to the collector, because a sibling version
    /// may have deduped against the same digest.
    #[test]
    fn removing_a_package_leaves_its_blobs_to_the_collector() {
        let (db, org) = world("pkg-remove");
        let p = ensure(&db, &org, Ecosystem::Npm, "widget", ORIGIN_LOCAL, 1).unwrap();
        let f = file("w.tgz", 10);
        let v = publish_version(
            &db,
            &p.id,
            "1.0.0",
            &License::Unknown,
            "{}",
            std::slice::from_ref(&f),
            &Provenance::default(),
            10,
        )
        .unwrap();
        set_tag(&db, &p.id, "latest", &v.id, 10).unwrap();
        note_blob(&db, &org, &f.digest, 10, 10).unwrap();

        assert!(remove(&db, &org, &p.id).unwrap());
        assert!(by_id(&db, &org, &p.id).unwrap().is_none());
        assert!(versions(&db, &p.id).unwrap().is_empty());
        assert_eq!(
            bytes_for_org(&db, &org).unwrap(),
            10,
            "the bytes went with the row instead of waiting for the sweep"
        );
        assert!(collectable(&db, &org, &f.digest, 1_000).unwrap());
        assert!(!remove(&db, &org, &p.id).unwrap());
    }

    /// A registry nobody switched on answers for nothing, and the
    /// settings page still renders a row per ecosystem.
    #[test]
    fn every_ecosystem_is_off_until_an_admin_says_otherwise() {
        let (db, org) = world("pkg-policy");
        let all = ecosystem_policies(&db, &org).unwrap();
        assert_eq!(all.len(), Ecosystem::ALL.len());
        assert!(all.iter().all(|p| !p.enabled() && !p.proxies()));
        assert_eq!(
            all.iter().map(|p| p.ecosystem).collect::<Vec<_>>(),
            Ecosystem::ALL.to_vec()
        );

        set_ecosystem_policy(&db, &org, Ecosystem::Npm, MODE_PROXY, "allow", 5).unwrap();
        // The list still returns a row per ecosystem once one is
        // configured: the configured one read from its row, the rest
        // still filled in as off.
        let all = ecosystem_policies(&db, &org).unwrap();
        assert_eq!(all.len(), Ecosystem::ALL.len());
        let listed = all.iter().find(|p| p.ecosystem == Ecosystem::Npm).unwrap();
        assert_eq!(listed.mode, MODE_PROXY);
        assert_eq!(listed.license_unknown, "allow");
        assert!(all
            .iter()
            .filter(|p| p.ecosystem != Ecosystem::Npm)
            .all(|p| !p.enabled()));

        let npm = ecosystem_policy(&db, &org, Ecosystem::Npm).unwrap();
        assert!(npm.enabled() && npm.proxies());
        assert_eq!(npm.license_unknown, "allow");
        // The others did not move.
        assert!(!ecosystem_policy(&db, &org, Ecosystem::Oci)
            .unwrap()
            .enabled());

        set_ecosystem_policy(&db, &org, Ecosystem::Npm, MODE_PRIVATE, "block", 6).unwrap();
        let npm = ecosystem_policy(&db, &org, Ecosystem::Npm).unwrap();
        assert!(
            npm.enabled() && !npm.proxies(),
            "private still serves, it just does not proxy"
        );

        assert!(set_ecosystem_policy(&db, &org, Ecosystem::Npm, "sometimes", "block", 7).is_err());
        assert!(set_ecosystem_policy(&db, &org, Ecosystem::Npm, MODE_PRIVATE, "maybe", 7).is_err());
    }

    /// A search matches names containing the query, and `LIKE`'s own
    /// wildcards in the query mean themselves.
    #[test]
    fn a_search_matches_substrings_and_its_wildcards_are_literal() {
        let (db, org) = world("pkg-search");
        for name in ["left_pad", "leftxpad", "@acme/widget", "100%-real"] {
            ensure(&db, &org, Ecosystem::Npm, name, ORIGIN_LOCAL, 1).unwrap();
        }
        ensure(&db, &org, Ecosystem::Cargo, "widget", ORIGIN_LOCAL, 1).unwrap();
        let names = |q: &str, eco: Option<Ecosystem>| -> Vec<String> {
            let mut v: Vec<String> = list(&db, &org, eco, Some(q), 50, 0)
                .unwrap()
                .into_iter()
                .map(|p| p.name)
                .collect();
            v.sort();
            v
        };
        assert_eq!(names("left_pad", None), ["left_pad"], "_ is not a wildcard");
        assert_eq!(names("WIDGET", None), ["@acme/widget", "widget"]);
        assert_eq!(names("widget", Some(Ecosystem::Cargo)), ["widget"]);
        assert_eq!(names("0%", None), ["100%-real"], "% is not a wildcard");
        assert_eq!(names("pad", None), ["left_pad", "leftxpad"]);
        assert_eq!(list(&db, &org, None, Some("  "), 50, 0).unwrap().len(), 5);

        let counts = counts(&db, &org).unwrap();
        assert_eq!(counts.len(), Ecosystem::ALL.len());
        assert!(counts.contains(&(Ecosystem::Npm, 4)));
        assert!(counts.contains(&(Ecosystem::Cargo, 1)));
        assert!(counts.contains(&(Ecosystem::Oci, 0)));
    }
}
