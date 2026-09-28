//! PostgreSQL handle + embedded migrations.
//!
//! The database holds everything that is not package bytes: the
//! organization this install serves, its people and their tokens, what
//! was published and when, the admission policy and what it caught.
//! Package bytes live in the object store, content-addressed; see
//! `skein-server`'s `registry::blobs`.

use postgres::types::ToSql;
use postgres::{Client, NoTls, Row};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio_postgres_rustls::MakeRustlsConnect;

/// The control-plane database. One connection behind a mutex — control
/// operations are point reads/writes measured in microseconds against a
/// local/regional Postgres; contention here is never the bottleneck (the
/// bytes are in the object store).
#[derive(Clone)]
pub struct ControlDb {
    conn: Arc<Mutex<ClientBox>>,
}

/// Writes that would wait on another session's lock fail after this many
/// milliseconds instead of hanging a request thread. Overridable with
/// `SKEIN_DB_LOCK_TIMEOUT_MS`.
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 5000;

/// Cluster-wide advisory lock key serializing migrations: two server
/// processes booting against the same database must not interleave DDL.
const MIGRATE_LOCK_KEY: i64 = 0x534B_4549_4E00_0001; // "SKEIN\0\0\x01"

pub(crate) const MIGRATIONS: &[&str] = &[
    // 0001 — the registry.
    //
    // Carved out of stratum-core's control plane (its migrations 0001,
    // 0005, 0113, 0116, 0117 and 0118), folded into one starting point
    // and trimmed to what a self-hosted registry needs: no repositories,
    // no billing, no forge jobs.
    r#"
    -- The organization this install serves. Exactly one row, enforced
    -- by the database rather than by every caller remembering: the
    -- unique index over a constant admits a second row never.
    --
    -- Kept as a row with an id, rather than dropped, because the id is
    -- the object-store prefix every blob lives under (`o/<id>/pkg/…`)
    -- and the scope every package lookup is written against. A second
    -- namespace later is a new row and a relaxed index, not a rewrite of
    -- every query and every stored key.
    CREATE TABLE orgs (
        id                     TEXT PRIMARY KEY,
        name                   TEXT NOT NULL UNIQUE,
        created_at             BIGINT NOT NULL,
        -- The licence policy. `allow_list` admits only what is listed;
        -- `deny_list` admits everything except. Both spellings exist
        -- because they are not the same policy under an expression: an
        -- organization that has approved four licences wants a fifth to
        -- be refused, and one that has banned AGPL wants a licence
        -- nobody has heard of to pass.
        license_mode           TEXT NOT NULL DEFAULT 'deny_list'
                               CHECK (license_mode IN ('allow_list','deny_list')),
        -- What happens on a violation. `audit` records what it would
        -- have refused and serves anyway; `block` refuses. Audit is the
        -- default because a policy that blocks from day one meets a
        -- deadline in week one and gets switched off, and nobody learns
        -- what it would have cost.
        registry_policy_mode   TEXT NOT NULL DEFAULT 'audit'
                               CHECK (registry_policy_mode IN ('audit','block')),
        -- An upstream version published less than N days ago is not
        -- served. 0 disables.
        registry_cooldown_days INT NOT NULL DEFAULT 0
    );
    CREATE UNIQUE INDEX orgs_singleton ON orgs ((TRUE));

    -- The people who may reach this registry. There is no anonymous
    -- reader and no public package: everything here is private to the
    -- organization, so every request is one of these people, through a
    -- token or a browser session.
    --
    -- `role` is the whole of a person's authority, and a token is
    -- narrowed by it on every request — demote somebody and the token
    -- in their `.npmrc` loses the difference on its next use.
    CREATE TABLE users (
        id            TEXT PRIMARY KEY,
        -- Stored lowercase; what a person types to sign in.
        username      TEXT NOT NULL UNIQUE,
        display_name  TEXT NOT NULL DEFAULT '',
        -- argon2id. NULL means the account cannot sign in to the UI,
        -- which is what a service account for CI wants: it holds tokens
        -- and nothing else.
        password_hash TEXT,
        role          TEXT NOT NULL CHECK (role IN ('admin','publisher','reader')),
        created_at    BIGINT NOT NULL,
        disabled_at   BIGINT
    );

    -- API tokens: `skein_<id>_<secret>`, SHA-256 of the secret at rest.
    -- `scopes` is the ceiling the token was minted with; what it may do
    -- on a given request is that ceiling narrowed by its owner's role
    -- at that moment.
    CREATE TABLE tokens (
        id           TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        hash         TEXT NOT NULL,
        scopes       TEXT NOT NULL,
        label        TEXT NOT NULL,
        created_at   BIGINT NOT NULL,
        expires_at   BIGINT,
        last_used_at BIGINT,
        revoked_at   BIGINT
    );
    CREATE INDEX tokens_user ON tokens(user_id, created_at DESC);

    -- Browser sessions for the UI. A bearer credential stored like a
    -- token: 256 random bits, only the SHA-256 kept, checked on every
    -- request so revocation is instant rather than "within the TTL".
    CREATE TABLE sessions (
        id           TEXT PRIMARY KEY,
        user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash   TEXT NOT NULL,
        created_at   BIGINT NOT NULL,
        expires_at   BIGINT NOT NULL,
        last_seen_at BIGINT NOT NULL,
        revoked_at   BIGINT
    );
    CREATE INDEX sessions_user ON sessions(user_id);

    -- Append-only. No UPDATE or DELETE statement for this table exists
    -- anywhere in the codebase.
    CREATE TABLE audit_log (
        seq       BIGSERIAL PRIMARY KEY,
        at        BIGINT NOT NULL,
        org_id    TEXT NOT NULL,
        principal TEXT NOT NULL,
        user_id   TEXT,
        action    TEXT NOT NULL,
        context   TEXT
    );
    CREATE INDEX audit_org_at ON audit_log(org_id, seq DESC);

    CREATE TABLE packages (
        id              TEXT PRIMARY KEY,
        org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        ecosystem       TEXT NOT NULL
                        CHECK (ecosystem IN ('npm','maven','pypi','cargo','oci')),
        -- What the publisher called it, and what a lookup matches on.
        -- The normalised form carries the unique index because several
        -- ecosystems fold names: PEP 503 makes `.`, `_` and `-`
        -- equivalent, npm lowercases. Two spellings that differ only
        -- there are one package, and admitting them as two rows would
        -- let the second answer for a name the first already owns.
        name            TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        -- 'local' was published here; 'proxied' was cached from an
        -- upstream registry. The distinction decides who may write it
        -- and whether the licence gate ran, and it is what makes
        -- "private always wins" enforceable: a proxied row is never
        -- created for a name that already has a local one.
        origin          TEXT NOT NULL DEFAULT 'local'
                        CHECK (origin IN ('local','proxied')),
        created_at      BIGINT NOT NULL,
        updated_at      BIGINT NOT NULL,
        UNIQUE (org_id, ecosystem, normalized_name)
    );
    CREATE INDEX packages_recent ON packages(org_id, updated_at DESC);

    CREATE TABLE package_versions (
        id                    TEXT PRIMARY KEY,
        package_id            TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
        version               TEXT NOT NULL,
        normalized_version    TEXT NOT NULL,
        -- Yanked, not deleted. A version's bytes never change and a
        -- version never disappears: npm, PyPI, Maven and Cargo all cache
        -- on the assumption that a resolved version is stable, and a
        -- mutable one is a supply-chain hole. Yank hides it from
        -- resolution; it stays fetchable by exact version so a lockfile
        -- that already names it still builds.
        yanked                BOOLEAN NOT NULL DEFAULT FALSE,
        yank_reason           TEXT,
        -- The SPDX expression this version is under, and where we got
        -- it. 'declared' is the ecosystem's own metadata; 'unknown' is
        -- a disposition the policy has to have an answer for, not an
        -- error.
        license_expr          TEXT,
        license_source        TEXT NOT NULL DEFAULT 'unknown'
                              CHECK (license_source IN ('declared','detected','unknown')),
        -- The ecosystem's own version document, as published: npm's
        -- version manifest, a POM, a wheel's METADATA, an OCI config.
        -- Stored verbatim because it is what the resolver on the other
        -- end needs and we are not the authority on its shape.
        metadata              TEXT NOT NULL DEFAULT '{}',
        size_bytes            BIGINT NOT NULL DEFAULT 0,
        -- Who published it, and with which credential. SET NULL rather
        -- than CASCADE: removing a person must not remove the record of
        -- what they shipped.
        published_by_user_id  TEXT REFERENCES users(id) ON DELETE SET NULL,
        published_by_token_id TEXT REFERENCES tokens(id) ON DELETE SET NULL,
        published_at          BIGINT NOT NULL,
        -- When the *upstream* published a cached version. `published_at`
        -- is when this registry wrote the row, which for a proxied
        -- artifact is when somebody first installed it — the wrong clock
        -- for the cooldown, which would otherwise refuse every freshly
        -- cached version for the next N days. NULL for a version
        -- published here.
        upstream_published_at BIGINT,
        UNIQUE (package_id, normalized_version)
    );
    CREATE INDEX package_versions_pkg ON package_versions(package_id, published_at DESC);

    -- One row per file a version is made of. npm and Cargo have exactly
    -- one; a Maven version has a jar, a POM and usually sources and
    -- javadoc; an OCI manifest names a config and every layer. The
    -- digest is the join to the bytes, and two versions naming the same
    -- digest share one object.
    CREATE TABLE package_files (
        version_id   TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
        filename     TEXT NOT NULL,
        digest       TEXT NOT NULL,
        size_bytes   BIGINT NOT NULL,
        content_type TEXT NOT NULL,
        -- The *other* digests this artifact has, as JSON: npm wants a
        -- SHA-1 `shasum` and a SHA-512 `integrity`, Maven publishes
        -- `.md5` and `.sha1` beside every file, PyPI reports an MD5.
        -- Computed once at publish from bytes we had just verified, so a
        -- resolve never has to fetch an object to answer one.
        digests      TEXT NOT NULL DEFAULT '{}',
        PRIMARY KEY (version_id, filename)
    );
    CREATE INDEX package_files_digest ON package_files(digest);

    -- The bytes in the store. Nothing here carries a refcount: a blob is
    -- live iff some `package_files` row names its digest, which the
    -- collector answers with one query, and a refcount that drifts is a
    -- silently deleted layer.
    CREATE TABLE package_blobs (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        digest     TEXT NOT NULL,
        size_bytes BIGINT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (org_id, digest)
    );

    -- Mutable pointers into the immutable set: npm dist-tags (`latest`,
    -- `next`), OCI tags. A tag moves; what it points at does not.
    CREATE TABLE package_tags (
        package_id TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
        tag        TEXT NOT NULL,
        version_id TEXT NOT NULL REFERENCES package_versions(id) ON DELETE CASCADE,
        updated_at BIGINT NOT NULL,
        PRIMARY KEY (package_id, tag)
    );

    -- Which ecosystems this registry admits, and on what terms. Absent
    -- means 'off': an ecosystem nobody switched on answers 404, so
    -- enabling one is a deliberate act with an audit row behind it.
    --
    -- `license_unknown` is per ecosystem because the ecosystems differ:
    -- npm, PyPI, Cargo and Maven publishers usually declare a licence,
    -- and OCI images mostly declare none.
    CREATE TABLE org_ecosystems (
        org_id          TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        ecosystem       TEXT NOT NULL
                        CHECK (ecosystem IN ('npm','maven','pypi','cargo','oci')),
        mode            TEXT NOT NULL DEFAULT 'off'
                        CHECK (mode IN ('off','private','proxy')),
        license_unknown TEXT NOT NULL DEFAULT 'block'
                        CHECK (license_unknown IN ('block','allow')),
        updated_at      BIGINT NOT NULL,
        PRIMARY KEY (org_id, ecosystem)
    );

    CREATE TABLE org_license_rules (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        -- An SPDX identifier, case-folded: SPDX ids compare
        -- case-insensitively and a rule that catches one spelling
        -- catches nothing.
        spdx_id     TEXT NOT NULL,
        disposition TEXT NOT NULL CHECK (disposition IN ('allow','deny')),
        updated_at  BIGINT NOT NULL,
        PRIMARY KEY (org_id, spdx_id)
    );

    -- Names that are ours and are never fetched from upstream,
    -- published or not. A normalised name prefix matched on a segment
    -- boundary, never as a bare substring — see `policy::namespace_covers`.
    CREATE TABLE org_reserved_namespaces (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        ecosystem  TEXT NOT NULL
                   CHECK (ecosystem IN ('npm','maven','pypi','cargo','oci')),
        pattern    TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        PRIMARY KEY (org_id, ecosystem, pattern)
    );

    -- What the admission policy caught, one row per package version with
    -- a hit count: a CI run resolving eight hundred dependencies must not
    -- write eight hundred rows, and "how many times did this come up" is
    -- the number that decides whether a rule earns its keep.
    CREATE TABLE package_policy_events (
        org_id      TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        ecosystem   TEXT NOT NULL,
        name        TEXT NOT NULL,
        version     TEXT NOT NULL,
        -- 'blocked' when it was refused, 'would_block' when audit mode
        -- served it anyway.
        disposition TEXT NOT NULL CHECK (disposition IN ('blocked','would_block')),
        -- Which rule decided: 'license', 'cooldown', 'reserved'.
        rule        TEXT NOT NULL,
        reason      TEXT NOT NULL,
        hits        BIGINT NOT NULL DEFAULT 1,
        first_at    BIGINT NOT NULL,
        last_at     BIGINT NOT NULL,
        PRIMARY KEY (org_id, ecosystem, name, version)
    );
    CREATE INDEX package_policy_events_org ON package_policy_events(org_id, last_at DESC);

    -- Blobs bigger than one object. A large blob (an OCI layer runs to
    -- hundreds of megabytes) is an ordered list of blocks, each one an
    -- ordinary content-addressed object, cut from the request as it
    -- streams in so nothing larger than one block is ever resident.
    CREATE TABLE package_blocks (
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        -- The whole blob's digest: the name the client asks for.
        digest     TEXT NOT NULL,
        seq        INT NOT NULL,
        -- The block's own digest, which is its key in the store.
        block      TEXT NOT NULL,
        size_bytes BIGINT NOT NULL,
        PRIMARY KEY (org_id, digest, seq)
    );
    CREATE INDEX package_blocks_block ON package_blocks(org_id, block);

    -- An in-flight upload. The OCI protocol lets a client open a
    -- session, PATCH into it over several requests and finish with a PUT
    -- naming the digest — possibly on a different node, which is why
    -- this is a table and not a map in memory.
    CREATE TABLE package_uploads (
        id         TEXT PRIMARY KEY,
        org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
        -- The repository the session was opened against, re-checked at
        -- every PATCH: a session id is a bearer capability.
        package    TEXT NOT NULL,
        blocks     TEXT NOT NULL DEFAULT '[]',
        size_bytes BIGINT NOT NULL DEFAULT 0,
        started_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    );
    CREATE INDEX package_uploads_stale ON package_uploads(updated_at);
    "#,
    // 0002 — the commercial licence.
    //
    // Weft Sandboxes' model (sandy's control-plane `license/service.ts`,
    // which keeps the same facts in two meta items), counting seats —
    // people who can sign in — where sandy counts concurrent sandboxes.
    r#"
    -- One row, like `orgs`: the key in force and what the daily check
    -- last heard. Created here, so `installed_at` is when this install
    -- started keeping licence state and day one is never "overdue".
    CREATE TABLE license (
        singleton         BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
        key               TEXT,
        -- The SKEIN_LICENSE_KEY last applied. A key installed through the
        -- API stands until the environment's key *changes*, rather than
        -- being overwritten by the same stale variable on every restart.
        configured_key    TEXT,
        installed_at      BIGINT NOT NULL,
        last_check_at     BIGINT,
        last_check_status TEXT CHECK (last_check_status IN
                              ('active','lapsed','revoked','unknown')),
        notice            TEXT,
        last_check_error  TEXT,
        -- The daily check is claimed here, not decided per process: ten
        -- replicas behind a load balancer, or one restarted ten times,
        -- still send one check a day.
        check_claimed_at  BIGINT,
        -- The most seats seen since the last successful check: what it
        -- reports as `peakSeats`.
        peak_since_check  BIGINT NOT NULL DEFAULT 0
    );
    INSERT INTO license (installed_at)
        VALUES ((EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::BIGINT);

    -- The most seats seen in each UTC calendar month, the last thirteen
    -- kept: what an offline licence's annual true-up reports.
    CREATE TABLE license_monthly_peaks (
        month TEXT PRIMARY KEY CHECK (month ~ '^[0-9]{4}-[0-9]{2}$'),
        peak  BIGINT NOT NULL
    );
    "#,
    // 0003 — an OCI tag keeps its case (`packages::version_key`). Tags
    // stored before were keyed lowercased; they are keyed as written.
    // No two can collide: they were distinct lowercased, so they are
    // distinct as written.
    r#"
    UPDATE package_versions v SET normalized_version = v.version
      FROM packages p
     WHERE p.id = v.package_id AND p.ecosystem = 'oci'
       AND v.normalized_version <> v.version;
    "#,
    // 0004 — the collector's grace runs from a blob's last use, not its
    // first storage.
    //
    // `created_at` is when a digest was first stored, and storing or
    // reusing the same digest again never moved it. So a layer stored a
    // week ago and unreferenced since was collectable at the very moment
    // a push was building on it — answered 200 to a HEAD, mounted, or
    // written again — and a sweep between that answer and the manifest
    // took the layer out from under the push. `touched_at` is moved by
    // every use (`packages::note_blob`, `note_blocked_blob`,
    // `touch_blob`) and is what the collector measures.
    //
    // Deliberately not indexed: the collector scans this table once an
    // hour, while a touch is an UPDATE on every HEAD, and an index on
    // the column a touch changes would make every one of them a non-HOT
    // update that rewrites the index too.
    r#"
    ALTER TABLE package_blobs ADD COLUMN touched_at BIGINT;
    UPDATE package_blobs SET touched_at = created_at;
    ALTER TABLE package_blobs ALTER COLUMN touched_at SET NOT NULL;
    "#,
];

/// How to reach the database: the URL's own settings, and TLS when its
/// `sslmode` asks for it. Built once, from the URL, and kept for every
/// reconnect — so a bad CA file or an `sslmode` nobody supports is
/// refused at start, not on the first failover.
///
/// `sslmode` is libpq's, and so is `sslrootcert`, so a URL copied from a
/// cloud console or a DBA works as written:
///
/// | `sslmode` | Skein |
/// |---|---|
/// | absent, `disable`, `allow`, `prefer` | no TLS — as before this existed |
/// | `require`, `verify-full` | TLS; the certificate chain **and** the host name are verified |
/// | `verify-ca` | TLS; the chain is verified, the host name is not |
///
/// `require` is stricter than libpq, which encrypts without verifying:
/// an encrypted connection to whoever answers is not one a registry's
/// database password should travel over. A server whose certificate
/// comes from a private CA (Amazon RDS, Azure, a corporate CA) needs
/// that CA: `sslrootcert=/path/ca.pem` trusts exactly that file, as in
/// libpq; `sslrootcert=system`, or no `sslrootcert`, trusts the public
/// roots, the OS store and `SKEIN_CA_FILE`.
///
/// Until this existed Skein connected with `NoTls` only: every managed
/// PostgreSQL that insists on TLS — RDS with `rds.force_ssl`, Azure
/// Flexible Server — refused it, `sslmode=require` failed its handshake,
/// and `sslmode=verify-full` was rejected as an invalid URL.
#[derive(Clone)]
pub(crate) struct Connector {
    config: postgres::Config,
    tls: Option<MakeRustlsConnect>,
}

/// The TLS settings a URL carries, taken out of it: the `postgres` crate
/// knows `sslmode` only as disable/prefer/require and not `sslrootcert`
/// at all, so both are read here and the rest is handed on.
fn split_tls(url: &str) -> Result<(String, Option<String>, Option<String>), String> {
    let take = |k: &str, v: &str, mode: &mut Option<String>, root: &mut Option<String>| match k {
        "sslmode" => {
            *mode = Some(v.to_string());
            true
        }
        "sslrootcert" => {
            *root = Some(v.to_string());
            true
        }
        _ => false,
    };
    let (mut mode, mut root) = (None, None);
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        let Some((base, query)) = url.split_once('?') else {
            return Ok((url.to_string(), None, None));
        };
        let mut kept = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v)?;
            if !take(k, &v, &mut mode, &mut root) {
                kept.push(pair);
            }
        }
        let rest = if kept.is_empty() {
            base.to_string()
        } else {
            format!("{base}?{}", kept.join("&"))
        };
        Ok((rest, mode, root))
    } else {
        // libpq's `key=value key=value` form.
        let mut kept = Vec::new();
        for word in url.split_whitespace() {
            let (k, v) = word.split_once('=').unwrap_or((word, ""));
            if !take(k, v.trim_matches('\''), &mut mode, &mut root) {
                kept.push(word);
            }
        }
        Ok((kept.join(" "), mode, root))
    }
}

fn percent_decode(s: &str) -> Result<String, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| format!("a bad %-escape in the database URL near {:?}", &s[i..]))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the database URL is not UTF-8".to_string())
}

impl Connector {
    pub(crate) fn from_url(url: &str) -> Result<Connector, String> {
        let (rest, mode, root) = split_tls(url)?;
        let mut config: postgres::Config = rest
            .parse()
            .map_err(|e| format!("SKEIN_DB_URL is not a PostgreSQL URL Skein can read: {e}"))?;
        // A half-open connection — a failover, a NAT that forgot us —
        // is noticed by the kernel rather than waited on forever.
        config
            .keepalives(true)
            .keepalives_idle(Duration::from_secs(60));
        let verify_host = match mode.as_deref() {
            None | Some("disable" | "allow" | "prefer") => {
                config.ssl_mode(postgres::config::SslMode::Disable);
                return Ok(Connector { config, tls: None });
            }
            Some("require" | "verify-full") => true,
            Some("verify-ca") => false,
            Some(other) => {
                return Err(format!(
                    "sslmode={other} is not one Skein knows: use disable, require, verify-ca \
                     or verify-full"
                ))
            }
        };
        let roots = match root.as_deref() {
            None | Some("system") => skein_tls::roots_from_env()?,
            Some(path) => {
                skein_tls::roots_only(Path::new(path)).map_err(|e| format!("sslrootcert: {e}"))?
            }
        };
        let tls = skein_tls::client_config(roots, verify_host)?;
        config.ssl_mode(postgres::config::SslMode::Require);
        Ok(Connector {
            config,
            tls: Some(MakeRustlsConnect::new(tls)),
        })
    }

    fn connect(&self) -> Result<Client, postgres::Error> {
        match &self.tls {
            None => self.config.connect(NoTls),
            Some(tls) => self.config.connect(tls.clone()),
        }
    }
}

/// A connection error with its causes: `postgres` says "error performing
/// TLS handshake" and keeps *why* — an unknown issuer, a name mismatch —
/// in its source chain, which is the only part anybody can act on.
fn connect_error(e: &postgres::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        let s = cause.to_string();
        if !out.contains(&s) {
            out.push_str(": ");
            out.push_str(&s);
        }
        source = source.and_then(|s| s.source());
    }
    if out.contains("no encryption") {
        out.push_str(
            " — this server accepts only TLS: add sslmode=verify-full (and sslrootcert=… for a \
             private CA) to SKEIN_DB_URL",
        );
    }
    skein_tls::hint(&out)
}

/// The sync `postgres` client drives its own internal runtime with
/// `block_on`, which panics if the calling thread carries any tokio
/// runtime context — async workers and `spawn_blocking` threads alike.
/// The server calls control functions from both, so every database call
/// routes through here: with a runtime context present, hop to a scoped
/// OS thread (microseconds, against point queries); otherwise run
/// directly. `block_in_place` is NOT sufficient — it only works on
/// worker threads, not in `spawn_blocking` context.
fn run<T, F>(f: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::scope(|s| s.spawn(f).join().expect("db call thread"))
    } else {
        f()
    }
}

/// The live client plus what it takes to make a new one. A lost
/// connection (database restart, failover, terminated backend) is
/// re-established once per call, transparently — a fleet must not need
/// restarting because Postgres did. `postgres::Client`'s Drop also
/// drives its runtime; dropping it on a tokio thread (server shutdown)
/// would panic, so Drop hops threads too.
struct ClientBox {
    client: Option<Client>,
    connector: Connector,
    lock_ms: u64,
}

impl ClientBox {
    fn client(&mut self) -> &mut Client {
        self.client.as_mut().expect("client present until drop")
    }

    fn reconnect(&mut self) -> Result<(), postgres::Error> {
        let mut fresh = self.connector.connect()?;
        fresh.batch_execute(&format!("SET lock_timeout = {}", self.lock_ms))?;
        // Replace before the old client drops (its Drop is runtime-safe
        // here: reconnect already runs off the async threads via `run`).
        self.client = Some(fresh);
        Ok(())
    }
}

impl Drop for ClientBox {
    fn drop(&mut self) {
        if let Some(client) = self.client.take() {
            if tokio::runtime::Handle::try_current().is_ok() {
                std::thread::spawn(move || drop(client));
            }
        }
    }
}

/// A locked connection: the same query surface as `postgres::Client`,
/// with every call routed through [`run`] and retried once on a lost
/// connection.
pub(crate) struct Conn<'a>(MutexGuard<'a, ClientBox>);

impl Conn<'_> {
    fn call<T, F>(&mut self, f: F) -> Result<T, postgres::Error>
    where
        T: Send,
        F: Fn(&mut Client) -> Result<T, postgres::Error> + Send,
    {
        let boxed: &mut ClientBox = &mut self.0;
        run(move || match f(boxed.client()) {
            Err(e) if connection_lost(&e) => match boxed.reconnect() {
                Ok(()) => f(boxed.client()),
                Err(re) => Err(re),
            },
            other => other,
        })
    }

    pub fn execute(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<u64, postgres::Error> {
        self.call(|c| c.execute(sql, params))
    }

    pub fn query(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Vec<Row>, postgres::Error> {
        self.call(|c| c.query(sql, params))
    }

    pub fn query_one(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Row, postgres::Error> {
        self.call(|c| c.query_one(sql, params))
    }

    pub fn query_opt(
        &mut self,
        sql: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<Row>, postgres::Error> {
        self.call(|c| c.query_opt(sql, params))
    }

    /// Run several statements as one unit, rolling back if the closure
    /// returns `Err`.
    ///
    /// Needed because some control-plane facts are only true together: a
    /// version with none of its files is a version a resolver would cache
    /// as empty. The closure gets a plain `Transaction`; it is deliberately not the retrying `call`
    /// wrapper, because replaying half a transaction after a reconnect
    /// would be worse than failing.
    pub fn transaction<T, F>(&mut self, f: F) -> Result<T, postgres::Error>
    where
        T: Send,
        F: FnOnce(&mut postgres::Transaction) -> Result<T, postgres::Error> + Send,
    {
        let boxed: &mut ClientBox = &mut self.0;
        run(move || {
            let mut tx = boxed.client().transaction()?;
            let out = f(&mut tx)?;
            tx.commit()?;
            Ok(out)
        })
    }
}

impl ControlDb {
    /// Connect to `postgres://…` and bring the schema current.
    pub fn open(url: &str) -> Result<ControlDb, String> {
        run(|| {
            let connector = Connector::from_url(url)?;
            let mut conn = connector
                .connect()
                .map_err(|e| format!("connect control db: {}", connect_error(&e)))?;
            let lock_ms = std::env::var("SKEIN_DB_LOCK_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_LOCK_TIMEOUT_MS);
            conn.batch_execute(&format!("SET lock_timeout = {lock_ms}"))
                .map_err(|e| e.to_string())?;
            Self::migrate(&mut conn)?;
            Ok(ControlDb {
                conn: Arc::new(Mutex::new(ClientBox {
                    client: Some(conn),
                    connector,
                    lock_ms,
                })),
            })
        })
    }

    fn migrate(conn: &mut Client) -> Result<(), String> {
        conn.execute("SELECT pg_advisory_lock($1)", &[&MIGRATE_LOCK_KEY])
            .map_err(|e| e.to_string())?;
        let result = Self::migrate_locked(conn);
        let _ = conn.execute("SELECT pg_advisory_unlock($1)", &[&MIGRATE_LOCK_KEY]);
        result
    }

    fn migrate_locked(conn: &mut Client) -> Result<(), String> {
        conn.batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL)",
        )
        .map_err(|e| e.to_string())?;
        let current: i64 = conn
            .query_one(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                &[],
            )
            .map_err(|e| e.to_string())?
            .get(0);
        // A database a newer Skein has migrated is one this build does
        // not understand: its code would write rows the schema no longer
        // has, or miss columns the newer one relies on. Refused, so a
        // rollback to an older release is a decision someone makes with a
        // backup in hand rather than something that happens quietly.
        if current > MIGRATIONS.len() as i64 {
            return Err(format!(
                "this database is at schema version {current}, written by a newer Skein; this \
                 build knows versions up to {}. Run that release or a later one — or restore the \
                 backup taken before the upgrade",
                MIGRATIONS.len()
            ));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate() {
            let version = (i + 1) as i64;
            if version <= current {
                continue;
            }
            let mut tx = conn.transaction().map_err(|e| e.to_string())?;
            tx.batch_execute(sql)
                // `detail`, not `{e}`: a failing migration reported as
                // "migration 28: db error" tells an operator watching a
                // deploy nothing at all, and tells whoever wrote the
                // migration less than that. This is the first thing
                // anybody reads when a release will not start.
                .map_err(|e| format!("migration {version}: {}", detail(&e)))?;
            tx.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2)",
                &[&version, &crate::ids::now_ms()],
            )
            .map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn lock(&self) -> Conn<'_> {
        Conn(self.conn.lock().unwrap())
    }
}

/// Is this a lost connection rather than a server-side answer? The very
/// first call on a terminated session surfaces an io-sourced
/// "error communicating with the server" before `is_closed()` turns
/// true, so both shapes count. A server-side error always carries a
/// DbError and is never retried.
fn connection_lost(e: &postgres::Error) -> bool {
    if e.is_closed() {
        return true;
    }
    if e.as_db_error().is_some() {
        return false;
    }
    let mut src = std::error::Error::source(e);
    while let Some(s) = src {
        if s.downcast_ref::<std::io::Error>().is_some() {
            return true;
        }
        src = std::error::Error::source(s);
    }
    false
}

/// What a Postgres error actually says.
///
/// `postgres::Error`'s own `Display` renders a server-side failure as
/// the literal string **"db error"** — the message, the constraint name
/// and the SQLSTATE all live on the `DbError` behind it and are never
/// reached by `{e}`. So every `format!("doing the thing: {e}")` in this
/// crate produces "doing the thing: db error", which tells an operator
/// nothing and tells a developer debugging a failing test even less.
///
/// In stratum-core, where this was written, that cost a debugging cycle:
/// a real constraint failure surfaced as "db error" and had to be
/// reproduced by hand to find out what had gone wrong.
///
/// The detail is safe to surface: it is our own SQL and our own
/// constraint names, not user data. Where a message reaches a client it
/// still goes through the API layer's own choice of status and wording.
pub fn detail(e: &postgres::Error) -> String {
    match e.as_db_error() {
        Some(d) => {
            let code = d.code().code();
            match d.constraint() {
                Some(c) => format!("{} [{code}, constraint {c}]", d.message()),
                None => format!("{} [{code}]", d.message()),
            }
        }
        None => e.to_string(),
    }
}

/// Did this error come from a UNIQUE/PK constraint? (name-collision arms
/// answer "already exists" instead of a 500).
pub(crate) fn is_unique_violation(e: &postgres::Error) -> bool {
    e.as_db_error()
        .map(|d| *d.code() == postgres::error::SqlState::UNIQUE_VIOLATION)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An older build refuses a database a newer one migrated, rather
    /// than starting against a schema it does not understand.
    #[test]
    fn a_database_from_a_newer_release_is_refused() {
        let url = skein_testkit::pg::test_db_url("db_newer");
        let db = ControlDb::open(&url).unwrap();
        let next = MIGRATIONS.len() as i64 + 1;
        db.lock()
            .execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, 0)",
                &[&next],
            )
            .unwrap();
        drop(db);
        let err = ControlDb::open(&url)
            .err()
            .expect("a newer schema was accepted");
        assert!(
            err.contains(&format!("schema version {next}")) && err.contains("newer Skein"),
            "{err}"
        );
    }

    /// A database that accepts only TLS — what RDS, Azure and most
    /// corporate PostgreSQL look like — is reached, with its certificate
    /// verified, and only when the URL asks for TLS. Before this, Skein
    /// connected with `NoTls` whatever the URL said: `sslmode=require`
    /// failed its handshake and `verify-full` was an invalid URL.
    #[test]
    fn a_database_that_insists_on_tls_is_reached_over_verified_tls() {
        let pki = skein_testkit::pki::Pki::new();
        let cert = pki.server("pg", &["db.acme.test", "127.0.0.1"]);
        let pg = skein_testkit::pg::Pg::start_tls(&cert).unwrap();
        let url = pg.database("tls");
        let ca = pki.ca_pem.display().to_string();

        // Plain: the server refuses it — which is how the successes below
        // prove they really were TLS.
        let err = ControlDb::open(&url).err().expect("plaintext was admitted");
        assert!(err.contains("no encryption"), "{err}");

        for q in [
            format!("sslmode=verify-full&sslrootcert={ca}"),
            format!("sslmode=require&sslrootcert={ca}"),
            format!("sslmode=verify-ca&sslrootcert={ca}"),
            // Percent-encoded, as a URL builder would write it.
            format!("sslmode=verify-full&sslrootcert={}", ca.replace('/', "%2F")),
        ] {
            let db = ControlDb::open(&format!("{url}?{q}")).unwrap_or_else(|e| panic!("{q}: {e}"));
            assert!(crate::registry::ping(&db).is_ok(), "{q}");
        }
        // The key=value form libpq also takes.
        let kv = format!(
            "host=127.0.0.1 port={} user=skein dbname={} sslmode=verify-full sslrootcert={ca}",
            pg.port,
            url.rsplit('/').next().unwrap()
        );
        ControlDb::open(&kv).unwrap_or_else(|e| panic!("{kv}: {e}"));

        // Not trusted: said so, with where the CA goes.
        let err = ControlDb::open(&format!("{url}?sslmode=require"))
            .err()
            .expect("a certificate nobody vouches for was accepted");
        assert!(
            err.contains("UnknownIssuer") && err.contains("SKEIN_CA_FILE"),
            "{err}"
        );

        // A certificate for another host: verify-full refuses it,
        // verify-ca (the chain, not the name) accepts it.
        let other = pki.server("other", &["elsewhere.acme.test"]);
        drop(pg);
        let pg = skein_testkit::pg::Pg::start_tls(&other).unwrap();
        let url = pg.database("tls_name");
        let err = ControlDb::open(&format!("{url}?sslmode=verify-full&sslrootcert={ca}"))
            .err()
            .expect("a certificate for another host was accepted");
        assert!(
            err.contains("NotValidForName") || err.contains("not valid for"),
            "{err}"
        );
        ControlDb::open(&format!("{url}?sslmode=verify-ca&sslrootcert={ca}")).unwrap();

        // An sslmode nobody supports is refused by name, not guessed at.
        let err = ControlDb::open(&format!("{url}?sslmode=verify_full"))
            .err()
            .unwrap();
        assert!(err.contains("sslmode=verify_full"), "{err}");
    }

    /// An install upgraded to the migration that gives blobs a
    /// `touched_at` keeps every blob it already holds, each aged by when
    /// it was stored — not made immortal by a NULL, not made collectable
    /// on the spot by a zero, and not refused by the `NOT NULL`.
    ///
    /// Found by content rather than by number, so the test still names
    /// the right migration if another is appended ahead of it in a merge.
    #[test]
    fn blobs_stored_before_touched_at_existed_are_aged_by_their_storage() {
        let url = skein_testkit::pg::test_db_url("db_touched_upgrade");
        let at = MIGRATIONS
            .iter()
            .position(|m| m.contains("ADD COLUMN touched_at"))
            .expect("the migration that adds touched_at");
        {
            let mut c = Client::connect(&url, NoTls).unwrap();
            c.batch_execute(
                "CREATE TABLE schema_migrations (
                    version BIGINT PRIMARY KEY, applied_at BIGINT NOT NULL)",
            )
            .unwrap();
            for (i, sql) in MIGRATIONS[..at].iter().enumerate() {
                c.batch_execute(sql).unwrap();
                c.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, 0)",
                    &[&((i + 1) as i64)],
                )
                .unwrap();
            }
            c.batch_execute(
                "INSERT INTO orgs (id, name, created_at) VALUES ('01ORG', 'acme', 1);
                 INSERT INTO package_blobs (org_id, digest, size_bytes, created_at)
                     VALUES ('01ORG', repeat('a', 64), 5, 1000),
                            ('01ORG', repeat('b', 64), 6, 9000);",
            )
            .unwrap();
        }

        let db = ControlDb::open(&url).expect("the upgrade applies to a table with rows in it");
        let rows = db
            .lock()
            .query(
                "SELECT created_at, touched_at FROM package_blobs ORDER BY digest",
                &[],
            )
            .unwrap();
        let ages: Vec<(i64, i64)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        assert_eq!(ages, vec![(1000, 1000), (9000, 9000)]);
        assert_eq!(
            crate::packages::unreferenced_blobs(&db, "01ORG", 5_000, 10).unwrap(),
            vec![("a".repeat(64), 5)]
        );
    }

    /// A failing migration says what was wrong with it.
    ///
    /// This is the first thing anybody reads when a release will not
    /// start, and it used to read `migration 28: db error` — which tells
    /// an operator nothing and tells whoever wrote the migration less.
    /// It cost a debugging cycle here within minutes of `detail`
    /// existing: a `PRIMARY KEY` over an expression, which Postgres
    /// refuses, reported as "db error" and diagnosed only after the
    /// message was fixed.
    ///
    /// Asserted through `apply_migrations` on a deliberately broken
    /// statement rather than by reading the format string, because the
    /// format string being right is not the claim — the claim is that
    /// the SQLSTATE reaches the operator.
    #[test]
    fn a_failing_migration_names_what_postgres_objected_to() {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url("db_migfail")).unwrap();
        let err = db
            .lock()
            .execute(
                "CREATE TABLE broken (a TEXT, PRIMARY KEY (COALESCE(a, a)))",
                &[],
            )
            .expect_err("an expression in a PRIMARY KEY must be refused");
        assert_eq!(err.to_string(), "db error", "the premise has changed");
        let named = detail(&err);
        assert!(named.contains("42601"), "no SQLSTATE in {named:?}");
        assert!(
            named.contains("syntax error"),
            "no reason in {named:?} — an operator has nothing to act on"
        );
    }

    /// `detail` exists because `postgres::Error`'s own `Display` renders
    /// every server-side failure as the literal string **"db error"**.
    /// That is not a hypothetical: it cost a debugging cycle on the
    /// issues tracker, where a real constraint failure surfaced as
    /// `set issue state: db error` and had to be reproduced by hand.
    ///
    /// So the test provokes a **real** constraint violation rather than
    /// asserting over a hand-made error. A fake would prove the
    /// formatting and not the thing that matters — that the message,
    /// the SQLSTATE and the constraint name are actually reachable from
    /// what Postgres hands back.
    #[test]
    fn a_database_error_says_what_went_wrong_rather_than_db_error() {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url("db_detail")).unwrap();
        let u = crate::users::create(
            &db,
            "ada",
            crate::users::Role::Reader,
            Some("a long enough password"),
        )
        .unwrap();

        // Same primary key twice.
        let err = db
            .lock()
            .execute(
                "INSERT INTO users (id, username, role, created_at) VALUES ($1, $2, $3, $4)",
                &[&u.id, &"other", &"reader", &0i64],
            )
            .expect_err("a duplicate primary key must fail");

        // The thing the plain `{e}` gives you, and the reason this
        // function exists.
        assert_eq!(err.to_string(), "db error");

        let d = detail(&err);
        assert!(d.contains("23505"), "no SQLSTATE in {d:?}");
        assert!(d.contains("users_pkey"), "no constraint name in {d:?}");
        assert_ne!(d, "db error");

        // An error with no `DbError` behind it — a connection failure
        // rather than a server-side refusal — falls back to Display
        // rather than losing the message.
        let conn = match Client::connect("postgres://127.0.0.1:1/nope", NoTls) {
            Ok(_) => panic!("something is listening on port 1"),
            Err(e) => e,
        };
        assert!(conn.as_db_error().is_none());
        assert_eq!(detail(&conn), conn.to_string());
    }

    /// `connection_lost` decides whether a failed statement is retried
    /// on a fresh connection or handed back as the server's answer, and
    /// its three arms each need their own evidence:
    ///
    /// * a transport failure the client has not yet recorded as
    ///   "closed" — the io-sourced shape the very first call on a
    ///   terminated session surfaces — is lost;
    /// * a server-side error, even one that announces the session is
    ///   ending, is an answer and is never retried (retrying a
    ///   constraint violation would be a bug, and retrying `FATAL
    ///   57P01` would re-run the statement the operator was stopping);
    /// * a session the client already knows is closed is lost.
    ///
    /// A refused connect carries its `io::Error` at a depth the harness
    /// can produce every time, which is why it stands in for the first
    /// arm rather than a terminated backend, whose shape depends on
    /// whether the client read the server's FIN before the next request.
    #[test]
    fn a_transport_failure_is_lost_and_a_server_answer_is_not() {
        let refused = match Client::connect("postgres://127.0.0.1:1/nope", NoTls) {
            Ok(_) => panic!("something is listening on port 1"),
            Err(e) => e,
        };
        assert!(!refused.is_closed(), "the premise has changed: {refused}");
        assert!(refused.as_db_error().is_none());
        assert!(
            connection_lost(&refused),
            "an io-sourced error is a lost connection"
        );

        let mut client =
            Client::connect(&skein_testkit::pg::test_db_url("db_lost"), NoTls).unwrap();
        let refusal = client
            .execute("SELECT 1 / 0", &[])
            .expect_err("division by zero is refused by the server");
        assert!(refusal.as_db_error().is_some());
        assert!(
            !connection_lost(&refusal),
            "a server-side answer is never retried"
        );

        // The server ends the session itself. The statement that asked
        // is answered (57P01, an answer, not a loss); everything after it
        // finds the session gone, by whichever of the two shapes the
        // client meets first.
        let ended = client
            .execute("SELECT pg_terminate_backend(pg_backend_pid())", &[])
            .expect_err("terminating your own backend ends the session");
        let answered = ended.as_db_error().map(|d| d.code().code()) == Some("57P01");
        let lost = connection_lost(&ended);
        assert!(answered || lost, "{}", detail(&ended));
        let after = client
            .execute("SELECT 1", &[])
            .expect_err("the session is gone");
        assert!(after.as_db_error().is_none(), "{}", detail(&after));
        assert!(connection_lost(&after), "{}", detail(&after));
    }
}
