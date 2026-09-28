//! The collector: package bytes nothing references any more, and upload
//! sessions nobody finished.
//!
//! Carried over from stratum-core's `workers/gc.rs`. Mark-sweep, not
//! refcounting:
//!
//! * **The grace window is load-bearing, not politeness.** A publish
//!   writes its object and *then* its `package_files` row, and a
//!   `docker push` is told a layer is here and *then* sends the manifest
//!   naming it — so a blob used seconds ago and not yet referenced is a
//!   publish in flight. Collecting it would delete the bytes of a
//!   version that is about to become visible.
//! * **The grace runs from the last use, not the first storage.**
//!   Content addressing means the bytes a push relies on may be bytes an
//!   untagged image left behind a week ago. Measured from when they were
//!   first stored — as it once was — the window protected nothing for
//!   them: a sweep between a HEAD answered 200 and the manifest took the
//!   layer, and the push failed or was accepted naming a layer that was
//!   gone. Every use moves `touched_at` — storing, storing again, a
//!   HEAD, a mount, a manifest's check (`packages::touch_blob`) — and
//!   that is what the window is measured from.
//! * **Both halves are re-read immediately before the delete.** The
//!   listing is a snapshot: a publish can name the digest during the
//!   sweep, and a client can be told it is here and start building on
//!   it. `packages::collectable` asks both; re-reading only the
//!   reference lost the second.
//!
//! What the re-read cannot close is a use that lands between it and the
//! delete: a window one object-store delete wide, the same one the
//! reference check has always had. Closing it would take a claim the
//! collector writes as its re-check and every use respects.
//!
//! The row is forgotten only after the object is gone, so a crash in
//! between leaves a row whose object is missing — which the next pass
//! deletes again harmlessly — rather than an object no row remembers,
//! which nothing would ever find.
//!
//! Two nodes sweeping at once is safe for the same reasons: every delete
//! is re-checked and idempotent.

use crate::app::{AppState, SharedState};
use skein_control::{packages, PackagePrefix};

/// How many unreferenced blobs one pass considers. What it does not
/// reach this pass, it reaches the next.
const BATCH: i64 = 500;

/// How long an untouched upload session is left alone. A `docker push`
/// of a large image can sit between requests for a while; what this
/// protects against is not a slow push but a table that only grows.
const UPLOAD_GRACE_MS: i64 = 24 * 60 * 60 * 1000;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Swept {
    pub blobs: usize,
    pub bytes: i64,
    pub uploads: usize,
}

/// Start the periodic collector: every `SKEIN_GC_INTERVAL_SECS` (default
/// an hour, `0` switches it off), collecting what nothing references and
/// nobody has used for at least `SKEIN_GC_GRACE_SECS` (default an hour).
pub fn spawn(state: SharedState) {
    let every = env_secs("SKEIN_GC_INTERVAL_SECS", 3600);
    if every == 0 {
        return;
    }
    let grace = env_secs("SKEIN_GC_GRACE_SECS", 3600);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(every));
        tick.tick().await;
        loop {
            tick.tick().await;
            // An install that has not been bootstrapped has nothing to
            // collect; `org()` would panic before it has one.
            match skein_control::registry::the_org(&state.db) {
                Ok(Some(_)) => {}
                _ => continue,
            }
            let st = state.clone();
            match tokio::task::spawn_blocking(move || sweep(&st, grace)).await {
                Ok(Ok(s)) if s != Swept::default() => eprintln!(
                    "skein: gc collected {} blob(s), {} byte(s), {} abandoned upload(s)",
                    s.blobs, s.bytes, s.uploads
                ),
                Ok(Ok(_)) => {}
                Ok(Err(e)) => eprintln!("skein: gc: {e}"),
                Err(e) => eprintln!("skein: gc: join: {e}"),
            }
        }
    });
}

fn env_secs(var: &str, default: u64) -> u64 {
    std::env::var(var)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

/// One pass, blocking. Also what `skein admin gc` runs.
pub fn sweep(state: &SharedState, grace_secs: u64) -> Result<Swept, String> {
    let org = state.org();
    let mut out = Swept::default();
    let prefix = org.package_prefix();
    let before = skein_control::ids::now_ms() - grace_secs as i64 * 1000;

    for (digest, size) in packages::unreferenced_blobs(&state.db, &org.id, before, BATCH)? {
        if collect(state, &org.id, &prefix, &digest, before)? {
            out.blobs += 1;
            out.bytes += size;
        }
    }

    // Upload sessions nobody finished, **and their blocks** — objects
    // with no `package_blobs` row, which the sweep above never sees.
    let stale = packages::stale_uploads(
        &state.db,
        skein_control::ids::now_ms() - UPLOAD_GRACE_MS,
        BATCH,
    )?;
    for up in stale {
        if up.org_id != org.id {
            continue;
        }
        for b in &up.blocks {
            // A block a dead session wrote may be exactly the block a
            // finished blob deduped against.
            if packages::block_referenced(&state.db, &org.id, &b.block, &up.id)? {
                continue;
            }
            crate::registry::blobs::delete(&state.store_url, &prefix, &b.block)?;
        }
        packages::finish_upload(&state.db, &org.id, &up.id)?;
        out.uploads += 1;
    }
    Ok(out)
}

/// Delete one blob the listing found — unless, since the listing,
/// something has named it or somebody has been told it is here. Whether
/// it was deleted.
fn collect(
    state: &AppState,
    org_id: &str,
    prefix: &PackagePrefix,
    digest: &str,
    before: i64,
) -> Result<bool, String> {
    // The listing is a snapshot. A publish may have named this digest
    // since, or a HEAD, a mount or a manifest's check may have told a
    // client it is here — and the client is building on that answer.
    if !packages::collectable(&state.db, org_id, digest, before)? {
        return Ok(false);
    }
    // A blob is one object or a list of blocks, and the shape is not
    // the collector's to know: it asks for the blocks and deletes
    // whichever it finds. Without this a large layer would be
    // "collected" by deleting a key that never existed, and its
    // blocks would stay in the bucket for ever.
    let blocks = packages::blocks_of(&state.db, org_id, digest)?;
    if blocks.is_empty() {
        crate::registry::blobs::delete(&state.store_url, prefix, digest)?;
    } else {
        for b in &blocks {
            // Blocks dedupe across blobs: two images sharing a base
            // layer share its blocks.
            if packages::block_referenced_elsewhere(&state.db, org_id, &b.block, digest)? {
                continue;
            }
            crate::registry::blobs::delete(&state.store_url, prefix, &b.block)?;
        }
    }
    // The block list goes **after** the blocks themselves, so a crash
    // between the two leaves orphaned objects the next pass finds
    // rather than a list pointing at nothing.
    packages::forget_blocks(&state.db, org_id, digest)?;
    packages::forget_blob(&state.db, org_id, digest)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::blobs;
    use skein_store::ObjectStore;

    /// The re-check before the delete sees a client that was told a
    /// blob is here *after* the listing, and leaves the blob alone.
    ///
    /// The listing is a snapshot. A sweep that re-read only the
    /// reference — as this one did — deleted a layer a `docker push` had
    /// been answered 200 for a moment earlier, because nothing names a
    /// layer until the manifest arrives. Two old, unreferenced blobs;
    /// one is asked about between the listing and the delete; only the
    /// other goes, from the store and from the table.
    #[test]
    fn a_blob_used_after_the_listing_is_not_deleted() {
        let db = skein_control::ControlDb::open(&skein_testkit::pg::test_db_url("gc-recheck"))
            .expect("open control db");
        let org = skein_control::registry::create_org(&db, "acme").expect("org");
        let bucket = skein_testkit::Minio::shared().bucket("gc-recheck");
        let state = AppState::new(
            db,
            bucket.base_url.clone(),
            "http://127.0.0.1".into(),
            crate::license::Licensing::from_env().expect("licensing"),
        );
        let prefix = org.package_prefix();

        let asked: &[u8] = b"bytes a client is told are here";
        let idle: &[u8] = b"bytes nobody asks about";
        for bytes in [asked, idle] {
            let d = blobs::put(&state.store_url, &prefix, &blobs::digest_of(bytes), bytes)
                .expect("put");
            packages::note_blob(&state.db, &org.id, &d, bytes.len() as i64, 10).expect("note");
        }
        let before = 1_000;
        let listed = packages::unreferenced_blobs(&state.db, &org.id, before, BATCH).unwrap();
        assert_eq!(listed.len(), 2, "{listed:?}");

        // Between the listing and the delete, a HEAD answers 200 for one.
        assert!(
            packages::touch_blob(&state.db, &org.id, &blobs::digest_of(asked), 5_000)
                .unwrap()
                .is_some()
        );

        let mut taken = Vec::new();
        for (d, _) in &listed {
            if collect(&state, &org.id, &prefix, d, before).unwrap() {
                taken.push(d.clone());
            }
        }
        assert_eq!(taken, vec![blobs::digest_of(idle)]);

        let store = ObjectStore::new(&state.store_url);
        assert!(
            store.get(&prefix.blob(&blobs::digest_of(asked))).is_ok(),
            "the collector deleted bytes a client had just been told were here"
        );
        assert!(
            packages::blob_exists(&state.db, &org.id, &blobs::digest_of(asked))
                .unwrap()
                .is_some()
        );
        assert!(store.get(&prefix.blob(&blobs::digest_of(idle))).is_err());
        assert!(
            packages::blob_exists(&state.db, &org.id, &blobs::digest_of(idle))
                .unwrap()
                .is_none()
        );
    }

    /// A block an unfinished upload holds is in use, whichever way the
    /// collector comes at it: collecting an old blob that shares it, or
    /// sweeping another, abandoned session that wrote it too.
    ///
    /// Blocks are content-addressed, so re-pushing a large layer writes
    /// the very block keys its old blob had. The collector looked only at
    /// finished blobs' block lists, and deleted the new push's blocks
    /// under it.
    #[test]
    fn a_block_an_unfinished_upload_holds_is_not_deleted() {
        let db = skein_control::ControlDb::open(&skein_testkit::pg::test_db_url("gc-blocks"))
            .expect("open control db");
        let org = skein_control::registry::create_org(&db, "acme").expect("org");
        let bucket = skein_testkit::Minio::shared().bucket("gc-blocks");
        let state = std::sync::Arc::new(AppState::new(
            db,
            bucket.base_url.clone(),
            "http://127.0.0.1".into(),
            crate::license::Licensing::from_env().expect("licensing"),
        ));
        let prefix = org.package_prefix();
        let store = ObjectStore::new(&state.store_url);
        let block = |bytes: &[u8]| {
            let d = blobs::put(&state.store_url, &prefix, &blobs::digest_of(bytes), bytes)
                .expect("put");
            packages::Block {
                block: d,
                size_bytes: bytes.len() as i64,
            }
        };
        let now = skein_control::ids::now_ms();

        // An old, unreferenced blob of one block; a push in flight has
        // just written the same block.
        let shared = block(b"a block an old layer and a new push share");
        let old_layer = blobs::digest_of(b"the old layer, as a whole");
        packages::note_blocked_blob(
            &state.db,
            &org.id,
            &old_layer,
            std::slice::from_ref(&shared),
            10,
        )
        .unwrap();
        let live = packages::start_upload(&state.db, &org.id, "team/app", now).unwrap();
        packages::extend_upload(
            &state.db,
            &org.id,
            &live.id,
            std::slice::from_ref(&shared),
            now,
        )
        .unwrap();
        assert!(collect(&state, &org.id, &prefix, &old_layer, 1_000).unwrap());
        assert!(
            store.get(&prefix.blob(&shared.block)).is_ok(),
            "collecting an old blob deleted a block a push in flight holds"
        );

        // An abandoned session: its own block goes, and a block the live
        // session also holds stays.
        let own = block(b"a block only the abandoned session wrote");
        let dead = packages::start_upload(&state.db, &org.id, "team/app", 1).unwrap();
        packages::extend_upload(
            &state.db,
            &org.id,
            &dead.id,
            &[own.clone(), shared.clone()],
            1,
        )
        .unwrap();
        assert!(
            state.ready().unwrap(),
            "the org loads, as the setup layer would"
        );
        let swept = sweep(&state, 3600).unwrap();
        assert_eq!(swept.uploads, 1, "{swept:?}");
        assert!(
            store.get(&prefix.blob(&own.block)).is_err(),
            "the dead session's block stayed"
        );
        assert!(
            store.get(&prefix.blob(&shared.block)).is_ok(),
            "sweeping an abandoned session deleted a block a live one holds"
        );
    }
}
