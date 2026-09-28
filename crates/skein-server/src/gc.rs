//! The collector: package bytes nothing references any more, and upload
//! sessions nobody finished.
//!
//! Carried over from stratum-core's `workers/gc.rs`. Mark-sweep, not
//! refcounting:
//!
//! * **The grace window is load-bearing, not politeness.** A publish
//!   writes its object and *then* its `package_files` row, so a blob
//!   uploaded seconds ago and not yet referenced is a publish in flight.
//!   Collecting it would delete the bytes of a version that is about to
//!   become visible.
//! * **The reference is re-read immediately before the delete.** The
//!   listing is a snapshot; a publish that lands during the sweep can
//!   dedupe against a digest this pass already decided was garbage. The
//!   second read is what stops that publish from losing its bytes.
//!
//! The row is forgotten only after the object is gone, so a crash in
//! between leaves a row whose object is missing — which the next pass
//! deletes again harmlessly — rather than an object no row remembers,
//! which nothing would ever find.
//!
//! Two nodes sweeping at once is safe for the same reasons: every delete
//! is re-checked and idempotent.

use crate::app::SharedState;
use skein_control::packages;

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
/// an hour, `0` switches it off), collecting what has been unreferenced
/// for at least `SKEIN_GC_GRACE_SECS` (default an hour).
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
        // Somebody published against it between the listing and now.
        if packages::blob_referenced(&state.db, &org.id, &digest)? {
            continue;
        }
        // A blob is one object or a list of blocks, and the shape is not
        // the collector's to know: it asks for the blocks and deletes
        // whichever it finds. Without this a large layer would be
        // "collected" by deleting a key that never existed, and its
        // blocks would stay in the bucket for ever.
        let blocks = packages::blocks_of(&state.db, &org.id, &digest)?;
        if blocks.is_empty() {
            crate::registry::blobs::delete(&state.store_url, &prefix, &digest)?;
        } else {
            for b in &blocks {
                // Blocks dedupe across blobs: two images sharing a base
                // layer share its blocks.
                if packages::block_referenced_elsewhere(&state.db, &org.id, &b.block, &digest)? {
                    continue;
                }
                crate::registry::blobs::delete(&state.store_url, &prefix, &b.block)?;
            }
        }
        // The block list goes **after** the blocks themselves, so a crash
        // between the two leaves orphaned objects the next pass finds
        // rather than a list pointing at nothing.
        packages::forget_blocks(&state.db, &org.id, &digest)?;
        packages::forget_blob(&state.db, &org.id, &digest)?;
        out.blobs += 1;
        out.bytes += size;
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
            if packages::block_referenced(&state.db, &org.id, &b.block)? {
                continue;
            }
            crate::registry::blobs::delete(&state.store_url, &prefix, &b.block)?;
        }
        packages::finish_upload(&state.db, &org.id, &up.id)?;
        out.uploads += 1;
    }
    Ok(out)
}
