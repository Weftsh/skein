//! The testkit's own gate: MinIO starts, buckets are per-test, and every
//! request goes through the store's SigV4 path (no anonymous access).

use skein_store::{ObjectStore, PutCond, PutError};
use skein_testkit::Minio;

#[test]
fn signed_put_get_roundtrip_and_conditional_writes() {
    let minio = Minio::shared();
    let bucket = minio.bucket("smoke");
    let store = ObjectStore::new(&bucket.base_url);

    // Basic roundtrip.
    store.put("a/b/c.txt", b"hello", PutCond::None).unwrap();
    assert_eq!(store.get("a/b/c.txt").unwrap(), b"hello");

    // Range GET must be honored (invariant I13: 206 or fail loudly).
    let mut r = store.get_stream("a/b/c.txt", Some((1, 3))).unwrap();
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut r, &mut buf).unwrap();
    assert_eq!(buf, b"ell");

    // Create-only semantics.
    store
        .put("once.txt", b"first", PutCond::IfNoneMatchStar)
        .unwrap();
    match store.put("once.txt", b"second", PutCond::IfNoneMatchStar) {
        Err(PutError::Conflict) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }

    // CAS semantics.
    let (_, etag) = store.get_with_etag("once.txt").unwrap();
    store
        .put("once.txt", b"third", PutCond::IfMatch(etag))
        .unwrap();
    let (body, _) = store.get_with_etag("once.txt").unwrap();
    assert_eq!(body, b"third");
    match store.put(
        "once.txt",
        b"stale",
        PutCond::IfMatch("\"deadbeef\"".into()),
    ) {
        Err(PutError::Conflict) => {}
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[test]
fn buckets_are_isolated_per_test() {
    let minio = Minio::shared();
    let b1 = minio.bucket("iso1");
    let b2 = minio.bucket("iso2");
    let s1 = ObjectStore::new(&b1.base_url);
    let s2 = ObjectStore::new(&b2.base_url);
    s1.put("k", b"v1", PutCond::None).unwrap();
    assert!(s2.get("k").is_err());
}

#[test]
fn list_and_delete_roundtrip() {
    let minio = Minio::shared();
    let bucket = minio.bucket("listdel");
    let store = ObjectStore::new(&bucket.base_url);
    for i in 0..5 {
        store
            .put(&format!("e1/seg-{i}.bin"), b"x", PutCond::None)
            .unwrap();
    }
    store.put("e2/other.bin", b"y", PutCond::None).unwrap();
    let listed = store.list("e1/").unwrap();
    assert_eq!(listed.len(), 5);
    assert!(listed
        .iter()
        .all(|(k, lm)| k.starts_with("e1/") && !lm.is_empty()));
    store.delete("e1/seg-0.bin").unwrap();
    store.delete("e1/seg-0.bin").unwrap(); // idempotent
    assert_eq!(store.list("e1/").unwrap().len(), 4);
    assert_eq!(store.list("").unwrap().len(), 5);
}

/// `probe` fails on a bucket that does not exist — which a GET of an
/// absent key cannot tell from an absent key — and `ensure_bucket`
/// creates it, once.
#[test]
fn a_missing_bucket_fails_the_probe_and_ensure_bucket_creates_it() {
    let minio = Minio::shared();
    let url = format!("{}/t-never-made-{}", minio.endpoint, std::process::id());
    let store = ObjectStore::new(&url);

    // The premise: an absent key and an absent bucket look alike to GET.
    assert!(skein_store::is_absent(&store.get("x").unwrap_err()));
    let err = store
        .probe()
        .expect_err("a bucket that does not exist passed the probe");
    assert!(err.contains("not usable"), "{err}");

    assert!(store.ensure_bucket().unwrap(), "the bucket was not created");
    assert!(!store.ensure_bucket().unwrap(), "created twice");
    store.probe().expect("a fresh bucket is usable");

    // A URL with no bucket in its path is not ours to guess at.
    let bare = ObjectStore::new(&minio.endpoint);
    let err = bare.ensure_bucket().unwrap_err();
    assert!(err.contains("create the bucket yourself"), "{err}");
}

/// A URL that names no bucket lists the whole service, and that must not
/// read as an empty, usable bucket.
#[test]
fn a_url_with_no_bucket_is_not_a_usable_bucket() {
    let minio = Minio::shared();
    let err = ObjectStore::new(&minio.endpoint)
        .probe()
        .expect_err("the service root passed as a bucket");
    assert!(err.contains("does the URL name one"), "{err}");
}
