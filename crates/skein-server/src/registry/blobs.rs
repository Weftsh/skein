//! Package bytes in the object store: content-addressed, verified on the
//! way in, streamed on the way out.
//!
//! One artifact is one object at `o/<org>/pkg/<sha256>`, and the key can
//! only be built through [`skein_control::PackagePrefix`]. Nothing in
//! this module formats a key itself.
//!
//! ## Nothing becomes addressable before its digest is checked
//!
//! [`put`] hashes what arrived and refuses if it is not what the client
//! said it was uploading. A registry that stores whatever bytes turn up
//! under whatever name the uploader claims is a registry where anybody
//! who can publish once can substitute the contents of a package
//! everybody else already trusts. The digest is the name, so the digest
//! has to be true.
//!
//! The check is also what makes the **store** the tie-breaker rather
//! than the database. Two publishes of identical bytes race to write the
//! same key; both compute the same digest, both write the same object,
//! and neither can corrupt the other, because the content decides the
//! key. There is nothing to serialise.
//!
//! ## Size, and the two shapes a blob has
//!
//! `ObjectStore::put` takes a slice — there is no streaming PUT and no
//! multipart upload — so one object must fit in memory,
//! and [`MAX_ARTIFACT`] is the ceiling. That is comfortable for a
//! tarball, a wheel, a jar or a crate, all of which are single-digit
//! megabytes in the ordinary case and tens of megabytes at worst.
//!
//! It is **not** enough for an OCI layer, which routinely runs to
//! hundreds of megabytes and arrives as a single request body. So a
//! large blob is an ordered list of **blocks**, each one an ordinary
//! content-addressed object in the same key-space, cut out of the
//! request as it streams in — nothing bigger than [`BLOCK`] is ever
//! resident, on the way in or out.
//!
//! A blob has one shape or the other and the caller never chooses:
//! [`get`] asks for a block list first and falls back to the single
//! object, so a blocked blob cannot be addressed the wrong way and read
//! back as absent.

use skein_control::PackagePrefix;
use skein_store::{ObjectStore, PutCond};

/// The largest single artifact the registry accepts.
///
/// npm's own registry refuses a tarball over a few hundred megabytes and
/// nothing in the four tarball ecosystems approaches this in practice; a
/// package this size is nearly always somebody having committed a build
/// directory. The number is here rather than at each door so that all
/// four agree, and so the axum body limit and the check can be read
/// beside each other.
pub const MAX_ARTIFACT: usize = 128 * 1024 * 1024;

/// Why a blob write was refused.
#[derive(Debug)]
pub enum BlobError {
    /// The bytes are not what the uploader said they were. Always the
    /// client's fault and never retryable, so it must not be answered
    /// with a 5xx that invites a retry loop.
    DigestMismatch {
        expected: String,
        got: String,
    },
    /// Over [`MAX_ARTIFACT`].
    TooLarge {
        size: usize,
    },
    Store(String),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::DigestMismatch { expected, got } => write!(
                f,
                "the upload does not match its digest: it said sha256:{expected} \
                 and the bytes are sha256:{got}"
            ),
            BlobError::TooLarge { size } => write!(
                f,
                "that artifact is {size} bytes, and the limit is {MAX_ARTIFACT}"
            ),
            BlobError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// The digest of these bytes, as bare lowercase hex — the spelling
/// [`skein_control::packages::normalize_digest`] stores.
pub fn digest_of(body: &[u8]) -> String {
    skein_store::sig::sha256_hex(body)
}

/// Store one artifact under its own digest, after proving that is its
/// digest.
///
/// `expected` is what the client claimed, already normalised to bare
/// hex. Returns the digest, which is the same value — returned so a
/// caller that trusted the client's spelling cannot accidentally go on
/// using it.
///
/// Idempotent by construction: the key is the content, so re-uploading
/// identical bytes overwrites an identical object. `PutCond::None` and
/// not `IfNoneMatchStar` deliberately — a conditional create would make
/// the *second* publisher of identical bytes fail, and "somebody else
/// already uploaded these exact bytes" is not an error, it is the
/// deduplication working.
pub fn put(
    store_url: &str,
    prefix: &PackagePrefix,
    expected: &str,
    body: &[u8],
) -> Result<String, BlobError> {
    if body.len() > MAX_ARTIFACT {
        return Err(BlobError::TooLarge { size: body.len() });
    }
    let got = digest_of(body);
    if got != expected {
        return Err(BlobError::DigestMismatch {
            expected: expected.to_string(),
            got,
        });
    }
    let key = prefix.blob(&got);
    ObjectStore::new(store_url)
        .put(&key, body, PutCond::None)
        .map_err(|e| BlobError::Store(format!("package put {key}: {e:?}")))?;
    Ok(got)
}

/// Read one artifact back whole.
///
/// Single object or blocked, the caller does not say and cannot get it
/// wrong: the block list decides. Whole, so this is for things that fit
/// — a manifest, a tarball, a wheel. A layer is read through
/// [`stream`], which never holds more than one block.
pub fn get(store_url: &str, prefix: &PackagePrefix, digest: &str) -> Result<Vec<u8>, String> {
    let key = prefix.blob(digest);
    ObjectStore::new(store_url).get(&key)
}

/// Delete one artifact. Idempotent, like every other delete against the
/// store — the collector calls this after re-checking that nothing
/// references the digest, and a key already gone is the outcome it
/// wanted.
pub fn delete(store_url: &str, prefix: &PackagePrefix, digest: &str) -> Result<(), String> {
    let key = prefix.blob(digest);
    ObjectStore::new(store_url).delete(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is the key, so a lie about the digest is refused
    /// before anything is written. Without this, one publisher could
    /// substitute the bytes of a package everybody already trusts.
    #[test]
    fn bytes_that_do_not_match_their_digest_are_refused_before_any_write() {
        // A store URL that could not possibly answer: if the check were
        // ordered after the write, this test would fail with a connection
        // error rather than a mismatch, which is exactly the regression
        // worth catching.
        let org = skein_control::registry::Org {
            id: "01ORG".into(),
            name: "acme".into(),
            created_at: 0,
        };
        let prefix = org.package_prefix();
        let body = b"the real bytes";
        let lie = "b".repeat(64);

        let err = put("http://127.0.0.1:1", &prefix, &lie, body).unwrap_err();
        match err {
            BlobError::DigestMismatch { expected, got } => {
                assert_eq!(expected, lie);
                assert_eq!(got, digest_of(body));
                assert_ne!(got, lie);
            }
            other => panic!("expected a digest mismatch, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_artifact_is_refused_before_it_is_hashed() {
        let org = skein_control::registry::Org {
            id: "01ORG".into(),
            name: "acme".into(),
            created_at: 0,
        };
        let body = vec![0u8; MAX_ARTIFACT + 1];
        let err = put(
            "http://127.0.0.1:1",
            &org.package_prefix(),
            &digest_of(&body),
            &body,
        )
        .unwrap_err();
        assert!(matches!(err, BlobError::TooLarge { size } if size == MAX_ARTIFACT + 1));
    }

    /// Every refusal is a sentence somebody has to act on, so each says
    /// which of the two things went wrong and what the numbers were.
    #[test]
    fn each_refusal_names_what_was_wrong_with_it() {
        let mismatch = BlobError::DigestMismatch {
            expected: "aa".into(),
            got: "bb".into(),
        }
        .to_string();
        assert!(mismatch.contains("sha256:aa"), "{mismatch}");
        assert!(mismatch.contains("sha256:bb"), "{mismatch}");

        let big = BlobError::TooLarge { size: 999 }.to_string();
        assert!(big.contains("999"), "{big}");
        assert!(big.contains(&MAX_ARTIFACT.to_string()), "{big}");

        assert_eq!(
            BlobError::Store("bucket gone".into()).to_string(),
            "bucket gone"
        );
    }

    /// The key is the content and the organization, and nothing else —
    /// which is what makes two publishes of identical bytes a race
    /// nobody can lose.
    #[test]
    fn the_key_is_the_organization_and_the_digest() {
        let org = |id: &str| skein_control::registry::Org {
            id: id.into(),
            name: "acme".into(),
            created_at: 0,
        };
        let hex = "a".repeat(64);
        let mine = org("01ONE").package_prefix();
        assert_eq!(mine.blob(&hex), format!("o/01ONE/pkg/{hex}"));
        // Both spellings of a digest land on one key.
        assert_eq!(mine.blob(&format!("sha256:{hex}")), mine.blob(&hex));
        // …and another organization's identical bytes are a different key.
        assert_ne!(mine.blob(&hex), org("01TWO").package_prefix().blob(&hex));
    }
}
