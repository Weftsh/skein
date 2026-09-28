//! Ed25519 public keys trusted to sign Weft licences, by `kid`.
//!
//! Compiled into every release. The matching private keys live only in
//! AWS KMS in Weft's billing account and never leave it. They are
//! Skein's own: Weft's license service (weftsh/license) signs each
//! product's keys with that product's KMS key under its own `kid`, so a
//! key signed for Weft Sandboxes names a `kid` this list does not have and
//! never verifies here, whatever its payload says.
//!
//! Adding or rotating a key: create an `ECC_NIST_EDWARDS25519` KMS key,
//! export its public key (`aws kms get-public-key`), add it here under a
//! new `kid`, and keep the old entry until every licence it signed has
//! expired. The release workflow refuses to publish while this is empty.

/// `(kid, PEM-encoded SPKI Ed25519 public key)`.
pub const RELEASE_SIGNING_KEYS: &[(&str, &str)] = &[];
