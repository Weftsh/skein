//! Ed25519 public keys trusted to sign Weft licences, by `kid`.
//!
//! Compiled into every release. The matching private keys live only in
//! AWS KMS in Weft's billing account and never leave it — the same keys
//! Weft Sandboxes trusts (sandy's `packages/license/src/trusted-keys.ts`),
//! because the keys are the same keys.
//!
//! Adding or rotating a key: create an `ECC_NIST_EDWARDS25519` KMS key,
//! export its public key (`aws kms get-public-key`), add it here under a
//! new `kid`, and keep the old entry until every licence it signed has
//! expired. The release workflow refuses to publish while this is empty.

/// `(kid, PEM-encoded SPKI Ed25519 public key)`.
pub const RELEASE_SIGNING_KEYS: &[(&str, &str)] = &[];
