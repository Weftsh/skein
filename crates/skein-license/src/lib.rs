//! Skein's commercial licence.
//!
//! The same model as Weft Sandboxes (sandy's `packages/license`), and the
//! same keys: `weft_lic_v1.<payload>.<signature>`, Ed25519, verified
//! locally against public keys compiled into the release, issued by the
//! same `weft-license` tool. A Skein key says `"product": "skein"`, so a
//! key issued for another Weft product cannot pass as one.
//!
//! **A licence never stops Skein.** A missing, invalid, expired or
//! over-cap licence produces warnings — in the UI, the API and the log —
//! and never a refused install, publish or sign-in. There is deliberately
//! no "allowed" answer anywhere in this crate. Weft's enforcement levers
//! are release access and the contract.
//!
//! What a licence caps and reports is **seats**: people who can sign in.
//! A CI service account, which has no password and cannot sign in, is
//! not a seat.

pub mod check;
pub mod key;
pub mod status;
pub mod time;
pub mod trusted;

#[cfg(feature = "issue")]
pub mod issue;

pub use check::{CheckOptions, CheckOutcome, CheckRequest, CheckResponse, RemoteStatus};
pub use key::{verify, Mode, Payload, Rejected, Tier, TrustedKeys, VerifyFailure};
pub use status::{evaluate, EvaluateInput, LicenseState, LicenseStatus};
