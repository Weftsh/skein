//! Skein's control plane: the relational truth beside the object store.
//!
//! PostgreSQL behind one process-wide handle. Package *bytes* live in
//! object storage; this database holds what was published, by whom and
//! under which licence, the admission policy and what it caught, and the
//! people and credentials that may reach the registry. The `ControlDb`
//! surface is deliberately narrow: modules speak SQL through it, nothing
//! else does.
//!
//! Carved out of stratum-core's `stratum-control`. The package modules
//! are that crate's, nearly line for line; identity is new, because a
//! self-hosted registry serves one organization and has no forge around
//! it to borrow people from.

pub mod audit;
pub mod auth;
pub mod db;
pub mod ids;
pub mod packages;
pub mod registry;
pub mod sessions;
pub mod users;

pub use db::ControlDb;
pub use registry::{Org, PackagePrefix};

/// Lowercase hex of a byte string. One copy, because every digest in the
/// tree is rendered with it and two renderings would be two chances to
/// disagree about case.
pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}
