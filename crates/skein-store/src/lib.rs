//! Skein's object-store client.
//!
//! Package bytes live in any S3-compatible bucket — AWS S3, MinIO,
//! Cloudflare R2, Ceph RGW — addressed by content. The surface is
//! deliberately small: GET (optionally ranged), PUT (optionally
//! conditional), LIST and DELETE, SigV4-signed when credentials are in
//! the environment.
//!
//! Carried over from `stratum-store`, where it serves the forge's
//! repositories; the latency models that crate carries for benchmarking
//! are not here.

pub mod sig;
pub mod store;

pub use store::{diagnose, is_absent, store_status, ObjectStore, PutCond, PutError};
