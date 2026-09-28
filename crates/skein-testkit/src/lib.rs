//! Hermetic test infrastructure for Skein.
//!
//! Everything here runs in-process or as local subprocesses with no
//! external credentials: a real PostgreSQL cluster per test process, a
//! real MinIO standing in for S3 (every request SigV4-signed, anonymous
//! access never relied on), and the real `skein` binary.
//!
//! Carried over from stratum-core's `stratum-testkit`, including the
//! lessons it paid for: port races that let a suite talk to somebody
//! else's server, and clusters that outlived their test binary.

pub(crate) mod detach;
pub mod fake_registry;
pub mod minio;
pub mod pg;
pub mod pki;
pub mod server;
pub(crate) mod tempdir;
pub mod wait;

pub use minio::{Bucket, Minio};
pub use server::{Reply, Server, ServerBuilder};
pub use wait::{wait_for, wait_until};
