//! The package registry: the organization's own packages, served to the
//! tools people already use.
//!
//! Layered so the parts that *decide* things are pure and can be argued
//! with in a unit test rather than against a live npm client:
//!
//! - `blobs` — bytes in the object store, content-addressed and verified.
//! - `npm` — the npm registry protocol, translated to the control plane.
//! - `spdx`, `policy` — the admission policy: what may enter from an
//!   upstream registry, decided per version.
//! - `upstream` — fetching from a public registry, and the rules that
//!   make it safe.
//!
//! ## Why the protocol adapters are thin
//!
//! Everything an adapter knows is the shape of one ecosystem's wire
//! format. Naming, validation, immutability and ownership all live in
//! `skein_control::packages`, so five adapters cannot drift into five
//! different answers about what a package *is*. An adapter that
//! normalised a name itself would be an adapter that could admit a
//! second row for a name another adapter already owns.
//!
//! ## Why there is no API of our own to publish with
//!
//! The whole promise is that existing tooling works: an `.npmrc`, a
//! `settings.xml`, a `pip.conf`. That is why this module answers each
//! ecosystem's own wire protocol rather than offering an API somebody
//! would then have to write a plugin against.

pub mod blobs;
pub mod npm;
pub mod policy;
pub mod spdx;
pub mod upstream;
