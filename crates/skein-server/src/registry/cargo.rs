//! Cargo's sparse index and its length-prefixed publish body.
//!
//! ## The publish body is framed, not JSON
//!
//! `cargo publish` sends one request whose body is:
//!
//! ```text
//! [u32 LE json length][json metadata][u32 LE crate length][.crate bytes]
//! ```
//!
//! Nothing else in this tree reads a framed body, and it is the one
//! place a registry can be made to allocate a gigabyte from four bytes.
//! [`parse_publish`] therefore checks each length against what is
//! actually left in the buffer *before* using it, rather than trusting
//! the frame and discovering the problem in the allocator.
//!
//! ## The index is one file per crate, and the path is a hash of nothing
//!
//! Cargo derives a crate's index path from its name by length:
//! `a` → `1/a`, `ab` → `2/ab`, `abc` → `3/a/abc`, and everything longer
//! → `ab/cd/abcdef`. It is not a hash and it is not configurable; a
//! registry that laid the index out any other way is one `cargo` cannot
//! read.
//!
//! ## `auth-required`
//!
//! A private registry has to set `"auth-required": true` in
//! `config.json`. Without it Cargo does not send a credential when
//! fetching the index, so every request arrives anonymous and a private
//! registry answers 401 to a client that had a perfectly good token and
//! never offered it.
//!
//! ## The publish body and the index describe a dependency differently
//!
//! They are two formats, not one format sent twice. `cargo publish`
//! names a dependency's version requirement `version_req` and a renamed
//! dependency's local name `explicit_name_in_toml`, beside the crate's
//! real `name`; the index calls the requirement `req`, puts the local
//! name in `name` and the real one in `package`. A registry that echoed
//! the publish's dependencies into the index — which is what this door
//! did until the real client was run against it — writes a line with no
//! `req`, and Cargo reads it as "version 1.4.0's index entry is invalid"
//! for every crate that has a dependency at all. `cargo publish` itself
//! still succeeds (it only warns that the new version never appeared),
//! so the first person to find out is whoever depends on it.
//!
//! So a publish's dependencies are parsed into [`PublishDep`], which
//! refuses one without a requirement at the door, and every index line
//! restates them with [`PublishDep::in_index`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where in the index a crate's file lives.
///
/// By name length, which is Cargo's rule and not ours. Lower-cased,
/// because Cargo lower-cases before building the path and a registry
/// that did not would have `Serde` and `serde` in two places.
pub fn index_prefix(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    // Counted and sliced in **bytes**, deliberately. A crate name is
    // ASCII — Cargo says so and `packages::normalize_name` refuses
    // anything else — and counting in `chars` while slicing in bytes is
    // how a non-ASCII name that slipped through panics on a slice
    // boundary rather than 404ing.
    let b = n.as_bytes();
    if !b.is_ascii() {
        return String::new();
    }
    match b.len() {
        0 => String::new(),
        1 => format!("1/{n}"),
        2 => format!("2/{n}"),
        3 => format!("3/{}/{n}", &n[..1]),
        _ => format!("{}/{}/{n}", &n[..2], &n[2..4]),
    }
}

/// One line of a crate's index file.
///
/// Newline-delimited JSON, one object per version, in publication
/// order. Cargo reads every line and picks; the order is not load
/// bearing, but a stable one makes the file diffable and makes a
/// conditional GET actually hit.
pub fn index_line(
    name: &str,
    version: &str,
    cksum: &str,
    yanked: bool,
    declared: &Declared,
) -> String {
    let mut line = serde_json::json!({
        "name": name,
        "vers": version,
        // Restated in the index's own words — see the module docs —
        // but nothing added and nothing dropped: Cargo resolves against
        // exactly what the publisher declared.
        "deps": declared.deps.iter().map(PublishDep::in_index).collect::<Vec<_>>(),
        // Echoed. Cargo merges `features2` into these on read, so a
        // `dep:` or `?` value here reads the same to every Cargo that
        // understands those at all; the split crates.io makes exists
        // only so a Cargo older than 1.60 skips the line quietly.
        "features": declared.features,
        // The SHA-256 of the `.crate` file, hex and unprefixed, which
        // is what Cargo verifies the download against.
        "cksum": cksum.trim_start_matches("sha256:"),
        "yanked": yanked,
        // What the publisher declared, not `null`: the resolver refuses
        // two crates that link the same native library, and it can only
        // do that if the index says which one this crate links.
        "links": declared.links,
    });
    // Only when declared, which is how the index spells "no minimum" —
    // Cargo's MSRV-aware resolver reads it to prefer a version the
    // consumer's toolchain can build.
    if let Some(rv) = &declared.rust_version {
        line["rust_version"] = serde_json::json!(rv);
    }
    line.to_string()
}

/// What a publish declares that a resolver needs, kept on the version
/// row so the index line can be rebuilt from it on every read.
///
/// Stored in the publish's own words; [`index_line`] restates it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct Declared {
    #[serde(default)]
    pub deps: Vec<PublishDep>,
    #[serde(default)]
    pub features: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub links: Option<String>,
    #[serde(default)]
    pub rust_version: Option<String>,
}

/// One dependency, as `cargo publish` declares it.
///
/// Typed rather than carried as JSON so that a publish whose dependency
/// has no requirement is refused at the door, instead of becoming an
/// index line no Cargo can read.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct PublishDep {
    /// The crate's real name, even when the dependency is renamed.
    pub name: String,
    /// `req` in the index.
    pub version_req: String,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default = "yes")]
    pub default_features: bool,
    #[serde(default)]
    pub target: Option<String>,
    /// `normal`, `dev` or `build`. Absent is `normal`.
    #[serde(default)]
    pub kind: Option<String>,
    /// The index URL of another registry. Absent — which is what Cargo
    /// sends for a dependency on this same registry — means this one,
    /// in the publish body and in the index alike.
    #[serde(default)]
    pub registry: Option<String>,
    /// The name the depending crate uses, when it renamed the
    /// dependency with `package = "…"`.
    #[serde(default)]
    pub explicit_name_in_toml: Option<String>,
}

fn yes() -> bool {
    true
}

impl PublishDep {
    /// This dependency as an index line states it.
    ///
    /// A renamed dependency is the one that differs most: the index's
    /// `name` is the name the depending crate *uses* and `package` is
    /// the crate it really is. Swapped, Cargo looks for the wrong crate,
    /// or finds the right one and compiles it under a name the code
    /// does not use.
    pub fn in_index(&self) -> serde_json::Value {
        let (name, package) = match self.explicit_name_in_toml.as_deref() {
            Some(local) => (local, Some(self.name.as_str())),
            None => (self.name.as_str(), None),
        };
        let mut d = serde_json::json!({
            "name": name,
            "req": self.version_req,
            "features": self.features,
            "optional": self.optional,
            "default_features": self.default_features,
            "target": self.target,
            "kind": self.kind.as_deref().unwrap_or("normal"),
        });
        if let Some(r) = &self.registry {
            d["registry"] = serde_json::json!(r);
        }
        if let Some(p) = package {
            d["package"] = serde_json::json!(p);
        }
        d
    }
}

/// `config.json`, the first thing Cargo fetches.
pub fn config_json(dl: &str, api: &str) -> String {
    serde_json::json!({
        // No markers, so Cargo appends `/{crate}/{version}/download`.
        // Spelling the markers out would let the path drift from the
        // route that serves it.
        "dl": dl,
        "api": api,
        // Without this Cargo sends no credential when it fetches the
        // index, and a private registry answers 401 to a client holding
        // a perfectly good token it never offered.
        "auth-required": true,
    })
    .to_string()
}

/// What `cargo publish` declares about the crate it is sending.
#[derive(Debug, Clone, Deserialize)]
pub struct Metadata {
    pub name: String,
    pub vers: String,
    /// Already SPDX by Cargo's own rule — `license` in `Cargo.toml` is
    /// documented as an SPDX 2.1 expression, which is the only
    /// ecosystem of the five where that is true.
    ///
    /// Cargo also sends `license_file`, a path to a licence *inside*
    /// the archive, used when the licence is not one SPDX names. It is
    /// deliberately not read: deciding anything from it means opening
    /// the archive and fingerprinting the file, which this door does
    /// not do, and "the licence is in a file we did not read" is
    /// honestly `unknown` rather than a licence.
    pub license: Option<String>,
    /// Everything the index line is rebuilt from.
    #[serde(flatten)]
    pub declared: Declared,
}

/// A parsed publish request.
#[derive(Debug)]
pub struct Publish {
    pub metadata: Metadata,
    pub crate_file: Vec<u8>,
}

/// The largest metadata document a publish may carry.
///
/// The crate file has the store's own ceiling; this is separate and far
/// smaller, because the metadata is JSON we parse into memory and a
/// crate's dependency list is measured in kilobytes. Four bytes of
/// length should never be able to ask for more than that.
pub const MAX_METADATA: usize = 4 * 1024 * 1024;

/// Read `cargo publish`'s framed body.
///
/// Every length is checked against what is actually left before it is
/// used. A registry that trusted the frame would let four bytes ask for
/// a gigabyte, and the failure would be an allocation rather than a 400.
pub fn parse_publish(body: &[u8]) -> Result<Publish, String> {
    let take_len = |at: usize| -> Result<usize, String> {
        if body.len() < at + 4 {
            return Err("that is not a cargo publish body: it ends inside a length".into());
        }
        let n = u32::from_le_bytes([body[at], body[at + 1], body[at + 2], body[at + 3]]) as usize;
        if body.len() < at + 4 + n {
            return Err(format!(
                "that is not a cargo publish body: it declares {n} bytes and {} remain",
                body.len() - at - 4
            ));
        }
        Ok(n)
    };

    let json_len = take_len(0)?;
    if json_len > MAX_METADATA {
        return Err(format!(
            "the publish metadata is {json_len} bytes, and the limit is {MAX_METADATA}"
        ));
    }
    let json = &body[4..4 + json_len];
    let metadata: Metadata = serde_json::from_slice(json)
        .map_err(|e| format!("the publish metadata is not what cargo sends: {e}"))?;

    let at = 4 + json_len;
    let crate_len = take_len(at)?;
    let crate_file = body[at + 4..at + 4 + crate_len].to_vec();
    if crate_file.is_empty() {
        return Err("the publish carried no crate file".into());
    }
    // Trailing bytes are not a framing this client sends, and admitting
    // them would mean two different bodies publish the same crate.
    if body.len() != at + 4 + crate_len {
        return Err("that is not a cargo publish body: it has bytes after the crate".into());
    }
    Ok(Publish {
        metadata,
        crate_file,
    })
}

/// Cargo's own error shape. It prints `detail` and nothing else, so the
/// sentence has to carry the whole explanation.
pub fn error_body(msg: &str) -> serde_json::Value {
    serde_json::json!({ "errors": [{ "detail": msg }] })
}

/// What a successful publish answers. Cargo prints any warning it
/// finds here, so an empty set is the quiet success.
pub fn publish_ok() -> serde_json::Value {
    serde_json::json!({
        "warnings": { "invalid_categories": [], "invalid_badges": [], "other": [] }
    })
}

/// The `.crate` filename for a version, which is the name Cargo's cache
/// uses and the last segment of the download URL.
pub fn crate_filename(name: &str, version: &str) -> String {
    format!("{name}-{version}.crate")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// By name length, which is Cargo's rule and not ours: a registry
    /// that laid the index out any other way is one `cargo` cannot
    /// read, and it fails as "crate not found" rather than as anything
    /// pointing at the layout.
    #[test]
    fn the_index_path_follows_cargos_own_length_rule() {
        assert_eq!(index_prefix("a"), "1/a");
        assert_eq!(index_prefix("ab"), "2/ab");
        assert_eq!(index_prefix("abc"), "3/a/abc");
        assert_eq!(index_prefix("abcd"), "ab/cd/abcd");
        assert_eq!(index_prefix("serde"), "se/rd/serde");
        // Lower-cased before the path is built, or `Serde` and `serde`
        // land in two places and one of them is unreachable.
        assert_eq!(index_prefix("Serde"), "se/rd/serde");
        assert_eq!(index_prefix(""), "");
        // A crate name is ASCII, and a non-ASCII one that somehow
        // reached here must 404 rather than panic on a slice boundary
        // — counting in `chars` and slicing in bytes is exactly how
        // that happens.
        assert_eq!(index_prefix("caf\u{e9}"), "");
        assert_eq!(index_prefix("\u{4f60}\u{597d}"), "");
    }

    /// The metadata `cargo publish` 1.96 really sent for a crate with
    /// one renamed dependency on the same registry, captured from the
    /// wire by `clients_e2e::cargo_publishes_and_builds_against_skein`.
    /// No `registry` key at all: Cargo leaves it out for "this one".
    const REAL_PUBLISH: &str = r#"{"name":"acme-widget","vers":"1.4.0","deps":[{"optional":false,"default_features":true,"name":"acme-base","features":[],"version_req":"^0.1","target":null,"kind":"normal","explicit_name_in_toml":"base"}],"features":{},"authors":[],"description":"a widget","documentation":null,"homepage":null,"readme":null,"readme_file":null,"keywords":[],"categories":[],"license":"MIT","license_file":null,"repository":null,"badges":{},"links":null,"rust_version":null}"#;

    fn line_of(declared: &Declared) -> serde_json::Value {
        let line = index_line("widget", "1.0.0", "sha256:deadbeef", false, declared);
        assert!(!line.contains('\n'), "a line with a newline is two lines");
        serde_json::from_str(&line).expect("one json object")
    }

    #[test]
    fn an_index_line_is_what_cargo_resolves_against() {
        let declared: Declared = serde_json::from_value(serde_json::json!({
            "deps": [{
                "name": "serde", "version_req": "^1", "features": ["derive"],
                "optional": true, "default_features": false,
                "target": "cfg(unix)", "kind": "normal"
            }],
            "features": { "default": ["std"], "std": [], "serde": ["dep:serde"] },
        }))
        .expect("the publish's shape");
        let v = line_of(&declared);
        assert_eq!(v["name"], "widget");
        assert_eq!(v["vers"], "1.0.0");
        // Hex and unprefixed: this is what Cargo compares the download
        // against, and `sha256:` in front of it fails every install.
        assert_eq!(v["cksum"], "deadbeef");
        assert_eq!(v["yanked"], false);
        assert!(v["links"].is_null());
        assert!(v.get("rust_version").is_none(), "{v}");
        // What the publisher declared, every field of it.
        let dep = &v["deps"][0];
        assert_eq!(dep["name"], "serde");
        assert_eq!(dep["req"], "^1");
        assert_eq!(dep["features"][0], "derive");
        assert_eq!(dep["optional"], true);
        assert_eq!(dep["default_features"], false);
        assert_eq!(dep["target"], "cfg(unix)");
        assert_eq!(dep["kind"], "normal");
        assert!(dep.get("package").is_none(), "not renamed: {dep}");
        assert_eq!(v["features"]["default"][0], "std");
        assert_eq!(v["features"]["serde"][0], "dep:serde");
    }

    /// The publish body and the index are two formats. Every word the
    /// publish uses that the index does not — `version_req`,
    /// `explicit_name_in_toml` — is restated, and none of them reaches
    /// the index, where Cargo reads a line carrying them and no `req` as
    /// "this version's index entry is invalid".
    #[test]
    fn a_dependency_is_restated_in_the_indexs_own_words() {
        let meta: Metadata = serde_json::from_str(REAL_PUBLISH).expect("cargo's own body");
        let v = line_of(&meta.declared);
        let dep = &v["deps"][0];
        // Renamed: the index's `name` is the one the code uses, and
        // `package` is the crate it really is.
        assert_eq!(dep["name"], "base", "{dep}");
        assert_eq!(dep["package"], "acme-base", "{dep}");
        assert_eq!(dep["req"], "^0.1", "{dep}");
        // Same registry: absent in the publish, absent in the index.
        assert!(dep.get("registry").is_none(), "{dep}");
        for publish_only in ["version_req", "explicit_name_in_toml"] {
            assert!(dep.get(publish_only).is_none(), "{publish_only}: {dep}");
        }

        // A dependency on another registry names it, in both; one with
        // no `kind` is an ordinary one.
        let other: PublishDep = serde_json::from_value(serde_json::json!({
            "name": "rand", "version_req": "=0.8.5",
            "registry": "https://github.com/rust-lang/crates.io-index"
        }))
        .unwrap();
        let d = other.in_index();
        assert_eq!(
            d["registry"],
            "https://github.com/rust-lang/crates.io-index"
        );
        assert_eq!(d["kind"], "normal");
        assert_eq!(d["default_features"], true);
        assert_eq!(d["req"], "=0.8.5");
    }

    /// `links` and `rust_version` are the publisher's and reach the index:
    /// the resolver refuses two crates linking one native library only
    /// if the index says which one this crate links.
    #[test]
    fn links_and_rust_version_reach_the_index() {
        let declared = Declared {
            links: Some("z".into()),
            rust_version: Some("1.70".into()),
            ..Declared::default()
        };
        let v = line_of(&declared);
        assert_eq!(v["links"], "z");
        assert_eq!(v["rust_version"], "1.70");
        assert_eq!(v["deps"], serde_json::json!([]));
        assert_eq!(v["features"], serde_json::json!({}));
    }

    /// What is stored on the row reads back as what was declared, so an
    /// index line built on a later read is the one built at publish.
    #[test]
    fn what_is_stored_reads_back_as_declared() {
        let meta: Metadata = serde_json::from_str(REAL_PUBLISH).unwrap();
        let stored = serde_json::to_string(&meta.declared).unwrap();
        let back: Declared = serde_json::from_str(&stored).unwrap();
        assert_eq!(back, meta.declared);
        // A row with nothing declared is a crate with no dependencies.
        assert_eq!(
            serde_json::from_str::<Declared>("{}").unwrap(),
            Declared::default()
        );
    }

    /// Without `auth-required`, Cargo sends no credential when it
    /// fetches the index — so a private registry answers 401 to a
    /// client that had a perfectly good token and never offered it.
    #[test]
    fn the_config_tells_cargo_this_registry_needs_a_credential() {
        let v: serde_json::Value =
            serde_json::from_str(&config_json("https://skein.test/dl", "https://skein.test"))
                .unwrap();
        assert_eq!(v["auth-required"], true);
        assert_eq!(v["dl"], "https://skein.test/dl");
        assert_eq!(v["api"], "https://skein.test");
        // No `{crate}` markers: Cargo appends `/{crate}/{version}/download`
        // itself, and spelling them out lets the path drift from the
        // route that serves it.
        assert!(!v["dl"].as_str().unwrap().contains('{'), "{v}");
    }

    fn framed(json: &[u8], krate: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(json);
        out.extend_from_slice(&(krate.len() as u32).to_le_bytes());
        out.extend_from_slice(krate);
        out
    }

    #[test]
    fn a_publish_body_is_read_frame_by_frame() {
        let json = br#"{"name":"widget","vers":"1.0.0","license":"MIT OR Apache-2.0",
            "deps":[],"features":{}}"#;
        let body = framed(json, b"the crate bytes");
        let p = parse_publish(&body).expect("parses");
        assert_eq!(p.metadata.name, "widget");
        assert_eq!(p.metadata.vers, "1.0.0");
        // Cargo's `license` is documented to be an SPDX expression,
        // which makes this the one ecosystem of the five where the
        // declaration needs no mapping at all.
        assert_eq!(p.metadata.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(p.crate_file, b"the crate bytes");
    }

    /// The one place in this tree where four bytes on the wire choose
    /// an allocation. Every length is checked against what is actually
    /// left before it is used, so a hostile frame is a 400 rather than
    /// an allocator failure.
    #[test]
    fn a_frame_that_lies_about_its_length_is_refused_not_allocated() {
        let json = br#"{"name":"widget","vers":"1.0.0"}"#;

        // Four bytes claiming a gigabyte, with nothing behind them.
        let mut huge = u32::to_le_bytes(1_000_000_000).to_vec();
        huge.extend_from_slice(b"{}");
        let err = parse_publish(&huge).unwrap_err();
        assert!(err.contains("1000000000"), "{err}");

        // A metadata length past our own ceiling, even when the bytes
        // really are there: this document is parsed into memory and a
        // crate's dependency list is measured in kilobytes.
        let big = vec![b' '; MAX_METADATA + 1];
        let over = framed(&big, b"x");
        assert!(parse_publish(&over).unwrap_err().contains("limit"));

        for (what, body) in [
            ("empty", Vec::new()),
            ("a length and nothing else", u32::to_le_bytes(9).to_vec()),
            (
                "no second frame",
                [u32::to_le_bytes(json.len() as u32).to_vec(), json.to_vec()].concat(),
            ),
            (
                "a crate length past the end",
                [
                    u32::to_le_bytes(json.len() as u32).to_vec(),
                    json.to_vec(),
                    u32::to_le_bytes(999).to_vec(),
                    b"short".to_vec(),
                ]
                .concat(),
            ),
            ("an empty crate file", framed(json, b"")),
            (
                // Two different bodies publishing one crate is how a
                // proxy in front of us and this parser come to disagree
                // about what was sent.
                "bytes after the crate",
                [framed(json, b"x"), b"trailing".to_vec()].concat(),
            ),
            ("metadata that is not json", framed(b"not json", b"x")),
            (
                "metadata missing a field cargo always sends",
                framed(br#"{"vers":"1.0.0"}"#, b"x"),
            ),
            (
                // Admitted, it becomes an index line with no `req`,
                // which no Cargo can read.
                "a dependency with no version requirement",
                framed(
                    br#"{"name":"widget","vers":"1.0.0","deps":[{"name":"serde"}]}"#,
                    b"x",
                ),
            ),
            (
                "features that are not lists of names",
                framed(
                    br#"{"name":"widget","vers":"1.0.0","features":{"std":"yes"}}"#,
                    b"x",
                ),
            ),
        ] {
            assert!(parse_publish(&body).is_err(), "{what} was accepted");
        }
    }

    #[test]
    fn the_error_shape_is_the_one_cargo_prints() {
        let v = error_body("widget 1.0.0 is already published");
        assert_eq!(
            v["errors"][0]["detail"],
            "widget 1.0.0 is already published"
        );
        // Cargo reads `warnings` on success and prints whatever is in
        // it, so the quiet success is three empty lists rather than an
        // empty object.
        let ok = publish_ok();
        assert!(ok["warnings"]["other"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_crate_file_is_named_the_way_cargos_cache_names_it() {
        assert_eq!(crate_filename("widget", "1.0.0"), "widget-1.0.0.crate");
    }
}
