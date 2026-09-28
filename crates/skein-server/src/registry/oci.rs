//! The OCI distribution protocol's grammar, and the manifests it moves.
//!
//! ## Why this one lives at `/v2/` and not under a prefix
//!
//! Not a preference. A container client parses `host/path/image` as
//! registry `host` and repository `path/image`, and then talks to
//! `https://host/v2/…`. There is nowhere to put a base path: `docker
//! pull skein.example.com/oci/team/service` means "pull `oci/team/
//! service` from `skein.example.com`", not "pull `team/service` from the
//! registry at `skein.example.com/oci`". So `/v2/` is a reserved
//! top-level segment, and Skein has to be served at the root of a host.
//!
//! A Skein install serves one organization, so the organization is not
//! in the name at all: the repository is the **whole path** —
//! `skein.example.com/team/service:1.0` is repository `team/service`,
//! and `skein.example.com/app:1` is repository `app`.
//!
//! ## The four shapes, and reading them from the right
//!
//! ```text
//! /v2/<name>/blobs/uploads/            open a session
//! /v2/<name>/blobs/uploads/<session>   write to one, or finish it
//! /v2/<name>/blobs/<digest>            one layer or config
//! /v2/<name>/manifests/<reference>     a tag or a digest
//! /v2/<name>/tags/list
//! ```
//!
//! `<name>` may contain slashes — `team/platform/service` is a legal
//! repository — so the marker is found from the **right**, and
//! `blobs/uploads/` is looked for before `blobs/`, because every upload
//! path contains both.
//!
//! ## What a manifest is, to us
//!
//! A JSON document naming a config blob and a list of layer blobs by
//! digest, or — for a multi-platform image — a list of other manifests.
//! We do not interpret a layer. What we read is the set of digests it
//! references, because that is what has to exist before the manifest may
//! be accepted and what has to stay alive while it does.

use serde::Deserialize;

/// What an OCI request is addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `POST /v2/<name>/blobs/uploads/`
    StartUpload {
        name: String,
    },
    /// `PATCH`/`PUT`/`GET`/`DELETE` on one session.
    Upload {
        name: String,
        session: String,
    },
    Blob {
        name: String,
        digest: String,
    },
    Manifest {
        name: String,
        reference: String,
    },
    Tags {
        name: String,
    },
}

/// Split an OCI path — everything after `/v2/` — into what it
/// addresses.
///
/// `None` for anything that is not one of the five shapes. Strict, and
/// read from the right: a repository name may contain slashes, so
/// reading from the left would make `acme/blobs/service/blobs/sha256:…`
/// ambiguous, and guessing wrong means one repository's layer served
/// under another's name.
pub fn parse_path(path: &str) -> Option<Target> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return None;
    }
    // No empty, traversing or non-ASCII component ever becomes part of
    // a name. Refused rather than cleaned: a cleaned path is a second
    // way to address one stored object.
    if path.split('/').any(|p| {
        p.is_empty() || p == "." || p == ".." || p.chars().any(|c| c.is_control() || !c.is_ascii())
    }) && !path.ends_with("/blobs/uploads/")
    {
        return None;
    }

    // Two exact suffixes first, because neither carries a variable
    // part and both would otherwise be read as something else:
    // `…/blobs/uploads` has `/blobs/` in it and would be taken as a
    // request for a blob called `uploads`, which is not a digest, and
    // the whole request would 404 instead of opening a session.
    if let Some(name) = path.strip_suffix("/blobs/uploads") {
        return valid_name(name).then(|| Target::StartUpload {
            name: name.to_string(),
        });
    }
    if let Some(name) = path.strip_suffix("/tags/list") {
        return valid_name(name).then(|| Target::Tags {
            name: name.to_string(),
        });
    }

    // The **rightmost** marker wins, whichever it is. Checking one
    // marker before another rather than comparing positions is how
    // `acme/blobs/manifests/latest` — a repository legitimately called
    // `acme/blobs` — gets read as a blob request for `manifests/latest`
    // and 404s for a tag that is right there.
    let uploads = path.rfind("/blobs/uploads/");
    let blobs = path.rfind("/blobs/");
    let manifests = path.rfind("/manifests/");
    let rightmost = [uploads, blobs, manifests].into_iter().flatten().max();

    if let Some(at) = rightmost {
        // `/blobs/uploads/` and `/blobs/` start at the same index when
        // both are present, so the longer one is preferred explicitly.
        if uploads == Some(at) {
            let name = &path[..at];
            let session = &path[at + "/blobs/uploads/".len()..];
            if !valid_name(name) {
                return None;
            }
            return Some(if session.is_empty() {
                Target::StartUpload {
                    name: name.to_string(),
                }
            } else if valid_session(session) {
                Target::Upload {
                    name: name.to_string(),
                    session: session.to_string(),
                }
            } else {
                return None;
            });
        }
        if blobs == Some(at) {
            let (name, digest) = (&path[..at], &path[at + "/blobs/".len()..]);
            if valid_name(name) && valid_digest(digest) {
                return Some(Target::Blob {
                    name: name.to_string(),
                    digest: digest.to_string(),
                });
            }
            return None;
        }
        let (name, reference) = (&path[..at], &path[at + "/manifests/".len()..]);
        if valid_name(name) && valid_reference(reference) {
            return Some(Target::Manifest {
                name: name.to_string(),
                reference: reference.to_string(),
            });
        }
        return None;
    }

    None
}

/// The distribution spec's repository-name grammar: lowercase
/// alphanumerics and `.`, `_`, `-`, in path components separated by `/`.
pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    name.split('/').all(|c| {
        !c.is_empty()
            && c.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "._-".contains(ch))
            // A component may not begin or end with a separator, which
            // is what stops `a/.-/b` and friends.
            && !c.starts_with(['.', '_', '-'])
            && !c.ends_with(['.', '_', '-'])
    })
}

/// `sha256:` and 64 lowercase hex characters. Nothing else: this
/// registry stores under SHA-256 and a digest in another algorithm is
/// one it could never have written.
pub fn valid_digest(d: &str) -> bool {
    match d.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }
        None => false,
    }
}

/// A tag, per the spec: 1–128 characters of alphanumerics, `_`, `.`,
/// `-`, not starting with a separator.
pub fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 128
        && !t.starts_with(['.', '-'])
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// A manifest reference is a tag **or** a digest, and the two are told
/// apart by the colon a digest has and a tag cannot.
pub fn valid_reference(r: &str) -> bool {
    valid_digest(r) || valid_tag(r)
}

fn valid_session(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A manifest, read only as far as we need it.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    pub config: Option<Descriptor>,
    #[serde(default)]
    pub layers: Vec<Descriptor>,
    /// Present on an index (a multi-platform image): the manifests it
    /// points at, each of which is itself stored here.
    #[serde(default)]
    pub manifests: Vec<Descriptor>,
    /// `org.opencontainers.image.licenses`, when anybody set it — which
    /// is rarely, and is why OCI's `unknown` disposition defaults to
    /// admitting rather than refusing.
    #[serde(default)]
    pub annotations: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    pub digest: String,
    #[serde(default)]
    pub size: i64,
}

/// The media type to serve a stored manifest as.
///
/// A client sends `Accept:` and expects the type it asked for. We store
/// what was pushed and answer with the `mediaType` the document itself
/// declares — which is the only answer that cannot disagree with the
/// bytes, and the bytes are what the digest covers.
pub const DEFAULT_MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

impl Manifest {
    /// Every blob this manifest depends on: the config, the layers, and
    /// — for an index — the manifests it points at.
    ///
    /// This is what must already exist before the manifest is accepted,
    /// and what must stay alive while it does. A registry that accepted
    /// a manifest naming a layer nobody uploaded would serve an image
    /// that cannot be pulled, and the client's error would be about the
    /// layer rather than about the push that was wrong.
    pub fn referenced(&self) -> Vec<&Descriptor> {
        let mut out: Vec<&Descriptor> = Vec::new();
        if let Some(c) = &self.config {
            out.push(c);
        }
        out.extend(self.layers.iter());
        out.extend(self.manifests.iter());
        out
    }

    /// Whether this is an index rather than an image: the members are
    /// other manifests, which live in this registry too, so they are
    /// checked as manifests and not as blobs.
    pub fn is_index(&self) -> bool {
        !self.manifests.is_empty() && self.layers.is_empty()
    }

    /// The licence, if the image declared one.
    ///
    /// `org.opencontainers.image.licenses` is defined to be an SPDX
    /// expression, so it needs no mapping — but almost nothing sets it,
    /// which is exactly why OCI's `unknown` disposition defaults to
    /// admitting. An organization that refuses unknown licences on
    /// containers would be able to pull almost no public image, and
    /// that reads as the feature being broken rather than as policy.
    pub fn license(&self) -> Option<&str> {
        self.annotations
            .get("org.opencontainers.image.licenses")
            .map(String::as_str)
            .filter(|s| !s.trim().is_empty())
    }
}

/// The distribution spec's error shape. A client prints `message`, and
/// `code` is what tooling matches on.
pub fn error_body(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({ "errors": [{ "code": code, "message": message, "detail": null }] })
}

/// `{"name": …, "tags": [...]}`, the tags-list document.
pub fn tags_body(name: &str, tags: &[String]) -> serde_json::Value {
    serde_json::json!({ "name": name, "tags": tags })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// From the right, because a repository name may contain slashes.
    /// From the left, `acme/blobs/service/blobs/sha256:…` is ambiguous,
    /// and guessing wrong serves one repository's layer under another's
    /// name.
    #[test]
    fn a_path_is_read_from_the_right() {
        assert_eq!(
            parse_path("acme/service/blobs/uploads/"),
            Some(Target::StartUpload {
                name: "acme/service".into()
            })
        );
        assert_eq!(
            parse_path("acme/service/blobs/uploads"),
            Some(Target::StartUpload {
                name: "acme/service".into()
            })
        );
        assert_eq!(
            parse_path("acme/service/blobs/uploads/01ABC"),
            Some(Target::Upload {
                name: "acme/service".into(),
                session: "01ABC".into()
            })
        );
        assert_eq!(
            parse_path(&format!("acme/service/blobs/sha256:{}", "a".repeat(64))),
            Some(Target::Blob {
                name: "acme/service".into(),
                digest: format!("sha256:{}", "a".repeat(64)),
            })
        );
        assert_eq!(
            parse_path("acme/service/manifests/latest"),
            Some(Target::Manifest {
                name: "acme/service".into(),
                reference: "latest".into()
            })
        );
        assert_eq!(
            parse_path("acme/service/tags/list"),
            Some(Target::Tags {
                name: "acme/service".into()
            })
        );

        // A repository whose own name contains the markers. Read from
        // the left, every one of these addresses something else.
        assert_eq!(
            parse_path("acme/blobs/manifests/latest"),
            Some(Target::Manifest {
                name: "acme/blobs".into(),
                reference: "latest".into()
            })
        );
        assert_eq!(
            parse_path("acme/team/tags/service/tags/list"),
            Some(Target::Tags {
                name: "acme/team/tags/service".into()
            })
        );
    }

    #[test]
    fn a_path_that_is_not_one_of_the_five_shapes_is_refused() {
        for bad in [
            "",
            "/",
            "acme/service",
            "acme/service/blobs/",
            "acme/service/blobs/not-a-digest",
            "acme/service/blobs/sha512:abc",
            "acme/service/manifests/",
            "acme/service/manifests/.leading-dot",
            "acme/service/tags",
            "blobs/sha256:x",
            "acme/../etc/manifests/latest",
            "acme//service/manifests/latest",
            "ACME/service/manifests/latest",
            "acme/service/blobs/uploads/not a session",
            // An uppercase digest is a digest we could never have
            // written: the store's keys are lowercase hex.
            &format!("acme/service/blobs/sha256:{}", "A".repeat(64)),
        ] {
            assert_eq!(parse_path(bad), None, "{bad:?} parsed");
        }
    }

    /// An upload path whose *name* half is not a legal repository
    /// name. The session id is fine and the shape is right, so this is
    /// the one refusal that has to be made on the name alone — and it
    /// matters, because the name is the package row a session writes
    /// into.
    #[test]
    fn an_upload_under_an_illegal_name_is_refused() {
        assert_eq!(parse_path("ACME/service/blobs/uploads/01ABC"), None);
        assert_eq!(parse_path("acme/-bad/blobs/uploads/"), None);
        assert_eq!(parse_path("acme/-bad/blobs/uploads"), None);
        assert_eq!(parse_path("-bad/blobs/uploads/"), None);
    }

    /// One organization per install, so the repository is the whole
    /// path: a single component is a repository in its own right, not
    /// an organization missing its name, and every component of a
    /// deeper one is kept rather than one of them being peeled off.
    #[test]
    fn a_repository_is_the_whole_path_and_may_be_one_component() {
        assert_eq!(
            parse_path("app/manifests/latest"),
            Some(Target::Manifest {
                name: "app".into(),
                reference: "latest".into()
            })
        );
        assert_eq!(
            parse_path("app/tags/list"),
            Some(Target::Tags { name: "app".into() })
        );
        assert_eq!(
            parse_path("app/blobs/uploads/"),
            Some(Target::StartUpload { name: "app".into() })
        );
        assert_eq!(
            parse_path("app/blobs/uploads/01ABC"),
            Some(Target::Upload {
                name: "app".into(),
                session: "01ABC".into()
            })
        );
        assert_eq!(
            parse_path(&format!("app/blobs/sha256:{}", "b".repeat(64))),
            Some(Target::Blob {
                name: "app".into(),
                digest: format!("sha256:{}", "b".repeat(64)),
            })
        );
        assert_eq!(
            parse_path("team/platform/service/manifests/1.0"),
            Some(Target::Manifest {
                name: "team/platform/service".into(),
                reference: "1.0".into()
            })
        );
        // A repository may be *called* one of the markers, and still
        // is one only when something follows it.
        assert_eq!(
            parse_path("blobs/manifests/latest"),
            Some(Target::Manifest {
                name: "blobs".into(),
                reference: "latest".into()
            })
        );
        assert_eq!(parse_path("manifests/latest"), None);
        assert_eq!(parse_path("tags/list"), None);
    }

    #[test]
    fn the_name_grammar_is_the_specs_and_not_a_looser_one() {
        assert!(valid_name("acme/service"));
        assert!(valid_name("acme/team_1/service-2.0"));
        assert!(!valid_name(""));
        assert!(!valid_name("Acme/service"), "uppercase is not a legal name");
        assert!(!valid_name("acme//service"));
        assert!(!valid_name("acme/-service"));
        assert!(!valid_name("acme/service-"));
        assert!(!valid_name("acme/serv ice"));
        assert!(!valid_name(&"a/".repeat(200)));
    }

    #[test]
    fn a_tag_and_a_digest_are_told_apart_by_the_colon() {
        assert!(valid_tag("latest"));
        assert!(valid_tag("v1.2.3-rc1"));
        assert!(!valid_tag(""));
        assert!(!valid_tag(".hidden"));
        assert!(!valid_tag("-leading"));
        assert!(!valid_tag("has:colon"));
        assert!(!valid_tag(&"x".repeat(129)));

        let d = format!("sha256:{}", "0".repeat(64));
        assert!(valid_digest(&d));
        assert!(valid_reference(&d));
        assert!(valid_reference("latest"));
        assert!(!valid_digest("sha256:short"));
        assert!(!valid_digest(&format!("md5:{}", "0".repeat(64))));
    }

    const IMAGE: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                    "size": 7 },
        "layers": [
          { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "size": 32 },
          { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
            "size": 64 }
        ],
        "annotations": { "org.opencontainers.image.licenses": "Apache-2.0" }
      }"#;

    /// A manifest names what has to exist before it may be accepted and
    /// what has to stay alive while it does. A registry that took a
    /// manifest naming a layer nobody uploaded would serve an image
    /// nobody can pull, and the client's error would be about the layer
    /// rather than about the push that was wrong.
    #[test]
    fn a_manifest_names_its_config_and_every_layer() {
        let m: Manifest = serde_json::from_str(IMAGE).expect("a manifest");
        let refs = m.referenced();
        assert_eq!(refs.len(), 3, "the config is a reference too");
        assert!(refs[0].digest.ends_with("1111"));
        assert_eq!(refs[2].size, 64);
        assert!(!m.is_index());
        // Defined to be an SPDX expression, so it needs no mapping.
        assert_eq!(m.license(), Some("Apache-2.0"));
    }

    /// An index's members are other *manifests*, which live in this
    /// registry too — so they are checked as manifests rather than as
    /// blobs, and confusing the two makes a multi-platform push fail
    /// with "blob unknown" for something that is right there.
    #[test]
    fn an_index_points_at_manifests_and_says_so() {
        let index = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
              { "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                "size": 500 }
            ]
          }"#;
        let m: Manifest = serde_json::from_str(index).expect("an index");
        assert!(m.is_index());
        assert_eq!(m.referenced().len(), 1);
        assert!(m.config.is_none());
        // Almost nothing sets the licence annotation, which is exactly
        // why OCI's `unknown` disposition defaults to admitting.
        assert_eq!(m.license(), None);
    }

    #[test]
    fn a_manifest_that_is_not_one_is_refused_rather_than_read_as_empty() {
        assert!(serde_json::from_str::<Manifest>("not json").is_err());
        // A document with no layers and no manifests parses — an empty
        // image is legal — and simply references nothing.
        let bare: Manifest = serde_json::from_str("{}").expect("an object");
        assert!(bare.referenced().is_empty());
        assert!(!bare.is_index());
        // A descriptor with no digest is not a descriptor.
        assert!(serde_json::from_str::<Manifest>(r#"{"layers":[{"size":1}]}"#).is_err());
    }

    #[test]
    fn the_error_and_tag_documents_are_the_shapes_a_client_reads() {
        let e = error_body("MANIFEST_UNKNOWN", "no such manifest");
        assert_eq!(e["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert_eq!(e["errors"][0]["message"], "no such manifest");
        let t = tags_body("acme/service", &["latest".into(), "v1".into()]);
        assert_eq!(t["name"], "acme/service");
        assert_eq!(t["tags"][1], "v1");
    }
}
