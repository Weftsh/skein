//! Maven's door: `GET` and `PUT` of files at coordinate-shaped paths.
//!
//! Maven has no API. `mvn deploy` `PUT`s each file of a release one
//! request at a time — the jar, the POM, a sources jar, and a `.sha1`
//! and `.md5` beside each of them — and `mvn install` `GET`s them back.
//! The only document the repository itself produces is
//! `maven-metadata.xml`.
//!
//! ## The refusals are ordered, and the order is the point
//!
//! See [`registry_door`]: no credential is a 401 with a `Basic`
//! challenge before anything else is looked at — which is also what
//! makes Maven send the `<server>` credential from `settings.xml` at
//! all, because it does not offer one on a `GET` until it is asked.
//! Only then does Maven being off, or the file being absent, get a 404.
//!
//! ## A version accretes, and immutability is per file
//!
//! npm publishes a version in one request, so "this version exists" and
//! "this version is complete" are the same moment. Maven's are not, and
//! the order is not promised: the jar can land before the POM that
//! declares the licence. So the first file of a version creates the
//! version and each later one is added to it, with a second upload of a
//! filename that is already there refused rather than overwritten.
//!
//! That is the invariant doing real work. Without it, `mvn deploy
//! -Dmaven.deploy.overwrite` — or simply a second run of a release
//! job — would silently replace the bytes behind a version somebody
//! else has already built against.
//!
//! ## `mvn deploy` uploads `maven-metadata.xml` too, and we ignore it
//!
//! We generate that document from our own rows, so the client's copy is
//! redundant at best and stale at worst: it was assembled from what
//! that developer's repository knew, which is not what this one holds.
//! Accepted with a 200 and discarded, because refusing it fails the
//! deploy over a file whose content we do not need.

use crate::api::{internal, registry_door};
use crate::app::SharedState;
use crate::registry::{blobs, maven};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use skein_control::auth::{Principal, Scope};
use skein_control::packages::{self, Ecosystem, License, PackageFile};
use skein_control::registry::Org;

/// The body limit for a deploy. A Maven `PUT` is the file itself, with
/// nothing around it, so the ceiling is exactly the artifact ceiling.
pub const BODY_LIMIT: usize = blobs::MAX_ARTIFACT;

/// A refusal Maven will actually show, in the **reason phrase**.
///
/// stratum-core wrote this door believing Maven prints whatever body it
/// is given beside the status code. It does not: Maven 3.9 reports a
/// failed transfer as `status code: 403, reason phrase: Forbidden
/// (403)` and never reads the body at all. So every sentence this door
/// wrote — "rita is a reader here", "a snapshot … deploy a release
/// version", "already deployed … never changes" — was sent to nobody,
/// and a person got a bare status to decode. Found by driving the real
/// `mvn` in `clients_e2e.rs`; every hand-built request in the e2e suite
/// read the body and was satisfied.
///
/// The sentence goes in the status line, which is also where Nexus puts
/// its reasons and so where Maven users are used to reading them. The
/// body keeps it too, as plain text, for `curl` and a browser.
fn maven_error(status: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    let reason = reason_phrase(&msg);
    let mut r = (status, [(header::CONTENT_TYPE, "text/plain")], msg).into_response();
    // Cannot fail — `reason_phrase` emits only what a status line may
    // carry — but a refusal that lost its sentence is still a refusal,
    // so a failure here is the standard phrase rather than a panic.
    if let Ok(p) = hyper::ext::ReasonPhrase::try_from(reason) {
        r.extensions_mut().insert(p);
    }
    r
}

/// The longest reason phrase this door writes. Every sentence here is
/// shorter; the ceiling is for a filename echoed back in a 409, which
/// is somebody's input.
const MAX_REASON: usize = 512;

/// A sentence as a status line may carry it: one line of printable
/// ASCII.
///
/// A CR or LF here would end the status line and start a header —
/// response splitting — so every control character becomes a space.
/// Non-ASCII is legal on the wire as `obs-text`, but HTTP gives it no
/// charset and a client may read it as Latin-1, which turns an em dash
/// into `â€”` in somebody's build log; the few this file writes are
/// spelled in ASCII and anything else is a `?`.
fn reason_phrase(msg: &str) -> String {
    let mut out: String = msg
        .chars()
        .map(|c| match c {
            '\u{2014}' | '\u{2013}' => '-',
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201c}' | '\u{201d}' => '"',
            '\u{2026}' => '.',
            c if c.is_ascii_graphic() || c == ' ' => c,
            c if c.is_whitespace() || c.is_control() => ' ',
            _ => '?',
        })
        .collect();
    if out.len() > MAX_REASON {
        out.truncate(MAX_REASON - 3);
        out.push_str("...");
    }
    out
}

/// Maven's refusal, as [`registry_door::Refusal`] wants it.
fn refusal(status: StatusCode, msg: String) -> Response {
    maven_error(status, msg)
}

/// Authorize, in Maven's dialect of refusal, and only then check Maven
/// is switched on — the same order as every other door.
fn open(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
) -> Result<(Org, Principal), Response> {
    let p = registry_door::authorize(state, headers, need, refusal)?;
    let org = registry_door::eco_org(state, headers, Ecosystem::Maven)?;
    Ok((org, p))
}

/// `GET /maven/*path` — one file of a release, or the generated
/// `maven-metadata.xml`.
pub async fn get(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let org = match open(&state, &headers, Scope::PackageRead) {
        Ok((o, _)) => o,
        Err(r) => return r,
    };
    let Some(target) = maven::parse_path(&path) else {
        return maven_error(StatusCode::NOT_FOUND, "no such artifact");
    };
    match target {
        maven::Target::Metadata { name, checksum } => metadata(state, org, name, checksum).await,
        maven::Target::Artifact {
            name,
            version,
            filename,
        } => artifact(state, org, name, version, filename).await,
    }
}

/// The generated `maven-metadata.xml`, or a checksum of it.
async fn metadata(
    state: SharedState,
    org: Org,
    name: String,
    checksum: Option<String>,
) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Maven, &name) {
        Ok(Some(p)) => p,
        // A name that is not a legal Maven name is the same answer:
        // Maven asked for something we do not have.
        Ok(None) | Err(_) => return maven_error(StatusCode::NOT_FOUND, "no such artifact"),
    };
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    // Publication order, oldest first: `<latest>` and `<release>` are
    // the last of them, and Maven takes those words literally rather
    // than sorting the list itself.
    let mut rows: Vec<_> = versions.iter().collect();
    rows.sort_by_key(|v| v.published_at);
    let names: Vec<String> = rows
        .iter()
        .filter(|v| !v.yanked)
        .map(|v| v.version.clone())
        .collect();
    let updated = rows
        .last()
        .map(|v| v.published_at)
        .unwrap_or(pkg.updated_at);
    let doc = maven::metadata_xml(&pkg.name, &names, &maven::maven_timestamp(updated));

    match checksum {
        None => (
            [(header::CONTENT_TYPE, "application/xml")],
            doc.into_bytes(),
        )
            .into_response(),
        // Computed over the document we are about to serve, in the same
        // request. Storing one would let it drift from a document that
        // is regenerated on every read, and a checksum that disagrees
        // with its file makes Maven fail the build with a corruption
        // error pointing at the developer's own `~/.m2`.
        Some(alg) => {
            let body = match alg.as_str() {
                "sha1" => maven_sha1(doc.as_bytes()),
                "sha256" => blobs::digest_of(doc.as_bytes())
                    .trim_start_matches("sha256:")
                    .to_string(),
                // md5 and sha512 are legal in the path grammar and are
                // not published: a checksum we cannot compute must be
                // absent rather than wrong, and Maven treats an absent
                // one as a warning and carries on.
                _ => return maven_error(StatusCode::NOT_FOUND, "no such checksum"),
            };
            ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
        }
    }
}

fn maven_sha1(bytes: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

async fn artifact(
    state: SharedState,
    org: Org,
    name: String,
    version: String,
    filename: String,
) -> Response {
    let Some(file) = (match lookup(&state, &org, &name, &version, &filename) {
        Ok(f) => f,
        Err(r) => return r,
    }) else {
        return maven_error(StatusCode::NOT_FOUND, "no such artifact");
    };
    match registry_door::read_artifact(&state, &file.digest).await {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, maven::content_type(&filename)),
                (
                    header::CACHE_CONTROL,
                    "private, max-age=31536000, immutable",
                ),
            ],
            bytes,
        )
            .into_response(),
        // A row whose bytes the store does not have. Absent rather than
        // a 500, so a resolver moves on to its next repository instead
        // of failing the build on this one.
        Ok(None) => maven_error(StatusCode::NOT_FOUND, "no such artifact"),
        Err(r) => r,
    }
}

fn lookup(
    state: &SharedState,
    org: &Org,
    name: &str,
    version: &str,
    filename: &str,
) -> Result<Option<PackageFile>, Response> {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Maven, name) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return Ok(None),
    };
    let ver = match packages::version_by_number(&state.db, &pkg.id, version) {
        Ok(Some(v)) => v,
        Ok(None) | Err(_) => return Ok(None),
    };
    match packages::files(&state.db, &ver.id) {
        Ok(fs) => Ok(fs.into_iter().find(|f| f.filename == filename)),
        Err(e) => Err(internal(e)),
    }
}

/// `PUT /maven/*path` — one file of a release.
pub async fn put(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let (org, principal) = match open(&state, &headers, Scope::PackageWrite) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let Some(target) = maven::parse_path(&path) else {
        return maven_error(
            StatusCode::BAD_REQUEST,
            "that is not a Maven coordinate: a path is \
             groupId/as/directories/artifactId/version/filename",
        );
    };
    let (name, version, filename) = match target {
        // Generated from our own rows, so the client's copy is
        // redundant at best and stale at worst. Accepted rather than
        // refused: refusing fails the whole deploy over a file whose
        // content we do not need.
        maven::Target::Metadata { .. } => return StatusCode::OK.into_response(),
        maven::Target::Artifact {
            name,
            version,
            filename,
        } => (name, version, filename),
    };

    if maven::is_snapshot(&version) {
        return maven_error(
            StatusCode::BAD_REQUEST,
            format!(
                "{version} is a snapshot, and this registry does not hold snapshots. A \
                 published version's bytes never change here, which is the whole basis \
                 of the provenance and the licence gate — and a snapshot is a version \
                 whose bytes are meant to. Deploy a release version."
            ),
        );
    }
    // The name is checked by `ensure` and the version by
    // `publish_version` — but only on the request that *creates* them.
    // A second file of an existing version reaches `add_file`, which
    // checks neither, so a version string that could not be stored
    // safely has to be refused here or it would be refused
    // inconsistently: fine on the jar, fine again on the POM, and a
    // 400 only if the jar happened to be first.
    if let Err(e) = packages::normalize_version(&version) {
        return maven_error(StatusCode::BAD_REQUEST, e);
    }

    let now = skein_control::ids::now_ms();
    let pkg = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Maven,
        &name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return maven_error(StatusCode::BAD_REQUEST, e),
    };
    // Maven does not proxy, so nothing writes a cached row here today.
    // Kept because the day it does, a name cached from upstream must not
    // be one a local deploy can add files to — mixing the two is how a
    // local publish silently shadows, or is shadowed by, a public one.
    if pkg.is_proxied() {
        return maven_error(
            StatusCode::CONFLICT,
            format!(
                "{:?} is cached from an upstream registry here and cannot be published to",
                pkg.name
            ),
        );
    }

    // Bytes first, row second — see `registry_door::store_artifact`.
    let digest = match registry_door::store_artifact(&state, &body, now, refusal).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let file = PackageFile {
        filename: filename.clone(),
        digest,
        size_bytes: body.len() as i64,
        content_type: maven::content_type(&filename).to_string(),
        // The `.sha1` Maven publishes beside each file is itself an
        // uploaded file, so there is nothing to compute here — unlike
        // npm, where the digests live in a document we generate.
        digests: "{}".to_string(),
    };

    // The POM is the only file that says anything about the licence,
    // and it does not always arrive first.
    let licence = if filename.ends_with(".pom") {
        declared_licence(&body)
    } else {
        License::Unknown
    };

    let existing = match packages::version_by_number(&state.db, &pkg.id, &version) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let version_id = match existing {
        Some(v) => v.id,
        None => {
            match packages::publish_version(
                &state.db,
                &pkg.id,
                &version,
                &licence,
                "{}",
                &[],
                &registry_door::provenance(&principal),
                now,
            ) {
                Ok(v) => {
                    // One entry per release rather than per file: a
                    // six-file deploy is one publish, and the version's
                    // own provenance names who made it.
                    crate::api::audit(
                        &state,
                        &principal,
                        "package.publish",
                        serde_json::json!({
                            "ecosystem": "maven",
                            "name": pkg.name,
                            "version": v.version,
                        }),
                    );
                    v.id
                }
                // Two files of one release racing each other. The loser
                // finds the version the winner created, which is the
                // right answer for both.
                Err(packages::PublishError::Exists) => {
                    match packages::version_by_number(&state.db, &pkg.id, &version) {
                        Ok(Some(v)) => v.id,
                        Ok(None) => {
                            return internal("the version vanished mid-publish".to_string())
                        }
                        Err(e) => return internal(e),
                    }
                }
                Err(packages::PublishError::Other(e)) => {
                    return maven_error(StatusCode::BAD_REQUEST, e)
                }
            }
        }
    };
    if let License::Declared(_) = &licence {
        // Fills a gap; never replaces. A second POM for a version that
        // already has a licence is either the same answer or an attempt
        // to relabel a published artifact.
        if let Err(e) = packages::set_license(&state.db, &version_id, &licence) {
            return internal(e);
        }
    }

    match packages::add_file(&state.db, &version_id, &file) {
        Ok(()) => {}
        Err(packages::PublishError::Exists) => {
            return maven_error(
                StatusCode::CONFLICT,
                format!(
                    "{filename} is already deployed at {} {version}, and a published \
                     file never changes here",
                    pkg.name
                ),
            )
        }
        Err(packages::PublishError::Other(e)) => return internal(e),
    }
    // Maven reads 201 and 200 alike; 201 is the truthful one for a file
    // that did not exist a moment ago.
    StatusCode::CREATED.into_response()
}

/// The licence a POM declares, mapped to SPDX where the curated table
/// knows the spelling.
///
/// Three outcomes and they are all different: the POM declared nothing
/// (`Unknown`), it declared something we mapped (`Declared`), or it
/// declared free text no table knows — which is also `Unknown`, because
/// guessing would admit an artifact under a rule written for a
/// different licence and nothing would ever surface it.
fn declared_licence(pom: &[u8]) -> License {
    let Ok(text) = std::str::from_utf8(pom) else {
        return License::Unknown;
    };
    match maven::license_of(text).and_then(|d| maven::spdx_expression(&d)) {
        Some(expr) => License::Declared(expr),
        None => License::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever sentence a refusal carries, the status line it becomes
    /// is one line of printable ASCII: nothing in it can end the line
    /// and start a header, and nothing arrives in Maven's log as
    /// mojibake.
    #[test]
    fn a_reason_phrase_is_one_line_of_printable_ascii() {
        assert_eq!(
            reason_phrase("the licence gate — and a snapshot"),
            "the licence gate - and a snapshot"
        );
        assert_eq!(
            reason_phrase("x\r\nSet-Cookie: a=b"),
            "x  Set-Cookie: a=b",
            "a line break survived into the status line"
        );
        assert_eq!(reason_phrase("caf\u{e9}\ttab\u{0}nul"), "caf? tab nul");
        assert_eq!(reason_phrase("‘a’ “b” c…"), "'a' \"b\" c.");

        let long = reason_phrase(&"x".repeat(10_000));
        assert_eq!(long.len(), MAX_REASON);
        assert!(long.ends_with("..."));

        // And hyper accepts every one of them as a reason phrase, so the
        // sentence is never silently dropped for the standard one.
        for s in [
            "rita is a reader here, and a reader may not publish to this registry",
            "1.0-SNAPSHOT is a snapshot — deploy a release version",
            "a\r\nb",
            "\u{1F600} emoji",
        ] {
            assert!(
                hyper::ext::ReasonPhrase::try_from(reason_phrase(s)).is_ok(),
                "{s:?}"
            );
        }
    }

    /// The sentence reaches the response twice: in the status line,
    /// which is all Maven prints, and in the body, for everybody else.
    #[test]
    fn a_maven_refusal_carries_its_sentence_in_the_status_line() {
        let r = maven_error(StatusCode::FORBIDDEN, "rita is a reader — no");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let reason = r
            .extensions()
            .get::<hyper::ext::ReasonPhrase>()
            .expect("no reason phrase: Maven would print only \"Forbidden\"");
        assert_eq!(reason.as_bytes(), b"rita is a reader - no");
    }
}
