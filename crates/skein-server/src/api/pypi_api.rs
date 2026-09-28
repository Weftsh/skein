//! PyPI's door: the Simple API pip reads, and the form post twine
//! sends.
//!
//! ```text
//! GET  /pypi/simple/                    every project
//! GET  /pypi/simple/<name>/             one project's files
//! GET  /pypi/files/<name>/<filename>    one file
//! POST /pypi/                           twine upload
//! ```
//!
//! ## The trailing slash on `/simple/<name>/` is not cosmetic
//!
//! pip resolves a link relative to the page it read. Served without the
//! slash, `acme_widget-1.4.0.whl` resolves against `…/simple/` rather
//! than `…/simple/acme-widget/`, and every download 404s. pip's own
//! answer is to redirect, so this door does too rather than serving the
//! page at both and quietly breaking relative links at one of them. The
//! root index is the same page shape — its links are relative project
//! names — so `/simple` redirects to `/simple/` for the same reason.
//!
//! ## A version accretes here too
//!
//! `twine upload dist/*` posts the sdist and the wheel as two separate
//! requests, so the first creates the version and the second adds to
//! it — the same shape as Maven, for the same reason, and with the same
//! per-file immutability.
//!
//! ## A refusal is a reason phrase
//!
//! twine prints the **reason phrase** of the status line when an upload
//! fails — `HTTPError: 403 Forbidden from …` and then the phrase — and
//! shows the body only under `--verbose`. pip does the same with an
//! index it cannot read. So a refusal whose sentence is only in the body
//! reaches the person as the word "Forbidden", which tells a reader
//! nothing about why they may not publish. Every refusal this door
//! writes carries its sentence in both places: the reason phrase for
//! twine and pip, and the body for `--verbose`, curl, and any hop that
//! speaks HTTP/2, which has no reason phrase at all.

use crate::api::{internal, registry_door};
use crate::app::SharedState;
use crate::registry::{blobs, pypi};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use skein_control::auth::Scope;
use skein_control::packages::{self, Ecosystem, License, PackageFile};
use skein_control::registry::Org;

/// The body limit for an upload: the artifact ceiling, and room for the
/// form fields twine sends beside it — the README goes in
/// `description`, so a megabyte rather than a few hundred bytes.
pub const UPLOAD_BODY_LIMIT: usize = blobs::MAX_ARTIFACT + 1024 * 1024;

/// The longest reason phrase this door writes. A status line is not the
/// place for an essay, and the body carries the whole sentence anyway.
const MAX_REASON: usize = 512;

/// A refusal, in the shape twine and pip show a person: the sentence as
/// the reason phrase, and again as a plain-text body. Plain text because
/// twine prints whatever it is given under `--verbose`, and JSON braces
/// in a terminal help nobody.
fn pypi_error(status: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    let mut r = (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{msg}\n"),
    )
        .into_response();
    if let Some(p) = reason_phrase(&msg) {
        r.extensions_mut().insert(p);
    }
    r
}

/// `msg` as something a status line may carry.
///
/// HTTP/1.1 allows tab, space, visible ASCII and obs-text in a reason
/// phrase. obs-text is legal and still wrong here: Python's `http.client`
/// decodes the status line as Latin-1, so an em dash reaches the
/// person as `â€”`. Anything outside printable ASCII is replaced, and a
/// phrase hyper would refuse is simply not sent — the canonical phrase
/// and the body still are.
fn reason_phrase(msg: &str) -> Option<hyper::ext::ReasonPhrase> {
    let mut out = String::with_capacity(msg.len().min(MAX_REASON));
    for c in msg.trim().chars() {
        let c = match c {
            ' '..='~' => c,
            '\u{2014}' | '\u{2013}' => '-',
            '\u{2018}' | '\u{2019}' => '\'',
            '\u{201c}' | '\u{201d}' => '"',
            _ => '?',
        };
        if out.len() >= MAX_REASON {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        return None;
    }
    hyper::ext::ReasonPhrase::try_from(out).ok()
}

fn refusal(status: StatusCode, msg: String) -> Response {
    pypi_error(status, msg)
}

/// Authorize, in PyPI's dialect of refusal, and only then check PyPI is
/// switched on — the order every door keeps; see [`registry_door`].
fn open(
    state: &SharedState,
    headers: &HeaderMap,
    need: Scope,
) -> Result<(Org, skein_control::auth::Principal), Response> {
    let p = registry_door::authorize(state, headers, need, refusal)?;
    let org = registry_door::eco_org(state, headers, Ecosystem::Pypi)?;
    Ok((org, p))
}

/// `GET /pypi/*path`
pub async fn get(
    State(state): State<SharedState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    let org = match open(&state, &headers, Scope::PackageRead) {
        Ok((o, _)) => o,
        Err(r) => return r,
    };
    let raw = path.trim_start_matches('/');
    let trailing = raw.ends_with('/');
    let parts: Vec<&str> = raw.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["simple"] => {
            if !trailing {
                // The root's links are relative project names, so it has
                // the same trailing-slash rule as a project page: served
                // at `/simple`, `acme-widget/` resolves to
                // `/pypi/acme-widget/`, which is nothing.
                return redirect("/pypi/simple/");
            }
            simple_root(state, org).await
        }
        ["simple", name] => {
            if !trailing {
                // pip resolves a link relative to the page it read.
                // Without the slash every filename resolves one
                // directory up and every download 404s, so this is a
                // redirect rather than a page served at both addresses.
                return redirect(&format!("/pypi/simple/{name}/"));
            }
            simple_page(state, org, (*name).to_string()).await
        }
        ["files", name, filename] => {
            file(state, org, (*name).to_string(), (*filename).to_string()).await
        }
        _ => pypi_error(StatusCode::NOT_FOUND, "no such path"),
    }
}

fn redirect(to: &str) -> Response {
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, to)]).into_response()
}

/// Every project, all of them.
///
/// Paged, because `packages::list` answers at most a page at a time — a
/// single call asking for more is silently clamped, and a root index cut
/// off at the first page is one where the two hundred and first project
/// a mirror asks about does not exist.
async fn simple_root(state: SharedState, org: Org) -> Response {
    const PAGE: i64 = 200;
    let mut names = Vec::new();
    let mut offset = 0;
    loop {
        let page = match packages::list(
            &state.db,
            &org.id,
            Some(Ecosystem::Pypi),
            None,
            PAGE,
            offset,
        ) {
            Ok(ps) => ps,
            Err(e) => return internal(e),
        };
        let n = page.len() as i64;
        names.extend(page.into_iter().map(|p| p.normalized_name));
        if n < PAGE {
            break;
        }
        offset += n;
    }
    // Sorted, so the page is the same document whichever project was
    // touched last — `list` orders by activity, which is right for a
    // screen and noise for an index.
    names.sort();
    names.dedup();
    html(pypi::simple_root(&names))
}

async fn simple_page(state: SharedState, org: Org, name: String) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Pypi, &name) {
        Ok(Some(p)) => p,
        // An empty page rather than a 404. PEP 503 says an unknown
        // project *may* 404, and pip treats a 404 from an index as
        // "this index is broken" in some versions while an empty page
        // is unambiguously "not here" in all of them.
        Ok(None) | Err(_) => return html(pypi::simple_page(&name, &href_base(&name), &[])),
    };
    let versions = match packages::versions(&state.db, &pkg.id) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let mut links = Vec::new();
    for v in &versions {
        // A yanked version stays listed: PEP 592 yanking means "do not
        // pick this unless it is pinned", and removing it from the page
        // breaks every lockfile that already names it. What makes pip
        // not pick it is the mark on the link — see `pypi::simple_page`.
        let files = match packages::files(&state.db, &v.id) {
            Ok(f) => f,
            Err(e) => return internal(e),
        };
        for f in files {
            links.push(pypi::Link {
                filename: f.filename,
                sha256: f.digest,
                yanked: v.yanked.then(|| v.yank_reason.clone().unwrap_or_default()),
            });
        }
    }
    html(pypi::simple_page(
        &pkg.name,
        &href_base(&pkg.normalized_name),
        &links,
    ))
}

/// Where a project's artifacts live, as a path. Path-absolute rather
/// than fully qualified: the links then keep working through any proxy
/// in front of the registry without the page having to know which host
/// it was fetched on.
fn href_base(name: &str) -> String {
    format!("/pypi/files/{name}")
}

fn html(body: String) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body.into_bytes(),
    )
        .into_response()
}

async fn file(state: SharedState, org: Org, name: String, filename: String) -> Response {
    let pkg = match packages::by_name(&state.db, &org.id, Ecosystem::Pypi, &name) {
        Ok(Some(p)) => p,
        Ok(None) | Err(_) => return pypi_error(StatusCode::NOT_FOUND, "no such file"),
    };
    let found = match file_named(&state, &pkg.id, &filename) {
        Ok(f) => f,
        Err(e) => return internal(e),
    };
    let Some(f) = found else {
        return pypi_error(StatusCode::NOT_FOUND, "no such file");
    };
    match registry_door::read_artifact(&state, &f.digest).await {
        Ok(Some(bytes)) => (
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CACHE_CONTROL,
                    "private, max-age=31536000, immutable",
                ),
            ],
            bytes,
        )
            .into_response(),
        Ok(None) => pypi_error(StatusCode::NOT_FOUND, "no such file"),
        Err(r) => r,
    }
}

/// The file of this project called `filename`, under whichever version
/// holds it.
///
/// A file is addressed by project and filename — `/files/<name>/<file>`
/// — and not by version, so a filename has to name one file across the
/// whole project; see the check in [`upload`].
fn file_named(
    state: &SharedState,
    package_id: &str,
    filename: &str,
) -> Result<Option<PackageFile>, String> {
    for v in packages::versions(&state.db, package_id)? {
        if let Some(f) = packages::files(&state.db, &v.id)?
            .into_iter()
            .find(|f| f.filename == filename)
        {
            return Ok(Some(f));
        }
    }
    Ok(None)
}

/// `POST /pypi/` — twine's upload.
pub async fn upload(State(state): State<SharedState>, headers: HeaderMap, body: Bytes) -> Response {
    let (org, principal) = match open(&state, &headers, Scope::PackageWrite) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let Some(boundary) = pypi::boundary_of(content_type) else {
        return pypi_error(
            StatusCode::BAD_REQUEST,
            "a package upload is multipart/form-data, as twine sends it",
        );
    };
    let parts = match pypi::parse_multipart(&boundary, &body) {
        Ok(p) => p,
        Err(e) => return pypi_error(StatusCode::BAD_REQUEST, e),
    };
    let up = match pypi::parse_upload(&parts) {
        Ok(u) => u,
        Err(e) => return pypi_error(StatusCode::BAD_REQUEST, e),
    };

    // twine's own digest of the bytes it meant to send. A mismatch is a
    // truncated upload, not a policy question, and saying so is more
    // use than storing something nobody asked for.
    let digest = blobs::digest_of(&up.content);
    if let Some(claimed) = &up.sha256 {
        if digest.trim_start_matches("sha256:") != claimed {
            return pypi_error(
                StatusCode::BAD_REQUEST,
                format!(
                    "the upload does not match the SHA-256 twine sent for it \
                     ({claimed}); it arrived truncated or altered"
                ),
            );
        }
    }
    if let Err(e) = packages::normalize_version(&up.version) {
        return pypi_error(StatusCode::BAD_REQUEST, e);
    }

    let now = skein_control::ids::now_ms();
    let pkg = match packages::ensure(
        &state.db,
        &org.id,
        Ecosystem::Pypi,
        &up.name,
        packages::ORIGIN_LOCAL,
        now,
    ) {
        Ok(p) => p,
        Err(e) => return pypi_error(StatusCode::BAD_REQUEST, e),
    };
    if pkg.is_proxied() {
        return pypi_error(
            StatusCode::CONFLICT,
            format!(
                "{:?} is cached from an upstream registry here and cannot be published to",
                pkg.name
            ),
        );
    }

    // A filename names one file across the whole project, because that
    // is how it is fetched: `/files/<name>/<filename>`, no version in
    // it. The database only holds a filename unique *within* a version,
    // so without this a `2.0.0` upload carrying `1.0.0`'s wheel filename
    // was accepted, listed twice on the page with two digests, and
    // served in place of the original at the original's URL — a
    // published file changing its bytes, which is the one thing a
    // registry promises cannot happen.
    //
    // Checked before the bytes are stored, so a refusal costs nothing.
    // Two uploads racing the same filename into two different versions
    // can both pass this check; closing that needs the uniqueness in the
    // schema, and it takes a publisher racing their own upload.
    match file_named(&state, &pkg.id, &up.filename) {
        Ok(Some(_)) => return already_uploaded(&up, &pkg.name),
        Ok(None) => {}
        Err(e) => return internal(e),
    }

    let digest = match registry_door::store_artifact(&state, &up.content, now, refusal).await {
        Ok(d) => d,
        Err(r) => return r,
    };
    let file = PackageFile {
        filename: up.filename.clone(),
        digest,
        size_bytes: up.content.len() as i64,
        content_type: "application/octet-stream".into(),
        digests: "{}".to_string(),
    };

    let existing = match packages::version_by_number(&state.db, &pkg.id, &up.version) {
        Ok(v) => v,
        Err(e) => return internal(e),
    };
    let version_id = match existing {
        Some(v) => v.id,
        None => {
            match packages::publish_version(
                &state.db,
                &pkg.id,
                &up.version,
                &up.license,
                "{}",
                &[],
                &registry_door::provenance(&principal),
                now,
            ) {
                Ok(v) => v.id,
                // `twine upload dist/*` posts the sdist and the wheel
                // together; the loser of the race finds the version the
                // winner made, which is the right answer for both.
                Err(packages::PublishError::Exists) => {
                    match packages::version_by_number(&state.db, &pkg.id, &up.version) {
                        Ok(Some(v)) => v.id,
                        Ok(None) => return internal("the version vanished mid-upload".to_string()),
                        Err(e) => return internal(e),
                    }
                }
                Err(packages::PublishError::Other(e)) => {
                    return pypi_error(StatusCode::BAD_REQUEST, e)
                }
            }
        }
    };
    if let License::Declared(_) = &up.license {
        if let Err(e) = packages::set_license(&state.db, &version_id, &up.license) {
            return internal(e);
        }
    }

    match packages::add_file(&state.db, &version_id, &file) {
        Ok(()) => {}
        Err(packages::PublishError::Exists) => return already_uploaded(&up, &pkg.name),
        Err(packages::PublishError::Other(e)) => return internal(e),
    }

    crate::api::audit(
        &state,
        &principal,
        "package.publish",
        serde_json::json!({
            "ecosystem": "pypi",
            "name": pkg.name,
            "version": up.version,
            "filename": up.filename,
        }),
    );
    // twine treats any 2xx as success and prints the body on failure.
    StatusCode::OK.into_response()
}

/// 409, which is also what `twine upload --skip-existing` reads as
/// "already there, carry on".
fn already_uploaded(up: &pypi::Upload, name: &str) -> Response {
    pypi_error(
        StatusCode::CONFLICT,
        format!(
            "{} is already uploaded for {name}, and a published file never changes here",
            up.filename
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The phrase is what twine prints, so it must survive the trip:
    /// printable ASCII kept as it is, the punctuation a sentence here
    /// actually uses turned into its ASCII twin rather than Latin-1
    /// mojibake, and anything that could end the status line — or write
    /// a header after it — never sent.
    #[test]
    fn a_refusal_becomes_a_reason_phrase_a_status_line_can_carry() {
        let phrase = |m: &str| reason_phrase(m).map(|p| p.as_bytes().to_vec());
        assert_eq!(
            phrase("rita is a reader here, and a reader may not publish to this registry"),
            Some(b"rita is a reader here, and a reader may not publish to this registry".to_vec())
        );
        assert_eq!(
            phrase("a \u{2014} b \u{201c}c\u{201d} \u{2018}d\u{2019} caf\u{e9}"),
            Some(b"a - b \"c\" 'd' caf?".to_vec())
        );
        assert_eq!(
            phrase("line one\r\nX-Injected: 1"),
            Some(b"line one??X-Injected: 1".to_vec()),
            "a newline in a message would have ended the status line"
        );
        assert_eq!(phrase("   "), None);
        assert_eq!(phrase(&"x".repeat(5000)).map(|p| p.len()), Some(MAX_REASON));

        // …and the response carries it, with the body beside it.
        let r = pypi_error(StatusCode::FORBIDDEN, "no, and here is why");
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            r.extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .map(|p| p.as_bytes()),
            Some(&b"no, and here is why"[..])
        );
    }
}
