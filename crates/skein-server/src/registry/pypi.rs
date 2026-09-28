//! PyPI's two halves: the Simple API pip reads, and the
//! `multipart/form-data` upload twine posts.
//!
//! They have almost nothing in common. Installing is an HTML page of
//! links (PEP 503); publishing is a form post with the artifact in a
//! field called `content` and everything else in fields beside it.
//!
//! ## Why the multipart parser is written here
//!
//! There is no multipart parser in this workspace and `axum`'s is
//! behind a feature we do not carry. The format is small and completely
//! specified, and the one this needs to read is narrower still — twine
//! sends no nested parts, no `base64` transfer encoding and no
//! continuation headers. Writing it here keeps the dependency out and,
//! more usefully, keeps the parser *strict*: it refuses shapes a
//! general one would accept, and every one of those shapes is a way for
//! two different bodies to be read as the same upload.
//!
//! ## Names are folded, and that is an authorization decision
//!
//! PEP 503 says `Foo.Bar_baz` and `foo-bar-baz` are one project.
//! `packages::normalize_name` already folds them, which is where it
//! belongs: an adapter that folded differently from its neighbours
//! would be an adapter that could create a second row for a name
//! another one already owns.

use skein_control::packages::License;

/// One part of a `multipart/form-data` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    pub name: String,
    /// Present on the file part, absent on the ordinary fields.
    pub filename: Option<String>,
    pub value: Vec<u8>,
}

/// The `boundary=` of a `multipart/form-data` content type.
///
/// A quoted boundary is legal and twine does not send one, but a proxy
/// in front of us may rewrite the header — so both are read rather than
/// only the shape we happen to have seen.
pub fn boundary_of(content_type: &str) -> Option<String> {
    let (kind, params) = content_type.split_once(';')?;
    if !kind.trim().eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }
    for param in params.split(';') {
        let (k, v) = param.split_once('=')?;
        if k.trim().eq_ignore_ascii_case("boundary") {
            let v = v.trim().trim_matches('"');
            if v.is_empty() || v.len() > 70 {
                return None;
            }
            return Some(v.to_string());
        }
    }
    None
}

/// Split a `multipart/form-data` body into its parts.
///
/// Strict on purpose. Every refusal below is a shape that could make
/// two different bodies read as one upload, and "be liberal in what you
/// accept" is how a parser in front of an authorization decision comes
/// to disagree with the one behind it.
pub fn parse_multipart(boundary: &str, body: &[u8]) -> Result<Vec<Part>, String> {
    let delim = format!("--{boundary}").into_bytes();
    let mut parts = Vec::new();
    let mut at = match find(body, &delim, 0) {
        Some(0) => delim.len(),
        // A preamble before the first boundary is legal in MIME and is
        // not something any registry client sends.
        _ => return Err("that is not a multipart body".into()),
    };
    loop {
        // After a delimiter comes either `--` (the end) or CRLF.
        if body[at..].starts_with(b"--") {
            return Ok(parts);
        }
        let Some(rest) = body[at..].strip_prefix(b"\r\n") else {
            return Err("a multipart boundary is not followed by a newline".into());
        };
        let start = body.len() - rest.len();
        let Some(headers_end) = find(body, b"\r\n\r\n", start) else {
            return Err("a multipart part has no header block".into());
        };
        let headers = std::str::from_utf8(&body[start..headers_end])
            .map_err(|_| "a multipart part's headers are not text".to_string())?;
        let value_start = headers_end + 4;

        // The next boundary ends this part, and the CRLF before it
        // belongs to the delimiter rather than to the value.
        let Some(next) = find(body, &delim, value_start) else {
            return Err("a multipart body ends without its closing boundary".into());
        };
        if next < 2 || &body[next - 2..next] != b"\r\n" {
            return Err("a multipart part does not end with a newline".into());
        }
        let value = body[value_start..next - 2].to_vec();

        let Some((name, filename)) = disposition(headers) else {
            return Err("a multipart part has no name".into());
        };
        parts.push(Part {
            name,
            filename,
            value,
        });
        at = next + delim.len();
    }
}

/// `Content-Disposition: form-data; name="x"; filename="y"`.
fn disposition(headers: &str) -> Option<(String, Option<String>)> {
    let line = headers
        .split("\r\n")
        .find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))?;
    let (_, params) = line.split_once(';')?;
    let mut name = None;
    let mut filename = None;
    for param in params.split(';') {
        let Some((k, v)) = param.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"').to_string();
        match k.trim().to_ascii_lowercase().as_str() {
            "name" => name = Some(v),
            "filename" => filename = Some(v),
            _ => {}
        }
    }
    Some((name?, filename))
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// What twine posted.
#[derive(Debug, Clone)]
pub struct Upload {
    pub name: String,
    pub version: String,
    pub filename: String,
    pub content: Vec<u8>,
    /// The hex SHA-256 twine computed. Checked against ours: this is
    /// the client's claim about the bytes it meant to send, and a
    /// mismatch is a truncated upload, not a policy question.
    pub sha256: Option<String>,
    pub license: License,
}

/// Read an upload out of the parts, refusing anything that is not one.
pub fn parse_upload(parts: &[Part]) -> Result<Upload, String> {
    let field = |n: &str| -> Option<String> {
        parts
            .iter()
            .find(|p| p.name == n && p.filename.is_none())
            .and_then(|p| String::from_utf8(p.value.clone()).ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    };
    // twine has posted `:action=file_upload` since forever, and a body
    // without it is either a different verb or not twine at all.
    // Refusing is what makes "this door only uploads files" true rather
    // than merely usual.
    match field(":action").as_deref() {
        Some("file_upload") => {}
        Some(other) => return Err(format!("this repository does not support :action={other}")),
        None => return Err("a PyPI upload needs :action=file_upload".into()),
    }
    let name = field("name").ok_or("an upload needs a name")?;
    let version = field("version").ok_or("an upload needs a version")?;
    let file = parts
        .iter()
        .find(|p| p.name == "content" && p.filename.is_some())
        .ok_or("an upload needs a file in the \"content\" field")?;
    let filename = file
        .filename
        .clone()
        .filter(|f| !f.is_empty())
        .ok_or("the uploaded file has no name")?;
    if !is_distribution_filename(&filename) {
        return Err(format!("{filename:?} is not a distribution filename"));
    }

    let classifiers: Vec<String> = parts
        .iter()
        .filter(|p| p.name == "classifiers" && p.filename.is_none())
        .filter_map(|p| String::from_utf8(p.value.clone()).ok())
        .collect();
    Ok(Upload {
        name,
        version,
        filename,
        content: file.value.clone(),
        sha256: field("sha256_digest").map(|s| s.to_ascii_lowercase()),
        license: license_of(
            // PEP 639's `License-Expression` is already SPDX and wins
            // outright; the free-text `license` field is not and is
            // read only through the classifier table below.
            field("license_expression").as_deref(),
            field("license").as_deref(),
            &classifiers,
        ),
    })
}

/// Whether `filename` may be stored and linked to.
///
/// The filename becomes a path component and a link in a document
/// other people's tools follow, so it is held to the characters a
/// distribution filename is actually made of — a normalized name, a PEP
/// 440 version (which brings `!` for an epoch and `+` for a local
/// label), compatibility tags, and an extension — rather than to a list
/// of characters known to be dangerous.
///
/// An allow-list, because the deny-list it replaced missed the ones that
/// break the *link* rather than the page: `#` starts the fragment pip
/// reads the digest from, `?` starts a query, and `%` is decoded by the
/// router, so the name pip asks for is not the name that was stored.
/// Each of those was accepted, stored and listed with an href that
/// answered 404. The rest of what the allow-list refuses — a space, `&`,
/// `;` — did resolve, and is refused anyway on this parser's usual
/// grounds: no build tool writes it, so only a hand-made request could,
/// and a name the index has to be careful with is a name it need not
/// hold.
pub fn is_distribution_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename.len() <= 255
        && !filename.starts_with('.')
        && !filename.starts_with('-')
        && filename
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+!".contains(&b))
}

/// Three sources, in the order of how much they can be trusted.
///
/// 1. **`License-Expression`** (PEP 639, metadata 2.4) is *defined* to
///    be an SPDX expression. Taken as it stands.
/// 2. **A trove classifier** is drawn from a fixed vocabulary, so the
///    mapping below is exact rather than a guess — that is the whole
///    reason it is preferred to the field a human typed.
/// 3. **`License`** is free text and famously holds things like "see
///    LICENSE" and the entire MIT licence pasted in. Read only through
///    the same exact table; anything else is unknown.
///
/// Unknown is a decision the organization makes per ecosystem, not a
/// gap. Guessing here would admit an artifact under a rule written for
/// a different licence, and nothing would ever surface it.
pub fn license_of(
    expression: Option<&str>,
    free_text: Option<&str>,
    classifiers: &[String],
) -> License {
    if let Some(expr) = expression.map(str::trim).filter(|e| !e.is_empty()) {
        return License::Declared(expr.to_string());
    }
    let from_classifiers: Vec<&'static str> = classifiers
        .iter()
        .filter_map(|c| spdx_of_classifier(c))
        .collect();
    if !from_classifiers.is_empty() {
        // Several classifiers mean a *choice* in Python packaging — a
        // project classified under both MIT and Apache is offering
        // either — so `OR`, which is also the reading that lets a
        // policy admit it on the side it actually allows.
        let mut ids = from_classifiers;
        ids.dedup();
        return License::Declared(ids.join(" OR "));
    }
    match free_text.and_then(spdx_of_free_text) {
        Some(id) => License::Declared(id.to_string()),
        None => License::Unknown,
    }
}

/// Trove classifiers are a **fixed vocabulary**, so this is a mapping
/// rather than a guess. That is why it is preferred to the free-text
/// field a person typed by hand.
pub fn spdx_of_classifier(c: &str) -> Option<&'static str> {
    let c = c.trim();
    let tail = c.strip_prefix("License :: OSI Approved :: ")?;
    Some(match tail {
        "MIT License" | "MIT No Attribution License (MIT-0)" => "MIT",
        "Apache Software License" => "Apache-2.0",
        "BSD License" => "BSD-3-Clause",
        "ISC License (ISCL)" => "ISC",
        "Mozilla Public License 2.0 (MPL 2.0)" => "MPL-2.0",
        "GNU General Public License v2 (GPLv2)" => "GPL-2.0-only",
        "GNU General Public License v3 (GPLv3)" => "GPL-3.0-only",
        "GNU Lesser General Public License v2 (LGPLv2)" => "LGPL-2.0-only",
        "GNU Lesser General Public License v3 (LGPLv3)" => "LGPL-3.0-only",
        "GNU Affero General Public License v3" => "AGPL-3.0-only",
        "The Unlicense (Unlicense)" => "Unlicense",
        "Python Software Foundation License" => "PSF-2.0",
        "Eclipse Public License 2.0 (EPL-2.0)" => "EPL-2.0",
        // `License :: OSI Approved` on its own, and anything the table
        // does not know, is unknown rather than guessed.
        _ => return None,
    })
}

/// The handful of free-text spellings that are unambiguous.
///
/// Deliberately tiny. "BSD" alone is three different licences and
/// "GPL" is six; neither is here, and an artifact declaring one lands
/// on the organization's `unknown` disposition instead of being
/// admitted under a rule that meant something else.
pub fn spdx_of_free_text(s: &str) -> Option<&'static str> {
    let n = s.trim().to_ascii_lowercase();
    Some(match n.as_str() {
        "mit" | "mit license" | "the mit license" => "MIT",
        "apache-2.0" | "apache 2.0" | "apache license 2.0" | "apache license, version 2.0" => {
            "Apache-2.0"
        }
        "bsd-3-clause" | "bsd 3-clause" => "BSD-3-Clause",
        "bsd-2-clause" | "bsd 2-clause" => "BSD-2-Clause",
        "isc" => "ISC",
        "mpl-2.0" => "MPL-2.0",
        "gpl-3.0-only" | "gpl-3.0" | "gplv3" => "GPL-3.0-only",
        "agpl-3.0-only" | "agpl-3.0" => "AGPL-3.0-only",
        "unlicense" => "Unlicense",
        _ => return None,
    })
}

/// One file on a project's page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub filename: String,
    /// The SHA-256 it is stored under, `sha256:`-prefixed or bare.
    pub sha256: String,
    /// PEP 592: `Some` for a file of a yanked release, holding the
    /// reason — empty when none was given, which is still a yank.
    pub yanked: Option<String>,
}

/// A PEP 503 simple-index page for one project.
///
/// `href_base` is a **path-absolute** prefix for the artifacts, e.g.
/// `/pypi/files/acme-widget`. Not a bare filename: pip resolves a link
/// relative to the page it read, and the page lives under
/// `/simple/<name>/` while the files do not — a relative
/// `acme_widget-1.0.whl` resolves to `/simple/<name>/acme_widget-1.0.whl`
/// and 404s. Path-absolute rather than fully qualified so the links
/// keep working through any proxy in front of the registry without the
/// page having to know what host it was fetched on.
///
/// The fragment on each link is not decoration: pip verifies the file
/// against it, so an index that omits it is one where a corrupted
/// download installs.
///
/// A yanked release stays on the page — removing it breaks every
/// lockfile that pins it — and carries PEP 592's `data-yanked`, which is
/// the only thing that tells pip not to *choose* it. Listing it without
/// the attribute is not a yank at all: pip takes the newest version it
/// sees, so the release somebody yanked because it was broken is the
/// one every unpinned install gets.
pub fn simple_page(name: &str, href_base: &str, files: &[Link]) -> String {
    let mut out = String::from(
        "<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" \
         content=\"1.0\">\n    <title>Links for ",
    );
    out.push_str(&html_escape(name));
    out.push_str("</title>\n  </head>\n  <body>\n    <h1>Links for ");
    out.push_str(&html_escape(name));
    out.push_str("</h1>\n");
    let base = href_base.trim_end_matches('/');
    for f in files {
        let yanked = match &f.yanked {
            Some(reason) => format!(" data-yanked=\"{}\"", html_escape(reason)),
            None => String::new(),
        };
        out.push_str(&format!(
            "    <a href=\"{}/{}#sha256={}\"{yanked}>{}</a><br>\n",
            html_escape(base),
            html_escape(&f.filename),
            html_escape(f.sha256.trim_start_matches("sha256:")),
            html_escape(&f.filename)
        ));
    }
    out.push_str("  </body>\n</html>\n");
    out
}

/// The root index. pip only reads this for `pip search`-shaped things
/// and for a mirror; it is cheap and its absence is a 404 somebody has
/// to explain.
pub fn simple_root(names: &[String]) -> String {
    let mut out = String::from(
        "<!DOCTYPE html>\n<html>\n  <head>\n    <meta name=\"pypi:repository-version\" \
         content=\"1.0\">\n    <title>Simple index</title>\n  </head>\n  <body>\n",
    );
    for n in names {
        let e = html_escape(n);
        out.push_str(&format!("    <a href=\"{e}/\">{e}</a><br>\n"));
    }
    out.push_str("  </body>\n</html>\n");
    out
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(parts: &[(&str, Option<&str>, &[u8])], boundary: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, filename, value) in parts {
            out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            out.extend_from_slice(
                match filename {
                    Some(f) => format!(
                        "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\
                         Content-Type: application/octet-stream\r\n\r\n"
                    ),
                    None => format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n"),
                }
                .as_bytes(),
            );
            out.extend_from_slice(value);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        out
    }

    fn upload_parts() -> Vec<(&'static str, Option<&'static str>, &'static [u8])> {
        vec![
            (":action", None, b":action" as &[u8]),
            ("protocol_version", None, b"1"),
            ("name", None, b"acme-widget"),
            ("version", None, b"1.4.0"),
            ("filetype", None, b"bdist_wheel"),
            ("metadata_version", None, b"2.1"),
            ("sha256_digest", None, b"ABCDEF"),
            (
                "classifiers",
                None,
                b"License :: OSI Approved :: MIT License",
            ),
            (
                "content",
                Some("acme_widget-1.4.0-py3-none-any.whl"),
                b"PK the wheel",
            ),
        ]
    }

    fn fixed(
        mut parts: Vec<(&'static str, Option<&'static str>, &'static [u8])>,
    ) -> Vec<(&'static str, Option<&'static str>, &'static [u8])> {
        parts[0] = (":action", None, b"file_upload");
        parts
    }

    #[test]
    fn a_boundary_is_read_quoted_or_bare() {
        assert_eq!(
            boundary_of("multipart/form-data; boundary=abc123").as_deref(),
            Some("abc123")
        );
        assert_eq!(
            boundary_of("Multipart/Form-Data; charset=utf-8; BOUNDARY=\"a b c\"").as_deref(),
            Some("a b c")
        );
        assert_eq!(boundary_of("application/json"), None);
        assert_eq!(boundary_of("multipart/form-data"), None);
        assert_eq!(boundary_of("multipart/form-data; boundary="), None);
        // RFC 2046 caps a boundary at 70 characters, and a parser that
        // accepts an unbounded one accepts a body whose delimiter is
        // longer than the body.
        assert_eq!(
            boundary_of(&format!("multipart/form-data; boundary={}", "x".repeat(71))),
            None
        );
    }

    /// The shapes a general parser would wave through. A content type
    /// that is not multipart at all, and one that is but names no
    /// boundary, are different mistakes and neither is a body.
    #[test]
    fn a_content_type_that_is_not_multipart_yields_no_boundary() {
        assert_eq!(boundary_of("application/json; charset=utf-8"), None);
        assert_eq!(boundary_of("multipart/form-data; charset=utf-8"), None);
    }

    /// The delimiter framing itself, which is what tells one part from
    /// the next. A body whose parts are not framed the way the format
    /// says is refused rather than guessed at — every guess here is a
    /// way for two different bodies to be read as one upload.
    #[test]
    fn a_part_that_is_not_framed_by_crlf_is_refused() {
        assert!(parse_multipart("B", b"--Bxyz").is_err());
        // The two bytes before the next boundary are `lo`, not CRLF, so
        // the part does not end where the format says it does.
        let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello--B--\r\n";
        assert!(parse_multipart("B", body).is_err());
    }

    /// `Content-Disposition` carries parameters we do not read, and one
    /// can be a bare flag with no `=` at all. Neither is a reason to
    /// refuse the part — they are simply not the two we want.
    #[test]
    fn disposition_parameters_we_do_not_read_are_skipped() {
        let body = b"--B\r\nContent-Disposition: form-data; flag; charset=utf-8; \
                     name=\"a\"\r\n\r\nv\r\n--B--\r\n";
        let parts = parse_multipart("B", body).expect("parses");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].name, "a");
        assert_eq!(parts[0].value, b"v");
        assert!(parts[0].filename.is_none());
    }

    /// The classifier table across the vocabulary that actually
    /// appears. Exact rather than fuzzy: a tail the table does not know
    /// is `None`, because turning "Nonsense License" into something
    /// would admit an artifact under a rule that meant another licence.
    #[test]
    fn the_classifier_table_maps_what_it_knows_and_nothing_else() {
        for (classifier, want) in [
            ("BSD License", "BSD-3-Clause"),
            ("ISC License (ISCL)", "ISC"),
            ("GNU General Public License v3 (GPLv3)", "GPL-3.0-only"),
            ("GNU General Public License v2 (GPLv2)", "GPL-2.0-only"),
            (
                "GNU Lesser General Public License v3 (LGPLv3)",
                "LGPL-3.0-only",
            ),
            (
                "GNU Lesser General Public License v2 (LGPLv2)",
                "LGPL-2.0-only",
            ),
            ("GNU Affero General Public License v3", "AGPL-3.0-only"),
            ("Python Software Foundation License", "PSF-2.0"),
            ("Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"),
            ("Eclipse Public License 2.0 (EPL-2.0)", "EPL-2.0"),
            ("The Unlicense (Unlicense)", "Unlicense"),
            ("MIT No Attribution License (MIT-0)", "MIT"),
        ] {
            let full = format!("License :: OSI Approved :: {classifier}");
            assert_eq!(spdx_of_classifier(&full), Some(want), "{full}");
        }
        // The prefix is there and the tail is not one we know.
        assert_eq!(
            spdx_of_classifier("License :: OSI Approved :: Nonsense License"),
            None
        );
        // Not a licence classifier at all.
        assert_eq!(
            spdx_of_classifier("Programming Language :: Python :: 3"),
            None
        );
    }

    /// The free-text spellings that are unambiguous. Each is one seen
    /// in the wild; the ambiguous ones are checked next door.
    #[test]
    fn the_free_text_table_reads_the_spellings_that_are_unambiguous() {
        for (text, want) in [
            ("Apache 2.0", "Apache-2.0"),
            ("Apache License, Version 2.0", "Apache-2.0"),
            ("apache-2.0", "Apache-2.0"),
            ("BSD 3-Clause", "BSD-3-Clause"),
            ("BSD-2-Clause", "BSD-2-Clause"),
            ("ISC", "ISC"),
            ("MPL-2.0", "MPL-2.0"),
            ("GPLv3", "GPL-3.0-only"),
            ("AGPL-3.0", "AGPL-3.0-only"),
            ("Unlicense", "Unlicense"),
            ("The MIT License", "MIT"),
        ] {
            assert_eq!(spdx_of_free_text(text), Some(want), "{text}");
        }
    }

    #[test]
    fn twines_upload_is_read_field_by_field() {
        let raw = body(&fixed(upload_parts()), "BOUND");
        let parts = parse_multipart("BOUND", &raw).expect("parses");
        let up = parse_upload(&parts).expect("an upload");
        assert_eq!(up.name, "acme-widget");
        assert_eq!(up.version, "1.4.0");
        assert_eq!(up.filename, "acme_widget-1.4.0-py3-none-any.whl");
        assert_eq!(up.content, b"PK the wheel");
        // Lower-cased, because that is how a hex digest compares.
        assert_eq!(up.sha256.as_deref(), Some("abcdef"));
        assert_eq!(up.license, License::Declared("MIT".into()));
    }

    /// Every one of these is a shape that could make two different
    /// bodies read as one upload, or none at all. A general parser
    /// would accept several of them.
    #[test]
    fn a_malformed_multipart_body_is_refused_rather_than_guessed_at() {
        let ok = body(&fixed(upload_parts()), "BOUND");
        for (what, raw) in [
            ("empty", Vec::new()),
            ("no leading boundary", b"just some bytes".to_vec()),
            (
                "a preamble before the first boundary",
                [b"preamble\r\n".to_vec(), ok.clone()].concat(),
            ),
            ("truncated mid-part", ok[..ok.len() / 2].to_vec()),
            (
                "no closing boundary",
                ok[..ok.len() - "--BOUND--\r\n".len()].to_vec(),
            ),
        ] {
            assert!(parse_multipart("BOUND", &raw).is_err(), "{what} was parsed");
        }
        // A part with no `name` has nothing to be read as.
        let nameless = b"--B\r\nContent-Type: text/plain\r\n\r\nx\r\n--B--\r\n";
        assert!(parse_multipart("B", nameless).is_err());
    }

    /// A body that parses but is not an upload. Each of these is a
    /// separate sentence in somebody's `twine upload` output, so each
    /// is refused separately rather than as one "bad request".
    #[test]
    fn a_body_that_is_not_a_file_upload_is_refused_for_the_right_reason() {
        let missing = |field: &str| {
            let parts: Vec<_> = fixed(upload_parts())
                .into_iter()
                .filter(|(n, _, _)| *n != field)
                .collect();
            let raw = body(&parts, "BOUND");
            parse_upload(&parse_multipart("BOUND", &raw).expect("parses"))
                .expect_err(&format!("an upload with no {field} was accepted"))
        };
        assert!(missing(":action").contains(":action"));
        assert!(missing("name").contains("name"));
        assert!(missing("version").contains("version"));
        assert!(missing("content").contains("content"));

        // A verb this door does not do. twine's `file_upload` is the
        // only one; the others (`submit`, `doc_upload`) were PyPI
        // features that no longer exist.
        let mut parts = fixed(upload_parts());
        parts[0] = (":action", None, b"doc_upload");
        let raw = body(&parts, "BOUND");
        let err = parse_upload(&parse_multipart("BOUND", &raw).unwrap()).unwrap_err();
        assert!(err.contains("doc_upload"), "{err}");
    }

    /// The filename becomes a path component and a link in a document
    /// other people's tools follow, so it is refused rather than
    /// cleaned up — a cleaned name is a second way to address one
    /// stored object.
    #[test]
    fn a_dangerous_distribution_filename_is_refused() {
        for bad in [
            "../../etc/passwd",
            "a/b.whl",
            "a\\b.whl",
            ".hidden.whl",
            "x\u{0}.whl",
            "caf\u{e9}.whl",
            "a\".whl",
            "<script>.whl",
            "",
        ] {
            let mut parts = fixed(upload_parts());
            let last = parts.len() - 1;
            parts[last] = (
                "content",
                Some(Box::leak(bad.to_string().into_boxed_str())),
                b"x",
            );
            let raw = body(&parts, "BOUND");
            let parsed = parse_multipart("BOUND", &raw).expect("parses");
            assert!(
                parse_upload(&parsed).is_err(),
                "{bad:?} was accepted as a filename"
            );
        }
    }

    /// The characters that break a *link* rather than a page. `#`, `?`
    /// and `%` were accepted by the deny-list this replaced, stored, and
    /// listed with an href that answered 404: `#` ends the path where
    /// the digest fragment should start, `?` begins a query, and `%` is
    /// decoded by the router into a different name. The others no build
    /// tool writes. And the shapes real build tools produce, epoch and
    /// local label included, still pass.
    #[test]
    fn a_filename_that_cannot_be_followed_as_a_link_is_refused() {
        for bad in [
            "acme_widget-1.0#x.whl",
            "acme_widget-1.0?x=1.whl",
            "acme_widget-1.0%2e.whl",
            "acme widget-1.0.tar.gz",
            "acme&widget-1.0.tar.gz",
            "acme'widget-1.0.tar.gz",
            "acme;widget-1.0.tar.gz",
            "-acme-1.0.tar.gz",
            &"a".repeat(256),
        ] {
            assert!(!is_distribution_filename(bad), "{bad:?} was accepted");
        }
        for good in [
            "acme_widget-1.4.0-py3-none-any.whl",
            "acme_widget-1.4.0.tar.gz",
            "Acme.Widget-1.4.0.zip",
            "acme_widget-1!2.0+local.7-py2.py3-none-manylinux_2_17_x86_64.whl",
            "acme-widget-1.0rc1.tar.gz",
        ] {
            assert!(is_distribution_filename(good), "{good:?} was refused");
        }
    }

    /// Three sources, and the order matters. `License-Expression` is
    /// *defined* to be SPDX; a classifier comes from a fixed
    /// vocabulary so its mapping is exact; the free-text field is
    /// neither and is read through the same exact table or not at all.
    #[test]
    fn the_licence_is_taken_from_the_most_trustworthy_source_present() {
        let mit = vec!["License :: OSI Approved :: MIT License".to_string()];
        // PEP 639 wins outright, even against a classifier that
        // disagrees — it is the only one of the three the standard says
        // is an SPDX expression.
        assert_eq!(
            license_of(Some("Apache-2.0 OR MIT"), Some("whatever"), &mit),
            License::Declared("Apache-2.0 OR MIT".into())
        );
        assert_eq!(
            license_of(None, Some("see LICENSE"), &mit),
            License::Declared("MIT".into())
        );
        assert_eq!(
            license_of(None, Some("MIT"), &[]),
            License::Declared("MIT".into())
        );
        // Several classifiers mean a *choice* in Python packaging, so
        // `OR` — which is also the reading that lets a policy admit the
        // project on the side it actually allows.
        assert_eq!(
            license_of(
                None,
                None,
                &[
                    "License :: OSI Approved :: MIT License".to_string(),
                    "License :: OSI Approved :: Apache Software License".to_string(),
                ]
            ),
            License::Declared("MIT OR Apache-2.0".into())
        );
    }

    /// "BSD" alone is three licences and "GPL" is six. Neither is in
    /// the table, so a project declaring one lands on the
    /// organization's `unknown` disposition rather than being admitted
    /// under a rule that meant something else.
    #[test]
    fn an_ambiguous_or_unknown_licence_is_unknown_rather_than_guessed() {
        assert_eq!(license_of(None, Some("BSD"), &[]), License::Unknown);
        assert_eq!(license_of(None, Some("GPL"), &[]), License::Unknown);
        assert_eq!(license_of(None, Some("see LICENSE"), &[]), License::Unknown);
        assert_eq!(license_of(None, None, &[]), License::Unknown);
        assert_eq!(
            license_of(None, None, &["License :: OSI Approved".to_string()]),
            License::Unknown
        );
        assert_eq!(license_of(Some("   "), None, &[]), License::Unknown);
    }

    /// pip verifies a download against the fragment on the link, so an
    /// index that omits it is one where a corrupted download installs.
    #[test]
    fn the_simple_page_carries_a_digest_on_every_link() {
        let page = simple_page(
            "acme-widget",
            "/pypi/files/acme-widget",
            &[link(
                "acme_widget-1.4.0-py3-none-any.whl",
                "sha256:deadbeef",
                None,
            )],
        );
        assert!(
            page.contains(
                "<a href=\"/pypi/files/acme-widget/\
                 acme_widget-1.4.0-py3-none-any.whl#sha256=deadbeef\">\
                 acme_widget-1.4.0-py3-none-any.whl</a>"
            ),
            "{page}"
        );
        assert!(page.contains("pypi:repository-version"), "{page}");
        assert!(
            !page.contains("data-yanked"),
            "a release nobody yanked is marked yanked: {page}"
        );
    }

    fn link(filename: &str, sha256: &str, yanked: Option<&str>) -> Link {
        Link {
            filename: filename.into(),
            sha256: sha256.into(),
            yanked: yanked.map(str::to_string),
        }
    }

    /// PEP 592. A yanked file stays linked — a lockfile that pins it
    /// must keep installing — and carries `data-yanked`, which is what
    /// stops pip *choosing* it. An empty reason is still a yank: the
    /// attribute's presence is the signal, its value only the reason.
    #[test]
    fn a_yanked_file_stays_linked_and_is_marked_yanked() {
        let page = simple_page(
            "acme-widget",
            "/pypi/files/acme-widget",
            &[
                link("acme_widget-1.0.0.tar.gz", "sha256:aa", None),
                link(
                    "acme_widget-1.1.0.tar.gz",
                    "sha256:bb",
                    Some("broke <imports> & \"more\""),
                ),
                link("acme_widget-1.2.0.tar.gz", "sha256:cc", Some("")),
            ],
        );
        let line = |f: &str| {
            page.lines()
                .find(|l| l.contains(&format!(">{f}</a>")))
                .unwrap_or_else(|| panic!("{f} is not linked: {page}"))
                .to_string()
        };
        assert!(
            !line("acme_widget-1.0.0.tar.gz").contains("data-yanked"),
            "{page}"
        );
        assert!(
            line("acme_widget-1.1.0.tar.gz")
                .contains("data-yanked=\"broke &lt;imports&gt; &amp; &quot;more&quot;\""),
            "the reason is not on the link, or not escaped: {page}"
        );
        assert!(
            line("acme_widget-1.2.0.tar.gz").contains("data-yanked=\"\""),
            "a yank with no reason was not marked: {page}"
        );
    }

    /// A name or filename carrying HTML would otherwise be served to
    /// every developer in the organization as markup.
    #[test]
    fn the_index_escapes_what_html_requires() {
        // Every character HTML requires escaping, in one page: a name
        // or filename carrying markup would otherwise be served to
        // every developer in the organization as markup.
        let page = simple_page(
            "a<b>&c'd",
            "/files/x",
            &[link("x\"y'z>.whl", "sha256:00", Some("<'&'>"))],
        );
        assert!(page.contains("a&lt;b&gt;&amp;c&#39;d"), "{page}");
        assert!(page.contains("x&quot;y&#39;z&gt;.whl"), "{page}");
        assert!(
            page.contains("data-yanked=\"&lt;&#39;&amp;&#39;&gt;\""),
            "{page}"
        );
        assert!(!page.contains("a<b>"), "{page}");

        let root = simple_root(&["a<b".to_string()]);
        assert!(root.contains("<a href=\"a&lt;b/\">a&lt;b</a>"), "{root}");
    }
}
