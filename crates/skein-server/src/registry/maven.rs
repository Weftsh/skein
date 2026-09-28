//! Maven's wire protocol, which is a file server with a naming
//! convention.
//!
//! There is no API here. Maven `GET`s and `PUT`s files at paths it
//! derives from a coordinate, and `maven-metadata.xml` is the only
//! document the repository itself has to produce. Everything below is
//! that convention plus one document generator, and all of it is pure.
//!
//! ## The path is the coordinate, read from the right
//!
//! ```text
//! com/acme/widget/1.4.0/widget-1.4.0.jar
//! └───┬──┘ └─┬──┘ └─┬─┘ └──────┬───────┘
//!  groupId  artifactId version  filename
//! ```
//!
//! Read from the **right**: filename, version, artifactId, and whatever
//! is left is the groupId with its dots written as slashes. Read from
//! the left it is ambiguous — a groupId has any number of segments, so
//! `com/acme/widget/…` could be group `com` artifact `acme`, and
//! guessing wrong stores one project's jar under another's name.
//!
//! ## SNAPSHOT versions are refused, and that is a real limitation
//!
//! A `-SNAPSHOT` version is *mutable by design*: the same coordinate
//! resolves to different bytes on different days, and Maven keeps a
//! per-version `maven-metadata.xml` naming the current timestamped
//! build. That is the opposite of the invariant this registry is built
//! on — a published version's bytes never change — and it is a
//! supply-chain hole rather than a convenience: "which snapshot was in
//! that release?" has no answer.
//!
//! So a snapshot upload is refused with a sentence saying so. This is
//! stated on the docs page rather than discovered, because for a team
//! that publishes snapshots on every merge it is the difference between
//! this being usable and not.

/// What a Maven request is addressing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// One file of one version.
    Artifact {
        /// `groupId:artifactId`, which is what `packages` stores.
        name: String,
        version: String,
        filename: String,
    },
    /// `maven-metadata.xml` for a whole artifact, or a checksum of it.
    /// The repository generates this; it is never stored.
    Metadata {
        name: String,
        /// `None` for the document, `Some("sha1")` or `Some("md5")` for
        /// a checksum of it.
        checksum: Option<String>,
    },
}

const METADATA: &str = "maven-metadata.xml";

/// Split a repository path into what it addresses.
///
/// `None` for anything that is not a legal coordinate. Deliberately
/// strict: a path that does not parse is a request for something this
/// repository could never hold, and inventing a coordinate for it is
/// how two different paths come to address one stored object.
pub fn parse_path(path: &str) -> Option<Target> {
    // Only the leading slash is stripped. Dropping a **trailing** one
    // — or filtering empty components out of the middle — makes
    // `com/acme/widget/1.0/` parse as a perfectly good coordinate:
    // group `com`, artifact `acme`, version `widget`, file `1.0`. That
    // is a different object under a URL that reads like the real one,
    // which is exactly the collision this function exists to prevent.
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // An empty, traversing, or non-ASCII component never reaches a
    // coordinate.
    if parts.iter().any(|p| {
        p.is_empty()
            || *p == "."
            || *p == ".."
            || p.chars().any(|c| c.is_control() || !c.is_ascii())
    }) {
        return None;
    }

    let last = *parts.last()?;
    // `maven-metadata.xml`, or `maven-metadata.xml.sha1`.
    if let Some(checksum) = metadata_kind(last) {
        // `<group…>/<artifact>/maven-metadata.xml` — at least one group
        // segment, so three components.
        if parts.len() < 3 {
            return None;
        }
        let artifact = parts[parts.len() - 2];
        let group = parts[..parts.len() - 2].join(".");
        return Some(Target::Metadata {
            name: format!("{group}:{artifact}"),
            checksum,
        });
    }

    // `<group…>/<artifact>/<version>/<file>` — at least one group
    // segment, so four components.
    if parts.len() < 4 {
        return None;
    }
    let filename = last.to_string();
    let version = parts[parts.len() - 2].to_string();
    let artifact = parts[parts.len() - 3];
    let group = parts[..parts.len() - 3].join(".");
    if group.is_empty() || artifact.is_empty() || version.is_empty() || filename.is_empty() {
        return None;
    }
    Some(Target::Artifact {
        name: format!("{group}:{artifact}"),
        version,
        filename,
    })
}

/// `Some(None)` for the metadata document, `Some(Some(alg))` for a
/// checksum of it, `None` for anything else.
fn metadata_kind(last: &str) -> Option<Option<String>> {
    if last == METADATA {
        return Some(None);
    }
    let rest = last.strip_prefix(METADATA)?.strip_prefix('.')?;
    match rest {
        "sha1" | "md5" | "sha256" | "sha512" => Some(Some(rest.to_string())),
        _ => None,
    }
}

/// A version whose bytes are allowed to change, which is the one thing
/// this registry does not do.
pub fn is_snapshot(version: &str) -> bool {
    version.to_ascii_uppercase().ends_with("-SNAPSHOT")
}

/// The `Content-Type` for a file Maven asked for.
///
/// Maven does not care — it reads the bytes whatever we say — but a
/// person who pastes the URL into a browser does, and a `.pom` served
/// as `application/octet-stream` downloads instead of displaying.
pub fn content_type(filename: &str) -> &'static str {
    match filename.rsplit('.').next().unwrap_or("") {
        "pom" | "xml" => "application/xml",
        "jar" | "war" | "ear" => "application/java-archive",
        "md5" | "sha1" | "sha256" | "sha512" | "asc" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// `maven-metadata.xml` for one artifact.
///
/// Maven reads this to resolve `LATEST`, `RELEASE` and version ranges.
/// Most builds pin an exact version and never fetch it, but a build
/// that does and gets a 404 fails with a message about the repository
/// rather than about the range, so it is generated rather than omitted.
///
/// `versions` must be in publication order: `<latest>` and `<release>`
/// are the last of them, which is what Maven means by those words — it
/// does not sort.
pub fn metadata_xml(name: &str, versions: &[String], last_updated: &str) -> String {
    let (group, artifact) = match name.split_once(':') {
        Some((g, a)) => (g, a),
        None => ("", name),
    };
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n");
    out.push_str(&format!("  <groupId>{}</groupId>\n", xml_escape(group)));
    out.push_str(&format!(
        "  <artifactId>{}</artifactId>\n",
        xml_escape(artifact)
    ));
    out.push_str("  <versioning>\n");
    if let Some(newest) = versions.last() {
        out.push_str(&format!("    <latest>{}</latest>\n", xml_escape(newest)));
        // Every version here is a release: snapshots are refused, so
        // `<release>` and `<latest>` are the same version rather than
        // being different by accident.
        out.push_str(&format!("    <release>{}</release>\n", xml_escape(newest)));
    }
    out.push_str("    <versions>\n");
    for v in versions {
        out.push_str(&format!("      <version>{}</version>\n", xml_escape(v)));
    }
    out.push_str("    </versions>\n");
    out.push_str(&format!(
        "    <lastUpdated>{}</lastUpdated>\n",
        xml_escape(last_updated)
    ));
    out.push_str("  </versioning>\n</metadata>\n");
    out
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// `yyyyMMddHHmmss`, which is the only format Maven accepts in
/// `<lastUpdated>`.
pub fn maven_timestamp(epoch_ms: i64) -> String {
    let secs = epoch_ms.div_euclid(1000);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (h, mi, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
    // Howard Hinnant's civil_from_days, the same one the rest of the
    // tree uses — there is no date crate in this workspace and adding
    // one for four lines would be a dependency for a formatting choice.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}")
}

/// The licence a POM declares, as free text.
///
/// A **scanner, not a parser**, and the limit is worth stating: it
/// finds the first `<licenses>` element and reads the `<name>` of each
/// `<license>` inside it. It does not resolve a parent POM, evaluate a
/// property, or understand namespaces — all three are real and all
/// three are how a POM can declare a licence this will not see.
///
/// That is the honest position rather than a gap: a licence this cannot
/// read is not silently admitted, it lands on the ecosystem's
/// `unknown` disposition, which is a decision the organization makes.
pub fn license_of(pom: &str) -> Option<String> {
    let pom = strip_comments(pom);
    let start = pom.find("<licenses>")? + "<licenses>".len();
    let end = pom[start..].find("</licenses>")? + start;
    let block = &pom[start..end];

    let mut names = Vec::new();
    let mut rest = block;
    while let Some(open) = rest.find("<name>") {
        let after = &rest[open + "<name>".len()..];
        let Some(close) = after.find("</name>") else {
            break;
        };
        let text = unescape(after[..close].trim());
        if !text.is_empty() {
            names.push(text);
        }
        rest = &after[close..];
    }
    if names.is_empty() {
        return None;
    }
    // Maven's `<licenses>` is a list, and the POM specification says a
    // project under several of them is under **all** of them — unlike
    // npm's `licenses[]`, which historically meant a choice. `AND` is
    // therefore the truthful join, and it is also the strict one: a
    // policy that admits the pair admits it, and one that refuses
    // either refuses.
    Some(names.join(" AND "))
}

/// Remove `<!-- … -->` so a commented-out `<licenses>` block is not
/// read as a declaration. A real one has been seen in the wild above
/// the real block, which would otherwise win by being first.
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find("<!--") {
        out.push_str(&rest[..at]);
        match rest[at..].find("-->") {
            Some(end) => rest = &rest[at + end + 3..],
            // An unterminated comment swallows the remainder, which is
            // what an XML parser would do too.
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        // Last, so `&amp;lt;` comes back as `&lt;` rather than `<`.
        .replace("&amp;", "&")
}

/// Maven licence names are **free text**, not SPDX, and there is no
/// authoritative mapping. This is a curated table of the spellings that
/// actually appear, and it is deliberately small.
///
/// A name that is not here comes back `None` and lands on the
/// ecosystem's `unknown` disposition. That is the right failure: a
/// fuzzy match that turned "Apache License" into `Apache-2.0` would
/// silently admit an Apache 1.1 artifact under a rule written for 2.0,
/// and nobody would ever find out.
pub fn spdx_of(name: &str) -> Option<&'static str> {
    let n = name.trim().to_ascii_lowercase();
    let n = n.trim_end_matches(&[',', '.'][..]).trim();
    let hit = |id: &'static str| Some(id);
    match n {
        "apache license, version 2.0"
        | "apache license version 2.0"
        | "apache license 2.0"
        | "apache-2.0"
        | "apache 2"
        | "apache 2.0"
        | "the apache software license, version 2.0"
        | "the apache license, version 2.0" => hit("Apache-2.0"),
        "mit" | "mit license" | "the mit license" | "mit-0" => hit("MIT"),
        "bsd"
        | "bsd license"
        | "the bsd license"
        | "bsd-3-clause"
        | "new bsd license"
        | "3-clause bsd license" => hit("BSD-3-Clause"),
        "bsd-2-clause" | "simplified bsd license" | "2-clause bsd license" => hit("BSD-2-Clause"),
        "eclipse public license - v 1.0" | "eclipse public license v1.0" | "epl-1.0" => {
            hit("EPL-1.0")
        }
        "eclipse public license - v 2.0" | "eclipse public license v2.0" | "epl-2.0" => {
            hit("EPL-2.0")
        }
        "gnu lesser general public license" | "lgpl-2.1" | "lgpl, version 2.1" => {
            hit("LGPL-2.1-only")
        }
        "gnu general public license, version 2" | "gpl-2.0" => hit("GPL-2.0-only"),
        "gnu general public license, version 3" | "gpl-3.0" => hit("GPL-3.0-only"),
        "mozilla public license version 2.0"
        | "mpl-2.0"
        | "mozilla public license, version 2.0" => hit("MPL-2.0"),
        "the unlicense" | "unlicense" => hit("Unlicense"),
        "cc0" | "cc0-1.0" | "public domain" => hit("CC0-1.0"),
        _ => None,
    }
}

/// A whole `<licenses>` block turned into an SPDX expression, or `None`
/// if any part of it is a name the table does not know.
///
/// All or nothing on purpose. "Apache-2.0 AND something we could not
/// read" is not a licence a policy can decide about, and reporting the
/// half we understood would have an organization believe it had checked
/// the artifact when it had checked part of it.
pub fn spdx_expression(declared: &str) -> Option<String> {
    let mut out = Vec::new();
    for part in declared.split(" AND ") {
        out.push(spdx_of(part)?);
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join(" AND "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read from the right, because a groupId has any number of
    /// segments. Read from the left, `com/acme/widget/1.0/x.jar` could
    /// be group `com` artifact `acme` — and guessing wrong stores one
    /// project's jar under another project's name.
    #[test]
    fn a_coordinate_is_read_from_the_right() {
        assert_eq!(
            parse_path("com/acme/widget/1.4.0/widget-1.4.0.jar"),
            Some(Target::Artifact {
                name: "com.acme:widget".into(),
                version: "1.4.0".into(),
                filename: "widget-1.4.0.jar".into(),
            })
        );
        // A deep groupId, which is the ordinary case in Java.
        assert_eq!(
            parse_path("/org/example/tools/deep/thing/2.0/thing-2.0.pom"),
            Some(Target::Artifact {
                name: "org.example.tools.deep:thing".into(),
                version: "2.0".into(),
                filename: "thing-2.0.pom".into(),
            })
        );
        // A single-segment groupId is legal and still needs four parts.
        assert_eq!(
            parse_path("acme/widget/1.0/widget-1.0.jar"),
            Some(Target::Artifact {
                name: "acme:widget".into(),
                version: "1.0".into(),
                filename: "widget-1.0.jar".into(),
            })
        );
    }

    #[test]
    fn metadata_and_its_checksums_are_recognised() {
        assert_eq!(
            parse_path("com/acme/widget/maven-metadata.xml"),
            Some(Target::Metadata {
                name: "com.acme:widget".into(),
                checksum: None,
            })
        );
        assert_eq!(
            parse_path("com/acme/widget/maven-metadata.xml.sha1"),
            Some(Target::Metadata {
                name: "com.acme:widget".into(),
                checksum: Some("sha1".into()),
            })
        );
        // Not a checksum algorithm we publish, so it is not metadata.
        // It still parses — as an ordinary (and nonexistent) artifact,
        // which 404s. The claim worth making is that we do not
        // *generate* a document for it, because generating one under a
        // name Maven did not ask for is how a checksum comes to
        // disagree with the file it is supposed to cover.
        assert!(matches!(
            parse_path("com/acme/widget/maven-metadata.xml.crc"),
            Some(Target::Artifact { .. })
        ));
    }

    /// Anything that could address a second stored object under one
    /// path, or escape the prefix, is refused rather than cleaned up.
    #[test]
    fn a_path_that_is_not_a_coordinate_is_refused() {
        for bad in [
            "",
            "/",
            "widget/1.0/widget-1.0.jar", // no groupId
            "com/acme/widget",           // no version or file
            "com/acme/../../../etc/passwd/1.0/x.jar",
            "com/acme/widget/./1.0/x.jar",
            "com/acme/widget/1.0/x\u{0}.jar",
            // A trailing slash is the dangerous one. Filtered out, this
            // parses as group `com`, artifact `acme`, version `widget`,
            // file `1.0` — a different object under a URL that reads
            // like the real one.
            "com/acme/widget/1.0/",
            "com/acme//widget/1.0/x.jar",
            "com/acme/widget/maven-metadata.xml/",
            "com/acmé/widget/1.0/x.jar",
            "maven-metadata.xml",
            "widget/maven-metadata.xml",
        ] {
            assert_eq!(parse_path(bad), None, "{bad:?} parsed as a coordinate");
        }
    }

    /// The one thing this registry does not do, and the check that
    /// decides it. `-SNAPSHOT` is case-insensitive in Maven.
    #[test]
    fn a_snapshot_version_is_recognised_however_it_is_spelled() {
        assert!(is_snapshot("1.0-SNAPSHOT"));
        assert!(is_snapshot("1.0-snapshot"));
        assert!(is_snapshot("2.1.3-Snapshot"));
        assert!(!is_snapshot("1.0"));
        assert!(!is_snapshot("1.0-SNAPSHOT-final"));
        assert!(!is_snapshot("snapshot"));
    }

    #[test]
    fn the_metadata_document_names_the_newest_version_last() {
        let xml = metadata_xml(
            "com.acme:widget",
            &["1.0.0".into(), "1.1.0".into(), "2.0.0".into()],
            "20260913120000",
        );
        assert!(xml.contains("<groupId>com.acme</groupId>"), "{xml}");
        assert!(xml.contains("<artifactId>widget</artifactId>"), "{xml}");
        assert!(xml.contains("<latest>2.0.0</latest>"), "{xml}");
        // Every version here is a release, because snapshots never got
        // in. `<release>` and `<latest>` agreeing is a fact about the
        // registry, not a coincidence.
        assert!(xml.contains("<release>2.0.0</release>"), "{xml}");
        assert_eq!(xml.matches("<version>").count(), 3, "{xml}");
        assert!(
            xml.contains("<lastUpdated>20260913120000</lastUpdated>"),
            "{xml}"
        );
    }

    /// An artifactId can contain characters XML must escape. Emitting
    /// them raw produces a document Maven refuses to parse, and the
    /// error it prints is about the repository being broken.
    #[test]
    fn the_metadata_document_escapes_what_xml_requires() {
        // Every character XML requires escaping, in one document.
        let xml = metadata_xml("com.acme:a&b\"c'd", &["1.0<x>y".into()], "0");
        assert!(
            xml.contains("<artifactId>a&amp;b&quot;c&apos;d</artifactId>"),
            "{xml}"
        );
        assert!(xml.contains("<version>1.0&lt;x&gt;y</version>"), "{xml}");
        assert!(!xml.contains("a&b"), "{xml}");
    }

    /// The last refusal in the coordinate parser: four components that
    /// are all present, and one of them empty after the split. Reached
    /// by a path whose group segment is the only thing missing.
    #[test]
    fn a_coordinate_with_an_empty_part_is_refused_even_at_four_components() {
        // `/a/b/c` after the leading slash is three; four with an empty
        // group is what the final guard is for.
        assert_eq!(parse_path("/com/acme/widget/1.0/"), None);
        assert_eq!(parse_path("com/acme/widget//x.jar"), None);
    }

    /// A name with no `:` in it should not panic the document
    /// generator. It cannot arrive from `parse_path`, which always
    /// builds `group:artifact` — but `metadata_xml` is also called with
    /// a stored `packages.name`, and a guard on a security-adjacent
    /// boundary is cheaper than the argument about whether it can.
    #[test]
    fn a_name_with_no_colon_still_produces_a_document() {
        let xml = metadata_xml("widget", &["1.0".into()], "0");
        assert!(xml.contains("<groupId></groupId>"), "{xml}");
        assert!(xml.contains("<artifactId>widget</artifactId>"), "{xml}");
    }

    /// An unterminated `<name>` inside a `<licenses>` block stops the
    /// scan rather than running off the end. A POM can be truncated in
    /// transit, and a scanner that looped would hang the publish.
    #[test]
    fn an_unterminated_name_element_stops_the_scan() {
        let pom = "<project><licenses><license><name>MIT</licenses></project>";
        assert_eq!(license_of(pom), None);
        // …and one good name followed by a broken one keeps the good.
        let pom = "<project><licenses><license><name>MIT</name></license>\
                   <license><name>Apache</licenses></project>";
        assert_eq!(license_of(pom).as_deref(), Some("MIT"));
    }

    /// The rest of the curated table, and the empty-expression case.
    /// Each spelling is one that appears in real POMs.
    #[test]
    fn the_curated_table_covers_the_spellings_that_actually_appear() {
        for (name, want) in [
            ("Eclipse Public License - v 1.0", "EPL-1.0"),
            ("EPL-2.0", "EPL-2.0"),
            ("GNU Lesser General Public License", "LGPL-2.1-only"),
            ("GNU General Public License, version 2", "GPL-2.0-only"),
            ("GPL-3.0", "GPL-3.0-only"),
            ("Mozilla Public License Version 2.0", "MPL-2.0"),
            ("Simplified BSD License", "BSD-2-Clause"),
            ("New BSD License", "BSD-3-Clause"),
            ("The Unlicense", "Unlicense"),
            ("Public Domain", "CC0-1.0"),
        ] {
            assert_eq!(spdx_of(name), Some(want), "{name}");
        }
        // An expression with nothing in it is not a licence.
        assert_eq!(spdx_expression(""), None);
    }

    #[test]
    fn a_timestamp_is_the_only_format_maven_accepts() {
        // 2026-09-13T12:00:00Z, checked against Python's datetime
        // rather than worked out by hand — the last time this file
        // carried a hand-computed epoch it was three months out and
        // the test agreed with it.
        assert_eq!(maven_timestamp(1_789_300_800_000), "20260913120000");
        // …and one second before midnight, which is where an
        // off-by-one in the day arithmetic shows up.
        assert_eq!(maven_timestamp(1_789_300_799_000), "20260913115959");
        assert_eq!(maven_timestamp(0), "19700101000000");
    }

    #[test]
    fn a_poms_licence_is_read_from_the_licences_block() {
        let pom = r#"<?xml version="1.0"?>
        <project>
          <name>Widget</name>
          <licenses>
            <license>
              <name>Apache License, Version 2.0</name>
              <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
            </license>
          </licenses>
        </project>"#;
        assert_eq!(
            license_of(pom).as_deref(),
            Some("Apache License, Version 2.0")
        );
        assert_eq!(
            spdx_expression("Apache License, Version 2.0"),
            Some("Apache-2.0".into())
        );
    }

    /// Maven's `<licenses>` is a conjunction — the POM specification
    /// says a project under several is under all of them. npm's
    /// `licenses[]` historically meant a *choice*, and reading Maven's
    /// the same way would admit a project on the strength of the
    /// permissive half of a pair it is not actually offering.
    #[test]
    fn several_licences_join_with_and_because_that_is_what_maven_means() {
        let pom = r#"<project><licenses>
            <license><name>MIT</name></license>
            <license><name>Apache License 2.0</name></license>
          </licenses></project>"#;
        assert_eq!(
            license_of(pom).as_deref(),
            Some("MIT AND Apache License 2.0")
        );
        assert_eq!(
            spdx_expression("MIT AND Apache License 2.0"),
            Some("MIT AND Apache-2.0".into())
        );
    }

    /// A commented-out block above the real one would otherwise win by
    /// being first, and hand a policy the wrong licence with complete
    /// confidence.
    #[test]
    fn a_commented_out_licence_is_not_a_declaration() {
        let pom = r#"<project>
          <!-- <licenses><license><name>GPL-3.0</name></license></licenses> -->
          <licenses><license><name>MIT</name></license></licenses>
        </project>"#;
        assert_eq!(license_of(pom).as_deref(), Some("MIT"));

        // An unterminated comment swallows the rest, which is what a
        // real parser does too — so nothing is declared rather than
        // something wrong being.
        assert_eq!(license_of("<project><!-- <licenses>…"), None);
    }

    #[test]
    fn a_pom_with_no_licence_declares_nothing() {
        assert_eq!(license_of("<project><name>x</name></project>"), None);
        assert_eq!(license_of("<project><licenses></licenses></project>"), None);
        assert_eq!(
            license_of("<project><licenses><license/></licenses></project>"),
            None
        );
        assert_eq!(license_of("not xml at all"), None);
        // Escaped text comes back unescaped, so a policy compares the
        // licence the POM meant rather than its encoding.
        assert_eq!(
            license_of(
                "<project><licenses><license><name>A &amp; B</name></license></licenses></project>"
            )
            .as_deref(),
            Some("A & B")
        );
    }

    /// A name the table does not know is **unknown**, never guessed.
    /// Turning "Apache License" into `Apache-2.0` would admit an
    /// Apache 1.1 artifact under a rule somebody wrote for 2.0, and
    /// nothing would ever surface it.
    #[test]
    fn an_unmapped_licence_name_is_unknown_rather_than_guessed() {
        assert_eq!(spdx_of("Apache License"), None);
        assert_eq!(spdx_of("Weird Corporate Licence v3"), None);
        assert_eq!(spdx_of(""), None);
        // …and one unreadable half makes the whole expression unknown,
        // because "Apache-2.0 AND something" is not a licence a policy
        // can decide about.
        assert_eq!(spdx_expression("MIT AND Weird Corporate Licence v3"), None);

        // Case and trailing punctuation do not change the answer: these
        // are the spellings that actually appear in real POMs.
        assert_eq!(spdx_of("  THE MIT LICENSE  "), Some("MIT"));
        assert_eq!(spdx_of("Apache License, Version 2.0."), Some("Apache-2.0"));
    }

    #[test]
    fn a_file_is_served_as_the_type_a_browser_can_read() {
        assert_eq!(content_type("widget-1.0.pom"), "application/xml");
        assert_eq!(content_type("widget-1.0.jar"), "application/java-archive");
        assert_eq!(content_type("widget-1.0.jar.sha1"), "text/plain");
        assert_eq!(
            content_type("widget-1.0.module"),
            "application/octet-stream"
        );
        assert_eq!(content_type("nodots"), "application/octet-stream");
    }
}
