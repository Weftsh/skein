//! The npm registry protocol, as the real client speaks it.
//!
//! Two documents and one blob:
//!
//! * a **packument** — `GET /<name>` — the whole package: every version's
//!   manifest, the dist-tags, and a `dist.tarball` URL per version.
//! * a **publish document** — `PUT /<name>` — one new version's manifest
//!   plus the tarball, base64 in `_attachments`.
//! * the **tarball** itself, at whatever URL the packument named.
//!
//! Everything in this module that decides something is a pure function
//! over `serde_json::Value`, so the awkward parts — a client that sends
//! two versions at once, an attachment whose length lies, a legacy
//! `license` object — are argued with in unit tests rather than against
//! a live `npm publish`.
//!
//! ## What the wire actually carries, and what we do not take on trust
//!
//! `dist.shasum` is **SHA-1** and `dist.integrity` is `sha512-<base64>`;
//! neither is the SHA-256 this registry addresses blobs by. So the
//! client's digests are not used as the storage key — the key is a
//! SHA-256 we compute from the bytes we actually received. The client's
//! own claims are still checked ([`parse_publish`] refuses a length or a
//! shasum that disagrees with the attachment), because a corrupted
//! upload that we store and then advertise as good is a package that
//! fails to install for everybody, forever, with no indication of why.
//!
//! The packument we serve advertises **our** shasum and integrity,
//! computed from the stored bytes. That is the only way the two can
//! never disagree.
//!
//! ## Refusing rather than taking the first
//!
//! A publish document is a whole packument by shape, so it *can* carry
//! several versions. `npm publish` sends exactly one. A document with
//! two is refused rather than having its first version taken, on the
//! same principle the workflow parser refuses an unknown key: silently
//! ignoring half of what somebody sent is the failure mode that looks
//! like success.

use sha1::Digest as _;
use skein_control::packages::License;

/// One version being published: everything the control plane needs and
/// nothing about how it arrived.
///
/// The attachment's own filename is deliberately not carried. npm's
/// convention derives it from the name and version ([`tarball_name`]),
/// the client takes the last path segment of `dist.tarball` as its cache
/// filename regardless, and storing the publisher's spelling would give
/// two clients two names for one artifact.
#[derive(Debug, Clone)]
pub struct Publish {
    /// The package name as the client spelled it.
    pub name: String,
    pub version: String,
    pub license: License,
    /// The version manifest, verbatim, with `dist` removed — we rewrite
    /// that on the way out and storing the client's copy would leave a
    /// `tarball` URL pointing at wherever they published from last.
    pub metadata: serde_json::Value,
    pub tarball: Vec<u8>,
    /// `dist-tags` the publish asks for, usually just `latest`.
    pub tags: Vec<(String, String)>,
}

fn field<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    v.get(key).filter(|x| !x.is_null())
}

fn text(v: &serde_json::Value, key: &str) -> Option<String> {
    field(v, key)?.as_str().map(str::to_string)
}

/// npm's `license` field, in all three spellings it has had.
///
/// Modern packages say `"license": "MIT"`. There are two legacy forms
/// still on the wire in packages published years ago and never
/// republished: an object `{"type": "MIT", "url": …}`, and an array
/// `"licenses": [{"type": "MIT"}, …]` for dual licensing. Reading only
/// the modern one would report a licence of "unknown" for a package that
/// plainly states it — which, once the policy gate exists, means
/// refusing a package on a technicality.
pub fn license_of(manifest: &serde_json::Value) -> License {
    if let Some(s) = manifest.get("license").and_then(|l| l.as_str()) {
        let s = s.trim();
        if !s.is_empty() {
            return License::Declared(s.to_string());
        }
    }
    if let Some(t) = manifest
        .get("license")
        .and_then(|l| l.get("type"))
        .and_then(|t| t.as_str())
    {
        let t = t.trim();
        if !t.is_empty() {
            return License::Declared(t.to_string());
        }
    }
    if let Some(list) = manifest.get("licenses").and_then(|l| l.as_array()) {
        let types: Vec<String> = list
            .iter()
            .filter_map(|e| {
                e.as_str()
                    .or_else(|| e.get("type").and_then(|t| t.as_str()))
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty())
            .collect();
        if !types.is_empty() {
            // A list of licences is a choice between them, which is what
            // SPDX's `OR` means. Joining them this way lets one
            // expression parser handle both the modern and the legacy
            // spelling.
            return License::Declared(types.join(" OR "));
        }
    }
    License::Unknown
}

/// Decode base64, ignoring the whitespace a JSON encoder may have
/// wrapped it with.
fn decode_attachment(data: &str) -> Option<Vec<u8>> {
    let packed: String = data.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    crate::authx::base64_decode(&packed)
}

fn sha1_hex(data: &[u8]) -> String {
    let d = sha1::Sha1::digest(data);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read a publish document, or say what is wrong with it.
///
/// Every refusal names the field, because this is the message a person
/// meets when `npm publish` fails and it is the only thing they have to
/// go on.
pub fn parse_publish(body: &serde_json::Value) -> Result<Publish, String> {
    let name = text(body, "name").ok_or("this publish has no \"name\"")?;

    let versions = field(body, "versions")
        .and_then(|v| v.as_object())
        .ok_or("this publish has no \"versions\"")?;
    if versions.is_empty() {
        return Err("this publish names no version".into());
    }
    if versions.len() > 1 {
        // Taking the first would publish one version and silently drop
        // the rest, and the client would report success.
        return Err(format!(
            "this publish carries {} versions and npm publishes one at a time",
            versions.len()
        ));
    }
    let (version, manifest) = versions.iter().next().expect("one version");

    let attachments = field(body, "_attachments")
        .and_then(|v| v.as_object())
        .ok_or("this publish carries no tarball (\"_attachments\" is missing)")?;
    if attachments.len() != 1 {
        return Err(format!(
            "this publish carries {} attachments and a version has one tarball",
            attachments.len()
        ));
    }
    let (filename, attachment) = attachments.iter().next().expect("one attachment");

    let data = text(attachment, "data")
        .ok_or_else(|| format!("the attachment {filename:?} carries no \"data\""))?;
    let tarball = decode_attachment(&data)
        .ok_or_else(|| format!("the attachment {filename:?} is not valid base64"))?;
    if tarball.is_empty() {
        return Err(format!("the attachment {filename:?} is empty"));
    }

    // The client's own claims about what it sent. Checked so that a
    // corrupted upload is refused now rather than stored, advertised as
    // good, and failing to install for everybody afterwards.
    if let Some(claimed) = attachment.get("length").and_then(|l| l.as_u64()) {
        if claimed != tarball.len() as u64 {
            return Err(format!(
                "the attachment {filename:?} says it is {claimed} bytes and decoded to {}",
                tarball.len()
            ));
        }
    }
    if let Some(shasum) = manifest
        .get("dist")
        .and_then(|d| d.get("shasum"))
        .and_then(|s| s.as_str())
    {
        let got = sha1_hex(&tarball);
        if !shasum.trim().is_empty() && !shasum.eq_ignore_ascii_case(&got) {
            return Err(format!(
                "the tarball does not match the shasum this publish declared: \
                 it said {shasum} and the bytes are {got}"
            ));
        }
    }

    // `dist` is the registry's to write, not the publisher's: theirs
    // names whatever registry they last published to.
    let mut metadata = manifest.clone();
    if let Some(obj) = metadata.as_object_mut() {
        obj.remove("dist");
    }

    let tags = field(body, "dist-tags")
        .and_then(|v| v.as_object())
        .map(|o| {
            o.iter()
                .filter_map(|(tag, v)| v.as_str().map(|s| (tag.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(Publish {
        name,
        version: version.clone(),
        license: license_of(manifest),
        metadata,
        tarball,
        tags,
    })
}

/// One version, as the packument presents it.
pub struct VersionView {
    pub version: String,
    pub metadata: String,
    /// The alternate digests recorded at publish, as stored JSON. The
    /// caller turns these into `(shasum, integrity)`; this module never
    /// reads inside it.
    pub digests: String,
    pub filename: String,
    pub yanked: bool,
}

/// The `dist` block for one version: where the tarball is and what it
/// hashes to.
///
/// `shasum` and `integrity` are computed from the **stored** bytes by
/// the caller, never copied from the publish document, so the packument
/// cannot advertise a digest the tarball does not have.
pub fn dist(tarball_url: &str, shasum: &str, integrity: &str) -> serde_json::Value {
    serde_json::json!({
        "tarball": tarball_url,
        "shasum": shasum,
        "integrity": integrity,
    })
}

/// Build the packument a client reads.
///
/// `tarball_url` is called once per version with `(version, filename)`
/// so the caller decides the URL shape without this module knowing about
/// routing.
///
/// A yanked version is still listed, because a lockfile that already
/// names it must keep resolving; npm's own convention is to mark it and
/// let the client's `--no-audit`/range logic avoid it, and removing it
/// outright breaks reproducible installs.
pub fn packument(
    name: &str,
    versions: &[VersionView],
    tags: &[(String, String)],
    mut tarball_url: impl FnMut(&VersionView) -> String,
    mut digests: impl FnMut(&VersionView) -> (String, String),
) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    let mut vs = serde_json::Map::new();
    let mut deprecated_any = false;

    for v in versions {
        let mut manifest: serde_json::Value =
            serde_json::from_str(&v.metadata).unwrap_or_else(|_| serde_json::json!({}));
        let obj = manifest.as_object_mut().expect("an object");
        obj.insert("name".into(), serde_json::json!(name));
        obj.insert("version".into(), serde_json::json!(v.version));
        let (shasum, integrity) = digests(v);
        obj.insert("dist".into(), dist(&tarball_url(v), &shasum, &integrity));
        if v.yanked {
            deprecated_any = true;
            obj.insert(
                "deprecated".into(),
                serde_json::json!(
                    "this version was yanked; it still installs, and should not be used"
                ),
            );
        }
        vs.insert(v.version.clone(), manifest);
    }

    let vs_keys: std::collections::BTreeSet<String> = vs.keys().cloned().collect();
    out.insert("name".into(), serde_json::json!(name));
    out.insert("_id".into(), serde_json::json!(name));
    out.insert("versions".into(), serde_json::Value::Object(vs));
    // A tag naming a version this document does not carry is dropped,
    // never repointed. npm resolves `lodash@latest` by reading the tag
    // and then looking the version up in `versions`; a dangling tag
    // makes that fail with "no matching version", which reads as a
    // corrupt registry. Repointing it at some other version would be
    // worse — it would silently install something other than what the
    // tag means. This happens for real in two places: a version whose
    // files are gone, and a cached proxied version the admission policy
    // now withholds.
    //
    // `latest` naming a version that is here but **yanked** is the other
    // case, and the opposite answer: it is served as [`latest_unyanked`].
    // A yank is somebody saying "not this one", and `latest` is what
    // `npm install <pkg>` with no range and `npm view` read as current —
    // left alone, both went on offering exactly what had been taken down.
    // npm's own registry moves `latest` the same way when the version it
    // names is unpublished. Only here, in what is served: the stored tag
    // does not move, so un-yanking puts it back; and only `latest` —
    // `next` pointing at a yanked beta is what somebody chose.
    let yanked: std::collections::BTreeSet<&str> = versions
        .iter()
        .filter(|v| v.yanked)
        .map(|v| v.version.as_str())
        .collect();
    out.insert(
        "dist-tags".into(),
        serde_json::Value::Object(
            tags.iter()
                .filter(|(_, v)| vs_keys.contains(v.as_str()))
                .filter_map(|(t, v)| {
                    if t == "latest" && yanked.contains(v.as_str()) {
                        latest_unyanked(versions).map(|l| (t.clone(), serde_json::json!(l)))
                    } else {
                        Some((t.clone(), serde_json::json!(v)))
                    }
                })
                .collect(),
        ),
    );
    if deprecated_any {
        // npm reads this nowhere, but a person reading the raw document
        // during an incident does.
        out.insert("_hasYanked".into(), serde_json::json!(true));
    }
    serde_json::Value::Object(out)
}

/// What `latest` is served as when the version it names is yanked: the
/// highest version nobody yanked, by semver precedence — a release over
/// any pre-release, a pre-release only when no release is left — or
/// `None` when everything is yanked, and `latest` is left out.
///
/// Highest by [`semver_cmp`], not newest by publish time: a fix to an
/// older line published this morning is not what "latest" means. A
/// release over a pre-release, because promoting `2.0.0-beta.1` to
/// `latest` would hand every unpinned install a beta nobody tagged for
/// them. A version that is not semver cannot be placed, so it is never
/// chosen.
pub fn latest_unyanked(versions: &[VersionView]) -> Option<&str> {
    let mut candidates: Vec<(Semver<'_>, &str)> = versions
        .iter()
        .filter(|v| !v.yanked)
        .filter_map(|v| Semver::parse(&v.version).map(|s| (s, v.version.as_str())))
        .collect();
    candidates.sort_by(|a, b| a.0.cmp(&b.0));
    let release = candidates.iter().rev().find(|(s, _)| s.pre.is_empty());
    release.or(candidates.last()).map(|(_, v)| *v)
}

/// A version in semver's shape — `MAJOR.MINOR.PATCH`, an optional
/// `-pre.release` and an optional `+build` — held for ordering.
///
/// Written here because nothing else in the workspace orders versions,
/// and one purpose does not justify a dependency: the only question
/// asked of it is which of two versions is higher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Semver<'a> {
    core: [u64; 3],
    /// Pre-release identifiers; empty for a release.
    pre: Vec<&'a str>,
}

impl<'a> Semver<'a> {
    /// `None` for anything that is not semver: a registry may hold a
    /// version npm would not publish today, and an order guessed for it
    /// is an order nobody can check.
    pub fn parse(v: &'a str) -> Option<Semver<'a>> {
        let v = v.trim();
        let v = v.split_once('+').map_or(v, |(core, _build)| core);
        let (core, pre) = match v.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (v, None),
        };
        let mut nums = core.split('.');
        let mut out = [0u64; 3];
        for n in &mut out {
            let part = nums.next()?;
            let digits = !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
            if !digits || (part.len() > 1 && part.starts_with('0')) {
                return None;
            }
            *n = part.parse().ok()?;
        }
        if nums.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => Vec::new(),
            Some(p) => {
                let ids: Vec<&str> = p.split('.').collect();
                let ok = ids.iter().all(|id| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
                if !ok {
                    return None;
                }
                ids
            }
        };
        Some(Semver { core: out, pre })
    }
}

impl Ord for Semver<'_> {
    /// Semver 2.0.0's precedence: the three numbers; then a release above
    /// any pre-release of it; then pre-releases identifier by identifier —
    /// numeric ones by value and below alphanumeric ones, alphanumeric
    /// ones by ASCII, and a shorter list below a longer one it prefixes.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (a, b) in self.pre.iter().zip(&other.pre) {
                        let order = match (a.parse::<u64>(), b.parse::<u64>()) {
                            (Ok(x), Ok(y)) => x.cmp(&y),
                            (Ok(_), Err(_)) => Ordering::Less,
                            (Err(_), Ok(_)) => Ordering::Greater,
                            (Err(_), Err(_)) => a.cmp(b),
                        };
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }
}

impl PartialOrd for Semver<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Whether `name` is under one of the organization's npm scopes.
///
/// The scope is compared whole and as npm folds it: `@ACME/x` is under
/// `@acme`, and `@acme-corp/x` and `@acmecorp/x` are not — they are
/// somebody else's. Not `policy::namespace_covers`, which reads `-` as a
/// segment boundary so that a reserved `acme` covers `acme-utils`; for a
/// scope that would take another owner's scope for ours.
pub fn under_scopes(name: &str, scopes: &[String]) -> bool {
    let name = name.trim().to_ascii_lowercase();
    skein_control::packages::npm_scope_of(&name).is_some_and(|s| scopes.iter().any(|o| o == s))
}

/// Why `name` may not be published here — the sentence npm prints — or
/// `None` when it may.
///
/// npm publishing is held to the organization's scopes, because the
/// `.npmrc` every client is handed routes only those here: a name outside
/// them is one an install sends to public npmjs, where anybody can own
/// it. `own` is the organization's own scope, `@<name>`, which a
/// suggestion prefers; `scopes` is sorted.
pub fn scope_refusal(name: &str, scopes: &[String], own: &str) -> Option<String> {
    let name = name.trim();
    let listed = scopes.join(", ");
    let folded = name.to_ascii_lowercase();
    match skein_control::packages::npm_scope_of(&folded) {
        Some(scope) if scopes.iter().any(|s| s == scope) => None,
        Some(scope) if scopes.is_empty() => Some(format!(
            "{scope} is not one of this organization's npm scopes, and it has none yet — an \
             admin can add it under Admission policy"
        )),
        Some(scope) => Some(format!(
            "{scope} is not one of this organization's npm scopes ({listed}) — an admin can add \
             it under Admission policy"
        )),
        None if scopes.is_empty() => Some(format!(
            "npm packages here are published under this organization's scopes, and it has none \
             yet; \"{name}\" has no scope — an admin can add one under Admission policy"
        )),
        None => {
            let suggest = scopes.iter().find(|s| *s == own).unwrap_or(&scopes[0]);
            Some(format!(
                "npm packages here are published under this organization's scopes ({listed}); \
                 \"{name}\" has no scope — publish it as {suggest}/{name}"
            ))
        }
    }
}

/// `sha512-<base64>`, npm's Subresource Integrity spelling.
pub fn integrity_of(body: &[u8]) -> String {
    use sha2::Digest as _;
    let d = sha2::Sha512::digest(body);
    format!("sha512-{}", crate::authx::base64_encode(&d))
}

/// The shasum npm expects beside it: SHA-1, hex.
pub fn shasum_of(body: &[u8]) -> String {
    sha1_hex(body)
}

/// The tarball filename a version is served under.
///
/// npm's convention, and not cosmetic: the client takes the last path
/// segment of `dist.tarball` as the cache filename, and a scoped
/// package's tarball drops the scope — `@acme/widget` at 1.0.0 is
/// `widget-1.0.0.tgz`.
pub fn tarball_name(name: &str, version: &str) -> String {
    let bare = name.rsplit('/').next().unwrap_or(name);
    format!("{bare}-{version}.tgz")
}

/// Whether this name needs a scope segment in a URL, and the pieces.
///
/// npm sends a scoped name to the registry URL-encoded — `@acme%2fwidget`
/// — but some clients and every human sends `@acme/widget`. Both have to
/// reach the same package, which is why the route takes a wildcard and
/// this is where the two spellings are folded.
pub fn decode_name(raw: &str) -> String {
    raw.replace("%2F", "/").replace("%2f", "/")
}

/// One upstream version, as the gate needs to see it.
pub struct UpstreamVersion {
    pub version: String,
    pub licence: Option<String>,
    pub published_at: Option<i64>,
    pub tarball: Option<String>,
}

/// Read an upstream packument into the facts the policy decides on.
///
/// `time` is npm's per-version publish timestamp map, which is where
/// the cooldown's age comes from. It is a sibling of `versions` rather
/// than a field on each one, which is easy to miss and is the only
/// place that date exists.
pub fn upstream_versions(doc: &serde_json::Value) -> Vec<UpstreamVersion> {
    let times = doc.get("time").and_then(|t| t.as_object());
    doc.get("versions")
        .and_then(|v| v.as_object())
        .map(|vs| {
            vs.iter()
                .map(|(version, manifest)| UpstreamVersion {
                    version: version.clone(),
                    licence: license_of(manifest).expr().map(str::to_string),
                    published_at: times
                        .and_then(|t| t.get(version))
                        .and_then(|d| d.as_str())
                        .and_then(parse_iso8601_ms),
                    tarball: manifest
                        .get("dist")
                        .and_then(|d| d.get("tarball"))
                        .and_then(|t| t.as_str())
                        .map(str::to_string),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `2026-09-13T02:31:00.000Z` → epoch milliseconds.
///
/// Hand-rolled because this workspace carries no date library and the
/// only shape npm emits is this one. Anything else is `None`, which the
/// cooldown reads as "no date" and does not hold — the alternative,
/// guessing, would hold or release a release on a misparsed year.
pub fn parse_iso8601_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |a: usize, z: usize| s.get(a..z)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    // Days from the civil epoch — Howard Hinnant's algorithm, which is
    // exact for every proleptic Gregorian date and needs no table.
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400) + h * 3600 + mi * 60 + sec) * 1000)
}

/// Rewrite an upstream packument to the versions that may be served,
/// with every `dist.tarball` pointed back at us.
///
/// **Filtering here rather than at the tarball is the point.** A
/// client handed the whole document resolves to a version the gate then
/// refuses, and that reads as a broken registry rather than as a policy
/// decision. Filtering also has to be per version: packages relicense,
/// and a cooldown is about one release rather than the package.
///
/// A `dist-tags` entry pointing at a version that did not survive is
/// dropped rather than repointed. Repointing `latest` at an older
/// release would quietly downgrade every `npm install` that does not
/// pin, which is a worse surprise than the tag being absent.
pub fn filter_packument(
    doc: &serde_json::Value,
    admitted: &dyn Fn(&str) -> bool,
    mut tarball_url: impl FnMut(&str) -> String,
) -> serde_json::Value {
    let mut out = doc.clone();
    let Some(obj) = out.as_object_mut() else {
        return out;
    };

    let kept: Vec<String> = doc
        .get("versions")
        .and_then(|v| v.as_object())
        .map(|vs| vs.keys().filter(|v| admitted(v)).cloned().collect())
        .unwrap_or_default();

    if let Some(vs) = obj.get_mut("versions").and_then(|v| v.as_object_mut()) {
        vs.retain(|version, _| kept.iter().any(|k| k == version));
        for (version, manifest) in vs.iter_mut() {
            if let Some(m) = manifest.as_object_mut() {
                let url = tarball_url(version);
                match m.get_mut("dist").and_then(|d| d.as_object_mut()) {
                    Some(dist) => {
                        dist.insert("tarball".into(), serde_json::json!(url));
                    }
                    None => {
                        m.insert("dist".into(), serde_json::json!({ "tarball": url }));
                    }
                }
            }
        }
    }

    if let Some(tags) = obj.get_mut("dist-tags").and_then(|t| t.as_object_mut()) {
        tags.retain(|_, v| {
            v.as_str()
                .is_some_and(|version| kept.iter().any(|k| k == version))
        });
    }
    // `time` keeps entries for versions that were filtered out. It is
    // metadata about the package's history rather than an offer to
    // serve, and clients read it for "when was this published" rather
    // than for resolution.
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish_doc(version: &str, tarball: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "_id": "@acme/widget",
            "name": "@acme/widget",
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": "@acme/widget",
                    "version": version,
                    "license": "MIT",
                    "dependencies": { "left-pad": "^1.0.0" },
                    "dist": { "shasum": sha1_hex(tarball), "tarball": "https://elsewhere/x.tgz" }
                }
            },
            "_attachments": {
                "@acme/widget-1.0.0.tgz": {
                    "content_type": "application/octet-stream",
                    "data": crate::authx::base64_encode(tarball),
                    "length": tarball.len(),
                }
            }
        })
    }

    #[test]
    fn a_publish_carries_its_version_manifest_and_its_bytes() {
        let bytes = b"a tarball, near enough";
        let p = parse_publish(&publish_doc("1.0.0", bytes)).unwrap();
        assert_eq!(p.name, "@acme/widget");
        assert_eq!(p.version, "1.0.0");
        assert_eq!(p.tarball, bytes);
        assert_eq!(p.license, License::Declared("MIT".into()));
        assert_eq!(p.tags, vec![("latest".to_string(), "1.0.0".to_string())]);
        assert_eq!(p.metadata["dependencies"]["left-pad"], "^1.0.0");
    }

    /// The publisher's `dist` names whatever registry they published to
    /// last. Keeping it would have us serve a packument pointing at
    /// somebody else's tarball.
    #[test]
    fn the_publishers_dist_block_is_dropped() {
        let p = parse_publish(&publish_doc("1.0.0", b"bytes")).unwrap();
        assert!(
            p.metadata.get("dist").is_none(),
            "kept the publisher's dist: {:?}",
            p.metadata
        );
    }

    /// Not "take the first": a document with two versions publishes one
    /// and silently drops the other, and the client reports success.
    #[test]
    fn a_publish_of_two_versions_is_refused_rather_than_half_done() {
        let mut doc = publish_doc("1.0.0", b"bytes");
        doc["versions"]["2.0.0"] =
            serde_json::json!({ "name": "@acme/widget", "version": "2.0.0" });
        let err = parse_publish(&doc).unwrap_err();
        assert!(err.contains("2 versions"), "{err}");
    }

    /// A corrupted upload refused now, rather than stored, advertised as
    /// good, and failing to install for everybody afterwards.
    #[test]
    fn an_attachment_that_disagrees_with_itself_is_refused() {
        let bytes = b"the real bytes";

        let mut wrong_length = publish_doc("1.0.0", bytes);
        wrong_length["_attachments"]["@acme/widget-1.0.0.tgz"]["length"] = serde_json::json!(9999);
        let err = parse_publish(&wrong_length).unwrap_err();
        assert!(err.contains("9999"), "{err}");

        let mut wrong_shasum = publish_doc("1.0.0", bytes);
        wrong_shasum["versions"]["1.0.0"]["dist"]["shasum"] = serde_json::json!("a".repeat(40));
        let err = parse_publish(&wrong_shasum).unwrap_err();
        assert!(err.contains("shasum"), "{err}");

        let mut bad_b64 = publish_doc("1.0.0", bytes);
        bad_b64["_attachments"]["@acme/widget-1.0.0.tgz"]["data"] = serde_json::json!("!!!!");
        assert!(parse_publish(&bad_b64).unwrap_err().contains("base64"));
    }

    /// `length` is optional on the wire, so its absence is not a
    /// refusal — only a *disagreement* is. A registry that required it
    /// would reject publishes from any client that does not send it.
    #[test]
    fn an_attachment_without_a_declared_length_is_still_accepted() {
        let bytes = b"a tarball with no declared length";
        let mut doc = publish_doc("1.0.0", bytes);
        doc["_attachments"]["@acme/widget-1.0.0.tgz"]
            .as_object_mut()
            .unwrap()
            .remove("length");
        let p = parse_publish(&doc).expect("a publish with no length");
        assert_eq!(p.tarball, bytes);
    }

    #[test]
    fn a_publish_missing_any_of_its_parts_says_which() {
        let full = publish_doc("1.0.0", b"bytes");
        for (key, needle) in [
            ("name", "\"name\""),
            ("versions", "\"versions\""),
            ("_attachments", "_attachments"),
        ] {
            let mut doc = full.clone();
            doc.as_object_mut().unwrap().remove(key);
            let err = parse_publish(&doc).unwrap_err();
            assert!(err.contains(needle), "removing {key} said: {err}");
        }
        let mut empty = full.clone();
        empty["versions"] = serde_json::json!({});
        assert!(parse_publish(&empty).unwrap_err().contains("no version"));

        let mut two = full.clone();
        two["_attachments"]["extra.tgz"] = serde_json::json!({ "data": "eA==" });
        assert!(parse_publish(&two).unwrap_err().contains("2 attachments"));

        let mut nothing = full;
        nothing["_attachments"]["@acme/widget-1.0.0.tgz"]["data"] = serde_json::json!("");
        assert!(parse_publish(&nothing).unwrap_err().contains("empty"));
    }

    /// Three spellings of `license` have been on the wire, and packages
    /// published years ago still carry the old two. Reading only the
    /// modern one reports "unknown" for a package that plainly states
    /// its licence — which, once the policy gate exists, is a refusal on
    /// a technicality.
    #[test]
    fn every_spelling_of_the_license_field_is_read() {
        let modern = serde_json::json!({ "license": "MIT" });
        assert_eq!(license_of(&modern), License::Declared("MIT".into()));

        let legacy_object = serde_json::json!({ "license": { "type": "ISC", "url": "…" } });
        assert_eq!(license_of(&legacy_object), License::Declared("ISC".into()));

        let legacy_array = serde_json::json!({
            "licenses": [{ "type": "MIT" }, { "type": "Apache-2.0" }]
        });
        assert_eq!(
            license_of(&legacy_array),
            License::Declared("MIT OR Apache-2.0".into()),
            "a list of licences is a choice between them"
        );

        let bare_strings = serde_json::json!({ "licenses": ["MIT"] });
        assert_eq!(license_of(&bare_strings), License::Declared("MIT".into()));

        for none in [
            serde_json::json!({}),
            serde_json::json!({ "license": "" }),
            serde_json::json!({ "license": "   " }),
            serde_json::json!({ "license": null }),
            serde_json::json!({ "licenses": [] }),
            serde_json::json!({ "license": { "url": "…" } }),
            // A legacy object whose `type` is present but blank: read
            // far enough to find it, then fall through rather than
            // declaring a licence of "".
            serde_json::json!({ "license": { "type": "   " } }),
            serde_json::json!({ "licenses": [{ "type": "  " }, { "type": "" }] }),
        ] {
            assert_eq!(license_of(&none), License::Unknown, "{none:?}");
        }
    }

    fn view(version: &str, yanked: bool) -> VersionView {
        VersionView {
            version: version.into(),
            metadata: r#"{"dependencies":{"left-pad":"^1.0.0"}}"#.into(),
            digests: r#"{"sha1":"s","sha512":"sha512-i"}"#.into(),
            filename: tarball_name("@acme/widget", version),
            yanked,
        }
    }

    /// The packument is what a resolver reads, so it has to carry the
    /// dependencies — and a `dist` that matches the bytes we hold.
    #[test]
    fn the_packument_carries_dependencies_and_our_own_digests() {
        let versions = [view("1.0.0", false), view("2.0.0", false)];
        let tags = [("latest".to_string(), "2.0.0".to_string())];
        let doc = packument(
            "@acme/widget",
            &versions,
            &tags,
            |v| format!("https://weft.test/-/{}", v.filename),
            |_| ("sha1sum".into(), "sha512-xyz".into()),
        );

        assert_eq!(doc["name"], "@acme/widget");
        assert_eq!(doc["dist-tags"]["latest"], "2.0.0");
        let one = &doc["versions"]["1.0.0"];
        assert_eq!(one["name"], "@acme/widget");
        assert_eq!(one["version"], "1.0.0");
        assert_eq!(
            one["dependencies"]["left-pad"], "^1.0.0",
            "a packument with no dependencies installs the package and none of them"
        );
        assert_eq!(
            one["dist"]["tarball"],
            "https://weft.test/-/widget-1.0.0.tgz"
        );
        assert_eq!(one["dist"]["shasum"], "sha1sum");
        assert_eq!(one["dist"]["integrity"], "sha512-xyz");
        assert!(doc.get("_hasYanked").is_none());
    }

    /// A yanked version stays in the packument: a lockfile that already
    /// names it must keep resolving, or yanking one version breaks every
    /// build that pinned it.
    #[test]
    fn a_yanked_version_is_marked_but_still_listed() {
        let versions = [view("1.0.0", true), view("2.0.0", false)];
        let doc = packument(
            "@acme/widget",
            &versions,
            &[],
            |v| v.filename.clone(),
            |_| ("s".into(), "i".into()),
        );
        assert!(doc["versions"]["1.0.0"]["deprecated"].is_string());
        assert!(doc["versions"]["2.0.0"].get("deprecated").is_none());
        assert_eq!(doc["_hasYanked"], true);
        assert_eq!(
            doc["versions"].as_object().unwrap().len(),
            2,
            "yanking removed a version somebody's lockfile names"
        );
    }

    /// The filter is handed whatever the upstream sent, and an
    /// upstream that answers something other than an object is not a
    /// packument. Returned unchanged rather than turned into an empty
    /// one: an empty packument reads as "this package has no versions",
    /// which a resolver caches, and "the upstream answered nonsense"
    /// is a different thing the caller reports as a 502.
    #[test]
    fn a_document_that_is_not_an_object_comes_back_untouched() {
        let doc = serde_json::json!("not a packument");
        let out = filter_packument(&doc, &|_| true, |v| v.to_string());
        assert_eq!(out, doc);
    }

    /// A version whose manifest carries no `dist` at all. npm's own
    /// documents always have one, and a proxied document is whatever
    /// the upstream chose to send — so the block is created rather than
    /// the version being silently served with a tarball URL pointing at
    /// the upstream we are standing in front of.
    #[test]
    fn a_version_with_no_dist_block_gets_one_pointing_at_us() {
        let doc = serde_json::json!({
            "name": "left-pad",
            "dist-tags": { "latest": "1.0.0" },
            "versions": {
                "1.0.0": { "name": "left-pad", "version": "1.0.0" },
                "2.0.0": { "name": "left-pad", "version": "2.0.0",
                           "dist": { "tarball": "https://registry.npmjs.org/x.tgz" } }
            }
        });
        let out = filter_packument(&doc, &|_| true, |v| format!("https://weft.test/{v}.tgz"));
        assert_eq!(
            out["versions"]["1.0.0"]["dist"]["tarball"],
            "https://weft.test/1.0.0.tgz"
        );
        // …and one that had a `dist` has it replaced, not merged over.
        assert_eq!(
            out["versions"]["2.0.0"]["dist"]["tarball"],
            "https://weft.test/2.0.0.tgz"
        );
    }

    /// The recorded answers from **registry.npmjs.org** — not ours —
    /// read the way the product reads them, and the fake the proxy suite
    /// runs against held to the same shape.
    ///
    /// This is the test the `Retry-After`, Stripe billing-period and
    /// runner-label bugs all lacked in stratum-core. Each of those was a
    /// fake that was wrong in exactly the place the product depended on
    /// it, with a green test named for the case. The recordings in
    /// `skein-testkit/fixtures/registry` are re-recorded by
    /// `scripts/record-npm-fixtures.py`; when npmjs moves a field, this
    /// goes red here rather than in production.
    #[test]
    fn upstream_fixtures_parse_like_the_fake() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../skein-testkit/fixtures/registry");
        let mut checked = 0;
        for name in ["left-pad", "is-number", "lodash"] {
            let body = std::fs::read(dir.join(format!("npm-{name}.json")))
                .unwrap_or_else(|e| panic!("fixture npm-{name}: {e}"));
            let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let versions = upstream_versions(&doc);
            assert!(!versions.is_empty(), "{name}: no versions were read");

            for v in &versions {
                // The tarball URL is absolute and on npmjs's own origin,
                // which is what `upstream::fetch`'s same-origin check
                // relies on. If npmjs ever moves artifacts to a separate
                // CDN host, this is where we find out.
                let url = v
                    .tarball
                    .as_deref()
                    .unwrap_or_else(|| panic!("{name} {} named no tarball", v.version));
                assert!(
                    url.starts_with("https://registry.npmjs.org/"),
                    "{name} {}: {url}",
                    v.version
                );
                // `time` is a **sibling map keyed by version**, not a
                // field inside each manifest. Read the wrong way the
                // cooldown silently holds nothing, and every test of it
                // would still pass.
                assert!(
                    v.published_at.is_some(),
                    "{name} {}: no publish date was read, so the cooldown reads nothing",
                    v.version
                );
                checked += 1;
            }

            // The fake the proxy suite runs against, held to the same
            // three facts the gate is decided from — read off the
            // document it actually serves, over loopback, by the same
            // parser. Not a hand-written copy of its shape: a copy would
            // agree with the recording while the fake drifted, which is
            // exactly how a fake ends up green where the product is
            // broken.
            let fake = skein_testkit::fake_registry::FakeRegistry::start();
            let first = &versions[0];
            fake.add(
                name,
                vec![skein_testkit::fake_registry::Version::new(
                    &first.version,
                    first.licence.as_deref(),
                    Some("2020-01-01T00:00:00.000Z"),
                )],
            );
            let served: serde_json::Value = serde_json::from_str(
                &ureq::get(&format!("{}/{name}", fake.base_url))
                    .call()
                    .unwrap_or_else(|e| {
                        panic!("{name}: the fake would not serve its packument: {e}")
                    })
                    .into_string()
                    .unwrap(),
            )
            .unwrap();
            let from_fake = upstream_versions(&served);
            assert_eq!(
                from_fake.len(),
                1,
                "{name}: the fake's document did not parse"
            );
            assert_eq!(from_fake[0].version, first.version, "{name}");
            assert_eq!(
                from_fake[0].licence, first.licence,
                "{name}: the fake declares its licence where npmjs does not"
            );
            assert!(
                from_fake[0].published_at.is_some(),
                "{name}: the fake's publish date is not where npmjs puts it"
            );
            let tarball = from_fake[0].tarball.as_deref().unwrap_or_default();
            assert!(
                tarball.starts_with(&format!("{}/", fake.base_url)),
                "{name}: the fake's tarball is not on its own origin, as npmjs's are: {tarball}"
            );
            // And the shape around it: `time` a sibling of `versions`,
            // `dist.tarball` inside each version, as recorded.
            for (doc, who) in [(&doc, "npmjs"), (&served, "the fake")] {
                assert!(
                    doc["time"].is_object(),
                    "{name}: {who} has no sibling `time` map"
                );
                assert!(
                    doc["versions"].is_object(),
                    "{name}: {who} has no `versions` map"
                );
                assert!(
                    doc["dist-tags"].is_object(),
                    "{name}: {who} has no `dist-tags`"
                );
            }
        }
        assert!(
            checked >= 10,
            "only {checked} recorded versions were checked"
        );
    }

    /// `left-pad`'s oldest releases declare `"license": "BSD"`, which is
    /// three different licences. Recorded from the wild rather than
    /// invented, because the temptation to map it is exactly the
    /// mistake: an artifact admitted under a rule somebody wrote for
    /// BSD-3-Clause when it is in fact BSD-2-Clause, and nothing would
    /// ever surface it.
    #[test]
    fn an_ambiguous_recorded_licence_is_read_as_declared_and_not_resolved() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../skein-testkit/fixtures/registry");
        let body = std::fs::read(dir.join("npm-left-pad.json")).expect("fixture");
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let versions = upstream_versions(&doc);
        let bsd = versions
            .iter()
            .find(|v| v.licence.as_deref() == Some("BSD"))
            .expect("left-pad's early releases declare a bare \"BSD\"");
        // Passed through exactly as declared. What happens to it is the
        // organization's policy's business — `spdx::evaluate` answers
        // `Unknown` for a name no rule matches, and the ecosystem's
        // `unknown` disposition decides.
        assert_eq!(bsd.licence.as_deref(), Some("BSD"));
    }

    /// A dist-tag naming a version the document does not carry is
    /// dropped, never repointed.
    ///
    /// npm resolves `widget@latest` by reading the tag and then looking
    /// that version up in `versions`; a dangling tag fails the install
    /// with "no matching version", which reads as a corrupt registry.
    /// Repointing the tag at some other version would be worse — it
    /// would silently install something other than what the tag means.
    ///
    /// Two real paths reach this: a version whose files are gone, and a
    /// cached proxied version the admission policy now withholds.
    #[test]
    fn a_dist_tag_naming_a_version_we_do_not_carry_is_dropped() {
        let versions = [view("1.0.0", false)];
        let tags = [
            ("latest".to_string(), "2.0.0".to_string()),
            ("stable".to_string(), "1.0.0".to_string()),
        ];
        let doc = packument(
            "@acme/widget",
            &versions,
            &tags,
            |v| v.filename.clone(),
            |_| ("s".into(), "i".into()),
        );
        assert!(
            doc["dist-tags"]["latest"].is_null(),
            "a tag pointed at a version the document does not have: {doc}"
        );
        assert_eq!(
            doc["dist-tags"]["stable"], "1.0.0",
            "a tag that does resolve was dropped too: {doc}"
        );
    }

    /// Which names may be published, and what npm prints for the ones
    /// that may not — every shape, including an organization an admin
    /// has left with no scope at all.
    #[test]
    fn a_publish_outside_the_organizations_scopes_is_refused_in_words() {
        let scopes = vec!["@acme".to_string(), "@old".to_string()];
        for ok in ["@acme/widget", "@ACME/Widget", " @old/thing "] {
            assert_eq!(scope_refusal(ok, &scopes, "@acme"), None, "{ok}");
            assert!(under_scopes(ok, &scopes), "{ok}");
        }
        for foreign in ["@acme-corp/x", "@acmecorp/x", "@acm/x", "plain"] {
            assert!(!under_scopes(foreign, &scopes), "{foreign}");
        }
        assert_eq!(
            scope_refusal("plain-name", &scopes, "@acme").as_deref(),
            Some(
                "npm packages here are published under this organization's scopes (@acme, \
                 @old); \"plain-name\" has no scope — publish it as @acme/plain-name"
            )
        );
        // The suggestion is the organization's own scope while it has it…
        let renamed = vec!["@acme".to_string(), "@acme-corp".to_string()];
        assert!(scope_refusal("w", &renamed, "@acme-corp")
            .unwrap()
            .ends_with("publish it as @acme-corp/w"));
        // …and the first there is when an admin removed it.
        assert!(scope_refusal("w", &scopes, "@gone")
            .unwrap()
            .ends_with("publish it as @acme/w"));
        assert_eq!(
            scope_refusal("@ZZZ/thing", &scopes, "@acme").as_deref(),
            Some(
                "@zzz is not one of this organization's npm scopes (@acme, @old) — an admin can \
                 add it under Admission policy"
            )
        );
        let none: Vec<String> = Vec::new();
        assert!(scope_refusal("@zzz/thing", &none, "@acme")
            .unwrap()
            .contains("it has none yet"));
        assert!(scope_refusal("plain", &none, "@acme")
            .unwrap()
            .contains("an admin can add one"));
        assert!(!under_scopes("@acme/x", &none));
    }

    /// Semver's own precedence example, in order, and the cases a
    /// string comparison gets wrong.
    #[test]
    fn versions_order_by_semver_precedence() {
        let ordered = [
            "0.9.0",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.2.0",
            "1.9.0",
            "1.10.0",
            "10.0.0",
        ];
        for pair in ordered.windows(2) {
            let (a, b) = (Semver::parse(pair[0]), Semver::parse(pair[1]));
            assert!(a.is_some() && b.is_some(), "{pair:?}");
            assert!(a < b, "{} is not below {}", pair[0], pair[1]);
        }
        // Build metadata is not part of precedence.
        assert_eq!(
            Semver::parse("1.0.0+build.5")
                .unwrap()
                .cmp(&Semver::parse("1.0.0").unwrap()),
            std::cmp::Ordering::Equal
        );
        for not_semver in [
            "",
            "1",
            "1.0",
            "1.0.0.0",
            "v1.0.0",
            "01.0.0",
            "1.0.0-",
            "1.0.0-a..b",
            "latest",
        ] {
            assert!(Semver::parse(not_semver).is_none(), "{not_semver:?}");
        }
    }

    /// What `latest` falls back to, argued case by case.
    #[test]
    fn latest_falls_back_to_the_highest_release_nobody_yanked() {
        let vs = |list: &[(&str, bool)]| -> Vec<VersionView> {
            list.iter().map(|(v, y)| view(v, *y)).collect()
        };
        // Highest, not newest: 1.10.0 published before 1.9.0.
        assert_eq!(
            latest_unyanked(&vs(&[
                ("1.10.0", false),
                ("1.9.0", false),
                ("1.11.0", true)
            ])),
            Some("1.10.0")
        );
        // A release over any pre-release, however high.
        assert_eq!(
            latest_unyanked(&vs(&[
                ("1.0.0", false),
                ("2.0.0-rc.1", false),
                ("1.1.0", true)
            ])),
            Some("1.0.0")
        );
        // A pre-release when nothing else is left.
        assert_eq!(
            latest_unyanked(&vs(&[
                ("2.0.0-rc.1", false),
                ("2.0.0-rc.2", false),
                ("1.0.0", true)
            ])),
            Some("2.0.0-rc.2")
        );
        // Nothing unyanked, or nothing that can be placed.
        assert_eq!(latest_unyanked(&vs(&[("1.0.0", true)])), None);
        assert_eq!(
            latest_unyanked(&vs(&[("banana", false), ("1.0.0", true)])),
            None
        );

        let doc = packument(
            "@acme/widget",
            &vs(&[("1.0.0", false), ("1.1.0", true), ("2.0.0-beta", true)]),
            &[
                ("latest".to_string(), "1.1.0".to_string()),
                ("next".to_string(), "2.0.0-beta".to_string()),
                ("stable".to_string(), "1.1.0".to_string()),
            ],
            |v| v.filename.clone(),
            |_| ("s".into(), "i".into()),
        );
        assert_eq!(
            doc["dist-tags"],
            serde_json::json!({ "latest": "1.0.0", "next": "2.0.0-beta", "stable": "1.1.0" }),
            "only latest is repointed, and only because it names a yanked version"
        );
        let all_yanked = packument(
            "@acme/widget",
            &vs(&[("1.0.0", true)]),
            &[("latest".to_string(), "1.0.0".to_string())],
            |v| v.filename.clone(),
            |_| ("s".into(), "i".into()),
        );
        assert_eq!(all_yanked["dist-tags"], serde_json::json!({}));
        assert!(all_yanked["versions"]["1.0.0"]["deprecated"].is_string());
    }

    /// Unparseable stored metadata must not take the whole packument
    /// down: one bad row would otherwise make every version of the
    /// package unresolvable.
    #[test]
    fn a_version_with_unreadable_metadata_still_resolves() {
        let broken = VersionView {
            version: "1.0.0".into(),
            metadata: "not json at all".into(),
            digests: "{}".into(),
            filename: "widget-1.0.0.tgz".into(),
            yanked: false,
        };
        let doc = packument(
            "@acme/widget",
            &[broken],
            &[],
            |v| v.filename.clone(),
            |_| ("s".into(), "i".into()),
        );
        assert_eq!(doc["versions"]["1.0.0"]["version"], "1.0.0");
        assert_eq!(doc["versions"]["1.0.0"]["dist"]["shasum"], "s");
    }

    /// The client takes the last path segment of `dist.tarball` as its
    /// cache filename, and a scoped package's tarball drops the scope.
    #[test]
    fn a_scoped_packages_tarball_drops_the_scope() {
        assert_eq!(tarball_name("@acme/widget", "1.0.0"), "widget-1.0.0.tgz");
        assert_eq!(tarball_name("lodash", "4.17.21"), "lodash-4.17.21.tgz");
    }

    /// npm sends a scoped name URL-encoded; a person sends it plain.
    /// Both must reach one package.
    #[test]
    fn both_spellings_of_a_scoped_name_decode_alike() {
        assert_eq!(decode_name("@acme%2fwidget"), "@acme/widget");
        assert_eq!(decode_name("@acme%2Fwidget"), "@acme/widget");
        assert_eq!(decode_name("@acme/widget"), "@acme/widget");
        assert_eq!(decode_name("lodash"), "lodash");
    }

    #[test]
    fn the_digests_we_advertise_are_the_ones_npm_checks() {
        // Values from the well-known SHA-1 and SHA-512 of "abc".
        assert_eq!(
            shasum_of(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let integrity = integrity_of(b"abc");
        assert!(integrity.starts_with("sha512-"), "{integrity}");
        assert_eq!(integrity_of(b"abc"), integrity_of(b"abc"));
        assert_ne!(integrity_of(b"abc"), integrity_of(b"abd"));
    }

    fn upstream_doc() -> serde_json::Value {
        serde_json::json!({
            "name": "left-pad",
            "dist-tags": { "latest": "2.0.0", "legacy": "1.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "left-pad", "version": "1.0.0", "license": "MIT",
                    "dist": { "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.0.0.tgz",
                              "shasum": "aaa" }
                },
                "2.0.0": {
                    "name": "left-pad", "version": "2.0.0", "license": "GPL-3.0",
                    "dist": { "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-2.0.0.tgz" }
                }
            },
            "time": {
                "created": "2020-01-01T00:00:00.000Z",
                "1.0.0": "2020-01-01T00:00:00.000Z",
                "2.0.0": "2026-09-13T02:31:00.000Z"
            }
        })
    }

    /// The three facts the gate decides on, including the publish date —
    /// which lives in a `time` map beside `versions` rather than on each
    /// version, and is the only place that date exists.
    #[test]
    fn an_upstream_packument_yields_the_facts_the_policy_needs() {
        let vs = upstream_versions(&upstream_doc());
        let one = vs.iter().find(|v| v.version == "1.0.0").expect("1.0.0");
        assert_eq!(one.licence.as_deref(), Some("MIT"));
        assert_eq!(one.published_at, Some(1_577_836_800_000));
        assert!(one
            .tarball
            .as_deref()
            .unwrap()
            .ends_with("left-pad-1.0.0.tgz"));

        let two = vs.iter().find(|v| v.version == "2.0.0").expect("2.0.0");
        assert_eq!(two.licence.as_deref(), Some("GPL-3.0"));
        assert!(two.published_at.unwrap() > one.published_at.unwrap());

        // A document with no `time` is not an error: the cooldown reads
        // a missing date as "unknown" and does not hold on it.
        let mut undated = upstream_doc();
        undated.as_object_mut().unwrap().remove("time");
        assert!(upstream_versions(&undated)
            .iter()
            .all(|v| v.published_at.is_none()));
    }

    /// Hand-rolled because this workspace carries no date library.
    /// Pinned against known instants rather than against itself.
    #[test]
    fn npm_timestamps_parse_and_nonsense_does_not() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601_ms("2020-01-01T00:00:00.000Z"),
            Some(1_577_836_800_000)
        );
        // A leap day, which a naive day count gets wrong.
        assert_eq!(
            parse_iso8601_ms("2024-02-29T00:00:00.000Z"),
            Some(1_709_164_800_000)
        );
        // A century that is not a leap year, which a simpler rule does.
        assert_eq!(
            parse_iso8601_ms("1900-03-01T00:00:00.000Z"),
            Some(-2_203_891_200_000)
        );
        assert_eq!(
            parse_iso8601_ms("2026-09-13T02:31:00.000Z"),
            Some(1_789_266_660_000)
        );

        for bad in [
            "",
            "yesterday",
            "2020-01-01",
            "2020-13-01T00:00:00Z",
            "2020-01-32T00:00:00Z",
            "2020-01-01T25:00:00Z",
            "2020-01-01T00:61:00Z",
            "20200101T000000Z",
            "xxxx-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_iso8601_ms(bad), None, "{bad:?} parsed");
        }
    }

    /// Filtering at metadata time is the whole point: a client handed
    /// the full document resolves to a version the gate then refuses,
    /// and that reads as a broken registry rather than a policy.
    #[test]
    fn a_filtered_packument_offers_only_what_may_be_served() {
        let doc = upstream_doc();
        let out = filter_packument(&doc, &|v| v == "1.0.0", |v| {
            format!("https://weft.test/-/left-pad-{v}.tgz")
        });
        let vs = out["versions"].as_object().expect("versions");
        assert_eq!(vs.len(), 1);
        assert!(vs.contains_key("1.0.0"));
        assert!(
            !vs.contains_key("2.0.0"),
            "a refused version was still offered"
        );

        // Every surviving tarball points at us, not at the upstream.
        assert_eq!(
            out["versions"]["1.0.0"]["dist"]["tarball"],
            "https://weft.test/-/left-pad-1.0.0.tgz"
        );
        // …and the rest of the dist block survives, so npm still has
        // something to check the bytes against.
        assert_eq!(out["versions"]["1.0.0"]["dist"]["shasum"], "aaa");
    }

    /// A tag pointing at a version that did not survive is **dropped**,
    /// never repointed. Repointing `latest` at an older release would
    /// silently downgrade every install that does not pin — a worse
    /// surprise than the tag being absent.
    #[test]
    fn a_dist_tag_for_a_refused_version_is_dropped_not_repointed() {
        let out = filter_packument(&upstream_doc(), &|v| v == "1.0.0", |v| v.to_string());
        let tags = out["dist-tags"].as_object().expect("dist-tags");
        assert!(
            !tags.contains_key("latest"),
            "latest was repointed at an older release: {tags:?}"
        );
        assert_eq!(tags.get("legacy").and_then(|v| v.as_str()), Some("1.0.0"));
    }

    /// Nothing admitted is an empty document, not an error and not the
    /// unfiltered one. npm reads it as "no matching version", which is
    /// the truth.
    #[test]
    fn a_packument_with_nothing_admitted_offers_nothing() {
        let out = filter_packument(&upstream_doc(), &|_| false, |v| v.to_string());
        assert_eq!(out["versions"].as_object().map(|v| v.len()), Some(0));
        assert_eq!(out["dist-tags"].as_object().map(|t| t.len()), Some(0));
        assert_eq!(out["name"], "left-pad", "the document is still a packument");
    }

    #[test]
    fn base64_round_trips_through_the_decoder_we_use() {
        for case in [
            &b""[..],
            b"a",
            b"ab",
            b"abc",
            b"abcd",
            b"the quick brown fox jumps over the lazy dog",
            &[0u8, 255, 128, 1][..],
        ] {
            let encoded = crate::authx::base64_encode(case);
            assert_eq!(
                decode_attachment(&encoded).unwrap(),
                case,
                "round trip failed for {case:?}"
            );
        }
        // …and the whitespace a JSON encoder may wrap it with is ignored.
        assert_eq!(decode_attachment("YW Jj\nZA==").unwrap(), b"abcd");
    }
}
