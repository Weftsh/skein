use std::io::Read;
use std::time::Duration;

/// Minimal S3-compatible client: GET / GET-with-Range / conditional PUT /
/// LIST / DELETE against `base_url` (e.g. `http://127.0.0.1:9000/skein`
/// path-style, or `https://skein.s3.eu-west-1.amazonaws.com` virtual-host
/// style). Requests are SigV4-signed when AWS credentials are in the
/// environment (`AWS_ACCESS_KEY_ID` etc. — see sig.rs); anonymous
/// otherwise.
pub struct ObjectStore {
    base_url: String,
    /// Host header value ("host[:port]") — must match what the HTTP layer
    /// sends, since SigV4 signs it.
    host: String,
    /// URL path prefix including the bucket ("/skein"), part of the
    /// canonical URI.
    path_prefix: String,
    signer: Option<crate::sig::SigV4>,
    agent: ureq::Agent,
}

/// Read timeout for ordinary traffic. A large layer streams block by
/// block, so this is generous by design.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

impl ObjectStore {
    pub fn new(base_url: &str) -> Self {
        Self::with_timeout(base_url, DEFAULT_TIMEOUT)
    }

    /// A client with a bounded read timeout. Health probing needs a
    /// *short* one: `readyz` proves the store is reachable, and with the
    /// 300 s default a store that accepts connections but never answers
    /// makes the health check itself hang for five minutes instead of
    /// reporting 503 — so no load balancer ever evicts the instance. A
    /// probe that cannot fail fast is not a probe.
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        let rest = base_url
            .split_once("://")
            .map(|(_, r)| r)
            .unwrap_or(&base_url);
        let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
        Self {
            host: host.to_string(),
            path_prefix: if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            },
            signer: crate::sig::SigV4::from_env(),
            base_url,
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(5))
                .timeout(timeout)
                .build(),
        }
    }

    /// SigV4-sign `req` for `key` if credentials are configured.
    fn signed(
        &self,
        mut req: ureq::Request,
        method: &str,
        key: &str,
        payload_sha256: &str,
    ) -> Result<ureq::Request, String> {
        if let Some(signer) = &self.signer {
            let path = format!("{}/{key}", self.path_prefix);
            let hdrs = signer.sign(method, &self.host, &path, payload_sha256)?;
            for (name, value) in hdrs.headers {
                req = req.set(name, &value);
            }
        }
        Ok(req)
    }

    /// GET an object (optionally a byte range), returning a streaming
    /// reader.
    pub fn get_stream(
        &self,
        key: &str,
        range: Option<(u64, u64)>, // inclusive start..end byte offsets
    ) -> Result<Box<dyn Read + Send>, String> {
        let url = format!("{}/{}", self.base_url, key);
        // Transient failures (throttling, connection resets) get two retries
        // with backoff; 4xx never retries.
        let mut attempt = 0;
        let resp = loop {
            let mut req = self
                .signed(self.agent.get(&url), "GET", key, crate::sig::EMPTY_SHA256)
                .map_err(|e| format!("GET {key}: {e}"))?;
            if let Some((start, end)) = range {
                req = req.set("Range", &format!("bytes={start}-{end}"));
            }
            match req.call() {
                Ok(r) => break r,
                Err(ureq::Error::Status(code, _)) if code < 500 => {
                    return Err(format!("GET {key}: HTTP {code}"));
                }
                Err(e) if attempt < 2 => {
                    attempt += 1;
                    std::thread::sleep(Duration::from_millis(100 << attempt));
                    let _ = e;
                }
                Err(e) => return Err(format!("GET {key}: {e}")),
            }
        };
        let status = resp.status();
        // A store or proxy that ignores Range and returns 200 would silently
        // shift every offset we resolve against — fail loudly instead.
        match (range.is_some(), status) {
            (true, 206) | (false, 200) => {}
            (true, other) => return Err(format!("GET {key}: expected 206 for range, got {other}")),
            (false, other) => return Err(format!("GET {key}: HTTP {other}")),
        }
        Ok(Box::new(resp.into_reader()))
    }

    /// GET a whole object into memory.
    pub fn get(&self, key: &str) -> Result<Vec<u8>, String> {
        let mut buf = Vec::new();
        self.get_stream(key, None)?
            .read_to_end(&mut buf)
            .map_err(|e| format!("read {key}: {e}"))?;
        Ok(buf)
    }

    /// GET a whole object plus its ETag (the CAS token for a later put).
    pub fn get_with_etag(&self, key: &str) -> Result<(Vec<u8>, String), String> {
        let url = format!("{}/{}", self.base_url, key);
        let resp = self
            .signed(self.agent.get(&url), "GET", key, crate::sig::EMPTY_SHA256)
            .map_err(|e| format!("GET {key}: {e}"))?
            .call()
            // Status errors formatted like get_stream's ("HTTP <code>")
            // so 404 detection is uniform.
            .map_err(|e| match e {
                ureq::Error::Status(code, _) => format!("GET {key}: HTTP {code}"),
                e => format!("GET {key}: {e}"),
            })?;
        let etag = resp.header("ETag").unwrap_or_default().to_string();
        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| format!("read {key}: {e}"))?;
        Ok((buf, etag))
    }

    /// PUT an object, optionally guarded by a write condition. The store
    /// must enforce the condition (verified against MinIO: 412 on
    /// violated If-None-Match:* and stale If-Match).
    pub fn put(&self, key: &str, body: &[u8], cond: PutCond) -> Result<(), PutError> {
        let url = format!("{}/{}", self.base_url, key);
        let mut req = self
            .signed(
                self.agent.put(&url),
                "PUT",
                key,
                &crate::sig::sha256_hex(body),
            )
            .map_err(PutError::Other)?;
        match &cond {
            PutCond::None => {}
            PutCond::IfNoneMatchStar => req = req.set("If-None-Match", "*"),
            PutCond::IfMatch(etag) => req = req.set("If-Match", etag),
        }
        match req.send_bytes(body) {
            Ok(_) => Ok(()),
            // 409 alongside 412. Real S3 answers 409
            // ConditionalRequestConflict when two conditional writes to
            // one key overlap, and 412 only when the precondition
            // genuinely failed; a racing pair can see 409 then 412 on the
            // retry. Both mean "someone else won, re-read and retry",
            // which is exactly `Conflict`. MinIO never emits 409, so a
            // suite run only against MinIO never sees it — stratum-core
            // learned this on a real fleet.
            Err(ureq::Error::Status(412, _)) | Err(ureq::Error::Status(409, _)) => {
                Err(PutError::Conflict)
            }
            Err(e) => Err(PutError::Other(format!("PUT {key}: {e}"))),
        }
    }
}

/// LIST and DELETE, needed by the blob collector.
impl ObjectStore {
    /// List keys under `prefix` via ListObjectsV2, fully paginated.
    /// Returns (key, last_modified_rfc3339) pairs.
    pub fn list(&self, prefix: &str) -> Result<Vec<(String, String)>, String> {
        Ok(self
            .list_entries(prefix)?
            .into_iter()
            .map(|e| (e.key, e.last_modified))
            .collect())
    }

    /// LIST every key under `prefix` with its size in bytes, as the
    /// store reports it.
    ///
    /// This is the *physical* view: what the bucket actually holds,
    /// which is the number that catches a database that has quietly lost
    /// track of what it wrote, or a sweep that has stopped deleting.
    pub fn list_sized(&self, prefix: &str) -> Result<Vec<(String, u64)>, String> {
        Ok(self
            .list_entries(prefix)?
            .into_iter()
            .map(|e| (e.key, e.size))
            .collect())
    }

    fn list_entries(&self, prefix: &str) -> Result<Vec<ListEntry>, String> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut query: Vec<(&str, &str)> =
                vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
            let tok = token.clone();
            if let Some(t) = tok.as_deref() {
                query.push(("continuation-token", t));
            }
            let qs = crate::sig::canonical_query(&query);
            let url = format!("{}://{}{}?{qs}", self.scheme(), self.host, self.path_prefix);
            let mut req = self.agent.get(&url);
            if let Some(signer) = &self.signer {
                let path = if self.path_prefix.is_empty() {
                    "/".to_string()
                } else {
                    self.path_prefix.clone()
                };
                let hdrs = signer.sign_with_query(
                    "GET",
                    &self.host,
                    &path,
                    &query,
                    crate::sig::EMPTY_SHA256,
                )?;
                for (name, value) in hdrs.headers {
                    req = req.set(name, &value);
                }
            }
            let resp = req.call().map_err(|e| match e {
                ureq::Error::Status(code, _) => format!("LIST {prefix}: HTTP {code}"),
                e => format!("LIST {prefix}: {e}"),
            })?;
            let body = resp
                .into_string()
                .map_err(|e| format!("LIST {prefix}: {e}"))?;
            out.extend(parse_list_xml(&body));
            match (
                xml_tag(&body, "IsTruncated").as_deref(),
                xml_tag(&body, "NextContinuationToken"),
            ) {
                (Some("true"), Some(t)) => token = Some(t),
                _ => break,
            }
        }
        Ok(out)
    }

    /// Prove the bucket is usable: it exists, and it answers **404** for
    /// a key that is not there.
    ///
    /// Two requests because each catches what the other cannot. A GET of
    /// an absent key answers 404 whether the *key* or the whole *bucket*
    /// is missing, so on its own it passes an install whose bucket was
    /// never created, and the first publish fails instead. A one-key LIST
    /// fails on a missing bucket — and the GET is still needed, because
    /// only it shows an IAM policy without `s3:ListBucket` turning absence
    /// into 403, which would make every missing artifact look like a
    /// permissions failure.
    pub fn probe(&self) -> Result<(), String> {
        self.list_page("skein-probe/", 1)
            .map_err(|e| format!("the bucket at {} is not usable: {e}", self.base_url))?;
        match self.get("skein-probe/absent") {
            Ok(_) => Ok(()),
            Err(e) if is_absent(&e) => Ok(()),
            Err(e) => Err(diagnose(e)),
        }
    }

    /// Create the bucket if it does not exist. Path-style URLs only
    /// (`http://minio:9000/skein`): that is MinIO and the other
    /// self-hosted stores, where creating the bucket at startup saves a
    /// separate tool. A bucket on AWS is infrastructure somebody should
    /// create on purpose, with its own policy, and this refuses to.
    pub fn ensure_bucket(&self) -> Result<bool, String> {
        let bucket = self.path_prefix.trim_start_matches('/');
        if bucket.is_empty() || bucket.contains('/') {
            return Err(format!(
                "{} does not name a bucket as its path, so Skein cannot create it; \
                 create the bucket yourself",
                self.base_url
            ));
        }
        if self.list_page("skein-probe/", 1).is_ok() {
            return Ok(false);
        }
        let url = format!("{}://{}/{bucket}", self.scheme(), self.host);
        let mut req = self.agent.put(&url);
        if let Some(signer) = &self.signer {
            let hdrs = signer.sign(
                "PUT",
                &self.host,
                &format!("/{bucket}"),
                crate::sig::EMPTY_SHA256,
            )?;
            for (name, value) in hdrs.headers {
                req = req.set(name, &value);
            }
        }
        match req.send_bytes(&[]) {
            Ok(_) => Ok(true),
            // Created by somebody else in between: the outcome we wanted.
            Err(ureq::Error::Status(409, _)) => Ok(false),
            Err(ureq::Error::Status(code, _)) => {
                Err(format!("create bucket {bucket}: HTTP {code}"))
            }
            Err(e) => Err(format!("create bucket {bucket}: {e}")),
        }
    }

    /// One page of a listing, at most `max` keys.
    fn list_page(&self, prefix: &str, max: usize) -> Result<Vec<ListEntry>, String> {
        let max = max.to_string();
        let query: Vec<(&str, &str)> =
            vec![("list-type", "2"), ("prefix", prefix), ("max-keys", &max)];
        let qs = crate::sig::canonical_query(&query);
        let url = format!("{}://{}{}?{qs}", self.scheme(), self.host, self.path_prefix);
        let mut req = self.agent.get(&url);
        if let Some(signer) = &self.signer {
            let path = if self.path_prefix.is_empty() {
                "/".to_string()
            } else {
                self.path_prefix.clone()
            };
            let hdrs = signer.sign_with_query(
                "GET",
                &self.host,
                &path,
                &query,
                crate::sig::EMPTY_SHA256,
            )?;
            for (name, value) in hdrs.headers {
                req = req.set(name, &value);
            }
        }
        let resp = req.call().map_err(|e| match e {
            ureq::Error::Status(code, _) => format!("LIST {prefix}: HTTP {code}"),
            e => format!("LIST {prefix}: {e}"),
        })?;
        let body = resp
            .into_string()
            .map_err(|e| format!("LIST {prefix}: {e}"))?;
        // A URL with no bucket in it lists the *service* — every bucket
        // — and that answer parses as an empty page. Only a bucket
        // listing is an answer from a bucket.
        if !body.contains("<ListBucketResult") {
            return Err(format!(
                "LIST {prefix}: {} answered, but not as a bucket — does the URL name one?",
                self.base_url
            ));
        }
        Ok(parse_list_xml(&body))
    }

    /// DELETE one object (idempotent — S3 204s for absent keys).
    pub fn delete(&self, key: &str) -> Result<(), String> {
        let url = format!("{}/{}", self.base_url, key);
        let req = self
            .signed(
                self.agent.delete(&url),
                "DELETE",
                key,
                crate::sig::EMPTY_SHA256,
            )
            .map_err(|e| format!("DELETE {key}: {e}"))?;
        match req.call() {
            Ok(_) => Ok(()),
            Err(ureq::Error::Status(404, _)) => Ok(()),
            Err(ureq::Error::Status(code, _)) => Err(format!("DELETE {key}: HTTP {code}")),
            Err(e) => Err(format!("DELETE {key}: {e}")),
        }
    }

    fn scheme(&self) -> &str {
        if self.base_url.starts_with("https://") {
            "https"
        } else {
            "http"
        }
    }
}

/// Extract every <Key>/<LastModified> pair from a ListObjectsV2 response.
/// Keys in our stores are URI-unreserved, so no XML entities appear.
/// One `<Contents>` element of a ListObjectsV2 page: the three fields
/// anything here reads. `<Size>` is what S3 and MinIO both emit for the
/// object's byte length; an absent or unparsable one reads as zero
/// rather than failing the whole listing, because a GC sweep that
/// cannot list is worse than an inventory that undercounts one key.
struct ListEntry {
    key: String,
    last_modified: String,
    size: u64,
}

fn parse_list_xml(body: &str) -> Vec<ListEntry> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("<Contents>") {
        let Some(end) = rest[start..].find("</Contents>") else {
            break;
        };
        let chunk = &rest[start..start + end];
        if let Some(key) = xml_tag(chunk, "Key") {
            out.push(ListEntry {
                key,
                last_modified: xml_tag(chunk, "LastModified").unwrap_or_default(),
                size: xml_tag(chunk, "Size")
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0),
            });
        }
        rest = &rest[start + end + 11..];
    }
    out
}

fn xml_tag(chunk: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let s = chunk.find(&open)? + open.len();
    let e = chunk[s..].find(&close)? + s;
    Some(chunk[s..e].to_string())
}

/// Write condition for ObjectStore::put.
pub enum PutCond {
    None,
    /// Create-only: fail with Conflict if the key already exists.
    IfNoneMatchStar,
    /// Compare-and-swap: fail with Conflict unless the stored ETag matches.
    IfMatch(String),
}

#[derive(Debug)]
pub enum PutError {
    /// The write condition failed (concurrent writer won).
    Conflict,
    Other(String),
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutError::Conflict => write!(f, "conditional write conflict"),
            PutError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// The HTTP status an object-store error carries, if it carries one.
///
/// Every status failure here is formatted `<VERB> <key>: HTTP <code>`,
/// and callers only ever *prefix* that, so the code is the last thing in
/// the message. Requiring exactly three digits at the very end is what
/// stops a key or package name that happens to contain the bytes
/// `HTTP 404` from being read as a status — stratum-core learned the
/// general lesson from a repository named `rfc-403`.
pub fn store_status(err: &str) -> Option<u16> {
    let code = err.rsplit_once(": HTTP ")?.1;
    if code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()) {
        code.parse().ok()
    } else {
        None
    }
}

/// The object is not there: the store answered 404.
///
/// Deliberately *only* 404. Real S3 answers **403 AccessDenied** for a
/// missing key when the principal lacks `s3:ListBucket`, and reading
/// that as absence would turn a permissions problem into "no such
/// package" for every artifact in the registry. [`diagnose`] names it
/// instead.
pub fn is_absent(err: &str) -> bool {
    store_status(err) == Some(404)
}

/// Name the most likely cause of a store 403 in the error itself: an IAM
/// policy that grants `s3:GetObject` but not `s3:ListBucket`, under which
/// S3 answers 403 for keys that simply are not there.
pub fn diagnose(err: String) -> String {
    if store_status(&err) == Some(403) {
        format!(
            "{err} — the store answered 403 where an absent key must answer 404; \
             the usual cause is a bucket policy without s3:ListBucket"
        )
    } else {
        err
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_is_read_only_from_the_tail_of_the_message() {
        assert_eq!(store_status("GET o/1/pkg/ab: HTTP 404"), Some(404));
        assert_eq!(store_status("read artifact: GET k: HTTP 503"), Some(503));
        assert!(is_absent("GET k: HTTP 404"));
        // A key that merely contains the phrase is not a status.
        assert_eq!(store_status("GET o/HTTP 404/x: connection reset"), None);
        assert_eq!(store_status("GET k: expected 206 for range, got 404"), None);
        assert_eq!(store_status("GET k: HTTP 40"), None);
        assert_eq!(store_status("GET k: HTTP 4044"), None);
        assert!(!is_absent("GET k: HTTP 403"));

        let d = diagnose("GET k: HTTP 403".into());
        assert!(d.contains("s3:ListBucket"), "{d}");
        assert_eq!(diagnose("GET k: HTTP 500".into()), "GET k: HTTP 500");
    }

    #[test]
    fn a_base_url_splits_into_host_and_bucket_path_in_both_addressing_styles() {
        let path = ObjectStore::new("http://127.0.0.1:9000/skein/");
        assert_eq!(path.host, "127.0.0.1:9000");
        assert_eq!(path.path_prefix, "/skein");
        assert_eq!(path.base_url, "http://127.0.0.1:9000/skein");
        let vhost = ObjectStore::new("https://skein.s3.eu-west-1.amazonaws.com");
        assert_eq!(vhost.host, "skein.s3.eu-west-1.amazonaws.com");
        assert_eq!(vhost.path_prefix, "");
        assert_eq!(vhost.scheme(), "https");
        assert_eq!(path.scheme(), "http");
    }

    #[test]
    fn a_list_page_is_read_key_by_key() {
        let body = "<ListBucketResult><IsTruncated>true</IsTruncated>\
            <Contents><Key>o/1/pkg/aa</Key><LastModified>2026-01-01T00:00:00Z</LastModified><Size>12</Size></Contents>\
            <Contents><Key>o/1/pkg/bb</Key><Size>nope</Size></Contents>\
            <NextContinuationToken>tok</NextContinuationToken></ListBucketResult>";
        let entries = parse_list_xml(body);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "o/1/pkg/aa");
        assert_eq!(entries[0].size, 12);
        assert_eq!(
            entries[1].size, 0,
            "an unreadable size undercounts, never fails"
        );
        assert_eq!(entries[1].last_modified, "");
        assert_eq!(
            xml_tag(body, "NextContinuationToken").as_deref(),
            Some("tok")
        );
        assert_eq!(xml_tag(body, "Missing"), None);
    }
}
