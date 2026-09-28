//! AWS Signature Version 4 request signing (S3, path-style URLs).
//!
//! Credentials come from the standard environment variables
//! (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional
//! `AWS_SESSION_TOKEN`, region from `AWS_REGION`/`AWS_DEFAULT_REGION`,
//! default `us-east-1`). No credentials → `None`, and requests go out
//! unsigned (anonymous), which is what pure-local benchmarking uses.
//!
//! Scope is deliberately small: the store only issues GET (optionally
//! ranged) and PUT with a fully-buffered body, no query strings, and
//! keys restricted to URI-unreserved characters plus `/` — so the
//! canonical request never needs percent-encoding. `signed_key` asserts
//! that restriction instead of implementing general encoding.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 of the empty string — the payload hash for bodyless requests.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

pub struct SigV4 {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
}

/// Headers to attach to an outgoing request, in (name, value) pairs.
pub struct SignedHeaders {
    pub headers: Vec<(&'static str, String)>,
}

impl SigV4 {
    pub fn from_env() -> Option<Self> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|_| "us-east-1".to_string());
        Some(Self {
            access_key,
            secret_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            region,
        })
    }

    /// Sign one request. `host` must match the Host header the HTTP layer
    /// will send (including `:port` when non-default); `path` is the full
    /// URL path (`/bucket/key...`); `payload_sha256` is the lowercase hex
    /// SHA-256 of the body (EMPTY_SHA256 for GET).
    pub fn sign(
        &self,
        method: &str,
        host: &str,
        path: &str,
        payload_sha256: &str,
    ) -> Result<SignedHeaders, String> {
        self.sign_at("s3", method, host, path, &[], payload_sha256, now_utc()?)
    }

    /// Query-string signing for LIST. Query values are percent-encoded
    /// per AWS canonical rules; pass raw values here and send the encoded
    /// form (`canonical_query`) on the wire.
    pub fn sign_with_query(
        &self,
        method: &str,
        host: &str,
        path: &str,
        query: &[(&str, &str)],
        payload_sha256: &str,
    ) -> Result<SignedHeaders, String> {
        self.sign_at("s3", method, host, path, query, payload_sha256, now_utc()?)
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_at(
        &self,
        service: &str,
        method: &str,
        host: &str,
        path: &str,
        query: &[(&str, &str)],
        payload_sha256: &str,
        (date, amz_date): (String, String),
    ) -> Result<SignedHeaders, String> {
        // The canonical URI must equal the path byte-for-byte after AWS's
        // segment encoding; our key charset makes encoding the identity.
        if !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~'))
        {
            return Err(format!("sigv4: key needs URI encoding, refusing: {path}"));
        }

        let mut canonical_headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_sha256}\nx-amz-date:{amz_date}\n");
        let mut signed_names = "host;x-amz-content-sha256;x-amz-date".to_string();
        if let Some(tok) = &self.session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{tok}\n"));
            signed_names.push_str(";x-amz-security-token");
        }
        let canonical_query = canonical_query(query);
        let canonical_request = format!(
            "{method}\n{path}\n{canonical_query}\n{canonical_headers}\n{signed_names}\n{payload_sha256}"
        );
        let scope = format!("{date}/{}/{service}/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let key = derive_key(&self.secret_key, &date, &self.region, service);
        let signature = hex(&hmac(&key, string_to_sign.as_bytes()));

        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}",
            self.access_key
        );
        let mut headers = vec![
            ("x-amz-date", amz_date),
            ("x-amz-content-sha256", payload_sha256.to_string()),
            ("Authorization", auth),
        ];
        if let Some(tok) = &self.session_token {
            headers.push(("x-amz-security-token", tok.clone()));
        }
        Ok(SignedHeaders { headers })
    }
}

/// AWS canonical query string: keys sorted, both sides percent-encoded
/// with the URI-unreserved set. Also exactly what goes on the wire.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn derive_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k = hmac(format!("AWS4{secret}").as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, service.as_bytes());
    hmac(&k, b"aws4_request")
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// (YYYYMMDD, YYYYMMDDTHHMMSSZ) for the current UTC time. Civil-date
/// conversion per Howard Hinnant's days algorithm — no chrono dependency.
fn now_utc() -> Result<(String, String), String> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    Ok(format_utc(secs))
}

/// `(YYYYMMDD, YYYYMMDDTHHMMSSZ)` for an epoch second. Public because
/// it is the one civil-date conversion in the tree, and a second copy
/// somewhere else would be a second set of leap-year bugs.
pub fn format_utc(secs: u64) -> (String, String) {
    let days = (secs / 86_400) as i64;
    let (h, m, s) = (secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    let date = format!("{y:04}{mo:02}{d:02}");
    let amz = format!("{date}T{h:02}{m:02}{s:02}Z");
    (date, amz)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        // 2026-08-19 23:59:07 UTC
        assert_eq!(
            format_utc(1_787_183_947),
            ("20260819".into(), "20260819T235907Z".into())
        );
        // Epoch + leap-year day: 2024-02-29 00:00:00
        assert_eq!(format_utc(1_709_164_800).1, "20240229T000000Z");
        assert_eq!(format_utc(0).1, "19700101T000000Z");
    }

    #[test]
    fn aws_documented_signing_key() {
        // The worked example from AWS's SigV4 documentation.
        let key = derive_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn get_signature_shape() {
        let sig = SigV4 {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
            session_token: None,
            region: "us-east-1".into(),
        };
        let hdrs = sig
            .sign_at(
                "s3",
                "GET",
                "127.0.0.1:9000",
                "/skein/o/01j/pkg/abc123",
                &[],
                EMPTY_SHA256,
                ("20260819".into(), "20260819T000000Z".into()),
            )
            .unwrap();
        let auth = &hdrs
            .headers
            .iter()
            .find(|(n, _)| *n == "Authorization")
            .unwrap()
            .1;
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260819/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="
        ));
        assert_eq!(auth.len(), auth.rfind('=').unwrap() + 1 + 64);
    }

    /// The service name reaches both the credential scope and the
    /// derived signing key, so signing the same request for `ses`
    /// changes the visible scope *and* the signature. Pinning only the
    /// scope would let a signer that forgot the key derivation pass.
    #[test]
    fn the_service_reaches_the_scope_and_the_signature() {
        let sig = SigV4 {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
            session_token: None,
            region: "us-east-1".into(),
        };
        let at = ("20260819".to_string(), "20260819T000000Z".to_string());
        let auth = |service: &str| {
            sig.sign_at(
                service,
                "POST",
                "email.us-east-1.amazonaws.com",
                "/v2/email/outbound-emails",
                &[],
                EMPTY_SHA256,
                at.clone(),
            )
            .unwrap()
            .headers
            .iter()
            .find(|(n, _)| *n == "Authorization")
            .unwrap()
            .1
            .clone()
        };
        let ses = auth("ses");
        assert!(
            ses.contains("/20260819/us-east-1/ses/aws4_request"),
            "scope names the service: {ses}"
        );
        let signature = |a: &str| a[a.rfind('=').unwrap() + 1..].to_string();
        assert_ne!(
            signature(&ses),
            signature(&auth("s3")),
            "the signing key must be derived from the service too"
        );
    }

    #[test]
    fn refuses_keys_needing_encoding() {
        let sig = SigV4 {
            access_key: "k".into(),
            secret_key: "s".into(),
            session_token: None,
            region: "r".into(),
        };
        assert!(sig
            .sign_at(
                "s3",
                "GET",
                "h",
                "/b/with space",
                &[],
                EMPTY_SHA256,
                ("20260819".into(), "20260819T000000Z".into())
            )
            .is_err());
    }
}
