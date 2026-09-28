//! The daily check.
//!
//! An online key sends one small request a day. It is never in the path of
//! an install, a publish or a sign-in: the server runs it on a timer, a
//! failure only becomes a warning after [`crate::status::CHECK_OVERDUE_DAYS`],
//! and the request carries exactly the fields in [`CHECK_FIELDS`] — which
//! licence, which Skein, and the most people who could sign in since the
//! last check. No names, no package, no address, no count of anything else.
//!
//! sandy's check sends a region and peak sandboxes; Skein has neither, and
//! reports seats instead.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every field that leaves the install. The body is built from this list,
/// so a field added to [`CheckRequest`] and not here is not sent.
pub const CHECK_FIELDS: [&str; 3] = ["keyId", "version", "peakSeats"];

pub const DEFAULT_ENDPOINT: &str = "https://license.weft.sh/v1/check";

const MAX_NOTICE_CHARS: usize = 500;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    /// The licence id from the key (`lid`).
    pub key_id: String,
    /// This Skein's version.
    pub version: String,
    /// The most people who could sign in since the last successful check.
    pub peak_seats: u64,
}

impl CheckRequest {
    /// The request body: [`CHECK_FIELDS`] and nothing else.
    pub fn body(&self) -> String {
        let mut body = serde_json::Map::new();
        for field in CHECK_FIELDS {
            let value = match field {
                "keyId" => Value::from(self.key_id.as_str()),
                "version" => Value::from(self.version.as_str()),
                "peakSeats" => Value::from(self.peak_seats),
                _ => unreachable!("every field in CHECK_FIELDS has a value"),
            };
            body.insert(field.to_string(), value);
        }
        Value::Object(body).to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemoteStatus {
    Active,
    Lapsed,
    Revoked,
    Unknown,
}

impl RemoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RemoteStatus::Active => "active",
            RemoteStatus::Lapsed => "lapsed",
            RemoteStatus::Revoked => "revoked",
            RemoteStatus::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<RemoteStatus> {
        [
            RemoteStatus::Active,
            RemoteStatus::Lapsed,
            RemoteStatus::Revoked,
            RemoteStatus::Unknown,
        ]
        .into_iter()
        .find(|r| r.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckResponse {
    pub status: RemoteStatus,
    /// A message from Weft for the admins — a renewal reminder, say.
    pub notice: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    Ok(CheckResponse),
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub endpoint: String,
    /// Per attempt.
    pub timeout: Duration,
    pub attempts: u32,
    /// The wait before attempt `n` (from 1) is `backoff * 2^n`: 2 s, then
    /// 4 s, by default.
    pub backoff: Duration,
}

impl Default for CheckOptions {
    fn default() -> CheckOptions {
        CheckOptions {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            timeout: Duration::from_secs(10),
            attempts: 3,
            backoff: Duration::from_secs(1),
        }
    }
}

/// Reads a check's answer; `None` for anything that is not one.
pub fn parse_response(raw: &Value) -> Option<CheckResponse> {
    let status = RemoteStatus::parse(raw.get("status")?.as_str()?)?;
    let notice = raw
        .get("notice")
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty())
        .map(|n| n.chars().take(MAX_NOTICE_CHARS).collect());
    Some(CheckResponse { status, notice })
}

/// Sends one check, with retries. Never panics and never follows a
/// redirect: the endpoint is the one configured, or no endpoint.
///
/// No proxy is read from the environment. ureq's reading of
/// `HTTPS_PROXY` ignores `NO_PROXY`, so it would send a loopback endpoint
/// through the proxy too; the npm upstream makes direct calls for the same
/// reason. An install that can reach the internet only through a proxy
/// does not complete the check, and that is a warning after seven days,
/// never a refusal.
pub fn send(req: &CheckRequest, opts: &CheckOptions) -> CheckOutcome {
    let agent = skein_tls::agent()
        .redirects(0)
        .timeout(opts.timeout)
        .user_agent(&format!("skein/{}", req.version))
        .build();
    let body = req.body();
    let mut last = "no attempt made".to_string();
    for attempt in 0..opts.attempts.max(1) {
        if attempt > 0 {
            std::thread::sleep(opts.backoff * 2u32.pow(attempt));
        }
        let resp = match agent
            .post(&opts.endpoint)
            .set("content-type", "application/json")
            .send_string(&body)
        {
            Ok(resp) => resp,
            Err(ureq::Error::Status(code, _)) => {
                last = format!("the licence endpoint answered HTTP {code}");
                if (400..500).contains(&code) && code != 429 {
                    break;
                }
                continue;
            }
            Err(e) => {
                last = format!("the licence endpoint could not be reached: {e}");
                continue;
            }
        };
        // A 3xx arrives here with redirects off; it is not an answer.
        if !(200..300).contains(&resp.status()) {
            last = format!(
                "the licence endpoint answered HTTP {} (redirects are not followed)",
                resp.status()
            );
            continue;
        }
        let mut text = String::new();
        use std::io::Read;
        if resp
            .into_reader()
            .take(MAX_RESPONSE_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            last = "the licence endpoint's answer could not be read".into();
            continue;
        }
        match serde_json::from_str::<Value>(&text)
            .ok()
            .as_ref()
            .and_then(parse_response)
        {
            Some(r) => return CheckOutcome::Ok(r),
            None => last = "the licence endpoint returned an unrecognised answer".into(),
        }
    }
    CheckOutcome::Failed(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn req() -> CheckRequest {
        CheckRequest {
            key_id: "lic_test_123".into(),
            version: "0.1.0".into(),
            peak_seats: 12,
        }
    }

    #[test]
    fn the_body_is_exactly_the_documented_fields() {
        let v: Value = serde_json::from_str(&req().body()).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        let mut want = CHECK_FIELDS.to_vec();
        want.sort();
        let mut got = keys.clone();
        got.sort();
        assert_eq!(got, want);
        assert_eq!(v["keyId"], "lic_test_123");
        assert_eq!(v["version"], "0.1.0");
        assert_eq!(v["peakSeats"], 12);
    }

    #[test]
    fn answers_are_read_strictly_and_notices_are_bounded() {
        for (raw, want) in [
            (
                serde_json::json!({"status": "active"}),
                Some(RemoteStatus::Active),
            ),
            (
                serde_json::json!({"status": "revoked", "x": 1}),
                Some(RemoteStatus::Revoked),
            ),
            (serde_json::json!({"status": "fine"}), None),
            (serde_json::json!({"state": "active"}), None),
            (serde_json::json!([1]), None),
        ] {
            assert_eq!(parse_response(&raw).map(|r| r.status), want, "{raw}");
        }
        // A byte slice would panic on the multibyte boundary; chars cannot.
        let long = "é".repeat(600);
        let r = parse_response(&serde_json::json!({"status": "active", "notice": long})).unwrap();
        assert_eq!(r.notice.unwrap().chars().count(), 500);
        let r = parse_response(&serde_json::json!({"status": "active", "notice": ""})).unwrap();
        assert_eq!(r.notice, None);
    }

    /// One recorded request: the head lines and the body.
    #[derive(Debug, Clone)]
    struct Seen {
        head: Vec<String>,
        body: String,
    }

    /// A licence endpoint on loopback that answers each request with the
    /// next of `answers` (status, body), then 500s.
    fn endpoint(answers: Vec<(u16, &'static str)>) -> (String, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/check", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            let mut answers = answers.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut head = Vec::new();
                let mut len = 0;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim_end().to_string();
                    if line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                    head.push(line);
                }
                let mut body = vec![0; len];
                let _ = reader.read_exact(&mut body);
                log.lock().unwrap().push(Seen {
                    head,
                    body: String::from_utf8_lossy(&body).into(),
                });
                let (code, text) = answers.next().unwrap_or((500, "{}"));
                let extra = if (300..400).contains(&code) {
                    "location: http://127.0.0.1:9/elsewhere\r\n"
                } else {
                    ""
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\n{extra}\
                     content-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
            }
        });
        (url, seen)
    }

    fn quick(url: &str) -> CheckOptions {
        CheckOptions {
            endpoint: url.to_string(),
            timeout: Duration::from_secs(5),
            attempts: 3,
            backoff: Duration::ZERO,
        }
    }

    #[test]
    fn a_check_posts_the_fields_and_reads_the_answer() {
        let (url, seen) = endpoint(vec![(200, r#"{"status":"active","notice":"Renew soon"}"#)]);
        let out = send(&req(), &quick(&url));
        assert_eq!(
            out,
            CheckOutcome::Ok(CheckResponse {
                status: RemoteStatus::Active,
                notice: Some("Renew soon".into())
            })
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(
            seen[0].head[0].starts_with("POST /v1/check "),
            "{:?}",
            seen[0].head
        );
        assert!(
            seen[0]
                .head
                .iter()
                .any(|h| h.eq_ignore_ascii_case("user-agent: skein/0.1.0")),
            "{:?}",
            seen[0].head
        );
        assert_eq!(seen[0].body, req().body());
    }

    #[test]
    fn a_server_error_is_retried_and_a_refusal_is_not() {
        let (url, seen) = endpoint(vec![(503, "{}"), (200, r#"{"status":"lapsed"}"#)]);
        assert!(
            matches!(send(&req(), &quick(&url)), CheckOutcome::Ok(r) if r.status == RemoteStatus::Lapsed)
        );
        assert_eq!(seen.lock().unwrap().len(), 2);

        let (url, seen) = endpoint(vec![(429, "{}"), (200, r#"{"status":"active"}"#)]);
        assert!(matches!(send(&req(), &quick(&url)), CheckOutcome::Ok(_)));
        assert_eq!(seen.lock().unwrap().len(), 2, "429 is worth another try");

        let (url, seen) = endpoint(vec![(400, "{}"), (200, r#"{"status":"active"}"#)]);
        let out = send(&req(), &quick(&url));
        assert_eq!(
            out,
            CheckOutcome::Failed("the licence endpoint answered HTTP 400".into())
        );
        assert_eq!(seen.lock().unwrap().len(), 1, "a 400 will be a 400 again");

        let (url, seen) = endpoint(vec![]);
        assert!(matches!(send(&req(), &quick(&url)), CheckOutcome::Failed(e) if e.contains("500")));
        assert_eq!(
            seen.lock().unwrap().len(),
            3,
            "three attempts, then give up"
        );
    }

    #[test]
    fn a_redirect_is_not_followed() {
        let (url, seen) = endpoint(vec![(302, ""), (302, ""), (302, "")]);
        let out = send(&req(), &quick(&url));
        assert!(
            matches!(&out, CheckOutcome::Failed(e) if e.contains("302")),
            "{out:?}"
        );
        // Every attempt came here; none went to the Location.
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[test]
    fn an_unrecognised_answer_or_no_endpoint_is_a_failure_not_a_panic() {
        let (url, _) = endpoint(vec![
            (200, "<html>"),
            (200, r#"{"status":"ok"}"#),
            (200, ""),
        ]);
        let out = send(&req(), &quick(&url));
        assert_eq!(
            out,
            CheckOutcome::Failed("the licence endpoint returned an unrecognised answer".into())
        );
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", closed.local_addr().unwrap());
        drop(closed);
        let out = send(&req(), &quick(&url));
        assert!(
            matches!(&out, CheckOutcome::Failed(e) if e.contains("could not be reached")),
            "{out:?}"
        );
    }
}
