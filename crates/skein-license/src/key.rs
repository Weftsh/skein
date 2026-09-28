//! The key, and verifying it offline.
//!
//! A key is `weft_lic_v1.<payload>.<signature>`: `payload` is base64url
//! (no padding) JSON, and `signature` is the base64url Ed25519 signature
//! over the payload segment **exactly as it appears in the key** — its
//! ASCII, not the decoded JSON, so re-serialising cannot change what was
//! signed. Weft signs with an Ed25519 key in AWS KMS; a release carries the
//! public halves in [`crate::trusted::RELEASE_SIGNING_KEYS`]. Verifying
//! never makes a network call.
//!
//! This is sandy's `packages/license/src/key.ts`, and a key minted by its
//! `weft-license issue` verifies here byte for byte — the recorded keys in
//! `fixtures/` hold that. Two fields make a key a *Skein* key:
//!
//! - `"product": "skein"`. A key without it was issued for Weft Sandboxes
//!   and is refused, so one product's key cannot pass as another's.
//! - `"maxSeats"`: how many people may be able to sign in, or `null` for
//!   no cap.
//!
//! `weft-license` also requires `accounts` and `maxConcurrent` (sandy's
//! AWS accounts and sandbox cap), so a real Skein key carries them. Skein
//! runs on no particular AWS account and has no sandboxes; it tolerates
//! both and reads neither.

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use serde_json::Value;

use crate::time::parse_iso8601;

pub const KEY_PREFIX: &str = "weft_lic_v1";
/// The `product` a Skein key names.
pub const PRODUCT: &str = "skein";
const MAX_KEY_LENGTH: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Community,
    Team,
    Business,
    Enterprise,
}

impl Tier {
    pub const ALL: [Tier; 4] = [
        Tier::Community,
        Tier::Team,
        Tier::Business,
        Tier::Enterprise,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Community => "community",
            Tier::Team => "team",
            Tier::Business => "business",
            Tier::Enterprise => "enterprise",
        }
    }

    fn parse(s: &str) -> Option<Tier> {
        Tier::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// How an install reports to Weft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A daily check carrying three fields. Community, Team and Business.
    Online,
    /// No outbound calls at all; an annual true-up from the monthly peaks.
    /// Enterprise only.
    Offline,
}

/// A verified Skein key's terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Payload {
    /// The signing key that signed it.
    pub kid: String,
    /// The licence's id — what the daily check reports as `keyId`.
    pub lid: String,
    /// Who it is issued to.
    pub entity: String,
    pub tier: Tier,
    pub mode: Mode,
    /// Issued and expires, ISO 8601 as written in the key.
    pub iat: String,
    pub exp: String,
    /// People who may be able to sign in; `None` is no cap.
    pub max_seats: Option<u64>,
    /// A trial key.
    pub trial: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyFailure {
    /// Not shaped like a key at all.
    Malformed,
    /// Signed by a key this release does not trust.
    UnknownSigningKey,
    /// The signature does not match — a forged or edited payload.
    BadSignature,
    /// Signed, but the terms are not a Skein key's.
    InvalidPayload,
}

impl VerifyFailure {
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyFailure::Malformed => "malformed",
            VerifyFailure::UnknownSigningKey => "unknown_signing_key",
            VerifyFailure::BadSignature => "bad_signature",
            VerifyFailure::InvalidPayload => "invalid_payload",
        }
    }
}

/// Why a key was refused: the kind, and a sentence for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    pub reason: VerifyFailure,
    pub detail: String,
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.reason.as_str())
    }
}

fn reject(reason: VerifyFailure, detail: impl Into<String>) -> Rejected {
    Rejected {
        reason,
        detail: detail.into(),
    }
}

/// Public keys trusted to sign licences, by `kid`.
#[derive(Debug, Clone, Default)]
pub struct TrustedKeys {
    keys: BTreeMap<String, VerifyingKey>,
}

impl TrustedKeys {
    /// From PEM-encoded SPKI Ed25519 public keys. Anything else — an RSA
    /// key, a certificate, a typo — is an error naming the `kid`, never a
    /// key that silently verifies nothing.
    pub fn from_pem<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<TrustedKeys, String> {
        let mut keys = BTreeMap::new();
        for (kid, pem) in entries {
            let key = VerifyingKey::from_public_key_pem(pem.trim()).map_err(|e| {
                format!("licence signing key {kid} is not an Ed25519 public key: {e}")
            })?;
            keys.insert(kid.to_string(), key);
        }
        Ok(TrustedKeys { keys })
    }

    /// The keys compiled into this release.
    pub fn release() -> Result<TrustedKeys, String> {
        TrustedKeys::from_pem(crate::trusted::RELEASE_SIGNING_KEYS.iter().copied())
    }

    /// These keys and `more` (a development install's own keys).
    pub fn with(mut self, more: TrustedKeys) -> TrustedKeys {
        self.keys.extend(more.keys);
        self
    }

    pub fn ids(&self) -> Vec<String> {
        self.keys.keys().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn is_base64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Verifies a key's signature and terms. Expiry is not a refusal here —
/// an expired key is still *this customer's* key; [`crate::evaluate`]
/// decides what its dates mean.
///
/// The order is sandy's and it matters: the `kid` is read from the
/// unverified payload only to choose a public key, and **nothing else in
/// the payload is looked at until the signature holds** — not even to word
/// an error, because an unsigned payload is whatever anybody typed.
pub fn verify(key: &str, trusted: &TrustedKeys) -> Result<Payload, Rejected> {
    use VerifyFailure::*;
    let key = key.trim();
    if key.len() > MAX_KEY_LENGTH {
        return Err(reject(Malformed, "key is too long"));
    }
    let parts: Vec<&str> = key.split('.').collect();
    let [prefix, payload_part, sig_part] = parts[..] else {
        return Err(reject(
            Malformed,
            format!("key must look like {KEY_PREFIX}.<payload>.<signature>"),
        ));
    };
    if prefix != KEY_PREFIX {
        return Err(reject(
            Malformed,
            format!("key must look like {KEY_PREFIX}.<payload>.<signature>"),
        ));
    }
    let decode = |s: &str| {
        is_base64url(s)
            .then(|| URL_SAFE_NO_PAD.decode(s).ok())
            .flatten()
    };
    let (Some(payload_bytes), Some(signature)) = (decode(payload_part), decode(sig_part)) else {
        return Err(reject(Malformed, "key segments must be base64url"));
    };
    let Ok(raw) = serde_json::from_slice::<Value>(&payload_bytes) else {
        return Err(reject(Malformed, "payload is not JSON"));
    };
    let Some(kid) = raw.get("kid").and_then(Value::as_str) else {
        return Err(reject(Malformed, "payload has no kid"));
    };
    let Some(public) = trusted.keys.get(kid) else {
        return Err(reject(
            UnknownSigningKey,
            format!("no trusted signing key with id {kid}"),
        ));
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature.as_slice()) else {
        return Err(reject(BadSignature, "signature does not match"));
    };
    if public
        .verify_strict(payload_part.as_bytes(), &Signature::from_bytes(&signature))
        .is_err()
    {
        return Err(reject(BadSignature, "signature does not match"));
    }
    validate_payload(&raw).map_err(|detail| reject(InvalidPayload, detail))
}

fn positive_integer(v: &Value) -> Option<u64> {
    // JSON has one number type, and `weft-license` is JavaScript: `5` and
    // `5.0` are the same number there, so both are accepted here.
    let f = v.as_f64()?;
    (f.fract() == 0.0 && (1.0..=9_007_199_254_740_991.0).contains(&f)).then_some(f as u64)
}

/// The terms of a signed payload, or the first thing wrong with them.
pub fn validate_payload(raw: &Value) -> Result<Payload, String> {
    let Some(p) = raw.as_object() else {
        return Err("payload must be an object".into());
    };
    if p.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Err("unsupported payload version".into());
    }
    let text = |field: &str| -> Result<String, String> {
        match p.get(field).and_then(Value::as_str) {
            Some(s) if !s.is_empty() => Ok(s.to_string()),
            _ => Err(format!("{field} must be a non-empty string")),
        }
    };
    let (kid, lid, entity, iat, exp) = (
        text("kid")?,
        text("lid")?,
        text("entity")?,
        text("iat")?,
        text("exp")?,
    );
    let Some(tier) = p.get("tier").and_then(Value::as_str).and_then(Tier::parse) else {
        return Err(format!(
            "tier must be one of {}",
            Tier::ALL.map(Tier::as_str).join(", ")
        ));
    };
    let mode = match p.get("mode").and_then(Value::as_str) {
        Some("online") => Mode::Online,
        Some("offline") => Mode::Offline,
        _ => return Err("mode must be online or offline".into()),
    };
    if mode == Mode::Offline && tier != Tier::Enterprise {
        return Err("offline keys are issued for the enterprise tier only".into());
    }
    match p.get("product").and_then(Value::as_str) {
        Some(PRODUCT) => {}
        Some(other) => {
            return Err(format!(
                "this key was issued for {other}, not Skein; ask Weft for a Skein key"
            ))
        }
        None => {
            return Err(
                "this key names no product, so it was issued for Weft Sandboxes, not Skein; \
                 ask Weft for a Skein key"
                    .into(),
            )
        }
    }
    let max_seats = match p.get("maxSeats") {
        Some(Value::Null) => None,
        Some(v) => match positive_integer(v) {
            Some(n) => Some(n),
            None => return Err("maxSeats must be a positive integer or null".into()),
        },
        None => return Err("maxSeats must be a positive integer or null".into()),
    };
    let (Some(issued), Some(expires)) = (parse_iso8601(&iat), parse_iso8601(&exp)) else {
        return Err("iat and exp must be ISO 8601 timestamps".into());
    };
    if expires <= issued {
        return Err("exp must be after iat".into());
    }
    let trial = match p.get("trial") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("trial must be a boolean".into()),
    };
    Ok(Payload {
        kid,
        lid,
        entity,
        tier,
        mode,
        iat,
        exp,
        max_seats,
        trial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue::{self, Signer};
    use serde_json::json;

    fn signer() -> Signer {
        Signer::from_seed("test-1", [7; 32])
    }

    fn trusted() -> TrustedKeys {
        signer().trusted()
    }

    #[test]
    fn a_signed_key_round_trips_to_its_terms() {
        let key = signer().issue(&issue::payload()).unwrap();
        assert!(key.starts_with("weft_lic_v1."));
        let p = verify(&key, &trusted()).unwrap();
        assert_eq!(p.lid, "lic_test_123");
        assert_eq!(p.entity, "Example Corp");
        assert_eq!(p.tier, Tier::Team);
        assert_eq!(p.mode, Mode::Online);
        assert_eq!(p.max_seats, Some(25));
        assert!(!p.trial);
        // Surrounding whitespace from a paste is not part of the key.
        assert_eq!(verify(&format!("  {key}\n"), &trusted()).unwrap(), p);
    }

    #[test]
    fn an_edited_payload_is_a_bad_signature() {
        let key = signer().issue(&issue::payload()).unwrap();
        let sig = key.rsplit('.').next().unwrap();
        let mut forged = issue::payload();
        forged["tier"] = json!("enterprise");
        forged["maxSeats"] = Value::Null;
        let part = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        let err = verify(&format!("{KEY_PREFIX}.{part}.{sig}"), &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::BadSignature);
    }

    #[test]
    fn the_signature_covers_the_segment_not_the_json() {
        // The same JSON, re-encoded with different whitespace, is a
        // different segment — and the signature must not follow it there.
        let key = signer().issue(&issue::payload()).unwrap();
        let parts: Vec<&str> = key.split('.').collect();
        let json = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let mut spaced = json.clone();
        spaced.push(b' ');
        let part = URL_SAFE_NO_PAD.encode(spaced);
        let err = verify(&format!("{KEY_PREFIX}.{part}.{}", parts[2]), &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::BadSignature);
    }

    #[test]
    fn an_untrusted_signer_or_an_unknown_kid_is_refused() {
        let stranger = Signer::from_seed("test-1", [9; 32]);
        let key = stranger.issue(&issue::payload()).unwrap();
        assert_eq!(
            verify(&key, &trusted()).unwrap_err().reason,
            VerifyFailure::BadSignature
        );
        let mut p = issue::payload();
        p["kid"] = json!("nope");
        let key = Signer::from_seed("nope", [7; 32]).issue(&p).unwrap();
        let err = verify(&key, &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::UnknownSigningKey);
        assert!(err.detail.contains("nope"), "{err}");
        // A release with no keys trusts nothing.
        assert_eq!(
            verify(
                &signer().issue(&issue::payload()).unwrap(),
                &TrustedKeys::default()
            )
            .unwrap_err()
            .reason,
            VerifyFailure::UnknownSigningKey
        );
    }

    #[test]
    fn malformed_keys_are_refused_without_panicking() {
        let long = "x".repeat(10_000);
        for bad in [
            "",
            "abc",
            "weft_lic_v1..",
            "weft_lic_v1.a.b.c",
            "other.eyJ9.AA",
            "weft_lic_v1.@@.@@",
            "weft_lic_v1.eyJ9=.AA",
            "weft_lic_v1.bm90IGpzb24.AA",
            "weft_lic_v1.e30.AA",
            long.as_str(),
        ] {
            let err = verify(bad, &trusted()).unwrap_err();
            assert_eq!(err.reason, VerifyFailure::Malformed, "{bad:.40}: {err}");
        }
    }

    #[test]
    fn a_short_signature_is_a_bad_signature_not_a_panic() {
        let key = signer().issue(&issue::payload()).unwrap();
        let (head, _) = key.rsplit_once('.').unwrap();
        let err = verify(&format!("{head}.AAAA"), &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::BadSignature);
    }

    /// The class: a key for another Weft product. A sandy key names no
    /// product at all, and with `maxConcurrent: null` and no seat cap it
    /// would otherwise read as an unlimited Skein licence.
    #[test]
    fn a_key_for_another_product_is_refused_with_a_sentence() {
        let mut sandy = issue::payload();
        sandy.as_object_mut().unwrap().remove("product");
        sandy.as_object_mut().unwrap().remove("maxSeats");
        let err = verify(&signer().sign_unchecked(&sandy), &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::InvalidPayload);
        assert!(err.detail.contains("Weft Sandboxes"), "{err}");

        let mut other = issue::payload();
        other["product"] = json!("spool");
        let err = verify(&signer().sign_unchecked(&other), &trusted()).unwrap_err();
        assert_eq!(err.reason, VerifyFailure::InvalidPayload);
        assert!(err.detail.contains("spool"), "{err}");
    }

    #[test]
    fn the_terms_are_checked_after_the_signature() {
        let cases: Vec<(&str, Value, &str)> = vec![
            ("v", json!(2), "version"),
            ("lid", json!(""), "lid"),
            ("entity", json!(7), "entity"),
            ("tier", json!("platinum"), "tier"),
            ("mode", json!("sometimes"), "mode"),
            ("mode", json!("offline"), "enterprise"),
            ("maxSeats", json!(0), "maxSeats"),
            ("maxSeats", json!(2.5), "maxSeats"),
            ("maxSeats", json!("10"), "maxSeats"),
            ("iat", json!("yesterday"), "ISO 8601"),
            ("exp", json!("2020-01-01T00:00:00Z"), "after iat"),
            ("trial", json!("yes"), "trial"),
        ];
        for (field, value, needle) in cases {
            let mut p = issue::payload();
            p[field] = value.clone();
            let err = verify(&signer().sign_unchecked(&p), &trusted()).unwrap_err();
            assert_eq!(err.reason, VerifyFailure::InvalidPayload, "{field}={value}");
            assert!(err.detail.contains(needle), "{field}={value}: {err}");
            // The issuer refuses the same payload before signing it.
            assert!(signer().issue(&p).is_err(), "{field}={value} issued");
        }
        let mut missing = issue::payload();
        missing.as_object_mut().unwrap().remove("maxSeats");
        let err = verify(&signer().sign_unchecked(&missing), &trusted()).unwrap_err();
        assert!(err.detail.contains("maxSeats"), "{err}");
    }

    #[test]
    fn the_terms_sandy_requires_and_skein_ignores_are_tolerated() {
        // `accounts` and `maxConcurrent` are required by `weft-license`, so
        // every real key has them; an offline enterprise key with no cap
        // and a whole number written as a float are ordinary keys too.
        let mut p = issue::payload();
        p["accounts"] = json!(["111122223333"]);
        p["maxConcurrent"] = json!(50);
        p["tier"] = json!("enterprise");
        p["mode"] = json!("offline");
        p["maxSeats"] = json!(40.0);
        p["trial"] = json!(true);
        let got = verify(&signer().issue(&p).unwrap(), &trusted()).unwrap();
        assert_eq!(got.mode, Mode::Offline);
        assert_eq!(got.max_seats, Some(40));
        assert!(got.trial);
        p["maxSeats"] = Value::Null;
        let got = verify(&signer().issue(&p).unwrap(), &trusted()).unwrap();
        assert_eq!(got.max_seats, None);
    }

    #[test]
    fn only_ed25519_public_keys_are_trusted() {
        // An RSA SPKI key: a real PEM, the wrong algorithm.
        let rsa = "-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDi9i02C/atJUzG/wu7wucvoBoU
EIE0lJpTQHYtchp6aX3RgT6H5E02TrZJ24zGDXGMJgLTxgVbI1XdnHHRU2hJhZmE
3IHPpGuDtGV+nYdBK1xMeQjbODwUBScxS3JrZm957I1gPs3JE+DJa8/Pz2Zy96Sz
ztXuWoXAjKUfP6yNMQIDAQAB
-----END PUBLIC KEY-----
";
        let err = TrustedKeys::from_pem([("rsa", rsa)]).unwrap_err();
        assert!(err.contains("rsa") && err.contains("Ed25519"), "{err}");
        assert!(TrustedKeys::from_pem([("junk", "not a key")]).is_err());
        let ok = TrustedKeys::from_pem([("test-1", signer().public_pem().as_str())]).unwrap();
        assert_eq!(ok.ids(), vec!["test-1".to_string()]);
    }
}
