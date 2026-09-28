//! Issuing keys, for tests and development installs only.
//!
//! Production keys come from Weft's billing automation through sandy's
//! `weft-license issue`, signed in AWS KMS; nothing a customer runs can
//! sign. This signer produces the same bytes from a local seed, so a test
//! key is shaped exactly like a real one — `accounts` and `maxConcurrent`
//! included, because `weft-license` requires both.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Value};

use crate::key::{validate_payload, TrustedKeys, KEY_PREFIX};

/// A signing key with its `kid`.
pub struct Signer {
    kid: String,
    key: SigningKey,
}

impl Signer {
    /// A deterministic key: the same seed is the same key in every run.
    pub fn from_seed(kid: &str, seed: [u8; 32]) -> Signer {
        Signer {
            kid: kid.to_string(),
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The public half as SPKI PEM — what `RELEASE_SIGNING_KEYS` holds and
    /// what `SKEIN_DEV_LICENSE_PUBLIC_KEYS` takes.
    pub fn public_pem(&self) -> String {
        self.key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("an Ed25519 public key encodes")
    }

    /// Trusting only this key.
    pub fn trusted(&self) -> TrustedKeys {
        TrustedKeys::from_pem([(self.kid.as_str(), self.public_pem().as_str())])
            .expect("our own key parses")
    }

    /// Signs `payload` after checking it is a valid Skein key's terms, as
    /// `weft-license issue` refuses an invalid payload.
    pub fn issue(&self, payload: &Value) -> Result<String, String> {
        validate_payload(payload).map_err(|e| format!("invalid license payload: {e}"))?;
        Ok(self.sign_unchecked(payload))
    }

    /// Signs anything, valid or not — how a test makes a key whose
    /// signature holds and whose terms do not.
    pub fn sign_unchecked(&self, payload: &Value) -> String {
        let part = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("JSON"));
        let sig = self.key.sign(part.as_bytes());
        format!(
            "{KEY_PREFIX}.{part}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }
}

/// A valid Team key's terms for 25 seats, signed by `test-1`, in the shape
/// `weft-license` mints. Tests edit the field they are about.
pub fn payload() -> Value {
    json!({
        "v": 1,
        "kid": "test-1",
        "lid": "lic_test_123",
        "entity": "Example Corp",
        "tier": "team",
        "accounts": [],
        "maxConcurrent": null,
        "mode": "online",
        "iat": "2026-10-01T00:00:00.000Z",
        "exp": "2027-10-01T00:00:00.000Z",
        "product": "skein",
        "maxSeats": 25,
    })
}
