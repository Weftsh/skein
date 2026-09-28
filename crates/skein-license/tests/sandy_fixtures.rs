//! Keys encoded, validated and signed by sandy's own `key.ts`, recorded by
//! `scripts/record-license-fixtures.mjs`. The Rust verifier's beliefs
//! about the format — no padding, the signature over the segment's ASCII,
//! the fields `weft-license` insists on — are held to what sandy's code
//! actually produced.

use serde_json::Value;
use skein_license::{verify, Mode, Tier, TrustedKeys, VerifyFailure};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/sandy-issued.json")).expect("fixture JSON")
}

fn trusted(f: &Value) -> TrustedKeys {
    TrustedKeys::from_pem([(
        f["kid"].as_str().unwrap(),
        f["public_key_pem"].as_str().unwrap(),
    )])
    .expect("the recorded public key is Ed25519 SPKI")
}

#[test]
fn a_skein_key_from_sandys_encoder_verifies_with_its_terms() {
    let f = fixture();
    let p = verify(f["keys"]["skein_team"].as_str().unwrap(), &trusted(&f)).unwrap();
    assert_eq!(p.lid, "lic_fixture_001");
    assert_eq!(p.entity, "Fixture Corp");
    assert_eq!(p.tier, Tier::Team);
    assert_eq!(p.mode, Mode::Online);
    assert_eq!(p.max_seats, Some(25));
    assert!(!p.trial);

    let p = verify(
        f["keys"]["skein_enterprise_offline_uncapped"]
            .as_str()
            .unwrap(),
        &trusted(&f),
    )
    .unwrap();
    assert_eq!(p.tier, Tier::Enterprise);
    assert_eq!(p.mode, Mode::Offline);
    assert_eq!(p.max_seats, None);
    assert!(p.trial);
}

#[test]
fn a_weft_sandboxes_key_is_refused_by_skein() {
    let f = fixture();
    // sandy's own verifier accepted it when it was recorded: it is a
    // genuine, correctly signed key — for another product.
    assert_eq!(f["sandy_verdicts"]["sandboxes_team"], "ok");
    let err = verify(f["keys"]["sandboxes_team"].as_str().unwrap(), &trusted(&f)).unwrap_err();
    assert_eq!(err.reason, VerifyFailure::InvalidPayload);
    assert!(err.detail.contains("Weft Sandboxes"), "{err}");
}

#[test]
fn a_recorded_key_edited_by_one_character_is_refused() {
    let f = fixture();
    let key = f["keys"]["skein_team"].as_str().unwrap();
    // Flip one character of the payload segment and one of the signature.
    let flip = |key: &str, at: usize| {
        let mut b = key.as_bytes().to_vec();
        b[at] = if b[at] == b'A' { b'B' } else { b'A' };
        String::from_utf8(b).unwrap()
    };
    let payload_at = "weft_lic_v1.".len() + 20;
    let err = verify(&flip(key, payload_at), &trusted(&f)).unwrap_err();
    assert!(
        matches!(
            err.reason,
            VerifyFailure::BadSignature | VerifyFailure::Malformed
        ),
        "{err}"
    );
    let err = verify(&flip(key, key.len() - 10), &trusted(&f)).unwrap_err();
    assert_eq!(err.reason, VerifyFailure::BadSignature, "{err}");
}
