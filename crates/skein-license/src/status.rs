//! What the licence means today.
//!
//! There is deliberately no "allowed" answer here. Every outcome is a
//! state and a list of sentences for the admin's banner, the API and the
//! log; none of them is consulted by anything that serves a package, signs
//! somebody in or creates a person.

use serde::Serialize;

use crate::check::RemoteStatus;
use crate::key::{Mode, Payload, Rejected, Tier};
use crate::time::format_iso8601;

/// Days before expiry at which Skein starts warning.
pub const EXPIRY_WARNING_DAYS: i64 = 30;
/// Days after expiry at which Weft stops sharing new releases.
pub const RELEASE_GRACE_DAYS: i64 = 30;
/// Days without a successful online check before Skein warns.
pub const CHECK_OVERDUE_DAYS: i64 = 7;

const DAY_MS: i64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseState {
    /// No key configured.
    Unlicensed,
    /// A key is configured and does not verify.
    Invalid,
    Active,
    /// Active, and expires within [`EXPIRY_WARNING_DAYS`].
    Expiring,
    /// Past its expiry. Skein serves exactly as before.
    Lapsed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LicenseStatus {
    pub state: LicenseState,
    pub tier: Option<Tier>,
    pub license_id: Option<String>,
    pub entity: Option<String>,
    pub mode: Option<Mode>,
    pub expires_at: Option<String>,
    pub trial: bool,
    /// The licence's seat cap; `None` with a key is no cap.
    pub max_seats: Option<u64>,
    /// People who can sign in right now.
    pub seats: u64,
    /// More people can sign in than the licence covers. Nobody is refused.
    pub over_cap: bool,
    /// Whether this install should still receive new signed releases and
    /// security patches. Informational: Weft enforces it by what it
    /// shares, not by anything in Skein.
    pub release_access: bool,
    /// Online keys only: no successful daily check for
    /// [`CHECK_OVERDUE_DAYS`].
    pub check_overdue: bool,
    /// Plain sentences for the banner, the API and the log.
    pub warnings: Vec<String>,
}

pub struct EvaluateInput<'a> {
    pub now_ms: i64,
    /// The verified key, or why it did not verify; `None` with no key.
    pub key: Option<&'a Result<Payload, Rejected>>,
    /// People who can sign in.
    pub seats: u64,
    /// When the install started keeping licence state, so day one is not
    /// "overdue".
    pub installed_at_ms: Option<i64>,
    pub last_check_at_ms: Option<i64>,
    pub last_check_status: Option<RemoteStatus>,
}

pub fn evaluate(input: &EvaluateInput) -> LicenseStatus {
    let mut s = LicenseStatus {
        state: LicenseState::Unlicensed,
        tier: None,
        license_id: None,
        entity: None,
        mode: None,
        expires_at: None,
        trial: false,
        max_seats: None,
        seats: input.seats,
        over_cap: false,
        release_access: false,
        check_overdue: false,
        warnings: Vec::new(),
    };
    let lic = match input.key {
        None => {
            s.warnings.push(
                "No licence key is configured. Skein serves normally; add a key to receive \
                 signed updates."
                    .into(),
            );
            return s;
        }
        Some(Err(rejected)) => {
            s.state = LicenseState::Invalid;
            s.warnings.push(format!(
                "The licence key could not be verified ({}): {}. Skein serves normally.",
                rejected.reason.as_str(),
                rejected.detail
            ));
            return s;
        }
        Some(Ok(lic)) => lic,
    };
    s.tier = Some(lic.tier);
    s.license_id = Some(lic.lid.clone());
    s.entity = Some(lic.entity.clone());
    s.mode = Some(lic.mode);
    s.expires_at = Some(lic.exp.clone());
    s.trial = lic.trial;
    s.max_seats = lic.max_seats;

    apply_expiry(&mut s, lic, input.now_ms);

    if let Some(cap) = lic.max_seats {
        if input.seats > cap {
            s.over_cap = true;
            s.warnings.push(format!(
                "{} people can sign in; the {} licence covers {cap}. Nobody is refused. Two \
                 consecutive months over the cap lead to a notice to reduce seats or change tier.",
                input.seats,
                lic.tier.as_str()
            ));
        }
    }

    if lic.mode == Mode::Online {
        let reference = input.last_check_at_ms.or(input.installed_at_ms);
        if reference.is_some_and(|r| input.now_ms - r > CHECK_OVERDUE_DAYS * DAY_MS) {
            s.check_overdue = true;
            s.warnings.push(format!(
                "The daily licence check has not succeeded for more than {CHECK_OVERDUE_DAYS} \
                 days. Skein is unaffected; check outbound HTTPS access to the licence endpoint."
            ));
        }
        if input.last_check_status == Some(RemoteStatus::Revoked) {
            s.release_access = false;
            s.warnings
                .push("Weft reports this licence as revoked. Skein serves normally.".into());
        }
    }
    s
}

fn apply_expiry(s: &mut LicenseStatus, lic: &Payload, now_ms: i64) {
    // `verify` has already proved `exp` parses.
    let exp = crate::time::parse_iso8601(&lic.exp).unwrap_or(i64::MIN);
    let ms_left = exp - now_ms;
    if ms_left <= 0 {
        let days_lapsed = -ms_left / DAY_MS;
        s.state = LicenseState::Lapsed;
        s.release_access = days_lapsed < RELEASE_GRACE_DAYS;
        s.warnings.push(if s.release_access {
            format!(
                "The licence expired {days_lapsed} day(s) ago. Skein serves normally. New \
                 releases and security patches stop {} day(s) from now unless it is renewed.",
                RELEASE_GRACE_DAYS - days_lapsed
            )
        } else {
            "The licence has lapsed. Skein serves normally, but this install no longer receives \
             new releases or security patches."
                .into()
        });
        return;
    }
    s.release_access = true;
    let days_left = (ms_left + DAY_MS - 1) / DAY_MS;
    if days_left <= EXPIRY_WARNING_DAYS {
        s.state = LicenseState::Expiring;
        s.warnings.push(format!(
            "The licence expires in {days_left} day(s), on {}.",
            &format_iso8601(exp)[..10]
        ));
    } else {
        s.state = LicenseState::Active;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issue::{self, Signer};
    use crate::key::verify;
    use crate::time::parse_iso8601;
    use serde_json::json;

    fn key_with(edit: impl FnOnce(&mut serde_json::Value)) -> Result<Payload, Rejected> {
        let signer = Signer::from_seed("test-1", [7; 32]);
        let mut p = issue::payload();
        edit(&mut p);
        verify(&signer.sign_unchecked(&p), &signer.trusted())
    }

    fn at(s: &str) -> i64 {
        parse_iso8601(s).unwrap()
    }

    fn input<'a>(key: Option<&'a Result<Payload, Rejected>>, now: &str) -> EvaluateInput<'a> {
        EvaluateInput {
            now_ms: at(now),
            key,
            seats: 3,
            installed_at_ms: Some(at(now)),
            last_check_at_ms: None,
            last_check_status: None,
        }
    }

    #[test]
    fn no_key_is_unlicensed_and_says_skein_serves() {
        let s = evaluate(&input(None, "2026-11-01"));
        assert_eq!(s.state, LicenseState::Unlicensed);
        assert!(!s.release_access);
        assert_eq!(s.seats, 3);
        assert!(
            s.warnings[0].contains("serves normally"),
            "{:?}",
            s.warnings
        );
    }

    #[test]
    fn an_invalid_key_says_why() {
        let bad = key_with(|p| {
            p.as_object_mut().unwrap().remove("product");
        });
        let s = evaluate(&input(Some(&bad), "2026-11-01"));
        assert_eq!(s.state, LicenseState::Invalid);
        assert!(
            s.warnings[0].contains("invalid_payload"),
            "{:?}",
            s.warnings
        );
        assert!(s.warnings[0].contains("Weft Sandboxes"), "{:?}", s.warnings);
    }

    #[test]
    fn an_active_key_reports_its_terms_and_no_warnings() {
        let k = key_with(|_| {});
        let s = evaluate(&input(Some(&k), "2026-11-01"));
        assert_eq!(s.state, LicenseState::Active);
        assert_eq!(s.tier, Some(Tier::Team));
        assert_eq!(s.license_id.as_deref(), Some("lic_test_123"));
        assert_eq!(s.max_seats, Some(25));
        assert!(s.release_access);
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    }

    #[test]
    fn expiry_warns_then_lapses_then_loses_release_access() {
        let k = key_with(|_| {});
        let s = evaluate(&input(Some(&k), "2027-09-15T00:00:00Z"));
        assert_eq!(s.state, LicenseState::Expiring);
        assert!(s.warnings[0].contains("16 day(s)"), "{:?}", s.warnings);
        assert!(s.warnings[0].contains("2027-10-01"), "{:?}", s.warnings);

        let s = evaluate(&input(Some(&k), "2027-10-11T00:00:00Z"));
        assert_eq!(s.state, LicenseState::Lapsed);
        assert!(s.release_access);
        assert!(s.warnings[0].contains("10 day(s) ago"), "{:?}", s.warnings);
        assert!(
            s.warnings[0].contains("20 day(s) from now"),
            "{:?}",
            s.warnings
        );

        let s = evaluate(&input(Some(&k), "2027-11-15T00:00:00Z"));
        assert_eq!(s.state, LicenseState::Lapsed);
        assert!(!s.release_access);
        assert!(
            s.warnings[0].contains("no longer receives"),
            "{:?}",
            s.warnings
        );
    }

    #[test]
    fn more_people_than_seats_is_a_warning_and_nothing_else() {
        let k = key_with(|p| p["maxSeats"] = json!(2));
        let s = evaluate(&input(Some(&k), "2026-11-01"));
        assert_eq!(s.state, LicenseState::Active);
        assert!(s.over_cap);
        assert!(s.release_access);
        assert!(
            s.warnings[0].starts_with("3 people can sign in"),
            "{:?}",
            s.warnings
        );
        assert!(
            s.warnings[0].contains("Nobody is refused"),
            "{:?}",
            s.warnings
        );
        // Exactly at the cap is within it; no cap is never over it.
        let k = key_with(|p| p["maxSeats"] = json!(3));
        assert!(!evaluate(&input(Some(&k), "2026-11-01")).over_cap);
        let k = key_with(|p| p["maxSeats"] = serde_json::Value::Null);
        let mut i = input(Some(&k), "2026-11-01");
        i.seats = 10_000;
        assert!(!evaluate(&i).over_cap);
    }

    #[test]
    fn an_overdue_check_warns_from_install_or_the_last_success() {
        let k = key_with(|_| {});
        let mut i = input(Some(&k), "2026-11-20");
        i.installed_at_ms = Some(at("2026-11-12"));
        assert!(evaluate(&i).check_overdue, "8 days since install");
        i.last_check_at_ms = Some(at("2026-11-19"));
        assert!(!evaluate(&i).check_overdue, "checked yesterday");
        i.last_check_at_ms = Some(at("2026-11-12"));
        let s = evaluate(&i);
        assert!(s.check_overdue);
        assert!(
            s.warnings.iter().any(|w| w.contains("7 days")),
            "{:?}",
            s.warnings
        );
    }

    #[test]
    fn an_offline_key_is_never_overdue_and_ignores_remote_status() {
        let k = key_with(|p| {
            p["tier"] = json!("enterprise");
            p["mode"] = json!("offline");
        });
        let mut i = input(Some(&k), "2026-11-20");
        i.installed_at_ms = Some(at("2026-10-01"));
        i.last_check_status = Some(RemoteStatus::Revoked);
        let s = evaluate(&i);
        assert!(!s.check_overdue);
        assert!(s.release_access);
        assert!(s.warnings.is_empty(), "{:?}", s.warnings);
    }

    #[test]
    fn revoked_removes_release_access_and_says_skein_serves() {
        let k = key_with(|_| {});
        let mut i = input(Some(&k), "2026-11-01");
        i.last_check_at_ms = Some(at("2026-11-01"));
        i.last_check_status = Some(RemoteStatus::Revoked);
        let s = evaluate(&i);
        assert_eq!(s.state, LicenseState::Active);
        assert!(!s.release_access);
        assert!(s.warnings[0].contains("revoked"), "{:?}", s.warnings);
    }

    #[test]
    fn the_status_serialises_in_the_apis_words() {
        let k = key_with(|_| {});
        let v = serde_json::to_value(evaluate(&input(Some(&k), "2026-11-01"))).unwrap();
        assert_eq!(v["state"], "active");
        assert_eq!(v["tier"], "team");
        assert_eq!(v["mode"], "online");
        assert_eq!(v["max_seats"], 25);
        assert_eq!(v["release_access"], true);
    }
}
