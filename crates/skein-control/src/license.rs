//! The licence's state in the database: the key in force, what the daily
//! check last heard, and the seat peaks the check and the true-up report.
//!
//! Nothing here decides anything. `skein_license::evaluate` turns these
//! facts into warnings; nothing that serves a package reads them.

use crate::db::{detail, ControlDb};

/// The one `license` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseRow {
    pub key: Option<String>,
    pub configured_key: Option<String>,
    pub installed_at: i64,
    pub last_check_at: Option<i64>,
    pub last_check_status: Option<String>,
    pub notice: Option<String>,
    pub last_check_error: Option<String>,
    pub check_claimed_at: Option<i64>,
    pub peak_since_check: i64,
}

pub fn get(db: &ControlDb) -> Result<LicenseRow, String> {
    let r = db
        .lock()
        .query_one(
            "SELECT key, configured_key, installed_at, last_check_at, last_check_status, \
                    notice, last_check_error, check_claimed_at, peak_since_check \
             FROM license",
            &[],
        )
        .map_err(|e| format!("read licence: {}", detail(&e)))?;
    Ok(LicenseRow {
        key: r.get(0),
        configured_key: r.get(1),
        installed_at: r.get(2),
        last_check_at: r.get(3),
        last_check_status: r.get(4),
        notice: r.get(5),
        last_check_error: r.get(6),
        check_claimed_at: r.get(7),
        peak_since_check: r.get(8),
    })
}

/// Applies `SKEIN_LICENSE_KEY` at boot — only when it differs from the one
/// last applied, so a key an admin installed through the API is not
/// overwritten by the same stale variable on every restart. `true` when
/// it replaced the key in force.
pub fn apply_configured(db: &ControlDb, configured: &str) -> Result<bool, String> {
    let n = db
        .lock()
        .execute(
            "UPDATE license SET key = $1, configured_key = $1, last_check_at = NULL, \
                    last_check_status = NULL, notice = NULL, last_check_error = NULL, \
                    check_claimed_at = NULL \
             WHERE configured_key IS DISTINCT FROM $1",
            &[&configured],
        )
        .map_err(|e| format!("apply the configured licence key: {}", detail(&e)))?;
    Ok(n == 1)
}

/// Installs a key an admin supplied. What the old key's check heard is
/// cleared with it, and so is the claim, so the new key is checked at the
/// next opportunity rather than tomorrow.
pub fn install(db: &ControlDb, key: &str) -> Result<(), String> {
    db.lock()
        .execute(
            "UPDATE license SET key = $1, last_check_at = NULL, last_check_status = NULL, \
                    notice = NULL, last_check_error = NULL, check_claimed_at = NULL",
            &[&key],
        )
        .map(|_| ())
        .map_err(|e| format!("install the licence key: {}", detail(&e)))
}

/// Records how many seats there are now: raises the peak since the last
/// check and this month's peak, and keeps the last thirteen months. Every
/// replica samples; a peak is a maximum, so more samplers only make it
/// more exact.
pub fn record_seats(db: &ControlDb, seats: i64, month: &str) -> Result<(), String> {
    db.lock()
        .transaction(|tx| {
            tx.execute(
                "UPDATE license SET peak_since_check = GREATEST(peak_since_check, $1)",
                &[&seats],
            )?;
            tx.execute(
                "INSERT INTO license_monthly_peaks (month, peak) VALUES ($1, $2) \
                 ON CONFLICT (month) DO UPDATE \
                 SET peak = GREATEST(license_monthly_peaks.peak, EXCLUDED.peak)",
                &[&month, &seats],
            )?;
            tx.execute(
                "DELETE FROM license_monthly_peaks WHERE month NOT IN \
                 (SELECT month FROM license_monthly_peaks ORDER BY month DESC LIMIT 13)",
                &[],
            )?;
            Ok(())
        })
        .map_err(|e| format!("record seats: {}", detail(&e)))
}

/// `(YYYY-MM, peak)`, oldest first.
pub fn monthly_peaks(db: &ControlDb) -> Result<Vec<(String, i64)>, String> {
    db.lock()
        .query(
            "SELECT month, peak FROM license_monthly_peaks ORDER BY month",
            &[],
        )
        .map(|rows| rows.iter().map(|r| (r.get(0), r.get(1))).collect())
        .map_err(|e| format!("read seat history: {}", detail(&e)))
}

/// Claims the check: `true` for exactly one caller per `gap_ms`, however
/// many replicas ask and however often they restart.
pub fn claim_check(db: &ControlDb, now_ms: i64, gap_ms: i64) -> Result<bool, String> {
    db.lock()
        .execute(
            "UPDATE license SET check_claimed_at = $1 \
             WHERE check_claimed_at IS NULL OR check_claimed_at <= $1::BIGINT - $2::BIGINT",
            &[&now_ms, &gap_ms],
        )
        .map(|n| n == 1)
        .map_err(|e| format!("claim the licence check: {}", detail(&e)))
}

/// A check Weft answered. The peak since the last check starts again from
/// the seats there are now.
pub fn record_check_ok(
    db: &ControlDb,
    at_ms: i64,
    status: &str,
    notice: Option<&str>,
    seats_now: i64,
) -> Result<(), String> {
    db.lock()
        .execute(
            "UPDATE license SET last_check_at = $1, last_check_status = $2, notice = $3, \
                    last_check_error = NULL, peak_since_check = $4",
            &[&at_ms, &status, &notice, &seats_now],
        )
        .map(|_| ())
        .map_err(|e| format!("record the licence check: {}", detail(&e)))
}

/// A check that did not get an answer. What the last good one heard stays.
pub fn record_check_failed(db: &ControlDb, error: &str) -> Result<(), String> {
    db.lock()
        .execute("UPDATE license SET last_check_error = $1", &[&error])
        .map(|_| ())
        .map_err(|e| format!("record the licence check: {}", detail(&e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::users::{self, Role};

    fn db(hint: &str) -> ControlDb {
        let db = ControlDb::open(&skein_testkit::pg::test_db_url(hint)).unwrap();
        crate::registry::create_org(&db, "acme").unwrap();
        db
    }

    #[test]
    fn a_fresh_install_has_one_empty_licence_row() {
        let db = db("lic_fresh");
        let row = get(&db).unwrap();
        assert_eq!(row.key, None);
        assert!(row.installed_at > 1_700_000_000_000, "{}", row.installed_at);
        assert_eq!(row.peak_since_check, 0);
        // The singleton: a second row is refused by the database.
        let err = db
            .lock()
            .execute("INSERT INTO license (installed_at) VALUES (1)", &[])
            .unwrap_err();
        assert!(crate::db::detail(&err).contains("duplicate key"), "{err}");
    }

    /// Seats are people who can sign in; the licence reads nothing else.
    #[test]
    fn a_seat_is_somebody_who_can_sign_in() {
        let db = db("lic_seats");
        assert_eq!(users::seat_count(&db).unwrap(), 0);
        let ada = users::create(&db, "ada", Role::Admin, Some("pw-ada-12345")).unwrap();
        users::create(&db, "rita", Role::Reader, Some("pw-rita-12345")).unwrap();
        let ci = users::create(&db, "ci", Role::Publisher, None).unwrap();
        assert_eq!(
            users::seat_count(&db).unwrap(),
            2,
            "a service account is not a seat"
        );

        let rita = users::by_username(&db, "rita").unwrap().unwrap();
        users::set_disabled(&db, &rita.id, true).unwrap();
        assert_eq!(
            users::seat_count(&db).unwrap(),
            1,
            "nor is somebody disabled"
        );
        users::set_disabled(&db, &rita.id, false).unwrap();
        assert_eq!(users::seat_count(&db).unwrap(), 2, "until re-enabled");

        users::set_password(&db, &ci.id, "pw-ci-123456").unwrap();
        assert_eq!(
            users::seat_count(&db).unwrap(),
            3,
            "a password makes a seat"
        );
        users::delete(&db, &rita.id).unwrap();
        assert_eq!(users::seat_count(&db).unwrap(), 2);
        let _ = ada;
    }

    #[test]
    fn the_configured_key_is_applied_only_when_it_changes() {
        let db = db("lic_configured");
        assert!(apply_configured(&db, "k1").unwrap());
        assert_eq!(get(&db).unwrap().key.as_deref(), Some("k1"));
        // An admin installs another through the API.
        install(&db, "k2").unwrap();
        // A restart with the same environment leaves it standing…
        assert!(!apply_configured(&db, "k1").unwrap());
        assert_eq!(get(&db).unwrap().key.as_deref(), Some("k2"));
        // …and a changed environment replaces it.
        assert!(apply_configured(&db, "k3").unwrap());
        assert_eq!(get(&db).unwrap().key.as_deref(), Some("k3"));
    }

    #[test]
    fn peaks_are_maxima_and_thirteen_months_are_kept() {
        let db = db("lic_peaks");
        record_seats(&db, 4, "2026-01").unwrap();
        record_seats(&db, 2, "2026-01").unwrap();
        record_seats(&db, 3, "2026-02").unwrap();
        assert_eq!(get(&db).unwrap().peak_since_check, 4);
        assert_eq!(
            monthly_peaks(&db).unwrap(),
            vec![("2026-01".into(), 4), ("2026-02".into(), 3)]
        );
        for m in 3..=12 {
            record_seats(&db, 1, &format!("2026-{m:02}")).unwrap();
        }
        record_seats(&db, 1, "2027-01").unwrap();
        record_seats(&db, 1, "2027-02").unwrap();
        let months: Vec<String> = monthly_peaks(&db)
            .unwrap()
            .into_iter()
            .map(|m| m.0)
            .collect();
        assert_eq!(months.len(), 13);
        assert_eq!(months[0], "2026-02", "the oldest month went");
        assert_eq!(months[12], "2027-02");
    }

    #[test]
    fn a_check_is_claimed_once_per_gap() {
        let db = db("lic_claim");
        let day = 86_400_000;
        assert!(claim_check(&db, 1_000 * day, 23 * 3_600_000).unwrap());
        assert!(!claim_check(&db, 1_000 * day + 1, 23 * 3_600_000).unwrap());
        assert!(!claim_check(&db, 1_000 * day + 22 * 3_600_000, 23 * 3_600_000).unwrap());
        assert!(claim_check(&db, 1_000 * day + 23 * 3_600_000, 23 * 3_600_000).unwrap());
        // A new key drops the claim, so it is checked at the next tick.
        install(&db, "k").unwrap();
        assert!(claim_check(&db, 1_000 * day + 23 * 3_600_000 + 5, 23 * 3_600_000).unwrap());
    }

    #[test]
    fn a_check_answer_resets_the_peak_and_a_failure_keeps_the_last_answer() {
        let db = db("lic_answer");
        record_seats(&db, 9, "2026-10").unwrap();
        record_check_ok(&db, 5, "active", Some("Renew soon"), 3).unwrap();
        let row = get(&db).unwrap();
        assert_eq!(row.peak_since_check, 3);
        assert_eq!(row.last_check_status.as_deref(), Some("active"));
        record_check_failed(&db, "the licence endpoint answered HTTP 503").unwrap();
        let row = get(&db).unwrap();
        assert_eq!(row.last_check_at, Some(5));
        assert_eq!(row.notice.as_deref(), Some("Renew soon"));
        assert!(row.last_check_error.unwrap().contains("503"));
        // The status column refuses a word the check cannot answer.
        assert!(record_check_ok(&db, 6, "fine", None, 3).is_err());
    }
}
