//! The commercial licence, inside the server.
//!
//! **Nothing here can refuse anything.** No door, sign-in or admin action
//! reads it. What it does: verify the key offline, count seats (people
//! who can sign in), keep the monthly peaks, run the daily check for an
//! online key, and turn all of that into warnings for admins — in the UI,
//! at `GET /api/v1/license`, and in the log when they change.
//!
//! sandy's control plane (`license/service.ts`) is the model, down to the
//! configured key standing until the environment's *changes*. Two
//! differences are Skein's: seats rather than concurrent sandboxes, and
//! the daily check claimed in the database, because Skein runs as several
//! identical replicas where sandy has one worker.

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use skein_control::license as db;
use skein_control::users::seat_count;
use skein_control::ControlDb;
use skein_license::check::{self, CheckOptions, CheckOutcome, CheckRequest};
use skein_license::time::{format_iso8601, month_of};
use skein_license::{
    evaluate, EvaluateInput, LicenseStatus, Mode, Payload, Rejected, RemoteStatus, TrustedKeys,
};

use crate::app::SharedState;

/// How long after one check another may be claimed. Checked hourly, so a
/// check lands once a day, give or take the hour.
const CHECK_GAP: Duration = Duration::from_secs(23 * 3600);
const CHECK_TICK: Duration = Duration::from_secs(3600);
const SAMPLE_EVERY: Duration = Duration::from_secs(60);

pub struct Licensing {
    trusted: TrustedKeys,
    configured_key: Option<String>,
    endpoint: String,
    first_check: Duration,
    version: &'static str,
    /// The warnings last logged by this process, so the log says when they
    /// change rather than every minute.
    last_logged: Mutex<String>,
}

fn env(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|v| !v.trim().is_empty())
}

impl Licensing {
    /// From the environment. A configuration mistake — an insecure
    /// endpoint, development keys outside development — refuses to start,
    /// because it is the operator's to fix and fixing it is one variable.
    /// A key that does not verify is **not** a mistake of that kind: it
    /// starts, and says so.
    pub fn from_env() -> Result<Licensing, String> {
        let dev = matches!(env("SKEIN_DEV_MODE").as_deref(), Some("1" | "true" | "yes"));
        let mut trusted = TrustedKeys::release()?;
        if let Some(json) = env("SKEIN_DEV_LICENSE_PUBLIC_KEYS") {
            if !dev {
                return Err(
                    "SKEIN_DEV_LICENSE_PUBLIC_KEYS requires SKEIN_DEV_MODE=1: a \
                            production install trusts only Weft's release keys"
                        .into(),
                );
            }
            let map: std::collections::BTreeMap<String, String> = serde_json::from_str(&json)
                .map_err(|e| {
                    format!(
                        "SKEIN_DEV_LICENSE_PUBLIC_KEYS must be a JSON object of kid to PEM: {e}"
                    )
                })?;
            trusted = trusted.with(TrustedKeys::from_pem(
                map.iter().map(|(k, v)| (k.as_str(), v.as_str())),
            )?);
        }
        let endpoint =
            env("SKEIN_LICENSE_ENDPOINT").unwrap_or_else(|| check::DEFAULT_ENDPOINT.into());
        if !dev && !endpoint.starts_with("https://") {
            return Err(format!(
                "SKEIN_LICENSE_ENDPOINT must be HTTPS (got {endpoint}); plain HTTP is for \
                 development, with SKEIN_DEV_MODE=1"
            ));
        }
        // The first check waits a random part of an hour, so a fleet
        // restarted together does not check together. Tests say 0.
        let first_check = match env("SKEIN_LICENSE_CHECK_DELAY_SECS") {
            Some(s) => Duration::from_secs(s.trim().parse().map_err(|_| {
                format!("SKEIN_LICENSE_CHECK_DELAY_SECS must be a number of seconds, not {s:?}")
            })?),
            None => {
                let r = skein_control::ids::random(8);
                let n = u64::from_le_bytes(r.try_into().expect("8 bytes"));
                Duration::from_secs(n % CHECK_TICK.as_secs())
            }
        };
        Ok(Licensing {
            trusted,
            configured_key: env("SKEIN_LICENSE_KEY").map(|k| k.trim().to_string()),
            endpoint,
            first_check,
            version: env!("CARGO_PKG_VERSION"),
            last_logged: Mutex::new(String::new()),
        })
    }

    pub fn trusted_key_ids(&self) -> Vec<String> {
        self.trusted.ids()
    }

    /// Applies `SKEIN_LICENSE_KEY` if it changed since it was last applied.
    pub fn init(&self, conn: &ControlDb) -> Result<(), String> {
        if let Some(key) = &self.configured_key {
            if db::apply_configured(conn, key)? {
                match self.verify(key) {
                    Ok(p) => eprintln!(
                        "skein: licence key from SKEIN_LICENSE_KEY applied: {} ({}, {})",
                        p.lid,
                        p.tier.as_str(),
                        p.entity
                    ),
                    Err(r) => eprintln!(
                        "skein: the licence key in SKEIN_LICENSE_KEY does not verify ({r}); \
                         Skein serves normally"
                    ),
                }
            }
        }
        Ok(())
    }

    pub fn verify(&self, key: &str) -> Result<Payload, Rejected> {
        skein_license::verify(key, &self.trusted)
    }

    /// Installs a key an admin pasted, if it verifies.
    pub fn install(
        &self,
        conn: &ControlDb,
        key: &str,
    ) -> Result<Result<Payload, Rejected>, String> {
        let key = key.trim();
        let verified = self.verify(key);
        if verified.is_ok() {
            db::install(conn, key)?;
        }
        Ok(verified)
    }

    /// Counts seats now, records them, and says what the licence means.
    pub fn report(&self, conn: &ControlDb, now_ms: i64) -> Result<Report, String> {
        let seats = seat_count(conn)?;
        db::record_seats(conn, seats, &month_of(now_ms))?;
        let row = db::get(conn)?;
        let verified = row.key.as_deref().map(|k| self.verify(k));
        let status = evaluate(&EvaluateInput {
            now_ms,
            key: verified.as_ref(),
            seats: seats.max(0) as u64,
            installed_at_ms: Some(row.installed_at),
            last_check_at_ms: row.last_check_at,
            last_check_status: row
                .last_check_status
                .as_deref()
                .and_then(RemoteStatus::parse),
        });
        self.log_if_changed(&status);
        let peaks = db::monthly_peaks(conn)?;
        let this_month = month_of(now_ms);
        Ok(Report {
            key_source: match (&row.key, &row.configured_key) {
                (None, _) => None,
                (Some(k), Some(c)) if k == c => Some("environment"),
                (Some(_), _) => Some("api"),
            },
            notice: row.notice,
            last_check_at: row.last_check_at.map(format_iso8601),
            last_check_status: row.last_check_status,
            last_check_error: row.last_check_error,
            peak_seats_this_month: peaks
                .iter()
                .find(|(m, _)| *m == this_month)
                .map(|(_, p)| *p)
                .unwrap_or(seats),
            monthly_peaks: peaks
                .into_iter()
                .map(|(month, peak)| MonthPeak { month, peak })
                .collect(),
            status,
        })
    }

    fn log_if_changed(&self, status: &LicenseStatus) {
        let joined = status.warnings.join(" | ");
        let mut last = self.last_logged.lock().unwrap();
        if *last != joined {
            if !joined.is_empty() {
                for w in &status.warnings {
                    eprintln!("skein: licence: {w}");
                }
            } else if !last.is_empty() {
                eprintln!("skein: licence: no warnings");
            }
            *last = joined;
        }
    }

    /// Runs the check if the key is an online one and this caller wins the
    /// claim (`gap` since the last; zero for an admin's "check now").
    /// Blocking: it waits on the network. Never an error for a check that
    /// failed — that is recorded, and becomes a warning after a week.
    pub fn run_check(&self, conn: &ControlDb, gap: Duration) -> Result<CheckRun, String> {
        let row = db::get(conn)?;
        let Some(Ok(lic)) = row.key.as_deref().map(|k| self.verify(k)) else {
            return Ok(CheckRun::NoValidKey);
        };
        if lic.mode == Mode::Offline {
            return Ok(CheckRun::Offline);
        }
        let now = skein_control::ids::now_ms();
        if !db::claim_check(conn, now, gap.as_millis() as i64)? {
            return Ok(CheckRun::NotDue);
        }
        let seats = seat_count(conn)?;
        db::record_seats(conn, seats, &month_of(now))?;
        let peak = db::get(conn)?.peak_since_check;
        let req = CheckRequest {
            key_id: lic.lid.clone(),
            version: self.version.to_string(),
            peak_seats: peak.max(0) as u64,
        };
        let outcome = check::send(
            &req,
            &CheckOptions {
                endpoint: self.endpoint.clone(),
                ..CheckOptions::default()
            },
        );
        match outcome {
            CheckOutcome::Ok(r) => {
                db::record_check_ok(
                    conn,
                    skein_control::ids::now_ms(),
                    r.status.as_str(),
                    r.notice.as_deref(),
                    seat_count(conn)?,
                )?;
                Ok(CheckRun::Answered)
            }
            CheckOutcome::Failed(e) => {
                eprintln!("skein: licence check failed; Skein is unaffected: {e}");
                db::record_check_failed(conn, &e)?;
                Ok(CheckRun::Failed(e))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckRun {
    Answered,
    Failed(String),
    NoValidKey,
    Offline,
    NotDue,
}

#[derive(Serialize)]
pub struct MonthPeak {
    pub month: String,
    pub peak: i64,
}

/// What `GET /api/v1/license` and `skein admin license status` answer.
/// The key itself is never in it.
#[derive(Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub status: LicenseStatus,
    /// `environment` (SKEIN_LICENSE_KEY), `api` (installed by an admin),
    /// or null with no key.
    pub key_source: Option<&'static str>,
    pub notice: Option<String>,
    pub last_check_at: Option<String>,
    pub last_check_status: Option<String>,
    pub last_check_error: Option<String>,
    pub peak_seats_this_month: i64,
    /// Oldest first, the last thirteen months: an offline licence's
    /// true-up.
    pub monthly_peaks: Vec<MonthPeak>,
}

/// The timers: seats sampled every minute (which also logs a change in
/// the warnings), and the check tried every hour after a random start.
pub fn spawn(state: SharedState) {
    let st = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(SAMPLE_EVERY);
        loop {
            tick.tick().await;
            let s = st.clone();
            let now = skein_control::ids::now_ms();
            match tokio::task::spawn_blocking(move || s.license.report(&s.db, now)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => eprintln!("skein: licence: sampling seats: {e}"),
                Err(e) => eprintln!("skein: licence: join: {e}"),
            }
        }
    });
    tokio::spawn(async move {
        tokio::time::sleep(state.license.first_check).await;
        let mut tick = tokio::time::interval(CHECK_TICK);
        loop {
            tick.tick().await;
            let s = state.clone();
            match tokio::task::spawn_blocking(move || s.license.run_check(&s.db, CHECK_GAP)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => eprintln!("skein: licence check: {e}"),
                Err(e) => eprintln!("skein: licence check: join: {e}"),
            }
        }
    });
}
