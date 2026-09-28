//! The exit path must *reap* the postmaster, not wait out its deadline.
//!
//! `Pg::shared` lives in a `OnceLock`, which Rust never drops, so the
//! cluster is stopped from a `libc::atexit` hook instead of from
//! `KillOnDrop`. That hook used to send `SIGINT` and then poll
//! `libc::kill(pid, 0)` until a five-second deadline — but the postmaster
//! is a *direct child* of the test process and nothing ever waits on it,
//! so the moment it exits it becomes a **zombie**, and signal 0 succeeds
//! against a zombie for as long as it goes unreaped. The loop therefore
//! never returned early: every test binary that had touched a database
//! paid the full five seconds on the way out and then `SIGKILL`ed a
//! corpse.
//!
//! That is not a rounding error. `cargo test` runs test binaries one at a
//! time, and on the CI run this test was written against the gap between
//! one binary's last result and the next binary's first line had a median
//! of **5.01s** over 67 transitions — **4.5 minutes** of dead time in the
//! correctness gate and another 4.5 in the coverage job, which is a fifth
//! of each.
//!
//! `KillOnDrop::drop`, ten lines further down the same file, polls
//! `Child::try_wait()` — which reaps — and was always correct. Only the
//! hook, rewritten in raw `libc` because a `static` has no `Child` to call
//! it on, lost the property.
//!
//! So this measures the thing that actually costs: how long a test binary
//! takes to *exit* after its last test has finished.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

/// Set for the child only: the probe is a no-op in an ordinary run.
const PROBE: &str = "SKEIN_TESTKIT_PG_EXIT_PROBE";
const MARKER: &str = "main-returning-at-ms ";

/// The budget. The bug parks for 5000ms; a reaping exit path takes a few
/// tens of milliseconds. Anything in between is a regression worth
/// hearing about, and the gap is wide enough that a busy runner cannot
/// close it.
const BUDGET_MS: u128 = 2_000;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before the epoch")
        .as_millis()
}

/// The child half. Boots the shared cluster, takes a database from it so
/// the postmaster is genuinely serving, then stamps the moment the test
/// body ends. Everything after that stamp is exit-path cost.
#[test]
fn shared_cluster_exit_probe() {
    if std::env::var_os(PROBE).is_none() {
        return;
    }
    let url = skein_testkit::pg::test_db_url("exitprobe");
    assert!(url.starts_with("postgres://"), "unexpected url: {url}");

    let mut out = std::io::stdout();
    writeln!(out, "{MARKER}{}", now_ms()).expect("write the marker");
    out.flush().expect("flush the marker");
}

#[test]
fn the_exit_path_reaps_the_postmaster_instead_of_waiting_out_its_deadline() {
    let exe = std::env::current_exe().expect("this test binary's own path");

    // Re-running *this* binary, rather than a purpose-built helper, is
    // deliberate: the cost being measured is a test binary's exit, and a
    // test binary is what CI pays it on.
    let out = Command::new(&exe)
        .args([
            "shared_cluster_exit_probe",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("run the probe");

    assert!(
        out.status.success(),
        "the probe did not pass ({}); its output was:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout)
    );

    // `--nocapture` interleaves the probe's write onto libtest's own
    // "test <name> ... " line, so the marker is found in the text rather
    // than at the start of a line.
    let text = String::from_utf8_lossy(&out.stdout);
    let stamped: u128 = text
        .split_once(MARKER)
        .map(|(_, rest)| rest.trim_start().trim_matches(char::is_control))
        .and_then(|rest| {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .unwrap_or_else(|| panic!("the probe never reached its marker:\n{text}"));

    let exiting = now_ms().saturating_sub(stamped);
    assert!(
        exiting < BUDGET_MS,
        "a test binary took {exiting}ms to exit after its last test finished, \
         budget {BUDGET_MS}ms. The shared-cluster atexit hook is waiting out \
         its own deadline instead of reaping the postmaster: signal 0 \
         succeeds against an unreaped zombie, so the liveness poll never \
         sees it go. Multiply this by every test binary in the workspace."
    );
}
