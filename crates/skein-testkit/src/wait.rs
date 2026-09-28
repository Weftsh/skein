//! Wait for the thing the next step depends on, not for the clock.
//!
//! CLAUDE.md states the rule and this repo has already paid for breaking
//! it twice: a test that polled a mock's call count passed before the
//! page had finished with the response, and the fix was to wait for the
//! form to clear — the observable the next interaction actually needs.
//!
//! The e2e suites had drifted the other way. There were 197
//! `thread::sleep`s across `crates/`, and the multi-second ones at
//! statement position were all the same shape: sleep long enough for a
//! background worker to have ticked, then assert. That is slow when it
//! works and misleading when it does not — a machine busy enough to miss
//! the tick fails with an assertion about the product, not about the
//! wait.
//!
//! These take a deadline and a probe, return the moment the probe is
//! satisfied, and name what they were waiting for when they give up.

use std::time::{Duration, Instant};

/// How often the probe runs. Short enough that a fast condition is not
/// rounded up to something a person would notice, long enough that
//  polling an HTTP endpoint is not itself the load.
const TICK: Duration = Duration::from_millis(25);

/// Block until `pred` holds, or panic naming `what`.
pub fn wait_until(what: &str, within: Duration, mut pred: impl FnMut() -> bool) {
    let started = Instant::now();
    loop {
        if pred() {
            return;
        }
        assert!(
            started.elapsed() < within,
            "waited {within:?} for {what} and it never happened"
        );
        std::thread::sleep(TICK);
    }
}

/// Block until `probe` yields a value, and return it.
///
/// The `Option` shape is what most call sites actually want: they are
/// looking *for* something — a run with this sha, a check with that
/// conclusion — and want it back, not a second lookup after the wait.
pub fn wait_for<T>(what: &str, within: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let started = Instant::now();
    loop {
        if let Some(v) = probe() {
            return v;
        }
        assert!(
            started.elapsed() < within,
            "waited {within:?} for {what} and it never appeared"
        );
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The point of the helper: it returns when the condition holds, not
    /// when the budget runs out. A sleep-based wait cannot pass this.
    #[test]
    fn a_satisfied_condition_returns_immediately_not_at_the_deadline() {
        let calls = AtomicU32::new(0);
        let started = Instant::now();
        wait_until(
            "a condition that is true on the third look",
            Duration::from_secs(30),
            || calls.fetch_add(1, Ordering::SeqCst) >= 2,
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    /// And `wait_for` hands back what it found, so the caller does not
    /// look twice and race itself.
    #[test]
    fn wait_for_returns_the_value_the_probe_yielded() {
        let calls = AtomicU32::new(0);
        let got = wait_for(
            "a value on the second look",
            Duration::from_secs(30),
            || {
                if calls.fetch_add(1, Ordering::SeqCst) >= 1 {
                    Some("landed")
                } else {
                    None
                }
            },
        );
        assert_eq!(got, "landed");
    }

    /// A timeout has to say what it was waiting for. A bare
    /// "assertion failed" in an e2e run tells the next reader nothing,
    /// which is most of why these sleeps were written as sleeps.
    #[test]
    #[should_panic(expected = "the run to appear")]
    fn giving_up_names_what_it_waited_for() {
        wait_until("the run to appear", Duration::from_millis(50), || false);
    }

    #[test]
    #[should_panic(expected = "a value that never comes")]
    fn wait_for_giving_up_names_what_it_waited_for() {
        wait_for(
            "a value that never comes",
            Duration::from_millis(50),
            || None::<()>,
        );
    }
}
