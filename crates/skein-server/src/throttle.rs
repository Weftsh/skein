//! Throttling password checks.
//!
//! Three doors take a password: the UI's sign-in (`POST
//! /api/v1/session`), `npm login` (npm's CouchDB exchange), and a
//! password change, which checks the current one. Each check is an
//! Argon2 hash, so without a limit anybody who can reach one of them can
//! guess at full speed and spend the server's CPU doing it. All three go
//! through one [`Throttle`] in `AppState`, so a guesser cannot split
//! their attempts between doors.
//!
//! ## The policy
//!
//! Failures are counted against two keys at once:
//!
//! * the **name** tried, normalised the way sign-in reads it — so `ADA`
//!   and `ada` are one counter. A name nobody holds counts exactly like
//!   one somebody does: the lock must not say who has an account.
//! * the **address** it came from — the other shape of guessing, one
//!   password tried against many names. See [`Policy::client_address`]
//!   for which address that is behind a proxy.
//!
//! [`Policy::per_name`] failures for a name (default 5), or
//! [`Policy::per_address`] for an address (default 20), within
//! [`Policy::window`] (default 15 minutes) of the first, lock that key
//! for a window from the failure that filled it. While a key is locked
//! every check for it is refused **before** Argon2 runs — the right
//! password included, which is the point: a guesser who lands on it
//! while locked must not be told so.
//!
//! A refusal is not a failure. It neither counts nor stretches the lock:
//! npm retries a refused `PUT` on its own, and a client that re-locked
//! its own user with every retry would never get back in.
//!
//! A success clears the **name**'s counter, not the address's: a valid
//! account of their own must not be a reset button for somebody spraying
//! one password across everybody else's.
//!
//! ## An attempt is counted when it is let in
//!
//! Not when it fails. Between letting an attempt in and knowing how it
//! went sits an Argon2 hash, and a limiter that counts only afterwards
//! lets in everything that arrives while the first few are still hashing
//! — as many free guesses as the server can hash at once. So
//! [`Throttle::admit`] counts the attempt, a success takes it back, and
//! an internal error ([`Throttle::release`]) takes it back from every key.
//!
//! ## Bounded, and per process
//!
//! Counters live in this process's memory: several replicas each keep
//! their own, which still bounds guessing to replicas × the limit, and a
//! restart forgets them. An entry is dropped once its window has passed,
//! and the map holds at most [`Policy::max_keys`] keys: when it is full
//! and nothing has expired, the oldest key that is not locked makes room
//! — so a flood of one-failure random names cannot switch tracking off
//! for the next one. Only when every key held is locked does a new one
//! go uncounted.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many failures lock a key, for how long, and where an address
/// comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Failures for one name within [`Policy::window`] that lock it.
    pub per_name: u32,
    /// Failures from one address within [`Policy::window`] that lock it.
    pub per_address: u32,
    /// How long failures are remembered, and how long a lock lasts.
    pub window: Duration,
    /// The most keys held at once.
    pub max_keys: usize,
    /// Take the client's address from the right-most `X-Forwarded-For`
    /// entry rather than the TCP peer: `SKEIN_TRUST_PROXY_HEADERS`.
    pub trust_forwarded_for: bool,
}

/// The longest window an operator may set: a day. A lock that outlasts
/// that is a locked-out person nobody can let back in but a restart.
const MAX_WINDOW_SECS: u64 = 24 * 60 * 60;

/// The longest name kept as a key. A real name is at most 39
/// characters; this is only so a megabyte of made-up username is not a
/// megabyte of map key.
const MAX_NAME_KEY: usize = 64;

impl Default for Policy {
    fn default() -> Policy {
        Policy {
            per_name: 5,
            per_address: 20,
            window: Duration::from_secs(15 * 60),
            max_keys: 100_000,
            trust_forwarded_for: false,
        }
    }
}

impl Policy {
    /// From the environment. A value that does not parse refuses to
    /// start: a limit the operator set and Skein silently ignored is
    /// worse than one they are told to fix.
    pub fn from_env() -> Result<Policy, String> {
        Policy::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Policy, String> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let mut p = Policy::default();
        let count = |var: &str, default: u32| -> Result<u32, String> {
            match get(var) {
                None => Ok(default),
                Some(v) => match v.trim().parse::<u32>() {
                    Ok(n) if n >= 1 => Ok(n),
                    _ => Err(format!(
                        "{var} must be a whole number of at least 1, not {v:?}"
                    )),
                },
            }
        };
        p.per_name = count("SKEIN_LOGIN_MAX_FAILURES", p.per_name)?;
        p.per_address = count("SKEIN_LOGIN_MAX_FAILURES_PER_ADDRESS", p.per_address)?;
        if let Some(v) = get("SKEIN_LOGIN_WINDOW_SECS") {
            match v.trim().parse::<u64>() {
                Ok(n) if (1..=MAX_WINDOW_SECS).contains(&n) => p.window = Duration::from_secs(n),
                _ => {
                    return Err(format!(
                        "SKEIN_LOGIN_WINDOW_SECS must be between 1 and {MAX_WINDOW_SECS} seconds, \
                         not {v:?}"
                    ))
                }
            }
        }
        if let Some(v) = get("SKEIN_TRUST_PROXY_HEADERS") {
            p.trust_forwarded_for = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" => true,
                "0" | "false" | "no" => false,
                _ => {
                    return Err(format!(
                        "SKEIN_TRUST_PROXY_HEADERS must be true or false, not {v:?}"
                    ))
                }
            };
        }
        Ok(p)
    }

    /// The address a request is counted against.
    ///
    /// By default the TCP peer's. A client can write any
    /// `X-Forwarded-For` it likes, and reading it would let one spread
    /// its guesses over as many made-up addresses as it cared to invent.
    ///
    /// Behind a reverse proxy the peer is the proxy, for everybody — so
    /// the operator says so (`SKEIN_TRUST_PROXY_HEADERS=true`) and the
    /// address is the **right-most** entry of the last `X-Forwarded-For`
    /// line: the one the proxy appended. Everything to its left arrived
    /// from the client and is not read. A request with no such entry, or
    /// one that is not an address, is counted against the peer.
    ///
    /// `forwarded_for` is the last header line's raw bytes, so a
    /// client-written prefix that is not UTF-8 cannot make the proxy's
    /// entry unreadable.
    pub fn client_address(&self, peer: IpAddr, forwarded_for: Option<&[u8]>) -> IpAddr {
        if !self.trust_forwarded_for {
            return peer;
        }
        forwarded_for
            .and_then(|line| line.rsplit(|b| *b == b',').next())
            .and_then(|last| std::str::from_utf8(last).ok())
            .and_then(|s| parse_address(s.trim()))
            .unwrap_or(peer)
    }
}

/// An address as a proxy may write it: bare, or with a port.
fn parse_address(s: &str) -> Option<IpAddr> {
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// What failures are counted against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    Name(String),
    Address(IpAddr),
}

impl Key {
    /// The name as sign-in reads it: trimmed and lowercased. One that is
    /// not a valid username still counts — it answers the same 401, so it
    /// must lock the same way — cut to a bounded length.
    pub fn name(typed: &str) -> Key {
        let n = skein_control::users::normalize_username(typed)
            .unwrap_or_else(|_| typed.trim().to_lowercase());
        let mut end = n.len().min(MAX_NAME_KEY);
        while !n.is_char_boundary(end) {
            end -= 1;
        }
        Key::Name(n[..end].to_string())
    }

    /// An address, as the unit one party controls: an IPv4 address, or
    /// an IPv6 `/64` — a single host is routinely handed a whole `/64`,
    /// and counting each of its addresses apart would give it 2^64
    /// budgets. An IPv4 address mapped into IPv6 is the IPv4 address.
    pub fn address(ip: IpAddr) -> Key {
        Key::Address(match ip {
            IpAddr::V4(_) => ip,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let s = v6.segments();
                    IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
                }
            },
        })
    }

    /// `for ada` or `from 192.0.2.7`, for the refusal's sentence.
    pub fn describe(&self) -> String {
        match self {
            Key::Name(n) => format!("for {n}"),
            Key::Address(a) => format!("from {}", Key::address_text(a)),
        }
    }

    /// An address as the audit log and the refusal write it: an IPv6 key
    /// is a `/64`, and says so.
    pub fn address_text(a: &IpAddr) -> String {
        match a {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("{v6}/64"),
        }
    }
}

/// A check refused because a key is locked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub key: Key,
    pub retry_after: Duration,
}

/// Whole seconds, rounded up and at least one: `Retry-After: 0` reads
/// as "now", and now would be refused again.
pub fn whole_secs(d: Duration) -> u64 {
    (d.as_secs() + u64::from(d.subsec_nanos() > 0)).max(1)
}

impl Refusal {
    pub fn retry_after_secs(&self) -> u64 {
        whole_secs(self.retry_after)
    }

    /// What the person is told. The wait is in words — see
    /// [`wait_in_words`] — where `Retry-After` stays in seconds.
    pub fn sentence(&self) -> String {
        format!(
            "too many failed sign-ins {}; try again in {}",
            self.key.describe(),
            wait_in_words(self.retry_after_secs())
        )
    }
}

/// A wait as a person counts it: seconds under a minute and a half,
/// whole minutes rounded up past that.
///
/// The default lock is fifteen minutes, and it used to be said as "try
/// again in 900 seconds" — a number somebody who had just mistyped their
/// password had to divide by sixty. Seconds stay below 90 because a
/// minute is too coarse there: 61 seconds would read "2 minutes". Up,
/// never down, so nobody is told to come back while the lock still
/// stands.
fn wait_in_words(secs: u64) -> String {
    match secs {
        1 => "1 second".to_string(),
        s if s < 90 => format!("{s} seconds"),
        s => minutes_in_words(s.div_ceil(60)),
    }
}

fn minutes_in_words(n: u64) -> String {
    if n == 1 {
        "1 minute".to_string()
    } else {
        format!("{n} minutes")
    }
}

/// A key that the failure just recorded locked. Reported once per lock,
/// so the audit log gets one entry for an attack rather than one per
/// refused guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockout {
    pub key: Key,
    pub failures: u32,
    pub locked_for: Duration,
}

#[derive(Debug)]
struct Entry {
    /// Attempts counted: failed, or let in and not yet answered.
    count: u32,
    /// The first of them; the window runs from here until the key locks.
    since: Instant,
    /// When the count reached the limit; the lock runs a window from here.
    locked_at: Option<Instant>,
    /// Whether this lock has been reported by [`Throttle::failed`].
    reported: bool,
}

impl Entry {
    fn fresh(now: Instant) -> Entry {
        Entry {
            count: 0,
            since: now,
            locked_at: None,
            reported: false,
        }
    }

    fn ends(&self, window: Duration) -> Instant {
        self.locked_at.unwrap_or(self.since) + window
    }

    fn live(&self, now: Instant, window: Duration) -> bool {
        now < self.ends(window)
    }
}

/// The counters. One per process, shared by every password door.
pub struct Throttle {
    policy: Policy,
    inner: Mutex<Inner>,
}

struct Inner {
    entries: HashMap<Key, Entry>,
    swept: Option<Instant>,
}

impl Throttle {
    pub fn new(policy: Policy) -> Throttle {
        Throttle {
            policy,
            inner: Mutex::new(Inner {
                entries: HashMap::new(),
                swept: None,
            }),
        }
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    fn limit(&self, key: &Key) -> u32 {
        match key {
            Key::Name(_) => self.policy.per_name,
            Key::Address(_) => self.policy.per_address,
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding this cannot leave a counter half
        // written in a way that matters more than refusing every
        // sign-in would.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Let one password check in, counting it against every key — or
    /// refuse it, touching nothing, because the first key given that is
    /// locked. Pass the name first: a person who mistyped their own
    /// password should hear about their name, not about their office's
    /// shared address.
    pub fn admit(&self, keys: &[Key], now: Instant) -> Result<(), Refusal> {
        let window = self.policy.window;
        let mut inner = self.inner();
        inner.sweep_if_due(now, window);
        for key in keys {
            if let Some(e) = inner.entries.get(key) {
                if e.live(now, window) && e.count >= self.limit(key) {
                    return Err(Refusal {
                        key: key.clone(),
                        retry_after: e.ends(window).saturating_duration_since(now),
                    });
                }
            }
        }
        for key in keys {
            let limit = self.limit(key);
            if let Some(e) = inner.entry(key, now, window, self.policy.max_keys) {
                e.count += 1;
                if e.count >= limit && e.locked_at.is_none() {
                    e.locked_at = Some(now);
                }
            }
        }
        Ok(())
    }

    /// The check [`Throttle::admit`] let in failed. It is already
    /// counted; what is left is to say which keys it locked, once each.
    pub fn failed(&self, keys: &[Key], now: Instant) -> Vec<Lockout> {
        let window = self.policy.window;
        let mut inner = self.inner();
        let mut locked = Vec::new();
        for key in keys {
            let limit = self.limit(key);
            // Gone since it was let in — a success on the same name, or
            // the window passing mid-hash: this failure starts it again.
            if !inner.entries.get(key).is_some_and(|e| e.live(now, window)) {
                if let Some(e) = inner.entry(key, now, window, self.policy.max_keys) {
                    e.count += 1;
                    if e.count >= limit {
                        e.locked_at = Some(now);
                    }
                }
            }
            if let Some(e) = inner.entries.get_mut(key) {
                if e.count >= limit && !e.reported {
                    e.reported = true;
                    locked.push(Lockout {
                        key: key.clone(),
                        failures: e.count,
                        locked_for: e.ends(window).saturating_duration_since(now),
                    });
                }
            }
        }
        locked
    }

    /// The check let in succeeded: a name's counter is cleared, and an
    /// address gets back the attempt it was charged — a success is not a
    /// failure, and does not wipe the failures before it.
    pub fn succeeded(&self, keys: &[Key]) {
        let mut inner = self.inner();
        for key in keys {
            match key {
                Key::Name(_) => {
                    inner.entries.remove(key);
                }
                Key::Address(_) => inner.refund(key, self.limit(key)),
            }
        }
    }

    /// The check let in never reached an answer — the database failed —
    /// so it is neither: every key gets its attempt back.
    pub fn release(&self, keys: &[Key]) {
        let mut inner = self.inner();
        for key in keys {
            inner.refund(key, self.limit(key));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner().entries.len()
    }
}

impl Inner {
    /// Drop every expired entry, at most once a window: enough to keep
    /// the map to what is live without a pass over it on every request.
    fn sweep_if_due(&mut self, now: Instant, window: Duration) {
        if self.swept.is_some_and(|at| now < at + window) {
            return;
        }
        self.entries.retain(|_, e| e.live(now, window));
        self.swept = Some(now);
    }

    /// The live entry for `key`, starting a fresh one if it has none —
    /// or `None` when the map is full of locks and it cannot be held.
    fn entry(
        &mut self,
        key: &Key,
        now: Instant,
        window: Duration,
        max_keys: usize,
    ) -> Option<&mut Entry> {
        if self.entries.get(key).is_some_and(|e| !e.live(now, window)) {
            self.entries.remove(key);
        }
        if !self.entries.contains_key(key) && !self.make_room(now, window, max_keys) {
            return None;
        }
        Some(
            self.entries
                .entry(key.clone())
                .or_insert_with(|| Entry::fresh(now)),
        )
    }

    /// Room for one more key: drop what has expired, and if that is not
    /// enough, the oldest key that is not locked. `false` when every key
    /// held is a live lock — those are the ones worth keeping.
    fn make_room(&mut self, now: Instant, window: Duration, max_keys: usize) -> bool {
        if self.entries.len() < max_keys {
            return true;
        }
        self.entries.retain(|_, e| e.live(now, window));
        self.swept = Some(now);
        if self.entries.len() < max_keys {
            return true;
        }
        let oldest = self
            .entries
            .iter()
            .filter(|(_, e)| e.locked_at.is_none())
            .min_by_key(|(_, e)| e.since)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                self.entries.remove(&k);
                true
            }
            None => false,
        }
    }

    fn refund(&mut self, key: &Key, limit: u32) {
        if let Some(e) = self.entries.get_mut(key) {
            e.count = e.count.saturating_sub(1);
            if e.count < limit {
                e.locked_at = None;
                e.reported = false;
            }
            if e.count == 0 {
                self.entries.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            per_name: 3,
            per_address: 5,
            window: Duration::from_secs(60),
            max_keys: 1000,
            trust_forwarded_for: false,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn keys(name: &str, addr: &str) -> Vec<Key> {
        vec![Key::name(name), Key::address(ip(addr))]
    }

    /// One attempt through the throttle, failing.
    fn fail(t: &Throttle, k: &[Key], now: Instant) -> Result<Vec<Lockout>, Refusal> {
        t.admit(k, now)?;
        Ok(t.failed(k, now))
    }

    #[test]
    fn the_limit_locks_the_name_and_the_next_check_is_refused() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        assert_eq!(fail(&t, &k, now), Ok(vec![]));
        assert_eq!(fail(&t, &k, now), Ok(vec![]));
        let third = fail(&t, &k, now).unwrap();
        assert_eq!(
            third,
            vec![Lockout {
                key: Key::name("ada"),
                failures: 3,
                locked_for: Duration::from_secs(60),
            }]
        );
        let r = t.admit(&k, now + Duration::from_secs(10)).unwrap_err();
        assert_eq!(r.key, Key::name("ada"));
        assert_eq!(r.retry_after, Duration::from_secs(50));
        assert_eq!(
            r.sentence(),
            "too many failed sign-ins for ada; try again in 50 seconds"
        );
        // The same name from somewhere else is the same name.
        assert!(t
            .admit(&keys("ADA", "198.51.100.9"), now + Duration::from_secs(10))
            .is_err());
        // Somebody else is untouched.
        assert!(t.admit(&keys("bob", "192.0.2.1"), now).is_ok());
    }

    #[test]
    fn a_refusal_neither_counts_nor_stretches_the_lock() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        for _ in 0..3 {
            fail(&t, &k, now).unwrap();
        }
        for s in 1..50 {
            assert!(t.admit(&k, now + Duration::from_secs(s)).is_err());
        }
        // Still a minute from the third failure, not from the last refusal.
        assert!(t.admit(&k, now + Duration::from_secs(59)).is_err());
        assert!(t.admit(&k, now + Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn a_lock_ends_after_a_window_and_the_count_starts_again() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        for _ in 0..3 {
            fail(&t, &k, now).unwrap();
        }
        let later = now + Duration::from_secs(61);
        // Two more failures after the lock are two, not five.
        assert_eq!(fail(&t, &k, later), Ok(vec![]));
        assert_eq!(fail(&t, &k, later), Ok(vec![]));
        assert_eq!(fail(&t, &k, later).unwrap().len(), 1);
    }

    #[test]
    fn failures_older_than_the_window_are_forgotten() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        fail(&t, &k, now).unwrap();
        fail(&t, &k, now).unwrap();
        // The window runs from the first failure: a third at 61s starts
        // a new count rather than locking.
        let later = now + Duration::from_secs(61);
        assert_eq!(fail(&t, &k, later), Ok(vec![]));
        assert!(t.admit(&k, later).is_ok());
    }

    #[test]
    fn a_lock_lasts_a_window_from_the_failure_that_filled_it() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let at = |s: u64| now + Duration::from_secs(s);
        let k = keys("ada", "192.0.2.1");
        fail(&t, &k, at(0)).unwrap();
        fail(&t, &k, at(30)).unwrap();
        let locked = fail(&t, &k, at(40)).unwrap();
        assert_eq!(locked[0].locked_for, Duration::from_secs(60));
        // A window after the first failure is not the end of the lock…
        let r = t.admit(&k, at(70)).unwrap_err();
        assert_eq!(r.retry_after, Duration::from_secs(30));
        // …a window after the third is.
        assert!(t.admit(&k, at(99)).is_err());
        assert!(t.admit(&k, at(100)).is_ok());
    }

    #[test]
    fn a_success_clears_the_name_but_not_the_address() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        // Four failures from one address, two of them on ada.
        fail(&t, &keys("ada", "192.0.2.1"), now).unwrap();
        fail(&t, &keys("ada", "192.0.2.1"), now).unwrap();
        fail(&t, &keys("bob", "192.0.2.1"), now).unwrap();
        fail(&t, &keys("cy", "192.0.2.1"), now).unwrap();
        let k = keys("ada", "192.0.2.1");
        t.admit(&k, now).unwrap();
        t.succeeded(&k);
        // ada starts again: three more failures from elsewhere to lock.
        for _ in 0..2 {
            fail(&t, &keys("ada", "198.51.100.1"), now).unwrap();
        }
        assert!(t.admit(&keys("ada", "198.51.100.2"), now).is_ok());
        // The address kept its four, and not the success: one more locks.
        let locked = fail(&t, &keys("dee", "192.0.2.1"), now).unwrap();
        assert_eq!(
            locked.iter().map(|l| &l.key).collect::<Vec<_>>(),
            [&Key::address(ip("192.0.2.1"))]
        );
        let r = t.admit(&keys("eve", "192.0.2.1"), now).unwrap_err();
        assert_eq!(
            r.sentence(),
            "too many failed sign-ins from 192.0.2.1; try again in 60 seconds"
        );
    }

    #[test]
    fn an_attempt_counts_from_the_moment_it_is_let_in() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        // Three let in and none answered yet: the fourth is refused.
        for _ in 0..3 {
            t.admit(&k, now).unwrap();
        }
        assert!(t.admit(&k, now).is_err());
        // They fail, and the lock is reported once, not three times.
        let reports: usize = (0..3).map(|_| t.failed(&k, now).len()).sum();
        assert_eq!(reports, 1);
    }

    #[test]
    fn an_attempt_that_never_got_an_answer_is_given_back() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        fail(&t, &k, now).unwrap();
        fail(&t, &k, now).unwrap();
        t.admit(&k, now).unwrap();
        t.release(&k);
        assert!(
            t.admit(&k, now).is_ok(),
            "the released attempt still counted"
        );
    }

    #[test]
    fn a_failure_whose_entry_went_meanwhile_starts_it_again() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        let k = keys("ada", "192.0.2.1");
        t.admit(&k, now).unwrap();
        t.admit(&k, now).unwrap();
        // The first succeeds and clears ada; the second then fails.
        t.succeeded(&k);
        assert_eq!(t.failed(&k, now), vec![]);
        fail(&t, &k, now).unwrap();
        assert_eq!(fail(&t, &k, now).unwrap().len(), 1, "1 + 2 is three");
    }

    #[test]
    fn a_name_is_read_the_way_sign_in_reads_it_and_kept_short() {
        assert_eq!(Key::name("  ADA "), Key::name("ada"));
        // Not a valid username: still a key, still lowercased, bounded.
        assert_eq!(Key::name("No/Such"), Key::Name("no/such".into()));
        assert_eq!(Key::name(""), Key::Name(String::new()));
        let Key::Name(long) = Key::name(&"x".repeat(1 << 20)) else {
            unreachable!()
        };
        assert_eq!(long.len(), MAX_NAME_KEY);
        // Cut on a character boundary, not through one.
        let Key::Name(wide) = Key::name(&"é".repeat(100)) else {
            unreachable!()
        };
        assert!(wide.len() <= MAX_NAME_KEY && wide.chars().all(|c| c == 'é'));
    }

    #[test]
    fn an_address_is_what_one_party_controls() {
        assert_eq!(
            Key::address(ip("2001:db8:1:2:aaaa::1")),
            Key::address(ip("2001:db8:1:2:bbbb::9"))
        );
        assert_ne!(
            Key::address(ip("2001:db8:1:2::1")),
            Key::address(ip("2001:db8:1:3::1"))
        );
        assert_eq!(
            Key::address(ip("::ffff:192.0.2.1")),
            Key::address(ip("192.0.2.1"))
        );
        assert_eq!(
            Key::address(ip("2001:db8:1:2::7")).describe(),
            "from 2001:db8:1:2::/64"
        );
    }

    #[test]
    fn a_full_map_makes_room_from_what_is_not_locked() {
        let t = Throttle::new(Policy {
            max_keys: 4,
            ..policy()
        });
        let now = Instant::now();
        // ada locked, and her address three failures in (unlocked); then
        // two names tried once each: four keys, full.
        for _ in 0..3 {
            fail(&t, &keys("ada", "192.0.2.1"), now).unwrap();
        }
        fail(&t, &[Key::name("x1")], now + Duration::from_secs(1)).unwrap();
        fail(&t, &[Key::name("x2")], now + Duration::from_secs(2)).unwrap();
        assert_eq!(t.len(), 4);
        // A new key still counts — three failures lock it — because the
        // oldest unlocked key made room…
        let at = now + Duration::from_secs(3);
        assert_eq!(fail(&t, &[Key::name("x3")], at), Ok(vec![]));
        assert_eq!(fail(&t, &[Key::name("x3")], at), Ok(vec![]));
        assert_eq!(fail(&t, &[Key::name("x3")], at).unwrap().len(), 1);
        assert!(t.admit(&[Key::name("x3")], at).is_err());
        assert_eq!(t.len(), 4);
        // …which was the address (unlocked, oldest), not ada's lock:
        // the address's three failures are forgotten, ada's are not.
        assert!(t.admit(&[Key::name("ada")], at).is_err());
        for _ in 0..4 {
            fail(&t, &[Key::address(ip("192.0.2.1"))], at).unwrap();
        }
        assert!(t.admit(&[Key::address(ip("192.0.2.1"))], at).is_ok());
        // Once every key held is a lock, a new one goes uncounted rather
        // than evicting a lock or refusing everybody.
        let t = Throttle::new(Policy {
            max_keys: 2,
            per_name: 1,
            ..policy()
        });
        fail(&t, &[Key::name("a")], now).unwrap();
        fail(&t, &[Key::name("b")], now).unwrap();
        assert_eq!(fail(&t, &[Key::name("c")], now), Ok(vec![]));
        assert_eq!(t.len(), 2);
        assert!(t.admit(&[Key::name("a")], now).is_err());
        assert!(t.admit(&[Key::name("c")], now).is_ok());
        // Expired entries are what goes first.
        let later = now + Duration::from_secs(61);
        fail(&t, &[Key::name("d")], later).unwrap();
        assert!(t.admit(&[Key::name("d")], later).is_err());
    }

    #[test]
    fn expired_entries_are_swept_as_time_passes() {
        let t = Throttle::new(policy());
        let now = Instant::now();
        for i in 0..50 {
            fail(&t, &[Key::name(&format!("n{i}"))], now).unwrap();
        }
        assert_eq!(t.len(), 50);
        t.admit(&[Key::name("late")], now + Duration::from_secs(61))
            .unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn the_address_is_the_peer_unless_the_proxy_is_trusted() {
        let peer = ip("10.0.0.5");
        let untrusted = policy();
        assert_eq!(
            untrusted.client_address(peer, Some(b"203.0.113.9")),
            peer,
            "a header anybody can write moved the count"
        );
        let trusted = Policy {
            trust_forwarded_for: true,
            ..policy()
        };
        for (line, want) in [
            (&b"203.0.113.9"[..], "203.0.113.9"),
            (b"1.1.1.1, 2.2.2.2, 203.0.113.9", "203.0.113.9"),
            (b"1.1.1.1,203.0.113.9 ", "203.0.113.9"),
            (b"203.0.113.9:4711", "203.0.113.9"),
            (b"2001:db8::1", "2001:db8::1"),
            (b"[2001:db8::1]:443", "2001:db8::1"),
            // A client-written prefix that is not UTF-8 does not hide the
            // entry the proxy appended.
            (b"\xff\xfe, 203.0.113.9", "203.0.113.9"),
            // Nothing readable where the proxy writes: the peer.
            (b"unknown", "10.0.0.5"),
            (b"203.0.113.9, ", "10.0.0.5"),
            (b"", "10.0.0.5"),
        ] {
            assert_eq!(
                trusted.client_address(peer, Some(line)),
                ip(want),
                "{}",
                String::from_utf8_lossy(line)
            );
        }
        assert_eq!(trusted.client_address(peer, None), peer);
    }

    #[test]
    fn the_policy_reads_the_environment_and_refuses_what_it_cannot_read() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(Policy::from_lookup(env(&[])), Ok(Policy::default()));
        assert_eq!(
            Policy::from_lookup(env(&[
                ("SKEIN_LOGIN_MAX_FAILURES", "10"),
                ("SKEIN_LOGIN_MAX_FAILURES_PER_ADDRESS", " 100 "),
                ("SKEIN_LOGIN_WINDOW_SECS", "300"),
                ("SKEIN_TRUST_PROXY_HEADERS", "TRUE"),
            ])),
            Ok(Policy {
                per_name: 10,
                per_address: 100,
                window: Duration::from_secs(300),
                trust_forwarded_for: true,
                ..Policy::default()
            })
        );
        // Empty is unset.
        assert_eq!(
            Policy::from_lookup(env(&[("SKEIN_TRUST_PROXY_HEADERS", "")])),
            Ok(Policy::default())
        );
        for (var, bad) in [
            ("SKEIN_LOGIN_MAX_FAILURES", "0"),
            ("SKEIN_LOGIN_MAX_FAILURES", "five"),
            ("SKEIN_LOGIN_MAX_FAILURES_PER_ADDRESS", "-1"),
            ("SKEIN_LOGIN_WINDOW_SECS", "0"),
            ("SKEIN_LOGIN_WINDOW_SECS", "86401"),
            ("SKEIN_TRUST_PROXY_HEADERS", "ture"),
        ] {
            let err =
                Policy::from_lookup(|k: &str| (k == var).then(|| bad.to_string())).expect_err(bad);
            assert!(err.starts_with(var), "{err}");
            assert!(err.contains(bad), "{err}");
        }
    }

    #[test]
    fn a_wait_is_whole_seconds_rounded_up_and_never_zero() {
        assert_eq!(whole_secs(Duration::from_millis(1)), 1);
        assert_eq!(whole_secs(Duration::ZERO), 1);
        assert_eq!(whole_secs(Duration::from_millis(59_001)), 60);
        assert_eq!(whole_secs(Duration::from_secs(60)), 60);
        let r = Refusal {
            key: Key::name("ada"),
            retry_after: Duration::from_millis(400),
        };
        assert_eq!(
            r.sentence(),
            "too many failed sign-ins for ada; try again in 1 second"
        );
    }

    /// The sentence counts a wait in the unit a person counts it in.
    /// The default lock is fifteen minutes, and "try again in 900
    /// seconds" left somebody who had just mistyped their password doing
    /// arithmetic. Under a minute and a half it stays seconds, where a
    /// minute would round a 61-second wait up to two; past that, whole
    /// minutes, rounded up, so the person is never told to come back
    /// before the lock is gone. `Retry-After` stays in seconds: it is
    /// read by programs.
    #[test]
    fn a_wait_is_said_in_minutes_once_it_is_long_enough_to_count_them() {
        let said = |ms: u64| {
            Refusal {
                key: Key::name("tom"),
                retry_after: Duration::from_millis(ms),
            }
            .sentence()
        };
        for (ms, wait) in [
            (900_000, "15 minutes"),
            (899_500, "15 minutes"),
            (840_001, "15 minutes"),
            (840_000, "14 minutes"),
            (121_000, "3 minutes"),
            (120_000, "2 minutes"),
            (90_000, "2 minutes"),
            (89_000, "89 seconds"),
            (60_000, "60 seconds"),
            (1_000, "1 second"),
        ] {
            assert_eq!(
                said(ms),
                format!("too many failed sign-ins for tom; try again in {wait}"),
                "{ms} ms"
            );
        }
        let r = Refusal {
            key: Key::name("tom"),
            retry_after: Duration::from_secs(900),
        };
        assert_eq!(r.retry_after_secs(), 900, "Retry-After is still seconds");
        // A lock set longer than the default reads the same way, and the
        // singular exists for the unit the rule itself never reaches.
        assert_eq!(wait_in_words(60 * 60), "60 minutes");
        assert_eq!(minutes_in_words(1), "1 minute");
    }
}
