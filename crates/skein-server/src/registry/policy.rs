//! The admission decision: may this package enter, and what happens if
//! not.
//!
//! Pure — no database, no network, no clock. The caller supplies the
//! facts and the time; this decides. That is what lets the awkward
//! combinations be argued with in a unit test instead of against a live
//! upstream, and it is why [`decide`] takes `now_ms` rather than reading
//! the clock itself.
//!
//! ## Three questions, kept apart
//!
//! They get conflated and they fail differently:
//!
//! 1. **May this name enter at all?** A reserved namespace is never
//!    proxied. This closes the hole "private always wins" leaves open:
//!    that rule protects a name the organization has *already
//!    published*, so if somebody registers `@acme/new-service` upstream
//!    first, a build asking for it gets theirs.
//! 2. **May this version enter?** The licence, and the cooldown.
//! 3. **What happens when it may not?** `audit` records and serves;
//!    `block` refuses.
//!
//! ## Why the order is reserved → cooldown → licence
//!
//! Each refusal should name the most actionable thing. A reserved
//! namespace is a configuration fact the developer can do nothing about
//! and an admin can fix in a second; a cooldown is a wait; a licence is
//! a decision. Reporting the licence problem with a package that was
//! never going to be fetched anyway sends somebody to argue about
//! licensing when the answer was "that is our own scope".

use super::spdx::{self, Verdict};

/// What the organization has decided.
pub struct Admission<'a> {
    /// Refuse rather than record.
    pub blocking: bool,
    /// Upstream versions younger than this are not served. `0` disables.
    pub cooldown_days: i64,
    /// Normalised name prefixes this organization has claimed.
    pub reserved: &'a [String],
    pub licences: &'a spdx::Policy,
    /// What to do when the licence cannot be read. Per ecosystem,
    /// because most container images declare nothing.
    pub unknown_allowed: bool,
}

/// What is known about the version being admitted.
pub struct Candidate<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// The declared SPDX expression, if there was one.
    pub licence: Option<&'a str>,
    /// When the upstream published it, in epoch milliseconds. `None`
    /// when the upstream did not say — which is not the same as "old".
    pub published_at: Option<i64>,
}

/// Which rule decided, for the findings table and the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Reserved,
    Cooldown,
    Licence,
}

impl Rule {
    pub fn as_str(self) -> &'static str {
        match self {
            Rule::Reserved => "reserved",
            Rule::Cooldown => "cooldown",
            Rule::Licence => "license",
        }
    }
}

/// The answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Admit,
    /// Refused, or recorded-and-served under `audit`. `blocked` is what
    /// the caller does; `rule` and `reason` are what it writes down.
    Refuse {
        blocked: bool,
        rule: Rule,
        reason: String,
    },
}

impl Decision {
    /// Whether the bytes are actually withheld. In audit mode a refusal
    /// is recorded and the package is served anyway — which is the
    /// whole point of audit mode.
    pub fn withholds(&self) -> bool {
        matches!(self, Decision::Refuse { blocked: true, .. })
    }
}

/// Whether `pattern` covers `name`, on a segment boundary.
///
/// `@acme` covers `@acme/widget` and does **not** cover `@acmecorp/x`.
/// A bare substring match would be the more obvious implementation and
/// would reserve half the registry by accident: an organization
/// claiming `@ac` would silently take `@acme` too.
pub fn namespace_covers(pattern: &str, name: &str) -> bool {
    let p = pattern.trim_end_matches(['/', '.', ':']);
    if p.is_empty() {
        return false;
    }
    if !name.starts_with(p) {
        return false;
    }
    match name[p.len()..].chars().next() {
        // An exact match is covered.
        None => true,
        // Otherwise the next character must be a separator, so the
        // pattern named a whole segment.
        Some(c) => c == '/' || c == '.' || c == ':' || c == '-',
    }
}

/// Days between `then` and `now`, floored. Negative spans are zero: an
/// upstream whose clock is ahead of ours has published something "in
/// the future", and treating that as infinitely old would wave it
/// straight through the cooldown that exists to catch it.
fn days_since(then_ms: i64, now_ms: i64) -> i64 {
    const DAY: i64 = 86_400_000;
    (now_ms.saturating_sub(then_ms) / DAY).max(0)
}

/// Decide.
pub fn decide(a: &Admission<'_>, c: &Candidate<'_>, now_ms: i64) -> Decision {
    let refuse = |rule: Rule, reason: String| Decision::Refuse {
        blocked: a.blocking,
        rule,
        reason,
    };

    // 1. A name this organization has claimed is never fetched from
    //    anywhere else, whatever its licence and however old it is.
    if let Some(p) = a.reserved.iter().find(|p| namespace_covers(p, c.name)) {
        return refuse(
            Rule::Reserved,
            format!(
                "{:?} is inside {p:?}, a namespace this organization has reserved — it is \
                 never fetched from an upstream registry. Publish it here, or release the \
                 reservation.",
                c.name
            ),
        );
    }

    // 2. Too new to trust. Before the licence, because waiting is a
    //    smaller ask than a licence argument and the wait applies
    //    whatever the licence turns out to be.
    if a.cooldown_days > 0 {
        if let Some(published) = c.published_at {
            let age = days_since(published, now_ms);
            if age < a.cooldown_days {
                return refuse(
                    Rule::Cooldown,
                    format!(
                        "{} {} was published upstream {} ago and this organization waits \
                         {} days before serving a new release. Nearly every compromised \
                         release is withdrawn inside that window.",
                        c.name,
                        c.version,
                        if age == 0 {
                            "less than a day".to_string()
                        } else if age == 1 {
                            "1 day".to_string()
                        } else {
                            format!("{age} days")
                        },
                        a.cooldown_days
                    ),
                );
            }
        }
        // An upstream that does not say when it published is **not**
        // held: the cooldown is a claim about age, and refusing
        // everything whose age is unknown would switch off a registry
        // rather than filter it. The licence gate still applies.
    }

    // 3. The licence.
    match c.licence.map(|l| spdx::evaluate(l, a.licences)) {
        Some(Verdict::Allowed) => Decision::Admit,
        Some(Verdict::Denied(id)) => refuse(
            Rule::Licence,
            format!(
                "{} {} is licensed {} and this organization does not admit {id}.",
                c.name,
                c.version,
                c.licence.unwrap_or("")
            ),
        ),
        // Declared but unreadable, or not declared at all: the same
        // situation from the policy's point of view, and the same
        // per-ecosystem disposition decides.
        Some(Verdict::Unknown) | None => {
            if a.unknown_allowed {
                Decision::Admit
            } else {
                refuse(
                    Rule::Licence,
                    match c.licence {
                        Some(l) => format!(
                            "{} {} declares a licence this registry cannot read ({l:?}), and \
                             this organization does not admit packages whose licence is \
                             unknown.",
                            c.name, c.version
                        ),
                        None => format!(
                            "{} {} declares no licence, and this organization does not admit \
                             packages whose licence is unknown.",
                            c.name, c.version
                        ),
                    },
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::spdx::{Policy, Rule as LicRule};

    const DAY: i64 = 86_400_000;
    const NOW: i64 = 1_757_000_000_000;

    fn open() -> Policy {
        Policy::deny_list(&[("GPL-3.0", LicRule::Deny)])
    }

    fn admission<'a>(reserved: &'a [String], licences: &'a Policy) -> Admission<'a> {
        Admission {
            blocking: true,
            cooldown_days: 0,
            reserved,
            licences,
            unknown_allowed: true,
        }
    }

    fn candidate<'a>(name: &'a str, licence: Option<&'a str>) -> Candidate<'a> {
        Candidate {
            name,
            version: "1.0.0",
            licence,
            published_at: Some(NOW - 30 * DAY),
        }
    }

    /// The reservation closes the hole "private always wins" leaves: it
    /// protects a name we have already published, and this protects one
    /// we have not.
    #[test]
    fn a_reserved_namespace_is_never_fetched_from_upstream() {
        let reserved = vec!["@acme".to_string()];
        let lic = open();
        let a = admission(&reserved, &lic);

        let d = decide(&a, &candidate("@acme/not-published-yet", Some("MIT")), NOW);
        assert!(d.withholds(), "{d:?}");
        match d {
            Decision::Refuse { rule, reason, .. } => {
                assert_eq!(rule, Rule::Reserved);
                assert!(reason.contains("@acme"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        // A name outside it is ordinary.
        assert_eq!(
            decide(&a, &candidate("lodash", Some("MIT")), NOW),
            Decision::Admit
        );
    }

    /// A prefix covers a whole segment, never a bare substring. An
    /// organization claiming `@ac` must not silently take `@acme`.
    #[test]
    fn a_namespace_covers_segments_and_not_substrings() {
        assert!(namespace_covers("@acme", "@acme/widget"));
        assert!(namespace_covers("@acme", "@acme"));
        assert!(namespace_covers("com.acme", "com.acme.widget"));
        assert!(namespace_covers("com.acme", "com.acme:widget"));
        assert!(namespace_covers("acme", "acme-utils"));

        assert!(!namespace_covers("@ac", "@acme/widget"));
        assert!(!namespace_covers("@acme", "@acmecorp/widget"));
        assert!(!namespace_covers("acme", "notacme/x"));
        assert!(!namespace_covers("", "anything"));
        assert!(!namespace_covers("/", "anything"));
        // A trailing separator on the pattern is the same pattern.
        assert!(namespace_covers("@acme/", "@acme/widget"));
    }

    /// The cooldown is the control that actually catches a compromised
    /// release, so the boundary is pinned exactly: younger than N days
    /// is held, N days old is served.
    #[test]
    fn the_cooldown_holds_a_release_until_it_is_old_enough() {
        let reserved: Vec<String> = Vec::new();
        let lic = open();
        let mut a = admission(&reserved, &lic);
        a.cooldown_days = 3;

        let at = |age_days: i64| Candidate {
            name: "left-pad",
            version: "1.0.0",
            licence: Some("MIT"),
            published_at: Some(NOW - age_days * DAY),
        };
        assert!(decide(&a, &at(0), NOW).withholds(), "published today");
        assert!(decide(&a, &at(2), NOW).withholds(), "two days old");
        // The sentence a person reads is the whole of what a refusal
        // is, and its three shapes are "less than a day", "1 day" and
        // "N days". The middle one is a separate branch precisely
        // because "1 days" reads as a bug in the product.
        for (age, phrase) in [(0, "less than a day"), (1, "1 day"), (2, "2 days")] {
            match decide(&a, &at(age), NOW) {
                Decision::Refuse { reason, .. } => {
                    assert!(reason.contains(phrase), "{age} days old: {reason}")
                }
                other => panic!("{age} days old was admitted: {other:?}"),
            }
        }
        assert_eq!(
            decide(&a, &at(3), NOW),
            Decision::Admit,
            "exactly the window"
        );
        assert_eq!(decide(&a, &at(30), NOW), Decision::Admit);

        // Zero disables it entirely.
        a.cooldown_days = 0;
        assert_eq!(decide(&a, &at(0), NOW), Decision::Admit);
    }

    /// An upstream whose clock is ahead of ours publishes "in the
    /// future". Treating that as infinitely old would wave straight
    /// through the release the cooldown exists to catch.
    #[test]
    fn a_release_dated_in_the_future_is_still_too_new() {
        let reserved: Vec<String> = Vec::new();
        let lic = open();
        let mut a = admission(&reserved, &lic);
        a.cooldown_days = 3;
        let future = Candidate {
            name: "left-pad",
            version: "1.0.0",
            licence: Some("MIT"),
            published_at: Some(NOW + 10 * DAY),
        };
        assert!(decide(&a, &future, NOW).withholds());
    }

    /// An upstream that does not say when it published is not held. The
    /// cooldown is a claim about age; refusing everything whose age is
    /// unknown switches a registry off rather than filtering it.
    #[test]
    fn a_release_with_no_date_is_not_held_by_the_cooldown() {
        let reserved: Vec<String> = Vec::new();
        let lic = open();
        let mut a = admission(&reserved, &lic);
        a.cooldown_days = 30;
        let undated = Candidate {
            name: "left-pad",
            version: "1.0.0",
            licence: Some("MIT"),
            published_at: None,
        };
        assert_eq!(decide(&a, &undated, NOW), Decision::Admit);
    }

    #[test]
    fn a_forbidden_licence_is_refused_and_the_reason_names_it() {
        let reserved: Vec<String> = Vec::new();
        let lic = open();
        let a = admission(&reserved, &lic);
        match decide(&a, &candidate("copyleft-thing", Some("GPL-3.0")), NOW) {
            Decision::Refuse { rule, reason, .. } => {
                assert_eq!(rule, Rule::Licence);
                assert!(reason.contains("GPL-3.0"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        // Dual-licensed is admitted: the consumer takes the MIT side.
        assert_eq!(
            decide(&a, &candidate("dual", Some("MIT OR GPL-3.0")), NOW),
            Decision::Admit
        );
    }

    /// Per ecosystem, because most container images declare nothing and
    /// one global default is wrong for somebody either way.
    #[test]
    fn an_unreadable_or_absent_licence_follows_the_unknown_disposition() {
        let reserved: Vec<String> = Vec::new();
        let lic = open();
        let mut a = admission(&reserved, &lic);

        a.unknown_allowed = true;
        assert_eq!(decide(&a, &candidate("x", None), NOW), Decision::Admit);
        assert_eq!(
            decide(&a, &candidate("x", Some("see LICENSE")), NOW),
            Decision::Admit
        );

        a.unknown_allowed = false;
        let absent = decide(&a, &candidate("x", None), NOW);
        assert!(absent.withholds());
        match absent {
            Decision::Refuse { reason, .. } => assert!(reason.contains("no licence"), "{reason}"),
            other => panic!("{other:?}"),
        }
        // Unreadable says so differently from absent — a maintainer who
        // wrote something needs to know it was not understood.
        match decide(&a, &candidate("x", Some("see LICENSE")), NOW) {
            Decision::Refuse { reason, .. } => {
                assert!(reason.contains("cannot read"), "{reason}")
            }
            other => panic!("{other:?}"),
        }
    }

    /// Audit mode records the same verdict and serves anyway. This is
    /// the difference between a policy an organization can adopt and one
    /// it switches off after the first red build.
    #[test]
    fn audit_mode_reaches_the_same_verdict_and_withholds_nothing() {
        let reserved = vec!["@acme".to_string()];
        let lic = open();
        let mut a = admission(&reserved, &lic);
        a.blocking = false;

        for c in [
            candidate("@acme/x", Some("MIT")),
            candidate("y", Some("GPL-3.0")),
        ] {
            match decide(&a, &c, NOW) {
                Decision::Refuse { blocked, .. } => {
                    assert!(!blocked, "audit mode withheld {}", c.name)
                }
                other => panic!("audit mode admitted {}: {other:?}", c.name),
            }
        }
        // And something acceptable is still simply admitted.
        assert_eq!(
            decide(&a, &candidate("z", Some("MIT")), NOW),
            Decision::Admit
        );
    }

    /// Ordering: the most actionable refusal wins. A reserved name
    /// reports the reservation even when its licence is also forbidden
    /// and it is also too new — arguing about the licence of a package
    /// that was never going to be fetched wastes everybody's afternoon.
    #[test]
    fn the_first_refusal_is_the_most_actionable_one() {
        let reserved = vec!["@acme".to_string()];
        let lic = open();
        let mut a = admission(&reserved, &lic);
        a.cooldown_days = 30;

        let all_wrong = Candidate {
            name: "@acme/x",
            version: "1.0.0",
            licence: Some("GPL-3.0"),
            published_at: Some(NOW),
        };
        match decide(&a, &all_wrong, NOW) {
            Decision::Refuse { rule, .. } => assert_eq!(rule, Rule::Reserved),
            other => panic!("{other:?}"),
        }

        // Without the reservation, the wait is reported before the
        // licence: it applies whatever the licence turns out to be.
        let no_reservation: Vec<String> = Vec::new();
        let b = Admission {
            reserved: &no_reservation,
            ..a
        };
        match decide(&b, &all_wrong, NOW) {
            Decision::Refuse { rule, .. } => assert_eq!(rule, Rule::Cooldown),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_rule_has_a_stable_name_for_the_findings_table() {
        assert_eq!(Rule::Reserved.as_str(), "reserved");
        assert_eq!(Rule::Cooldown.as_str(), "cooldown");
        assert_eq!(Rule::Licence.as_str(), "license");
    }
}
