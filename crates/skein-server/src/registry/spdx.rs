//! SPDX licence expressions, parsed and evaluated against a policy.
//!
//! Pure: no database, no network, no clock. Everything the licence gate
//! decides is decided here, so the awkward cases can be argued with in a
//! unit test rather than against a live proxy — which is the same split
//! `workflow::parse` and `review` keep, and for the same reason.
//!
//! ## The grammar, and the part that matters
//!
//! A declared licence is rarely a bare identifier. The three forms that
//! appear on the wire are `MIT`, `MIT OR Apache-2.0`, and
//! `Apache-2.0 WITH LLVM-exception`, with parentheses around any of it.
//!
//! **`OR` admits if *either* side is allowed, and `AND` requires
//! *both*.** That asymmetry is the whole point and it is easy to get
//! backwards. `MIT OR GPL-3.0` under a policy that forbids GPL is
//! **allowed**: the consumer chooses which licence to take it under, and
//! they can choose MIT. `MIT AND GPL-3.0` under the same policy is
//! **refused**: both apply at once and one of them is forbidden.
//!
//! Getting that backwards is not a cosmetic bug. Reading `OR` as `AND`
//! refuses a large share of the npm registry — a great many packages are
//! dual-licensed — and the feature looks broken. Reading `AND` as `OR`
//! silently admits the licence the organization went to the trouble of
//! forbidding.
//!
//! ## What it refuses to guess
//!
//! An expression it cannot parse is [`Verdict::Unknown`], not "allowed"
//! and not "denied". The caller decides what unknown means, per
//! ecosystem, because most container images declare nothing at all and a
//! single global default would either block almost every public image or
//! wave through everything that omits the field.

use std::collections::BTreeMap;

/// What a policy says about one identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Allow,
    Deny,
}

/// An organization's licence policy.
#[derive(Debug, Clone)]
pub struct Policy {
    /// `true` = allow-list: only what is listed may enter.
    /// `false` = deny-list: everything except what is listed.
    ///
    /// Both exist because they are not the same policy. An organization
    /// that has approved four licences wants a fifth to be refused; one
    /// that has banned AGPL wants a licence nobody has heard of to pass.
    pub allow_list: bool,
    /// Case-folded SPDX id → disposition.
    pub rules: BTreeMap<String, Rule>,
}

impl Policy {
    pub fn deny_list(rules: &[(&str, Rule)]) -> Policy {
        Policy {
            allow_list: false,
            rules: rules
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), *v))
                .collect(),
        }
    }

    pub fn allow_list(rules: &[(&str, Rule)]) -> Policy {
        Policy {
            allow_list: true,
            rules: rules
                .iter()
                .map(|(k, v)| (k.to_ascii_lowercase(), *v))
                .collect(),
        }
    }

    /// One identifier's verdict.
    ///
    /// An id nobody named falls to the list's own default: under an
    /// allow-list it is denied, under a deny-list allowed. That is what
    /// makes the two modes different rather than two spellings of one.
    fn admits(&self, id: &str) -> bool {
        match self.rules.get(&id.to_ascii_lowercase()) {
            Some(Rule::Allow) => true,
            Some(Rule::Deny) => false,
            None => !self.allow_list,
        }
    }
}

/// What the gate decided about an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    /// Refused, naming the identifier that did it. The sentence a
    /// developer reads is built from this, so it has to say *which*
    /// licence was the problem rather than repeating the expression.
    Denied(String),
    /// The expression could not be read. Not a refusal: the caller's
    /// per-ecosystem `unknown` disposition decides.
    Unknown,
}

/// The parsed shape. Deliberately small — this is not a general SPDX
/// implementation, and pretending otherwise would invite trusting it
/// with licence *compatibility*, which is a legal question and not one
/// a registry should answer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expr {
    Id(String),
    Or(Box<Expr>, Box<Expr>),
    And(Box<Expr>, Box<Expr>),
}

/// Evaluate `expr` under `policy`.
pub fn evaluate(expr: &str, policy: &Policy) -> Verdict {
    match parse(expr) {
        Some(e) => match check(&e, policy) {
            Ok(()) => Verdict::Allowed,
            Err(id) => Verdict::Denied(id),
        },
        None => Verdict::Unknown,
    }
}

/// `Ok` = admitted; `Err(id)` names the identifier that refused it.
fn check(e: &Expr, policy: &Policy) -> Result<(), String> {
    match e {
        Expr::Id(id) => {
            if policy.admits(id) {
                Ok(())
            } else {
                Err(id.clone())
            }
        }
        // Either side will do — the consumer chooses. Only if *both*
        // are refused is the whole expression refused, and the name
        // reported is the left one, which is the one a reader met first.
        Expr::Or(a, b) => match (check(a, policy), check(b, policy)) {
            (Ok(()), _) | (_, Ok(())) => Ok(()),
            (Err(x), Err(_)) => Err(x),
        },
        // Both apply at once, so one refusal refuses the whole thing.
        Expr::And(a, b) => check(a, policy).and(check(b, policy)),
    }
}

/// Tokens, in the only three shapes this grammar has.
#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Id(String),
    Or,
    And,
    Open,
    Close,
}

/// Tokens, or `None` for anything that is not an SPDX expression.
///
/// One pass, walking whitespace-separated words. `WITH` emits no token
/// of its own and swallows the identifier after it: the policy rules on
/// the licence, not the exception (see the test for why).
fn lex(s: &str) -> Option<Vec<Tok>> {
    let toks = drop_exceptions(s)?;
    if toks.is_empty() {
        return None;
    }
    Some(toks)
}

/// The single pass behind [`lex`].
fn drop_exceptions(s: &str) -> Option<Vec<Tok>> {
    let spaced = s.replace('(', " ( ").replace(')', " ) ");
    let mut out = Vec::new();
    let mut skip = false;
    for w in spaced.split_whitespace() {
        if skip {
            // The exception itself. Anything but a bare identifier here
            // is malformed.
            if !w
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+' || c == '_')
            {
                return None;
            }
            skip = false;
            continue;
        }
        match w.to_ascii_uppercase().as_str() {
            "(" => out.push(Tok::Open),
            ")" => out.push(Tok::Close),
            "OR" => out.push(Tok::Or),
            "AND" => out.push(Tok::And),
            "WITH" => {
                // `WITH` must follow an identifier and precede one.
                if !matches!(out.last(), Some(Tok::Id(_))) {
                    return None;
                }
                skip = true;
            }
            _ => {
                if !w.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '+' || c == '_'
                }) {
                    return None;
                }
                out.push(Tok::Id(w.to_string()));
            }
        }
    }
    if skip {
        return None; // trailing `WITH`
    }
    Some(out)
}

/// `expr := and ( "OR" and )*` — `AND` binds tighter, as SPDX says.
fn parse(s: &str) -> Option<Expr> {
    let toks = lex(s)?;
    let mut at = 0;
    let e = parse_or(&toks, &mut at)?;
    if at != toks.len() {
        return None;
    }
    Some(e)
}

fn parse_or(toks: &[Tok], at: &mut usize) -> Option<Expr> {
    let mut left = parse_and(toks, at)?;
    while matches!(toks.get(*at), Some(Tok::Or)) {
        *at += 1;
        let right = parse_and(toks, at)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_and(toks: &[Tok], at: &mut usize) -> Option<Expr> {
    let mut left = parse_atom(toks, at)?;
    while matches!(toks.get(*at), Some(Tok::And)) {
        *at += 1;
        let right = parse_atom(toks, at)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Some(left)
}

fn parse_atom(toks: &[Tok], at: &mut usize) -> Option<Expr> {
    match toks.get(*at) {
        Some(Tok::Id(id)) => {
            *at += 1;
            Some(Expr::Id(id.clone()))
        }
        Some(Tok::Open) => {
            *at += 1;
            let e = parse_or(toks, at)?;
            if !matches!(toks.get(*at), Some(Tok::Close)) {
                return None;
            }
            *at += 1;
            Some(e)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_gpl() -> Policy {
        Policy::deny_list(&[("GPL-3.0", Rule::Deny), ("AGPL-3.0", Rule::Deny)])
    }

    fn only_permissive() -> Policy {
        Policy::allow_list(&[
            ("MIT", Rule::Allow),
            ("Apache-2.0", Rule::Allow),
            ("ISC", Rule::Allow),
        ])
    }

    #[test]
    fn a_bare_identifier_is_decided_by_the_list_it_is_on() {
        assert_eq!(evaluate("MIT", &no_gpl()), Verdict::Allowed);
        assert_eq!(
            evaluate("GPL-3.0", &no_gpl()),
            Verdict::Denied("GPL-3.0".into())
        );
        // A deny-list admits what nobody named…
        assert_eq!(evaluate("Zlib", &no_gpl()), Verdict::Allowed);
        // …and an allow-list refuses it. That difference is the whole
        // reason both modes exist.
        assert_eq!(
            evaluate("Zlib", &only_permissive()),
            Verdict::Denied("Zlib".into())
        );
        assert_eq!(evaluate("MIT", &only_permissive()), Verdict::Allowed);
    }

    #[test]
    fn identifiers_are_matched_without_regard_to_case() {
        assert_eq!(evaluate("mit", &only_permissive()), Verdict::Allowed);
        assert_eq!(evaluate("Mit", &only_permissive()), Verdict::Allowed);
        assert_eq!(
            evaluate("gpl-3.0", &no_gpl()),
            Verdict::Denied("gpl-3.0".into())
        );
    }

    /// The asymmetry that is the whole point, and the one that is easy
    /// to write backwards.
    ///
    /// `OR` is a choice the consumer makes, so one acceptable side is
    /// enough. `AND` is both at once, so one refusal refuses it all.
    /// Reading `OR` as `AND` would refuse a large share of npm, which
    /// is dual-licensed as a matter of habit; reading `AND` as `OR`
    /// would admit the licence somebody deliberately forbade.
    #[test]
    fn or_admits_on_either_side_and_and_requires_both() {
        let p = no_gpl();
        assert_eq!(evaluate("MIT OR GPL-3.0", &p), Verdict::Allowed);
        assert_eq!(evaluate("GPL-3.0 OR MIT", &p), Verdict::Allowed);
        assert_eq!(
            evaluate("GPL-3.0 OR AGPL-3.0", &p),
            Verdict::Denied("GPL-3.0".into()),
            "neither side is acceptable, so the whole expression is not"
        );

        assert_eq!(
            evaluate("MIT AND GPL-3.0", &p),
            Verdict::Denied("GPL-3.0".into())
        );
        assert_eq!(
            evaluate("GPL-3.0 AND MIT", &p),
            Verdict::Denied("GPL-3.0".into())
        );
        assert_eq!(evaluate("MIT AND ISC", &p), Verdict::Allowed);
    }

    /// `AND` binds tighter than `OR`, as SPDX specifies. Getting the
    /// precedence wrong changes the answer for exactly the expressions
    /// people write when they are being careful.
    #[test]
    fn and_binds_tighter_than_or() {
        let p = no_gpl();
        // (MIT AND GPL) OR ISC → the right side saves it.
        assert_eq!(evaluate("MIT AND GPL-3.0 OR ISC", &p), Verdict::Allowed);
        // Parenthesised the other way, nothing saves it.
        assert_eq!(
            evaluate("MIT AND (GPL-3.0 OR AGPL-3.0)", &p),
            Verdict::Denied("GPL-3.0".into())
        );
        assert_eq!(evaluate("(MIT OR GPL-3.0) AND ISC", &p), Verdict::Allowed);
    }

    /// `WITH` names an exception to a licence. The base identifier is
    /// what the policy rules on; the exception is dropped rather than
    /// treated as a licence of its own, because an organization ruling
    /// on `LLVM-exception` separately is asking a legal question a
    /// registry has no business answering.
    #[test]
    fn with_rules_on_the_licence_not_the_exception() {
        let p = only_permissive();
        assert_eq!(
            evaluate("Apache-2.0 WITH LLVM-exception", &p),
            Verdict::Allowed
        );
        assert_eq!(
            evaluate("GPL-3.0 WITH Classpath-exception-2.0", &no_gpl()),
            Verdict::Denied("GPL-3.0".into())
        );
        assert_eq!(
            evaluate("(Apache-2.0 WITH LLVM-exception) OR MIT", &p),
            Verdict::Allowed
        );
        // The exception must not itself satisfy an allow-list.
        assert_eq!(
            evaluate("GPL-3.0 WITH MIT", &p),
            Verdict::Denied("GPL-3.0".into()),
            "the exception was read as the licence"
        );
    }

    /// Unparseable is `Unknown`, never a verdict. The caller decides
    /// what unknown means per ecosystem — most container images declare
    /// nothing, and one global default would be wrong for somebody.
    /// `WITH` takes an exception identifier, and an identifier is what
    /// it has to be. A parenthesis there is not a malformed licence we
    /// can decide about — it is a document we cannot read, and reading
    /// it as anything else would put a rule's answer on a guess.
    #[test]
    fn with_followed_by_something_that_is_not_an_identifier_is_unreadable() {
        let p = Policy::deny_list(&[("GPL-2.0-only", Rule::Deny)]);
        for bad in ["GPL-2.0-only WITH (Classpath-exception-2.0)", "MIT WITH )"] {
            assert_eq!(evaluate(bad, &p), Verdict::Unknown, "{bad}");
        }
        // …and the well-formed one still decides on the base licence.
        assert!(matches!(
            evaluate("GPL-2.0-only WITH Classpath-exception-2.0", &p),
            Verdict::Denied(_)
        ));
    }

    #[test]
    fn nonsense_is_unknown_rather_than_allowed_or_denied() {
        for bad in [
            "",
            "   ",
            "MIT OR",
            "OR MIT",
            "MIT AND",
            "(MIT",
            "MIT)",
            "()",
            "MIT OR OR ISC",
            "see LICENSE file",
            "MIT; Apache-2.0",
            "MIT WITH",
            "WITH MIT",
            "MIT MIT",
        ] {
            assert_eq!(
                evaluate(bad, &no_gpl()),
                Verdict::Unknown,
                "{bad:?} produced a verdict"
            );
        }
    }

    /// A deny-list that names nothing admits everything; an allow-list
    /// that names nothing admits nothing. Both are legitimate states an
    /// organization can be in, and neither should be a special case.
    #[test]
    fn an_empty_policy_means_what_its_mode_says() {
        let open = Policy::deny_list(&[]);
        let shut = Policy::allow_list(&[]);
        assert_eq!(evaluate("MIT", &open), Verdict::Allowed);
        assert_eq!(evaluate("AGPL-3.0", &open), Verdict::Allowed);
        assert_eq!(evaluate("MIT", &shut), Verdict::Denied("MIT".into()));
    }

    /// An explicit `Allow` row inside an allow-list, and an explicit
    /// `Deny` inside a deny-list, are the ordinary cases; the other two
    /// combinations are an operator overriding their own default and
    /// must work too.
    #[test]
    fn an_explicit_rule_beats_the_lists_default_in_both_directions() {
        let mostly_open = Policy::deny_list(&[("MIT", Rule::Deny)]);
        assert_eq!(
            evaluate("MIT", &mostly_open),
            Verdict::Denied("MIT".into()),
            "a deny-list did not honour an explicit deny"
        );
        let mostly_shut = Policy::allow_list(&[("MIT", Rule::Allow), ("GPL-3.0", Rule::Deny)]);
        assert_eq!(evaluate("MIT", &mostly_shut), Verdict::Allowed);
        assert_eq!(
            evaluate("GPL-3.0", &mostly_shut),
            Verdict::Denied("GPL-3.0".into())
        );
    }

    #[test]
    fn whitespace_and_parentheses_do_not_change_the_answer() {
        let p = no_gpl();
        for same in [
            "MIT OR Apache-2.0",
            "  MIT   OR   Apache-2.0  ",
            "(MIT OR Apache-2.0)",
            "((MIT) OR (Apache-2.0))",
        ] {
            assert_eq!(evaluate(same, &p), Verdict::Allowed, "{same:?}");
        }
    }
}
