//! Fetching from a public registry, and the two rules that make it
//! safe.
//!
//! ## Private always wins, and the proxy is never asked about a name we
//! own
//!
//! The order in the npm door is: look locally, and go
//! upstream only for a name this organization has never published and
//! has not reserved. Anything else builds dependency confusion into the
//! product — a public `@acme/widget` could answer for the private one,
//! and a build would install a stranger's bytes under our own scope.
//!
//! ## Filter the metadata document, do not pass it through
//!
//! npm's packument lists every version. Proxied unfiltered, a client
//! resolves to a version the gate will then refuse at tarball fetch, and
//! that reads as a broken registry rather than as a policy decision. So
//! the licence and the cooldown are evaluated **per version, at metadata
//! time**, the document is rewritten to the admissible versions, and the
//! blob fetch re-checks as defence in depth. Packages relicense between
//! versions, so this cannot be done per package.
//!
//! ## Hermetic by construction, and trusted in two halves
//!
//! The network lives behind [`Upstream`]. The suite supplies a fake; no
//! test reaches npmjs, and `SKEIN_UPSTREAM_NPM` points the real
//! implementation somewhere else when one does.
//!
//! Two halves, trusted differently:
//!
//! - **The base is not attacker-supplied.** It comes from the process
//!   environment, so the only actor who can aim it at `169.254.169.254`
//!   is the one who runs the server. It is still worth refusing an
//!   obviously wrong base, so [`check_base`] does — plain http to a
//!   public address, or a name inside a private network — but it admits
//!   loopback, because a mirror sidecar on the same host is a real
//!   deployment and it is what the test fake is. A self-hosted install
//!   that fronts an internal mirror (Nexus, Artifactory, Verdaccio on
//!   `10.x`) says so with `SKEIN_UPSTREAM_ALLOW_PRIVATE=true`: an
//!   explicit decision rather than a guard nobody can pass.
//! - **A tarball URL is attacker-supplied.** It comes out of the
//!   upstream's own document, so a compromised or merely mischievous
//!   packument could have this server fetch a stranger's bytes and store
//!   them under a name somebody trusts. So a fetched URL must be
//!   **same-origin with the configured base**. That refuses the
//!   link-local case an SSRF guard is for *and* the redirect-to-anywhere
//!   case an SSRF guard never covered.
//!
//! The honest limit: same-origin means an upstream that serves its
//! artifacts from a separate CDN host cannot be proxied as-is. npmjs
//! serves `dist.tarball` from `registry.npmjs.org`, and so does every
//! Artifactory and Nexus mirror, so this costs nothing today — but it
//! is a real constraint and it belongs in the release notes rather than
//! in somebody's afternoon.

use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// What an upstream registry can be asked.
///
/// Two calls, because that is all a pull-through needs: the metadata
/// document for a name, and the bytes of one artifact.
pub trait Upstream: Send + Sync {
    /// The metadata document, or `None` for a name the upstream does
    /// not have. An error is a transport failure, which is a different
    /// thing and must not read as "absent".
    fn metadata(&self, name: &str) -> Result<Option<Vec<u8>>, String>;
    /// One artifact's bytes, by the URL the metadata named.
    fn fetch(&self, url: &str) -> Result<Vec<u8>, String>;
}

/// The real one: npmjs, or whatever `SKEIN_UPSTREAM_NPM` names.
pub struct Http {
    base: String,
    timeout: Duration,
    /// Whether a base inside a private network is admitted — an
    /// operator's explicit decision, `SKEIN_UPSTREAM_ALLOW_PRIVATE`.
    allow_private: bool,
}

impl Http {
    /// Construction is pure: it records the base and resolves nothing.
    ///
    /// The SSRF guard runs at the outbound moment instead, in
    /// [`Http::metadata`] and [`Http::fetch`]. Guarding here would mean
    /// resolving DNS to build the struct — a network call in a
    /// constructor, which makes the type impossible to use in a
    /// hermetic test and re-checks nothing about the URL that is
    /// actually fetched. `fetch` takes a URL out of the upstream's own
    /// document, so the check has to be there in any case.
    pub fn new(base: &str) -> Http {
        Http {
            base: base.trim().trim_end_matches('/').to_string(),
            timeout: Duration::from_secs(30),
            allow_private: false,
        }
    }

    /// Admit a base inside a private network: an internal mirror.
    pub fn allowing_private(mut self, allow: bool) -> Http {
        self.allow_private = allow;
        self
    }

    /// The default upstream for an ecosystem, overridable for tests and
    /// for a deployment that fronts its own mirror.
    pub fn for_ecosystem(eco: &str) -> Option<Http> {
        let var = format!("SKEIN_UPSTREAM_{}", eco.to_ascii_uppercase());
        let allow_private = matches!(
            std::env::var("SKEIN_UPSTREAM_ALLOW_PRIVATE").as_deref(),
            Ok("1" | "true" | "yes")
        );
        let base = std::env::var(&var)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| match eco {
                "npm" => Some("https://registry.npmjs.org".to_string()),
                // The others arrive with their adapters. Returning
                // `None` rather than guessing a URL means an ecosystem
                // whose proxy is not built yet simply does not proxy.
                _ => None,
            })?;
        Some(Http::new(&base).allowing_private(allow_private))
    }
}

/// `(scheme, host, port)`, lowercased and with the default port filled
/// in, so two spellings of one origin compare equal.
fn origin_of(url: &str) -> Option<(String, String, u16)> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.trim().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let default = if scheme == "https" { 443 } else { 80 };
    // An IPv6 literal is bracketed, and its colons are not port
    // separators. Splitting on the last colon without this reads
    // `[::1]` as host `[:` port `1]`, which parses as neither and
    // silently becomes a different origin.
    let (host, port) = if let Some(end) = authority.strip_prefix('[') {
        let (inner, tail) = end.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if tail.is_empty() => default,
            None => return None,
        };
        (inner.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host.to_ascii_lowercase(), port))
}

/// Is every address this host resolves to loopback?
///
/// All of them, not any: a name that resolves to loopback *and* to a
/// public address would otherwise be admitted as a sidecar and then
/// connected to somewhere else entirely, which is the classic rebinding
/// shape.
fn resolves_only_to_loopback(host: &str, port: u16) -> bool {
    match (host, port).to_socket_addrs() {
        Ok(addrs) => {
            let addrs: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            !addrs.is_empty() && addrs.iter().all(|a| a.is_loopback())
        }
        Err(_) => false,
    }
}

/// Refuse a base nobody could have meant.
///
/// Plain http is admitted only for a loopback base, which is a mirror
/// sidecar on this host and is also what the test fake is; everything
/// else must be TLS, because an upstream reached in clear is one anybody
/// on the path can substitute a package into. A private-network address
/// is admitted only when the operator said so (`allow_private`).
fn check_base(base: &str, allow_private: bool) -> Result<(String, String, u16), String> {
    let Some((scheme, host, port)) = origin_of(base) else {
        return Err(format!("{base:?} is not a registry URL"));
    };
    if resolves_only_to_loopback(&host, port) {
        return Ok((scheme, host, port));
    }
    if scheme != "https" {
        return Err(format!(
            "{base:?} is not https — an upstream registry reached in clear is one \
             anybody on the path can substitute a package into"
        ));
    }
    // A public name, resolved once. Anything inside a private network
    // is refused: a base that resolves to the metadata service is a
    // misconfiguration worth failing loudly on even though the actor
    // who could set it already owns this process.
    let addrs: Vec<IpAddr> = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|_| format!("could not resolve {host}"))?
        .map(|a| a.ip())
        .collect();
    if addrs.is_empty() {
        return Err(format!("could not resolve {host}"));
    }
    if !allow_private && addrs.iter().any(|a| !a.is_global_enough()) {
        return Err(format!(
            "{host} resolves to an address inside a private network — set \
             SKEIN_UPSTREAM_ALLOW_PRIVATE=true if it is an internal mirror you meant"
        ));
    }
    Ok((scheme, host, port))
}

/// Not `IpAddr::is_global` — that is still unstable. Loopback is in the
/// set, but `check_base` has already decided about it.
trait GlobalEnough {
    fn is_global_enough(&self) -> bool;
}

impl GlobalEnough for IpAddr {
    fn is_global_enough(&self) -> bool {
        match self {
            IpAddr::V4(v4) => {
                !(v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
                    || v4.is_multicast()
                    || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                    || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
                    || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                    || v4.octets()[0] >= 240)
            }
            IpAddr::V6(v6) => {
                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    || v6
                        .to_ipv4_mapped()
                        .is_some_and(|v4| !IpAddr::V4(v4).is_global_enough()))
            }
        }
    }
}

impl Upstream for Http {
    fn metadata(&self, name: &str) -> Result<Option<Vec<u8>>, String> {
        // Checked here rather than at construction: this is the moment a
        // packet would leave, and construction has to stay pure so the
        // type is usable in a hermetic test.
        check_base(&self.base, self.allow_private)?;
        // The name is already normalised and validated by
        // `packages::normalize_name`; percent-encode the scope's slash
        // because that is how every npm client addresses one.
        let path = name.replace('/', "%2f");
        let url = format!("{}/{path}", self.base);
        match ureq::get(&url).timeout(self.timeout).call() {
            Ok(resp) => {
                let mut out = Vec::new();
                std::io::Read::read_to_end(&mut resp.into_reader(), &mut out)
                    .map_err(|e| format!("upstream {url}: {e}"))?;
                Ok(Some(out))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(format!("upstream {url}: {e}")),
        }
    }

    fn fetch(&self, url: &str) -> Result<Vec<u8>, String> {
        // A tarball URL comes out of the upstream's own document, so it
        // is exactly as untrusted as the document. It must name the
        // origin we configured and nothing else: that refuses the
        // link-local address an SSRF guard would catch *and* the
        // `https://evil.example/x.tgz` it would wave straight through,
        // which is the one that ends with a stranger's bytes stored
        // under a name somebody trusts.
        let base = check_base(&self.base, self.allow_private)?;
        if origin_of(url).as_ref() != Some(&base) {
            return Err(format!(
                "{url} is not on the configured upstream registry ({}://{}:{})",
                base.0, base.1, base.2
            ));
        }
        let resp = ureq::get(url)
            .timeout(self.timeout)
            .call()
            .map_err(|e| format!("upstream {url}: {e}"))?;
        let mut out = Vec::new();
        std::io::Read::read_to_end(&mut resp.into_reader(), &mut out)
            .map_err(|e| format!("upstream {url}: {e}"))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A base nobody could have meant is refused, and refused
    /// *without a packet leaving* — which is also what keeps this test
    /// hermetic.
    #[test]
    fn a_base_that_is_not_a_registry_is_refused_before_anything_is_sent() {
        for hostile in [
            // Inside the network, and not loopback: the metadata
            // service and a private subnet.
            "http://169.254.169.254/latest/meta-data",
            "https://169.254.169.254/latest/meta-data",
            "http://10.0.0.5",
            "https://10.0.0.5",
            // Not a URL at all, or not one we speak.
            "file:///etc/passwd",
            "not a url",
            "https://",
            "://nohost",
            // Credentials in the authority: a base nobody configures on
            // purpose, and a shape that makes the origin comparison in
            // `fetch` ambiguous.
            "https://user:pw@registry.npmjs.org",
            // Plain http to a public address. An upstream reached in
            // clear is one anybody on the path can substitute a package
            // into.
            "http://registry.npmjs.org",
        ] {
            let up = Http::new(hostile);
            assert!(
                up.metadata("lodash").is_err(),
                "{hostile:?} was fetched from"
            );
            assert!(up.fetch(hostile).is_err(), "{hostile:?} was fetched from");
        }
    }

    /// Loopback is admitted **deliberately**, and this pins the
    /// decision rather than leaving it as an accident of the checks
    /// above. A mirror sidecar on the same host is a real deployment,
    /// and it is what the suite's fake upstream is. The actor who can
    /// set this variable runs the server, so refusing loopback would
    /// cost a legitimate configuration and buy nothing.
    #[test]
    fn a_loopback_base_is_admitted_because_a_mirror_sidecar_is_one() {
        for local in [
            "http://127.0.0.1:9000",
            "http://localhost/registry",
            "http://[::1]:8080",
        ] {
            assert!(
                check_base(local, false).is_ok(),
                "{local:?} was refused, and a sidecar mirror is a real deployment"
            );
        }
    }

    /// An internal mirror is admitted only when the operator said so, and
    /// even then it must be TLS: the opt-in widens *where* the upstream
    /// may be, not *how* it may be reached.
    #[test]
    fn a_private_mirror_needs_the_operators_say_so_and_still_needs_tls() {
        assert!(check_base("https://10.0.0.5", false).is_err());
        assert!(check_base("https://10.0.0.5", true).is_ok());
        assert!(
            check_base("https://169.254.169.254", true).is_ok(),
            "the operator's call"
        );
        assert!(check_base("http://10.0.0.5", true).is_err(), "still TLS");
        let err = check_base("https://10.0.0.5", false).unwrap_err();
        assert!(err.contains("SKEIN_UPSTREAM_ALLOW_PRIVATE"), "{err}");
        let up = Http::new("https://10.0.0.5").allowing_private(true);
        assert!(up.allow_private);
    }

    /// The half that really is attacker-supplied. A tarball URL comes
    /// out of the upstream's own document, so it must name the origin
    /// we configured and nothing else.
    ///
    /// The second group is the case an ordinary SSRF guard misses
    /// entirely: `https://evil.example/x.tgz` is a public address, so it
    /// is not SSRF — it is a compromised packument having this server
    /// fetch a stranger's bytes and store them under a name somebody
    /// trusts.
    #[test]
    fn a_tarball_url_must_name_the_origin_we_configured() {
        let up = Http::new("https://registry.npmjs.org");
        for inside in [
            "http://169.254.169.254/latest/meta-data",
            "http://127.0.0.1:9000/x.tgz",
            "http://10.0.0.5/x.tgz",
        ] {
            assert!(up.fetch(inside).is_err(), "{inside} was fetched");
        }
        for elsewhere in [
            "https://evil.example/lodash-1.0.0.tgz",
            // The right host, the wrong scheme and the wrong port: both
            // are part of an origin.
            "http://registry.npmjs.org/lodash/-/lodash-1.0.0.tgz",
            "https://registry.npmjs.org:8443/lodash/-/lodash-1.0.0.tgz",
            // A near-miss hostname, which a `starts_with` or `contains`
            // comparison would admit.
            "https://registry.npmjs.org.evil.example/x.tgz",
            "https://notregistry.npmjs.org/x.tgz",
        ] {
            assert!(up.fetch(elsewhere).is_err(), "{elsewhere} was fetched");
        }
    }

    /// Two spellings of one origin are one origin — otherwise a
    /// registry whose document names the default port explicitly, or
    /// spells its host in capitals, would have every artifact refused.
    #[test]
    fn an_origin_compares_the_same_however_it_is_spelled() {
        let canonical = origin_of("https://registry.npmjs.org").expect("an origin");
        for same in [
            "https://registry.npmjs.org:443/lodash",
            "https://REGISTRY.NPMJS.ORG/lodash/-/lodash-1.0.0.tgz",
            "HTTPS://registry.npmjs.org/x?y=1",
            "https://registry.npmjs.org#frag",
        ] {
            assert_eq!(origin_of(same), Some(canonical.clone()), "{same}");
        }
        // An IPv6 literal's colons are not port separators. Read
        // naively, `[::1]` becomes host `[:` and port `1]` — neither
        // parses, and the origin silently becomes something else.
        assert_eq!(
            origin_of("http://[::1]/x"),
            Some(("http".into(), "::1".into(), 80))
        );
        assert_eq!(
            origin_of("http://[::1]:8080/x"),
            Some(("http".into(), "::1".into(), 8080))
        );
        assert_eq!(origin_of("http://[::1]junk/x"), None);
        assert_eq!(origin_of("http://host:not-a-port/x"), None);
    }

    /// An authority that is not one. Each of these gets past the
    /// scheme check and has to be refused on its own shape, which is
    /// the part a looser parser would let through.
    #[test]
    fn an_authority_that_is_not_one_has_no_origin() {
        // Empty host after a port separator.
        assert_eq!(origin_of("https://:443/x"), None);
        // A name that resolves to nothing.
        assert!(check_base("https://skein-no-such-host.invalid", false).is_err());
    }

    /// IPv6, which the `is_global_enough` set has to judge on its own
    /// terms: loopback, unspecified, multicast, unique-local,
    /// link-local, and an IPv4 address wearing a v6 hat — that last is
    /// the one a naive check misses, and `::ffff:10.0.0.5` is a private
    /// address however it is spelled.
    #[test]
    fn an_ipv6_address_is_judged_by_what_it_actually_addresses() {
        use std::net::Ipv6Addr;
        let bad: [Ipv6Addr; 6] = [
            "::1".parse().unwrap(),
            "::".parse().unwrap(),
            "ff02::1".parse().unwrap(),
            "fc00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            // An IPv4-mapped private address.
            "::ffff:10.0.0.5".parse().unwrap(),
        ];
        for a in bad {
            assert!(
                !IpAddr::V6(a).is_global_enough(),
                "{a} was treated as a public address"
            );
        }
        let good: Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
        assert!(IpAddr::V6(good).is_global_enough());
        // …and an IPv4-mapped *public* address is still public.
        let mapped: Ipv6Addr = "::ffff:1.1.1.1".parse().unwrap();
        assert!(IpAddr::V6(mapped).is_global_enough());
    }

    /// A host that does not resolve is not loopback either, and the
    /// two answers are different: one is "this is a sidecar", the other
    /// is "this is nothing".
    #[test]
    fn a_host_that_does_not_resolve_is_not_loopback() {
        assert!(!resolves_only_to_loopback(
            "skein-no-such-host.invalid",
            443
        ));
    }

    #[test]
    fn construction_is_pure_and_ignores_a_trailing_slash() {
        assert_eq!(
            Http::new("https://registry.npmjs.org/").base,
            Http::new("  https://registry.npmjs.org  ").base
        );
    }

    /// An ecosystem with no adapter does not silently acquire an
    /// upstream. Guessing a URL for one would mean the first person to
    /// enable `proxy` on it fetches from somewhere nobody chose.
    #[test]
    fn only_ecosystems_with_a_proxy_have_a_default_upstream() {
        for eco in ["npm", "maven", "pypi", "cargo", "oci"] {
            std::env::remove_var(format!("SKEIN_UPSTREAM_{}", eco.to_uppercase()));
        }
        for eco in ["maven", "pypi", "cargo", "oci"] {
            assert!(
                Http::for_ecosystem(eco).is_none(),
                "{eco} acquired an upstream without an adapter"
            );
        }
        assert_eq!(
            Http::for_ecosystem("npm").expect("npm has one").base,
            "https://registry.npmjs.org"
        );
    }
}
