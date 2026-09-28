# Admission policy

Switch the npm ecosystem to **Private + proxy** and your builds stop
talking to npmjs directly. Everything they ask for arrives through
Skein, is cached in your own bucket, and — this is the part worth
having — meets a policy on the way in.

That ordering is the whole argument. Every other tool in this category
tells you afterwards: a scan runs, a report appears, somebody reads it in
a fortnight. Skein is the registry your build resolves through, so it can
answer the question at the only moment answering it is cheap.

Everything here lives on the UI's **Admission policy** and **What it
caught** pages, and in the API under `/api/v1/policy` and
`/api/v1/findings`.

## Start in audit

A new install starts in `audit` mode, and you should leave it there
for a while.

In `audit`, every package is served and everything the rules *would* have
refused is written down. In `block`, those same packages are refused.
Nothing else differs — the rules are the same rules and they are
evaluated at the same moments.

This is not timidity. A policy that blocks from day one meets a deadline
in week one and gets switched off entirely, and then nobody ever learns
what it would have cost. A week of `would refuse` rows from your own
builds is a real answer to "what does this cost us", and it takes a
week rather than a negotiation.

When you switch to `block`, artifacts already in the cache are re-checked
too. That matters more than it sounds: audit mode *caches* everything it
flags, so a switch that only applied to future fetches would be a no-op
for precisely the packages audit mode found.

## Three questions, kept apart

They get conflated into one toggle, and then nobody can say which of them
refused their build. Here they are three controls, evaluated in this
order, and a refusal always names the one that decided.

### 1. Names that are yours

Reserve a prefix and nothing under it is ever fetched from a public
registry — published or not, today or in a year.

Serving your own packages already protects a name you have published:
the local lookup comes first, always, and a public `@acme/widget` can
never answer for your private one. What it does *not* protect is a name
you have not created yet. If somebody registers `@acme/new-service` on
npmjs this morning and a build asks for it this afternoon, without a
reservation they get theirs.

So: reserve your scope.

```
Admission policy → Names that are yours → @acme
```

Prefixes match on a **segment boundary**, never as a bare substring.
`@acme` covers `@acme/widget` and `@acme` itself; it does not cover
`@acmecorp/widget`. A substring match would be the more obvious
implementation and would reserve half the registry by accident — an
organization claiming `@ac` would silently take `@acme` too.

A reserved name is refused *without asking the upstream at all*. That is
deliberate beyond the refusal itself: asking would tell npmjs which
internal names your organization uses.

### 2. How long a release must exist before you will take it

Set a number of days. An upstream release younger than that is not
served. `0` turns it off, which is the default.

The case for it: every compromised-maintainer incident worth naming —
event-stream, ua-parser-js, coa and rc, node-ipc — was noticed and
withdrawn within hours to days. Almost nobody needs a package on the day
it ships. A waiting period costs you very little and catches the class of
attack that has actually happened, repeatedly.

The case against the thing people expect instead: a semver rule ("patches
only, automatically") looks like a control and protects far less than it
appears to. A malicious patch release is still a patch release.

**This is not a vulnerability scan and we are not going to imply it is.**
There is no advisory feed here. What there is, is a wait — and a wait is
what a withdrawal needs in order to happen before you are affected by it.

A release the upstream gives no date for is **not** held. The waiting
period is a claim about age, and refusing everything whose age is unknown
would switch a registry off rather than filter it. The licence gate still
applies to it.

### 3. On what terms — the licence

Two modes, and they are not the same policy:

- **Deny list** — everything enters except what you have listed. An
  organization that has banned AGPL wants a licence nobody has heard of
  to pass.
- **Allow list** — only what you have listed enters. An organization that
  has approved four licences wants a fifth refused.

A new install starts on a deny list with no rules, which admits
everything. An allow list with no rules admits nothing, so the screen
says so rather than leaving you to discover it through a build that
resolves nothing at all.

Rules are SPDX identifiers, compared case-insensitively, as SPDX defines
them.

Removing a rule is a third thing and not the same as denying: under a
deny list an absent rule *admits*, and under an allow list it *refuses*.

#### Expressions are evaluated, not string-matched

Packages declare things like `MIT OR Apache-2.0` and
`GPL-2.0-only WITH Classpath-exception-2.0`. These are evaluated:

| Expression | Decided |
|---|---|
| `A OR B` | admitted if **either** side is admitted — you choose which side you take |
| `A AND B` | admitted only if **both** are |
| `A WITH E` | decided on `A`, unless you have written a rule naming the exception |
| parentheses | as you would expect |

This is per version, never per package. Packages relicense between
versions, and a policy that decided once per name would either admit a
version it should not or refuse one it should.

#### When the licence cannot be read

Two cases that are the same from the policy's point of view: the package
declared nothing, and the package declared something we cannot parse.
Both land on the ecosystem's **unknown** setting, which is per ecosystem
because the ecosystems genuinely differ — npm, PyPI and Cargo publishers
usually declare a licence, and container images usually declare none. A
single global default would be wrong for somebody either way.

Where a declaration comes from, per ecosystem:

| Ecosystem | Declared licence |
|---|---|
| npm | `license`, plus the legacy `{type: …}` and `licenses[]` spellings |
| PyPI | `info.license`, classifiers, PEP 639 `License-Expression` |
| Cargo | `license` (already SPDX) or `license_file` |
| Maven | the POM's `<licenses><license><name>` — free text, not SPDX |
| Containers (OCI) | `org.opencontainers.image.licenses` — already SPDX, and usually absent |

## What a refusal looks like

To the person whose build stopped, a sentence:

```
npm error 403 Forbidden
npm error left-pad 1.3.0 is licensed WTFPL and this
npm error organization does not admit WTFPL.
```

To an admin, the same thing as a row under **What it caught**, with the rule that decided, the outcome (`refused`,
or `would refuse` under audit), and a count.

The count is the number worth reading. Findings are deduplicated to one
row per package version however many times it comes up — a CI run
resolving eight hundred dependencies must not write eight hundred rows —
so "12 times this week" is what tells you whether a rule is earning its
keep or quietly costing you a team's afternoon.

### Allowing something

Change the rule that refused it. For a licence, that is one click on the
findings screen; the rule is what decides, and the next install gets the
package.

**Dismissing a finding is not allowing the package.** The rule is still
in force and the next install writes the row again. That is deliberate:
it means a cleared row means somebody acted, rather than somebody tidied.

There is no approval queue, and there is not going to be one until people
have met the refusals for a while. A queue is states, notifications,
expiry and a second permission model; a refusal that is already a row
with an "allow this" beside it is most of the value for a fraction of the
surface.

## Two things you get whether or not you tighten anything

**Your builds stop depending on npmjs being up.** Everything that passes
the gate is cached in your own bucket, so the second build gets it at
your registry's latency. A package you have installed before keeps installing
during an upstream outage — the metadata and the bytes both come from the
cache. A package you have *never* installed cannot, and that answers 502
rather than 404: "we could not ask" and "it does not exist" are different
answers, and a resolver that caches the second on the first is one
somebody has to clear by hand.

**The resolver never sees a version it cannot have.** The metadata
document is filtered to admissible versions before your client reads it,
so npm resolves to something that works instead of resolving to something
we then refuse — which reads as a broken registry rather than as a
decision your organization made. A dist-tag pointing at a withheld
version is dropped rather than repointed: "this registry has no `latest`
for you" is a worse-sounding answer and a much better one than silently
installing something other than what the tag means.

The download is checked again anyway. A build with a lockfile goes
straight at the tarball URL and never reads metadata at all, so that
request meets the only gate it will ever meet.

## Who sets it

Reading the policy and the findings needs `org:read` — a reader whose
install was refused has to be able to see why without an admin in the
room. Changing any of it needs `org:admin`, because every control here
widens or narrows what every build in the organization may reach.

## The honest limits

- **The proxy is npm only, for now.** Maven, PyPI, Cargo and containers
  serve what your organization publishes; they do not fetch from Maven
  Central, PyPI, crates.io or Docker Hub yet, so nothing about those
  four meets this gate. Reserved namespaces and the licence recorded at
  publish still apply to them.
- **We gate the artifact we serve.** In practice every transitive
  dependency also arrives through this proxy and is gated in turn — which
  is the stronger property, and the reason this is worth doing at the
  registry — but that holds only while the proxy is the only route out of
  your build. A step that curls a tarball from somewhere else has not met
  any of this.
- **A licence is a declaration.** We read what the publisher declared,
  and a package that declares nothing is *unknown* — we do not open the
  artifact to guess from a LICENSE file, and we do not audit whether a
  declaration is true.
- **The waiting period measures from the upstream's own publish date.**
  If the upstream does not give one, it is not held.
