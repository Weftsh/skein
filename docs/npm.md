# npm

Skein speaks npm's own registry protocol at `/npm/`. `npm publish`,
`npm install`, dist-tags, scoped packages, `npm login`, `npm whoami`,
`npm ping` and `npm logout` all work unchanged.

## Pointing npm at Skein

A scope is the shape that works best: npm sends one scope to one
registry and leaves everything else where it was.

```ini
# ~/.npmrc, or .npmrc in the repository
@acme:registry=https://skein.example.com/npm/
//skein.example.com/npm/:_authToken=skein_…
```

`@acme/*` now resolves here and everything else at npmjs. Mint the token
in the UI under **Connect a client** or **Your tokens** —
`package:read` to install, `package:write` to publish. If your
organization has more than one npm scope (see below), route each of
them the same way; the **Connect a client** page writes a line for
every one.

Or let npm get one for you:

```sh
npm login --registry=https://skein.example.com/npm/
```

That exchanges your Skein username and password for a token and writes
it into your `.npmrc`. The token can install, and publish if your role
allows it; it never carries `org:admin`, whatever your role. `npm
logout` revokes it on the server, not just in the file.

A wrong password counts towards the same lock as signing in to the UI —
see [Sign-in protection](operations.md#sign-in-protection). A locked
`npm login` fails with `429 Too Many Requests` and says how long to
wait, but only after npm has retried twice on its own, 10 and then 60
seconds apart (`fetch-retries`); the retries are refused like the first
try and do not count.

```sh
npm whoami --registry=https://skein.example.com/npm/   # who the token is
npm ping   --registry=https://skein.example.com/npm/   # is the registry there
```

A token carries its owner's authority **now**: demote somebody and the
token in their `.npmrc` loses the difference on its next request;
disable them and it stops working.

### A certificate from your own CA

If Skein's certificate comes from your company's own CA, point Node at that CA; npm then trusts it alongside the public
roots, so the rest of npmjs keeps working:

```sh
export NODE_EXTRA_CA_CERTS=/etc/pki/acme-ca.pem
```

(`cafile` in `.npmrc` also works, but *replaces* the public roots.)

## Publishing

```sh
npm publish
```

### Only under your organization's scopes

npm packages here are published under the organization's own **npm
scopes**, and nowhere else. A new install has one, `@<organization>` —
`@acme` for `skein admin bootstrap --org acme` — and a name outside the
list is refused before anything is stored, in a sentence `npm publish`
prints:

```text
npm error 403 403 Forbidden - PUT https://skein.example.com/npm/plain-name -
  npm packages here are published under this organization's scopes (@acme);
  "plain-name" has no scope — publish it as @acme/plain-name
```

The reason is **dependency confusion**. The `.npmrc` above sends
`@acme/*` to Skein and everything else to public npmjs, which is what
lets a build use both. So an internal package published as `plain-name`,
or as `@someone-else/thing`, is one that `npm install` asks npmjs for —
and on npmjs anybody can register that name. The first person who does
has their code installed in your builds, under a name everybody believes
is yours. Holding publishing to your own scopes means every internal
package is one your `.npmrc` routes here, so npmjs is never asked for
it.

To publish under another scope — a second product line, a scope you
already use on npmjs — an admin adds it under **Admission policy → npm
scopes**, or:

```sh
curl -X POST https://skein.example.com/api/v1/npm/scopes \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{ "scope": "@acme-labs" }'
```

A scope is stored as npm writes it, `@` and lowercase. Removing one
(`DELETE /api/v1/npm/scopes?scope=@acme-labs`) is refused while packages
are published under it; delete them first.

**Renaming the organization adds the new name's scope and keeps the
old one.** The client snippets are written with the organization's name,
so after a rename new `.npmrc` files route the new scope — and every
package already published under the old one keeps publishing and
installing.

A package published before this rule existed with no scope at all keeps
installing, by exact version and by range, but takes no new versions:
publish its next release under a scope.

A name under one of your scopes is **never fetched from an upstream
registry**, published yet or not — see [the proxy](#everything-through-skein-the-proxy).

The registry reads the name and version from `package.json`. Publishing
a version that already exists is refused with a `409` — a published
version never changes, because every lockfile that names it was
reviewed against those bytes. The tarball is checked against the length
and SHA-1 npm declared before it is stored; the packument then
advertises the SHA-512 `integrity` npm verifies on install, computed
from the bytes that arrived.

`dist-tags` in a publish are applied only when they point at the
version being published. A tag naming some other version is ignored
rather than pointed at a version that may not exist.

## Yanking

In the UI (a package's page) or the API:

```sh
curl -X POST https://skein.example.com/api/v1/packages/$ID/versions/1.0.0/yank \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{ "yanked": true, "reason": "published by mistake" }'
```

A yanked version is marked deprecated in the packument and **still
installs by exact version**, so a lockfile that names it keeps
building.

`latest` never names a yanked version. If the version it points at is
yanked, the packument serves `latest` as the highest version nobody
yanked — by semver, so `1.10.0` is above `1.9.0`, and a release is
preferred to any pre-release — or leaves `latest` out when every
version is yanked. `npm view` and an `npm install` with no range then
get the previous release rather than the one you took down. The tag
itself does not move: un-yank the version and `latest` names it again.
Other dist-tags are served as they were set. `npm unpublish` is refused: deleting a package is an admin's
act in the UI, because it breaks everything that depends on it.

## Everything through Skein: the proxy

Switch npm to **Private + proxy** under **Admission policy** and point
npm's default registry at Skein:

```ini
registry=https://skein.example.com/npm/
//skein.example.com/npm/:_authToken=skein_…
```

Public packages then arrive through Skein, are cached in your bucket,
and meet the admission policy on the way in — see
[policy.md](policy.md). The upstream is `https://registry.npmjs.org`
unless `SKEIN_UPSTREAM_NPM` names another (an internal mirror needs
`SKEIN_UPSTREAM_ALLOW_PRIVATE=true`).

Your own packages always win: a name you have published locally is
never fetched from upstream, and a name cached from upstream cannot be
published over. A name under one of your organization's npm scopes is
never fetched from upstream **at all**, published or not, in audit mode
as in block mode: publishing is held to those scopes, so `@acme/new-thing`
is yours before anybody has published it, and asking npmjs for it would
install whoever registered it there first. It answers `404` until you
publish it here.

### When the policy refuses a version

The admission policy decides **per version, when the metadata is
read**: the packument npm receives lists only the versions the policy
admits (the header of `registry/upstream.rs` explains why — a client
handed every version resolves to one the tarball door then refuses,
which reads as a broken registry rather than a decision). So a refused
version is not refused with a reason in the terminal; to npm it simply
is not there:

```text
npm error code ETARGET
npm error notarget No matching version found for left-pad@2.0.0.
```

If no version at all is admitted, that is the whole answer. The reason —
which rule refused which version, and how often it was asked for — is on
the admin's **What it caught** page (`GET /api/v1/findings`). A lockfile
install, which goes straight to the tarball without reading a packument,
gets `403` with the reason itself.

## Limits

| | |
|---|---|
| One tarball | 128 MiB |
| Package name | 214 bytes, npm's own limit |
| Version string | 128 bytes |

A name that could escape its own path — `..`, a stray slash, a control
character, anything non-ASCII — is refused rather than cleaned up.
