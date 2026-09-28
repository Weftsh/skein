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
`package:read` to install, `package:write` to publish.

Or let npm get one for you:

```sh
npm login --registry=https://skein.example.com/npm/
```

That exchanges your Skein username and password for a token and writes
it into your `.npmrc`. The token can install, and publish if your role
allows it; it never carries `org:admin`, whatever your role. `npm
logout` revokes it on the server, not just in the file.

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
building. `npm unpublish` is refused: deleting a package is an admin's
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
published over.

## Limits

| | |
|---|---|
| One tarball | 128 MiB |
| Package name | 214 bytes, npm's own limit |
| Version string | 128 bytes |

A name that could escape its own path — `..`, a stray slash, a control
character, anything non-ASCII — is refused rather than cleaned up.
