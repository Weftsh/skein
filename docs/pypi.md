# PyPI

Skein serves both halves of PyPI's protocol: the PEP 503 simple index
that pip installs from, and the upload that `twine upload` sends.
Source distributions and wheels, private to your organization: every
install and every upload is a person with a token, and there is no
anonymous read.

```text
https://skein.example.com/pypi/                   twine uploads here
https://skein.example.com/pypi/simple/            pip's index
https://skein.example.com/pypi/simple/<project>/  one project's files
```

**Connect a client** in the UI writes both configurations below with
your registry's address filled in, and mints the token they need.

## Switching it on

`skein admin bootstrap` switches PyPI on, in private mode, with every
other ecosystem this build serves. An admin can switch it off and on
again on the **Admission policy** page, or over the API:

```sh
curl -X PUT https://skein.example.com/api/v1/ecosystems \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "ecosystem": "pypi", "mode": "private" }'
```

While it is off, everything under `/pypi/` answers 404 to somebody who
has signed in — and the same `401` as everywhere else to somebody who
has not, so nobody learns which ecosystems you use without saying who
they are.

Skein does not proxy pypi.org. It serves what your organization uploads
and nothing else; public packages still come from pypi.org.

## Configuring pip

`~/.config/pip/pip.conf`:

```ini
[global]
index-url = https://skein:skein_…@skein.example.com/pypi/simple/
```

The token is the password; the username is ignored. A token with
`package:read` is enough to install.

With `index-url`, pip asks Skein and nothing else. That is the safe
configuration, and it means exactly what it says: your own packages
install, and a public one — or a public dependency of one of yours —
does not, because Skein does not proxy pypi.org.

Serve Skein over HTTPS (see [operations](operations.md)). pip ignores a
plain-`http` index on any host but `localhost` unless it is also listed
as a `trusted-host`, and the token travels in every request.

### `extra-index-url`, and the risk in it

```ini
[global]
extra-index-url = https://skein:skein_…@skein.example.com/pypi/simple/
```

**This is a real risk and you should know what it is.** With an extra
index, pip resolves a name across *every* index it is given and takes
the highest version it finds anywhere. If somebody publishes
`acme-widget 99.0` on pypi.org, pip prefers it to your `1.4.0`, installs
it, and runs its build.

Skein cannot stop that: it is pip, not Skein, that asks pypi.org, and
Skein never sees the public answer. Reserving a namespace on the
**Admission policy** page does not help either — that rule governs what
Skein's own npm proxy fetches, and plays no part here. What does help:

- install your own packages with `index-url` pointing at Skein alone,
  in a step of their own, and public ones separately;
- pin with hashes (`pip install --require-hashes -r requirements.txt`),
  so an artifact other than the one you locked is refused;
- register your private names on pypi.org yourself, so nobody else can.

### A certificate from your own CA

If Skein's certificate comes from your company's own CA, give pip a bundle holding it *and* the public roots — `cert`
replaces pip's own list rather than adding to it:

```ini
[global]
cert = /etc/pki/bundle-with-acme-ca.pem
```

twine reads `REQUESTS_CA_BUNDLE` (or `--cert`), with the same bundle.

## Configuring twine

`~/.pypirc`:

```ini
[distutils]
index-servers = skein

[skein]
repository = https://skein.example.com/pypi/
username = __token__
password = skein_…
```

```sh
python -m build
twine upload -r skein dist/*
```

Uploading needs a token with `package:write`, held by a publisher or an
admin. `repository` may end in `/pypi/` or `/pypi`; both are the upload
address.

`twine upload dist/*` posts the sdist and the wheel as two requests;
both land on one release. If twine sends a `sha256_digest` it is checked
against the bytes that arrived — a mismatch is a truncated upload and is
refused rather than stored.

The licence is read from PEP 639's `License-Expression` first, then from
a trove classifier, and only then from the free-text `License` field.
The order is about how much each can be trusted: the first is *defined*
to be an SPDX expression, the second comes from a fixed vocabulary so
its mapping is exact, and the third is free text that famously holds
"see LICENSE" and entire licences pasted in. `BSD` alone is three
licences and `GPL` is six; neither is mapped, so a project declaring one
is recorded with an unknown licence rather than one it did not mean.

### When an upload is refused

twine prints the status line of a refusal — not its body, which it
shows only under `--verbose` — so Skein puts the reason there:

```text
Uploading distributions to https://skein.example.com/pypi/
Uploading acme_widget-1.3.0-py3-none-any.whl
WARNING  Error during upload. Retry with the --verbose option for more details.
ERROR    HTTPError: 403 Forbidden from https://skein.example.com/pypi/
         rita is a reader here, and a reader may not publish to this registry
```

| twine prints | Why |
|---|---|
| `403` — *… is a reader here …* | the person's role does not publish; an admin can make them a publisher |
| `403` — *this token was not minted with package:write …* | the role would, the token does not; mint one that does |
| `409` — *… is already uploaded for …* | that file is already there — see below |
| `400` — *… does not match the SHA-256 twine sent …* | the upload arrived truncated or altered |
| `400` — *… is not a distribution filename* | see the limits below |
| `401` | no token, or one that is revoked, expired or mistyped |

pip reports an index it cannot read differently: with a missing or
wrong token it says only *No matching distribution found*, and the
`401` appears when it is run with `-vv`.

## A published file never changes

Uploading a file a second time is refused with a `409`, and the first
upload's bytes are exactly what they were. A filename names one file
across the whole project, whichever version it was uploaded under,
because that is how pip fetches it.

twine itself refuses `--skip-existing` for any index but pypi.org and
TestPyPI, so a release job that may run twice should upload only what
it has just built.

### Yanking

```sh
curl -X POST \
  https://skein.example.com/api/v1/packages/$PACKAGE/versions/1.3.0/yank \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "yanked": true, "reason": "breaks on Python 3.13" }'
```

`$PACKAGE` is the id `GET /api/v1/packages?ecosystem=pypi&q=acme-widget`
returns. A yanked release stays on the index, marked the way PEP 592
says: pip passes over it for `pip install acme-widget`, and still
installs it for `acme-widget==1.3.0` — printing the reason — so a
lockfile that pins it keeps building.

## Limits

| | |
|---|---|
| One file | **128 MiB** |
| Project name | 214 bytes; `.`, `_` and `-` fold together and case does not matter (PEP 503) |
| Version | 128 bytes |
| Filename | letters, digits and `.` `_` `-` `+` `!` — what build tools write |

A filename that could escape its path, be read as markup, or break the
link pip follows — `/`, `<`, `#`, `?`, `%` — is refused rather than
cleaned up. Cleaning it up would give one stored file two names.

## What this does not do yet

- **No pull-through proxy for pypi.org.** Only npm proxies.
- **No `data-requires-python` on the index**, and no PEP 658 metadata
  files, so pip has to download a release to learn which Pythons it
  supports.
- **No JSON index (PEP 691).** pip asks for it, is answered in HTML, and
  reads that instead.
