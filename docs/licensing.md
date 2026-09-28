# Licensing

A Skein install needs a licence key from Weft to receive releases and
security patches. The model is Weft Sandboxes', with the same keys and the
same rules. This page covers the commercial licence key; the source code
licence (FSL-1.1-ALv2) is in [LICENSE.md](../LICENSE.md).

## A licence never stops Skein

This is the whole design, so it comes first. A missing, invalid, expired,
revoked or over-cap licence produces **warnings**: a banner for admins
in the UI, the card under **Settings → Licence**, `GET /api/v1/license`,
and a line in the log when they change. Nothing else happens. Every
install, publish, yank and sign-in works exactly as before, and adding
people works too.

Weft's levers are release access and the contract, not your registry.
Nothing that serves a package reads the licence.

## Seats

A licence covers a number of **seats**: people who can sign in. That
means a password, and not disabled.

| | A seat? |
|---|---|
| A person with a password | yes |
| A disabled person | no, until re-enabled |
| A CI service account (created with no password) | no — it holds tokens and cannot sign in |

Skein samples seats every minute and keeps two numbers: the most since
the last daily check, and the most in each calendar month (UTC, the last
thirteen months). Both are under **Settings → Licence** and in
`GET /api/v1/license` as `peak_seats_this_month` and `monthly_peaks`.

## Installing a key

Any of these, as an admin:

- **Settings → Licence**, paste the key, **Install**;
- `PUT /api/v1/license` with `{"key": "weft_lic_v1.…"}`;
- `skein admin license install < key.txt` on the server;
- `SKEIN_LICENSE_KEY` in the environment.

A key that does not verify is refused with the reason, and the key in
force stays. `SKEIN_LICENSE_KEY` is applied on start only when it
*differs from the value last applied*, so a key installed from the UI
stands across restarts until somebody changes the variable.

The key itself is never shown back: not in the API, the UI or the audit
log, which records which licence was installed (`license.install`, with
its id, tier and holder).

## What a key is

`weft_lic_v1.<payload>.<signature>` — base64url JSON, signed with
Ed25519. Skein verifies it offline against the public keys compiled into
the release; verifying never makes a network call. A Skein key says
`"product": "skein"`, so a key for another Weft product is refused
rather than read as one.

## What leaves your install

**Online keys** — most installs — send one request a day to
`https://license.weft.sh/v1/check`. It carries exactly three fields, and
the test suite fails if a fourth appears:

| Field | Example |
|---|---|
| `keyId` | `lic_2f8a…` — the licence's id |
| `version` | `0.1.0` — this Skein |
| `peakSeats` | `14` — the most people who could sign in since the last check |

No package, name, address or count of anything else. The answer
(`active`, `lapsed`, `revoked`, `unknown`, and an optional notice for
admins) is shown under **Settings → Licence**.

The check runs once a day across the whole install, however many
replicas you run and however often they restart: each tries hourly, and
the database lets one of them through per day. It never follows a
redirect, gives up after three tries, and a failure only becomes a
warning after seven days without a success. **Check now** (or
`skein admin license check`) runs it on demand — after fixing outbound
access, say.

The check connects directly; `HTTPS_PROXY` is not read. See
[operations.md](operations.md#outbound-connections).

**Offline keys**, issued for air-gapped Enterprise installs, make no
calls at all. Once a year, send
Weft the monthly peaks for the true-up:

```sh
skein admin license status --json | jq .monthly_peaks
```

## States

| State | Means |
|---|---|
| `unlicensed` | no key |
| `invalid` | a key that does not verify — the warning says why |
| `active` | |
| `expiring` | expires within 30 days |
| `lapsed` | past its expiry. For 30 days more this install still receives new releases and security patches; after that it does not |

`over_cap` (more seats than covered), `check_overdue` (no successful
check for seven days, online keys only) and `release_access` are reported
beside the state.

## Checking from the server

```sh
skein admin license status          # the terms, seats, last check, warnings
skein admin license status --json
skein admin license check           # run the daily check now
skein admin license keys            # the signing keys this build trusts
```
