# REST API

Everything the UI does is a call to `/api/v1/`, so anything it can do a
script can do. Requests and responses are JSON; a refusal is
`{"error": "<a sentence>"}` with an HTTP status that says which kind.

## Authentication

Send a token as `Authorization: Bearer skein_…`. Mint one in the UI
(**Your tokens**), with `POST /api/v1/me/tokens` from a browser session,
or on the server with `skein admin mint-token`.

A request with no credential is a **401**. A credential that does not
verify — revoked, expired, mistyped — is also a 401, never quietly
treated as none. A person whose role or token does not reach the
operation gets a **403** whose sentence says which of the two is the
limit.

A browser session (the `skein_session` cookie) works too, but a
state-changing request authenticated only by the cookie must carry the
header `x-skein-csrf: 1`. A request with an `Authorization` header is
exempt.

| Scope | May |
|---|---|
| `package:read` | install; read packages |
| `package:write` | install, publish, yank |
| `org:read` | install; read packages, people, the policy and its findings |
| `org:admin` | everything, including people, settings and deleting a package |

A token's scopes are narrowed on every request by its owner's role:
`reader` holds `org:read`, `publisher` holds `org:read` and
`package:write`, `admin` holds `org:admin`.

## You

| | |
|---|---|
| `GET /api/v1/session` | `{"signed_in": false}`, or who you are — 200 either way |
| `POST /api/v1/session` | sign in: `{"username", "password"}`; sets the session cookie |
| `DELETE /api/v1/session` | sign out |
| `GET /api/v1/me` | who this request is: username, role, effective scopes, `via` (`token` or `session`) |
| `PUT /api/v1/me/password` | `{"current", "new"}`; signs out every other session |
| `GET /api/v1/me/tokens` | your live tokens |
| `POST /api/v1/me/tokens` | `{"label", "scopes": [...], "expires_in_days"?}` → the token, **once** |
| `DELETE /api/v1/tokens/:id` | revoke one of yours (an admin may revoke anybody's) |

A wrong password is a **401** (`invalid username or password`) for
every reason — unknown name, wrong password, disabled account — and a
wrong `current` password is a **403**.

**Sign-in protection.** `POST /api/v1/session`, `PUT
/api/v1/me/password` and `npm login` share failure counters: by default
5 failures for one username, or 20 from one address, within 15 minutes
lock it for 15 minutes. A locked username or address is answered
**429 Too Many Requests** with `Retry-After: <seconds>` and
`{"error": "too many failed sign-ins for ada; try again in 14 minutes"}`
(`from <address>` for an address; the wait is in seconds under a minute
and a half, and in whole minutes, rounded up, past it), before the
password is checked — the right one included. Refused attempts do not
count. Tokens are never throttled. The limits, and how the address is found behind a proxy, are
in [operations.md](operations.md#sign-in-protection).

## Packages

| | |
|---|---|
| `GET /api/v1/packages?ecosystem=&q=&limit=&offset=` | most recently active first; `q` matches part of the name |
| `GET /api/v1/packages/:id` | the package, its versions (licence, publisher, files and digests) and tags |
| `POST /api/v1/packages/:id/versions/:version/yank` | `{"yanked": true, "reason"?}` — `package:write`. A yanked version still installs by exact version |
| `DELETE /api/v1/packages/:id` | remove every version — `org:admin`. Its bytes are collected later |
| `GET /api/v1/overview` | package counts per ecosystem, stored bytes, findings |

## The registry and its policy

| | |
|---|---|
| `GET /api/v1/ecosystems` | every ecosystem and its mode (`off`, `private`, `proxy`) |
| `PUT /api/v1/ecosystems` | `{"ecosystem", "mode", "license_unknown"?: "block"\|"allow"}` — `org:admin` |
| `GET /api/v1/policy?ecosystem=npm` | mode (`audit`/`block`), cooldown days, licence mode and rules, reserved names |
| `PUT /api/v1/policy` | `{"mode", "cooldown_days", "license_mode": "deny_list"\|"allow_list"}` — `org:admin` |
| `PUT /api/v1/policy/licenses` | `{"spdx_id", "disposition": "allow"\|"deny"\|null}` — null removes the rule. `spdx_id` must be an SPDX identifier (or `LicenseRef-…`), or it is a **400** naming it; it is matched case-insensitively and read back as typed |
| `POST /api/v1/policy/namespaces` | `{"ecosystem", "pattern"}` — reserve a name prefix |
| `DELETE /api/v1/policy/namespaces?ecosystem=&pattern=` | release one |
| `GET /api/v1/findings?limit=` | what the policy refused, or would have in audit mode, with hit counts |
| `DELETE /api/v1/findings?ecosystem=&name=&version=` | dismiss one. It does not allow the package; change the rule for that |

See [policy.md](policy.md) for what each control means.

## People and the organization (`org:admin` unless noted)

| | |
|---|---|
| `GET /api/v1/users` | everybody — `org:read` |
| `POST /api/v1/users` | `{"username", "role", "password"?}` — no password makes a service account |
| `PATCH /api/v1/users/:id` | `{"role"?, "disabled"?, "password"?, "display_name"?}` |
| `DELETE /api/v1/users/:id` | their tokens go with them; what they published stays, and still names them as its publisher — as the audit log still names them on everything they did |
| `GET /api/v1/users/:id/tokens` | their live tokens |
| `POST /api/v1/users/:id/tokens` | mint a token for somebody — how a CI service account gets one |
| `GET /api/v1/tokens` | every live token |
| `PUT /api/v1/org` | `{"name"}` — rename; stored keys use an id that never changes |
| `GET /api/v1/audit?before=&limit=` | the audit log, newest first |

The last active admin cannot be demoted, disabled or deleted: those
requests answer **409**.

## The licence (`org:admin`)

| | |
|---|---|
| `GET /api/v1/license` | what the licence says: `state`, its terms, `seats`, `over_cap`, `release_access`, `warnings`, the last check, `monthly_peaks`. Never the key |
| `PUT /api/v1/license` | `{"key"}` — install a key. One that does not verify is a **400** naming why, and the key in force stays |
| `POST /api/v1/license/check` | run the daily check now; **409** for an offline licence or no valid key |

Nothing else in the API — or anywhere — consults the licence. See
[licensing.md](licensing.md).

## Health

`GET /healthz` (liveness) and `GET /readyz` (the database, the bucket,
and whether the install is set up) — see [operations.md](operations.md).
