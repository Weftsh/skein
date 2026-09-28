# Operating Skein

Skein is one binary, `skein`, backed by PostgreSQL and an S3-compatible
bucket. Any number of `skein` processes can serve the same database and
bucket: package bytes are content-addressed, every write is checked
against its digest, and nothing is held in a process that another one
needs.

## Running it

With Docker Compose — Skein, PostgreSQL and MinIO on one machine:

```sh
docker compose up -d --build --wait
docker compose exec skein skein admin bootstrap --org acme
```

Open `http://localhost:8080` and sign in as `admin` with the password
the bootstrap printed. Change the passwords in `compose.yml` first, and
for anything beyond a trial put TLS in front of port 8080 and set
`SKEIN_PUBLIC_URL`.

Or run the image on its own against a PostgreSQL and a bucket you
already have:

```sh
docker run -d -p 8080:8080 \
  -e SKEIN_DB_URL=postgres://… -e SKEIN_STORE_URL=https://… \
  -e AWS_ACCESS_KEY_ID=… -e AWS_SECRET_ACCESS_KEY=… -e AWS_REGION=… \
  -e SKEIN_PUBLIC_URL=https://skein.example.com \
  ghcr.io/weftsh/skein
```

Or the static binary from a release: `skein` serves, and `skein admin …`
sets up and repairs. Releases carry Linux binaries for x86_64 and
arm64 and a multi-architecture image, `ghcr.io/weftsh/skein:<version>`.

`scripts/smoke.sh` builds the image, brings the Compose stack up,
bootstraps it, and publishes and installs through it with the real npm
— CI runs it on every push.

## Configuration

Everything is the environment.

| Variable | Default | Meaning |
|---|---|---|
| `SKEIN_DB_URL` | *(required)* | PostgreSQL URL, e.g. `postgres://skein:skein@db:5432/skein`. The schema is created and migrated on start. |
| `SKEIN_STORE_URL` | *(required)* | The bucket. Path-style (`http://minio:9000/skein`) or virtual-host style (`https://skein.s3.eu-west-1.amazonaws.com`). |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` | — | Credentials for the bucket. Every request is SigV4-signed when these are set. `AWS_REGION` defaults to `us-east-1`. |
| `SKEIN_STORE_CREATE_BUCKET` | `false` | Create the bucket on start if it does not exist. Path-style URLs only — for MinIO and other self-hosted stores; a bucket on AWS should be created on purpose, with its own policy. |
| `SKEIN_BIND` | `0.0.0.0:8080` | Where to listen. |
| `SKEIN_PUBLIC_URL` | `http://localhost:8080` | Where clients reach Skein. Written into the documents a registry hands out — an npm tarball URL, Cargo's `config.json` — and decides whether the session cookie is `Secure`. |
| `SKEIN_UPSTREAM_NPM` | `https://registry.npmjs.org` | The upstream the npm pull-through proxy reads from, when npm is in `proxy` mode. |
| `SKEIN_UPSTREAM_ALLOW_PRIVATE` | `false` | Admit an upstream inside a private network — an internal mirror. It must still be HTTPS unless it is on loopback. |
| `SKEIN_GC_INTERVAL_SECS` | `3600` | How often unreferenced package bytes are collected. `0` switches the collector off. |
| `SKEIN_GC_GRACE_SECS` | `3600` | How long bytes must have been unreferenced before they are collected. A publish writes its bytes before its row, so this must comfortably exceed the longest publish. |
| `SKEIN_DB_LOCK_TIMEOUT_MS` | `5000` | How long a write waits on another's lock before failing rather than hanging a request. |
| `SKEIN_LICENSE_KEY` | *(none)* | Your Skein licence key. Applied on start when it differs from the one last applied, so a key installed from the UI stands until this changes. See [licensing.md](licensing.md). |
| `SKEIN_LICENSE_ENDPOINT` | `https://license.weft.sh/v1/check` | Where an online licence's daily check goes. Must be HTTPS. |
| `SKEIN_LOGIN_MAX_FAILURES` | `5` | Failed password checks for one username, within the window, that lock it. See [Sign-in protection](#sign-in-protection). |
| `SKEIN_LOGIN_MAX_FAILURES_PER_ADDRESS` | `20` | Failed password checks from one client address, within the window, that lock it. |
| `SKEIN_LOGIN_WINDOW_SECS` | `900` | How long failures are remembered, and how long a lock lasts. At most `86400`. |
| `SKEIN_TRUST_PROXY_HEADERS` | `false` | Take the client's address from the right-most `X-Forwarded-For` entry — the one your proxy appended — instead of the TCP peer. Set it only when every request reaches Skein through that proxy. |

A limit that does not parse — `0`, a word, a window over a day —
refuses to start and names the variable, rather than running without
the limit somebody meant to set.

Skein serves plain HTTP. Put TLS in front of it — a load balancer, or a
reverse proxy such as Caddy or nginx — and set `SKEIN_PUBLIC_URL` to the
`https://` address people use. Behind that proxy, set
`SKEIN_TRUST_PROXY_HEADERS=true` too: otherwise every sign-in arrives
from the proxy's address, and twenty failures from anybody lock sign-in
for everybody.

Container images need two more things: Skein at the **root** of its own
host name, because a container client has nowhere to put a base path,
and a proxy that lets a multi-gigabyte request body through. See
[containers.md](containers.md).

### Outbound connections

Skein connects to its database and bucket, and to two things on the
internet, both optional:

- the npm upstream (`SKEIN_UPSTREAM_NPM`), only when npm is in `proxy`
  mode;
- `license.weft.sh`, once a day, only with an online licence key — see
  [licensing.md](licensing.md).

Both connect **directly**: `HTTPS_PROXY` is not read today. The HTTP
client's own proxy support ignores `NO_PROXY`, so honouring it would
also send loopback and internal addresses through the proxy. An install
that reaches the internet only through a forward proxy cannot use npm's
proxy mode, and its licence check does not complete — which becomes a
warning after seven days and never a refusal.

## Setting up

```sh
skein admin bootstrap --org acme
```

creates the organization this install serves, its first admin, and an
admin API token, prints the password and the token once, and switches
on every ecosystem this build serves in `private` mode. It refuses to
run twice. Until it has run, the server answers every registry and API
request with a 503 that says to run it, and `/readyz` is not ready.

## Health

- `GET /healthz` — the process is serving.
- `GET /readyz` — the database answers, the bucket exists and answers
  404 for a key it does not hold, and the install is set up. Two
  requests to the bucket, because each catches what the other cannot: a
  one-key LIST fails on a bucket that was never created (a GET of an
  absent key answers 404 either way), and the GET catches a policy
  without `s3:ListBucket`, under which S3 answers 403 for an absent key
  and every missing artifact would look like a permissions failure.

## The bucket

Bytes live under `o/<org-id>/pkg/<sha256>`. The IAM policy Skein needs on
its bucket is `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` and
`s3:ListBucket` — the last one so that a missing key answers 404 rather
than 403.

## Getting back in

```sh
skein admin reset-password admin     # prints a new password, signs them out everywhere
skein admin set-role ada admin       # promote somebody
skein admin mint-token ci --scope package:write --label release
```

Skein will not let the last active admin be demoted, disabled or
deleted — from the UI, the API or the command line.

## Sign-in protection

Three things check a password: signing in to the UI (`POST
/api/v1/session`), `npm login`, and changing your own password. Every
check is an Argon2 hash, and all three share one set of counters, so a
guesser gains nothing by moving between them.

- **5 failures for one username**, within 15 minutes of the first of
  them, lock that username; **20 from one address** lock that address.
  A lock lasts 15 minutes from the failure that filled it. All three
  numbers are settings — see the table above.
- While a username or address is locked, every password check for it is
  answered **429** with `Retry-After` and a sentence — `too many failed
  sign-ins for ada; try again in 840 seconds` — **before** the password
  is looked at. The right password is refused too; that is the point.
- A username nobody holds is counted and locked exactly like one
  somebody does, and answers in the same words, so a lock says nothing
  about who has an account. The username is read the way sign-in reads
  it: `ADA` and `ada` are one counter.
- A refused attempt is not a failure: it neither counts nor stretches
  the lock. A successful sign-in clears its username's counter, but not
  its address's — or one valid account would reset the count for
  somebody trying one password against everybody else's.
- **Tokens are not touched.** API tokens, the `.npmrc`, CI and every
  package manager keep working while a person's sign-in is locked.
  Anybody can keep somebody's sign-in locked by failing five times every
  fifteen minutes; that person's tokens still work, and the lock ends on
  its own. `skein admin reset-password` does not end it — the counters
  live in the server process — but restarting the server does.
- The first failure that locks a username or an address writes one
  `session.throttled` entry to the audit log, by `system:sign-in`,
  naming the username or the address, how many failures, and which of
  the three doors it was. One per lock, not one per refused guess.

The address is the TCP peer's. An IPv6 address counts as its `/64`,
because a single host is routinely handed a whole `/64`. Behind a
reverse proxy the peer is the proxy, for everybody, so set
`SKEIN_TRUST_PROXY_HEADERS=true`: the address is then the **right-most**
`X-Forwarded-For` entry, the one the proxy appended, and anything to its
left — which the client wrote — is ignored. A request with no entry
there is counted against the peer. Set it only when every request
reaches Skein through that proxy, and that proxy writes the address it
received the request from **last** — as nginx does with
`$proxy_add_x_forwarded_for`. Without the setting, a client can write
any `X-Forwarded-For` it likes and Skein ignores it.

Skein trusts exactly one hop, so check what yours writes. Behind two
proxies, or a load balancer that appends its own address after the
client's (Google Cloud's does), the right-most entry is a proxy's, and
every sign-in is counted against that one address; have the proxy
nearest Skein set the header to the address it received instead.

The counters live in each `skein` process. Several replicas behind a
load balancer each keep their own, which still bounds guessing to
replicas × the limit; a restart forgets them. A process holds at most
100,000 of them: when full it drops what has expired, then the oldest
that is not locked.

## Collecting unreferenced bytes

Deleting a package removes its rows at once; its bytes are collected
later, once nothing references them and they have been unreferenced for
`SKEIN_GC_GRACE_SECS`. `skein admin gc --grace-secs N` runs one pass now
and prints what it collected.
