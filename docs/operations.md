# Operating Skein

Skein is one binary, `skein`, backed by PostgreSQL and an S3-compatible
bucket. Any number of `skein` processes can serve the same database and
bucket: package bytes are content-addressed, every write is checked
against its digest, and nothing is held in a process that another one
needs.

## Running it

With Docker Compose — Skein, PostgreSQL and MinIO on one machine. Each
release carries `skein-compose-<version>.tar.gz`: the Compose files,
`.env.example` and the nginx configuration, pinned to that release's
image, so nothing needs building and no source is needed:

```sh
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf skein-compose-v0.1.0.tar.gz && cd skein-v0.1.0
cp .env.example .env          # set SKEIN_DB_PASSWORD and SKEIN_STORE_PASSWORD in it
docker compose up -d --wait
docker compose exec skein skein admin bootstrap --org acme
```

From a checkout of the source, the same with `docker compose up -d
--build --wait`, which builds the image first. The Compose files need
Docker Compose 2.24 or later (`docker compose version`).

`compose.yml` has no default passwords and refuses to start without
them. Open `http://localhost:8080` and sign in as `admin` with the
password the bootstrap printed.

With TLS in front, which is how anything beyond a trial should run: put
your certificate and key in a directory as `skein.crt` (the full chain,
leaf first) and `skein.key`, and in `.env` set `SKEIN_TLS_DIR` to that
directory and `SKEIN_PUBLIC_URL` to the `https://` address the
certificate names. Then

```sh
docker compose -f compose.yml -f compose.tls.yml up -d --wait
```

runs nginx ([`deploy/nginx.conf`](../deploy/nginx.conf)) on 443 and 80
and stops publishing Skein's own port.

Or run the image on its own against a PostgreSQL and a bucket you
already have:

```sh
docker run -d -p 8080:8080 \
  -e SKEIN_DB_URL='postgres://skein:…@db.internal:5432/skein?sslmode=verify-full' \
  -e SKEIN_STORE_URL=https://… \
  -e AWS_ACCESS_KEY_ID=… -e AWS_SECRET_ACCESS_KEY=… -e AWS_REGION=… \
  -e SKEIN_PUBLIC_URL=https://skein.example.com \
  -e SKEIN_CA_FILE=/etc/skein/ca.pem -v /etc/pki/acme-ca.pem:/etc/skein/ca.pem:ro \
  ghcr.io/weftsh/skein
```

Or the static binary from a release: `skein` serves, and `skein admin …`
sets up and repairs. Releases carry Linux binaries for x86_64 and
arm64 and a multi-architecture image, `ghcr.io/weftsh/skein:<version>`.

`scripts/smoke.sh` builds the image, brings the Compose stack up from
the release bundle (`scripts/bundle.sh`), bootstraps it, and publishes
and installs through it with the real npm — CI runs it on every push.

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
| `SKEIN_GC_GRACE_SECS` | `3600` | How long bytes nothing references must also have gone unused before they are collected. It runs from the last use — stored, stored again, pushed, mounted, or answered for to a `HEAD` — not from when a package or tag was deleted. A publish writes its bytes before its row, and a `docker push` asks about its layers before it sends the manifest, so this must comfortably exceed the longest publish or push. |
| `SKEIN_DB_LOCK_TIMEOUT_MS` | `5000` | How long a write waits on another's lock before failing rather than hanging a request. |
| `SKEIN_LICENSE_KEY` | *(none)* | Your Skein licence key. Applied on start when it differs from the one last applied, so a key installed from the UI stands until this changes. See [licensing.md](licensing.md). |
| `SKEIN_LICENSE_ENDPOINT` | `https://license.weft.sh/v1/skein/check` | Where an online licence's daily check goes. Must be HTTPS. |
| `SKEIN_CA_FILE` | *(none)* | A PEM file of your own CA certificates, trusted for every TLS connection Skein makes — the database, the bucket, an npm mirror, the licence endpoint. See [TLS and your own CA](#tls-and-your-own-ca). A file that is missing or holds no certificate refuses to start. |
| `SSL_CERT_FILE`, `SSL_CERT_DIR` | the OS's | Where the operating system's trust store is read from, as OpenSSL reads them. |
| `AWS_DEFAULT_REGION` | — | Read when `AWS_REGION` is not set. |
| `SKEIN_UPSTREAM_<ECOSYSTEM>` | — | An ecosystem's pull-through upstream. Only npm has a proxy today, so only `SKEIN_UPSTREAM_NPM` does anything. |
| `SKEIN_LOGIN_MAX_FAILURES` | `5` | Failed password checks for one username, within the window, that lock it. See [Sign-in protection](#sign-in-protection). |
| `SKEIN_LOGIN_MAX_FAILURES_PER_ADDRESS` | `20` | Failed password checks from one client address, within the window, that lock it. |
| `SKEIN_LOGIN_WINDOW_SECS` | `900` | How long failures are remembered, and how long a lock lasts. At most `86400`. |
| `SKEIN_TRUST_PROXY_HEADERS` | `false` | Take the client's address from the right-most `X-Forwarded-For` entry — the one your proxy appended — instead of the TCP peer. Set it only when every request reaches Skein through that proxy. |

A limit that does not parse — `0`, a word, a window over a day —
refuses to start and names the variable, rather than running without
the limit somebody meant to set.

For development and tests only — never set these in production:

| Variable | Meaning |
|---|---|
| `SKEIN_DEV_MODE` | `1` admits the two below and a plain-HTTP licence endpoint. |
| `SKEIN_DEV_LICENSE_PUBLIC_KEYS` | Extra licence signing keys to trust, as JSON `{"kid": "PEM"}`. Refused without `SKEIN_DEV_MODE=1`. |
| `SKEIN_LICENSE_CHECK_DELAY_SECS` | Seconds before the first licence check, instead of a random part of an hour. |
| `SKEIN_INSTANCE_ID` | Echoed on `/healthz` as `x-skein-instance`, so a test harness can tell its own server from another on the same port. |

Unset, `SKEIN_PUBLIC_URL` is `http://localhost:8080`, and Skein says so
loudly when it starts: every URL it hands out — npm tarballs, Cargo's
index, the snippets on the UI's **Connect a client** page — would name a
host nobody else can reach.

## TLS and your own CA

Skein trusts three sets of certificates, together, for every TLS
connection it makes: the public roots it was built with, the operating
system's store, and **`SKEIN_CA_FILE`**. On a network whose database,
bucket or npm mirror present certificates from your own CA, put that CA
(and any intermediates) in one PEM file and set `SKEIN_CA_FILE` to it;
nothing else needs to change. A certificate Skein cannot verify fails
with `UnknownIssuer` and a sentence naming `SKEIN_CA_FILE`, on `/readyz`
and in the log. `BadSignature` is the same fault one step on: the
certificate names a CA Skein trusts but a different key signed it —
your CA was re-issued under its old name, and the file still holds the
old one.

**PostgreSQL** is reached over TLS when `SKEIN_DB_URL` says so, with
libpq's own parameters, so a URL from your cloud console works as
written:

| `sslmode` | |
|---|---|
| absent, `disable`, `prefer` | no TLS |
| `require`, `verify-full` | TLS; the certificate and the host name are verified |
| `verify-ca` | TLS; the certificate is verified, the host name is not — for a database reached by an address its certificate does not name |

`require` verifies, where libpq's does not: Skein will not send its
database password to a server it cannot identify. `sslrootcert=/path`
trusts exactly that file, as in libpq — Amazon RDS and Azure publish
their CA bundles for this; without it, the three sets above apply. For
example:

```
SKEIN_DB_URL=postgres://skein:…@skein.abc123.eu-west-1.rds.amazonaws.com:5432/skein?sslmode=verify-full&sslrootcert=/etc/skein/rds-global-bundle.pem
```

Mount the file into the container and name the path inside it.

## Behind a reverse proxy or load balancer

Skein serves plain HTTP on `SKEIN_BIND`; put TLS in front of it and set
`SKEIN_PUBLIC_URL` to the `https://` address people use. Skein writes
that URL — never the `Host` a request arrived with — into everything it
hands out, so the proxy's `Host` header does not matter to it.
[`deploy/nginx.conf`](../deploy/nginx.conf) is a working configuration;
whatever you run, it needs:

- **No body limit below Skein's own.** A publish is one request body:
  up to 128 MiB of artifact for Maven, PyPI and Cargo, about 171 MiB of
  base64 for npm, and a container layer of any size up to 16 GiB. nginx
  refuses anything over 1 MiB by default (`client_max_body_size 0;`
  lifts it); a cloud load balancer may have its own ceiling.
- **Streaming, not buffering**, so a large layer is not spooled to the
  proxy's disk first (`proxy_request_buffering off;`).
- **Timeouts long enough for a large push** — minutes, not the usual
  60 seconds.
- **HTTP/1.1 to clients if you can.** Maven, twine and pip print only
  the status line of a refusal, so Skein puts its sentence — "rita is a
  reader here, and a reader may not publish…" — in the reason phrase.
  HTTP/2 has no reason phrase, and some load balancers rewrite it; the
  refusal is still correct, only less informative (twine shows the body
  with `--verbose`).
- Container images need Skein at the **root** of its own host name: a
  container client has nowhere to put a base path. See
  [containers.md](containers.md).
- **`SKEIN_TRUST_PROXY_HEADERS=true`**, when every request reaches Skein
  through the proxy: otherwise every sign-in arrives from the proxy's
  address, and twenty failures from anybody lock sign-in for everybody.
  See [Sign-in protection](#sign-in-protection). `compose.tls.yml` sets
  it.

## Several replicas

Run as many `skein` processes as you like against one database and one
bucket, behind a load balancer; no stickiness is needed. Sessions,
tokens, upload sessions (a `docker push` whose requests land on
different replicas) and the licence check all live in the database; the
collector's deletes are re-checked, so every replica may run it. Only
the sign-in counters are per process — see
[Sign-in protection](#sign-in-protection).

## Sizing

A publish is held in memory while its digest is checked: plan for the
largest artifact your people publish, times the publishes that happen at
once, on top of a few tens of megabytes per process. Container layers
are streamed in 16 MiB blocks and are the exception. Each process holds
one database connection.

## Outbound connections

Skein connects to its database and bucket, and to two things on the
internet, both optional:

- the npm upstream (`SKEIN_UPSTREAM_NPM`), only when npm is in `proxy`
  mode;
- `license.weft.sh`, once a day, only with an online licence key — see
  [licensing.md](licensing.md).

Each trusts what every TLS connection trusts, `SKEIN_CA_FILE` included,
so an internal mirror under your own CA works. The npm upstream's
redirects are followed only while they stay on the configured upstream;
a mirror that hands downloads to another host is refused with a
sentence saying so.

Both connect **directly**: `HTTPS_PROXY` is not read today. The HTTP
client's own proxy support ignores `NO_PROXY`, so honouring it would
also send loopback and internal addresses through the proxy. An install
that reaches the internet only through a forward proxy cannot use npm's
proxy mode, and its licence check does not complete — which becomes a
warning after seven days and never a refusal.

## Logs

Skein writes plain lines to standard error, one event per line, each
beginning `skein:` — start-up, the licence's warnings when they change,
the collector's work, and failures. There is no access log; your proxy
or load balancer keeps that. Lines carry no timestamp of their own: the
container runtime or journald adds one (`docker logs -t`). Nothing
secret is logged — no password, token or licence key.

## Air-gapped installs

Skein needs nothing from the internet to run: it starts, serves and
collects with no route out. The npm proxy mode and an online licence
key are the only features that reach outside, and both are off unless
you configure them. Use an offline licence key.

What you bring inside is the image or the static binary. Each release
carries the image as a file per architecture,
`skein-image-<version>-linux-<arch>.tar.gz`, beside the binaries and
their checksums:

```sh
docker load -i skein-image-v0.1.0-linux-amd64.tar.gz
```

The image loads under the name the Compose bundle already names,
`ghcr.io/weftsh/skein:<version>`, so the bundle then starts with nothing
pulled for Skein itself.

For the Compose file, bring the `postgres:16`, `nginx` and MinIO images
too — mirror them into your own registry, or `docker save` and
`docker load` them across.

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

## Backing up and restoring

Everything is in two places: the database and the bucket. Bytes are
content-addressed and never change once written, and a publish writes
its bytes before the row that names them — so a backup is consistent if
the **database is dumped first and the bucket copied after**: every
file the dump names is already in the bucket.

```sh
# 1. The database.
pg_dump -Fc "$SKEIN_DB_URL" > skein-$(date +%F).dump
# 2. The bucket, after the dump finished. MinIO's client shown; aws s3 sync works the same.
mc mirror --overwrite skein/skein backup/skein-$(date +%F)
```

The collector deletes bytes a package no longer needs once they have
been unreferenced for `SKEIN_GC_GRACE_SECS` (an hour by default). If a
bucket copy may take longer than that, stop the collector for the
duration (`SKEIN_GC_INTERVAL_SECS=0`) or keep bucket versioning on, so
that nothing the dump names is collected before it is copied.

To restore, into an empty database and bucket:

```sh
pg_restore --no-owner -d "$SKEIN_DB_URL" skein-2026-09-28.dump
mc mirror backup/skein-2026-09-28 skein/skein
```

then start Skein. Bytes the bucket holds that the dump does not name —
publishes after the dump — are collected after the grace period.

## Upgrading

Stop every replica, take a backup, start the new release: it migrates
the database on start, under a lock, so replicas starting together wait
for one another. Then start the rest. Migrations only go forward; a
release refuses to start against a database a newer release migrated,
saying which versions it knows. Going back means restoring the backup
taken before the upgrade.

## The admin command line

`skein admin …` runs against the same environment as the server —
`docker compose exec skein skein admin …` in Compose.

| | |
|---|---|
| `bootstrap --org <name>` | create the organization, its npm scope `@<name>`, and its first admin, once |
| `create-user <name> [--role reader\|publisher\|admin] [--no-password]` | add a person, or a CI service account with `--no-password` |
| `reset-password <name>` | a new password, and signed out everywhere |
| `set-role <name> <role>` | change what somebody may do |
| `mint-token <name> --scope <scope> [--label …]` | a token, printed once |
| `gc [--grace-secs N]` | collect unreferenced bytes now |
| `license status\|install\|check\|keys` | the licence — see [licensing.md](licensing.md) |

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
  answered **429** with `Retry-After` (seconds) and a sentence — `too
  many failed sign-ins for ada; try again in 14 minutes` — **before**
  the password is looked at. The right password is refused too; that is the point.
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
later, once nothing references them and nobody has used them for
`SKEIN_GC_GRACE_SECS`. Using them means storing them — the same bytes
published again under another name count — or, for a container layer,
being answered for to a `HEAD`, mounted into another repository, or
named by a manifest being pushed: each of those is a push building on
bytes it will not send, and the grace is what keeps them there until
its manifest arrives. The clock starts at the last use, not at the
delete, so bytes stored long ago and deleted now may go at the next
pass. `skein admin gc --grace-secs N` runs one pass now and prints what
it collected.
