# Operating Skein

Skein is one binary, `skein`, backed by PostgreSQL and an S3-compatible
bucket. Any number of `skein` processes can serve the same database and
bucket: package bytes are content-addressed, every write is checked
against its digest, and nothing is held in a process that another one
needs.

## Configuration

Everything is the environment.

| Variable | Default | Meaning |
|---|---|---|
| `SKEIN_DB_URL` | *(required)* | PostgreSQL URL, e.g. `postgres://skein:skein@db:5432/skein`. The schema is created and migrated on start. |
| `SKEIN_STORE_URL` | *(required)* | The bucket. Path-style (`http://minio:9000/skein`) or virtual-host style (`https://skein.s3.eu-west-1.amazonaws.com`). |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` | — | Credentials for the bucket. Every request is SigV4-signed when these are set. `AWS_REGION` defaults to `us-east-1`. |
| `SKEIN_STORE_CREATE_BUCKET` | `false` | Create the bucket on start if it does not exist. Path-style URLs only — for MinIO and other self-hosted stores; a bucket on AWS should be created on purpose, with its own policy. |
| `SKEIN_BIND` | `0.0.0.0:8080` | Where to listen. |
| `SKEIN_PUBLIC_URL` | `http://localhost:8080` | Where clients reach Skein. Written into the documents a registry hands out (an npm tarball URL), and decides whether the session cookie is `Secure`. |
| `SKEIN_UPSTREAM_NPM` | `https://registry.npmjs.org` | The upstream the npm pull-through proxy reads from, when npm is in `proxy` mode. |
| `SKEIN_UPSTREAM_ALLOW_PRIVATE` | `false` | Admit an upstream inside a private network — an internal mirror. It must still be HTTPS unless it is on loopback. |
| `SKEIN_GC_INTERVAL_SECS` | `3600` | How often unreferenced package bytes are collected. `0` switches the collector off. |
| `SKEIN_GC_GRACE_SECS` | `3600` | How long bytes must have been unreferenced before they are collected. A publish writes its bytes before its row, so this must comfortably exceed the longest publish. |
| `SKEIN_DB_LOCK_TIMEOUT_MS` | `5000` | How long a write waits on another's lock before failing rather than hanging a request. |

Skein serves plain HTTP. Put TLS in front of it — a load balancer, or a
reverse proxy such as Caddy or nginx — and set `SKEIN_PUBLIC_URL` to the
`https://` address people use.

Container images need two more things: Skein at the **root** of its own
host name, because a container client has nowhere to put a base path,
and a proxy that lets a multi-gigabyte request body through. See
[containers.md](containers.md).

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

## Collecting unreferenced bytes

Deleting a package removes its rows at once; its bytes are collected
later, once nothing references them and they have been unreferenced for
`SKEIN_GC_GRACE_SECS`. `skein admin gc --grace-secs N` runs one pass now
and prints what it collected.
