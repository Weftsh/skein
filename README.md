# Skein

**A self-hosted package registry for your organization — npm, Maven,
PyPI, Cargo and container images, behind one login, in your own
infrastructure.**

Skein is the package registry behind [Weft](https://weft.sh), packaged to
run on your own machines: one binary, PostgreSQL, and any S3-compatible
bucket. Publish with the tools you already use, install with a token
from your own registry, and decide at the door what third-party code
may enter your builds.

> **Pre-release.** Skein is being carved out of the hosted product right
> now. The npm registry, its pull-through proxy and admission policy,
> people and tokens, the web UI and the REST API work today; Maven,
> PyPI, Cargo and container images are landing next.

[![CI](https://github.com/weftsh/skein/actions/workflows/ci.yml/badge.svg)](https://github.com/weftsh/skein/actions/workflows/ci.yml)
[![License: FSL-1.1-ALv2](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](LICENSE.md)

## Why Skein

- **Everything is private.** There are no public packages and no
  anonymous reads. Every install and every publish is a person, with a
  token whose authority is their role *now* — demote somebody and the
  token in their `.npmrc` loses the difference on its next request.
- **A published version never changes.** Publishing `1.0.0` twice is
  refused, and every upload is checked against its digest before it is
  stored. Yank hides a version without breaking the lockfiles that pin
  it.
- **Decide what enters your builds, at the door.** Put npm in proxy mode
  and public packages arrive through Skein, cached in your own bucket,
  and meet a policy on the way in: licence rules evaluated as real SPDX
  expressions, a waiting period before a new release is served, and
  names that are yours and are never fetched from anywhere else. Start
  in audit mode and read what it *would* have refused before you turn
  it on.
- **Your builds stop depending on npmjs being up.** Anything installed
  once keeps installing from the cache during an upstream outage.
- **Small to run.** One stateless binary; run one, or ten behind a load
  balancer, against the same database and bucket.

## Try it

You need PostgreSQL and an S3-compatible bucket (MinIO is fine).

```sh
export SKEIN_DB_URL=postgres://skein:skein@127.0.0.1:5432/skein
export SKEIN_STORE_URL=http://127.0.0.1:9000/skein
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…
export SKEIN_PUBLIC_URL=http://localhost:8080

cargo run -p skein-server -- admin bootstrap --org acme   # once: prints the admin's password and token
cargo run -p skein-server                                  # serve on :8080
```

Open http://localhost:8080 and sign in as `admin` with the password the
bootstrap printed. **Connect a client** fills in each tool's
configuration for your registry and mints the token it needs. Or, by
hand, point npm at it:

```ini
# .npmrc
@acme:registry=http://localhost:8080/npm/
//localhost:8080/npm/:_authToken=skein_…
```

```sh
npm publish            # from a package named @acme/…
npm install @acme/widget
```

`npm login --registry=http://localhost:8080/npm/` also works, with your
Skein username and password.

- [docs/npm.md](docs/npm.md) — npm: configuration, publishing, yanking, the proxy
- [docs/policy.md](docs/policy.md) — the admission policy for what enters from upstream
- [docs/operations.md](docs/operations.md) — configuration, health, the bucket, recovery
- [docs/licensing.md](docs/licensing.md) — the licence key, seats, and exactly what the daily check sends
- [docs/api.md](docs/api.md) — the REST API

## Layout

```
crates/skein-store     the S3 client: SigV4, conditional PUT, LIST, DELETE
crates/skein-control   PostgreSQL: packages, versions, admission policy,
                       people, tokens, sessions, audit
crates/skein-server    the `skein` binary: the registry doors, the REST
                       API, the collector, and the UI (src/ui — three
                       files, no build step, compiled into the binary)
crates/skein-license   the licence: offline Ed25519 key verification, what it
                       means today, and the daily check — never a refusal
crates/skein-testkit   hermetic test harnesses: PostgreSQL, MinIO, a fake
                       npm upstream, a spawned server
```

## Development

```sh
scripts/fetch-minio.sh                  # once
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                  # needs PostgreSQL binaries installed
SKEIN_REQUIRE_CLIENTS=npm cargo test -p skein-server --test clients_e2e

# The UI in a real Chromium, every page plus the licence flow:
(cd crates/skein-server/tests/ui && npm ci && npx playwright install chromium)
SKEIN_REQUIRE_CLIENTS=browser cargo test -p skein-server --test ui_e2e
```

[CLAUDE.md](CLAUDE.md) is the working discipline: what a change has to
survive, and what to do when you find something wrong.

## License

A licence key from Weft is what receives releases and security patches;
it never stops Skein serving. See [docs/licensing.md](docs/licensing.md).

Skein is published under the [Functional Source License, Version 1.1,
ALv2 Future License](LICENSE.md): you may read, audit, modify and run it
for any purpose other than offering a competing product or service, and
each release becomes available under Apache-2.0 on the second
anniversary of its release.
