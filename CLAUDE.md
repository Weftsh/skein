# Working in Skein

Skein is the package registry from stratum-core (the Weft forge), carved
out to run on its own: one binary, PostgreSQL and an S3-compatible
bucket. The code keeps stratum-core's design record in its doc comments.
Read them before changing what they describe; they say why, and the why
is usually a bug somebody already paid for.

The short version: **run the gates before every push, fix what you
find rather than routing around it, and pin every fix with a test that
fails without it.**

## The gates

| Gate | What it proves | Where |
|---|---|---|
| **test** | `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` — against a real PostgreSQL and a real MinIO, never a mock | CI job `test` |
| **clients** | the real `npm` (and each client as its door lands) publishes to and installs from a real server, and a refusal reaches the person as a sentence | CI job `clients`, `crates/skein-server/tests/clients_e2e.rs` |

Locally:

```sh
scripts/fetch-minio.sh             # once; the testkit starts its own MinIO
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace             # needs PostgreSQL binaries on the machine
SKEIN_REQUIRE_CLIENTS=npm cargo test -p skein-server --test clients_e2e
```

A client that is not installed prints a **NOTE** and claims nothing. A
NOTE is not a pass: a machine with no `npm` has not proved the npm
contract. The CI job sets `SKEIN_REQUIRE_CLIENTS` so a missing client
fails there.

## A fake encodes what we believe

Every hermetic test sends bodies we built from what we believe a client
sends, and a suite built on a belief that is wrong is green precisely
where the product is broken. stratum-core learned it three times — a
fake GitHub that always sent `Retry-After`, a fake Stripe with the
billing period in the wrong place, a fake runner API that attached
labels GitHub does not — and each time the fix was to make the real wire
the evidence. That is why `clients_e2e.rs` drives real clients and
asserts on what came back *through the client*, and why the npm proxy's
fake upstream is held to recorded npmjs documents in
`crates/skein-testkit/fixtures/registry` by
`upstream_fixtures_parse_like_the_fake`.

## Nothing here is public

Every request is a person, through a token or a browser session. There
is no anonymous read and no public package. The order of refusals on a
registry door is the security boundary, and every door keeps it:

1. no credential that authenticates → 401 with a `Basic` challenge,
   before anything else is looked at;
2. the ecosystem is off, or the package is absent → 404;
3. the person's role or token does not reach → 403 with a sentence
   naming which.

A new door gets a negative suite, and every negative case ends by
proving the server is still healthy and serving.

## When you find a bug or a gap

1. **Fix it now, in this change.** Not a follow-up, not a TODO.
2. **Pin it with a test that fails without the fix.** If you cannot
   write the test first, revert the fix and watch the test go red.
3. **Test the behaviour, not the symptom.** Cover the class.
4. **Say so in the commit message**, in plain words.

None of these are reasons to skip a fix: "unrelated", "pre-existing",
"probably a flake", "the test is wrong", "it passes locally".

**"Flaky" is a claim, and it needs evidence.** A failure is real until
you can name the mechanism that made it spurious. Re-running confirms a
mechanism you already suspect; it never decides there wasn't one.

## Habits

- **Don't push half an increment.** A module nobody calls fails clippy's
  `dead_code`, and it is right to.
- **Exercise the thing, not the form.** Seeing a version in a listing
  proves a row was written, not that anybody can install it — follow the
  URL the registry handed out and compare the bytes.
- **Hermetic tests.** PostgreSQL and MinIO come from `skein-testkit`;
  the npm upstream is a fake on loopback. Nothing in `cargo test`
  reaches the real network except `clients_e2e.rs`, and only through the
  client being tested.
- **Report faithfully.** If something is failing, say so with the
  output. If a step was skipped, say which and why. "Done" means
  verified.
