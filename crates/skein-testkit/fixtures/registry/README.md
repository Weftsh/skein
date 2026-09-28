# Recorded upstream registry documents

These are **real answers from registry.npmjs.org**, recorded by
`scripts/record-npm-fixtures.py`. They are the evidence behind
`upstream_fixtures_parse_like_the_fake` in
`skein-server/src/registry/npm.rs`, which starts `skein-testkit`'s
`fake_registry`, reads what it serves with the product's own parser,
and fails the moment the fake and the recorded wire disagree.

That test exists because of a failure stratum-core, which Skein was
carved out of, paid for three times. `FakeGitHub` attached `Retry-After` to every refusal, so
the test named for a primary rate limit could not produce the input that
broke us. `FakeStripe` said the billing period lived on the
subscription, and it had moved to the item. The runner fake gave every
just-in-time runner three default labels real GitHub does not attach.
Each time a green suite sat on top of a belief that was wrong, and each
time the fix was to make the recorded wire the suite's evidence rather
than our own idea of it.

## What is in each file

Only the parts the product reads, trimmed to five versions — a whole
packument for `lodash` is a megabyte of README nobody would compare:

- `name`, `dist-tags`
- `versions[v]` with `name`, `version`, `license`, `licenses`, `dist`
  and `dependencies`
- `time[v]`, which is a **sibling map keyed by version**, not a field
  inside each version. The cooldown reads it, and getting that shape
  wrong means the cooldown silently holds nothing.

## What they are chosen to catch

- **`left-pad`** — its oldest versions declare `"license": "BSD"`, which
  is three different licences and is deliberately not in any mapping
  table. It is the ambiguous case, from the wild rather than invented.
- **`is-number`** — small, and every version dated, which is what the
  cooldown is read against.
- **`lodash`** — the shape a very old, very large package still has.

## Re-recording

```sh
python3 scripts/record-npm-fixtures.py
```

Commit what it writes. If a field has moved, the test goes red here
rather than in production.
