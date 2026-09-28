# Cargo

Skein serves your organization's crates to `cargo`: the sparse index,
`cargo publish`, downloads, and `cargo yank`. Like everything in Skein
it is private — every index read and every download is a person with a
token, and there is no anonymous access.

The examples use `https://skein.example.com` for your `SKEIN_PUBLIC_URL`
and `acme` for the registry's name in Cargo's configuration. The name is
yours to choose — it is only what you type after `--registry` — and your
organization's name is the natural one.

## Configuring Cargo

`~/.cargo/config.toml`:

```toml
[registries.acme]
index = "sparse+https://skein.example.com/cargo/index/"
credential-provider = ["cargo:token"]
```

`credential-provider` is required, not a nicety. Skein's `config.json`
says `auth-required`, and for a registry that does, Cargo reads no
token at all unless a provider is configured: every command stops with
"authenticated registries require a credential-provider to be
configured". `cargo:token` is Cargo's built-in provider and reads the
file below.

`~/.cargo/credentials.toml`:

```toml
[registries.acme]
token = "skein_…"
```

**Connect a client** in Skein's UI fills both files in for your
registry and mints the token they need. A token with `package:read`
resolves and downloads; publishing and yanking need `package:write`,
and a role that allows it.

## Depending on a crate

```sh
cargo add acme-widget@1.4.0 --registry acme
```

or, in `Cargo.toml`:

```toml
[dependencies]
acme-widget = { version = "1.4", registry = "acme" }
```

Renaming works as it does anywhere else —
`widget = { package = "acme-widget", version = "1.4", registry = "acme" }`
— and a crate published here may depend on other crates published here
the same way.

## Publishing

```sh
cargo publish --registry acme
```

Put `publish = ["acme"]` in the crate's `[package]` section: Cargo then
refuses to publish the crate to any other registry, crates.io
included.

`cargo publish` builds the packaged crate before it uploads, resolving
its dependencies through Skein, and afterwards waits until the new
version is in the index. Skein's index is assembled from the database on
every read, so the version is there the moment the upload is answered.

`license` in `Cargo.toml` is already an SPDX expression by Cargo's own
rule, so it is stored exactly as written. `license-file` points at a
file inside the archive, which Skein does not open: a crate that only
has one is recorded as *unknown* rather than being given a licence
somebody guessed.

A published version never changes. Publishing `1.4.0` twice is refused
— Cargo usually refuses it first, having read the index: "crate
acme-widget@1.4.0 already exists on `acme` index".

A crate may be up to 128 MiB.

## Yanking

```sh
cargo yank acme-widget --version 1.4.0 --registry acme
cargo yank acme-widget --version 1.4.0 --registry acme --undo
```

A yanked version is not chosen by a fresh resolution — Cargo reports
"version 1.4.0 is yanked" — but a `Cargo.lock` that already names it
still downloads and builds, so a yank never breaks a build that pinned
the version. It takes effect on the next index read. The audit log
records who yanked it, the same as a yank from the UI.

## When Cargo says no

What Cargo prints, and what it means here:

| Cargo says | Meaning |
|---|---|
| `` no token found for `acme` `` | there is no `credentials.toml` entry for this registry |
| `` token rejected for `acme` `` | the token is not one Skein knows: revoked, mistyped, or from another install |
| `(status 403 Forbidden): rita is a reader here, and a reader may not publish to this registry` | the person's role does not allow it |
| `(status 403 Forbidden): this token was not minted with package:write …` | the role allows it and the token does not: mint one with `package:write` |
| `` no matching package named `…` found `` | the crate is not published here — or Cargo is switched off, which reads the same on purpose |

## What Skein does on the wire

- **The token arrives with no scheme.** Cargo sends
  `Authorization: <token>` — the only one of the clients that does —
  and Skein's Cargo door reads that shape, as well as `Bearer`.
- **`auth-required`.** Cargo first asks for `config.json` without a
  token; Skein answers 401, and that is what makes Cargo send one.
- **The addresses in `config.json`** — where to download from and where
  to publish to — are built from `SKEIN_PUBLIC_URL`, so set it to the
  address people use. A client that reached Skein on loopback is
  answered with the loopback address it used; any other `Host` is not
  believed.
- **Routes**, under `SKEIN_PUBLIC_URL`:

  ```text
  GET    /cargo/index/config.json
  GET    /cargo/index/<prefix>/<name>
  GET    /cargo/api/v1/crates/<name>/<version>/download
  PUT    /cargo/api/v1/crates/new
  DELETE /cargo/api/v1/crates/<name>/<version>/yank
  PUT    /cargo/api/v1/crates/<name>/<version>/unyank
  ```

`skein admin bootstrap` switches Cargo on in `private` mode. An admin
switches it off or on under **Admission policy → Ecosystems**, or with
`PUT /api/v1/ecosystems` and `{"ecosystem": "cargo", "mode": "off"}`.
