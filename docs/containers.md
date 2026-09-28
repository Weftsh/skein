# Container images

Skein is a container registry as well as a package registry: `docker
push`, `docker pull`, tags, multi-platform images, and layers of any
size up to 16 GiB. Anything that speaks the OCI distribution protocol
works the same way — `podman`, `buildah`, `crane`, `skopeo`, a
Kubernetes node's pull.

Like everything else in Skein, nothing is public. Every pull is a person
with a token, and there is no anonymous read.

## Logging in

A token is the password; the username is not checked, so use anything:

```sh
echo "$SKEIN_TOKEN" | docker login skein.example.com --username skein --password-stdin
```

**Connect a client** in the UI mints a token and fills this in for your
host. A reader's token pulls; a publisher's token pushes too. Without a
token that verifies, every request — even the version probe `docker
login` makes first — is answered `401` with a `Basic` challenge, so the
only thing somebody without a credential learns is that they need one.

A person who may not push is told why, in docker's own output:

```text
denied: rita is a reader here, and a reader may not publish to this registry
```

## Naming an image

A Skein install serves one organization, so the organization is not
part of an image's name. The repository is **everything after the
host**:

```sh
docker tag service:latest skein.example.com/team/service:1.0
docker push skein.example.com/team/service:1.0     # repository "team/service"
docker pull skein.example.com/team/service:1.0

docker push skein.example.com/app:1                # repository "app" — one component is fine
```

A repository name is lowercase letters, digits, and `.`, `_`, `-`
between them, in `/`-separated components — the distribution spec's
grammar — and at most 214 bytes. The spec allows 255; a longer name is
refused with `NAME_INVALID` rather than truncated.

Each repository appears in the UI and `GET /api/v1/packages` as an `oci`
package under its whole name, with one version per tag.

## Tags move; manifests do not

Everywhere else in Skein a published version never changes. A **tag**
is the exception, because moving is what a tag is for: pushing `latest`
again points it at the new image. What never changes is the
**manifest**, which is addressed by its digest — the image a tag used to
point at is still pullable by digest after the tag has moved on:

```sh
docker pull skein.example.com/team/service@sha256:…
```

That is what a deployment should pin.

Tags are compared without regard to case today, so `V1` and `v1` are
one tag and pushing either replaces the other. Use lowercase tags.

A tag can be deleted through the registry API by a publisher —
`DELETE /v2/<repository>/manifests/<tag>`. A manifest cannot be deleted
by digest: it may be what somebody else's tag points at, and the
distribution spec lets a registry refuse, which is the answer that
cannot silently break another deployment. To remove a whole repository,
an admin deletes the package in the UI or with `DELETE
/api/v1/packages/<id>`.

## Multi-platform images

An image index — what `docker buildx build --platform …,… --push` and
`docker manifest push` produce — is stored like any other manifest. Its
platform manifests arrive by digest, with no tag of their own, and
everything they name is kept for as long as the index is tagged.

A blob Skein already holds is never sent twice: a `HEAD` for it answers
yes in every repository, and a cross-repository mount (`POST
/v2/<repository>/blobs/uploads/?mount=<digest>`) succeeds for any blob
the install holds. `docker manifest push`, which assembles an index in
one repository out of images pushed to others, depends on that.

## What is checked on a push

- Every layer is checked against its digest before it becomes
  addressable. An upload whose bytes are not the digest it was pushed
  as is refused with `DIGEST_INVALID` and never becomes pullable under
  either digest.
- A manifest is refused unless every blob it names is already here —
  and, for an index, every blob its platform manifests name. A registry
  that took one would serve an image nobody could pull, and the error a
  client printed would be about the missing layer rather than about the
  push that was wrong.

## Size

Layers are stored in 16 MiB blocks and streamed in and out, so a large
layer never becomes resident in Skein's memory. The ceiling is **16 GiB
per blob**. A manifest is at most 128 MiB, which no real manifest
approaches.

If Skein sits behind a reverse proxy, the proxy must let a large request
body through: with nginx, `client_max_body_size 0;` and
`proxy_request_buffering off;` on the location that serves `/v2/`.
Caddy has no body limit by default.

## Skein must be at the root of a host

A container client reads `host/path/image` as registry `host` and
repository `path/image`, and then talks to `https://host/v2/…`. There is
nowhere to put a base path: `docker pull skein.example.com/skein/team/app`
asks the registry at `skein.example.com` for a repository called
`skein/team/app`. So the container API answers at `/v2/` on the host
itself, and **Skein has to be served at the root of its own host name**
— `https://skein.example.com`, not `https://example.com/skein`. Set
`SKEIN_PUBLIC_URL` to that root.

## TLS

docker talks to a registry over HTTPS, and refuses plain HTTP for every
host except loopback (`127.0.0.0/8` and `::1`). So:

- **In production**, put TLS in front of Skein — a load balancer, or a
  reverse proxy such as Caddy or nginx — and log in to the `https://`
  host. See [operations](operations.md).
- **On your own machine**, `docker login 127.0.0.1:8080` works over
  plain HTTP as it is.
- **Anywhere else without TLS**, every docker daemon that talks to Skein
  has to list it in `insecure-registries` in `/etc/docker/daemon.json`
  and be restarted:

  ```json
  { "insecure-registries": ["skein.internal:8080"] }
  ```

  Credentials and images then cross the network in the clear, so this
  is for a network you trust and nothing else.

## Switching containers on and off

`skein admin bootstrap` switches containers on. An admin turns them off
or on again in the UI, or with

```sh
curl -X PUT https://skein.example.com/api/v1/ecosystems \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{ "ecosystem": "oci", "mode": "private" }'
```

While they are off, every repository under `/v2/` answers `404` to
somebody who has logged in, as if it were not there. Skein serves the images you push; it does not pull
through from Docker Hub or any other registry.

## Collecting unused layers

Deleting a repository, or a tag, leaves layers nothing references; they
are collected once they have been unreferenced for
`SKEIN_GC_GRACE_SECS`. A layer two images share stays as long as either
does. An upload that was started and never finished — an interrupted
`docker push` — is collected once nobody has written to it for a day.
