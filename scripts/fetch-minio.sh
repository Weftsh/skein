#!/usr/bin/env bash
# Put the pinned MinIO server binary at .testkit/bin/minio.
#
# MinIO stopped publishing prebuilt binaries. `dl.min.io`, which the test
# harness and CI both used to curl, answers **410 Gone** for every
# platform of the pinned release, and the GitHub release carries no
# assets — the same withdrawal that took `minio/minio` and `minio/mc` off
# Docker Hub and moved `deploy/compose.yml` to quay.io, arriving at the
# other artifact a few weeks later. The container image is the only thing
# still published.
#
# This pulls the image without a container runtime, straight off a
# registry's HTTP API, so the suite can fetch its store on a CI runner
# that has no docker daemon.
#
# The pin comes from `.minio-version`, which `crates/skein-testkit` also
# `include_str!`s, so the harness and CI cannot run different MinIOs.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release="$(tr -d '[:space:]' < "$root/.minio-version")"
out="${1:-$root/.testkit/bin/minio}"

if [ -x "$out" ]; then
  echo "minio already at $out"
  exit 0
fi

# The image carries a Linux binary and nothing else does. There is no
# darwin build left to fetch anywhere, so say what actually works here
# instead of producing an ELF that cannot execute — which is how this
# last went wrong, and it presented as "minio never became ready".
case "$(uname -s)" in
  Linux) ;;
  *)
    cat >&2 <<MSG
MinIO publishes no $(uname -s) binary any more, and the container image
carries a Linux one. Run it and point the harness at it instead:

  docker run -d --name skein-test-minio -p 9000:9000 \\
    -e MINIO_ROOT_USER=skein-test -e MINIO_ROOT_PASSWORD=skein-test-only \\
    ghcr.io/weftsh/minio:$release server /data
  export SKEIN_MINIO_URL=http://127.0.0.1:9000
MSG
    exit 1
    ;;
esac

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "no minio image for $(uname -m)" >&2; exit 1 ;;
esac

# The image is read from ghcr.io/weftsh/minio, a byte-for-byte copy of
# quay.io/minio/minio made by github.com/weftsh/minio-mirror (every
# platform, by digest).
api=https://ghcr.io/v2/weftsh/minio
accept='application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json'

# Anonymous pull. ghcr issues a token for the asking on a public package;
# the header is still required, so this is not an unauthenticated request.
token="$(curl -fsSL "https://ghcr.io/token?scope=repository:weftsh/minio:pull" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
get() { curl -fsSL -H "Authorization: Bearer $token" -H "Accept: $accept" "$@"; }

# A multi-arch tag resolves to an index; pick this machine's entry.
index="$(get "$api/manifests/$release")"
digest="$(printf '%s' "$index" | python3 -c "
import json,sys
m = json.load(sys.stdin)
if 'manifests' not in m:
    print('')          # already a single-arch manifest
else:
    for e in m['manifests']:
        p = e.get('platform', {})
        if p.get('os') == 'linux' and p.get('architecture') == '$arch':
            print(e['digest']); break
    else:
        sys.exit('no linux/$arch in $release')
")"
[ -n "$digest" ] && manifest="$(get "$api/manifests/$digest")" || manifest="$index"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Newest layer first: the binary lives in one of the upper layers, and
# walking from the top means the first hit is the one the image would
# actually present at that path.
layers="$(printf '%s' "$manifest" | python3 -c \
  "import json,sys; print('\n'.join(l['digest'] for l in reversed(json.load(sys.stdin)['layers'])))")"

found=
for layer in $layers; do
  get -o "$tmp/layer.tgz" "$api/blobs/$layer"
  # Each layer is its own tar; the path is absent from most of them, and
  # a miss is expected rather than an error.
  if tar -xzf "$tmp/layer.tgz" -C "$tmp" usr/bin/minio 2>/dev/null; then
    found=yes
    break
  fi
done
[ -n "$found" ] || { echo "usr/bin/minio not found in any layer of $release" >&2; exit 1; }

mkdir -p "$(dirname "$out")"
install -m 0755 "$tmp/usr/bin/minio" "$out"
echo "minio $release -> $out"
