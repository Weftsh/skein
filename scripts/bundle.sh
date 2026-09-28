#!/usr/bin/env bash
# The Compose bundle a release carries: what someone who has the release
# and not the source needs to run Skein — compose.yml, compose.tls.yml,
# .env.example and deploy/nginx.conf — with the image pinned to the
# release's own instead of built from a checkout.
#
#   scripts/bundle.sh <version> <out-dir> <image>
#   scripts/bundle.sh v0.1.0 artifacts ghcr.io/weftsh/skein:0.1.0
#
# writes <out-dir>/skein-compose-<version>.tar.gz, unpacking to
# skein-<version>/. The image job's smoke test runs the stack from this
# bundle, so the files a customer unpacks are the ones CI brought up.
#
# Until this existed a release shipped binaries and images and no Compose
# file, and the repository's compose.yml builds from source: the only
# documented install began with a clone and a Rust build.
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <version> <out-dir> <image>" >&2; exit 2; }
version="$1" out="$2" image="$3"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
dir="$stage/skein-$version"
mkdir -p "$dir/deploy"

# Each rewrite must find its line: compose.yml drifting away from what
# this script expects fails the release, not the customer.
rewrite() {
  local file="$1" from="$2" to="$3"
  grep -qxF -- "$from" "$file" || { echo "bundle: $file has no line: $from" >&2; exit 1; }
  FROM="$from" TO="$to" perl -0pi -e 's/^\Q$ENV{FROM}\E$/$ENV{TO}/m' "$file"
}

cp "$root/compose.yml" "$dir/compose.yml"
rewrite "$dir/compose.yml" '    build: .' '    # The released image; set SKEIN_IMAGE in .env to run another.'
rewrite "$dir/compose.yml" '    image: ${SKEIN_IMAGE:-skein:local}' "    image: \${SKEIN_IMAGE:-$image}"
rewrite "$dir/compose.yml" '#   docker compose up -d --build --wait' '#   docker compose up -d --wait'
if grep -q 'build:' "$dir/compose.yml"; then
  echo "bundle: compose.yml still builds from source" >&2
  exit 1
fi
cp "$root/compose.tls.yml" "$dir/compose.tls.yml"
rewrite "$dir/compose.tls.yml" \
  '#   docker compose -f compose.yml -f compose.tls.yml up -d --build --wait' \
  '#   docker compose -f compose.yml -f compose.tls.yml up -d --wait'
cp "$root/.env.example" "$dir/.env.example"
cp "$root/deploy/nginx.conf" "$dir/deploy/nginx.conf"
cp "$root/LICENSE.md" "$dir/LICENSE.md"

mkdir -p "$out"
tar -C "$stage" -czf "$out/skein-compose-$version.tar.gz" "skein-$version"
echo "$out/skein-compose-$version.tar.gz"
