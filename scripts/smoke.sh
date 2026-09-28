#!/usr/bin/env bash
# Prove the image works: build it, bring up the Compose stack from the
# release bundle a customer unpacks (scripts/bundle.sh), bootstrap, and
# publish and install through it with the real npm.
#
#   scripts/smoke.sh                  # build, run, check, leave it running
#   SMOKE_DOWN=1 scripts/smoke.sh     # …and take it down (with its volumes)
#   SMOKE_UPSTREAM=1 scripts/smoke.sh # also proxy a real package from npmjs,
#                                     # which proves the image can make TLS
#                                     # calls out (it needs ca-certificates)
#   SMOKE_EXTRA_CA=ca.pem scripts/smoke.sh
#                                     # build behind a TLS-intercepting proxy
#
# What the unit and e2e suites cannot see is the artefact people run:
# a missing CA store, a binary that does not start on the runtime base,
# a HEALTHCHECK that never passes. This is where those show.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
# compose.yml has no default passwords, and every `docker compose`
# command reads it — the cleanup and the log dump included — so these
# come first.
export SKEIN_DB_PASSWORD="${SKEIN_DB_PASSWORD:-smoke-db-$RANDOM$RANDOM}"
export SKEIN_STORE_PASSWORD="${SKEIN_STORE_PASSWORD:-smoke-store-$RANDOM$RANDOM}"
base="${SMOKE_BASE:-http://127.0.0.1:8080}"
work="$(mktemp -d)"
# The stack runs from the release bundle, not the checkout: what is
# brought up here is what a customer with no source brings up. Its
# files are kept beside the checkout so SMOKE_DOWN can find them later.
bundle="$root/target/smoke-bundle/skein-smoke"
dc() { docker compose -p skein-smoke --project-directory "$bundle" -f "$bundle/compose.yml" "$@"; }
cleanup() {
  if [ "${SMOKE_DOWN:-}" = 1 ]; then dc down -v >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "smoke: FAIL: $*" >&2; dc logs skein >&2 || true; exit 1; }

echo "smoke: building the image"
docker build ${SMOKE_EXTRA_CA:+--secret id=extra_ca,src=$SMOKE_EXTRA_CA} -t skein:local . \
  || fail "the image did not build"
echo "smoke: unpacking the release bundle"
rm -rf "$root/target/smoke-bundle"
scripts/bundle.sh smoke "$root/target/smoke-bundle" skein:local >/dev/null \
  || fail "the bundle did not build"
tar -C "$root/target/smoke-bundle" -xzf "$root/target/smoke-bundle/skein-compose-smoke.tar.gz"
grep -q 'build:' "$bundle/compose.yml" && fail "the bundle's compose.yml builds from source"
echo "smoke: starting the stack"
dc up -d --wait || fail "the stack did not come up"

echo "smoke: bootstrapping"
boot="$(dc exec -T skein skein admin bootstrap --org acme --json)" \
  || fail "bootstrap"
token="$(printf '%s' "$boot" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"

for _ in $(seq 1 30); do
  curl -fsS "$base/readyz" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$base/readyz" >/dev/null || fail "readyz never passed: $(curl -sS "$base/readyz")"
curl -fsS "$base/" | grep -q '/ui/app.js' || fail "the UI is not served"

echo "smoke: publishing and installing with the real npm"
host="${base#http://}"
mkdir -p "$work/pkg" "$work/app" "$work/home"
cat > "$work/pkg/package.json" <<JSON
{ "name": "@acme/smoke", "version": "1.0.0", "license": "MIT", "main": "index.js" }
JSON
echo "module.exports = 'smoke ok';" > "$work/pkg/index.js"
printf '@acme:registry=%s/npm/\n//%s/npm/:_authToken=%s\n' "$base" "$host" "$token" > "$work/npmrc"
export HOME="$work/home" npm_config_userconfig="$work/npmrc" npm_config_update_notifier=false
(cd "$work/pkg" && npm publish >/dev/null) || fail "npm publish"
echo '{ "name": "app", "version": "0.0.0", "private": true }' > "$work/app/package.json"
(cd "$work/app" && npm install --no-audit --no-fund @acme/smoke >/dev/null) || fail "npm install"
[ "$(node -e "console.log(require('$work/app/node_modules/@acme/smoke'))")" = "smoke ok" ] \
  || fail "the installed package is not what was published"

if [ "${SMOKE_UPSTREAM:-}" = 1 ]; then
  echo "smoke: proxying a real package from registry.npmjs.org"
  curl -fsS -X PUT "$base/api/v1/ecosystems" -H "Authorization: Bearer $token" \
    -H "Content-Type: application/json" -d '{"ecosystem":"npm","mode":"proxy"}' >/dev/null
  printf 'registry=%s/npm/\n//%s/npm/:_authToken=%s\n' "$base" "$host" "$token" > "$work/npmrc"
  v="$(npm view is-number@7.0.0 version)" || fail "npm view through the proxy"
  [ "$v" = "7.0.0" ] || fail "the proxy answered $v for is-number@7.0.0"
fi

echo "smoke: ok"
