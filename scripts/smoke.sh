#!/usr/bin/env bash
# Container smoke test: the image runs read-only, as non-root, with every capability dropped, serves the example page in
# static mode with the designed headers, and refuses what it should. Then the hosted roles against a throwaway TLS
# PostgreSQL (scripts/test-postgres.sh, started here): `migrate`, `serve --mode pages` and `serve --mode app` answer,
# and the switches are closed (SMOKE_HOSTED=0 skips this part).
#
#   bash scripts/smoke.sh <image>
set -euo pipefail
image="${1:?usage: smoke.sh <image>}"
engine="${CONTAINER_ENGINE:-docker}"
command -v "$engine" > /dev/null || engine=podman
port="${SMOKE_PORT:-18298}"
name="lib-smoke-$$"
here="$(cd "$(dirname "$0")/.." && pwd)"

cleanup() {
  "$engine" rm -f "$name" lib-smoke-pages-$$ lib-smoke-app-$$ > /dev/null 2>&1 || true
  [ -n "${PG_STARTED:-}" ] && bash "$here/scripts/test-postgres.sh" stop > /dev/null 2>&1 || true
}
trap cleanup EXIT

fail() { echo "smoke: FAIL: $*" >&2; "$engine" logs "$name" >&2 || true; exit 1; }

user="$("$engine" image inspect --format '{{.Config.User}}' "$image")"
[ "$user" = "65532:65532" ] || fail "image user is ${user}, want 65532:65532"

"$engine" run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p "127.0.0.1:${port}:8080" -v "${here}/examples:/config:ro" \
  -e SITE_CONFIG=/config/site.json -e MANIFEST=/config/manifest.json \
  "$image" serve --mode static > /dev/null

base="http://127.0.0.1:${port}"
for _ in $(seq 1 40); do curl -fsS "${base}/healthz" > /dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "${base}/healthz" > /dev/null || fail "the server did not start"

headers="$(curl -fsS -D - -o /tmp/lib-smoke-page.html "${base}/")"
grep -qi "^content-security-policy: default-src 'none'" <<< "$headers" || fail "no strict CSP on /"
grep -qi '^referrer-policy: no-referrer' <<< "$headers" || fail "no Referrer-Policy"
grep -qi '^x-content-type-options: nosniff' <<< "$headers" || fail "no nosniff"
grep -qi '^link: .*rel="linkset"' <<< "$headers" || fail "no linkset Link header"
grep -qi '^set-cookie' <<< "$headers" && fail "a cookie was set"
grep -q '<h1 class="name p-name">Ada Example</h1>' /tmp/lib-smoke-page.html || fail "the page did not render"

ct="$(curl -fsS -o /dev/null -w '%{content_type}' "${base}/links.json")"
[[ "$ct" == application/linkset+json* ]] || fail "links.json content type is ${ct}"
css="$(grep -o '/_/page\.[0-9a-f]*\.css' /tmp/lib-smoke-page.html | head -1)"
curl -fsS -D - -o /dev/null "${base}${css}" | grep -qi '^cache-control: public, max-age=31536000, immutable' || fail "the stylesheet is not immutable"

[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/")" = 405 ] || fail "POST / was not refused"
[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/.env")" = 404 ] || fail "/.env was served"
[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/.well-known/webfinger?resource=acct:ada@links.example.org")" = 200 ] || fail "webfinger"

"$engine" run --rm --read-only --cap-drop ALL -v "${here}/examples:/config:ro" "$image" check /config/manifest.json --owner operator > /dev/null \
  || fail "check subcommand"
if [ "${SMOKE_HOSTED:-1}" != 0 ]; then
  export PG_DIR="${PG_DIR:-${TMPDIR:-/tmp}/link-in-bio-smoke-pg}" PG_NAME=link-in-bio-smoke-pg PG_PORT=55435 DOCKER="$engine"
  bash "$here/scripts/test-postgres.sh" start > /dev/null
  PG_STARTED=1
  # shellcheck source=/dev/null
  . "$PG_DIR/env.sh"
  url="${TEST_DATABASE_URL/sslrootcert=*/sslrootcert=/certs/ca.crt}"
  hosted() { # <detach args|--rm> <args...>
    local mode="$1"; shift
    # shellcheck disable=SC2086
    "$engine" run $mode --read-only --cap-drop ALL --security-opt no-new-privileges --network host \
      -v "$PG_DIR/certs:/certs:ro" -e DATABASE_URL="$url" -e PAGES_DOMAIN=links.example.org -e APP_HOST=app.links.example.org \
      -e INTERNAL_LISTEN_ADDR=127.0.0.1:18302 "$image" "$@"
  }
  hosted --rm migrate | grep -q "schema up to date" || fail "migrate"
  hosted "-d --name lib-smoke-pages-$$" serve --mode pages --listen 127.0.0.1:18300 > /dev/null
  hosted "-d --name lib-smoke-app-$$" serve --mode app --listen 127.0.0.1:18301 > /dev/null
  for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:18301/healthz > /dev/null 2>&1 && break; sleep 0.25; done
  instance="$(curl -fsS -H 'Host: app.links.example.org' http://127.0.0.1:18301/api/v1/instance)" || fail "app: instance"
  grep -q '"signup":"closed"' <<< "$instance" || fail "sign-up is not closed by default"
  grep -q '"thirdPartyPages":false' <<< "$instance" || fail "third-party pages are not off by default"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18301/api/v1/logout)" = 403 ] || fail "app: a write without Origin was not refused"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: alice.links.example.org' http://127.0.0.1:18300/)" = 404 ] || fail "pages: an unknown handle"
  curl -fsS http://127.0.0.1:18302/metrics | grep -q '^link_in_bio_accounts_active 0' || fail "app: metrics"
fi
echo "smoke: OK (${image})"
