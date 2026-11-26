#!/usr/bin/env bash
# Container smoke test: the image runs read-only, as non-root, with every capability dropped, serves the example page in
# static mode with the designed headers, and refuses what it should. Then the hosted roles against a throwaway TLS
# PostgreSQL (scripts/test-postgres.sh, started here): `migrate`, `serve --mode pages` and `serve --mode app` answer,
# and the switches are closed (SMOKE_HOSTED=0 skips this part).
#
#   bash scripts/smoke.sh <image>
# Exit codes: 0 when every check passes; 1 on the first failure (the message says which, and the container's logs follow).
# Side effects: starts and removes containers named lib-smoke-*, writes /tmp/lib-smoke-page.html, and (hosted part) starts a
# throwaway PostgreSQL through scripts/test-postgres.sh and stops it again on exit.
# Environment: CONTAINER_ENGINE (docker, or podman when docker is absent), SMOKE_PORT (static port), SMOKE_HOSTED=0 (skip the
# hosted part), PG_DIR (where the throwaway database keeps its state).
set -euo pipefail
# The image under test is the one required argument.
image="${1:?usage: smoke.sh <image>}"
# Docker unless CONTAINER_ENGINE says otherwise; fall back to podman where docker is not installed.
engine="${CONTAINER_ENGINE:-docker}"
command -v "$engine" > /dev/null || engine=podman
# The host port for the static container, and the name every container started here shares (the PID keeps runs apart).
port="${SMOKE_PORT:-18298}"
name="lib-smoke-$$"
# The repository root, so the examples and scripts resolve wherever the script is run from.
here="$(cd "$(dirname "$0")/.." && pwd)"

# Remove every container this run started, then stop the throwaway database if this run started it. Never fails the run.
cleanup() {
  "$engine" rm -f "$name" lib-smoke-pages-$$ lib-smoke-app-$$ > /dev/null 2>&1 || true
  [ -n "${PG_STARTED:-}" ] && bash "$here/scripts/test-postgres.sh" stop > /dev/null 2>&1 || true
}
# Run cleanup however the script ends, including after a failure.
trap cleanup EXIT

# Print what failed, show the static container's log for context and stop with status 1.
fail() { echo "smoke: FAIL: $*" >&2; "$engine" logs "$name" >&2 || true; exit 1; }

# The image must run as the fixed non-root user, so a root image cannot pass.
user="$("$engine" image inspect --format '{{.Config.User}}' "$image")"
[ "$user" = "65532:65532" ] || fail "image user is ${user}, want 65532:65532"

# Start the static server as it runs in production: read-only filesystem, no capabilities, no privilege escalation, the example page.
"$engine" run -d --name "$name" --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p "127.0.0.1:${port}:8080" -v "${here}/examples:/config:ro" \
  -e SITE_CONFIG=/config/site.json -e MANIFEST=/config/manifest.json \
  "$image" serve --mode static > /dev/null

# Wait up to ten seconds for the server to answer its health check.
base="http://127.0.0.1:${port}"
for _ in $(seq 1 40); do curl -fsS "${base}/healthz" > /dev/null 2>&1 && break; sleep 0.25; done
curl -fsS "${base}/healthz" > /dev/null || fail "the server did not start"

# The page's response headers: strict CSP, no referrer, no sniffing, a linkset pointer and, above all, no cookie.
headers="$(curl -fsS -D - -o /tmp/lib-smoke-page.html "${base}/")"
grep -qi "^content-security-policy: default-src 'none'" <<< "$headers" || fail "no strict CSP on /"
grep -qi '^referrer-policy: no-referrer' <<< "$headers" || fail "no Referrer-Policy"
grep -qi '^x-content-type-options: nosniff' <<< "$headers" || fail "no nosniff"
grep -qi '^link: .*rel="linkset"' <<< "$headers" || fail "no linkset Link header"
grep -qi '^set-cookie' <<< "$headers" && fail "a cookie was set"
grep -q '<h1 class="name p-name">Ada Example</h1>' /tmp/lib-smoke-page.html || fail "the page did not render"

# The machine-readable twin has its registered media type, and the stylesheet is cached for a year because its name carries its hash.
ct="$(curl -fsS -o /dev/null -w '%{content_type}' "${base}/links.json")"
[[ "$ct" == application/linkset+json* ]] || fail "links.json content type is ${ct}"
css="$(grep -o '/_/page\.[0-9a-f]*\.css' /tmp/lib-smoke-page.html | head -1)"
curl -fsS -D - -o /dev/null "${base}${css}" | grep -qi '^cache-control: public, max-age=31536000, immutable' || fail "the stylesheet is not immutable"

# What the server must refuse or answer: no writes, no dotfiles, and WebFinger answers for the example account.
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "${base}/")" = 405 ] || fail "POST / was not refused"
[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/.env")" = 404 ] || fail "/.env was served"
[ "$(curl -s -o /dev/null -w '%{http_code}' "${base}/.well-known/webfinger?resource=acct:ada@links.example.org")" = 200 ] || fail "webfinger"

# The image's own `check` subcommand accepts the example manifest.
"$engine" run --rm --read-only --cap-drop ALL -v "${here}/examples:/config:ro" "$image" check /config/manifest.json --owner operator > /dev/null \
  || fail "check subcommand"
# The hosted roles, against a throwaway TLS PostgreSQL on its own port.
if [ "${SMOKE_HOSTED:-1}" != 0 ]; then
  export PG_DIR="${PG_DIR:-${TMPDIR:-/tmp}/link-in-bio-smoke-pg}" PG_NAME=link-in-bio-smoke-pg PG_PORT=55435 DOCKER="$engine"
  bash "$here/scripts/test-postgres.sh" start > /dev/null
  PG_STARTED=1
  # shellcheck source=/dev/null
  . "$PG_DIR/env.sh"
  # The same database URL, with the certificate path as the container sees it.
  url="${TEST_DATABASE_URL/sslrootcert=*/sslrootcert=/certs/ca.crt}"
  # Run one hosted role in a container (host network, read-only, no capabilities, the CA mounted): the first argument is `--rm`
  # for a one-shot command or the detach arguments for a server, the rest is the subcommand.
  hosted() { # <detach args|--rm> <args...>
    # The run mode, then the subcommand and its arguments.
    local mode="$1"; shift
    # The mode is deliberately unquoted: it is several words (`-d --name ...`).
    # shellcheck disable=SC2086
    "$engine" run $mode --read-only --cap-drop ALL --security-opt no-new-privileges --network host \
      -v "$PG_DIR/certs:/certs:ro" -e DATABASE_URL="$url" -e PAGES_DOMAIN=links.example.org -e APP_HOST=app.links.example.org \
      -e INTERNAL_LISTEN_ADDR=127.0.0.1:18302 "$image" "$@"
  }
  # Apply the schema, then start the two serving roles on their own ports.
  hosted --rm migrate | grep -q "schema up to date" || fail "migrate"
  hosted "-d --name lib-smoke-pages-$$" serve --mode pages --listen 127.0.0.1:18300 > /dev/null
  hosted "-d --name lib-smoke-app-$$" serve --mode app --listen 127.0.0.1:18301 > /dev/null
  # Wait for the app role, then check the closed-by-default switches, the origin check on writes, an unknown handle and the metrics.
  for _ in $(seq 1 40); do curl -fsS http://127.0.0.1:18301/healthz > /dev/null 2>&1 && break; sleep 0.25; done
  instance="$(curl -fsS -H 'Host: app.links.example.org' http://127.0.0.1:18301/api/v1/instance)" || fail "app: instance"
  grep -q '"signup":"closed"' <<< "$instance" || fail "sign-up is not closed by default"
  grep -q '"thirdPartyPages":false' <<< "$instance" || fail "third-party pages are not off by default"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:18301/api/v1/logout)" = 403 ] || fail "app: a write without Origin was not refused"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: alice.links.example.org' http://127.0.0.1:18300/)" = 404 ] || fail "pages: an unknown handle"
  curl -fsS http://127.0.0.1:18302/metrics | grep -q '^link_in_bio_accounts_active 0' || fail "app: metrics"
fi
echo "smoke: OK (${image})"
