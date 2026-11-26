# link-in-bio-service

One page for every profile: a link-in-bio page rendered on the server from a small JSON document, accessible (WCAG 2.2
AAA contrast), private by default (no cookies, no trackers, no redirector), and readable by other software through open
formats.

- **Pages work without JavaScript.** Groups are native `<details>`; the only script adds a colour-mode control and copy
  buttons.
- **A constrained theme.** Colour mode, season, accent, button style, corner radius, density, layout and a system font
  stack. Every combination is checked for 7:1 text contrast in every mode the page can show; one that fails is refused with
  a message that names the fix (`link-in-bio theme-table` prints the whole table).
- **Open formats.** [Profile Links](spec/profile-links-v1.md) (an RFC 9264 link set), microformats h-card with `rel="me"`,
  schema.org `ProfilePage`, WebFinger and a read-only ActivityPub actor, Nostr NIP-05 and the AT Protocol handle file.
- **One binary.** `serve --mode static` serves one page from files; `serve --mode local` is the editor's loopback backend;
  `check` validates a page document; `render` writes the page to a directory.
- **A hosted service in the same binary.** `serve --mode pages|app|admin`, `worker` and `migrate` run pages for many
  accounts on PostgreSQL. Accounts sign in with passkeys or a Sui wallet; invite codes come only from the operator; paid
  periods go through pluggable payment providers; links are screened. Every switch defaults to closed:
  [docs/HOSTED.md](docs/HOSTED.md).

## Quick start

```bash
cargo run -p link-in-bio -- check examples/manifest.json --owner operator
cargo run -p link-in-bio -- serve --mode static --config examples/site.json --manifest examples/manifest.json --listen 127.0.0.1:4298
# open http://127.0.0.1:4298/
```

Container: `quay.io/meddleware-org/link-in-bio-service` (also on Docker Hub), multi-arch, signed with cosign (keyless,
this repository's `docker-publish.yml` on a `v*` tag) and shipped with SBOMs and build provenance:

```bash
cosign verify --certificate-identity-regexp '^https://github.com/meddleware-org/link-in-bio-service/\.github/workflows/docker-publish\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com quay.io/meddleware-org/link-in-bio-service@<digest>
docker run --rm --read-only -p 127.0.0.1:8080:8080 -v "$PWD/examples:/config:ro" \
  -e SITE_CONFIG=/config/site.json -e MANIFEST=/config/manifest.json quay.io/meddleware-org/link-in-bio-service:<version> serve --mode static
```

## The page document

```json
{
  "schema": 1,
  "identity": { "displayName": "Ada Example", "handle": "ada", "bio": "One line about you.", "avatar": "me.jpg" },
  "items": [
    { "id": "gh", "title": "GitHub", "url": "https://github.com/example", "identity": true },
    { "kind": "group", "id": "work", "title": "Work", "items": [ { "id": "docs", "title": "Docs", "url": "https://docs.example.org/" } ] }
  ],
  "theme": { "colorMode": "system", "accent": "season", "buttons": "outline" }
}
```

Links are `https:` or `mailto:` only; `identity: true` marks your own profiles (`rel="me"`). Limits:
`link-in-bio schema`. The site configuration (host, footer, contact for `security.txt`) is `examples/site.json`.

## Development

```bash
bash scripts/test-postgres.sh start && . "${TMPDIR:-/tmp}/link-in-bio-test-pg/env.sh"   # a throwaway PostgreSQL 18 with TLS (DOCKER=podman works)
cargo fmt --check && cargo clippy --workspace --all-targets --locked -- -D warnings      # a missing doc comment on any item fails the build
cargo test --workspace --locked                                                          # the database tests skip without TEST_DATABASE_URL; CI forbids a skip
bash scripts/test-postgres.sh stop
cd page && npm ci && npm run check:vendored && npm run lint:css && npm run test:e2e      # the page: vendored files, styles, browsers
```

How to propose a change: [CONTRIBUTING.md](CONTRIBUTING.md). The project's invariants and layout: [CLAUDE.md](CLAUDE.md). Licence: [0BSD](LICENSE).
