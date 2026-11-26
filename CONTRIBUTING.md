# Contributing to link-in-bio-service

Thank you for looking. link-in-bio-service is part of [Meddleware](https://meddleware.co.uk): open tools you can use, take everything when you leave,
and run yourself. This file says how to build it, test it and propose a change.

## Build and test

The tests that touch the database need a PostgreSQL 18 with TLS. `scripts/test-postgres.sh` starts one in a container and writes the settings the tests read.

```bash
bash scripts/test-postgres.sh start                                  # a throwaway PostgreSQL 18 with TLS (Docker, or DOCKER=podman)
. "${TMPDIR:-/tmp}/link-in-bio-test-pg/env.sh"                       # TEST_DATABASE_URL and REQUIRE_TEST_DATABASE=1
cargo fmt --check                                                    # formatting
cargo clippy --workspace --all-targets --locked -- -D warnings       # lints; a missing doc comment on any item, private ones included, fails the build
cargo test --workspace --locked                                      # every crate; without TEST_DATABASE_URL the database tests skip, and CI forbids a skip
cargo deny check                                                     # advisories, licences, bans and sources
bash scripts/test-postgres.sh stop
```

The page (its stylesheet, script and browser tests) has its own checks:

```bash
cd page
npm ci
npm run check:vendored      # the tokens, brand icons and sprite this service vendors equal the pinned packages' files
npm run lint:css            # stylelint over the page's stylesheet
npm run test:e2e            # the real binary on the example page (E2E_BROWSERS=all for the five browsers)
npm run shots               # after a layout change: capture, then look at test-results/shots
```

The image is checked with `docker build -t link-in-bio-service:dev . && bash scripts/smoke.sh link-in-bio-service:dev`.
The README ("Quick start") and [CLAUDE.md](CLAUDE.md) ("Layers and commands") show the same commands with their context. CI runs them on every push and
pull request (`.github/workflows/rust-ci.yml`), and the release workflow runs them again on the tagged commit.
A change is ready when they all pass locally.

## Proposing a change

1. Open an issue first for anything larger than a fix, so the design can be agreed before the work.
2. Keep a change to one purpose. Write a short subject line in the imperative ("Refuse a link with a userinfo part"), and say why in the pull request.
3. **Never edit a migration that has been released.** The migrations are checked by checksum, comments included; a schema change is a new file in `crates/store/migrations/`.
4. **Every SQL statement lives in `crates/store`.** The other crates call its functions, so the database roles (owner, writer, read-only) stay the only way in.
5. Add or update tests with the behaviour they cover. A bug fix comes with a test that failed before it.
6. **A new manifest field** touches the parser, the model, the renderer, `fixtures/manifests.json`, the specification if other software can see it, and the editor (link-in-bio-ui) together.
7. **A new theme option** must pass the contrast table or be refused with a fix, and changes `page/src/page.css` and the fixtures.
8. A route change is made in `crates/api/src/hosted/routes.rs` and regenerates the OpenAPI files (`UPDATE_OPENAPI=1 cargo test -p link-in-bio-api`).
9. Add a line to `CHANGELOG.md`.
10. Security problems go to the address in [`SECURITY.md`](SECURITY.md), never to a public issue.

## House rules

- **Licence.** Everything here is [0BSD](LICENSE). By contributing you agree your contribution is released under it.
- **Versions.** Until the platform's mainnet launch, every release is a patch bump, breaking changes included; the changelog says what broke.
- **No operator data.** Host names, handles, links, prices and contact addresses belong to an operator's private deployment repository. Examples and tests use `example.org` and fixed test keys.
- **No echo.** A message, log line or error never repeats a configured or caller-supplied URL, token, key or password. Name the key or the position instead.
- **Privacy.** A page sets no cookie and loads nothing from elsewhere. The one cookie the service sets is the app's `__Host-` session cookie, after a person signs in. A colour choice is stored in the visitor's browser only while they tick "Remember on this device".
- **Fails closed.** Every hosted switch defaults to closed, and a setting can only close the service further.
- **Open standards.** Where a standard exists and fits, use it; the standards inventory in the audit (`docs/audit/link-in-bio-service-audit.md`) lists the ones this project speaks.
- **No JavaScript or TypeScript backend.** The service is Rust; `page/` holds the page's own assets and the build and test tooling only.

## Documentation

Every file explains itself, line by line where the code is not self-evident:

- a header on every file saying what it is for;
- a doc comment on every declaration (`///` in Rust, TSDoc in TypeScript and JavaScript, a comment line above a shell function), private ones included, and on every struct field and enum variant;
- comments that say **why**, cite the decision, issue or standard behind a choice, and are updated with the code;
- no `TODO` or `FIXME` without an issue or follow-up reference on the same line;
- every command a document shows has been run, and every link resolves.

The page's stylesheet and script are compiled into the binary with their comments removed (`crates/core/src/assets.rs`), so comments cost a visitor nothing; in `page/src/enhance.js` a comment stays on a line of its own, never after code.
