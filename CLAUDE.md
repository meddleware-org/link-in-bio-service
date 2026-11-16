# CLAUDE.md — link-in-bio-service

The server side of Link in Bio: one page per person, rendered on the server from a small document (the manifest), with the
documents other software reads (Profile Links, JSON-LD, WebFinger, ActivityPub, NIP-05, atproto-did). Usage:
[README.md](README.md). The format specification: [spec/profile-links-v1.md](spec/profile-links-v1.md).

## Invariants

- **No operator data in this repository.** Host names, handles, links, plans, prices and contact addresses belong to an
  operator's private deployment repository. Examples use `example.org`.
- **No JavaScript/TypeScript backend.** The service is Rust. `page/` holds build tooling and browser tests only; the page's
  stylesheet, script and sprite are committed files embedded in the binary.
- **One trust boundary.** `crates/core/src/manifest.rs` is the only parser of page documents. Every string goes through
  `text::clean_line`, every link through `safe_url::check_link` (`https:` and `mailto:` only), every theme through
  `theme::check` (AAA contrast in every mode the page can show). Unknown fields are dropped and reported. Nothing renders a
  manifest that did not pass the parser.
- **One renderer.** `crates/core/src/render.rs` (maud, auto-escaped) makes every page, the editor's preview included. No
  `PreEscaped` of anything a person typed (the only `PreEscaped` values are the sprite, fixed ids and the JSON-LD block, which
  is escaped by `interop::json_ld_for_html`). No inline `style` attribute and no inline script that runs.
- **Pages load nothing from elsewhere and set no cookie.** CSP `default-src 'none'` with `'self'` for styles, images and the
  one script; `Referrer-Policy: no-referrer`; links go straight to their targets (no redirector, no counting).
- **Pictures are re-encoded.** `crates/assets` decodes under limits and re-encodes from pixels (JPEG or PNG, 400×400,
  ≤ 64 KiB); tenants upload raster images only; the operator's own SVG is rasterised with resvg.
- **The local editor is loopback only.** `serve --mode local` binds 127.0.0.1, answers only loopback `Host` headers, and needs
  the editor header (and a loopback `Origin` if any) on every write. It makes no outbound request.
- **Vendored inputs are checked.** `crates/core/tokens/` (design-tokens), `assets/brand/` (ui brand icons) and
  `assets/icons.svg` (Simple Icons CC0, Lucide ISC) are written only by `page/scripts/*.mjs` from the pinned packages;
  `npm run check:vendored` fails when they drift.
- **No `unsafe`**, no `unwrap`/`expect` on request paths; release builds keep overflow checks and abort on panic.

## Layers and commands

| Crate | Holds |
| --- | --- |
| `link-in-bio-core` | manifest + parser, text and URL rules, theme + contrast + theme CSS, renderer, interop documents, embedded assets |
| `link-in-bio-assets` | the picture pipeline |
| `link-in-bio-api` | site config, the static and local routers, security headers |
| `link-in-bio` (`crates/cli`) | `serve --mode static|local`, `check`, `render`, `schema`, `theme-table` |

```bash
cargo +stable test --workspace --locked
cargo +stable clippy --workspace --all-targets --locked -- -D warnings && cargo +stable fmt --check && cargo deny check
cd page && npm ci && npm run check:vendored && npm run lint:css && npm run test:e2e   # E2E_BROWSERS=all for five browsers
cd page && npm run shots                                                             # then look at test-results/shots
docker build -t link-in-bio-service:dev . && bash scripts/smoke.sh link-in-bio-service:dev
```

Run the example page: `cargo run -p link-in-bio -- serve --mode static --config examples/site.json --manifest
examples/manifest.json --listen 127.0.0.1:4298`. The editor backend: `cargo run -p link-in-bio -- serve --mode local --dir
./my-page --owner operator`.

## Rules for changes

- A new manifest field: parser, model, renderer, `fixtures/manifests.json` cases, the spec if it is visible to other
  software, and the editor (link-in-bio-ui) together.
- A theme option: `theme.rs` (it must pass the contrast table or be refused with a fix), `page/src/page.css`, fixtures.
- After a layout change, `npm run shots` and look at the pictures before committing.
- Commit messages: one short line, no body, no trailer.
