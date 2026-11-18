# Security Audit — `link-in-bio-service`

**Classification:** Internal security review (first pass, awaiting external review)
**Project:** link-in-bio-service  (one page per person rendered on the server from a parsed document, with its
  interoperable documents; the hosted service: tenant pages by host, the account API with passkeys and Sui wallet
  sign-in, the operator console behind Cloudflare Access and Keto, a billing router over seven payment adapters and three
  bank feeds, layered link screening, reports and appeals, a single-writer worker, PostgreSQL)
**Project type:** Rust service (+ container image; renders public pages)
**Template:** AUDIT_TEMPLATE.md (2026-11-01) + AUDIT_TEMPLATE_RUST.md (2026-10-08) + AUDIT_TEMPLATE_AUTH.md (2026-10-08) +
  AUDIT_TEMPLATE_DB.md (2026-10-25) + AUDIT_TEMPLATE_IMG.md (2026-10-08) + AUDIT_TEMPLATE_SITE.md (2026-09-30) +
  AUDIT_TEMPLATE_A11Y.md (2026-11-01) + AUDIT_TEMPLATE_SUI_CLIENT.md (2026-10-08, the wallet sign-in's signature rows
  only) + AUDIT_TEMPLATE_VUE.md (2026-11-01, B.VUE-1 hosting headers only) + AUDIT_TEMPLATE_TS.md (2026-11-01, the
  `page/` build and test tooling only)
**Deployment status:** `v0.0.4` tagged (image `quay.io/meddleware-org/link-in-bio-service`, signed by CI). The workspace's
  `config/images.yaml` and `post-bootstrap/link-in-bio/overlays/default` pinned `0.0.3`
  (`sha256:4a7fbc5c…`) at review; the hosted service runs on testnet with every switch closed (`SIGNUP_MODE=closed`,
  `TERMS_VERSION=unset`, `THIRD_PARTY_PAGES=off`, `BILLING_PROVIDERS=chain-payments` on testnet, `CUSTOM_HOSTNAME_CAP=0`,
  no Web Risk or ThreatFox key). The fixes of this pass are unreleased (next patch, 0.0.5).
**Review date:** 2026-11-18
**Reviewer:** Internal review
**Severity ceiling:** High — the service decides who signs in to an account, whether a payment extends a paid period, and
  what HTML is served under the product's domain for every tenant. A sign-in flaw takes over accounts; a ledger flaw gives
  away or takes away paid time; a renderer flaw runs a tenant's script for every visitor. Realised ceiling at this pass:
  **Low** (F30–F34; F1 and F2 were Medium, F25–F29 Low, all RESOLVED).
**Status:** first-pass baseline

**Toolchain:** `rust-version = "1.94"` (MSRV job), stable in CI   **Edition:** 2024
**Crates published:** no (`publish = false`)
**Runtime:** tokio multi-thread; axum 0.8.9 (http1); reqwest 0.13.5 with rustls 0.23.46 (ring), no redirects followed
**Auth role(s):** issuer and verifier of session cookies (BFF for link-in-bio-ui); WebAuthn relying party; verifier of Sui
  personal-message signatures; verifier of Cloudflare Access JWTs (RS256); authorization decision point through Keto;
  verifier of payment-provider notifications; OAuth/GNAP client of Revolut and Open Payments wallets
**Identity provider:** Cloudflare Access (team `https://<team>.cloudflareaccess.com`, keys at `/cdn-cgi/access/certs`) for the
  console; Ory Keto read API (`/relation-tuples/check/openapi`, namespace `LinkInBio`) for its role. Accounts have no IdP:
  passkeys, Sui wallets and recovery codes.
**Token formats:** session cookie `__Host-lib_session` (256-bit random, SHA-256 at rest); Access JWT (RS256, `kid`); WebAuthn
  assertions; Sui personal-message signatures (ed25519, secp256k1, secp256r1)
**Signing / client credentials:** Chain Payments merchant API key (`CHAIN_PAYMENTS_KEY_FILE`, Secret
  `link-in-bio-chain-payments-key`, mounted 0440); per provider and bank, when switched on: Square token and signature key,
  GoCardless token and webhook secret, Paddle key and webhook secret, the Open Payments ed25519 client key, Wise token and
  SCA key, bunq API key and RSA key, Revolut RSA key and refresh token; Web Risk and ThreatFox keys (all `*_FILE`, mounted
  from Secrets; none in the image)
**Authorization model:** static for accounts (a session names one account; every account route reads only that account's
  rows); Keto `LinkInBio:admin#member@<Access subject>` for the console
**Database:** PostgreSQL on the shared tier (namespace `database`), database `link_in_bio`, tables in schema `lib`, page views
  `public.*_v1`
**Roles:** `link_in_bio_migrate` (owner, DDL; migrate Job; 2 connections, 60 s statements) · `link_in_bio_app` (writer, DML on
  `lib`; api, admin, worker and the account Job; 20 connections, 10 s statements, 30 s idle in transaction) ·
  `link_in_bio_pages` (read-only, the page server; 18 connections, 5 s statements, 5 s idle in transaction) —
  `k8s/clusters/meddleware-org/database/services.conf`
**Migrations:** sqlx `migrate!` embedded (`crates/store/migrations/0001`–`0004`), checksummed, applied under sqlx's advisory
  lock by the `migrate` CronJob template before the workloads roll
**Data classes:**

- public: published page documents, pictures (by hash), handles, the page status;
- internal: drafts and versions, checkouts and billing events, screening verdicts, the blocklist, invites, selections,
  the audit log, bank-feed cursors;
- personal: the 18+ declaration and terms acceptance, the declared country and request country of each purchase, wallet
  addresses, passkey public keys, report contacts and texts, appeals, refund reasons, Open Payments buyer wallet
  addresses, payer addresses in Chain Payments evidence;
- secret-adjacent: session, recovery-code and invite hashes; invite codes held for an account until redeemed; WebAuthn and
  wallet ceremony state; the Open Payments continuation token (until continued); bunq's installation token and a rotated
  Revolut refresh token in `lib.bank_feeds.state` (usable only with the worker's key files).

**Backups:** included in the shared tier's backup (the platform's); a restore drill of `link_in_bio` is the platform's
  restore-drill set (pre-mainnet evidence, DB-M9)
**Images:** `quay.io/meddleware-org/link-in-bio-service` (Docker Hub mirror), tags `0.0.2`–`0.0.4`
**Base images:** `docker.io/library/rust:1-slim@sha256:4df2ae8c…` (build) · `gcr.io/distroless/cc-debian13:nonroot@sha256:cb87acc5…`
  (runtime)
**Runtime user:** 65532 (distroless nonroot)   **Runtime FS:** read-only root; no writable mount
**Deployed by:** `post-bootstrap/link-in-bio/{base,hosted,overlays/default}`, digest from `config/images.yaml`
**Build args:** `VERSION`, `VENDOR`, `DESCRIPTION`, `SOURCE_URL`, `DOCUMENTATION_URL`, `IMAGE_URL` (labels only; none secret)
**Generator:** the service's own renderer (maud 0.27.0); no site generator   **Generated sources:** each page from its
  published document (database) or the operator's mounted files; the stylesheet, script, sprite, brand icons and tokens are
  committed files written by `page/scripts/*.mjs` from pinned packages (`npm run check:vendored` in CI)
**Audience:** end users (visitors of tenant pages)   **Unpublished material:** drafts are never served by the page server
  (it reads only `published`); the editor's preview is session-only and sandboxed
**Support promise:** the page's stylesheet works without script; `page/` runs the five-browser end-to-end suite (Chromium,
  Firefox, WebKit, plus mobile profiles) **Accessibility gates:** the shared AAA sweep (axe, `@meddleware/frontend-config`) and
  Lighthouse in CI over six fixture pages × modes **Known exceptions:** none recorded in this repository

---

## Executive summary

The service renders untrusted documents into public pages, signs people in, and keeps a ledger of paid time. Its trust
boundaries are well drawn:

- **One parser, one renderer.** `crates/core/src/manifest.rs` is the only reader of page documents: unknown fields are
  dropped, every string goes through `text::clean_line` (NFC, controls, bidi overrides, invisible and private-use
  characters refused), every link through `safe_url::check_link` (`https:` and `mailto:` only, no credentials, no IP
  hosts). Themes are fixed names checked for AAA contrast, so no tenant CSS exists. maud escapes everything; the only raw
  HTML is the sprite, an icon enum and the JSON-LD block, which is escaped. Pages carry a strict CSP and never set a cookie.
- **Sign-in.** webauthn-rs with user verification; Sui wallet messages rebuilt from the server's own record with a
  one-use nonce taken by `DELETE … RETURNING`; ZIP-215 ed25519 and low-S ECDSA through the platform's shared verifier;
  80-bit one-use recovery codes; `__Host-` SameSite=Strict cookies stored as SHA-256 with idle and absolute limits; CSRF by
  exact `Origin` plus a custom header. Suspension ends sessions and every sign-in path refuses a suspended account.
- **Console.** Access JWTs verified with ring (RS256 only, `kid` from the team's set, issuer, audience, time with 60 s
  skew), the Keto role checked and cached briefly, and everything fails closed.
- **Ledger.** Every change to a paid period is one row per `(provider, provider_event)`, so a payment seen by notification
  and by reconciliation extends the period once; notification signatures are checked per adapter in constant time.

**This pass fixed inline (all with tests; 127 tests pass against PostgreSQL over TLS):**

- **F1 (Medium):** a picture upload could make the API pod decode up to 256 MiB twice inside a 192 MiB pod, on the async
  workers. Decoding is now bounded at 4096 pixels a side and 64 MiB, one at a time per process, off the runtime.
- **F2 (Medium):** answers from providers, banks and wallets were read without a size bound, and an Open Payments wallet is
  a server the buyer chooses. Every upstream answer is now read up to a fixed size.
- **F3:** the page server read the Web Risk key path from the shared configuration and would fail at start once it was
  set (reported by the deployment work). It now ignores every `*_FILE` setting.
- **F4:** no router had a time or concurrency bound. Every listening router now has both, shared across its routes.
- **F5:** Open Payments' public-address check could be passed by DNS rebinding. The resolver now refuses private addresses
  when the connection is made, and IPv6 forms that embed an IPv4 address are judged by it.
- F6 to F12: reserved infrastructure labels, console cache headers, an https-only Access team domain, a `sandbox` preview,
  a bounded page cache, `forbid(unsafe_code)`, and `SECURITY.md`.

**Fixed after the first pass (F25–F29, unreleased, next patch 0.0.5):**

- **F25:** one database role per process kind with grants per table and the audit log insert-only for all of them (its
  retention runs through an owner function); role tests for the page server and a writer; the console holds no key.
- **F27:** a card provider's payment is applied only when what it says was paid covers the checkout.
- **F26 (OQ1, decided: refunds on request take back exactly their months, others pro rata):** refunds never take back more than the
  purchase bought.
- **F28 (OQ2, decided):** Web Risk in two switchable modes (lookup, the default: weekly rechecks of published links only,
  a 20 % reserve for publishes, a paid allowance as a hard stop; update: local lists, confirmations under their own cap,
  default 0) and per-account change limits (`NEW_LINKS_PER_ACCOUNT_DAY`); **F29:** pictures keyed per account.

**Open:** none above Info but F30–F34 (each dispositioned below).

**Dispositions (34 findings):** RESOLVED 17 · ADJUDICATED 4 · ACCEPTED-RISK 1 · DEFERRED 0 · Positive 12.
**Counts by severity:** Medium 2 · Low 13 · Info 7 · Positive 12.

**Posture:** a careful design with the right primitives at every boundary, now with least privilege between the service's
own processes and amount checks on the card providers' notifications before real money flows.

## Threat model / trust boundaries

| Actor | Holds / controls | Can do | Bounded by |
| --- | --- | --- | --- |
| Visitor of a tenant page | a browser | read pages and their documents; POST to the read-only inbox | GET/HEAD only (inbox drops); CSP; no cookie; ingress 30 r/s per IP; 30 s and 128 at once per process (F4) |
| Tenant (signed-in account) | its session cookie | edit, preview and publish its page; upload pictures; buy months; ask refunds; appeal | session → one account; the parser on every save and publish; asset quota; ingress 20 r/s, uploads 2 r/s; one decode at a time (F1) |
| Anyone (no account) | requests to the app API | start sign-up (closed today), sign in, report a page | `SIGNUP_MODE`/`TERMS_VERSION`; ingress 30 r/min on sign-up, sign-in and reports; uniform refusals |
| A buyer's Open Payments wallet | its servers' answers | answer the service's requests | https, public addresses only, checked at connect (F5); answers ≤ 1 MiB (F2); no redirects; 15 s |
| Payment providers (Square, GoCardless, Paddle, Chain Payments) | notifications, API answers | mark a checkout paid or refunded | signature per adapter; ledger key per event; answers ≤ 1 MiB (F2); paid amount must cover the checkout (F27) |
| Banks (statement import, feeds) | credits | pay bank-transfer checkouts | reference, currency and amount ≥ the checkout's; once per reference; statements ≤ 16 MiB |
| Operator (console) | Access identity + Keto role | moderate, suspend, grant months, issue invites, import statements, record refunds | Access JWT + Keto per request (cached 30 s); CSRF; every change audited |
| Cloudflare edge and tunnel | `CF-IPCountry`, client address, Access | country evidence, rate-limit key, console gate | origin reachable only through the tunnel (platform); F30 |
| Operator / cluster | Secrets, ConfigMaps, the CLI | everything | platform custody (PLATFORM lens) |

**Primary trust anchors:** for content, the parser in `crates/core/src/manifest.rs` (nothing renders a document it did not
accept); for accounts, the server-side record of each ceremony (`lib.challenges`, taken once); for money, the ledger's
unique `(provider, provider_event)` and each adapter's signature check.

### Service actor matrix (RUST lens)

| Actor | Controls | Bounded by |
| --- | --- | --- |
| Network client | request line, headers, bodies ≤ 64 KiB (5 MiB pictures, 4 MiB statements), timing | `DefaultBodyLimit` per router; nginx `client-max-body-size` per path; `TimeoutLayer` 30 s / 60 s; `GlobalConcurrencyLimitLayer` per router (F4); hyper's header limits |
| Upstream services (providers, banks, wallets, Web Risk, ThreatFox, Keto, Access keys, DoH) | response size, status, timing | 5–15 s timeouts, no redirects; bodies read up to 64 KiB–64 MiB per source (F2) |
| Sui signatures | the signature bytes | `access-gate-gateway-core::sig` (ZIP-215 ed25519, low-S secp256k1/r1; multisig and zkLogin refused), fuzzed in that crate |
| Shared state (PostgreSQL) | challenges, sessions, ledger | `DELETE … RETURNING` for one-use state; unique keys; readiness fails on loss |
| Ingress in front | which address is the client | nginx trusts `X-Forwarded-For` only from cloudflared (`set-real-ip-from`, platform) |
| Crate registry / build | compiled code | `Cargo.lock`, `cargo deny` (advisories, licences, bans, sources), `--locked` |

### Identity & credential matrix (AUTH lens)

| Authority / credential | Holder | What it confers | Misuse impact | Rotation / revocation |
| --- | --- | --- | --- | --- |
| Session cookie | the browser (HttpOnly) | one account's API | act as the account until expiry | 14 days idle, 60 days absolute; logout, suspension and deletion delete it |
| Passkey | the person's authenticator | sign-in | account takeover | removed in the app (never the last method) |
| Wallet key | the person's wallet | sign-in | account takeover | unlinked in the app |
| Recovery codes | the person | one sign-in each | account takeover | replaced in the app; used ones are spent |
| Invite codes | operator or the holding account | one free account each | free accounts | revoke; expiry; `may_share_invites` |
| Access JWT | the operator's browser (Access cookie) | the console with the Keto role | moderate, grant months, import statements | Access session (12 h); remove the Keto tuple |
| Keto tuple `LinkInBio:admin#member` | Keto (written by the operator) | the console role | full console | delete the tuple (effective within 30 s) |
| Chain Payments merchant key | api, worker (file; the console holds none, F25) | create and read merchant sessions | create checkouts in Link in Bio's name | `merchant rotate-key` (Chain Payments) |
| Provider and bank keys (off today) | api, worker; feeds worker only (files) | take payments, read accounts | depends on the provider (a Revolut token with payment scope could pay out) | each provider's dashboard; the console reads none (F25) |
| Database passwords (`link_in_bio_api`, `_admin`, `_worker`, `_jobs`) | one per process kind (Secret env) | that process's grants on `lib` (F25) | that process's rows; never an audit-log rewrite | `new-service-db-secret.sh --force` |

### Database actor matrix (DB lens)

| Actor / asset | Power | Bounded by |
| --- | --- | --- |
| page server (`link_in_bio_pages`) | SELECT on the four `public.*_v1` views only | read-only role (no grant on `lib`, provisioner); `Access::ReadOnly` sets `default_transaction_read_only` per connection; `the_pages_role_reads_only_the_public_views_and_writes_nothing` (F25) |
| api, admin, worker, account Job (`link_in_bio_api`, `_admin`, `_worker`, `_jobs`) | the DML each needs on `lib` (`docs/HOSTED.md` "Database roles per process") | one role per process kind with `read_only_tables`; audit log insert-only, pruned only through `lib.prune_audit_log`; no DDL, no TRUNCATE (`a_writer_cannot_rewrite_the_audit_log_or_change_the_schema`, F25) |
| migrate Job (`link_in_bio_migrate`) | schema | runs before rollout; embedded, checksummed migrations |
| Request author | values in queries; page sizes | bound parameters only; fixed `LIMIT`s (admin lists 100–500, audit 200); `statement_timeout` |
| Another service on the tier | connections, locks | per-role connection limits; its own database |
| Backup storage | a full copy | platform backup controls |

### On-chain dependency matrix (SC lens, sign-in rows)

| Object / package | ID | Sourced from | Used as | If wrong | Fails |
| --- | --- | --- | --- | --- | --- |
| Sui network name | `SUI_NETWORK` (`testnet`) | configuration | `Chain ID: sui:<network>` in the signed message | a signature for another network's message does not verify | closed |

The service reads no Move object and builds no transaction; Chain Payments' on-chain checks are that service's
(chain-payments-service audit).

### Image supply-chain matrix (IMG lens)

| Actor / asset | Power | Bounded by |
| --- | --- | --- |
| Base-image publishers | base layers | both `FROM`s digest-pinned; distroless `cc` runtime |
| Build context | files copied in | `.dockerignore` excludes `target`, `node_modules`, `.git`, `.github`, `*.md` (but `spec/`), `.env*` |
| Build args | labels | none secret |
| Registry | the manifest for a tag | deployment by digest (`config/images.yaml`); cosign keyless signature; policy-controller |
| CI publish job | what is pushed | Trivy before sign; SPDX and CycloneDX attestations; provenance |
| Manifests | how it runs | non-root 65532, read-only root, no privilege escalation, all capabilities dropped, `RuntimeDefault`, no service-account token, no service links |

### Content matrix (SITE lens)

| Actor / source | Controls | Bounded by |
| --- | --- | --- |
| Tenants | every page's text, links, picture, theme names | the parser (F17); screening (F22); moderation |
| The operator's site template (`SITE_CONFIG`) | footer, security contact, report link | operator configuration, parsed by `SiteConfig` |
| Vendored assets (tokens, sprite, icons) | the page's look and icons | written only by `page/scripts` from pinned packages; `check:vendored` in CI |
| Visitors | their browser | hosting headers (B.VUE-1 below) |

## Severity scale

Critical / High / Medium / Low / Info / Positive.

## Scope

**In scope (`main` = `68b2323`, tag `v0.0.4`, plus this pass's changes):**

- `crates/core/src/*` (manifest, text, safe_url, theme, render, interop, limits, icons, assets) and `crates/core/tests`
- `crates/assets/src/lib.rs`; `crates/auth/src/*` and `crates/auth/tests`
- `crates/billing/src/*` (router, manual, chain_payments, square, gocardless, paddle, bank_transfer, open_payments, httpsig,
  keys, bank_feed/*) and `crates/billing/tests`
- `crates/safety/src/lib.rs`; `crates/store/{src,migrations,tests}`
- `crates/api/src/*` (headers, site, static_mode, local_mode, hosted/*) and `crates/cli/src/main.rs`
- `Cargo.toml`, `Cargo.lock`, `deny.toml`, `Dockerfile`, `.dockerignore`, `.github/workflows/*`, `.github/dependabot.yml`
- `SECURITY.md`, `README.md`, `docs/HOSTED.md`, `CHANGELOG.md`, `openapi/*`, `page/` (tooling only)

**Cross-repo evidence (read-only):**

- `post-bootstrap/link-in-bio/{base,hosted,overlays/default}` (network policies, ingress limits, Deployments, `hosted.env`);
- `k8s/clusters/meddleware-org/database/services.conf`;
- `repos/link-in-bio-ui/src/components/PreviewFrame.vue` (the preview frame's `sandbox=""`, F9);
- `access-gate-gateway-core` 0.0.33 `sig.rs` (ZIP-215, low-S);
- `repos/chain-payments-service/crates/service/src/api.rs` (its request layers; see Risks).

**Out of scope:** link-in-bio-ui (its own audit); Chain Payments' verification (its audit); the shared PostgreSQL tier, the
edge and the cluster (platform audit); the providers' and banks' own security.

**Environment / commands (2026-11-18):**

| Command | Result |
| --- | --- |
| `cargo +stable test --workspace --locked` against the throwaway PostgreSQL (TLS `verify-full`, `REQUIRE_TEST_DATABASE=1`) | **127 passed, 0 failed, 0 ignored** (120 before this pass) |
| `cargo +stable clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo +stable fmt --check` | clean |
| `cargo deny check` | advisories ok, bans ok, licences ok, sources ok |
| Image build, Trivy, `scripts/smoke.sh`, the `page/` five-browser run | **not run** (no container builds or browser runs in the review environment); CI runs them on every push |
| `cargo llvm-cov` | not run this pass; CI publishes the line coverage summary |

## Findings

### F1 — A picture upload could exhaust the API pod's memory and stall its workers

**Severity:** Medium   **Disposition:** RESOLVED
**Where:** `crates/assets/src/lib.rs::normalise_raster` (`MAX_INPUT_SIDE = 8192`, `max_alloc = 256 MiB`, `crop_imm` copy);
`crates/api/src/hosted/app.rs::avatar_upload` (decoded inline on the async runtime); `api-deployment.yaml` (192 Mi limit).
**Issue:** A 5 MiB upload may describe 8192 × 8192 pixels (a flat JPEG or PNG compresses to almost nothing). Decoding was
allowed 256 MiB, and the square crop makes a second full copy, inside a pod limited to 192 MiB. Decoding and Lanczos
resizing also ran on a tokio worker thread.
**Impact:** One signed-in account (two requests a second at the ingress) could get both API pods OOM-killed repeatedly,
taking down sign-in, editing and checkout for everyone, and block other requests on the same worker while decoding.
**Remediation / evidence:**

- `MAX_INPUT_SIDE = 4096` (ten times the 400-pixel output) and `MAX_DECODE_BYTES = 64 MiB`, so a decode and its crop stay
  under 128 MiB; a compile-time assertion keeps two copies of the largest 8-bit picture within the budget and the budget
  pair under 192 MiB.
- `avatar_upload` decodes in `spawn_blocking`, one picture at a time per process (`App::pictures`, a semaphore of 1); the
  upload route takes two requests at once (`GlobalConcurrencyLimitLayer(2)`).
- Test: `pictures_too_large_to_decode_safely_are_refused_before_decoding` (crafted PNG headers: 4097 wide, 8192 high, and
  4096² at 16 bits per channel, each refused as `TooManyPixels` before any pixel buffer exists).

### F2 — Upstream answers were read without a size bound, from servers a buyer can choose

**Severity:** Medium   **Disposition:** RESOLVED
**Where:** `crates/billing/src/{lib.rs::send_json, open_payments.rs::{wallet, signed}, chain_payments.rs, bank_feed/*}`,
`crates/safety/src/lib.rs` (Web Risk, ThreatFox), `crates/api/src/hosted/{access.rs (JWKS, Keto), jobs.rs (DoH)}`:
`resp.json()`, `.bytes()` and `.text()` read whole bodies; the JWKS read checked its 64 KiB cap only after reading.
**Issue:** RUST lens §A *HTTP hygiene*: response bodies from upstreams must be size-bounded. With Open Payments on, the
buyer names their wallet address, and the service then reads documents from that wallet's servers.
**Impact:** A buyer with an account could point a checkout at a server that streams gigabytes within the 15 s timeout and
take the API pod down (latent today: Open Payments is off).
**Remediation / evidence:** `link_in_bio_billing::read_limited(resp, max)` refuses a declared length over `max` before
reading and stops while reading a chunked body; `read_json_or_null` keeps the old "not JSON means `Null`" behaviour for
error pages. Limits: 1 MiB for provider and wallet API answers (`MAX_ANSWER_BYTES`), 16 MiB for bank statements and
transaction lists (`MAX_STATEMENT_BYTES`), 64 KiB for the Access keys, Web Risk and DoH, 4 KiB for Keto, 64 MiB for a week
of ThreatFox indicators. Test: `answers_are_read_up_to_a_limit` (a hand-written HTTP server: a declared length over the
limit, a chunked body over it, and bodies within it).

### F3 — The page server read secret-file settings it never needs, and failed on them

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/cli/src/main.rs::hosted_env` blanked only `BILLING_PROVIDERS` and `BANK_FEEDS` for `serve --mode pages`;
`App::new` reads `WEB_RISK_KEY_FILE` whenever it is set. Every role shares the `link-in-bio-config` ConfigMap, and the
pages Deployment mounts no secret. Reported by the deployment work of 2026-11-18.
**Issue:** The same class as the 0.0.3 fix (FU-0135): a key path in the shared configuration made the page server read a
file it does not have.
**Impact:** Setting the Web Risk key (FU-0113) would crash-loop every tenant page; least privilege also says the page server
should never be able to read such a key.
**Remediation / evidence:** In read-only mode every `*_FILE` setting is unset (Web Risk, ThreatFox, every provider and bank
key, and any added later), besides `BILLING_PROVIDERS=manual` and no feeds; `docs/HOSTED.md` states it. Test:
`hosted_env_tests::the_page_server_never_reads_a_secret_file` (with every `*_FILE` set, the page server's configuration
names none and builds without a file, while the app's keeps them). The console reading keys it does not need is F25.

### F4 — No router had a time or concurrency bound

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `hosted/{app,admin,internal,pages}.rs::router`, `internal::worker_router`, `static_mode::router` (as served by the
CLI); `tower`/`tower-http` with `timeout` and `limit` were dependencies but unused.
**Issue:** RUST lens §A *HTTP hygiene*: no handler timeout and no concurrency limit sized against memory.
**Impact:** Slow upstreams (providers at 15 s, Web Risk at 5 s per link of a publish, database waits) let requests pile up
inside 128–192 MiB pods.
**Remediation / evidence:** `hosted::bounded(router, timeout, n)` adds `TimeoutLayer` (`408`) and a
`GlobalConcurrencyLimitLayer` shared by every route of the router: axum applies a router's layer to each route separately, so
a plain `ConcurrencyLimitLayer` would give every route its own limit. Bounds: app 60 s × 64 (bodies ≤ 64 KiB, plus two 5 MiB
pictures); console 60 s × 8 (statements ≤ 4 MiB); internal port 30 s × 32; worker port 30 s × 8; tenant and operator pages
30 s × 128. The app's 60 s covers a publish that screens up to 60 new links; a publish cut off by the bound has recorded the
verdicts it reached and continues on retry. Tests: `bounds_tests::a_slow_request_ends_in_408`,
`the_limit_is_shared_by_every_route`; every existing router test passes through the layers.

### F5 — Open Payments' public-address check could be passed by DNS rebinding

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/billing/src/open_payments.rs::{checked, is_public}`; the client was `link_in_bio_billing::http_client()`.
**Issue:** `checked` resolved a wallet's host and required every address to be public, then reqwest resolved the name
again to connect. A name with a zero TTL can answer a public address first and a private one second. `is_public` also
treated NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`), 6to4 (`2002::/16`) and site-local (`fec0::/10`) addresses as public.
**Impact:** With Open Payments on and an egress policy that allows the internet (it must, for buyers' wallets), a buyer
could make the API send signed requests to an address inside the operator's network. Latent: the provider is off and the
current egress policy allows only named hosts.
**Remediation / evidence:** `OpenPayments::http_client()` uses `PublicOnly`, a `reqwest::dns::Resolve` that refuses any name
with a non-public address at connect time; the app builds the adapter with it. `is_public` judges NAT64 and 6to4 addresses
by the IPv4 address they carry and refuses site-local. Tests: `only_public_addresses` (new cases),
`the_resolver_refuses_names_of_private_addresses_at_connect_time` (the resolver and a real request to `localhost`). The
conformance stand-in on `http://127.0.0.1` still passes (IP literals never reach a resolver, and `checked` allows them only
on a loopback test set-up).

### F6 — Handles could take the names other software looks up under the pages domain

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/core/src/limits.rs::RESERVED_HANDLES`.
**Issue:** Every handle is a host name under `PAGES_DOMAIN`. Mail clients, mail servers and browsers look up
`autoconfig`, `autodiscover`, `mta-sts`, `wpad` and similar labels by convention; `smtp`, `imap`, `ns1`, `webmail`,
`localhost` invite confusion.
**Impact:** A tenant page at `autoconfig.<domain>` or `mta-sts.<domain>` would answer where software expects the operator's
configuration (pages serve only their fixed routes, so the risk is confusion and future collisions, not code).
**Remediation / evidence:** 17 labels added (`autoconfig`, `autodiscover`, `email`, `ftp`, `imap`, `isatap`, `localhost`,
`mta-sts`, `mx`, `ns`, `ns1`, `ns2`, `pop`, `pop3`, `smtp`, `webmail`, `wpad`); the list is now sorted and checked for
duplicates. `/api/v1/limits` publishes it unchanged in shape. Test: `skeleton_tests::skeletons` (each refused by
`looks_reserved` and `check_handle`).

### F7 — Console answers had no cache, sniffing or referrer headers

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/api/src/hosted/admin.rs::router` (the app router's guard sets them; the console's had none).
**Issue:** Console answers carry personal data: report contacts and texts, appeals, the audit log, refund payers.
**Impact:** A shared or misconfigured cache could keep them; no exposure is known today (Cloudflare does not cache JSON by
default).
**Remediation / evidence:** a `no_store` middleware sets `Cache-Control: no-store`, `nosniff` and `no-referrer` on every
console answer, refusals included. Test: in `switches_fail_closed`, the overview and an unauthenticated `/admin/me` carry all
three.

### F8 — The Access team domain was not required to be https

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/api/src/hosted/config.rs` (`ACCESS_TEAM_DOMAIN`); `access.rs` fetches `<team>/cdn-cgi/access/certs`.
**Issue:** AUTH-M1: keys come only from a trusted set. A plain-HTTP team domain would fetch the signing keys over an
unauthenticated channel.
**Impact:** Misconfiguration only; on the path to Cloudflare, a swapped key set would let forged tokens through to the Keto
check (a forged subject that holds the tuple would pass).
**Remediation / evidence:** a team domain that is not `https://` is refused at start. Test: `refuses_doubtful_values` (http
refused; https with a trailing slash normalised).

### F9 — The draft preview relied on the editor's frame for its sandbox

**Severity:** Info   **Disposition:** RESOLVED
**Where:** `crates/api/src/hosted/app.rs::page_preview` (served on the app origin, `frame-ancestors <app>`).
**Issue:** The editor frames the preview with `sandbox=""` (link-in-bio-ui `PreviewFrame.vue`), but the response itself did not
carry a sandbox, so a preview opened at the top level ran as the app's origin. Its content is escaped and the CSP allows only
same-origin script, so nothing a tenant writes could run; this is defence in depth.
**Remediation / evidence:** the preview's CSP adds `sandbox` (no flags, matching the editor's frame, so the editor is
unaffected). Test: in `invite_signup_publish_serve_suspend_report`, the preview's CSP has a `sandbox` directive.

### F10 — The page cache could grow without bound under a flood of host names

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `crates/api/src/hosted/pages.rs::resolve` (past 10 000 entries it dropped only expired ones).
**Issue:** Every unknown host under the wildcard is remembered for the TTL; fresh entries were never dropped.
**Impact:** Enough made-up hosts within 30 s (many addresses at the ingress limit) would grow the page server's memory.
**Remediation / evidence:** `PageCache::insert` drops expired entries at `MAX_HOSTS` and, if every entry is still fresh,
starts again. Test: `cache_tests::the_cache_stays_bounded_under_a_flood_of_fresh_hosts` (30 000 fresh hosts; never more than
10 000; the newest kept).

### F11 — `unsafe_code` was `deny`, not `forbid`

**Severity:** Info   **Disposition:** RESOLVED
**Where:** `Cargo.toml` `[workspace.lints.rust]`.
**Issue:** `deny` can be overridden by a local `allow`. There is no `unsafe` in the workspace.
**Remediation / evidence:** `unsafe_code = "forbid"`; clippy and the build are clean.

### F12 — `SECURITY.md` lacked required sections and the hosted service

**Severity:** Low   **Disposition:** RESOLVED
**Where:** `SECURITY.md`.
**Issue:** No Supported versions or Disclosure sections; the security model described only the page and the local editor.
**Remediation / evidence:** rewritten with the five sections. The model now covers sign-in, sessions and CSRF, the console
gate, the ledger and every adapter's check, Open Payments' address rules, the database roles, request bounds and what a
deployment must provide.

### F13 — Passkeys

**Severity:** Positive
**Where:** `crates/auth/src/passkey.rs`; `hosted/app.rs::{signup_*, passkey_login_*, me_passkey_*}`; `store::take_challenge`.

- kanidm's webauthn-rs 0.6.2; RP ID = the app host, origin = the app origin, so a passkey is never offered to a tenant page.
- User verification is required by the passkey API, and `finish_login` checks `user_verified()` again.
- Ceremony state is kept server-side in `lib.challenges`, five minutes, taken once (`DELETE … RETURNING`), and bound to
  its kind and, for adding a passkey, to its account (`owner != a.id` refused).
- A sign-in names its credential; the stored passkey's owner is the account, and a discoverable response's user handle
  must name the same account. The updated counter is stored back.
- An unknown handle gets a discoverable ceremony too, so the answer does not say who has an account.
- Test: `crates/auth/tests/passkey.rs` (a software authenticator) and the hosted sign-up and sign-in tests.

### F14 — Sui wallet sign-in

**Severity:** Positive
**Where:** `crates/auth/src/wallet.rs`; `hosted/app.rs::{wallet_login_*, me_wallet_*, signup_*}`.

- The message is CAIP-122/EIP-4361 text with the app host as domain, the app origin as URI, `Chain ID: sui:<network>`, a
  128-bit nonce and issue and expiry times. Every field but the address comes from the server's configuration, and the
  verifier rebuilds the text from the stored record, never from the client.
- One use and five minutes, through the challenge table; sign-up, linking and sign-in are different kinds, and linking is
  bound to the signed-in account.
- Verification is the platform's shared verifier (`access-gate-gateway-core::sig`): the personal-message intent and
  BCS framing, ZIP-215 ed25519 (`ed25519-consensus` 2.1.0), low-S enforced for secp256k1 and secp256r1, multisig and
  zkLogin refused. The address is canonicalised before comparison.
- Tests: `sign_in_round_trip` (another key, another text, expiry, bad base64), `stored_challenges_read_back`, the hosted
  wallet sign-up test.

### F15 — Sessions, CSRF and recovery codes

**Severity:** Positive
**Where:** `crates/auth/src/{session,recovery}.rs`; `hosted/app.rs::{guard, account, start_session, logout}`;
`store::{session_account, use_recovery_code, suspend, delete_account}`.

- **Sessions:** 256 random bits in `__Host-lib_session` (Secure, HttpOnly, SameSite=Strict, Path=/, no Domain); only the
  SHA-256 is stored; a value of the wrong shape is never looked up. Expiry slides to `least(created + 60 d, now + 14 d)` in the
  same statement that reads it, and only for an active account. A new token is issued at every sign-in (no fixation);
  logout deletes the row and clears the cookie; suspension and deletion delete every session.
- **CSRF:** every method but GET, HEAD and OPTIONS needs `Origin` exactly the app origin and `X-Link-In-Bio-Request`
  (which a cross-site form cannot send, and the API grants no CORS). Provider notifications sit outside the guard and are
  authenticated by their signatures. Test: `switches_fail_closed` (foreign origin and missing header refused).
- **Recovery codes:** ten codes of 80 random bits (Crockford base32), shown once, stored as SHA-256, spent by an
  `UPDATE … WHERE used_at IS NULL AND status = 'active'`. Online guessing is bounded by 80 bits and 30 sign-ins a minute per
  address.
- Every sign-in path refuses a suspended or deleted account; failures answer one message and count a metric.

### F16 — The console gate

**Severity:** Positive
**Where:** `crates/api/src/hosted/{access,jwt}.rs`.

- RS256 only (`none` and HMAC refused); the key is found by `kid` in the team's set (never `jku` or an embedded `jwk`), and
  an unknown `kid` refreshes the set at most every 30 s; the set is at most 64 KiB (F2) and refreshed hourly.
- `iss` equals the team domain (https, F8), `aud` contains the application's AUD, `exp` and `nbf` with 60 s of skew, `sub`
  required. ring's `RSA_PKCS1_2048_8192_SHA256` (2048-bit minimum).
- Keto `LinkInBio:admin#member@<sub>` per request, cached 30 s when allowed and 5 s when denied; any Keto failure or
  non-success status is `503`. Without an Access configuration the console answers `503`.
- CSRF as in the app (the admin origin). Every change is in the audit log with `operator:<subject>`.
- Tests: `every_defect_is_refused_with_its_reason`, `forged_tokens_are_refused` (alg none, HS256, swapped payload), and the
  hosted console tests (no token `401`).

### F17 — The page parser, renderer and page headers

**Severity:** Positive
**Where:** `crates/core/src/{manifest,text,safe_url,theme,render,interop,icons}.rs`; `crates/api/src/{headers,static_mode}.rs`.

- **Parser:** the only reader of documents (64 KiB, schema 1, unknown fields dropped and reported), with bounds on every
  list and string in graphemes and bytes; property tests show it never panics and shared vectors (`fixtures/manifests.json`)
  pin it.
- **Links:** `https:` with a dotted host name, no credentials, no IP literal, no control characters, spaces or backslashes
  before parsing, at most 2048 bytes normalised; `mailto:` with one address and only `subject`. `javascript:`, `data:` and
  relative URLs are refused.
- **Themes:** every option is an enum; the CSS is generated from the token table, never from a document; contrast is AAA in
  every mode a page can show, or the theme is refused with a fix.
- **Renderer:** maud auto-escaping; the only raw HTML is the sprite, an `<use>` reference built from the `Icon` enum, and
  JSON-LD with `<`, `>` and `&` escaped. No inline style, no inline script that runs; a property test checks that accepted
  text adds no markup.
- **Federation:** WebFinger answers only `acct:<handle>@<host>` or the page URL; the ActivityPub actor is read-only and its
  inbox accepts and drops; NIP-05 and atproto-did serve the validated key and DID.
- **Headers (B.VUE-1):** `default-src 'none'`; `style-src`, `img-src`, `script-src`, `manifest-src 'self'`; `base-uri 'none'`;
  `form-action 'none'`; `frame-ancestors 'none'` and `X-Frame-Options: DENY`; `nosniff`; `no-referrer`; a restrictive
  `Permissions-Policy`; COOP `same-origin`; HSTS with subdomains; any `Set-Cookie` removed; only GET and HEAD (and the inbox).
  Pictures from `/api/v1/assets/` carry `default-src 'none'; sandbox`.

### F18 — Invites

**Severity:** Positive
**Where:** `hosted/admin.rs::{issue, selection_issue, revoke}`; `store::{create_invites, create_account}`.

- Codes are issued only in the console (at most 100 per request, 1–365 days), to the operator (shown once, hash only) or to
  an active account to pass on; nothing is issued automatically.
- Redemption locks the row (`FOR UPDATE`), requires it unredeemed, unrevoked and unexpired, and the holder still active with
  `may_share_invites`; the code text is cleared on redemption and `redeemed_by` is unique.
- The invite tree (`invited_by`) is recorded; codes held for an account are shown only while it may share them.

### F19 — The ledger, the router and refunds of unapplied payments

**Severity:** Positive
**Where:** `crates/billing/src/lib.rs::Router`; `store::{change_period_in, create_refund_request, record_refund}`;
`hosted/internal.rs::apply_event`; `hosted/jobs.rs::reconcile`.

- One billing event per `(provider, provider_event)` (unique constraint, `ON CONFLICT DO NOTHING`), applied with the period
  change in one transaction. A notification's paid event and the reconciliation's use the same key (`paid:<provider_ref>`),
  so the period is extended once; an unapplied Chain Payment is keyed by its webhook id.
- A refund request is once per event (unique `event_id`), only for an unapplied Chain Payments purchase within 30 days, by
  its own account; recording the refund takes the months back once, in the same transaction, and the period never goes
  below now.
- The router offers an operator-as-seller method only where the declared and request countries agree and are listed (GB by
  default); 1–12 months per purchase and at most 24 ahead; each method's minimum keeps its fixed fee within 3 % of a month.
- Tests: `billing_periods_are_idempotent`, `refund_requests_take_months_back_once`, `routing_by_country_and_switches`,
  `months_are_bounded`, and the hosted refund and payment tests.

### F20 — Every adapter's authenticity checks

**Severity:** Positive
**Where:** `crates/billing/src/*`; `crates/billing/tests/conformance.rs` (every adapter against a stand-in).

- **Chain Payments:** ed25519 over `<t>.<body>` with the pinned webhook public key (`CHAIN_PAYMENTS_WEBHOOK_KEY`), ±300 s;
  an unknown session is ignored; notifications arrive only on the internal port (NetworkPolicy: the Chain Payments worker).
- **Square:** HMAC-SHA256 over the registered notification URL plus body, compared in constant time.
- **GoCardless:** HMAC-SHA256 of the body, constant time. **Paddle:** `ts` within 300 s and any `h1` matching, constant time.
- **Bank transfer:** camt.053/054 parsed with roxmltree 0.21.2 (DTDs refused, so no entity expansion); only booked credits;
  the ISO 11649 reference must validate; currency and amount at least the checkout's; once per reference.
- **Open Payments:** every request signed (RFC 9421, ed25519, `Content-Digest` SHA-512), checked against the RFC examples;
  the finish hash (RFC 9635 §4.2.3) compared in constant time before the grant is taken once; the checkout is paid only when
  the operator's own incoming payment (its id checked to be on the operator's resource server) has received at least its
  amount in the configured asset.
- **Bank feeds:** bunq answers' server signatures checked; Revolut's client assertion is RS256 with the worker's key; Wise's
  SCA signature only when asked. The feeds' keys are read by the worker only.
- Manual and bank transfer refuse notifications; Open Payments has none.

### F21 — Database: roles for pages, query safety, transport, integrity

**Severity:** Positive
**Where:** `crates/store/src/{lib.rs,config.rs}`, `migrations/0001`–`0004`, `services.conf`.

- **Pages:** the page server connects as `link_in_bio_pages`, which can read only `public.page_v1`, `asset_v1`,
  `domain_v1` and `flagged_link_v1` (the provisioner grants it nothing on `lib`); every connection also sets
  `default_transaction_read_only`. The views expose no passkey, session, report or billing row.
- **Queries:** static strings with bound parameters; `AssertSqlSafe` only concatenates constant SQL (`REFUND_SELECT`) and the
  tests' `CREATE DATABASE` of a UUID; the admin search strips `%`, `_` and `\`; lists have fixed `LIMIT`s.
- **Transport:** `sslmode=verify-full` with `sslrootcert`, or plain text only with `ALLOW_INSECURE_DATABASE=1`; only three URL
  parameters accepted; `Debug` and errors redact the password (`the_password_never_appears_in_debug_or_errors`).
- **Integrity:** enumerations, formats and lengths check-constrained (`status`, `kind`, handle regex, billing reference
  regex, picture size); "suspended ⇔ a kind"; unique handle, skeleton, wallet, invite hash, billing event key.
- **Availability:** `/readyz` fails when the database does not answer, `/healthz` does not; statement and idle timeouts per
  role. Tests run on PostgreSQL over TLS with fresh databases; CI fails on a skipped database test.

### F22 — Safety: screening, reports, statements, suspension

**Severity:** Positive
**Where:** `crates/safety/src/lib.rs`; `hosted/{app,admin,pages,jobs}.rs`.

- Screening in layers: built-in checks (IP hosts, ports, 20 shorteners), the blocklist and ThreatFox (CC0, synced every 6 h,
  replaced in one transaction), then Web Risk under a monthly cap counted atomically in the database across processes
  (`take_from_counter`; since F28's rework, the Update API's local lists, with only a hash prefix sent to confirm a
  match). The Web Risk key is never in an error or log (fixed error strings). Every unscreened link is
  screened before a publish; flagged links are hidden on every page within the cache time.
- Reports need no account and record no reporter; reasons are an enumeration; details ≤ 4000 characters; an alert fires on
  a report open more than 24 h.
- Decisions carry a statement of reasons shown to the account holder, who may appeal; suspension answers 451 (legal), 410
  (policy) or 403 (for a time), ends sessions and is lifted by the worker when its time is up.
- The audit log and decided cases are kept two years, then pruned.

### F23 — Image and deployment hardening

**Severity:** Positive
**Where:** `Dockerfile`; `post-bootstrap/link-in-bio/{base,hosted}`.

- **Image:** both bases digest-pinned, distroless `cc` runtime; `cargo-chef` 0.1.78 and `cargo-about` 0.9.2 installed
  `--locked`; the binary built `--locked`; licence notices fail on an unaccepted licence; `Cargo.lock` copied for scanners;
  `USER 65532`.
- **Pods:** `runAsNonRoot`, read-only root, no privilege escalation, all capabilities dropped, `RuntimeDefault`, no
  service-account token, no service links; probes on `/healthz` and `/readyz`; limits 128–192 Mi; key files mounted `0440`
  read-only; the page server mounts no secret.
- **Network:** default deny in both directions; ingress only from nginx (8080), the Chain Payments worker (8081 on the
  api) and monitoring; egress per role to PostgreSQL, Chain Payments, Keto and the Access host (console), Web Risk (api,
  worker) and ThreatFox and DoH (worker), by FQDN through Cilium's DNS proxy.
- **Ingress limits (per client address):** pages 30 r/s; app API 20 r/s; sign-up, sign-in and reports 30 r/min; uploads 2 r/s
  and 5 MiB; console 20 r/s; bodies 16–64 KiB elsewhere.

### F24 — CI and release integrity

**Severity:** Positive
**Where:** `.github/workflows/{rust-ci,docker-publish}.yml`, `.github/dependabot.yml`, `deny.toml`, `README.md`.

- Every action pinned by SHA; `permissions: contents: read`, `id-token: write` only on the signing job; `DO_NOT_TRACK=1`.
- Branch CI: fmt, clippy `-D warnings`, tests on PostgreSQL with no skip and no ignore, llvm-cov, `cargo deny`, the SBOM gate,
  MSRV 1.94, the page job (vendored files current, stylelint, the five-browser run with the AAA sweep, Lighthouse, the npm
  audit gate) and the image job (configuration scan, notices, build, Trivy, smoke test).
- Release: tag-gated; the verify job is `rust-ci.yml` through `workflow_call`; Trivy before cosign keyless signing at the
  index digest; SPDX and CycloneDX attestations; provenance; the published `cosign verify` pins this repository's
  `docker-publish.yml` on `refs/tags/v`. The private mirror is best-effort and listed as such.
- Dependabot: Cargo, npm, Docker and Actions.

### F25 — One writer role and the full key set for processes that need less

**Severity:** Low   **Disposition:** RESOLVED (FU-0138)
**Where:** `services.conf` (`writer link_in_bio link_in_bio_app schema=lib`, used by api, admin, worker and the account Job);
`hosted/mod.rs::App::new` (every role builds every enabled provider and reads its key files, and the Web Risk key);
`admin-deployment.yaml` (mounts the Chain Payments merchant key).
**Issue:** DB lens: one role per process kind, with role tests. The public-facing API's role can rewrite any account's flags,
the ledger, the audit log and the feeds' state, though it needs neither the audit log's delete nor the feeds. The console
never calls a provider (grants, statements and refunds go through the store) and never screens with Web Risk, yet it reads
those keys. No test proves what the read-only role cannot do.
**Impact:** A compromised API pod could grant itself paid time or rewrite audit history; a compromised console pod holds
keys it does not use (with Revolut on, the worker's token and key are separate files, so the console would not hold them).
**Remediation / evidence:**

- One writer role per process kind (`link_in_bio_api`, `link_in_bio_admin`, `link_in_bio_worker`, `link_in_bio_jobs`),
  each with `insert_only_tables=audit_log` and `read_only_tables` for the tables it never writes. The table-by-process
  matrix is read from the store calls each process makes and kept in `docs/HOSTED.md` "Database roles per process"; the
  roles, their Secrets and the Deployments are the platform's (workspace `services.conf`).
- The worker's two-year retention no longer needs DELETE on the audit log: `lib.prune_audit_log` (schema 5,
  `SECURITY DEFINER` as the owner) removes only entries older than two years, whatever it is asked.
- Tests on the real engine with the provisioner's grants: `the_pages_role_reads_only_the_public_views_and_writes_nothing`
  (no read of `lib`, no write, no DDL, no temporary table) and `a_writer_cannot_rewrite_the_audit_log_or_change_the_schema`
  (no UPDATE, DELETE or TRUNCATE of the audit log, no DDL in `lib` or `public`; retention through the function keeps the
  last two years).
- `serve --mode admin` reads no `*_FILE` setting and builds no provider and no screener; its Overview shows the switches
  from the configuration (`the_console_starts_without_any_key_and_shows_the_switches`).

### F26 — A partial refund takes back every month, once per partial refund

**Severity:** Low   **Disposition:** RESOLVED (FU-0139, OQ1)
**Where:** `square.rs` (`refund.*` → `Outcome::Refunded`, `months: None`), `paddle.rs` (`adjustment.*` refunds),
`hosted/internal.rs::apply_event` (`months = e.months.unwrap_or(c.months)`).
**Issue:** Any completed refund event, whatever its amount, takes back all the checkout's months; two partial refunds of one
purchase take back twice. The period never goes below now.
**Impact:** Refunds are the operator's act in the provider's dashboard, so this hurts only the account holder of a refunded
purchase; the providers are off today.
**Remediation / evidence:** built as OQ1's first option, pro rata by amount, rounded down. `Store::refund_purchase` takes back
`floor(months × refunded ÷ paid)` on the running total of the purchase's refunds, under the checkout's row lock, so the
refunds of one purchase never take back more than it bought and add up to every month once the whole amount is refunded;
a refund of a checkout never paid takes nothing; a GoCardless failure or chargeback takes the whole purchase. Tests:
`refunds_take_months_back_pro_rata_and_never_more_than_bought` (store), `refunds_give_back_months_pro_rata_rounded_down`
(billing) and the hosted Square case below.

Then decided (refunds on request, `link_in_bio_billing::refunds`): within 14 days a purchase may be cancelled (all of it,
less the days used and its fee share); later, whole unstarted months come back, newest purchases first, at what each
purchase paid per month, less their fee share; a late Chain Payments payment comes back whole within 30 days. The
fee share is `(fixed + percent × paid) × k ÷ m`, charged as a share of what was paid (no exchange-rate exposure), and the
amount is rounded down in the unit paid. A request's refund takes back exactly its months: with the fee netted off, the
pro-rata rule would have left the account holder a month they were refunded for. `Store::refund_purchase`'s pro rata
stays for refunds that match no request, counted over every refund of the purchase (`billing_events.refund_of`, schema 6).
No process holds a key that can refund; a provider's refund notification of exactly a line's amount closes it. The fee
share uses the fees recorded on the checkout when it was made (schema 6; the configured ones for older checkouts),
Chain Payments' include its 0.2 % platform fee, and the operator's cost of sending a bank or Open Payments refund
(`BANK_TRANSFER_REFUND_FEE_PENCE`, `OPEN_PAYMENTS_REFUND_FEE_PENCE`) is deducted once per line; Sui gas is negligible.
Tests: the refund rules in `crates/billing/src/refunds.rs` (cancel, fee share in another currency and a coin, newest
purchases first, the month in progress and granted months kept, 0 or less refused), `refund_lines_take_back_exactly_their_months_once`
(store) and `refunds_on_request_net_of_fees_matched_or_recorded_exactly` (hosted).

### F27 — Notifications are applied without comparing the paid amount with the checkout

**Severity:** Low   **Disposition:** RESOLVED (FU-0140)
**Where:** `hosted/internal.rs::apply_event` (months and amount come from the checkout); `square.rs` (the event's
`amount_money` kept as evidence only); `paddle.rs` (totals kept, quantity not read).
**Issue:** A paid notification credits the checkout's months whatever the notification says was paid. That is safe only while
the provider cannot change what is paid: Square's quick-pay link has a fixed price, and Paddle's transaction a fixed quantity
unless its checkout lets the buyer change quantities.
**Impact:** With a provider setting that allows editing (Paddle quantity, a Square tip or discount), a buyer could pay less
for the same months. Latent: the card providers are off.
**Remediation / evidence:** before applying a `Paid` event, require the notification's amount and currency (Square
`amount_money`, Paddle `details.totals.grand_total` with `items[].quantity` equal to the months and the configured
`price_id`, GoCardless the payment request amount) to match the checkout, and record a mismatch as `short` in the audit log
without applying it. Tracked in FU-0140, with conformance tests per adapter.

Done: `ProviderEvent` carries what was paid (`Paid`: minor units and currency, and for Paddle the price id and quantity),
filled by the Square, GoCardless and Paddle adapters. `apply_event` applies a payment only when it covers the checkout
(Square and GoCardless at least its GBP amount; Paddle exactly its months of `PADDLE_PRICE_ID`); otherwise the checkout
stays open, the audit log records it once (`payment-not-covering`) and `link_in_bio_payment_mismatches_total` counts it.
Chain Payments, Open Payments and bank transfers already check the amount themselves. Tests:
`a_payment_counts_only_when_it_covers_the_checkout` (billing: short, another currency, fewer months and another price
refused) and `card_payments_apply_only_when_they_cover_the_checkout_and_refunds_take_months_pro_rata` (hosted).

### F28 — One account can spend the shared Web Risk budget

**Severity:** Low   **Disposition:** RESOLVED (FU-0141, OQ2; reworked 2026-11-18)
**Where:** `hosted/app.rs::page_publish` (every unscreened link of up to 60 is screened); `safety::Screener::screen` (the
monthly cap is global).
**Issue:** Each publish with 60 new URLs spends 60 calls. At the ingress limit one account could spend the 90 000 monthly calls in
well under an hour.
**Impact:** Screening then answers "unknown" for everyone until the month ends (links shown and rechecked hourly against the
lists only); no money is spent (the cap is hard). Latent: no Web Risk key and no third-party accounts today.
**Remediation / evidence:** a per-account daily budget of Web Risk calls (the number is OQ2), with links beyond it recorded
as unknown and rescreened by the worker. Tracked in FU-0141.

First built as a per-account daily budget of Lookup calls; then reworked, as decided, because cost grew with the links
held (each clean link was looked up again daily: about 1 800 calls a month for one full page, so about 50 full accounts
reached the 90 000 cap) and the worker's rescreen was bounded per account by nothing. Web Risk now runs in one of two
modes (`WEB_RISK_MODE`), never both:

- **Lookup** (the default, `uris.search`): links are looked up when published and rechecked weekly, and only while a
  published page of an active account shows them (`Store::screens_due_on_published`: draft-only, hidden and removed
  links are deferred a week, and a publish screens again any verdict that is due or stale). The worker's rechecks stop
  at 80 % of the month's allowance, keeping the rest for publishes; the allowance, `WEB_RISK_MONTHLY_CAP` (the free
  100 000 at most) plus `WEB_RISK_PAID_MONTHLY_CALLS` (default 0), is a hard stop. A full page now costs about 260 calls
  a month, not 1 800. This mode never calls `computeDiff` or `hashes.search`.
- **Update** (`crates/safety/src/webrisk.rs`): the worker alone keeps the three lists of hash prefixes in
  `lib.web_risk_lists` with `threatLists.computeDiff` (RAW; `RESET` and `DIFF`; the SHA-256 checksum verified, a
  mismatch discarding the diff and asking for the whole list; `recommendedNextDiff` followed). The app and the worker
  hold the lists in memory (built in this mode only) and reload them when they change. Links are canonicalised and
  expanded as "URLs and hashing" specifies (every canonicalisation test vector of that page and its expression examples
  pass) and checked locally, so daily rechecks cost nothing. Only a local match sends its prefix (never the URL) to
  `hashes.search`, cached until `expireTime` / `negativeExpireTime`, under `WEB_RISK_CONFIRM_MONTHLY_CAP` (default 0);
  an unconfirmed match is hidden until an operator reviews it (`webrisk-prefix`). This mode never calls `uris.search`.
- Pricing (<https://cloud.google.com/web-risk/pricing>, read 2026-11-18): `uris.search` free to 100 000 a month, then
  $0.50 per 1 000; `computeDiff` free without limit; `hashes.search` $50 per 1 000 with no free tier; and calling
  `computeDiff` prices that month's `uris.search` calls as `hashes.search`. So the project and key serve this service
  alone, and a switch from update to lookup is made at a month's start or with a fresh project (`docs/HOSTED.md`).
- `WEB_RISK_ACCOUNT_DAILY_CAP` is removed: `NEW_LINKS_PER_ACCOUNT_DAY` (`ACCOUNT_LIMITS`) bounds what one account can make
  the service check, and `CHANGES_PER_ACCOUNT_HOUR` how often; a publish that only removes or hides links is never
  limited.

Tests: `webrisk::tests::*` (the spec's vectors, expressions and hash prefixes; a reset then a diff with its checksum;
lookups; answers read), `layers_lists_caps_and_outage` and `lookup_mode_keeps_a_reserve_for_publishes_and_stops_at_the_paid_allowance`
(safety, against stand-ins: lookup mode makes no `computeDiff` or `hashes.search` call),
`lookup_mode_never_updates_lists_and_rechecks_only_links_on_published_pages` and
`an_account_has_change_budgets_but_can_always_remove_links` (hosted), `limits::tests::*` and
`each_web_risk_mode_takes_only_its_own_budget` (config).

### F29 — Pictures are keyed by their hash across accounts

**Severity:** Low   **Disposition:** RESOLVED (FU-0142)
**Where:** `lib.assets` (`sha256` primary key); `store::put_asset` (`ON CONFLICT (sha256) DO NOTHING`); `owns_asset`.
**Issue:** When a second account uploads a picture whose re-encoded bytes equal one already stored, the row keeps the first
owner and the second account cannot use the picture ("Upload the picture first"). Whoever can predict another person's
re-encoded picture (a public logo) could upload it first.
**Impact:** A refused avatar for the second account; no data crosses accounts (the first owner's row is unchanged).
**Remediation / evidence:** key the table by `(account_id, sha256)` in a new migration (expand: add the unique pair and change
`put_asset`'s conflict target in one release; contract: drop the old key in the next, so the running release keeps working),
with a store test that two accounts can each use the same picture. Tracked in FU-0142.

Done in one step rather than expand-then-contract: schema 5 makes `(sha256, account_id)` the primary key and `put_asset`
names it. While the rollout runs, an upload on a pod of the previous release fails until that pod is replaced; reading by
hash keeps working (identical bytes). Test: `two_accounts_can_each_use_the_same_picture` (each owns and counts its copy;
deleting one account keeps the other's).

### F30 — `CF-IPCountry` is trusted as tax evidence

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `hosted/app.rs::request_country`.
**Issue:** The request's country is read from Cloudflare's header.
**Impact:** None for authorization: it only narrows which operator-as-seller methods are offered and is recorded as evidence.
Cloudflare sets the header at the edge, and the origin is reachable only through the tunnel (platform). A client that could
reach nginx directly could choose its country; that is a platform boundary, recorded in `SECURITY.md`.

### F31 — Square and GoCardless notifications carry no timestamp

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `square.rs`, `gocardless.rs`.
**Issue:** Their signature schemes sign the body (and Square the URL) only, so a captured notification verifies forever.
**Impact:** None: replaying it changes nothing, because every event applies once (`paid:<ref>`, `refund:<id>`,
`gocardless:<event id>`). This is the providers' design; Paddle and Chain Payments, which sign a time, are checked within
300 s.

### F32 — In-cluster calls to Chain Payments and Keto are plain HTTP

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `hosted.env` (`CHAIN_PAYMENTS_MERCHANT_API=http://…svc.cluster.local:8081`, `KETO_READ_URL=http://keto…:4466`).
**Issue:** AUTH *Transport to identity services*: the merchant API key travels as a bearer header, and the Keto answer decides
the console role, over plain HTTP inside the cluster.
**Impact:** Only a process able to see pod traffic on the node could read or alter them. Both paths are restricted by
NetworkPolicies at both ends; transport encryption inside the cluster is the platform's (PLATFORM lens), the same
arrangement the chain-payments-service and content-hub audits record.

### F33 — Two self-inflicted races

**Severity:** Info   **Disposition:** ACCEPTED-RISK
**Where:** `store::{delete_passkey, delete_wallet}` ("never the last way to sign in" counts in the same statement);
`hosted/app.rs::checkout_create` (`months_ahead` read when the checkout is made).
**Issue:** Two concurrent deletions of an account's last two sign-in methods can both pass the count; two checkouts made
before either is paid can together go past 24 months ahead.
**Impact:** Only the account holder's own requests, at the same moment; recovery codes still sign in, and the extra months are
paid for. Not worth a lock.

### F34 — Reports can be sent by anyone

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `hosted/app.rs::report`.
**Issue:** Account-free reports (a legal expectation for a host) let anyone fill the queue.
**Impact:** Bounded by 30 reports a minute per address at the ingress, 4000-character details and a 24 h alert; reports change
nothing by themselves (an operator decides).

## Section A — Invariant verification matrix

| # | Invariant | Enforced at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Nothing renders a document the parser did not accept; every link is `https:` or `mailto:` | `manifest::parse`, `safe_url::check_link`; app save/publish/preview and page server all parse | `refuses_everything_else`, `crates/core/tests/vectors.rs` (vectors + property tests) | HOLDS |
| I2 | Accepted text never adds markup; no inline style or running inline script | maud; `json_ld_for_html`; `Icon` enum | render property test; `assert!(!html.contains(" style="))` | HOLDS |
| I3 | Pages set no cookie and load nothing from elsewhere | `headers::secure` (CSP, cookie removal) | hosted page tests (CSP), `static_mode` tests | HOLDS |
| I4 | A draft never runs as the app's origin | preview CSP `sandbox` (F9); editor frame `sandbox=""` | `invite_signup_publish_serve_suspend_report` | HOLDS |
| I5 | A ceremony (passkey, wallet) is answered once, within 5 minutes, by the kind and account it was made for | `take_challenge` (`DELETE … RETURNING`, kind, expiry); owner checks | `sign_in_material_sessions_and_challenges`; hosted sign-in tests | HOLDS |
| I6 | The wallet message is rebuilt from the server's record; signatures verify as Sui verifies them | `wallet::Challenge::{message, verify}`; core `sig` (ZIP-215, low-S) | `sign_in_round_trip`; core vectors (gateway) | HOLDS |
| I7 | Sessions are stored only as hashes, expire idle and absolutely, and only an active account's session counts | `session_account` | `tokens_and_cookies`; store session test | HOLDS |
| I8 | Every state-changing app and console request passes the CSRF rule | `app::guard`, `access::csrf_ok` | `csrf`; `switches_fail_closed` | HOLDS |
| I9 | A suspended or deleted account cannot sign in by any method, and loses its sessions | `suspend`, `delete_account`; status filters in every sign-in path | `invite_signup_publish_serve_suspend_report` | HOLDS |
| I10 | The console needs a valid Access token and the Keto role; any failure refuses | `access::require_admin`, `jwt::verify`, `is_admin` | `forged_tokens_are_refused`, `every_defect_is_refused_with_its_reason`, hosted console tests | HOLDS (Keto outage code-only) |
| I11 | Invites are issued only by the operator and redeemed once | admin routes only; `create_account` (`FOR UPDATE`, unique `redeemed_by`) | `accounts_invites_and_handles` | HOLDS |
| I12 | A provider event changes a paid period at most once | unique `(provider, provider_event)`; shared `paid:<ref>` key | `billing_periods_are_idempotent`; conformance suite | HOLDS |
| I13 | Only an authentic notification is applied | each adapter's `verify_notification` | `crates/billing/tests/conformance.rs` (tampered and stale refused) | HOLDS |
| I14 | A notification credits only what was paid | `apply_event` with `ProviderEvent::paid` (F27) | `a_payment_counts_only_when_it_covers_the_checkout`, `card_payments_apply_only_when_they_cover_the_checkout_and_refunds_take_months_pro_rata` | HOLDS |
| I15 | Refunds take back what was refunded | `Store::refund_line` (exactly a request's months), `Store::refund_purchase` (pro rata on the running total otherwise, F26) | `refunds_take_months_back_pro_rata_and_never_more_than_bought`, `refunds_give_back_months_pro_rata_rounded_down` | HOLDS |
| I16 | Every outbound URL a buyer controls reaches only public addresses | `OpenPayments::checked` + `PublicOnly` resolver | `only_public_addresses`, `the_resolver_refuses_names_of_private_addresses_at_connect_time` | HOLDS (F5) |
| I17 | Requests and upstream answers are bounded in size, time and number | body limits; `bounded`; `read_limited`; decode limits | `bounds_tests::*`, `answers_are_read_up_to_a_limit`, `pictures_too_large_to_decode_safely_are_refused_before_decoding` | HOLDS (F1, F2, F4) |
| I18 | The page server reads only public views and holds no key | read-only role and `Access::ReadOnly`; `hosted_env` | `the_page_server_never_reads_a_secret_file`, `…_payment_providers`, `the_pages_role_reads_only_the_public_views_and_writes_nothing` | HOLDS |
| I19 | Least privilege between the writer processes | a role per process kind; audit log insert-only, pruned through `lib.prune_audit_log`; the console holds no key (F25) | `a_writer_cannot_rewrite_the_audit_log_or_change_the_schema`, `the_console_starts_without_any_key_and_shows_the_switches` | HOLDS (per-table `read_only_tables` grants: provisioner, matrix in `docs/HOSTED.md`) |
| I20 | Values are bound parameters; no string-built SQL with values | `store` | inspection | HOLDS (code-only) |
| I21 | Database transport is `verify-full` only (or an explicit local switch); secrets never in `Debug` or errors | `DatabaseSettings::parse` | config tests incl. `the_password_never_appears_in_debug_or_errors` | HOLDS |
| I22 | Reserved and look-alike handles cannot be taken | `check_handle`, `looks_reserved`, unique `handle_skeleton` | `skeletons`; store handle test | HOLDS |
| I23 | The screening budget never passes its monthly cap | `take_from_counter(s)`: lookup within the allowance (rechecks to 80 %), update's calls monthly and `hashes.search` under its own cap; links an account can add per day (F28) | `layers_lists_caps_and_outage`, `lookup_mode_keeps_a_reserve_for_publishes_and_stops_at_the_paid_allowance`, `an_account_has_change_budgets_but_can_always_remove_links` | HOLDS |
| I24 | No panic on attacker input; no `unsafe` | `forbid(unsafe_code)`; no `unwrap` on request paths (OS RNG only); `overflow-checks`, `panic = "abort"` | clippy; parser property tests | HOLDS (code-only for the handlers) |

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

| Dependency | Pinned version | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `webauthn-rs` / `-core` | `=0.6.2` | passkey sign-in | `cargo deny` clean; MPL-2.0 reviewed exception | `danger-allow-state-serialisation` (state kept server-side only) |
| `access-gate-gateway-core` | `=0.0.33` | wallet sign-in | clean; fuzzed in its repo | ZIP-215 via `ed25519-consensus` 2.1.0; `k256`/`p256` 0.14.0 low-S |
| `ring` | `=0.17.14` | RNG, JWT RS256, HMAC, ed25519 signing | clean | — |
| `sqlx` | `=0.9.0` (rustls ring webpki) | every request but static pages | clean | runtime-checked queries; embedded migrations |
| `axum` / `tower` / `tower-http` | `=0.8.9` / `=0.5.3` / `=0.7.1` | every router | clean | timeout and global limit layers (F4) |
| `reqwest` / `rustls` | `=0.13.5` / `=0.23.46` | providers, banks, wallets, Web Risk, ThreatFox, Keto, Access keys | clean | no redirects; `PublicOnly` resolver for wallets (F5) |
| `maud` / `pulldown-cmark` | `=0.27.0` / `=0.13.6` | page rendering; the spec page | clean | auto-escaping |
| `image` / `resvg` | `=0.25.10` / `=0.50.0` | picture upload; operator SVG | clean | decode limits (F1); SVG from the operator only |
| `roxmltree` | `0.21.2` (lockfile) | statement import, Wise feed | clean | DTDs refused |
| Cloudflare Access keys, Keto | team domain; `KETO_READ_URL` | console: **closed** (`401`/`503`) | — | — |
| Chain Payments merchant API | `CHAIN_PAYMENTS_MERCHANT_API` | checkouts: **closed** (`503`); notifications retried by Chain Payments | — | in-cluster (F32) |
| Web Risk, ThreatFox | keys unset today | screening: **open** to the lists ("unknown", rechecked hourly) | — | the cap is hard |
| PostgreSQL tier | `services.conf` | everything but static pages: readiness fails, liveness stays up | platform | `verify-full` |
| `cargo deny check` at review | — | — | advisories, bans, licences, sources ok | `Cargo.lock` committed |
| `page/` npm tree | `page/package-lock.json` | build and test tooling only (nothing ships) | `mw-audit-gate` in CI (FU-0136 allowlist) | TS lens ◐ |

### B.2 Publish authority, capabilities & secret custody

| Authority / secret | Where held | Custody | Gates | Rotation |
| --- | --- | --- | --- | --- |
| Chain Payments merchant key | Secret `link-in-bio-chain-payments-key` (SOPS) | node + age key | checkouts | `merchant rotate-key`, re-encrypt |
| Provider and bank keys (when on) | one Secret per provider (SOPS), mounted as files | node + age key | payments, feeds | the provider's dashboard; `new-link-in-bio-secrets.sh <provider> --force` |
| Web Risk, ThreatFox keys (when on) | Secrets, files | node + age key | screening | the provider's console |
| DB passwords | `link-in-bio-{migrate,app,pages}-db` | SOPS | database | `new-service-db-secret.sh --force` |
| Keto tuple | Keto (auth namespace) | operator | console role | delete the tuple |
| Image publish | quay.io / Docker Hub robot tokens | GitHub | images | KEY_CUSTODY rows (FU-0013) |
| Cosign signing | keyless (GitHub OIDC) | Sigstore | image signatures | n/a |

#### CI & release integrity

All hold (F24): Actions pinned · least privilege · keyless signing (robot tokens inventoried in KEY_CUSTODY) · tag-gated
publish · release gate = CI (`workflow_call`) · Dependabot (cargo, npm, docker, actions) · images per the IMG lens · secrets
never echoed · no real-funds job · test-only modes: none in the binary (`jwt::testing` compiles only under `cfg(test)` or the
`testing` feature, which the image build does not enable; the local test set-ups are `http://127.0.0.1` URLs that
production configuration refuses).

### B.RS-1 Build & release

`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and the MSRV job (1.94) run in CI. The image follows the IMG
lens (F23, F24). No crates are published.

### B.SC-1 ID-constant trace

The service holds no package or object id. The only chain value is `SUI_NETWORK` (`testnet`), written into the signed
sign-in message.

### B.SC-3 Cross-implementation parity

| Behaviour | Implementation A | Implementation B | Shared vector / test |
| --- | --- | --- | --- |
| Sui personal-message verification | `access-gate-gateway-core::sig` (this service, the Rust gateway) | `@mysten/sui/verify` (wallets, the UI) | the core's conformance vectors (gateway repo) |
| Chain Payments webhook signature | `chain-payments-service core::webhook` | `billing::chain_payments::signature_valid` | each tests its own round trip (chain-payments-service audit suggestion) |

### B.AUTH-1 Key & credential inventory

| Key / credential | Type | Where held | Who can read it | Rotation · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| Session tokens | 256-bit opaque, SHA-256 at rest | browser; `lib.sessions` | the account holder | 14 d idle / 60 d · per sign-in | delete the account's sessions (suspend, or SQL) |
| Recovery codes | 80-bit, SHA-256 at rest | the person; `lib.recovery_codes` | the person | on replacement · per account | replace in the app |
| Invite codes | 80-bit, SHA-256 (holder codes readable) | `lib.invites` | operator; the holder | expiry 1–365 d | revoke in the console |
| Chain Payments merchant key | opaque bearer | Secret, mounted 0440 | api, worker (F25) | on suspicion · 2026-11-17 | `merchant rotate-key` |
| Provider, bank, Web Risk, ThreatFox keys | per provider | Secrets, files (off today) | api and worker; feeds and ThreatFox the worker only; never the console or the page server (F25) | on suspicion · not yet issued | revoke at the provider, re-issue |
| Open Payments client key | ed25519 (PKCS #8) | Secret, file (off today) | api, worker | on suspicion | remove from the wallet's `jwks.json`, re-issue |
| DB passwords | password | Secrets (env from `secretKeyRef`) | the pods using them | on suspicion · 2026-11-17 | `new-service-db-secret.sh --force` |

### B.AUTH-2 Client & authorization inventory

| Client / relation | Type | Redirect URIs | Scopes / relations | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| Session → account | BFF cookie | — | the account's own rows | the account holder | 2026-11-18 |
| `LinkInBio:admin#member` | Keto relation | — | the whole console | operator (written with the auth stack's tooling) | 2026-11-18 |
| Access application (console host) | Cloudflare Access (security-key MFA, 12 h) | Access-managed | `aud` = `ACCESS_AUD` | operator | 2026-11-18 (platform) |
| Revolut Business (off) | OAuth confidential client, RS256 client assertion | `REVOLUT_ISSUER` host | as set in Revolut | operator | 2026-11-18 |
| Open Payments (off) | GNAP client (operator's wallet address) | `https://<APP_HOST>/billing?checkout=…&openPayments=finish` | incoming-payment create/read; buyer's outgoing payment limited to the quote and receiver | operator | 2026-11-18 |

### B.AUTH-3 Protocol conformance

| Protocol | Spec followed | Deviations | Test pinning the wire shape |
| --- | --- | --- | --- |
| WebAuthn | Level 3 via webauthn-rs (UV required) | conditional mediation removed for the button flow | `crates/auth/tests/passkey.rs` |
| Wallet sign-in | CAIP-122 / EIP-4361 text, Sui personal-message intent | none | `sign_in_round_trip` |
| Access JWT | RFC 7519/8725, RS256 | none | `jwt` tests |
| HTTP Message Signatures, Content-Digest, GNAP finish hash | RFC 9421, RFC 9530, RFC 9635 §4.2.3 | none | the RFC examples in `httpsig` tests |
| Provider notifications | each provider's documented scheme | none | conformance suite |

### B.DB-1 Roles and grants

| Role | Process | Database | Schema | Tables | Limits | Evidence (test) |
| --- | --- | --- | --- | --- | --- | --- |
| `link_in_bio_migrate` | migrate Job | owner | owner of `lib`, `public` | DDL + DML | 2 conn, 60 s | provisioner (platform); none here |
| `link_in_bio_api`, `link_in_bio_admin`, `link_in_bio_worker`, `link_in_bio_jobs` | api, console, worker, account Job | CONNECT | USAGE `lib` | the DML each needs (`docs/HOSTED.md` "Database roles per process"), the rest `read_only_tables`; `audit_log` insert-only; no TRUNCATE, no DDL | 8, 4, 4 and 2 conn (api 2×4, console 4, worker 4, Job 1), 10 s, 30 s idle | provisioner; `a_writer_cannot_rewrite_the_audit_log_or_change_the_schema` (F25) |
| `link_in_bio_pages` | page server | CONNECT | `public` only | SELECT on the `*_v1` views; read-only default | 18 conn (2×8), 5 s, 5 s idle | provisioner; `the_pages_role_reads_only_the_public_views_and_writes_nothing` (F25) |

### B.DB-2 Schema change process

- A change is a new numbered file in `crates/store/migrations/`, embedded by `sqlx::migrate!` and checksummed; an edited
  released file is refused at start, and a newer schema than the build is an unknown applied version that `migrate` refuses.
- The `migrate` Job runs as the owner before the workloads roll (`apply.sh`); `0002`–`0004` only added tables and columns
  (expand only), so the previous release kept working during each rollout. `0005` changes the primary key of
  `lib.assets` in one step (F29): during that rollout only an upload on a pod of the previous release fails.
- Queries are runtime-checked, so the store and hosted tests on the real engine are the compatibility proof; a view change
  for the page server needs a new `_v2` view (the `_v1` name is the contract).

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade — B+ (167 tests on stable, 30 of them against PostgreSQL over TLS)

| Dimension | Assessment |
| --- | --- |
| Happy path | sign-up by passkey and by wallet with an invite; sign-in by each method; publish and serve; suspend and report; every adapter's checkout and notification; bank statement import; bank feeds; Open Payments end to end against a stand-in; refund requests |
| Error paths | expired and reused ceremonies, wrong signatures, forged and expired JWTs, CSRF refusals, closed switches, tampered and stale notifications, short bank credits, unknown references, reserved handles, oversize and malformed pictures, timeouts (F4) |
| Boundaries | parser limits (vectors, property tests), months bounds, the 3 % rule, pictures at the pixel and memory limits (F1), answers at the byte limits (F2), the page cache cap (F10) |
| Security-relevant | XSS by construction (property test), the URL rules, sessions and cookies, the ledger's once-only rule, signature checks per adapter, the GNAP hash, public-address rules and the resolver (F5) |

Not covered by tests:

- each writer role's per-table `read_only_tables` grants (the provisioner's; the matrix in `docs/HOSTED.md` is read from
  the code, and the role tests cover the page server and the audit log);
- the Keto-down path (code-only, `503`);
- concurrency between the API and the worker applying the same event (the unique key makes it safe; no race test);
- the image, probes and headers in a running container (CI's smoke test, not run here).

### C.2 Hermetic vs live

| Path | Hermetic? | Deferred to | Tracking |
| --- | --- | --- | --- |
| Passkeys with real authenticators | software authenticator only | the five-browser run with virtual authenticators; manual sign-in on the live app | release checklist |
| Access and Keto | static keys and roles in tests | the live console (`/api/v1/admin/me`) | deployment verification |
| Card and bank providers | stand-ins only | sandbox runs | FU-0118 |
| Open Payments and bank feeds | stand-ins only | sandbox runs | FU-0119 |
| Chain Payments | stand-in | testnet payments (SUI and USDC, 2026-11-17) | release checklist |
| Web Risk | stand-in | the Web Risk test URL once the key exists | FU-0113 |
| Image, probes, non-root | no | CI `image` job + `smoke.sh` | CI |
| Restore drill of `link_in_bio` | no | the platform's restore drills | pre-mainnet (DB-M9) |

## Section D — Deployment-readiness gates

### pre-localnet

- [x] builds; fmt, clippy `-D warnings`, `cargo deny` green; `forbid(unsafe_code)` (F11)
- [x] tests green on the real engine with TLS (127/127); no secrets in source
- [x] no panics on attacker-reachable paths (I24); no string-built SQL with values (I20)
- [x] migrations embedded and checksummed; enumerations check-constrained
- [x] every `FROM` digest-pinned; `.dockerignore` excludes env files and installs (F23)

### pre-testnet

- [x] timeouts on every outbound call; response bodies bounded; requests bounded (F2, F4)
- [x] ZIP-215 and low-S through the shared verifier (F14)
- [x] rate limits keyed on the trusted client address (ingress); SIGTERM handled (`shutdown_signal`)
- [x] verify-full TLS; credentials only from Secrets; nothing secret in logs (F21)
- [x] B.AUTH-1 and B.AUTH-2 inventories complete; cookie flags and CSRF tested (F15)
- [x] public responses only from public views (I18); readiness fails and liveness stays up on database loss
- [x] one role per process, least privilege proven by tests (F25, FU-0138)
- [x] deployment references the image by digest from `config/images.yaml`
- [x] `SECURITY.md` present and consistent (F12)

### pre-mainnet (before third-party pages and live payments)

- [x] notification amounts compared with the checkout (F27, FU-0140)
- [x] the partial-refund rule built (F26, OQ1: pro rata, FU-0139)
- [x] screening cost bounded per account and over the month (F28, OQ2: Update API lists, confirmation cap, change limits; FU-0141)
- [x] pictures keyed per account (F29, FU-0142)
- [ ] sandbox runs of every provider and feed that will be switched on (FU-0118, FU-0119)
- [ ] database in the backup set with an offsite copy; a dated restore drill (DB-M9)
- [x] personal-data inventory and deletion path written (`docs/HOSTED.md` Data and Erasure; `DELETE /api/v1/me`)
- [ ] egress for Open Payments, if switched on, excludes private ranges at the network layer too (suggestion below)
- [ ] external review

## Cross-project themes

- **Supply chain & release integrity.** `Cargo.lock` committed; exact crate pins; `cargo deny`; Actions, bases and tools
  pinned; signed, attested images; Dependabot (F24).
- **Wire-format coupling & conformance vectors.** The page document is defined in `spec/profile-links-v1.md` and pinned by
  `fixtures/manifests.json` (consumed by the parser tests; the editor reads the limits from `/api/v1/limits`). The OpenAPI
  documents are generated from the route tables and checked by a test. The Chain Payments webhook has no shared vector
  (chain-payments-service audit). Sui signature parity is the shared core's.
- **On-chain-truth boundary.** A Chain Payment counts only when Chain Payments, which read the chain, says so in a signed
  webhook; the service decides no on-chain question itself.
- **Deployment readiness.** Section D.
- **Chain-access layering & on-chain ID/ABI coupling.** The service builds no transaction and reads no Move object; wallet
  signatures go through the platform's shared verifier. N/A otherwise.
- **Versioning.** 0.0.4 is tagged; this pass's changes ship as 0.0.5.

## Normative requirements (MUST / MUST NOT)

- MUST render only documents the parser accepted, with every link `https:` or `mailto:` — **holds** (F17).
- MUST NOT let a tenant's content run script on any origin — **holds** (F17, F9).
- MUST answer each sign-in ceremony once, for its kind and account, within its lifetime — **holds** (F13, F14).
- MUST refuse every sign-in to a suspended or deleted account and end its sessions — **holds** (F15).
- MUST apply each provider event once — **holds** (F19); MUST credit only what was paid — **does not hold** (F27).
- MUST bound every request, upstream answer and decode in size, time and memory — **holds** (F1, F2, F4).
- MUST NOT let the page server read anything but the public views, or hold any key — **holds** (F3, F21; role tests F25).
- RS-M1 holds (F11, I24) · RS-M2 holds in the shared core (F14) · RS-M3 n/a here (no hand-written decoder; XML through
  roxmltree, protobuf none) · RS-M4 holds (F4) · RS-M5 holds (F2) · RS-M6 holds (one-use state by `DELETE … RETURNING` and
  unique keys; the database fails closed) · RS-M7 holds (ingress) · RS-M8 holds (redacted `Debug`, fixed error strings,
  `shutdown_signal`) · RS-M9 holds for signatures (shared core).
- SC-M6 holds (shared core) · SC-M1–M5, M7–M10 n/a (no Move reads or transactions).
- AUTH-M1 holds (F16, F8) · AUTH-M2 holds (files, rotation documented; F25 for who reads them) · AUTH-M3 n/a (issues no
  bearer token) · AUTH-M4 holds for Access and Keto (fail closed) · AUTH-M5 holds (deny by default; one account's rows) ·
  AUTH-M6 holds for the GNAP and Revolut clients · AUTH-M7 holds (F15) · AUTH-M8 n/a · AUTH-M9 n/a · AUTH-M10 holds (uniform
  refusals, ingress limits, no credentials logged) · AUTH-M11 holds for the wallet message (versioned, domain, URI, network,
  one-use nonce, rebuilt from the server's record).
- DB-M1 holds · DB-M2 holds (expand-only migrations) · DB-M3 **does not hold** (F25) · DB-M4 holds · DB-M5 holds (views;
  pinned by the view definitions, no column-pinning test) · DB-M6 holds · DB-M7 holds · DB-M8 holds · DB-M9 not yet
  (pre-mainnet) · DB-M10 holds (inventory and erasure in `docs/HOSTED.md`).
- IMG-M1…M8 hold (F23, F24).
- SITE-M1 holds (vendored inputs checked) · SITE-M2 n/a · SITE-M3 holds (drafts never served; preview session-only) · SITE-M4
  holds (the operator's template only) · SITE-M5 n/a (tenant links are screened, not link-checked).
- A11Y-M1/M2/M3/M5 hold through the page job's AAA sweep and the token contrast table (`theme::check`) · A11Y-M4 holds (the
  page has no dialog; mode buttons are native) · A11Y-M6/M7: the page's support promise is its own (no browserslist in this
  repo; the five-browser run is the evidence).

## Implementation suggestions (SHOULD / MAY)

- SHOULD, when Open Payments is switched on, give the api and worker egress to `world` with the private and link-local
  ranges excepted (`toCIDRSet` with `except`), so the resolver (F5) is not the only guard.
- SHOULD add a test that the API and the worker applying the same event at once extend the period once.
- SHOULD pin the public views' columns with a test (DB-M5) and add a Keto-down test (`503`).
- SHOULD extend the handle skeleton with further look-alikes (`q` for `g`, `u` for `v`, and the digits `2`, `3`, `4`, `6`,
  `7`).
- MAY rate-limit `GET /api/v1/billing/checkouts/{id}` separately: an Open Payments poll calls the operator's wallet.

## Open questions (`OQ#`)

- **OQ1** — How should a partial refund change the paid period: pro rata by amount (rounded down), only full refunds take
  months back, or a console adjustment by hand? (F26, FU-0139) Decided 2026-11-18: refunds on request (cancel within
  14 days less the days used and the fee share; unstarted months later, newest purchases first), taking back exactly
  their months; other refunds pro rata, rounded down, on the running total.
- **OQ2** — How many Web Risk calls may one account spend a day, and what happens beyond it? (F28, FU-0141) Decided
  2026-11-18: none per account; `NEW_LINKS_PER_ACCOUNT_DAY` bounds what an account can make the service check. Web Risk
  runs in lookup mode (weekly rechecks of published links, a 20 % reserve for publishes, `WEB_RISK_PAID_MONTHLY_CALLS`
  default 0) or update mode (local lists, `WEB_RISK_CONFIRM_MONTHLY_CAP` default 0), the maintainer's switch.

## Risks (residual)

- **Providers and banks:** their notification and API integrity is theirs; an attacker with a provider's webhook secret can
  credit any open checkout of that provider (rotation per provider).
- **The edge:** Cloudflare Access protects the console host; the origin must be reachable only through the tunnel, or
  `CF-IPCountry` and the client address could be chosen (F30).
- **Keys on the node:** custody of every Secret is the platform's (SOPS, age).
- **The shared verifier:** wallet sign-in trusts `access-gate-gateway-core`'s signature rules; a flaw there is shared with
  the gateway.
- **A related service:** chain-payments-service bounds its routers with `ConcurrencyLimitLayer`, which axum applies per route,
  so its limit of 64 is per route rather than per process (observed while building F4; FU-0143).

## Re-verification log

- 2026-11-18 — First pass at `68b2323` (v0.0.4) plus this pass's changes:
  - read every crate, the migrations, the CI, the Dockerfile, the deployment (network policies, ingress, Deployments,
    `hosted.env`), the database roles and the editor's preview frame;
  - 127/127 tests on PostgreSQL over TLS (120 before); clippy, fmt and `cargo deny` clean;
  - fixed F1–F12 inline (decode limits, bounded reads, the page server's key settings, router bounds, the wallet resolver,
    reserved labels, console headers, the Access https rule, the preview sandbox, the page cache, the lint level,
    SECURITY.md); F3 was reported by the deployment work the same day;
  - deferred F25–F29 to FU-0138–FU-0142 and recorded FU-0143 for chain-payments-service;
  - opened OQ1 and OQ2.

## Pre-save consistency checklist (this pass)

- [x] Section A ↔ findings (I14 GAP → F27; I15 GAP → F26; I19 GAP → F25)
- [x] Finding header ↔ body
- [x] Template line
- [x] Closing structure in order
- [x] Open questions stay open
- [x] Section D ↔ dispositions
- [x] Executive summary matches the current dispositions
- [x] Counts re-measured (127 tests; `cargo deny` clean)
- [x] Re-verification log entry
