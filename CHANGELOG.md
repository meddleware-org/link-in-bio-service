# Changelog

## Unreleased

Security audit first pass (`docs/audit/link-in-bio-service-audit.md`):

- The page server never reads a secret file: in `serve --mode pages` every `*_FILE` setting (the Web Risk and ThreatFox
  keys, every provider and bank key) is ignored, as `BILLING_PROVIDERS` and `BANK_FEEDS` already were. A Web Risk key
  path in the shared configuration used to make it fail at start.
- Pictures: at most 4096 pixels a side (was 8192) and 64 MiB per decode (was 256 MiB, more than the app pod holds);
  decoded off the async workers, one at a time per process, with two uploads at once.
- Answers from providers, banks, wallets, Web Risk, ThreatFox, Keto, the Access keys and DNS-over-HTTPS are read up to a
  fixed size (1 MiB for API answers, 16 MiB for bank statements).
- Open Payments: names are resolved by a resolver that refuses non-public addresses when the connection is made (no DNS
  rebinding between the check and the request); NAT64, 6to4 and site-local IPv6 addresses are judged by what they reach.
- Every router that listens beyond loopback has a time bound (30 s; 60 s for the app and the console) and a limit on
  requests at once shared by all its routes.
- The console's answers are `no-store`, `nosniff` and `no-referrer`; the draft preview's CSP adds `sandbox`.
- `ACCESS_TEAM_DOMAIN` must be https. Reserved handles include the names mail, DNS and browsers look up under a domain
  (`autoconfig`, `autodiscover`, `mta-sts`, `wpad`, `smtp`, `ns1`, …).
- The page cache stays at most 10 000 hosts under a flood of made-up host names; `unsafe_code` is `forbid`.

Audit findings F25–F29:

- One database role per process kind (api, console, worker, the account Job), each with the grants it needs
  (`docs/HOSTED.md` "Database roles per process"); the audit log is insert-only for all of them, and the worker's
  two-year retention runs through `lib.prune_audit_log` (schema 5), which removes nothing younger. Role tests: the page
  server's role reads only the public views and writes nothing; a writer cannot update, delete or truncate the audit log
  or run DDL.
- The console (`serve --mode admin`) holds no key: it reads no `*_FILE` setting and builds no provider or screener, and
  its Overview shows which providers, feeds and Web Risk are on from the configuration.
- A Square, GoCardless or Paddle payment is applied only when what the provider says was paid covers the checkout (Square
  and GoCardless at least its GBP amount; Paddle exactly its months of `PADDLE_PRICE_ID`). One that does not leaves the
  checkout open, is audited once as `payment-not-covering` and counted in `link_in_bio_payment_mismatches_total`.
- Refunds take months back pro rata, rounded down, on the running total of a purchase's refunds: never more than it
  bought, and every month once the whole amount is refunded. A refund of a checkout that was never paid takes nothing.
- `WEB_RISK_ACCOUNT_DAILY_CAP` (default 200, `0` for none): Web Risk calls one account's publishes may spend in a day.
  Past it, links are recorded as unknown and the worker screens them again within the hour under the monthly cap.
- Schema 5: pictures are keyed by `(sha256, account_id)`, so two accounts can each use a byte-identical picture. During
  the rollout an upload on a pod of the previous release fails until that pod is replaced.

## 0.0.4 — 2026-11-18

- Open Payments (Interledger), off unless `BILLING_PROVIDERS` lists `open-payments`: an incoming payment on the
  operator's wallet address per checkout, the buyer's quote and interactive outgoing-payment grant (GNAP, RFC 9635) with
  the finish hash checked, every request signed with HTTP Message Signatures (RFC 9421, ed25519, `Content-Digest` per
  RFC 9530); paid only when the incoming payment has received the whole amount. New routes
  `POST /api/v1/billing/checkouts/{id}/open-payments` and `…/open-payments/finish`; schema 2
  (`lib.open_payments_grants`). The signing code is checked against the RFC 9421, RFC 9530 and RFC 9635 examples.
- Bank feeds for bank transfer, off unless `BANK_FEEDS` names them: Wise (camt.053 balance statements, SCA one-time
  token signed with the operator's RSA key), bunq (installation, device and session; signed requests, verified
  answers; the payments list) and Revolut Business (RS256 client assertion, refresh token; the transactions list). The
  worker polls them every `BANK_FEED_POLL_SECS` and pays checkouts by the same rules as an imported statement; schema 3
  (`lib.bank_feeds`, a cursor per feed); `link-in-bio bank-feed revolut-token` for Revolut's one-time code exchange;
  the console's overview lists each feed's last poll and error.
- Refund requests for unapplied Chain Payments payments (FU-0132): the account holder asks within 30 days, once per
  payment (`POST /api/v1/billing/events/{id}/refund-request`); the console lists them
  (`GET /api/v1/admin/refund-requests`) and records the refund sent by hand with its transaction reference
  (`POST /api/v1/admin/refund-requests/{id}/refunded`), which takes the months back as a `refund` event, once. Every
  step is audited. `GET /api/v1/billing` events now carry `id`, `unapplied`, `refundableUntil` and `refundRequest`.
  Schema 4 (`lib.refund_requests`).
- Dates and times through `time` instead of `chrono` (RUSTSEC-2026-0543, chrono unmaintained; FU-0134), sqlx
  included; the deny.toml exception is gone. The JSON is unchanged: RFC 3339 in UTC with `Z`, full precision in the
  API and audit entries, milliseconds for the banks and Open Payments; stored wallet challenges still read.

## 0.0.3 — 2026-11-17

Fixes from the first hosted deploy:

- The page server parses an account's page by the same rules as the app (`hosted::account_page_options`). It used to
  re-check the handle against the reserved list, so the operator's own account with a reserved handle published a page
  that was then answered 404.
- The page server never reads payment providers: `serve --mode pages` treats `BILLING_PROVIDERS` as `manual`, so it
  needs no provider settings and holds no key (it used to refuse to start without `CHAIN_PAYMENTS_KEY_FILE`).
- `link-in-bio account add-wallet --handle <h> --wallet <0x…>`: another Sui wallet signs in to one of the operator's own
  accounts. Tenants link wallets in the app by signing with them; this command refuses their accounts.

## 0.0.2 — 2026-11-17

- The hosted service: `serve --mode pages` (tenant pages by host, read-only database role), `serve --mode app` (the
  account API and the internal port), `serve --mode admin` (the operator console's API behind Cloudflare Access and a
  Keto role), `worker`, `migrate`, `account create`. PostgreSQL schema 1 (`lib` tables, `public.*_v1` views for pages).
- Sign-in: passkeys (WebAuthn, user verification required, webauthn-rs), Sui wallet sign-in (CAIP-122-style message),
  one-use recovery codes, `__Host-` session cookies, CSRF by Origin and a custom header.
- Invite codes issued only by the operator (to the operator, to an account, or to a saved selection); the invite tree.
- Billing behind a provider port: the router (switches, country evidence, minimum months so a fixed fee stays at most 3 %
  of a month), the manual provider (operator grants) and Chain Payments; a conformance suite.
- Link screening in layers (built-in checks, blocklist and ThreatFox, Web Risk behind a monthly cap); reports without an
  account, decisions with statements of reasons, suspension (410/451/403), appeals, the audit log, retention.
- Card and bank adapters behind the same port, each with conformance tests against a stand-in API:
  - Square (payment links);
  - GoCardless (billing requests over Open Banking);
  - Paddle (merchant of record);
  - bank transfer (SEPA with an EPC QR payload, or Faster Payments; ISO 11649 references; camt.053/054 statement import
    in the console).

  Provider notifications arrive at `/api/v1/webhooks/<provider>`.
- A Chain Payments payment that arrives after its checkout was paid or closed (`payment.unapplied`) is credited as the
  months its quote was for, once. A refund instead is the account holder's request and the operator's manual act.
- Custom domains by DNS TXT (off unless `CUSTOM_HOSTNAME_CAP` > 0); `openapi/app.json` and `openapi/admin.json`.

## 0.0.1 — 2026-11-16

- First release: the page document (schema 1) and its parser, the theme and contrast model from design-tokens, the
  server-side renderer (works without JavaScript), the picture pipeline, Profile Links (RFC 9264), JSON-LD, WebFinger, a
  read-only ActivityPub actor, NIP-05, atproto-did and security.txt; `serve --mode static|local`, `check`, `render`,
  `schema`, `theme-table`; the five-browser end-to-end run with the shared AAA accessibility sweep.
