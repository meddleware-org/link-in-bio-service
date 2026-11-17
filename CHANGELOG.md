# Changelog

## Unreleased

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
