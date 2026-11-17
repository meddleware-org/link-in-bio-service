# Changelog

## 0.0.2 — unreleased

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
