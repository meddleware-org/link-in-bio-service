# The hosted service

The same binary that serves one page from files (`serve --mode static`) also runs pages for many accounts. This page is
the reference for running it: the process roles, the configuration and its switches, the data it keeps, and what each
part trusts.

## Process roles

| Command | What it serves | Database role | Typical port |
| --- | --- | --- | --- |
| `link-in-bio migrate` | applies the schema, then exits | owner (DDL) | none |
| `link-in-bio serve --mode pages` | every tenant host: `<handle>.<PAGES_DOMAIN>`, and verified custom domains when they are on | read-only (it can read only the `public.*_v1` views) | 8080 |
| `link-in-bio serve --mode app` | the account API on `APP_HOST` (`/api/v1/…`, the page assets under `/_/`), plus the internal port (provider notifications, `/metrics`) | writer (schema `lib`) | 8080 and `INTERNAL_LISTEN_ADDR` (8081) |
| `link-in-bio serve --mode admin` | the operator console's API (`/api/v1/admin/…`) behind Cloudflare Access and the `LinkInBio:admin#member` Keto role | writer | 8080 |
| `link-in-bio worker` | its own `/metrics` and `/healthz`; one process at a time holds an advisory lock and does the scheduled duties | writer | `WORKER_LISTEN_ADDR` (8081) |
| `link-in-bio account create --handle h --wallet 0x… --terms-version v` | creates one of the operator's own accounts while sign-up is closed (free, served while third-party pages are off; signs in with that Sui wallet) | writer | none |

The app's user interface (`link-in-bio-ui`) is a separate image. The ingress sends `/api/` and `/_/` on the app host to
`serve --mode app` and everything else to the UI.

## Configuration

Instance values come from the environment (a ConfigMap). Secrets are files mounted from Secrets, and their paths are
in the environment. Every switch starts at its safest value, and each one can only close the service further.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | required | `postgres://…?sslmode=verify-full&sslrootcert=…` (plain text only with `ALLOW_INSECURE_DATABASE=1`, for local tests) |
| `PAGES_DOMAIN` | required | tenant pages live at `<handle>.<PAGES_DOMAIN>` |
| `APP_HOST` | required | the app host; also the passkey RP ID |
| `SIGNUP_MODE` | `closed` | `closed`, `invite` (an operator-issued code is needed) or `open` |
| `TERMS_VERSION` | `unset` | the terms an account accepts at sign-up. While it is `unset`, sign-up stays closed whatever `SIGNUP_MODE` says |
| `THIRD_PARTY_PAGES` | `off` | when `off`, only the operator's own accounts' pages are served |
| `BILLING_PROVIDERS` | `manual` | comma list of `manual`, `chain-payments` (the fiat adapters join later) |
| `<PROVIDER>_COUNTRIES` | `GB` | countries where an operator-as-seller method is offered, e.g. `CHAIN_PAYMENTS_COUNTRIES=GB` |
| `PRICE_PENCE` | `300` | the price of one month in pence (GBP) |
| `GRACE_DAYS` | `7` | how long a page stays online after its paid period ends |
| `CUSTOM_HOSTNAME_CAP` | `0` | custom domains allowed in total; `0` means off, with a hard stop at 100 |
| `WEB_RISK_KEY_FILE` | unset | Google Web Risk API key; without it, screening uses the built-in checks and the lists only |
| `WEB_RISK_MONTHLY_CAP` | `90000` | a hard cap on Web Risk calls per month, counted across every process (at most 100 000, the free tier) |
| `THREATFOX_KEY_FILE` | unset | abuse.ch Auth-Key; when set, the worker syncs the last 7 days of ThreatFox indicators every 6 hours |
| `FEDERATION` | `on` | WebFinger, the read-only ActivityPub actor and NIP-05 on tenant pages |
| `SUI_NETWORK` | `testnet` | the chain id in the wallet sign-in message (`sui:<network>`) |
| `ASSET_QUOTA_BYTES` | `524288` | bytes of pictures one account may store |
| `SITE_CONFIG` | none | the page-site template for every tenant page (footer, `securityContact`, `securityPolicy`); `baseUrl` is replaced per tenant |
| `PAGE_CACHE_SECS` | `30` | how long a built tenant page is reused (a suspension, a flagged link or a new version shows within this time) |
| `CHAIN_PAYMENTS_MERCHANT_API`, `CHAIN_PAYMENTS_PUBLIC_API`, `CHAIN_PAYMENTS_ORIGIN`, `CHAIN_PAYMENTS_KEY_FILE`, `CHAIN_PAYMENTS_METHODS`, `CHAIN_PAYMENTS_WEBHOOK_KEY` | required when `chain-payments` is on | the in-cluster merchant API, the public session API as the service reaches it, the origin the buyer's browser calls, the merchant API key file, `id=label` pairs (`sui-testnet:SUI=SUI,sui-testnet:USDC=USDC`), and optionally the webhook public key (otherwise fetched once) |
| `ACCESS_TEAM_DOMAIN`, `ACCESS_AUD`, `KETO_READ_URL`, `ADMIN_ORIGIN` | none (the console answers 503) | the operator console's gate |

## Sign-in

- **Passkeys.** WebAuthn through kanidm's webauthn-rs. User verification is required, and the RP ID is `APP_HOST`, so
  a passkey made for the app is never offered to a tenant page. Ceremony state is kept in the database (one use, 5
  minutes).
- **Sui wallet.** The wallet signs a CAIP-122-style message as a Sui personal message (`Chain ID: sui:<network>`, a
  nonce, issued and expiry times). The server rebuilds the text from its own record and verifies ed25519, secp256k1 or
  secp256r1 signatures. Multisig and zkLogin are refused.
- **Recovery codes.** Ten one-use codes are shown once, at sign-up or when replaced; only their SHA-256 is kept.
- **Sessions.** The cookie is `__Host-lib_session`: Secure, HttpOnly, SameSite=Strict, host-only. Only its SHA-256 is
  stored. A session lasts 14 days idle and 60 days at most. Every state-changing request needs `Origin` = the app origin
  and the `X-Link-In-Bio-Request` header.

## Invites

- Free accounts come only from codes the operator issues in the console. A code goes either to the operator, who sees
  it once, or to an account, which sees it in the app to pass on until it is redeemed or revoked.
- "Issue K codes" gives codes to every account a saved selection matches at that moment. The criteria are account age,
  a published page, paid, invitees in good standing, and a tag.
- Nothing is issued automatically, and new accounts get no codes.
- Each code works once and expires. The invite tree (`invited_by`) is recorded, and an account's right to pass on codes
  can be revoked.

## Billing

- **Providers.** Each provider implements `BillingProvider`: start a checkout, verify and read its notifications, and
  report a checkout's outcome. Each passes the conformance checks in `crates/billing/tests/`.
- **Routing.** The router offers a method only where its seller may sell:
  - where the operator is the seller, the declared country and the request's country (`CF-IPCountry`) must agree and
    be on that method's list;
  - a merchant of record may be offered anywhere.
- **Months.** One purchase buys 1 to 12 months, and an account is never paid more than 24 months ahead. A method's
  minimum is `ceil(fixed fee × 1.25 / (3 % × price))`, so its fixed fee stays at most 3 % of a month.
- **The ledger.** Every change to a paid period (purchase, grant, refund) is one row per provider event, applied once.
  A payment seen both by notification and by the worker's reconciliation extends the period once.
- **Chain Payments.** Chain Payments sessions carry `units` (the months) and the account's opaque billing reference
  (never the handle). Its notifications are ed25519-signed (`Chain-Payments-Signature`) and arrive on the internal
  port.

## Pages, screening and safety

- **Publishing.** A page is published from the draft once the account is free, an operator account, or paid. Every link
  not screened yet is screened first.
- **Screening, in layers.**
  1. Built-in checks: IP-address hosts, unusual ports, link shorteners.
  2. The operator's blocklist and ThreatFox.
  3. Web Risk, under its monthly cap.

  A flagged link is hidden until an operator decides. A link that could not be checked is shown and checked again
  within the hour. Clean links are checked daily.
- **What a tenant host answers.**

  | Situation | Status |
  | --- | --- |
  | No page, not published, not paid, or third-party pages off | 404 |
  | Removed under the policy, or deleted | 410 |
  | Withheld on legal grounds | 451 |
  | Suspended for a time | 403 |

  Pages never set a cookie, and every page links to the report form.
- **Reports and appeals.** Reports need no account. A decision carries a statement of reasons, which the account holder
  sees and may appeal. Suspensions end the account's sessions.
- **Retention.** Every operator action is in the audit log, kept two years. Decided cases are kept two years.

## Data

| Kept | Where | Why |
| --- | --- | --- |
| Handle, the 18+ declaration with the terms version and time, declared country, flags | `lib.accounts` | the account; evidence of consent; tax evidence |
| Passkey public keys, wallet addresses, recovery code hashes, session hashes | `lib.passkeys`, `lib.wallets`, `lib.recovery_codes`, `lib.sessions` | sign-in |
| The draft, the published document and the last 20 versions; pictures (re-encoded, metadata stripped) | `lib.pages`, `lib.page_versions`, `lib.assets` | the page |
| Checkouts and billing events (with the countries seen at purchase) | `lib.checkouts`, `lib.billing_events` | accounting and tax records, kept after an account is deleted |
| Reports (an optional contact), appeals, the audit log | `lib.reports`, `lib.appeals`, `lib.audit_log` | trust and safety |

- **Erasure.** Deleting an account (`DELETE /api/v1/me`) removes its sign-in methods, sessions, pictures, domains and
  page versions, and empties its page. The row stays as `deleted`, so the handle is never reissued, and the billing
  records stay as the law requires.
- **Export.** `GET /api/v1/me/export` returns everything else stored about the account.

## API

The route tables in `crates/api/src/hosted/routes.rs` generate [`openapi/app.json`](../openapi/app.json) and
[`openapi/admin.json`](../openapi/admin.json). A test sends a request to every route in the tables and checks that the
committed documents match them.
