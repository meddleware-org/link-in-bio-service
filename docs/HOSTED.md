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
| `link-in-bio bank-feed revolut-token --code c --out f` | exchanges the code from Revolut Business's consent page for a refresh token and writes it to a new file (mode 0600) for `REVOLUT_REFRESH_TOKEN_FILE`; the token is never printed | none | none |

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
| `BILLING_PROVIDERS` | `manual` | comma list of `manual`, `chain-payments`, `square`, `gocardless`, `paddle`, `bank-transfer`, `open-payments` |
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
| `SQUARE_ACCESS_TOKEN_FILE`, `SQUARE_LOCATION_ID`, `SQUARE_SIGNATURE_KEY_FILE`, `SQUARE_API_BASE` (sandbox), `SQUARE_FIXED_PENCE` (25), `SQUARE_PERCENT_BPS` (140) | required when `square` is on | a payment link per checkout; notifications at `https://<APP_HOST>/api/v1/webhooks/square` (register exactly that URL: Square signs it) |
| `GOCARDLESS_ACCESS_TOKEN_FILE`, `GOCARDLESS_WEBHOOK_SECRET_FILE`, `GOCARDLESS_API_BASE` (sandbox), `GOCARDLESS_FIXED_PENCE` (20), `GOCARDLESS_PERCENT_BPS` (100) | required when `gocardless` is on | a billing request and its hosted flow; notifications at `/api/v1/webhooks/gocardless` |
| `PADDLE_API_KEY_FILE`, `PADDLE_WEBHOOK_SECRET_FILE`, `PADDLE_PRICE_ID`, `PADDLE_API_BASE` (sandbox), `PADDLE_FIXED_PENCE` (40), `PADDLE_PERCENT_BPS` (500) | required when `paddle` is on | a transaction for the one-month catalog price × months, paid on Paddle's default payment link; notifications at `/api/v1/webhooks/paddle` |
| `BANK_TRANSFER_SCHEME` (`sepa` or `faster-payments`), `BANK_TRANSFER_PAYEE`, `BANK_TRANSFER_IBAN`, `BANK_TRANSFER_BIC`, `BANK_TRANSFER_EUR_CENTS_PER_MONTH`, `BANK_TRANSFER_SORT_CODE`, `BANK_TRANSFER_ACCOUNT_NUMBER` | required when `bank-transfer` is on | payment details with an ISO 11649 reference (and an EPC QR payload for SEPA); paid when the operator imports the bank's camt.053/054 statement in the console |
| `OPEN_PAYMENTS_WALLET_ADDRESS`, `OPEN_PAYMENTS_KEY_ID`, `OPEN_PAYMENTS_KEY_FILE`, `OPEN_PAYMENTS_ASSET_CODE` (`GBP`), `OPEN_PAYMENTS_ASSET_SCALE` (2), `OPEN_PAYMENTS_MINOR_PER_MONTH` | required when `open-payments` is on (the last only when the asset is not GBP) | the operator's wallet address (the payee, and the client every grant names), the id of the client key registered with that wallet's provider (listed at `<wallet address>/jwks.json`), the ed25519 private key file (PKCS #8 PEM, or the base64 of it), and the wallet's asset; for another asset, its minor units per month |
| `BANK_FEEDS` | none | comma list of `wise`, `bunq`, `revolut`: the receiving banks' APIs the worker polls for bank-transfer credits (needs `bank-transfer` on). Only the worker reads the feeds' secrets |
| `BANK_FEED_POLL_SECS` | `900` | how often the worker polls the feeds (300 to 86 400) |
| `WISE_TOKEN_FILE`, `WISE_PROFILE_ID`, `WISE_SCA_KEY_FILE`, `WISE_API_BASE` (`https://api.wise-sandbox.com`), `WISE_API_VERSION` (`2026Q4`) | required when `wise` is a feed (the SCA key whenever Wise asks for SCA: UK and EEA profiles) | an API token, the business profile, and the RSA private key (PEM) whose public key is uploaded to Wise, which signs Wise's one-time token; statements are read as camt.053 for every standard balance |
| `BUNQ_API_KEY_FILE`, `BUNQ_KEY_FILE`, `BUNQ_PERMITTED_IPS`, `BUNQ_API_BASE` (`https://public-api.sandbox.bunq.com/v1`) | required when `bunq` is a feed (the IPs optional) | the API key, the RSA private key (PEM) the installation registers and every request is signed with, and the IPs the device may call from (unset: bunq binds the address it is registered from) |
| `REVOLUT_CLIENT_ID`, `REVOLUT_ISSUER`, `REVOLUT_KEY_FILE`, `REVOLUT_REFRESH_TOKEN_FILE`, `REVOLUT_API_BASE` (`https://sandbox-b2b.revolut.com/api/1.0`) | required when `revolut` is a feed | the client id, the redirect URI's host (the assertion's `iss`), the RSA private key (PEM) whose certificate is uploaded in Revolut Business, and the refresh token (`link-in-bio bank-feed revolut-token`) |
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
- **Card and bank providers.** Square (UK cards), GoCardless (UK bank payments over Open Banking), and Paddle (merchant
  of record, so offered anywhere) each send the buyer to the provider's hosted page. The app loads no provider script.
  Their signed notifications arrive at `/api/v1/webhooks/<provider>` on the app host.
- **Bank transfer.** There is no provider. The checkout shows the payee, the account and an `RF…` reference (with an EPC
  QR payload for SEPA). The operator imports the receiving bank's ISO 20022 statement
  (`POST /api/v1/admin/bank-statements`). A booked credit with the reference, in the right currency and for at least
  the amount, pays the checkout once. Underpayments and unknown references are reported and never applied.
- **Bank feeds.** The worker can read the credits itself from the receiving bank's API instead of the operator
  importing a statement: Wise (balance statements as camt.053, with Wise's SCA signature of the one-time token), bunq
  (installation, device and session; every request body signed and every answer's server signature checked) and
  Revolut Business (an RS256 client-assertion JWT and a refresh token). Each poll looks back two days past where it
  left off (seven on the first), and the credits are matched by the same rules as an imported statement. A feed's
  cursor and its own state (bunq's installation, a rotated Revolut refresh token) are in `lib.bank_feeds`; the
  console's overview shows when each feed last ran and its last error.
- **Open Payments (Interledger).** The checkout is an incoming payment on the operator's wallet address for the amount
  (a non-interactive incoming-payment grant). The buyer gives their wallet address (a URL, or a `$` payment pointer;
  `https` to a public host only). The service gets a quote there and an outgoing-payment grant limited to the quote's
  debit amount and to that incoming payment, with an interactive redirect: the buyer approves on their wallet's own
  page and comes back to `https://<APP_HOST>/billing?checkout=<id>&openPayments=finish&hash=…&interact_ref=…`. The app
  posts `hash` and `interact_ref`; the service checks the GNAP interaction hash (RFC 9635 §4.2.3, SHA-256, URL-safe
  base64 without padding), continues the grant and creates the outgoing payment. The checkout is paid only when the
  operator's incoming payment reports a received amount at least the expected one (read when the app polls the
  checkout, and by the worker's reconciliation). Every request to a grant or resource server is signed (RFC 9421,
  ed25519, `Content-Digest` with SHA-512). The continuation token is kept in `lib.open_payments_grants` only until the
  grant is continued. There are no notifications.
- **Chain Payments.** Chain Payments sessions carry `units` (the months) and the account's opaque billing reference
  (never the handle). Its notifications are ed25519-signed (`Chain-Payments-Signature`) and arrive on the internal
  port.
- **Refunds of unapplied payments.** A Chain Payments payment that arrives after its checkout was paid or closed is
  credited as the months its quote was for. Within 30 days its account holder may ask for the money back instead,
  once per payment (`POST /api/v1/billing/events/{id}/refund-request`). Nothing is sent automatically: the operator
  sends the refund by hand from the recipient (the same coin and amount, to the paying address, both shown in the
  console's queue, `GET /api/v1/admin/refund-requests`) and records it with the refund transaction's reference
  (`POST /api/v1/admin/refund-requests/{id}/refunded`). That takes the months back as a `refund` billing event, once.
  Each step is in the audit log.

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
| Open Payments grants: the buyer's wallet address, the outgoing payment, and (only until it is continued) the grant's continuation | `lib.open_payments_grants` | the payment's evidence; deleted with the checkout |
| Where each bank feed left off, and its own state (bunq's installation token and server key, a rotated Revolut refresh token) | `lib.bank_feeds` | reconciliation; never shown |
| Refund requests: the reason given, the refund's transaction reference, who recorded it and when | `lib.refund_requests` | accounting records, kept with the billing events |
| Reports (an optional contact), appeals, the audit log | `lib.reports`, `lib.appeals`, `lib.audit_log` | trust and safety |

- **Erasure.** Deleting an account (`DELETE /api/v1/me`) removes its sign-in methods, sessions, pictures, domains and
  page versions, and empties its page. The row stays as `deleted`, so the handle is never reissued, and the billing
  records stay as the law requires.
- **Export.** `GET /api/v1/me/export` returns everything else stored about the account.

## API

The route tables in `crates/api/src/hosted/routes.rs` generate [`openapi/app.json`](../openapi/app.json) and
[`openapi/admin.json`](../openapi/admin.json). A test sends a request to every route in the tables and checks that the
committed documents match them.
