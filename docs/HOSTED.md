# The hosted service

The same binary that serves one page from files (`serve --mode static`) also runs pages for many accounts. This page is
the reference for running it: the process roles, the configuration and its switches, the data it keeps, and what each
part trusts.

## Process roles

| Command | What it serves | Database role | Typical port |
| --- | --- | --- | --- |
| `link-in-bio migrate` | applies the schema, then exits | owner (DDL) | none |
| `link-in-bio serve --mode pages` | every tenant host: `<handle>.<PAGES_DOMAIN>`, and verified custom domains when they are on. It takes no payment and reads no key: `BILLING_PROVIDERS` counts as `manual`, `BANK_FEEDS` as empty and every `*_FILE` setting as unset | read-only (it can read only the `public.*_v1` views) | 8080 |
| `link-in-bio serve --mode app` | the account API on `APP_HOST` (`/api/v1/…`, the page assets under `/_/`), plus the internal port (provider notifications, `/metrics`) | writer (schema `lib`) | 8080 and `INTERNAL_LISTEN_ADDR` (8081) |
| `link-in-bio serve --mode admin` | the operator console's API (`/api/v1/admin/…`) behind Cloudflare Access and the `LinkInBio:admin#member` Keto role. It holds no key: it shows which providers, feeds and Web Risk are on from the configuration, but no `*_FILE` setting is required or read, and it builds no provider and no screener | writer | 8080 |
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
| `WEB_RISK_KEY_FILE` | unset | Google Web Risk API key; without it, screening uses the built-in checks and the lists only. The Google project and its key must serve this service alone (see "Web Risk: two modes") |
| `WEB_RISK_MODE` | `lookup` | `lookup` (`uris.search`, free up to 100 000 calls a month) or `update` (local hash-prefix lists; confirmations billed). Never both; see "Web Risk: two modes" before switching |
| `WEB_RISK_MONTHLY_CAP` | `90000` | lookup: the free allowance of `uris.search` calls a month (at most 100 000); update: a hard cap on every call, `threatLists.computeDiff` and `hashes.search` together. Counted across every process |
| `WEB_RISK_PAID_MONTHLY_CALLS` | `0` | lookup only: `uris.search` calls a month beyond the free allowance ($0.50 per 1 000), the two together a hard stop. Refused in update mode |
| `WEB_RISK_CONFIRM_MONTHLY_CAP` | `0` | update only: `hashes.search` calls a month, part of `WEB_RISK_MONTHLY_CAP`. It is that mode's only billed call ($50 per 1 000, no free tier), so the default spends nothing and a link matching a local prefix is hidden until an operator reviews it. Each call allowed can cost $0.05. Refused in lookup mode |
| `WEB_RISK_MAX_ENTRIES` | `262144` | update only: the most hash prefixes kept per list (`constraints.maxDatabaseEntries`, a power of two from 1024 to 1048576); about 1 MB of memory per list in the app and the worker at the default |
| `ACCOUNT_LIMITS` | `standard` | how much one account may change its page: `standard` (30 changes an hour, 120 new links a day) or `generous` (300 and 1 200). Each value below overrides the preset on its own; `0` means no limit |
| `CHANGES_PER_ACCOUNT_HOUR` | preset | changes per UTC hour: publishes and picture uploads, one count. A publish that only removes or hides links is never counted or refused |
| `NEW_LINKS_PER_ACCOUNT_DAY` | preset | links an account's published page did not have before, per UTC day (what an account can make the service screen) |
| `BANK_TRANSFER_REFUND_FEE_PENCE` | `0` | what sending one refund by bank transfer costs the operator, in pence; deducted once per refund line |
| `OPEN_PAYMENTS_REFUND_FEE_PENCE` | `0` | what sending one refund from the operator's Open Payments wallet costs, in pence; deducted once per refund line |
| `THREATFOX_KEY_FILE` | unset | abuse.ch Auth-Key; when set, the worker syncs the last 7 days of ThreatFox indicators every 6 hours |
| `FEDERATION` | `on` | WebFinger, the read-only ActivityPub actor and NIP-05 on tenant pages |
| `SUI_NETWORK` | `testnet` | the chain id in the wallet sign-in message (`sui:<network>`) |
| `SUI_RPC_URL` | the public full node of `SUI_NETWORK` (`https://fullnode.<network>.sui.io:443`; none for other networks) | the Sui full node (gRPC-web) the app's wallet uses, reported as `suiRpcUrl` by `GET /api/v1/instance`: a bare https origin (`https://host` or `https://host:port`), refused otherwise. The UI's CSP must allow the same origin: the deployment gives it to the UI container as `CSP_CONNECT_SRC_EXTRA` (static-server 0.1.13) from the same setting |
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
- **What was paid must cover the checkout.** Before a Square, GoCardless or Paddle payment is applied, what the provider
  says was paid is compared with the checkout: for Square and GoCardless at least its amount in GBP; for Paddle exactly
  its months of `PADDLE_PRICE_ID` (the buyer's currency varies). A payment that does not cover its checkout is not
  applied: the checkout stays open, the console's audit log records it once (`payment-not-covering`) and the metric
  `link_in_bio_payment_mismatches_total` counts it. Chain Payments, Open Payments and bank transfers check the amount
  themselves.
- **Refunds no request names take months back pro rata.** Such a refund takes back `floor(months × refunded ÷ paid)`
  months, counted on the running total of the purchase's refunds (requests' refunds included): the refunds of one
  purchase never take back more than it bought, and partial refunds that add up to the whole amount take back every
  month. A failed or charged-back payment (GoCardless) takes back the whole purchase. A refund of a checkout that was
  never paid is recorded and takes nothing. A refund on request takes back exactly its months (below).
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
- **Refunds on request.** A refund costs the platform nothing beyond the operator's time
  (`crates/billing/src/refunds.rs`):
  - **Cancel within 14 days of a purchase:** the whole purchase comes back, less the days already used (what the
    purchase paid per month ÷ 30, per day begun since its first month started; none if it has not started) and less
    its share of the provider's fee. Every month it still gives is taken back. This also covers the UK 14-day right to
    cancel a service.
  - **Later:** only whole months that have not begun. They are taken from the newest purchases first (months stack, so
    the newest purchase's months are the last of the paid period); the month in progress is kept; granted months are
    not refunded. Each month is valued at what its own purchase paid per month.
  - **A late Chain Payments payment** (one that arrived after its checkout was paid or closed, credited as months):
    whole, within 30 days.
  - **The fee share** of a refund of `k` of a purchase's `m` months is `(fixed + percent × paid) × k ÷ m`, with the
    method's fees as recorded on its checkout when it was made (`lib.checkouts.fee_fixed_pence`, `fee_percent_bps`;
    for a checkout made before schema 6, the fees configured now, `<PROVIDER>_FIXED_PENCE` and
    `<PROVIDER>_PERCENT_BPS`): providers keep their fee when a payment is refunded. Chain Payments' fee is its 0.2 %
    (20 bps, what its package sends the platform treasury of each payment; no fixed fee, so its `min_months` stays 1 and
    no price shown changes). It is charged as a share of what was paid, so a purchase paid in another currency or a coin
    pays the same share without an exchange rate.
  - **Sending costs:** what the operator pays to send a refund by bank transfer or from the Open Payments wallet
    (`BANK_TRANSFER_REFUND_FEE_PENCE`, `OPEN_PAYMENTS_REFUND_FEE_PENCE`, default 0) is deducted once per line, as a
    share of what was paid in its unit. A Sui transaction's gas is a fraction of a penny and is not deducted.
  - **Rounding:** money is counted in the unit paid; the amount is rounded down to its smallest unit (each deduction
    up). A refund that would be 0 or less is refused, saying why.
  - **Where it goes:** Square, GoCardless and Paddle are refunded in their dashboards (Paddle in the buyer's currency);
    Chain Payments in the same coin, pro rata of what was received, from the recipient to the payer; a bank transfer
    to the paying account, named from the statement when it says (`Dbtr`, `DbtrAcct`, `DbtrAgt`; bunq's counterparty);
    Open Payments to the buyer's wallet address.
  - **The flow.** `GET /api/v1/billing/refunds` shows what may be asked now, worked out exactly;
    `POST /api/v1/billing/refund-requests` asks (`kind`: `cancel` with the purchase, `unstarted` with an optional
    number of months, or `unapplied`), and the account holder may withdraw it
    (`POST /api/v1/billing/refund-requests/{id}/withdraw`). One open request per account. The console's queue
    (`GET /api/v1/admin/refund-requests`) shows each purchase's exact amount, unit, months and destination, and flags an
    unstarted-months request whose first month has begun since. Nothing is sent automatically and no process holds a key
    that can refund: the operator refunds by hand. A provider's refund notification of exactly a line's amount closes
    that line and takes back exactly its months; otherwise the operator records the reference
    (`POST /api/v1/admin/refund-requests/{id}/refunded`, naming the purchase when the request has several) or declines
    the request with a reason (`…/declined`). Each step is in the audit log (`refund-requested`, `refund-withdrawn`,
    `refund-matched`, `refund-recorded`, `refund-declined`, `refund-not-matching-request`).
  - **The ledger.** A request's refund takes back exactly the months on it (never more than the purchase still gives):
    with the fee netted off, the pro-rata rule would leave the account holder a month they were refunded for. A refund
    that matches no request (one the provider or the operator made on their own, or of another amount) takes months
    back pro rata over everything refunded of that purchase, requests' refunds included.

## Pages, screening and safety

- **Publishing.** A page is published from the draft once the account is free, an operator account, or paid. Every link
  not screened yet is screened first.
- **Screening, in layers.**
  1. Built-in checks: IP-address hosts, unusual ports, link shorteners.
  2. The operator's blocklist and ThreatFox.
  3. Web Risk, in the mode `WEB_RISK_MODE` names (below).

  A flagged link is hidden until an operator decides. A link that could not be checked is shown and checked again
  within the hour. Unused screens are pruned as before.
- **Web Risk: two modes, never both.**
  - **Lookup** (`WEB_RISK_MODE=lookup`, the default; `uris.search`). A link is looked up when a page that adds it is
    published. The worker looks up again, weekly, only the links a published page of an active account shows: links
    only in a draft, hidden or removed are not rechecked (their next check moves a week on, and a publish screens them
    again if their verdict is older than a week). Unknown links are still checked within the hour and flagged ones
    weekly. Every call counts against the month's allowance, `WEB_RISK_MONTHLY_CAP` (the free 100 000 at most) plus
    `WEB_RISK_PAID_MONTHLY_CALLS` (default 0; $0.50 per 1 000), a hard stop; the worker's rechecks stop at 80 % of
    it, so the last 20 % is kept for links being published. Over the allowance a link is unknown, shown, and screened
    by the lists. There is no per-account Web Risk cap: `NEW_LINKS_PER_ACCOUNT_DAY` bounds the lookups an account's
    publishes make, and the links it holds (60 a page at most) its weekly rechecks. This mode never calls
    `threatLists.computeDiff` or `hashes.search`.
  - **Update** (`WEB_RISK_MODE=update`; `crates/safety/src/webrisk.rs`). The worker alone keeps the MALWARE,
    SOCIAL_ENGINEERING and UNWANTED_SOFTWARE lists of hash prefixes in `lib.web_risk_lists` with
    `threatLists.computeDiff` (uncompressed answers; a `RESET` replaces a list, a `DIFF` removes then adds, and the
    SHA-256 of the sorted result must equal the answer's checksum or the diff is discarded and the next update asks for
    the whole list), asking again at `recommendedNextDiff` (30 minutes when none is given; failures back off from 15
    minutes to 8 hours). The app and the worker hold the lists in memory and reload them within a minute of a change;
    the lists are built and loaded in this mode only. A link is canonicalised and its host and path expressions hashed
    as "URLs and hashing" specifies (<https://cloud.google.com/web-risk/docs/urls-hashing>; its test vectors are in the
    tests), and every link is checked again daily, locally and at no cost. Only when a hash matches a local prefix is
    that prefix sent to `hashes.search`; full hashes are cached until their `expireTime`, and a prefix's absence until
    its `negativeExpireTime`. A match that may not be confirmed (`WEB_RISK_CONFIRM_MONTHLY_CAP` reached; 0 by default)
    is hidden until an operator reviews it (source `webrisk-prefix`) and checked again daily, so a list update clears
    it. This mode never calls `uris.search`.
  - **Cost** (<https://cloud.google.com/web-risk/pricing>, read 2026-11-18): "Lookup API uris.search: free for up to
    100,000 calls per month", then $0.50 per 1 000; "Update API threatLists.computeDiff: unlimited free use";
    `hashes.search` "to confirm threats" is "$50.00 / 1,000 count", with no free tier; and "Calling
    threatLists.computeDiff changes the pricing of uris.search calls to the pricing of hashes.search calls".
  - **The trade-off.** Lookup costs nothing up to 100 000 calls a month, but its calls grow with the links held (one per
    link on a published page a week: about 260 a month for a full page of 60, so the default 90 000, whose rechecks
    stop at 72 000, keeps about 275 full pages rechecked; beyond that, links wait for next month), and each lookup sends
    Google the full URL. Update costs nothing however many links
    are held, rechecks daily, and sends only a hash prefix, and only on a local match; but a match is either confirmed
    at $0.05 a call or hidden until an operator reviews it, and the lists take memory (about 1 MB each at the default
    size) and the worker's updates.
  - **One project, one service, one mode.** The Google Cloud project and its key must serve this service alone:
    anything else calling `uris.search` on it is repriced too once this service calls `computeDiff`. Switching from
    update to lookup: in the month the switch is made, every lookup is billed at the `hashes.search` rate ($50 per
    1 000), because `computeDiff` was called that month. Switch at the start of a month (after the last `computeDiff`
    of the old month) or with a fresh project and key. Switching from lookup to update costs nothing extra.
  - **Privacy:** in update mode full URLs are not sent to Google, only a hash prefix (typically 4 bytes) of a link that
    matches a local list entry, and Google answers with every full hash on its lists that starts with it. In lookup
    mode each new link, and each link on a published page weekly, is sent to Google in full.
  - **The console's Overview** shows the mode and the month's counters: calls against the allowance (and where
    rechecks stop) in lookup mode; calls, confirmations and the lists in update mode.
- **Change limits per account** (`ACCOUNT_LIMITS`, `crates/api/src/hosted/limits.rs`). Changes (publishes and picture
  uploads, one count) an hour and new links a day are counted in `lib.counters`; over a limit the answer is 429 with the limit, when it
  resets and `Retry-After`, and the draft is kept. Removing or hiding links and unpublishing are never limited: a
  publish whose only differences from the published page are links removed or hidden is always accepted.
  `NEW_LINKS_PER_ACCOUNT_DAY` is also what bounds how many links an account can make the service screen. The console's
  Overview shows the preset and the values in effect.
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
| Checkouts and billing events (with the countries seen at purchase, and the method's fees then) | `lib.checkouts`, `lib.billing_events` | accounting and tax records, kept after an account is deleted |
| Open Payments grants: the buyer's wallet address, the outgoing payment, and (only until it is continued) the grant's continuation | `lib.open_payments_grants` | the payment's evidence; deleted with the checkout |
| Where each bank feed left off, and its own state (bunq's installation token and server key, a rotated Revolut refresh token) | `lib.bank_feeds` | reconciliation; never shown |
| Refund requests and their lines: the reason given, each purchase's amount, unit and destination (a payer address, a bank account named by the statement), the refund's reference, who recorded it and when | `lib.refund_requests`, `lib.refund_lines` | accounting records, kept with the billing events |
| Web Risk's hash prefixes | `lib.web_risk_lists` | screening; no personal data |
| Reports (an optional contact), appeals, the audit log | `lib.reports`, `lib.appeals`, `lib.audit_log` | trust and safety |

- **Erasure.** Deleting an account (`DELETE /api/v1/me`) removes its sign-in methods, sessions, pictures, domains and
  page versions, and empties its page. The row stays as `deleted`, so the handle is never reissued, and the billing
  records stay as the law requires.
- **Export.** `GET /api/v1/me/export` returns everything else stored about the account.

## Database roles per process

What each process does to each `lib` table, read from the store calls it makes (`crates/store/src/lib.rs` and its
callers). S = SELECT, I = INSERT, U = UPDATE, D = DELETE; "—" means it never touches the table. Every role also needs
`USAGE` on `lib.audit_log_id_seq` (the audit log's id) and may execute `lib.prune_audit_log` (schema 5; it runs as the
schema owner and removes nothing younger than two years). The page server's role reads only the `public.*_v1` views.
The migrate Job runs as the owner.

| Table | api (`serve --mode app`) | admin (console) | worker | jobs (`account create`, `account add-wallet`) |
| --- | --- | --- | --- | --- |
| `accounts` | S I U | S U | S U | S I U |
| `passkeys` | S I U D | — | — | — |
| `wallets` | S I D | — | — | S I |
| `recovery_codes` | S I U D | — | — | — |
| `sessions` | S I U D | S D | S D | — |
| `challenges` | S I D | — | S D | — |
| `pages` | S I U | S | S | I |
| `page_versions` | S I D | S | S D | — |
| `assets` | S I D | S | S D | — |
| `selections` | — | S I D | — | — |
| `invites` | S U | S I U | S D | — |
| `checkouts` | S I U | S U | S U | — |
| `billing_events` | S I U | S I U | S I U | — |
| `refund_requests` | S I U | S U | — | — |
| `refund_lines` | S I U | S U | — | — |
| `open_payments_grants` | S I U | — | — | — |
| `domains` | S I D | S | S U | — |
| `reports` | S I | S U | S D | — |
| `appeals` | S I | S U | S D | — |
| `audit_log` | S I | S I | S I | I |
| `link_screens` | S I U | S I U | S I U D | — |
| `blocklist` | S | S I U D | S | — |
| `threat_iocs` | S | — | S I D | — |
| `counters` | S I U | S | S I U D | — |
| `bank_feeds` | — | S | S I U | — |
| `web_risk_lists` | S | S | S I U | — |

**The audit log is insert-only for every process** (`insert_only_tables=audit_log`): no process updates or deletes it,
and the worker's two-year retention goes through `lib.prune_audit_log`.

**Tables each process may have read-only** (`read_only_tables`, SELECT only), without breaking it:

- **api:** `selections`, `blocklist`, `threat_iocs`, `bank_feeds`, `web_risk_lists`.
- **admin:** `passkeys`, `wallets`, `recovery_codes`, `challenges`, `pages`, `page_versions`, `assets`,
  `open_payments_grants`, `domains`, `threat_iocs`, `counters`, `bank_feeds`, `web_risk_lists`.
- **worker:** `passkeys`, `wallets`, `recovery_codes`, `pages`, `selections`, `refund_requests`, `refund_lines`,
  `open_payments_grants`, `blocklist`.
- **jobs:** every table but `accounts`, `pages`, `wallets` and `audit_log`: `passkeys`, `recovery_codes`, `sessions`,
  `challenges`, `page_versions`, `assets`, `selections`, `invites`, `checkouts`, `billing_events`, `refund_requests`,
  `refund_lines`, `open_payments_grants`, `domains`, `reports`, `appeals`, `link_screens`, `blocklist`, `threat_iocs`,
  `counters`, `bank_feeds`, `web_risk_lists`.

`lib.web_risk_lists` is written by the worker only, in update mode (it keeps the lists); the app reads it to load them,
the console to show their state. In lookup mode the worker also moves the next check of due links no published page
shows (`link_screens` U, which it has) and reads `pages` and `accounts` to tell them apart.

**Writes made only for a narrow reason** (a finer grant than the table would need a column grant or a function):

- **api:** `accounts` U only for the declared country, erasure (`status = 'deleted'`) and `paid_until` through the ledger;
  `invites` U only to mark a code redeemed at sign-up; `checkouts` U only to mark one paid or expired (and its row lock
  for refunds, which needs U); `billing_events` U only `paid_until_after` of the row it just inserted;
  `refund_requests` U only when its account holder withdraws one or a provider's refund notification closes it, and
  `refund_lines` U only for that notification.
- **admin:** `accounts` U for flags, suspension and `paid_until` (operator grants, bank statements); `sessions` D only to
  end a suspended account's sessions; `checkouts` and `billing_events` U only when an imported statement pays a checkout or
  a refund is recorded; `refund_requests` and `refund_lines` U only to record or decline a refund.
- **worker:** `sessions`, `challenges`, `invites`, `reports`, `appeals`, `page_versions`, `assets` and `counters` D only for
  expiry and retention; `accounts` U only to lift suspensions whose time is up and for `paid_until` through the ledger.
- **jobs:** `accounts` I and U only to create the operator's own accounts and set their flags.

No process needs more than table-level grants: the row locks taken (`FOR UPDATE` on `checkouts`, `invites`,
`refund_requests` and `refund_lines`) are on tables where the process already has U.

## API

The route tables in `crates/api/src/hosted/routes.rs` generate [`openapi/app.json`](../openapi/app.json) and
[`openapi/admin.json`](../openapi/admin.json). A test sends a request to every route in the tables and checks that the
committed documents match them.
