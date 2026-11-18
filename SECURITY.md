# Security Policy

## Scope

The `link-in-bio-service` source and image (`link-in-bio` binary) in every role: the operator's page
(`serve --mode static`), the local editor's backend (`serve --mode local`), and the hosted service (`serve --mode
pages|app|admin`, `worker`, `migrate`, the `account` and `bank-feed` commands; [docs/HOSTED.md](docs/HOSTED.md)). Out of
scope: the cluster and edge it runs behind (Cloudflare, the ingress, the database tier, network policies), the payment
providers and banks themselves, and the editor UI (`link-in-bio-ui`, its own policy).

## Security model

1. **One parser is the trust boundary.** Page documents are parsed by hand-written code that drops unknown fields, bounds
   every string, refuses hidden text-direction and invisible characters, and accepts only `https:` and `mailto:` links (no
   credentials, no IP addresses). It is property-tested never to panic and shared vectors pin its behaviour. Themes are
   fixed names; no CSS a person writes ever reaches a page.
2. **Output is escaped by construction.** Pages are rendered with maud (auto-escaping); the JSON-LD block escapes `<`, `>`
   and `&`. A property test checks that accepted text never adds markup.
3. **Pages are inert.** CSP `default-src 'none'` with `'self'` for styles, images and one same-origin script;
   `frame-ancestors 'none'`; no cookie is ever set; `Referrer-Policy: no-referrer`; only GET and HEAD (and POST to the
   read-only ActivityPub inbox, which accepts and drops). The editor's preview of a draft is served with a `sandbox`
   policy, so a draft never runs as the app's origin.
4. **Pictures are re-encoded** from decoded pixels under size, pixel and memory limits (at most 4096 pixels a side and
   64 MiB per decode, one decode at a time per process), so metadata and appended payloads are dropped; SVG is accepted
   only from the operator's own configuration.
5. **Sign-in.** Passkeys (WebAuthn, user verification required, RP ID the app host) and Sui wallet sign-in (a
   CAIP-122-style message the server rebuilds from its own record: domain, URI, `sui:<network>`, a one-use nonce, a
   five-minute expiry; ed25519, secp256k1 and secp256r1; multisig and zkLogin refused). Recovery codes are 80-bit and
   one-use. Session, recovery and invite codes are stored only as SHA-256. Sessions are `__Host-` cookies (Secure,
   HttpOnly, SameSite=Strict), 14 days idle and 60 days at most, and end on suspension. Every state-changing app request
   needs `Origin` equal to the app origin and the `X-Link-In-Bio-Request` header.
6. **The console** answers only with a Cloudflare Access token (RS256 against the team's keys, issuer, audience and
   time checked, skew 60 s) whose subject holds `LinkInBio:admin#member` in Keto; Keto unreachable means `503`, never
   allowed. It sets the same CSRF rule, and its answers are never cached.
7. **Billing.** A paid period changes only through the ledger, once per provider event (a unique key), from a
   notification whose signature the provider's adapter checked (ed25519 for Chain Payments, HMAC-SHA256 for Square,
   GoCardless and Paddle with Paddle's five-minute window), from a bank credit matched by its ISO 11649 reference,
   currency and amount, or from asking the provider directly. Open Payments requests are signed (RFC 9421) and the
   wallet's answer is checked against the GNAP interaction hash; every URL a buyer's wallet names must be `https` to a
   host whose every address is public, checked again by the resolver when the connection is made. Answers from any
   provider, bank or wallet are read up to a fixed size.
8. **The database.** The page server connects with a read-only role that can read only the `public.*_v1` views. Every
   value is a bound parameter. TLS is `verify-full` only (plain text only with an explicit local-test switch).
9. **Requests are bounded** in size, time and number at once in every role that listens beyond loopback; the page server never reads a provider,
   bank, Web Risk or ThreatFox key, whatever the shared configuration names.
10. **The local editor is loopback only**, refuses non-loopback `Host` headers (DNS rebinding) and cross-origin writes, and
    makes no outbound request.

What a deployment must do itself: keep the console behind Cloudflare Access, reach the origin only through the tunnel
(the `CF-IPCountry` header and the client address come from the edge), and restrict egress per role (the example
deployment's network policies).

## Supported versions

Until 1.0 only the latest release receives fixes; a fix ships as the next patch version. Older images are not patched:
deploy the latest tag (by digest).

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Please do not open a
public issue, and do not test against accounts or pages that are not yours. You will get an answer within a week.

## Disclosure

Coordinated disclosure: we confirm the report, agree a fix and a date with you, release the fix, then publish an advisory
(credited to you unless you prefer otherwise). We aim to release a fix within 90 days of the report, sooner for anything
that lets someone sign in as another person, change a paid period or run script on a page.
