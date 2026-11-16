# Security Policy

## Scope

The `link-in-bio-service` source and image (`link-in-bio` binary). Out of scope: the cluster and edge it runs behind, and
the editor UI (`link-in-bio-ui`, its own policy).

## Security model

1. **One parser is the trust boundary.** Page documents are parsed by hand-written code that drops unknown fields, bounds
   every string, refuses hidden text-direction and invisible characters, and accepts only `https:` and `mailto:` links (no
   credentials, no IP addresses). It is property-tested never to panic and shared vectors pin its behaviour.
2. **Output is escaped by construction.** Pages are rendered with maud (auto-escaping); the JSON-LD block escapes `<`, `>`
   and `&`. A property test checks that accepted text never adds markup.
3. **Pages are inert.** CSP `default-src 'none'` with `'self'` for styles, images and one same-origin script;
   `frame-ancestors 'none'`; no cookie is ever set; `Referrer-Policy: no-referrer`; only GET and HEAD (and POST to the
   read-only ActivityPub inbox, which accepts and drops).
4. **Pictures are re-encoded** from decoded pixels under size limits, so metadata and appended payloads are dropped; SVG is
   accepted only from the operator's own configuration.
5. **The local editor is loopback only**, refuses non-loopback `Host` headers (DNS rebinding) and cross-origin writes, and
   makes no outbound request.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Please do not open a
public issue. You will get an answer within a week.
