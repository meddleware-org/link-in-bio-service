# Profile Links, version 1

**A profile of the Linkset media type (RFC 9264) for "link in bio" pages.**

- Profile URI: `https://meddleware.link/spec/profile-links/v1`
- Status: implementation specification, version 1 (2026-11-16). Licence: 0BSD (public-domain equivalent).
- Reference implementation: `link-in-bio-service` (`crates/core/src/interop.rs`), with conformance fixtures in `fixtures/`.

## 1. Purpose

A link-in-bio page is a profile made of links: one person or organisation, a short description, and an ordered list of
links, some of them the person's own profiles elsewhere. Every hosted service publishes such pages in its own HTML, which
other software can only scrape. Profile Links gives the same information a stable, machine-readable form built on an
existing IETF standard, so pages can be read, verified, mirrored and moved between services.

Profile Links defines no new media type. A Profile Links document **is** an `application/linkset+json` document (RFC 9264
§4.2) that follows the conventions below, and says so with the `profile` media type parameter (RFC 9264 §5).

## 2. Discovery

A page that has a Profile Links document advertises it in the HTTP response for the page and in its HTML:

```http
Link: <https://example.org/links.json>; rel="linkset"; type="application/linkset+json"; profile="https://meddleware.link/spec/profile-links/v1"
```

```html
<link rel="linkset" href="https://example.org/links.json" type="application/linkset+json">
```

The document itself is served with `Content-Type: application/linkset+json; profile="https://meddleware.link/spec/profile-links/v1"`
and should be cacheable and readable cross-origin (`Access-Control-Allow-Origin: *`): it is public by definition.

## 3. Structure

The document is a JSON object with one member, `linkset`, an array of link context objects (RFC 9264 §4.2.2).

### 3.1 The page context (first element)

| Member | Required | Meaning |
| --- | --- | --- |
| `anchor` | yes | the page's canonical URL |
| `item` | yes (may be empty) | the page's entries **in display order**: each link, and each group as a target whose `href` is the group's anchor (§3.2) |
| `http://microformats.org/wiki/rel-me` | no | the person's own profiles elsewhere (the same targets that carry `rel="me"` in the HTML) |
| `icon` | no | the profile picture (`href`, `type`) |
| `describedby` | no | richer descriptions of the profile, for example an ActivityPub actor (`type: application/activity+json`) |
| `profile` | yes | one target whose `href` is this profile's URI (RFC 9264 §5, RFC 6906) |

### 3.2 Group contexts (following elements)

A group is a named, ordered list of links shown together (for example "Tools"). Each group is a link context whose
`anchor` is the page URL with a fragment (`…#g-<id>`) and whose `item` lists the group's links in order. Groups do not nest.

### 3.3 Targets

Each target object has `href` (an absolute `https:` or `mailto:` URL) and, where known:

- `title*`: `[{ "value": "…", "language": "<BCP 47 tag>" }]` (RFC 9264 §4.2.4.2, internationalised title);
- `description`: `["…"]`, an extension target attribute (RFC 9264 §4.2.4.3) with a one-line description;
- `type`: `text/html` for a group's anchor.

Consumers must ignore members and target attributes they do not understand.

## 4. Example

```json
{
  "linkset": [
    {
      "anchor": "https://ada.example.org/",
      "item": [
        { "href": "https://github.com/ada", "title*": [{ "value": "GitHub", "language": "en" }] },
        { "href": "https://ada.example.org/#g-tools", "title*": [{ "value": "Tools", "language": "en" }], "type": "text/html" }
      ],
      "http://microformats.org/wiki/rel-me": [{ "href": "https://github.com/ada" }],
      "icon": [{ "href": "https://ada.example.org/_/avatar.3f2a.jpg", "type": "image/jpeg" }],
      "describedby": [{ "href": "https://ada.example.org/actor", "type": "application/activity+json" }],
      "profile": [{ "href": "https://meddleware.link/spec/profile-links/v1" }]
    },
    {
      "anchor": "https://ada.example.org/#g-tools",
      "item": [
        { "href": "https://docs.example.org/", "title*": [{ "value": "Docs", "language": "en" }], "description": ["Reference"] }
      ]
    }
  ]
}
```

## 5. Companion formats

A conforming page should also offer, from the same data:

- **microformats2 h-card** in its HTML, with `rel="me"` on the person's own profiles (IndieWeb identity verification);
- **schema.org `ProfilePage`** JSON-LD (search engines);
- **WebFinger** (RFC 7033) for `acct:<handle>@<domain>`, with a `self` link to a read-only **ActivityPub** actor whose
  `attachment` holds the links as `PropertyValue` fields (fediverse look-ups and verification);
- **`/.well-known/atproto-did`** on the page's own host when the person uses it as their AT Protocol handle;
- **Nostr NIP-05** (`/.well-known/nostr.json`) when the person names a Nostr key.

## 6. Security and privacy considerations

- Publishers must only list `https:` and `mailto:` targets; consumers must refuse other schemes (`javascript:`, `data:`).
- A Profile Links document carries no tracking: links point straight at their targets (no redirector), and fetching the
  document must not set cookies.
- `rel-me` is a claim, not a proof: a consumer verifies it by finding a link back from the target to the page.

## 7. Toward a standard (annex)

What would turn this profile into a shared standard, in order:

1. **Register "me" in the IANA link-relations registry** (RFC 8288 §2.1.1; expert review), citing the microformats
   definition, and switch the relation from the extension URI to `me`.
2. **Publish the profile URI with a stable, versioned resolution policy** (RFC 6906): this page, unchanged once published;
   a new version gets a new URI.
3. **Conformance suite:** the reference implementation's fixtures (valid and invalid documents with expected results) as a
   language-neutral test corpus.
4. **A second, independent implementation** (for example an IndieWeb site generator or another hosted service).
5. **Community review:** the IndieWeb wiki (link-in-bio, rel-me), the W3C Social Web Community Group (ActivityPub
   alignment) and the IETF HTTPAPI working group (Linkset authors), leading to either an informational RFC or a W3C
   Community Group report.
6. Optional extensions to consider then: per-link verification state, payment pointers (Open Payments / Web Monetization),
   per-link language, and scheduled visibility.
