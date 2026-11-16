//! The documents that make a page readable by other software, all derived from the same manifest:
//!
//! - **Profile Links** (`/links.json`): an RFC 9264 link set with the profile `…/spec/profile-links/v1`;
//! - schema.org **ProfilePage** JSON-LD (in the page);
//! - **WebFinger** (RFC 7033) and a read-only **ActivityPub** actor, so fediverse software can look the page up;
//! - Nostr **NIP-05** (`/.well-known/nostr.json`) and the AT Protocol handle file (`/.well-known/atproto-did`);
//! - **security.txt** (RFC 9116).

use serde_json::{Value, json};

use crate::manifest::{Item, Kind, Link, Manifest};
use crate::render::PageContext;

/// The extension relation type for "this is the same person" (the microformats rel-me definition), used until "me"
/// is in the IANA link-relations registry.
pub const REL_ME: &str = "http://microformats.org/wiki/rel-me";
pub const LINKSET_TYPE: &str = "application/linkset+json";
pub const ACTIVITY_TYPE: &str = "application/activity+json";

fn target(l: &Link, lang: &str) -> Value {
    let mut t = json!({ "href": l.url, "title*": [{ "value": l.title, "language": lang }] });
    if let Some(d) = &l.description {
        t["description"] = json!([d]);
    }
    t
}

/// The Profile Links document (RFC 9264 `application/linkset+json`).
///
/// The page is the anchor of the first link context. Its `item` targets list the page's links and groups in page
/// order; a group's own context (anchor `…#g-<id>`) lists that group's links as `item`. Identity links are repeated
/// under [`REL_ME`]. The avatar is the `icon`; the ActivityPub actor, when served, is `describedby`.
pub fn linkset(m: &Manifest, cx: &PageContext, profile_uri: &str) -> Value {
    let lang = m.meta.lang.as_str();
    let mut items = Vec::new();
    let mut contexts = Vec::new();
    for item in &m.items {
        match item {
            Item::Link(l) if !l.hidden => items.push(target(l, lang)),
            Item::Group(g) => {
                let links: Vec<Value> = g.items.iter().filter(|l| !l.hidden).map(|l| target(l, lang)).collect();
                if links.is_empty() {
                    continue;
                }
                let anchor = format!("{}#g-{}", cx.canonical, g.id);
                items.push(
                    json!({ "href": anchor, "title*": [{ "value": g.title, "language": lang }], "type": "text/html" }),
                );
                contexts.push(json!({ "anchor": anchor, "item": links }));
            }
            Item::Link(_) => {}
        }
    }
    let me: Vec<Value> = m.visible_links().filter(|l| l.identity).map(|l| json!({ "href": l.url })).collect();
    let mut main = json!({ "anchor": cx.canonical, "item": items });
    if !me.is_empty() {
        main[REL_ME] = json!(me);
    }
    if let Some(a) = &cx.avatar {
        main["icon"] = json!([{ "href": a.url, "type": a.mime }]);
    }
    if let Some(actor) = &cx.actor_url {
        main["describedby"] = json!([{ "href": actor, "type": ACTIVITY_TYPE }]);
    }
    main["profile"] = json!([{ "href": profile_uri }]);
    let mut linkset = vec![main];
    linkset.extend(contexts);
    json!({ "linkset": linkset })
}

/// The `Link` header value that advertises the Profile Links document from the page.
pub fn linkset_header(linkset_url: &str, profile_uri: &str) -> String {
    format!(r#"<{linkset_url}>; rel="linkset"; type="{LINKSET_TYPE}"; profile="{profile_uri}""#)
}

/// schema.org ProfilePage JSON-LD.
pub fn json_ld(m: &Manifest, cx: &PageContext) -> Value {
    let id = &m.identity;
    let mut entity = json!({
        "@type": match id.kind { Kind::Person => "Person", Kind::Organization => "Organization" },
        "name": id.display_name,
        "alternateName": format!("@{}", id.handle),
        "url": cx.canonical,
        "identifier": id.handle,
    });
    if let Some(b) = &id.bio {
        entity["description"] = json!(b);
    }
    if let Some(a) = &cx.avatar {
        entity["image"] = json!(a.url);
    }
    let same: Vec<&str> = m.visible_links().filter(|l| l.identity).map(|l| l.url.as_str()).collect();
    if !same.is_empty() {
        entity["sameAs"] = json!(same);
    }
    json!({ "@context": "https://schema.org", "@type": "ProfilePage", "url": cx.canonical, "mainEntity": entity })
}

/// JSON-LD serialised for a `<script type="application/ld+json">` element: `<`, `>` and `&` are escaped as Unicode
/// escapes, so the text can never close the element or open a comment.
pub fn json_ld_for_html(m: &Manifest, cx: &PageContext) -> String {
    json_ld(m, cx).to_string().replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

/// A WebFinger (RFC 7033) JRD for `acct:<handle>@<domain>`.
pub fn webfinger(m: &Manifest, cx: &PageContext, domain: &str) -> Value {
    let mut links = vec![json!({
        "rel": "http://webfinger.net/rel/profile-page", "type": "text/html", "href": cx.canonical
    })];
    if let Some(actor) = &cx.actor_url {
        links.push(json!({ "rel": "self", "type": ACTIVITY_TYPE, "href": actor }));
    }
    if let Some(a) = &cx.avatar {
        links.push(json!({ "rel": "http://webfinger.net/rel/avatar", "type": a.mime, "href": a.url }));
    }
    let mut aliases = vec![json!(cx.canonical)];
    if let Some(actor) = &cx.actor_url {
        aliases.push(json!(actor));
    }
    json!({ "subject": format!("acct:{}@{domain}", m.identity.handle), "aliases": aliases, "links": links })
}

/// Fields Mastodon shows on a profile (it keeps the first four).
const ACTOR_FIELDS: usize = 4;

/// A read-only ActivityPub actor: the profile, its links as `PropertyValue` fields (with `rel="me"` on the person's
/// own profiles so Mastodon can verify them), an empty outbox, follow requests held for approval and never approved.
pub fn actor(m: &Manifest, cx: &PageContext, public_key_pem: Option<&str>) -> Value {
    let Some(actor_url) = &cx.actor_url else { return Value::Null };
    let id = &m.identity;
    let fields: Vec<Value> = m
        .visible_links()
        .filter(|l| l.url.starts_with("https://"))
        .take(ACTOR_FIELDS)
        .map(|l| {
            let rel = if l.identity { "me nofollow noopener noreferrer" } else { "nofollow noopener noreferrer" };
            let shown = crate::render::display_url(&l.url);
            json!({
                "type": "PropertyValue",
                "name": l.title,
                "value": format!(r#"<a href="{}" rel="{rel}" target="_blank">{}</a>"#, html_attr(&l.url), html_text(&shown)),
            })
        })
        .collect();
    let mut a = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
            { "schema": "http://schema.org#", "PropertyValue": "schema:PropertyValue", "value": "schema:value",
              "manuallyApprovesFollowers": "as:manuallyApprovesFollowers" }
        ],
        "id": actor_url,
        "type": match id.kind { Kind::Person => "Person", Kind::Organization => "Organization" },
        "preferredUsername": id.handle,
        "name": id.display_name,
        "url": cx.canonical,
        "inbox": format!("{actor_url}/inbox"),
        "outbox": format!("{actor_url}/outbox"),
        "manuallyApprovesFollowers": true,
        "discoverable": m.meta.indexable,
        "attachment": fields,
    });
    if let Some(b) = &id.bio {
        a["summary"] = json!(format!("<p>{}</p>", html_text(b)));
    }
    if let Some(av) = &cx.avatar {
        a["icon"] = json!({ "type": "Image", "mediaType": av.mime, "url": av.url });
    }
    if let Some(pem) = public_key_pem {
        a["publicKey"] = json!({ "id": format!("{actor_url}#main-key"), "owner": actor_url, "publicKeyPem": pem });
    }
    a
}

/// The actor's (always empty) outbox.
pub fn outbox(actor_url: &str) -> Value {
    json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{actor_url}/outbox"),
        "type": "OrderedCollection",
        "totalItems": 0,
        "orderedItems": []
    })
}

/// Nostr NIP-05 for one name.
pub fn nostr_json(handle: &str, pubkey: &str) -> Value {
    json!({ "names": { handle: pubkey } })
}

/// RFC 9116 security.txt. `expires` is an RFC 3339 timestamp.
pub fn security_txt(contact: &str, canonical: &str, expires: &str, policy: Option<&str>) -> String {
    let mut s = format!("Contact: {contact}\nExpires: {expires}\nPreferred-Languages: en\nCanonical: {canonical}\n");
    if let Some(p) = policy {
        s.push_str(&format!("Policy: {p}\n"));
    }
    s
}

fn html_text(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn html_attr(s: &str) -> String {
    html_text(s).replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ParseOptions, parse};

    fn manifest() -> Manifest {
        parse(
            br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada","bio":"a < b"},
              "items":[{"id":"gh","title":"GitHub","url":"https://github.com/ada","identity":true},
                       {"kind":"group","id":"tools","title":"Tools","items":[{"id":"d","title":"Docs","url":"https://docs.example.org/"}]},
                       {"id":"h","title":"Hidden","url":"https://hidden.example.org/","hidden":true}]}"#,
            ParseOptions::default(),
        )
        .unwrap()
        .manifest
    }

    fn cx() -> PageContext {
        let mut c = crate::render::tests::cx();
        c.actor_url = Some("https://ada.example.org/actor".into());
        c
    }

    #[test]
    fn linkset_keeps_order_groups_and_identity() {
        let ls = linkset(&manifest(), &cx(), "https://example.org/spec/profile-links/v1");
        let main = &ls["linkset"][0];
        assert_eq!(main["anchor"], "https://example.org/");
        assert_eq!(main["item"].as_array().unwrap().len(), 2, "hidden links are left out");
        assert_eq!(main["item"][1]["href"], "https://example.org/#g-tools");
        assert_eq!(main[REL_ME][0]["href"], "https://github.com/ada");
        assert_eq!(ls["linkset"][1]["anchor"], "https://example.org/#g-tools");
        assert_eq!(ls["linkset"][1]["item"][0]["href"], "https://docs.example.org/");
    }

    #[test]
    fn json_ld_cannot_break_out_of_its_script_element() {
        let mut m = manifest();
        m.identity.display_name = "</script><script>alert(1)</script>".into();
        let s = json_ld_for_html(&m, &cx());
        assert!(!s.contains('<'));
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(back["mainEntity"]["name"], "</script><script>alert(1)</script>");
    }

    #[test]
    fn actor_and_webfinger() {
        let a = actor(&manifest(), &cx(), None);
        assert_eq!(a["preferredUsername"], "ada");
        assert_eq!(a["summary"], "<p>a &lt; b</p>");
        assert!(a["attachment"][0]["value"].as_str().unwrap().contains(r#"rel="me "#));
        let w = webfinger(&manifest(), &cx(), "example.org");
        assert_eq!(w["subject"], "acct:ada@example.org");
        assert!(w["links"].as_array().unwrap().iter().any(|l| l["rel"] == "self"));
    }
}
