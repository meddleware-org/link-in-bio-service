//! The page renderer: one HTML document per manifest, auto-escaped (maud), no inline style or script that runs, every
//! theme choice expressed as a `data-*` attribute the stylesheet reads. It works with scripts blocked; `enhance.js`
//! only adds the colour-mode control and copy buttons.

use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::icons::Icon;
use crate::manifest::{Item, Link, Manifest, Owner, SupportMethod};
use crate::theme::{ColorMode, Season};

/// Where the page's static files live (hashed paths under `/_/`).
#[derive(Debug, Clone)]
pub struct AssetUrls {
    /// The stylesheet's hashed path.
    pub css: String,
    /// The script's hashed path.
    pub js: String,
    /// The icon sprite's hashed path.
    pub icons: String,
}

/// The page's picture, already normalised (`link-in-bio-assets`).
#[derive(Debug, Clone)]
pub struct Avatar {
    /// Absolute URL (link previews and other software need one).
    pub url: String,
    /// The same file as a root-relative path (what the page itself loads, so it works on any host).
    pub path: String,
    /// The picture's width in pixels.
    pub width: u32,
    /// The picture's height in pixels.
    pub height: u32,
    /// The picture's media type.
    pub mime: &'static str,
}

/// A link in the page footer.
#[derive(Debug, Clone)]
pub struct FooterLink {
    /// The words of the link.
    pub text: String,
    /// Where the link goes.
    pub url: String,
}

/// The symbol a rights notice leads with. The same marks as `@meddleware/ui` `CopyrightLine` (its `symbolVariant`), so the
/// operator's page and the Vue sites show one notice (workspace docs/legal L-IP-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RightsSymbol {
    /// The Kopimi triangle: copy freely.
    Kopimi,
    /// The reversed C.
    Copyleft,
    /// ©.
    Copyright,
}

/// "<symbol> <year> <organisation>. <statement>", the symbol linking to the document that explains it.
#[derive(Debug, Clone)]
pub struct RightsNotice {
    /// Which symbol leads the notice.
    pub symbol: RightsSymbol,
    /// The document the symbol links to (an https URL, checked by the site configuration).
    pub href: String,
    /// The year shown.
    pub year: i32,
    /// The organisation the notice names.
    pub organisation: String,
    /// For example "All jams preserved."; empty for none.
    pub statement: String,
}

/// What the footer shows besides the colour control.
#[derive(Debug, Clone, Default)]
pub struct Footer {
    /// "Made with …" on tenant pages (entitlement-controlled).
    pub attribution: Option<FooterLink>,
    /// The account-free report form for this page (tenant pages).
    pub report_url: Option<String>,
    /// The operator's own footer links (legal notice, licence).
    pub links: Vec<FooterLink>,
    /// A short line of text.
    pub note: Option<String>,
    /// The rights notice, drawn like `CopyrightLine` (prefer it to a link and a `note`).
    pub rights: Option<RightsNotice>,
}

/// Everything the renderer needs besides the page document: addresses, the picture, the footer and which optional parts to draw.
#[derive(Debug, Clone)]
pub struct PageContext {
    /// The page's own absolute URL, with a trailing slash.
    pub canonical: String,
    /// The hashed paths of the static files.
    pub assets: AssetUrls,
    /// The page's picture, if it has one.
    pub avatar: Option<Avatar>,
    /// Whose page this is.
    pub owner: Owner,
    /// The footer's contents.
    pub footer: Footer,
    /// Favicons: the brand set for the operator's page; the avatar otherwise.
    pub brand_icons: bool,
    /// Sui explorer origin for support addresses (`https://suivision.xyz`).
    pub explorer: String,
    /// The Profile Links document (`/links.json`) and the ActivityPub actor, when served.
    pub linkset_url: Option<String>,
    /// The ActivityPub actor's address, when the page serves one.
    pub actor_url: Option<String>,
    /// Put the icon sprite inside the page (the editor's sandboxed preview cannot load an external sprite).
    pub inline_sprite: bool,
}

/// Render a page to a complete HTML document.
pub fn render_page(m: &Manifest, cx: &PageContext) -> String {
    page(m, cx).into_string()
}

/// Build the page: the head (metadata, icons and interop links), then the profile, the links, the contact and support sections, the operator's call to action and the footer.
fn page(m: &Manifest, cx: &PageContext) -> Markup {
    let t = &m.theme;
    let id = &m.identity;
    // The bio is the description; a page without one says whose links these are.
    let description = id.bio.clone().unwrap_or_else(|| format!("Links from {}", id.display_name));
    // The `color-scheme` meta tells the browser which built-in colours (form controls, scrollbars) to use.
    let color_scheme = match t.color_mode {
        ColorMode::System => "light dark",
        ColorMode::Light => "light",
        ColorMode::Dark => "dark",
    };
    // No season means no attribute at all.
    let season = (t.season != Season::None).then(|| t.season.as_str());
    // Every theme choice becomes a `data-*` attribute on the root element, which the stylesheet reads; there is no inline style.
    html! {
        (DOCTYPE)
        html lang=(m.meta.lang) data-theme=(t.color_mode.as_str()) data-season=[season] data-accent=(t.accent.as_str())
            data-buttons=(t.buttons.as_str()) data-radius=(t.radius.as_str()) data-density=(t.density.as_str())
            data-layout=(t.layout.as_str()) data-font=(t.font.as_str()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (id.display_name) }
                meta name="description" content=(description);
                meta name="color-scheme" content=(color_scheme);
                // A page that opted out of indexing says so in the page too.
                @if !m.meta.indexable { meta name="robots" content="noindex"; }
                link rel="canonical" href=(cx.canonical);
                // Open Graph and Twitter card metadata, so a shared link previews as a profile.
                meta property="og:type" content="profile";
                meta property="og:title" content=(id.display_name);
                meta property="og:description" content=(description);
                meta property="og:url" content=(cx.canonical);
                meta property="profile:username" content=(id.handle);
                @if let Some(a) = &cx.avatar {
                    meta property="og:image" content=(a.url);
                    meta property="og:image:type" content=(a.mime);
                    meta property="og:image:width" content=(a.width);
                    meta property="og:image:height" content=(a.height);
                    meta property="og:image:alt" content=(format!("Picture of {}", id.display_name));
                }
                // A small summary card, because the picture is square.
                meta name="twitter:card" content="summary";
                meta name="twitter:title" content=(id.display_name);
                meta name="twitter:description" content=(description);
                @if let Some(a) = &cx.avatar {
                    meta name="twitter:image" content=(a.url);
                    meta name="twitter:image:alt" content=(format!("Picture of {}", id.display_name));
                }
                // The stylesheet is the page's own, from the same origin, so the content policy needs no exception.
                link rel="stylesheet" href=(cx.assets.css);
                // The operator's page uses the brand icons; a tenant's page uses its own picture as the icon.
                @if cx.brand_icons {
                    link rel="icon" href="/favicon.ico" sizes="32x32";
                    link rel="icon" href="/favicon.svg" type="image/svg+xml";
                    link rel="apple-touch-icon" href="/apple-touch-icon.png";
                    link rel="manifest" href="/site.webmanifest";
                } @else if let Some(a) = &cx.avatar {
                    link rel="icon" href=(a.path) type=(a.mime);
                }
                // Tells software that reads links where the Profile Links document is.
                @if let Some(l) = &cx.linkset_url {
                    link rel="linkset" href=(l) type="application/linkset+json";
                }
                // Tells fediverse software where the actor is.
                @if let Some(a) = &cx.actor_url {
                    link rel="alternate" href=(a) type="application/activity+json";
                }
                // JSON-LD is a data block: browsers never execute it, and `<` is escaped so it cannot close the element.
                script type="application/ld+json" { (PreEscaped(crate::interop::json_ld_for_html(m, cx))) }
                // The one script, loaded as a module (deferred); the page works without it.
                script type="module" src=(cx.assets.js) {}
            }
            body {
                // The editor's preview cannot load an external sprite, so it carries the sprite inside the page.
                @if cx.inline_sprite { div class="sprite" hidden { (PreEscaped(crate::icons::SPRITE)) } }
                // The page is one microformats h-card, so software that reads microformats finds the name, picture, address and contact.
                main class="page h-card" {
                    header class="profile" {
                        @if let Some(a) = &cx.avatar {
                            img class="avatar u-photo" src=(a.path) alt="" width=(a.width) height=(a.height) decoding="async";
                        }
                        // The page's only heading is the person's name.
                        h1 class="name p-name" { (id.display_name) }
                        @if let Some(p) = &id.pronouns { p class="pronouns" { (p) } }
                        @if let Some(b) = &id.bio { p class="bio p-note" { (b) } }
                        // The page's own address, so the h-card has its url and uid.
                        p class="address" {
                            a class="u-url u-uid" href=(cx.canonical) { (display_url(&cx.canonical)) }
                        }
                    }
                    // A page with no visible links says so instead of showing an empty list.
                    @if m.visible_links().next().is_some() {
                        ul class="links" aria-label="Links" {
                            @for item in &m.items {
                                @match item {
                                    Item::Link(l) => @if !l.hidden { li { (link(l, cx)) } },
                                    // A group appears only if it has a visible link; it is a native `details` element, so it needs no script.
                                    Item::Group(g) => @if g.items.iter().any(|l| !l.hidden) {
                                        li class="group" id=(format!("g-{}", g.id)) {
                                            details open[g.open] {
                                                summary {
                                                    span { (g.title) }
                                                    (sprite_icon("chevron", "chevron", cx))
                                                }
                                                ul class="links" {
                                                    @for l in g.items.iter().filter(|l| !l.hidden) { li { (link(l, cx)) } }
                                                }
                                            }
                                        }
                                    },
                                }
                            }
                        }
                    } @else {
                        p class="empty" { "No links yet." }
                    }
                    // Contact entries are email links.
                    @if !m.contact.is_empty() {
                        section class="contact" aria-labelledby="contact-title" {
                            h2 id="contact-title" { "Contact" }
                            ul class="plain-list" {
                                @for c in &m.contact {
                                    li { a class="u-email" href=(c.url) { (c.label) } }
                                }
                            }
                        }
                    }
                    // Support entries are display-only: an address with a copy button (shown by the script) and a link to the explorer.
                    @if !m.support.is_empty() {
                        section class="support" aria-labelledby="support-title" {
                            h2 id="support-title" { "Support" }
                            @for s in &m.support {
                                @match s {
                                    SupportMethod::SuiAddress { address, label } => {
                                        div class="support-method" {
                                            p class="support-label" { (label.as_deref().unwrap_or("Sui address")) }
                                            p class="support-value" {
                                                code class="address-value" { (address) }
                                            }
                                            p class="support-actions" {
                                                button type="button" class="copy" data-copy=(address) hidden { "Copy address" }
                                                a href=(format!("{}/account/{}", cx.explorer, address)) { "View on the explorer" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Only the operator's page can have one (the parser drops it from tenant pages).
                    @if let Some(c) = &m.cta {
                        aside class="cta" aria-labelledby="cta-title" {
                            h2 id="cta-title" { (c.title) }
                            @if let Some(d) = &c.description { p { (d) } }
                            p { a class="button" href=(c.url) { (c.action.as_deref().unwrap_or("Find out more")) } }
                        }
                    }
                }
                // The footer: the colour choice, the report link, the attribution, the operator's links, a note and the rights notice.
                footer class="site-footer" {
                    // Only a page that follows the visitor's device lets the visitor choose; a fixed mode is the owner's choice.
                    @if t.color_mode == ColorMode::System { fieldset class="mode" hidden {
                        // The colour control starts hidden and is shown by the script, so a visitor without scripting never sees a control that does nothing.
                        legend { "Colour" }
                        button type="button" data-mode="light" aria-pressed="false" { "Light" }
                        button type="button" data-mode="dark" aria-pressed="false" { "Dark" }
                        button type="button" data-mode="system" aria-pressed="false" { "System" }
                        // Nothing is stored unless the visitor ticks this; unticking forgets (PECR Sch. A1 para 6:
                        // the information and the means of objecting, beside the choice; workspace docs/legal L-PECR-2).
                        label class="remember" { input type="checkbox" name="remember"; " Remember on this device" }
                    } }
                    // Every tenant page links to the account-free report form.
                    @if let Some(r) = &cx.footer.report_url { p { a href=(r) { "Report this page" } } }
                    // The "Made with" link shows only where the account's plan requires it.
                    @if let Some(a) = &cx.footer.attribution { p { "Made with " a href=(a.url) { (a.text) } } }
                    @if !cx.footer.links.is_empty() {
                        ul class="footer-links" {
                            @for l in &cx.footer.links { li { a href=(l.url) { (l.text) } } }
                        }
                    }
                    // A short free line of text.
                    @if let Some(n) = &cx.footer.note { p class="note" { (n) } }
                    @if let Some(r) = &cx.footer.rights { p class="rights" { (rights_notice(r)) } }
                }
            }
        }
    }
}

/// The notice in `CopyrightLine`'s markup and wording: the symbol (an inline SVG, the same geometry) as a link with an accessible
/// name, then the year, the organisation and the statement.
fn rights_notice(r: &RightsNotice) -> Markup {
    // The link's accessible name, since the symbol itself is decorative.
    let label = match r.symbol {
        RightsSymbol::Kopimi => "Kopimi legal notice",
        RightsSymbol::Copyleft => "Copyleft legal notice",
        RightsSymbol::Copyright => "Copyright legal notice",
    };
    html! {
        small class="copyright-line" {
            a class="symbol-link" href=(r.href) aria-label=(label) {
                @match r.symbol {
                    RightsSymbol::Copyright => { "©" }
                    RightsSymbol::Copyleft => {
                        svg class="symbol-mark" viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false" {
                            circle cx="12" cy="12" r="9.5" fill="none" stroke="currentColor" stroke-width="1.5" {}
                            text x="-12" y="12" transform="scale(-1,1)" text-anchor="middle" dominant-baseline="central" font-family="system-ui, sans-serif" font-size="13" fill="currentColor" { "C" }
                        }
                    }
                    RightsSymbol::Kopimi => {
                        svg class="symbol-mark" viewBox="0 0 24 24" width="1em" height="1em" aria-hidden="true" focusable="false" {
                            path d="M12 4L22 23H2Z" fill="none" stroke="currentColor" stroke-width="1.5" {}
                            text x="12" y="18" text-anchor="middle" dominant-baseline="middle" font-family="system-ui, sans-serif" font-size="11" fill="currentColor" { "C" }
                        }
                    }
                }
            }
            " " (r.year) " " (r.organisation) "."
            @if !r.statement.is_empty() { " " (r.statement) }
        }
    }
}

/// One link: an anchor with its icon, title and description. A profile marked as the person's own carries `rel="me"`; every link carries `noopener noreferrer`.
fn link(l: &Link, cx: &PageContext) -> Markup {
    let rel = if l.identity { "me noopener noreferrer" } else { "noopener noreferrer" };
    // Without a chosen icon, one is guessed from the host.
    let icon = l.icon.unwrap_or_else(|| guess_icon(&l.url));
    html! {
        a class="link" href=(l.url) rel=(rel) {
            (sprite_icon(icon.as_str(), "icon", cx))
            span class="link-text" {
                span class="link-title" { (l.title) }
                @if let Some(d) = &l.description { span class="link-description" { (d) } }
            }
        }
    }
}

/// One symbol of the sprite. The sprite path is the server's own hashed asset and the id a fixed name: nothing to escape.
fn sprite_icon(id: &str, class: &str, cx: &PageContext) -> Markup {
    // An inline sprite is referenced by fragment only; otherwise by the sprite's hashed path.
    let sprite = if cx.inline_sprite { "" } else { cx.assets.icons.as_str() };
    html! {
        svg class=(class) aria-hidden="true" focusable="false" width="24" height="24" {
            (PreEscaped(format!(r#"<use href="{sprite}#i-{id}"></use>"#)))
        }
    }
}

/// A sensible icon when the manifest names none.
fn guess_icon(url: &str) -> Icon {
    if url.starts_with("mailto:") {
        return Icon::Mail;
    }
    let host = crate::safe_url::display_host(url).unwrap_or_default();
    // Hosts and the icons they get, matched exactly or as a parent domain (`www.` is already dropped).
    let known: &[(&str, Icon)] = &[
        ("x.com", Icon::X),
        ("twitter.com", Icon::X),
        ("bsky.app", Icon::Bluesky),
        ("github.com", Icon::Github),
        ("gitlab.com", Icon::Gitlab),
        ("codeberg.org", Icon::Codeberg),
        ("huggingface.co", Icon::Huggingface),
        ("youtube.com", Icon::Youtube),
        ("matrix.to", Icon::Matrix),
        ("discord.gg", Icon::Discord),
        ("discord.com", Icon::Discord),
        ("t.me", Icon::Telegram),
        ("instagram.com", Icon::Instagram),
        ("tiktok.com", Icon::Tiktok),
        ("twitch.tv", Icon::Twitch),
        ("reddit.com", Icon::Reddit),
        ("npmjs.com", Icon::Npm),
    ];
    // A host matches on a full label boundary, so `evilgithub.com` does not get the GitHub icon.
    known.iter().find(|(h, _)| host == *h || host.ends_with(&format!(".{h}"))).map(|(_, i)| *i).unwrap_or(Icon::Link)
}

/// `https://example.org/` → `example.org`.
pub fn display_url(url: &str) -> String {
    url.trim_start_matches("https://").trim_end_matches('/').to_string()
}

/// Unit tests for the renderer, which are also used as a fixture by the interop tests.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::{ParseOptions, parse};

    /// A page context for tests: a tenant page with a report link, no picture and no actor.
    pub(crate) fn cx() -> PageContext {
        PageContext {
            canonical: "https://example.org/".into(),
            assets: AssetUrls { css: "/_/page.css".into(), js: "/_/enhance.js".into(), icons: "/_/icons.svg".into() },
            avatar: None,
            owner: Owner::Tenant,
            footer: Footer { report_url: Some("https://app.example.org/report?page=ada".into()), ..Footer::default() },
            brand_icons: false,
            explorer: "https://suivision.xyz".into(),
            linkset_url: Some("https://example.org/links.json".into()),
            actor_url: None,
            inline_sprite: false,
        }
    }

    /// Text is escaped, a profile link gets `rel="me"`, groups are `details`, icons come from the sprite, and the page has one heading and no inline style.
    #[test]
    fn renders_identity_links_with_rel_me_and_escapes_text() {
        let doc = br#"{"schema":1,"identity":{"displayName":"<script>alert(1)</script>","handle":"ada"},
          "items":[{"id":"a","title":"Me & \"you\"","url":"https://github.com/ada","identity":true},
                   {"kind":"group","id":"g","title":"Tools","items":[{"id":"b","title":"Docs","url":"https://docs.example.org/"}]}]}"#;
        let m = parse(doc, ParseOptions::default()).unwrap().manifest;
        let html = render_page(&m, &cx());
        assert!(!html.contains("<script>alert"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains(r#"rel="me noopener noreferrer""#));
        assert!(html.contains("<details>"));
        assert!(html.contains("#i-github"));
        assert!(html.contains("Report this page"));
        assert_eq!(html.matches("<h1").count(), 1);
        assert!(!html.contains(" style="));
    }

    /// The rights notice has the symbol link, the Kopimi triangle of the Vue component, the text, and no inline style.
    #[test]
    fn draws_the_rights_notice_like_the_vue_sites() {
        let doc = br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada"},"items":[]}"#;
        let m = parse(doc, ParseOptions::default()).unwrap().manifest;
        let mut c = cx();
        c.footer.rights = Some(RightsNotice {
            symbol: RightsSymbol::Kopimi,
            href: "https://example.org/legal/powr.broccoli-kopimi.pdf".into(),
            year: 2026,
            organisation: "Meddleware".into(),
            statement: "All jams preserved.".into(),
        });
        let html = render_page(&m, &c);
        assert!(html.contains(r#"<a class="symbol-link" href="https://example.org/legal/powr.broccoli-kopimi.pdf" aria-label="Kopimi legal notice">"#));
        // The Kopimi triangle of `CopyrightLine` (repos/ui src/components/CopyrightLine.vue): keep the two in step.
        assert!(html.contains(r#"<path d="M12 4L22 23H2Z""#));
        assert!(html.contains("</a> 2026 Meddleware. All jams preserved.</small>"));
        assert!(!html.contains(" style="));
    }

    /// Known hosts get their icon, a host that merely ends in a known name does not, and an email link gets the mail icon.
    #[test]
    fn guesses_icons_by_host() {
        assert_eq!(guess_icon("https://www.youtube.com/@x"), Icon::Youtube);
        assert_eq!(guess_icon("https://evilgithub.com/"), Icon::Link);
        assert_eq!(guess_icon("mailto:a@example.org"), Icon::Mail);
    }
}
