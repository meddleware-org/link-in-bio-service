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
    pub css: String,
    pub js: String,
    pub icons: String,
}

/// The page's picture, already normalised (`link-in-bio-assets`).
#[derive(Debug, Clone)]
pub struct Avatar {
    /// Absolute URL (link previews and other software need one).
    pub url: String,
    /// The same file as a root-relative path (what the page itself loads, so it works on any host).
    pub path: String,
    pub width: u32,
    pub height: u32,
    pub mime: &'static str,
}

#[derive(Debug, Clone)]
pub struct FooterLink {
    pub text: String,
    pub url: String,
}

#[derive(Debug, Clone, Default)]
pub struct Footer {
    /// "Made with …" on tenant pages (entitlement-controlled).
    pub attribution: Option<FooterLink>,
    /// The account-free report form for this page (tenant pages).
    pub report_url: Option<String>,
    /// The operator's own footer links (legal notice, licence).
    pub links: Vec<FooterLink>,
    /// A short line of text, for example the rights statement.
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PageContext {
    /// The page's own absolute URL, with a trailing slash.
    pub canonical: String,
    pub assets: AssetUrls,
    pub avatar: Option<Avatar>,
    pub owner: Owner,
    pub footer: Footer,
    /// Favicons: the brand set for the operator's page; the avatar otherwise.
    pub brand_icons: bool,
    /// Sui explorer origin for support addresses (`https://suivision.xyz`).
    pub explorer: String,
    /// The Profile Links document (`/links.json`) and the ActivityPub actor, when served.
    pub linkset_url: Option<String>,
    pub actor_url: Option<String>,
    /// Put the icon sprite inside the page (the editor's sandboxed preview cannot load an external sprite).
    pub inline_sprite: bool,
}

pub fn render_page(m: &Manifest, cx: &PageContext) -> String {
    page(m, cx).into_string()
}

fn page(m: &Manifest, cx: &PageContext) -> Markup {
    let t = &m.theme;
    let id = &m.identity;
    let description = id.bio.clone().unwrap_or_else(|| format!("Links from {}", id.display_name));
    let color_scheme = match t.color_mode {
        ColorMode::System => "light dark",
        ColorMode::Light => "light",
        ColorMode::Dark => "dark",
    };
    let season = (t.season != Season::None).then(|| t.season.as_str());
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
                @if !m.meta.indexable { meta name="robots" content="noindex"; }
                link rel="canonical" href=(cx.canonical);
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
                meta name="twitter:card" content="summary";
                meta name="twitter:title" content=(id.display_name);
                meta name="twitter:description" content=(description);
                @if let Some(a) = &cx.avatar {
                    meta name="twitter:image" content=(a.url);
                    meta name="twitter:image:alt" content=(format!("Picture of {}", id.display_name));
                }
                link rel="stylesheet" href=(cx.assets.css);
                @if cx.brand_icons {
                    link rel="icon" href="/favicon.ico" sizes="32x32";
                    link rel="icon" href="/favicon.svg" type="image/svg+xml";
                    link rel="apple-touch-icon" href="/apple-touch-icon.png";
                    link rel="manifest" href="/site.webmanifest";
                } @else if let Some(a) = &cx.avatar {
                    link rel="icon" href=(a.path) type=(a.mime);
                }
                @if let Some(l) = &cx.linkset_url {
                    link rel="linkset" href=(l) type="application/linkset+json";
                }
                @if let Some(a) = &cx.actor_url {
                    link rel="alternate" href=(a) type="application/activity+json";
                }
                // JSON-LD is a data block: browsers never execute it, and `<` is escaped so it cannot close the element.
                script type="application/ld+json" { (PreEscaped(crate::interop::json_ld_for_html(m, cx))) }
                script type="module" src=(cx.assets.js) {}
            }
            body {
                @if cx.inline_sprite { div class="sprite" hidden { (PreEscaped(crate::icons::SPRITE)) } }
                main class="page h-card" {
                    header class="profile" {
                        @if let Some(a) = &cx.avatar {
                            img class="avatar u-photo" src=(a.path) alt="" width=(a.width) height=(a.height) decoding="async";
                        }
                        h1 class="name p-name" { (id.display_name) }
                        @if let Some(p) = &id.pronouns { p class="pronouns" { (p) } }
                        @if let Some(b) = &id.bio { p class="bio p-note" { (b) } }
                        p class="address" {
                            a class="u-url u-uid" href=(cx.canonical) { (display_url(&cx.canonical)) }
                        }
                    }
                    @if m.visible_links().next().is_some() {
                        ul class="links" aria-label="Links" {
                            @for item in &m.items {
                                @match item {
                                    Item::Link(l) => @if !l.hidden { li { (link(l, cx)) } },
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
                    @if let Some(c) = &m.cta {
                        aside class="cta" aria-labelledby="cta-title" {
                            h2 id="cta-title" { (c.title) }
                            @if let Some(d) = &c.description { p { (d) } }
                            p { a class="button" href=(c.url) { (c.action.as_deref().unwrap_or("Find out more")) } }
                        }
                    }
                }
                footer class="site-footer" {
                    // Only a page that follows the visitor's device lets the visitor choose; a fixed mode is the owner's choice.
                    @if t.color_mode == ColorMode::System { fieldset class="mode" hidden {
                        legend { "Colour" }
                        button type="button" data-mode="light" aria-pressed="false" { "Light" }
                        button type="button" data-mode="dark" aria-pressed="false" { "Dark" }
                        button type="button" data-mode="system" aria-pressed="false" { "System" }
                    } }
                    @if let Some(r) = &cx.footer.report_url { p { a href=(r) { "Report this page" } } }
                    @if let Some(a) = &cx.footer.attribution { p { "Made with " a href=(a.url) { (a.text) } } }
                    @if !cx.footer.links.is_empty() {
                        ul class="footer-links" {
                            @for l in &cx.footer.links { li { a href=(l.url) { (l.text) } } }
                        }
                    }
                    @if let Some(n) = &cx.footer.note { p class="note" { (n) } }
                }
            }
        }
    }
}

fn link(l: &Link, cx: &PageContext) -> Markup {
    let rel = if l.identity { "me noopener noreferrer" } else { "noopener noreferrer" };
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
    known.iter().find(|(h, _)| host == *h || host.ends_with(&format!(".{h}"))).map(|(_, i)| *i).unwrap_or(Icon::Link)
}

/// `https://example.org/` → `example.org`.
pub fn display_url(url: &str) -> String {
    url.trim_start_matches("https://").trim_end_matches('/').to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::{ParseOptions, parse};

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

    #[test]
    fn guesses_icons_by_host() {
        assert_eq!(guess_icon("https://www.youtube.com/@x"), Icon::Youtube);
        assert_eq!(guess_icon("https://evilgithub.com/"), Icon::Link);
        assert_eq!(guess_icon("mailto:a@example.org"), Icon::Mail);
    }
}
