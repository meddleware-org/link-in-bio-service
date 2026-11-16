//! The page's static files, embedded in the binary and served under content-hashed names (`/_/page.<hash>.css`), so
//! they can be cached for a year and a release can never mix an old stylesheet with new markup.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::tokens::{SEASONS_CSS, TOKENS_CSS};

const PAGE_CSS: &str = include_str!("../../../page/src/page.css");
const ENHANCE_JS: &str = include_str!("../../../page/src/enhance.js");
pub const SPEC_PROFILE_LINKS: &str = include_str!("../../../spec/profile-links-v1.md");

pub const FAVICON_SVG: &[u8] = include_bytes!("../../../assets/brand/favicon.svg");
pub const FAVICON_ICO: &[u8] = include_bytes!("../../../assets/brand/favicon.ico");
pub const APPLE_TOUCH_ICON: &[u8] = include_bytes!("../../../assets/brand/apple-touch-icon.png");
pub const ICON_192: &[u8] = include_bytes!("../../../assets/brand/icon-192.png");
pub const ICON_512: &[u8] = include_bytes!("../../../assets/brand/icon-512.png");

/// One embedded file with its hashed path.
#[derive(Debug)]
pub struct Asset {
    pub path: String,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Asset {
    fn new(stem: &str, ext: &str, content_type: &'static str, body: Vec<u8>) -> Self {
        let digest = Sha256::digest(&body);
        let hash = hex::encode(&digest[..6]);
        Self { path: format!("/_/{stem}.{hash}.{ext}"), content_type, body }
    }
}

#[derive(Debug)]
pub struct Bundle {
    pub css: Asset,
    pub js: Asset,
    pub icons: Asset,
}

impl Bundle {
    pub fn get() -> &'static Bundle {
        static B: OnceLock<Bundle> = OnceLock::new();
        B.get_or_init(|| Bundle {
            css: Asset::new("page", "css", "text/css; charset=utf-8", page_css().into_bytes()),
            js: Asset::new("enhance", "js", "text/javascript; charset=utf-8", ENHANCE_JS.as_bytes().to_vec()),
            icons: Asset::new("icons", "svg", "image/svg+xml", crate::icons::SPRITE.as_bytes().to_vec()),
        })
    }

    pub fn urls(&self) -> crate::render::AssetUrls {
        crate::render::AssetUrls {
            css: self.css.path.clone(),
            js: self.js.path.clone(),
            icons: self.icons.path.clone(),
        }
    }

    pub fn find(&self, path: &str) -> Option<&Asset> {
        [&self.css, &self.js, &self.icons].into_iter().find(|a| a.path == path)
    }
}

/// The whole stylesheet: the design tokens, the seasons, the system colour mode (generated), the accent choices
/// (generated from the contrast table) and the page's own rules.
pub fn page_css() -> String {
    format!(
        "/* Link in Bio page. Design tokens: @meddleware/design-tokens (0BSD). */\n{TOKENS_CSS}\n{SEASONS_CSS}\n{}\n{}\n{PAGE_CSS}",
        crate::theme::system_mode_css(&[TOKENS_CSS, SEASONS_CSS]),
        crate::theme::accent_css(),
    )
}

/// `site.webmanifest` for the operator's brand icons.
pub fn webmanifest(name: &str) -> String {
    let bg = crate::tokens::Tokens::get().role(crate::tokens::Mode::Dark, "bg").hex();
    serde_json::json!({
        "name": name,
        "short_name": name,
        "icons": [
            { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
            { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" }
        ],
        "theme_color": bg,
        "background_color": bg,
        "display": "browser"
    })
    .to_string()
}

/// The Profile Links specification as an HTML page (served at the profile URI so the URI dereferences).
pub fn spec_html() -> String {
    let mut body = String::new();
    pulldown_cmark::html::push_html(&mut body, pulldown_cmark::Parser::new(SPEC_PROFILE_LINKS));
    let css = &Bundle::get().css.path;
    format!(
        "<!doctype html><html lang=\"en\" data-theme=\"system\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Profile Links v1</title><link rel=\"stylesheet\" href=\"{css}\"></head><body><main class=\"spec\">{body}</main></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashed_paths_are_stable_and_distinct() {
        let b = Bundle::get();
        assert!(b.css.path.starts_with("/_/page.") && b.css.path.ends_with(".css"));
        assert_ne!(b.css.path, b.js.path);
        assert!(b.find(&b.icons.path).is_some());
        assert!(b.find("/_/page.css").is_none());
    }

    #[test]
    fn stylesheet_has_every_part() {
        let css = page_css();
        assert!(css.contains("--mw-terracotta-500"));
        assert!(css.contains("[data-theme=\"system\"]"));
        assert!(css.contains("--lib-accent"));
        assert!(!css.contains("@import"), "no external stylesheet is ever loaded");
        assert!(!css.contains("url(http"), "no external resource is ever loaded");
    }
}
