//! The page's static files, embedded in the binary and served under content-hashed names (`/_/page.<hash>.css`), so
//! they can be cached for a year and a release can never mix an old stylesheet with new markup.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use crate::tokens::{SEASONS_CSS, TOKENS_CSS};

/// The page's own stylesheet rules, compiled into the binary from the file the browser tests also use.
const PAGE_CSS: &str = include_str!("../../../page/src/page.css");
/// The page's one script (the optional enhancements), compiled in from the same source file.
const ENHANCE_JS: &str = include_str!("../../../page/src/enhance.js");
/// The Profile Links specification, as Markdown, served at the profile URI so the URI dereferences.
pub const SPEC_PROFILE_LINKS: &str = include_str!("../../../spec/profile-links-v1.md");

/// The operator's favicon, an SVG.
pub const FAVICON_SVG: &[u8] = include_bytes!("../../../assets/brand/favicon.svg");
/// The same favicon as an ICO, for clients that do not read SVG.
pub const FAVICON_ICO: &[u8] = include_bytes!("../../../assets/brand/favicon.ico");
/// The icon iOS uses when a page is added to the home screen.
pub const APPLE_TOUCH_ICON: &[u8] = include_bytes!("../../../assets/brand/apple-touch-icon.png");
/// The 192-pixel icon named in the web app manifest.
pub const ICON_192: &[u8] = include_bytes!("../../../assets/brand/icon-192.png");
/// The 512-pixel icon named in the web app manifest.
pub const ICON_512: &[u8] = include_bytes!("../../../assets/brand/icon-512.png");

/// One embedded file with its hashed path.
#[derive(Debug)]
pub struct Asset {
    /// The content-hashed path the file is served at.
    pub path: String,
    /// The media type the file is served with.
    pub content_type: &'static str,
    /// The file's bytes.
    pub body: Vec<u8>,
}

impl Asset {
    /// Embed a file: its path is `/_/<stem>.<hash>.<ext>`, where the hash is the first six bytes of the SHA-256 of the body, so the path changes exactly when the content does.
    fn new(stem: &str, ext: &str, content_type: &'static str, body: Vec<u8>) -> Self {
        let digest = Sha256::digest(&body);
        let hash = hex::encode(&digest[..6]);
        Self { path: format!("/_/{stem}.{hash}.{ext}"), content_type, body }
    }
}

/// The three files every page links to, computed once.
#[derive(Debug)]
pub struct Bundle {
    /// The stylesheet.
    pub css: Asset,
    /// The enhancement script.
    pub js: Asset,
    /// The icon sprite.
    pub icons: Asset,
}

impl Bundle {
    /// The bundle, built on first use and shared after that.
    pub fn get() -> &'static Bundle {
        /// The one shared bundle.
        static B: OnceLock<Bundle> = OnceLock::new();
        B.get_or_init(|| Bundle {
            css: Asset::new("page", "css", "text/css; charset=utf-8", page_css().into_bytes()),
            js: Asset::new(
                "enhance",
                "js",
                "text/javascript; charset=utf-8",
                strip_js_comments(ENHANCE_JS).into_bytes(),
            ),
            icons: Asset::new("icons", "svg", "image/svg+xml", crate::icons::SPRITE.as_bytes().to_vec()),
        })
    }

    /// The paths to put in a page's head and sprite references.
    pub fn urls(&self) -> crate::render::AssetUrls {
        crate::render::AssetUrls {
            css: self.css.path.clone(),
            js: self.js.path.clone(),
            icons: self.icons.path.clone(),
        }
    }

    /// The embedded file served at a path, or `None` for any other path (so an unhashed or stale name is a 404).
    pub fn find(&self, path: &str) -> Option<&Asset> {
        [&self.css, &self.js, &self.icons].into_iter().find(|a| a.path == path)
    }
}

/// The whole stylesheet: the design tokens, the seasons, the system colour mode (generated), the accent choices
/// (generated from the contrast table) and the page's own rules.
pub fn page_css() -> String {
    format!(
        // The tokens come first so the page rules can use them; the generated parts sit between because they depend on the tokens.
        "/* Link in Bio page. Design tokens: @meddleware/design-tokens (0BSD). */\n{TOKENS_CSS}\n{SEASONS_CSS}\n{}\n{}\n{}",
        crate::theme::system_mode_css(&[TOKENS_CSS, SEASONS_CSS]),
        crate::theme::accent_css(),
        strip_css_comments(PAGE_CSS),
    )
}

/// The page's own source files are commented line by line (the documentation standard), but a visitor should not download
/// the comments: remove every `/* ... */` comment and the blank lines it leaves. The source holds no `/*` inside a string or
/// a `url()`; the test `shipped_files_carry_no_comments` fails if that ever stops being true.
fn strip_css_comments(src: &str) -> String {
    // The text outside comments, built up as the source is scanned.
    let mut out = String::with_capacity(src.len());
    // What is left to scan.
    let mut rest = src;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        // An unterminated comment swallows the rest of the file, as a browser would read it.
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => {
                rest = "";
            }
        }
    }
    out.push_str(rest);
    drop_blank_lines(&out)
}

/// The same for the script: remove lines that are wholly a `//` comment and every `/* ... */` block (the JSDoc blocks), and
/// the blank lines left over. The script keeps its comments on lines of their own, never after code, so nothing inside a
/// string or a regular expression can be mistaken for one; the test `shipped_files_carry_no_comments` enforces that.
fn strip_js_comments(src: &str) -> String {
    // The kept lines, in order.
    let mut out = String::with_capacity(src.len());
    // Whether the scan is inside a block comment.
    let mut in_block = false;
    for line in src.lines() {
        let t = line.trim_start();
        if in_block {
            // A block ends at its closing marker; the rest of that line is not code in this file's style.
            if t.contains("*/") {
                in_block = false;
            }
            continue;
        }
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("/*") {
            in_block = !t.contains("*/");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    drop_blank_lines(&out)
}

/// Drop lines that hold only white space and trailing white space, so removing a comment leaves no gap.
fn drop_blank_lines(src: &str) -> String {
    src.lines().map(str::trim_end).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n") + "\n"
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

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// Hashed paths have the expected shape, differ from each other and resolve; an unhashed path does not.
    #[test]
    fn hashed_paths_are_stable_and_distinct() {
        let b = Bundle::get();
        assert!(b.css.path.starts_with("/_/page.") && b.css.path.ends_with(".css"));
        assert_ne!(b.css.path, b.js.path);
        assert!(b.find(&b.icons.path).is_some());
        assert!(b.find("/_/page.css").is_none());
    }

    /// The files a visitor downloads carry none of the source's comments, and the stripping removes only comments.
    #[test]
    fn shipped_files_carry_no_comments() {
        let b = Bundle::get();
        let js = String::from_utf8(b.js.body.clone()).unwrap();
        assert!(!js.contains("//") && !js.contains("/*"), "a comment reached the shipped script");
        assert!(js.contains("localStorage") && js.contains("navigator.clipboard"), "the script's code is intact");
        let page_only = strip_css_comments(PAGE_CSS);
        assert!(!page_only.contains("/*") && !page_only.contains("*/"), "a comment reached the shipped rules");
        assert!(page_only.contains(".symbol-link") && page_only.contains("forced-colors"), "the rules are intact");
        assert_eq!(strip_css_comments("a{b:c}/* x */\n\n/* y\nz */d{e:f}"), "a{b:c}\nd{e:f}\n");
        assert_eq!(strip_js_comments("// x\nlet a = 1\n/** y\n * z */\nlet b = 2\n"), "let a = 1\nlet b = 2\n");
    }

    /// The stylesheet holds the tokens, the system colour mode and the accent choices, and loads nothing from elsewhere.
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
