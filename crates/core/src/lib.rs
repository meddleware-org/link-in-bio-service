//! `link-in-bio-core`: the one implementation of what a Link in Bio page is.
//!
//! - [`manifest`]: the page document (schema 1) and its hand-written parser, the trust boundary;
//! - [`text`], [`safe_url`]: the rules for every string and every link target;
//! - [`theme`], [`tokens`]: the constrained theme model, the contrast checks and the theme CSS, from design-tokens;
//! - [`render`]: the HTML page (works with scripts blocked);
//! - [`interop`]: Profile Links (RFC 9264), JSON-LD, WebFinger, ActivityPub actor, NIP-05, security.txt;
//! - [`assets`]: the stylesheet, script and sprite, embedded and content-addressed;
//! - [`limits`], [`icons`].
//!
//! Pure: no I/O, no async runtime, no clock.

/// The embedded stylesheet, script and sprite, served under content-hashed names.
pub mod assets;
/// The fixed set of link icons and the sprite they are drawn from.
pub mod icons;
/// The documents other software reads: Profile Links, JSON-LD, WebFinger, the ActivityPub actor, NIP-05 and security.txt.
pub mod interop;
/// The shared `Issue` type, a problem found in a page document.
mod issue;
/// The size and count limits that every page document is held to.
pub mod limits;
/// The page document, its hand-written parser and the trust boundary.
pub mod manifest;
/// The HTML renderer, the only code that makes a page.
pub mod render;
/// The rules for what a link may point at.
pub mod safe_url;
/// The rules for every string a person types into a page.
pub mod text;
/// The constrained theme model and its contrast checks, and the theme CSS.
pub mod theme;
/// The design tokens, read from the vendored stylesheet.
pub mod tokens;

// The names most callers need, re-exported so they do not have to know which module holds them.
pub use issue::Issue;
pub use manifest::{Manifest, Owner, ParseOptions, Parsed, parse};
