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

pub mod assets;
pub mod icons;
pub mod interop;
mod issue;
pub mod limits;
pub mod manifest;
pub mod render;
pub mod safe_url;
pub mod text;
pub mod theme;
pub mod tokens;

pub use issue::Issue;
pub use manifest::{Manifest, Owner, ParseOptions, Parsed, parse};
