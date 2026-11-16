//! Link icons: a fixed set drawn from one SVG sprite (`assets/icons.svg`, built by `page/scripts/build-icons.mjs` from
//! Simple Icons, CC0-1.0, and Lucide, ISC). Icons are names, never URLs, so a page cannot load an image from elsewhere.

use serde::Serialize;

macro_rules! icons {
    ($($var:ident => $s:literal),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Icon { $($var),+ }
        impl Icon {
            pub const ALL: &'static [Icon] = &[$(Icon::$var),+];
            pub fn as_str(self) -> &'static str { match self { $(Icon::$var => $s),+ } }
            pub fn parse(s: &str) -> Option<Icon> { match s { $($s => Some(Icon::$var),)+ _ => None } }
            pub fn names() -> Vec<&'static str> { Self::ALL.iter().map(|i| i.as_str()).collect() }
        }
    };
}

icons! {
    X => "x", Mastodon => "mastodon", Bluesky => "bluesky", Github => "github", Gitlab => "gitlab",
    Codeberg => "codeberg", Huggingface => "huggingface", Youtube => "youtube", Matrix => "matrix",
    Discord => "discord", Telegram => "telegram", Nostr => "nostr", Instagram => "instagram", Tiktok => "tiktok",
    Twitch => "twitch", Reddit => "reddit", Sui => "sui", Npm => "npm",
    Link => "link", Mail => "mail", Website => "website", Docs => "docs", Code => "code", Package => "package",
    Rss => "rss", Heart => "heart",
}

impl Serialize for Icon {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The sprite, embedded in the binary and served under a content hash.
pub const SPRITE: &str = include_str!("../../../assets/icons.svg");
