//! Link icons: a fixed set drawn from one SVG sprite (`assets/icons.svg`, built by `page/scripts/build-icons.mjs` from
//! Simple Icons, CC0-1.0, and Lucide, ISC). Icons are names, never URLs, so a page cannot load an image from elsewhere.

use serde::Serialize;

/// Declare the icon set once and derive everything else from it: the `Icon` enum, the list of all icons, each icon's name, and parsing a name back. Adding an icon is one line here plus its symbol in the sprite.
macro_rules! icons {
    ($($var:ident => $s:literal),+ $(,)?) => {
        /// One icon a link may show, named by what it stands for (a service, or a kind of link).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Icon {
            $(
                #[doc = concat!("The `", $s, "` icon.")]
                $var
            ),+
        }
        impl Icon {
            /// Every icon, in declaration order.
            pub const ALL: &'static [Icon] = &[$(Icon::$var),+];
            /// The icon's name, which is also its symbol id in the sprite and its value in a page document.
            pub fn as_str(self) -> &'static str { match self { $(Icon::$var => $s),+ } }
            /// The icon with this name, or `None` for any name outside the set.
            pub fn parse(s: &str) -> Option<Icon> { match s { $($s => Some(Icon::$var),)+ _ => None } }
            /// Every icon name, for the editor and the schema.
            pub fn names() -> Vec<&'static str> { Self::ALL.iter().map(|i| i.as_str()).collect() }
        }
    };
}

// The icon set: each variant with the name it has in documents and in the sprite (services first, then kinds of link).
icons! {
    X => "x", Mastodon => "mastodon", Bluesky => "bluesky", Github => "github", Gitlab => "gitlab",
    Codeberg => "codeberg", Huggingface => "huggingface", Youtube => "youtube", Matrix => "matrix",
    Discord => "discord", Telegram => "telegram", Nostr => "nostr", Instagram => "instagram", Tiktok => "tiktok",
    Twitch => "twitch", Reddit => "reddit", Sui => "sui", Npm => "npm",
    Link => "link", Mail => "mail", Website => "website", Docs => "docs", Code => "code", Package => "package",
    Rss => "rss", Heart => "heart",
}

impl Serialize for Icon {
    // An icon is written as its name.
    /// An icon is written as its name.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// The sprite, embedded in the binary and served under a content hash.
pub const SPRITE: &str = include_str!("../../../assets/icons.svg");
