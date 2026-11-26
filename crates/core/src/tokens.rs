//! The design tokens this service is built against: a vendored copy of `@meddleware/design-tokens`
//! (`tokens/`, refreshed and checked by `page/scripts/sync-tokens.mjs`). Parsed once, at first use.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The colour ramps and the semantic roles, as the design-tokens package publishes them.
pub const TOKENS_JSON: &str = include_str!("../tokens/tokens.json");
/// The tokens' stylesheet: custom properties for light and dark.
pub const TOKENS_CSS: &str = include_str!("../tokens/tokens.css");
/// The seasonal palettes' stylesheet.
pub const SEASONS_CSS: &str = include_str!("../tokens/seasons.css");

/// sRGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Parse `#rgb` or `#rrggbb`; anything else is `None`.
    pub fn parse(hex: &str) -> Option<Self> {
        let h = hex.trim().strip_prefix('#')?;
        // A three-digit colour is expanded by doubling each digit.
        let h = match h.len() {
            3 => h.chars().flat_map(|c| [c, c]).collect::<String>(),
            6 => h.to_string(),
            _ => return None,
        };
        // The six digits are one number; its bytes are the three channels.
        let v = u32::from_str_radix(&h, 16).ok()?;
        Some(Self((v >> 16) as u8, (v >> 8) as u8, v as u8))
    }

    /// The colour as lower-case `#rrggbb`.
    pub fn hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.0, self.1, self.2)
    }

    /// WCAG 2.x relative luminance.
    pub fn luminance(self) -> f64 {
        /// One channel, linearised as WCAG defines it.
        fn ch(c: u8) -> f64 {
            let s = f64::from(c) / 255.0;
            if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
        }
        0.2126 * ch(self.0) + 0.7152 * ch(self.1) + 0.0722 * ch(self.2)
    }

    /// WCAG 2.x contrast ratio (1–21).
    pub fn contrast(self, other: Rgb) -> f64 {
        let (a, b) = (self.luminance(), other.luminance());
        // The ratio is lighter over darker, each with 0.05 added, as WCAG defines it.
        let (hi, lo) = if a > b { (a, b) } else { (b, a) };
        (hi + 0.05) / (lo + 0.05)
    }
}

/// Colour mode a value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mode {
    /// The light colour mode.
    Light,
    /// The dark colour mode.
    Dark,
}

impl Mode {
    /// Both modes.
    pub const ALL: [Mode; 2] = [Mode::Light, Mode::Dark];
    /// The mode's name, as used in the token files.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Light => "light",
            Mode::Dark => "dark",
        }
    }
}

/// `season -> mode -> (accent, accent-contrast)`.
pub type SeasonAccents = BTreeMap<String, BTreeMap<Mode, (Rgb, Rgb)>>;

/// What the theme model needs from the tokens.
#[derive(Debug)]
pub struct Tokens {
    /// `ramp -> shade -> colour` for every named ramp (`red`, `moss`, `neutral`, …).
    pub ramps: BTreeMap<String, BTreeMap<String, Rgb>>,
    /// Semantic roles per mode (`bg`, `surface`, `text`, `accent`, …).
    pub semantic: BTreeMap<Mode, BTreeMap<String, Rgb>>,
    /// `season -> mode -> (accent, accent-contrast)`.
    pub season_accents: SeasonAccents,
}

impl Tokens {
    /// The vendored tokens, parsed on first use; a parse failure is a build-time mistake in the vendored files, so it panics.
    pub fn get() -> &'static Tokens {
        /// The one parsed copy.
        static T: OnceLock<Tokens> = OnceLock::new();
        T.get_or_init(|| Tokens::parse(TOKENS_JSON, SEASONS_CSS).expect("vendored design tokens parse"))
    }

    /// The colour of a semantic role (`bg`, `surface`, `text`, …) in a mode. Panics for an unknown role, which is a programming error: the roles are fixed by the token files.
    pub fn role(&self, mode: Mode, role: &str) -> Rgb {
        self.semantic[&mode][role]
    }

    /// Read the ramps (primary, brand and secondary hues, then the neutral ramp), the semantic roles of both modes and the season accents.
    pub fn parse(json: &str, seasons_css: &str) -> Result<Tokens, String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let mut ramps = BTreeMap::new();
        // The hue groups of the token file; each holds named ramps.
        for group in ["primary", "brand", "secondary"] {
            let obj = v[group].as_object().ok_or(format!("tokens.json: {group}"))?;
            for (name, shades) in obj {
                // A ramp is `shade -> colour`; a legacy swatch is a single colour (stored as shade "500").
                let map = match shades {
                    serde_json::Value::String(c) => {
                        let rgb = Rgb::parse(c).ok_or(format!("tokens.json: bad colour {name}"))?;
                        BTreeMap::from([("500".to_string(), rgb)])
                    }
                    other => shade_map(other)?,
                };
                ramps.insert(name.clone(), map);
            }
        }
        // The neutral ramp is a group of its own.
        ramps.insert("neutral".into(), shade_map(&v["neutral"])?);
        let mut semantic = BTreeMap::new();
        for mode in Mode::ALL {
            semantic.insert(mode, shade_map(&v["semantic"][mode.as_str()])?);
        }
        // Season accents are read from the seasons stylesheet, resolving their `var(--mw-…)` references against the ramps.
        let season_accents = parse_seasons(seasons_css, &ramps)?;
        Ok(Tokens { ramps, semantic, season_accents })
    }
}

/// Read an object of `shade -> hex colour` into colours.
fn shade_map(v: &serde_json::Value) -> Result<BTreeMap<String, Rgb>, String> {
    let obj = v.as_object().ok_or("tokens.json: expected an object")?;
    obj.iter()
        .map(|(k, c)| {
            let rgb = c.as_str().and_then(Rgb::parse).ok_or(format!("tokens.json: bad colour {k}"))?;
            Ok((k.clone(), rgb))
        })
        .collect()
}

/// Resolves `var(--mw-<ramp>-<shade>)` or a literal hex colour.
fn resolve(value: &str, ramps: &BTreeMap<String, BTreeMap<String, Rgb>>) -> Option<Rgb> {
    let value = value.trim();
    if let Some(inner) = value.strip_prefix("var(--mw-").and_then(|s| s.strip_suffix(')')) {
        let (ramp, shade) = inner.rsplit_once('-')?;
        return ramps.get(ramp)?.get(shade).copied();
    }
    Rgb::parse(value)
}

/// Reads the `--season-accent` and `--season-accent-contrast` values of every season block in seasons.css.
fn parse_seasons(css: &str, ramps: &BTreeMap<String, BTreeMap<String, Rgb>>) -> Result<SeasonAccents, String> {
    let mut out: BTreeMap<String, BTreeMap<Mode, (Rgb, Rgb)>> = BTreeMap::new();
    for (selector, body) in css_rules(css) {
        // The first selector of a rule says which season and mode it is for.
        let first = selector.split(',').next().unwrap_or("").trim();
        let Some(season) = first.split("data-season=\"").nth(1).and_then(|s| s.split('"').next()) else { continue };
        // Rules without the dark attribute are the light mode's.
        let mode = if first.contains("data-theme=\"dark\"") { Mode::Dark } else { Mode::Light };
        let decl = |name: &str| {
            body.split(';').find_map(|d| {
                let (k, v) = d.split_once(':')?;
                (k.trim() == name).then(|| v.trim().to_string())
            })
        };
        let accent = decl("--season-accent").and_then(|v| resolve(&v, ramps));
        let contrast = decl("--season-accent-contrast").and_then(|v| resolve(&v, ramps));
        let (Some(a), Some(c)) = (accent, contrast) else {
            return Err(format!("seasons.css: {season} ({}) lacks a resolvable accent", mode.as_str()));
        };
        out.entry(season.to_string()).or_default().insert(mode, (a, c));
    }
    Ok(out)
}

/// Splits CSS into `(selector, body)` pairs, ignoring comments and at-rules' nesting (the token files are flat).
pub fn css_rules(css: &str) -> Vec<(String, String)> {
    // Comments are removed first so a brace inside one cannot confuse the split.
    let css = strip_comments(css);
    let mut out = Vec::new();
    let mut rest = css.as_str();
    while let Some(open) = rest.find('{') {
        let selector = rest[..open].trim().to_string();
        let Some(close) = rest[open..].find('}') else { break };
        let body = rest[open + 1..open + close].to_string();
        out.push((selector, body));
        rest = &rest[open + close + 1..];
    }
    out
}

/// Remove `/* … */` comments; an unterminated comment drops the rest of the text.
pub fn strip_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Unit tests for the colour maths and the vendored tokens.
#[cfg(test)]
mod tests {
    use super::*;

    /// Black on white is 21:1, and mid grey on white matches the published WCAG figure.
    #[test]
    fn contrast_matches_wcag_reference_values() {
        let white = Rgb(255, 255, 255);
        let black = Rgb(0, 0, 0);
        assert!((white.contrast(black) - 21.0).abs() < 1e-9);
        assert!((Rgb::parse("#777").unwrap().contrast(white) - 4.478).abs() < 0.01);
    }

    /// The vendored files parse, the light background is the expected colour, and every season has a light and a dark accent.
    #[test]
    fn vendored_tokens_parse() {
        let t = Tokens::get();
        assert_eq!(t.role(Mode::Light, "bg"), Rgb::parse("#f7f4f1").unwrap());
        assert!(t.ramps["red"].contains_key("600"));
        for s in ["spring", "summer", "autumn", "winter"] {
            assert_eq!(t.season_accents[s].len(), 2, "{s} has light and dark");
        }
    }
}
