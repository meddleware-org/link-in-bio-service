//! The theme: a constrained set of options taken from the design tokens, never free CSS. Every combination is checked
//! for contrast in every colour mode it can show (text 7:1, the WCAG AAA level; interface edges 3:1), and a failing
//! combination is refused with a message that names the fix.

use serde::Serialize;

use crate::tokens::{Mode, Rgb, Tokens};

/// Minimum contrast for text (WCAG 1.4.6, AAA).
pub const TEXT_MIN: f64 = 7.0;
/// Minimum contrast for interface edges and focus indicators (WCAG 1.4.11).
pub const UI_MIN: f64 = 3.0;

macro_rules! options {
    ($(#[$m:meta])* $name:ident { $($var:ident => $s:literal),+ $(,)? } default $def:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name { $($var),+ }
        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$var),+];
            pub fn as_str(self) -> &'static str { match self { $($name::$var => $s),+ } }
            pub fn parse(s: &str) -> Option<Self> { match s { $($s => Some($name::$var),)+ _ => None } }
            pub fn names() -> Vec<&'static str> { Self::ALL.iter().map(|v| v.as_str()).collect() }
        }
        impl Default for $name { fn default() -> Self { $name::$def } }
        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { s.serialize_str(self.as_str()) }
        }
    };
}

options!(
    /// Which colour mode the page shows; `system` follows the visitor's device.
    ColorMode { System => "system", Light => "light", Dark => "dark" } default System);
options!(
    /// A fixed seasonal palette from design-tokens, or none.
    Season { None => "none", Spring => "spring", Summer => "summer", Autumn => "autumn", Winter => "winter" } default None);
options!(
    /// The accent hue: the season's accent, or one of the palette's functional and earth hues.
    Accent {
        Season => "season", Red => "red", Orange => "orange", Yellow => "yellow", Green => "green", Blue => "blue",
        Terracotta => "terracotta", Moss => "moss", Slate => "slate",
    } default Season);
options!(Buttons { Filled => "filled", Outline => "outline", Plain => "plain" } default Outline);
options!(Radius { Xs => "xs", Sm => "sm", Md => "md", Lg => "lg" } default Md);
options!(Density { Comfortable => "comfortable", Compact => "compact" } default Comfortable);
options!(Layout { List => "list", Cards => "cards" } default List);
options!(
    /// System font stacks only: no web fonts are ever loaded.
    Font { Sans => "sans", Serif => "serif", Rounded => "rounded", Mono => "mono" } default Sans);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Theme {
    pub color_mode: ColorMode,
    pub season: Season,
    pub accent: Accent,
    pub buttons: Buttons,
    pub radius: Radius,
    pub density: Density,
    pub layout: Layout,
    pub font: Font,
}

impl ColorMode {
    /// The modes a page in this colour mode can be seen in.
    pub fn modes(self) -> &'static [Mode] {
        match self {
            ColorMode::System => &Mode::ALL,
            ColorMode::Light => &[Mode::Light],
            ColorMode::Dark => &[Mode::Dark],
        }
    }
}

/// The accent colours chosen for one mode, and the contrast they reach.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    #[serde(serialize_with = "ser_rgb")]
    pub accent: Rgb,
    /// Text drawn on the accent (filled buttons).
    #[serde(serialize_with = "ser_rgb")]
    pub on_accent: Rgb,
    /// The lowest text contrast this combination produces.
    pub text_ratio: f64,
}

fn ser_rgb<S: serde::Serializer>(c: &Rgb, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&c.hex())
}

/// The candidate shades of a hue, in order of preference per mode (light pages prefer the 500/600 stops, dark
/// pages the 300/400 stops, as design-tokens' own roles do).
fn candidates(t: &Tokens, accent: Accent, season: Season, mode: Mode) -> Vec<(Rgb, Option<Rgb>)> {
    if accent == Accent::Season {
        let pair = match season {
            Season::None => (t.role(mode, "accent"), t.role(mode, "accent-contrast")),
            s => t.season_accents[s.as_str()][&mode],
        };
        return vec![(pair.0, Some(pair.1))];
    }
    let ramp = &t.ramps[accent.as_str()];
    let order: &[&str] = match mode {
        Mode::Light => &["500", "600", "400", "300"],
        Mode::Dark => &["300", "400", "500", "600"],
    };
    order.iter().filter_map(|s| ramp.get(*s)).map(|c| (*c, None)).collect()
}

/// Picks the accent for one mode, or returns the best contrast reached when nothing passes.
pub fn resolve_mode(accent: Accent, buttons: Buttons, season: Season, mode: Mode) -> Result<Resolved, f64> {
    let t = Tokens::get();
    let canvases = ["bg", "surface", "lift"].map(|r| t.role(mode, r));
    let label_candidates = [t.ramps["neutral"]["000"], t.ramps["neutral"]["800"], t.ramps["neutral"]["950"]];
    let mut best = 0.0_f64;
    for (shade, fixed_on) in candidates(t, accent, season, mode) {
        let outcome = match buttons {
            Buttons::Filled => {
                // Label on the fill. A season fixes its own contrast colour; a hue takes the best neutral.
                let ons: Vec<Rgb> = match fixed_on {
                    Some(c) => vec![c],
                    None => label_candidates.to_vec(),
                };
                let (on, ratio) = ons
                    .iter()
                    .map(|c| (*c, c.contrast(shade)))
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .unwrap_or((label_candidates[0], 0.0));
                (ratio, on)
            }
            Buttons::Outline | Buttons::Plain => {
                // The accent is the text colour (and, for outline, the edge) on every canvas the page uses.
                let ratio = canvases.iter().map(|c| c.contrast(shade)).fold(f64::INFINITY, f64::min);
                (ratio, fixed_on.unwrap_or(label_candidates[0]))
            }
        };
        best = best.max(outcome.0);
        if outcome.0 >= TEXT_MIN {
            return Ok(Resolved { accent: shade, on_accent: outcome.1, text_ratio: outcome.0 });
        }
    }
    Err(best)
}

/// Why a theme was refused, in plain words, with the fix.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ContrastFailure {
    pub mode: &'static str,
    pub best_ratio: f64,
    pub message: String,
}

/// Checks a whole theme in every mode its colour mode can show.
pub fn check(theme: &Theme) -> Result<Vec<(Mode, Resolved)>, Vec<ContrastFailure>> {
    let mut ok = Vec::new();
    let mut failures = Vec::new();
    for &mode in theme.color_mode.modes() {
        match resolve_mode(theme.accent, theme.buttons, theme.season, mode) {
            Ok(r) => ok.push((mode, r)),
            Err(best) => failures.push(ContrastFailure {
                mode: mode.as_str(),
                best_ratio: (best * 100.0).round() / 100.0,
                message: fix_message(theme, mode, best),
            }),
        }
    }
    if failures.is_empty() { Ok(ok) } else { Err(failures) }
}

fn fix_message(theme: &Theme, mode: Mode, best: f64) -> String {
    let what = match theme.accent {
        Accent::Season if theme.season == Season::None => "The default accent".to_string(),
        Accent::Season => format!("The {} accent", theme.season.as_str()),
        a => format!("The {} accent", a.as_str()),
    };
    let alternatives: Vec<&str> = Buttons::ALL
        .iter()
        .filter(|b| **b != theme.buttons && resolve_mode(theme.accent, **b, theme.season, mode).is_ok())
        .map(|b| b.as_str())
        .collect();
    let fix = if alternatives.is_empty() {
        "choose another accent".to_string()
    } else {
        format!("choose {} buttons or another accent", alternatives.join(" or "))
    };
    let only = match (theme.color_mode, mode) {
        (ColorMode::System, Mode::Dark) => ", or show the page in light mode only",
        (ColorMode::System, Mode::Light) => ", or show the page in dark mode only",
        _ => "",
    };
    format!(
        "{what} with {} buttons is too faint in {} mode ({best:.1}:1; text needs 7:1): {fix}{only}.",
        theme.buttons.as_str(),
        mode.as_str()
    )
}

/// One row of the option table the editor shows: whether the combination passes in each mode.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OptionRow {
    pub accent: Accent,
    pub buttons: Buttons,
    pub season: Season,
    pub light: Option<Resolved>,
    pub dark: Option<Resolved>,
}

/// Every accent × buttons × season combination, resolved in both modes.
pub fn option_table() -> Vec<OptionRow> {
    let mut rows = Vec::new();
    for &season in Season::ALL {
        for &accent in Accent::ALL {
            for &buttons in Buttons::ALL {
                rows.push(OptionRow {
                    accent,
                    buttons,
                    season,
                    light: resolve_mode(accent, buttons, season, Mode::Light).ok(),
                    dark: resolve_mode(accent, buttons, season, Mode::Dark).ok(),
                });
            }
        }
    }
    rows
}

/// The CSS that turns `data-accent`/`data-buttons` (per mode) into `--lib-accent`/`--lib-on-accent`. A combination
/// that fails in a mode gets no rule for that mode; the parser refuses such a theme, so no page needs one.
pub fn accent_css() -> String {
    let mut light = String::new();
    let mut dark = String::new();
    let mut system = String::new();
    for row in option_table() {
        // A season-coloured accent follows the season attribute; rules for hues do not depend on the season.
        if row.accent != Accent::Season && row.season != Season::None {
            continue;
        }
        let season_sel = if row.accent == Accent::Season && row.season != Season::None {
            format!("[data-season=\"{}\"]", row.season.as_str())
        } else if row.accent == Accent::Season {
            ":not([data-season])".to_string()
        } else {
            String::new()
        };
        let sel =
            format!("[data-accent=\"{}\"][data-buttons=\"{}\"]{season_sel}", row.accent.as_str(), row.buttons.as_str());
        if let Some(r) = row.light {
            light.push_str(&format!(
                ":root{sel}{{--lib-accent:{};--lib-on-accent:{}}}\n",
                r.accent.hex(),
                r.on_accent.hex()
            ));
        }
        if let Some(r) = row.dark {
            let decl = format!("{{--lib-accent:{};--lib-on-accent:{}}}\n", r.accent.hex(), r.on_accent.hex());
            dark.push_str(&format!(":root[data-theme=\"dark\"]{sel}{decl}"));
            system.push_str(&format!(":root[data-theme=\"system\"]{sel}{decl}"));
        }
    }
    format!("{light}{dark}@media (prefers-color-scheme: dark) {{\n{system}}}\n")
}

/// Every rule of the token files that applies to `[data-theme="dark"]`, repeated for `[data-theme="system"]` inside a
/// `prefers-color-scheme: dark` query, so the system mode works without JavaScript.
pub fn system_mode_css(token_css: &[&str]) -> String {
    let mut out = String::from("@media (prefers-color-scheme: dark) {\n");
    for css in token_css {
        for (selector, body) in crate::tokens::css_rules(css) {
            let selectors: Vec<String> = selector
                .split(',')
                .map(str::trim)
                .filter(|s| s.contains("[data-theme=\"dark\"]"))
                .map(|s| s.replace("[data-theme=\"dark\"]", "[data-theme=\"system\"]"))
                .collect();
            if !selectors.is_empty() {
                out.push_str(&format!("{} {{{}}}\n", selectors.join(",\n"), body.trim_end()));
            }
        }
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_theme_passes_in_both_modes() {
        assert!(check(&Theme::default()).is_ok());
    }

    #[test]
    fn every_passing_row_reaches_aaa_and_every_failing_row_says_how_to_fix_it() {
        for row in option_table() {
            for (mode, r) in [(Mode::Light, row.light), (Mode::Dark, row.dark)] {
                match r {
                    Some(r) => assert!(r.text_ratio >= TEXT_MIN, "{row:?} {mode:?}"),
                    None => {
                        let theme = Theme {
                            color_mode: if mode == Mode::Light { ColorMode::Light } else { ColorMode::Dark },
                            accent: row.accent,
                            buttons: row.buttons,
                            season: row.season,
                            ..Theme::default()
                        };
                        let f = check(&theme).unwrap_err();
                        assert!(f[0].message.contains("choose"), "{}", f[0].message);
                    }
                }
            }
        }
    }

    #[test]
    fn each_hue_has_at_least_one_passing_button_style_per_mode() {
        for &accent in Accent::ALL {
            for mode in Mode::ALL {
                assert!(
                    Buttons::ALL.iter().any(|b| resolve_mode(accent, *b, Season::None, mode).is_ok()),
                    "{accent:?} has no usable style in {mode:?}"
                );
            }
        }
    }

    #[test]
    fn system_css_mirrors_the_dark_rules() {
        let css = system_mode_css(&[crate::tokens::TOKENS_CSS, crate::tokens::SEASONS_CSS]);
        assert!(css.contains(":root[data-theme=\"system\"] {"));
        assert!(css.contains(":root[data-theme=\"system\"][data-season=\"winter\"]"));
        assert!(!css.contains(".dark"));
    }
}
