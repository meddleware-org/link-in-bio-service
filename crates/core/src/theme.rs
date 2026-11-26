//! The theme: a constrained set of options taken from the design tokens, never free CSS. Every combination is checked
//! for contrast in every colour mode it can show (text 7:1, the WCAG AAA level; interface edges 3:1), and a failing
//! combination is refused with a message that names the fix.

use serde::Serialize;

use crate::tokens::{Mode, Rgb, Tokens};

/// Minimum contrast for text (WCAG 1.4.6, AAA).
pub const TEXT_MIN: f64 = 7.0;
/// Minimum contrast for interface edges and focus indicators (WCAG 1.4.11).
pub const UI_MIN: f64 = 3.0;

/// Declare one theme option: an enum whose variants are named by a fixed string, with its list of all values, its name,
/// parsing from a name, the names for the editor, a default, and serialisation as the name. A document can only ever
/// choose among these values, which is what keeps the theme from being free CSS.
macro_rules! options {
    ($(#[$m:meta])* $name:ident { $($var:ident => $s:literal),+ $(,)? } default $def:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $(
                #[doc = concat!("The `", $s, "` choice.")]
                $var
            ),+
        }
        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [$name] = &[$($name::$var),+];
            /// The value's name, as written in a page document and in the page's `data-*` attribute.
            pub fn as_str(self) -> &'static str { match self { $($name::$var => $s),+ } }
            /// The value with this name, or `None` for any name outside the set.
            pub fn parse(s: &str) -> Option<Self> { match s { $($s => Some($name::$var),)+ _ => None } }
            /// Every name, for the editor and for error messages that list the valid choices.
            pub fn names() -> Vec<&'static str> { Self::ALL.iter().map(|v| v.as_str()).collect() }
        }
        impl Default for $name {
            /// The choice a document gets when it does not make one.
            fn default() -> Self { $name::$def }
        }
        impl Serialize for $name {
            /// A value is written as its name.
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
options!(
    /// How link buttons are drawn: with a filled background, an outline, or plain text. The choice decides which contrast rule applies to the accent.
    Buttons { Filled => "filled", Outline => "outline", Plain => "plain" } default Outline);
options!(
    /// Corner rounding, from small to large.
    Radius { Xs => "xs", Sm => "sm", Md => "md", Lg => "lg" } default Md);
options!(
    /// Spacing: comfortable or compact.
    Density { Comfortable => "comfortable", Compact => "compact" } default Comfortable);
options!(
    /// Whether links are a plain list or cards.
    Layout { List => "list", Cards => "cards" } default List);
options!(
    /// System font stacks only: no web fonts are ever loaded.
    Font { Sans => "sans", Serif => "serif", Rounded => "rounded", Mono => "mono" } default Sans);

/// The whole theme: one choice from each option, all of them from the fixed sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Theme {
    /// Light, dark, or follow the visitor's device.
    pub color_mode: ColorMode,
    /// A seasonal palette, or none.
    pub season: Season,
    /// The accent hue.
    pub accent: Accent,
    /// How buttons are drawn.
    pub buttons: Buttons,
    /// Corner rounding.
    pub radius: Radius,
    /// Spacing.
    pub density: Density,
    /// List or cards.
    pub layout: Layout,
    /// Which system font stack.
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
    /// The accent colour.
    #[serde(serialize_with = "ser_rgb")]
    pub accent: Rgb,
    /// Text drawn on the accent (filled buttons).
    #[serde(serialize_with = "ser_rgb")]
    pub on_accent: Rgb,
    /// The lowest text contrast this combination produces.
    pub text_ratio: f64,
}

/// Write a colour as its `#rrggbb` hex string.
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
    // The three backgrounds the page can draw on in this mode; an accent used as text must reach the minimum on every one.
    let canvases = ["bg", "surface", "lift"].map(|r| t.role(mode, r));
    // The neutrals tried for the label on a filled button: white, a dark grey and near black.
    let label_candidates = [t.ramps["neutral"]["000"], t.ramps["neutral"]["800"], t.ramps["neutral"]["950"]];
    // The best contrast any candidate reached, reported when none passes.
    let mut best = 0.0_f64;
    // Candidates are tried in order of preference; the first that passes wins, so the most natural shade is used.
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
                // The weakest canvas decides, so the accent is readable on all of them.
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
    /// The colour mode that failed (`light` or `dark`).
    pub mode: &'static str,
    /// The best text contrast any shade reached, rounded to two decimals.
    pub best_ratio: f64,
    /// A sentence naming the combination and how to fix it.
    pub message: String,
}

/// Checks a whole theme in every mode its colour mode can show.
pub fn check(theme: &Theme) -> Result<Vec<(Mode, Resolved)>, Vec<ContrastFailure>> {
    // The resolved colours per mode, and the failures, for the modes this colour mode can show.
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

/// The plain-words reason a combination failed, with the alternatives that would pass: other buttons, another accent, or showing the page in one mode only.
fn fix_message(theme: &Theme, mode: Mode, best: f64) -> String {
    let what = match theme.accent {
        Accent::Season if theme.season == Season::None => "The default accent".to_string(),
        Accent::Season => format!("The {} accent", theme.season.as_str()),
        a => format!("The {} accent", a.as_str()),
    };
    // Other button styles that do pass for this accent in this mode.
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
    // Only a page that follows the device can drop one mode; a fixed mode is already one.
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
    /// The accent hue.
    pub accent: Accent,
    /// The button style.
    pub buttons: Buttons,
    /// The seasonal palette, or none.
    pub season: Season,
    /// The resolved colours in light mode, or `None` when the combination fails there.
    pub light: Option<Resolved>,
    /// The resolved colours in dark mode, or `None` when the combination fails there.
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
    // The rules for light mode, for dark mode, and for the system mode inside a dark-scheme query.
    let mut light = String::new();
    let mut dark = String::new();
    let mut system = String::new();
    for row in option_table() {
        // A season-coloured accent follows the season attribute; rules for hues do not depend on the season.
        // A hue does not depend on the season, so only the no-season row is written for it.
        if row.accent != Accent::Season && row.season != Season::None {
            continue;
        }
        // A season accent is selected by the season attribute, or by its absence for the default.
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
    // Every dark rule is repeated for the system mode inside a dark-scheme query, so the system mode needs no script.
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

/// Unit tests for the theme.
#[cfg(test)]
mod tests {
    use super::*;

    /// The default theme meets the contrast rule in both modes.
    #[test]
    fn default_theme_passes_in_both_modes() {
        assert!(check(&Theme::default()).is_ok());
    }

    /// Every combination that passes reaches the 7:1 text minimum, and every combination that fails is refused with a message that says what to choose.
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

    /// No hue is unusable: each has at least one button style that passes in each mode.
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

    /// The system-mode CSS repeats the dark rules, season rules included, and holds no class-based selector.
    #[test]
    fn system_css_mirrors_the_dark_rules() {
        let css = system_mode_css(&[crate::tokens::TOKENS_CSS, crate::tokens::SEASONS_CSS]);
        assert!(css.contains(":root[data-theme=\"system\"] {"));
        assert!(css.contains(":root[data-theme=\"system\"][data-season=\"winter\"]"));
        assert!(!css.contains(".dark"));
    }
}
