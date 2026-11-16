//! Text that people type: normalised to NFC, trimmed, single-line, bounded in graphemes and bytes, and free of the
//! characters that let text pretend to be something else (bidirectional overrides, invisible separators, controls).

use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// Why a string was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    Empty,
    TooLong { max: usize },
    Control,
    Bidi,
    Invisible,
    PrivateUse,
}

impl TextError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::TooLong { .. } => "too_long",
            Self::Control => "control_character",
            Self::Bidi => "bidi_control",
            Self::Invisible => "invisible_character",
            Self::PrivateUse => "private_use_character",
        }
    }

    pub fn message(self) -> String {
        match self {
            Self::Empty => "This cannot be empty.".into(),
            Self::TooLong { max } => format!("This is too long: at most {max} characters."),
            Self::Control => "This contains a control character (for example a line break or tab). Use one line of plain text.".into(),
            Self::Bidi => "This contains a hidden text-direction control, which can make text look like something else. Remove it.".into(),
            Self::Invisible => "This contains an invisible character. Remove it.".into(),
            Self::PrivateUse => "This contains a private-use character that most devices cannot show. Remove it.".into(),
        }
    }
}

/// Bytes allowed per grapheme on top of the grapheme limit: emoji sequences are long in UTF-8 (a family is 18 bytes,
/// a subdivision flag 28), while a flood of combining marks on one letter is not.
const BYTES_PER_GRAPHEME: usize = 32;

/// Normalises and checks one line of text. `max` counts user-perceived characters (grapheme clusters).
pub fn clean_line(input: &str, max: usize, allow_empty: bool) -> Result<String, TextError> {
    let s: String = input.nfc().collect();
    let s = s.trim().to_string();
    if s.is_empty() {
        return if allow_empty { Ok(s) } else { Err(TextError::Empty) };
    }
    for c in s.chars() {
        check_char(c)?;
    }
    if s.graphemes(true).count() > max || s.len() > max * BYTES_PER_GRAPHEME {
        return Err(TextError::TooLong { max });
    }
    Ok(s)
}

fn check_char(c: char) -> Result<(), TextError> {
    let u = c as u32;
    match u {
        // C0, DEL, C1.
        0x00..=0x1F | 0x7F..=0x9F => Err(TextError::Control),
        // Bidirectional embeddings, overrides and isolates (Trojan Source). LRM/RLM/ALM stay allowed.
        0x202A..=0x202E | 0x2066..=0x2069 => Err(TextError::Bidi),
        // Zero-width space, word joiner and other invisible operators, line/paragraph separators, BOM,
        // interlinear annotations, Mongolian vowel separator, Hangul fillers.
        0x200B
        | 0x2028
        | 0x2029
        | 0x2060..=0x2064
        | 0xFEFF
        | 0xFFF9..=0xFFFB
        | 0x180E
        | 0x115F
        | 0x1160
        | 0x3164
        | 0xFFA0 => Err(TextError::Invisible),
        0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD => Err(TextError::PrivateUse),
        // Noncharacters.
        0xFDD0..=0xFDEF => Err(TextError::Invisible),
        _ if u & 0xFFFE == 0xFFFE => Err(TextError::Invisible),
        _ => Ok(()),
    }
}

/// Grapheme count, for limits the editor shows.
pub fn graphemes(s: &str) -> usize {
    s.graphemes(true).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trims_and_normalises() {
        // "e" + combining acute becomes the precomposed é.
        assert_eq!(clean_line("  e\u{0301}  ", 10, false).unwrap(), "\u{00e9}");
    }

    #[test]
    fn refuses_hostile_characters() {
        assert_eq!(clean_line("abc\u{202E}def", 10, false), Err(TextError::Bidi));
        assert_eq!(clean_line("a\u{2067}b", 10, false), Err(TextError::Bidi));
        assert_eq!(clean_line("a\nb", 10, false), Err(TextError::Control));
        assert_eq!(clean_line("a\u{200B}b", 10, false), Err(TextError::Invisible));
        assert_eq!(clean_line("a\u{E000}", 10, false), Err(TextError::PrivateUse));
        assert_eq!(clean_line("   ", 10, false), Err(TextError::Empty));
        assert_eq!(clean_line("   ", 10, true), Ok(String::new()));
    }

    #[test]
    fn counts_graphemes_not_bytes() {
        // A family emoji is one grapheme of many code points.
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        assert!(clean_line(&family.repeat(3), 3, false).is_ok());
        assert_eq!(clean_line(&family.repeat(4), 3, false), Err(TextError::TooLong { max: 3 }));
        // Right-to-left marks are fine.
        assert!(clean_line("\u{200F}שלום", 10, false).is_ok());
    }
}
