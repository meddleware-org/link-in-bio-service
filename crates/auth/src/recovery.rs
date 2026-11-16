//! Recovery codes: ten one-use codes shown once, each 80 random bits in Crockford base32 (`xxxx-xxxx-xxxx-xxxx`). Only
//! their SHA-256 is stored; online guessing is bounded by the sign-in rate limits.

use sha2::{Digest, Sha256};

pub const COUNT: usize = 10;
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// New codes: what to show the person, and what to store.
pub fn generate() -> (Vec<String>, Vec<Vec<u8>>) {
    let codes: Vec<String> = (0..COUNT).map(|_| encode(&crate::random_bytes::<10>())).collect();
    let hashes = codes.iter().map(|c| hash(c)).collect();
    (codes, hashes)
}

fn encode(bytes: &[u8; 10]) -> String {
    let mut bits: u128 = 0;
    for b in bytes {
        bits = (bits << 8) | u128::from(*b);
    }
    let chars: Vec<char> = (0..16).rev().map(|i| ALPHABET[((bits >> (i * 5)) & 31) as usize] as char).collect();
    chars.chunks(4).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join("-")
}

/// The canonical form of a typed code: case, spaces and hyphens ignored, and the look-alikes Crockford folds (`o`→`0`,
/// `i`/`l`→`1`). `None` when it cannot be a code.
pub fn normalise(typed: &str) -> Option<String> {
    let s: String = typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        })
        .collect();
    (s.len() == 16 && s.bytes().all(|b| ALPHABET.contains(&b)))
        .then(|| s.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join("-"))
}

/// The stored form of a code (after [`normalise`]).
pub fn hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_through_typing() {
        let (codes, hashes) = generate();
        assert_eq!(codes.len(), COUNT);
        let c = &codes[0];
        assert_eq!(c.len(), 19);
        let typed = c.to_uppercase().replace('-', " ");
        assert_eq!(normalise(&typed).as_deref(), Some(c.as_str()));
        assert_eq!(hash(&normalise(&typed).unwrap()), hashes[0]);
        assert_eq!(normalise("O000-0000-0000-000I").as_deref(), Some("0000-0000-0000-0001"));
        assert_eq!(normalise("too short"), None);
        assert_eq!(normalise("uuuu-uuuu-uuuu-uuuu"), None, "u is not in the alphabet");
    }
}
