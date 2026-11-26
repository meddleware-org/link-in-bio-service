//! Sui wallet sign-in. The server issues a challenge; the wallet signs a CAIP-122-style message (the Sign-In with X
//! text, chain `sui:<network>`) as a Sui personal message; the server rebuilds the exact text from its own record of
//! the challenge and checks the signature recovers the address (ed25519, secp256k1, secp256r1 through
//! `access-gate-gateway-core::sig`; multisig and zkLogin are refused, fail-closed).

use serde::{Deserialize, Serialize};
use time::macros::format_description;
use time::{Duration, OffsetDateTime, UtcOffset};

/// A challenge is answered within this time.
pub const VALID_FOR: Duration = Duration::minutes(5);

/// What the server remembers about a challenge (stored with it; the client is given the text to sign).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// The host the wallet is asked to sign in to (the app's host), which the signed text names so a signature for another site is worthless here.
    pub domain: String,
    /// The address the sign-in is for.
    pub uri: String,
    /// The Sui network, which becomes the chain id in the text.
    pub network: String,
    /// The wallet address in canonical form.
    pub address: String,
    /// A random value, so each challenge is signed once.
    pub nonce: String,
    /// The sentence the wallet shows the person.
    pub statement: String,
    /// When the challenge was made.
    #[serde(with = "rfc3339")]
    pub issued_at: OffsetDateTime,
    /// When the challenge stops being accepted.
    #[serde(with = "rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// The challenge's timestamps in its stored JSON: RFC 3339 in UTC with `Z` and as many fractional digits as needed
/// (none, 3, 6 or 9, the form the earlier chrono-based code wrote); any RFC 3339 offset is read and normalised to UTC.
mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::format_description::well_known::Rfc3339;
    use time::macros::format_description;
    use time::{OffsetDateTime, UtcOffset};

    /// An instant as RFC 3339 in UTC, with no fraction, three, six or nine digits, whichever is the shortest that is exact.
    pub fn format(t: OffsetDateTime) -> String {
        // Always UTC.
        let t = t.to_offset(UtcOffset::UTC);
        let secs = t.format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]")).unwrap_or_default();
        // The shortest of the forms the earlier code wrote that is still exact.
        let fraction = match t.nanosecond() {
            0 => String::new(),
            n if n % 1_000_000 == 0 => format!(".{:03}", n / 1_000_000),
            n if n % 1_000 == 0 => format!(".{:06}", n / 1_000),
            n => format!(".{n:09}"),
        };
        format!("{secs}{fraction}Z")
    }

    /// Write a timestamp as its string form.
    pub fn serialize<S: Serializer>(t: &OffsetDateTime, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format(*t))
    }

    /// Read an RFC 3339 timestamp with any offset, normalised to UTC.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<OffsetDateTime, D::Error> {
        let s = String::deserialize(d)?;
        OffsetDateTime::parse(&s, &Rfc3339).map(|t| t.to_offset(UtcOffset::UTC)).map_err(serde::de::Error::custom)
    }
}

/// Why a wallet sign-in step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WalletError {
    /// The text is not a Sui address.
    #[error("that is not a Sui address")]
    Address,
    /// The challenge is older than its lifetime.
    #[error("the sign-in request has expired; start again")]
    Expired,
    /// The signature is malformed, or is not the address's signature over this challenge.
    #[error("the signature does not match the address")]
    Signature,
}

/// The address in its canonical form (`0x` + 64 lowercase hex), or `None`.
pub fn canonical_address(a: &str) -> Option<String> {
    // A short address is padded with zeros and lower-cased, so the same address always has one form.
    let hex = a.strip_prefix("0x")?;
    (!hex.is_empty() && hex.len() <= 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("0x{:0>64}", hex.to_ascii_lowercase()))
}

impl Challenge {
    /// A challenge for an address: a random nonce and a lifetime of [`VALID_FOR`]. The address must be a Sui address.
    pub fn new(
        domain: &str,
        uri: &str,
        network: &str,
        address: &str,
        statement: &str,
        now: OffsetDateTime,
    ) -> Result<Self, WalletError> {
        // A malformed address is refused before any challenge exists.
        let address = canonical_address(address).ok_or(WalletError::Address)?;
        Ok(Self {
            domain: domain.into(),
            uri: uri.into(),
            network: network.into(),
            address,
            // 128 random bits.
            nonce: crate::random_hex(16),
            statement: statement.into(),
            issued_at: now,
            // The lifetime is fixed, not chosen by the caller.
            expires_at: now + VALID_FOR,
        })
    }

    /// The exact text the wallet signs (CAIP-122 / EIP-4361 layout with a Sui chain id).
    pub fn message(&self) -> String {
        // The timestamps in the text have whole seconds in UTC.
        let ts = |t: &OffsetDateTime| {
            t.to_offset(UtcOffset::UTC)
                .format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z"))
                .unwrap_or_default()
        };
        format!(
            "{domain} wants you to sign in with your Sui account:\n{address}\n\n{statement}\n\nURI: {uri}\nVersion: 1\n\
             Chain ID: sui:{network}\nNonce: {nonce}\nIssued At: {issued}\nExpiration Time: {expires}",
            domain = self.domain,
            address = self.address,
            statement = self.statement,
            uri = self.uri,
            network = self.network,
            nonce = self.nonce,
            issued = ts(&self.issued_at),
            expires = ts(&self.expires_at),
        )
    }

    /// Checks a wallet's signature (base64 `flag || signature || public key`, as Sui wallets return it).
    pub fn verify(&self, signature_b64: &str, now: OffsetDateTime) -> Result<(), WalletError> {
        // Expiry is checked first, so an old signature is never even verified.
        if now >= self.expires_at {
            return Err(WalletError::Expired);
        }
        // The same verifier the access gate uses, so there is one implementation of Sui's signature rules; multisig and zkLogin are refused there.
        if access_gate_gateway_core::sig::verify_personal_message_signature(
            &self.address,
            self.message().as_bytes(),
            signature_b64,
        ) {
            Ok(())
        } else {
            Err(WalletError::Signature)
        }
    }
}

/// Unit tests for challenges.
#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    /// What a Sui wallet does for an ed25519 key: sign the personal-message digest, then `0x00 || sig || pubkey`.
    fn wallet_sign(seed: &[u8; 32], message: &[u8]) -> (String, String) {
        // A key pair from a fixed seed, so the test is repeatable.
        let kp = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        let pk = kp.public_key().as_ref().to_vec();
        let address = access_gate_gateway_core::sig::derive_address(0, &pk);
        // A Sui personal message is signed as a digest of the message with an intent prefix.
        let digest = access_gate_gateway_core::sig::signing_digest(message);
        // The flag byte 0 is the ed25519 scheme.
        let mut raw = vec![0u8];
        raw.extend_from_slice(kp.sign(&digest).as_ref());
        raw.extend_from_slice(&pk);
        (address, STANDARD.encode(raw))
    }

    /// A challenge signed by the right key verifies; after its lifetime it is expired, and another key, other text, and non-base64 are each refused.
    #[test]
    fn sign_in_round_trip() {
        let now = OffsetDateTime::now_utc();
        let seed = [9u8; 32];
        // The address belongs to the key, so the challenge is made for it.
        let (address, _) = wallet_sign(&seed, b"");
        let c = Challenge::new(
            "app.example.link",
            "https://app.example.link/",
            "testnet",
            &address,
            "Sign in to Link in Bio.",
            now,
        )
        .unwrap();
        let text = c.message();
        // The text begins with the domain and names the account, as the sign-in-with-X layout requires.
        assert!(text.starts_with("app.example.link wants you to sign in with your Sui account:\n0x"));
        assert!(text.contains("\nChain ID: sui:testnet\n"));
        let (_, sig) = wallet_sign(&seed, text.as_bytes());
        assert_eq!(c.verify(&sig, now), Ok(()));
        // At exactly the expiry instant it is already expired.
        assert_eq!(c.verify(&sig, now + VALID_FOR), Err(WalletError::Expired));
        // A different key signing the right text.
        let (_, other) = wallet_sign(&[8u8; 32], text.as_bytes());
        assert_eq!(c.verify(&other, now), Err(WalletError::Signature));
        // The right key signing other text.
        let (_, wrong_text) = wallet_sign(&seed, b"something else");
        assert_eq!(c.verify(&wrong_text, now), Err(WalletError::Signature));
        assert_eq!(c.verify("not base64", now), Err(WalletError::Signature));
    }

    /// Challenges stored by the earlier implementation read back and are written back identically, in every fraction width; an offset is normalised to UTC and a non-date is refused.
    #[test]
    fn stored_challenges_read_back() {
        // As the chrono-based code stored it (chrono's serde: RFC 3339, UTC, `Z`, 0/3/6/9 fractional digits).
        let stored = serde_json::json!({
            "domain": "app.example.link",
            "uri": "https://app.example.link/",
            "network": "testnet",
            "address": format!("0x{}2", "0".repeat(63)),
            "nonce": "00112233445566778899aabbccddeeff",
            "statement": "Sign in to Link in Bio.",
            "issuedAt": "2026-11-17T09:41:07.123456Z",
            "expiresAt": "2026-11-17T09:46:07.123456Z",
        });
        let c: Challenge = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(c.issued_at, time::macros::datetime!(2026-11-17 09:41:07.123456 UTC));
        assert_eq!(c.expires_at - c.issued_at, VALID_FOR);
        assert!(c.message().contains("\nIssued At: 2026-11-17T09:41:07Z\nExpiration Time: 2026-11-17T09:46:07Z"));
        // Written back the same way.
        assert_eq!(serde_json::to_value(&c).unwrap(), stored);
        // The other fraction widths chrono wrote, and an offset (normalised to UTC).
        for (text, nanos) in [
            ("2026-11-17T09:41:07Z", 0),
            ("2026-11-17T09:41:07.120Z", 120_000_000),
            ("2026-11-17T09:41:07.123456789Z", 123_456_789),
        ] {
            let mut v = stored.clone();
            v["issuedAt"] = text.into();
            let c: Challenge = serde_json::from_value(v.clone()).unwrap();
            assert_eq!(c.issued_at.nanosecond(), nanos);
            assert_eq!(serde_json::to_value(&c).unwrap(), v);
        }
        let mut v = stored.clone();
        v["issuedAt"] = "2026-11-17T10:41:07.123456+01:00".into();
        let c: Challenge = serde_json::from_value(v).unwrap();
        assert_eq!(c.issued_at.offset(), UtcOffset::UTC);
        assert_eq!(serde_json::to_value(&c).unwrap(), stored);
        let mut v = stored;
        v["issuedAt"] = "yesterday".into();
        assert!(serde_json::from_value::<Challenge>(v).is_err());
    }

    /// Short addresses are padded, upper case is folded, and a missing prefix or an over-long address is refused.
    #[test]
    fn addresses() {
        assert_eq!(canonical_address("0x2").unwrap(), format!("0x{}2", "0".repeat(63)));
        assert_eq!(canonical_address("0xABcd").unwrap().len(), 66);
        assert!(canonical_address("2").is_none());
        assert!(canonical_address(&format!("0x{}", "a".repeat(65))).is_none());
    }
}
