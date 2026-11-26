//! RS256 JWT verification against a JWKS, with ring (no `jsonwebtoken`: its backends are aws-lc-rs or the
//! advisory-flagged `rsa` crate). Pure apart from the clock value passed in.
//!
//! Checks, in order: three base64url segments; header `alg` is `RS256` (anything else, including `none`, is refused);
//! the `kid` names a key in the set; the PKCS#1 v1.5 SHA-256 signature verifies over `header.payload`; `iss` equals
//! the configured issuer; `aud` (string or array) contains the configured audience; `exp` is in the future and `nbf`
//! (when present) in the past, each with a bounded clock skew; `sub` is non-empty.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;

/// Allowed clock difference between Cloudflare and this server.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// One RSA public key from a JWKS (`n`, `e` base64url).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// The key's id, which a token names in its header.
    pub kid: String,
    /// The key type, `RSA` (empty is accepted as RSA).
    #[serde(default)]
    pub kty: String,
    /// The algorithm the key is for, if stated; anything but RS256 is refused.
    #[serde(default)]
    pub alg: Option<String>,
    /// The modulus, base64url.
    pub n: String,
    /// The public exponent, base64url.
    pub e: String,
}

/// A key set as the identity provider publishes it.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkSet {
    /// The keys.
    pub keys: Vec<Jwk>,
}

/// Why a token was refused. The reason is logged and never sent to the caller, who only learns that they are not authenticated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    /// It is not three base64url parts with readable JSON.
    #[error("malformed token")]
    Malformed,
    /// The token or the key is not RS256 (this includes `none`).
    #[error("unsupported algorithm")]
    Algorithm,
    /// No key in the set has the id the token names.
    #[error("unknown signing key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("bad signature")]
    Signature,
    /// The issuer is not the configured one.
    #[error("wrong issuer")]
    Issuer,
    /// The configured audience is not among the token's.
    #[error("wrong audience")]
    Audience,
    /// It has expired (allowing the clock skew).
    #[error("expired")]
    Expired,
    /// It is not valid yet (allowing the clock skew).
    #[error("not yet valid")]
    NotYetValid,
    /// The subject is missing, blank or very long.
    #[error("no subject")]
    Subject,
}

/// The token header: the algorithm and the key id.
#[derive(Deserialize)]
struct Header {
    /// The signing algorithm.
    alg: String,
    /// The key id.
    kid: Option<String>,
}

/// The audience claim, which may be a string or a list.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum Aud {
    /// A single audience.
    One(String),
    /// Several audiences.
    Many(Vec<String>),
}

/// The claims this service reads; the rest are ignored.
#[derive(Debug, Clone, Deserialize)]
struct Claims {
    /// Who issued the token.
    iss: Option<String>,
    /// Who it is for.
    aud: Option<Aud>,
    /// When it expires, in Unix seconds.
    exp: Option<i64>,
    /// When it becomes valid, in Unix seconds.
    nbf: Option<i64>,
    /// The operator's stable id.
    sub: Option<String>,
    /// The operator's address, used as a display name when there is no name.
    email: Option<String>,
    /// The operator's name.
    name: Option<String>,
}

/// The verified identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The operator's stable id.
    pub subject: String,
    /// A display name: the `name` claim, else the e-mail address, else the subject.
    pub display_name: String,
}

/// The part of the token that selects the key (for a refresh on an unknown `kid`).
pub fn key_id(token: &str) -> Option<String> {
    // The key id is read before verifying, so the caller can refresh the key set for an unknown key; it proves nothing by itself.
    let header = token.split('.').next()?;
    let h: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).ok()?).ok()?;
    h.kid
}

/// Verify `token` against `keys` at time `now` (Unix seconds).
pub fn verify(token: &str, keys: &JwkSet, issuer: &str, audience: &str, now: i64) -> Result<Verified, JwtError> {
    // Exactly three parts, and no more.
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed);
    };
    let header: Header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h64).map_err(|_| JwtError::Malformed)?)
        .map_err(|_| JwtError::Malformed)?;
    // The algorithm is fixed: a token cannot choose a weaker one.
    if header.alg != "RS256" {
        return Err(JwtError::Algorithm);
    }
    // The key is found by id in the set, which the identity provider controls.
    let kid = header.kid.ok_or(JwtError::UnknownKey)?;
    let key =
        keys.keys.iter().find(|k| k.kid == kid && (k.kty.is_empty() || k.kty == "RSA")).ok_or(JwtError::UnknownKey)?;
    if key.alg.as_deref().is_some_and(|a| a != "RS256") {
        return Err(JwtError::Algorithm);
    }
    let n = URL_SAFE_NO_PAD.decode(&key.n).map_err(|_| JwtError::UnknownKey)?;
    let e = URL_SAFE_NO_PAD.decode(&key.e).map_err(|_| JwtError::UnknownKey)?;
    let sig = URL_SAFE_NO_PAD.decode(s64).map_err(|_| JwtError::Malformed)?;
    // The signature covers the first two parts as they were written.
    let signed = &token[..h64.len() + 1 + p64.len()];
    RsaPublicKeyComponents { n: &n, e: &e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &sig)
        .map_err(|_| JwtError::Signature)?;
    // The claims are read only after the signature has verified.
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p64).map_err(|_| JwtError::Malformed)?)
        .map_err(|_| JwtError::Malformed)?;
    // The issuer must be the configured team.
    if claims.iss.as_deref() != Some(issuer) {
        return Err(JwtError::Issuer);
    }
    // The audience may be one value or a list.
    let aud_ok = match &claims.aud {
        Some(Aud::One(a)) => a == audience,
        Some(Aud::Many(v)) => v.iter().any(|a| a == audience),
        None => false,
    };
    if !aud_ok {
        return Err(JwtError::Audience);
    }
    // A token without an expiry is refused.
    match claims.exp {
        Some(exp) if exp + CLOCK_SKEW_SECS > now => {}
        _ => return Err(JwtError::Expired),
    }
    if claims.nbf.is_some_and(|nbf| nbf - CLOCK_SKEW_SECS > now) {
        return Err(JwtError::NotYetValid);
    }
    // The subject must be non-empty and of sane length.
    let subject = claims.sub.filter(|s| !s.trim().is_empty() && s.chars().count() <= 512).ok_or(JwtError::Subject)?;
    // The name claim, else the address, else the subject, cut to 200 characters.
    let display_name: String = claims
        .name
        .filter(|n| !n.trim().is_empty())
        .or(claims.email.filter(|e| !e.trim().is_empty()))
        .unwrap_or_else(|| subject.clone())
        .chars()
        .take(200)
        .collect();
    Ok(Verified { subject, display_name })
}

/// Sign test tokens with a throwaway key (tests only; the `testing` feature exposes it to other crates' tests).
/// The key is in no JWKS that production trusts: production verifies against the Access team's keys only.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use ring::rand::SystemRandom;
    use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

    use super::{Jwk, JwkSet};

    include!("testkey.rs");

    /// A key set holding the test key under this id.
    pub fn jwks(kid: &str) -> JwkSet {
        JwkSet {
            keys: vec![Jwk {
                kid: kid.into(),
                kty: "RSA".into(),
                alg: Some("RS256".into()),
                n: TEST_KEY_N.into(),
                e: TEST_KEY_E.into(),
            }],
        }
    }

    /// Sign claims with the test key, with the header as given (so a test can ask for another algorithm).
    pub fn sign(header: &serde_json::Value, claims: &serde_json::Value) -> String {
        let der = STANDARD.decode(TEST_KEY_PKCS8_B64).expect("test key");
        let key = RsaKeyPair::from_pkcs8(&der).expect("pkcs8");
        let input =
            format!("{}.{}", URL_SAFE_NO_PAD.encode(header.to_string()), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let mut sig = vec![0; key.public().modulus_len()];
        key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), input.as_bytes(), &mut sig).expect("sign");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }
}

/// Unit tests for token verification.
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::testing::{jwks, sign};
    use super::*;

    /// The issuer the tests configure.
    const ISS: &str = "https://team.cloudflareaccess.com";
    /// The audience tag the tests configure.
    const AUD: &str = "aud-tag";
    /// The fixed time the tests verify at.
    const NOW: i64 = 1_800_000_000;

    /// Claims of a valid token.
    fn claims() -> serde_json::Value {
        json!({ "iss": ISS, "aud": [AUD], "sub": "user-1", "email": "op@example.org", "exp": NOW + 600, "nbf": NOW - 10 })
    }

    /// A token with these claims, signed with the test key.
    fn tok(c: &serde_json::Value) -> String {
        sign(&json!({ "alg": "RS256", "kid": "k1" }), c)
    }

    /// A valid token gives the subject and the address as the name, and its key id can be read.
    #[test]
    fn a_valid_token_yields_the_subject_and_a_display_name() {
        let v = verify(&tok(&claims()), &jwks("k1"), ISS, AUD, NOW).expect("valid");
        assert_eq!(v, Verified { subject: "user-1".into(), display_name: "op@example.org".into() });
        assert_eq!(key_id(&tok(&claims())).as_deref(), Some("k1"));
    }

    /// A wrong issuer, audience, expiry, start time, subject, key and shape each give their own error.
    #[test]
    fn every_defect_is_refused_with_its_reason() {
        let keys = jwks("k1");
        let mut c = claims();
        c["iss"] = json!("https://evil.cloudflareaccess.com");
        assert_eq!(verify(&tok(&c), &keys, ISS, AUD, NOW), Err(JwtError::Issuer));
        let mut c = claims();
        c["aud"] = json!("other");
        assert_eq!(verify(&tok(&c), &keys, ISS, AUD, NOW), Err(JwtError::Audience));
        let mut c = claims();
        c["exp"] = json!(NOW - 61);
        assert_eq!(verify(&tok(&c), &keys, ISS, AUD, NOW), Err(JwtError::Expired));
        let mut c = claims();
        c["nbf"] = json!(NOW + 61);
        assert_eq!(verify(&tok(&c), &keys, ISS, AUD, NOW), Err(JwtError::NotYetValid));
        let mut c = claims();
        c["sub"] = json!(" ");
        assert_eq!(verify(&tok(&c), &keys, ISS, AUD, NOW), Err(JwtError::Subject));
        assert_eq!(verify(&tok(&claims()), &jwks("other"), ISS, AUD, NOW), Err(JwtError::UnknownKey));
        assert_eq!(verify("a.b", &keys, ISS, AUD, NOW), Err(JwtError::Malformed));
    }

    /// A token with algorithm none, a swapped payload under a valid signature and a different algorithm are refused.
    #[test]
    fn forged_tokens_are_refused() {
        let keys = jwks("k1");
        // alg none, and a payload swapped under a valid signature.
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(json!({"alg": "none", "kid": "k1"}).to_string()),
            URL_SAFE_NO_PAD.encode(claims().to_string())
        );
        assert_eq!(verify(&none, &keys, ISS, AUD, NOW), Err(JwtError::Algorithm));
        let good = tok(&claims());
        let mut forged_claims = claims();
        forged_claims["sub"] = json!("admin");
        let parts: Vec<&str> = good.split('.').collect();
        let forged = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(forged_claims.to_string()), parts[2]);
        assert_eq!(verify(&forged, &keys, ISS, AUD, NOW), Err(JwtError::Signature));
        let hs = sign(&json!({ "alg": "HS256", "kid": "k1" }), &claims());
        assert_eq!(verify(&hs, &keys, ISS, AUD, NOW), Err(JwtError::Algorithm));
    }
}
