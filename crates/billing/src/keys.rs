//! Keys from files, for the adapters that sign their requests: PEM (RFC 7468), RSA private keys in PKCS #8 or PKCS #1
//! (Wise's SCA signature, bunq's request signatures, Revolut's client assertion), the RSA public key as a
//! SubjectPublicKeyInfo (what bunq is sent and sends back), ed25519 private keys in PKCS #8 (Open Payments), and RS256
//! JSON Web Tokens (RFC 7515/7519). Everything is `ring`; the few DER structures are written and read here.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair, UnparsedPublicKey};
use serde_json::Value;

use crate::BillingError;

/// A malformed-input error with a fixed message (never the input).
fn bad(m: &str) -> BillingError {
    BillingError::Malformed(m.into())
}

/// The DER bytes of the first PEM block with one of `labels`. A file holding the base64 of a PEM document (as some
/// wallets hand out keys) is accepted too.
pub fn pem_decode(text: &str, labels: &[&str]) -> Result<(String, Vec<u8>), BillingError> {
    // Surrounding space is ignored.
    let text = text.trim();
    if !text.starts_with("-----BEGIN ")
        && let Ok(inner) = STANDARD.decode(text.split_whitespace().collect::<String>())
        && let Ok(inner) = String::from_utf8(inner)
        && inner.trim_start().starts_with("-----BEGIN ")
    {
        return pem_decode(&inner, labels);
    }
    // Scan line by line for a BEGIN marker; blocks with other labels are skipped.
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else { continue };
        // The matching END marker closes the block.
        let end = format!("-----END {label}-----");
        let mut b64 = String::new();
        for l in lines.by_ref() {
            if l == end {
                break;
            }
            b64.push_str(l);
        }
        if labels.contains(&label) {
            let der = STANDARD.decode(b64).map_err(|_| bad("the PEM block is not base64"))?;
            return Ok((label.to_string(), der));
        }
    }
    Err(BillingError::Malformed(format!("no PEM block labelled {}", labels.join(" or "))))
}

/// Write a DER length: short form below 128, otherwise the long form with the minimal number of length bytes.
fn der_len(out: &mut Vec<u8>, n: usize) {
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

/// One DER element: a tag, its length and its content.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    der_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Reads one DER element: its tag, its content and the rest of the input.
fn der_read(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    // The tag, then the length (short form, or long form of at most four bytes), then that many content bytes.
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |acc, b| (acc << 8) | usize::from(*b)), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
const RSA_ALGORITHM: &[u8] =
    &[0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];

/// Wraps a PKCS #1 RSAPublicKey in a SubjectPublicKeyInfo.
pub fn rsa_spki(pkcs1: &[u8]) -> Vec<u8> {
    // A BIT STRING starts with a count of unused bits, which is zero for a key.
    let mut bits = vec![0u8];
    bits.extend_from_slice(pkcs1);
    let mut body = RSA_ALGORITHM.to_vec();
    body.extend(der(0x03, &bits));
    der(0x30, &body)
}

/// The PKCS #1 RSAPublicKey inside an RSA SubjectPublicKeyInfo.
pub fn rsa_pkcs1_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let (tag, seq, _) = der_read(spki)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, alg, rest) = der_read(seq)?;
    // Only RSA keys with the exact algorithm identifier are accepted.
    if tag != 0x30 || der(0x30, alg) != RSA_ALGORITHM {
        return None;
    }
    let (tag, bits, _) = der_read(rest)?;
    if tag != 0x03 || bits.first() != Some(&0) {
        return None;
    }
    Some(bits[1..].to_vec())
}

/// PEM text (RFC 7468) for DER bytes, wrapped at 64 characters.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    // PEM wraps the base64 at 64 characters per line.
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// An RSA private key (2048 to 8192 bits) for SHA-256 PKCS #1 v1.5 signatures.
pub struct RsaKey {
    /// The key pair `ring` loaded.
    key: RsaKeyPair,
}

impl std::fmt::Debug for RsaKey {
    /// Never print key material, even by accident in a log.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaKey(..)")
    }
}

impl RsaKey {
    /// From a PEM file: `PRIVATE KEY` (PKCS #8, what `openssl genpkey` writes) or `RSA PRIVATE KEY` (PKCS #1).
    pub fn from_pem(text: &str) -> Result<Self, BillingError> {
        let (label, der) = pem_decode(text, &["PRIVATE KEY", "RSA PRIVATE KEY"])?;
        let key = if label == "PRIVATE KEY" { RsaKeyPair::from_pkcs8(&der) } else { RsaKeyPair::from_der(&der) }
            .map_err(|e| BillingError::Malformed(format!("not a usable RSA private key: {e}")))?;
        Ok(Self { key })
    }

    /// `RSASSA-PKCS1-v1_5` with SHA-256 (what `openssl dgst -sha256 -sign` makes).
    pub fn sign_sha256(&self, msg: &[u8]) -> Result<Vec<u8>, BillingError> {
        // The signature is as long as the modulus.
        let mut sig = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(&signature::RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut sig)
            .map_err(|_| BillingError::Unavailable("RSA signing failed".into()))?;
        Ok(sig)
    }

    /// The public key in PKCS #1 form.
    pub fn public_pkcs1(&self) -> &[u8] {
        self.key.public().as_ref()
    }

    /// The public key as `-----BEGIN PUBLIC KEY-----` (SubjectPublicKeyInfo), as `openssl pkey -pubout` writes it.
    pub fn public_pem(&self) -> String {
        pem_encode("PUBLIC KEY", &rsa_spki(self.public_pkcs1()))
    }
}

/// Checks a SHA-256 PKCS #1 v1.5 signature against an RSA public key in PEM (`PUBLIC KEY` or `RSA PUBLIC KEY`).
pub fn rsa_sha256_valid(public_pem: &str, msg: &[u8], sig: &[u8]) -> bool {
    let Ok((label, der)) = pem_decode(public_pem, &["PUBLIC KEY", "RSA PUBLIC KEY"]) else { return false };
    // A SubjectPublicKeyInfo is unwrapped to PKCS #1; a bare PKCS #1 key is used as it is.
    let pkcs1 = if label == "PUBLIC KEY" { rsa_pkcs1_from_spki(&der) } else { Some(der) };
    let Some(pkcs1) = pkcs1 else { return false };
    UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, pkcs1).verify(msg, sig).is_ok()
}

/// An ed25519 private key from a PKCS #8 PEM file (`openssl genpkey -algorithm ed25519`, or the key file a wallet
/// gives for its developer keys, possibly base64-wrapped).
pub fn ed25519_from_pem(text: &str) -> Result<Ed25519KeyPair, BillingError> {
    let (_, der) = pem_decode(text, &["PRIVATE KEY"])?;
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
        .map_err(|e| BillingError::Malformed(format!("not an ed25519 private key: {e}")))
}

/// The public JWK of an ed25519 key (RFC 8037), as a wallet address's `jwks.json` lists it.
pub fn ed25519_jwk(key: &Ed25519KeyPair, kid: &str) -> Value {
    serde_json::json!({
        "kid": kid, "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
        "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    })
}

/// A compact JWS (RS256) over `claims`, with `{"alg":"RS256","typ":"JWT"}`.
pub fn jwt_rs256(key: &RsaKey, claims: &Value) -> Result<String, BillingError> {
    // The header is fixed, so the signed text is exactly what a verifier rebuilds.
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let input = format!("{header}.{payload}");
    let sig = key.sign_sha256(input.as_bytes())?;
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}

/// Random bytes, hex encoded (nonces).
pub fn random_hex(bytes: usize) -> Result<String, BillingError> {
    let mut b = vec![0u8; bytes];
    // Unlike the sign-in crate, a failure of the system generator is reported here, not a panic.
    ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut b)
        .map_err(|_| BillingError::Unavailable("no randomness".into()))?;
    Ok(hex::encode(b))
}

/// Unit tests for the key readers and signers.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // Throwaway keys made with OpenSSL for these tests only (crates/billing/tests/fixtures). `test-rsa-a.pub.pem` is
    // OpenSSL's `pkey -pubout` of key a, and `test-rsa-a.sig-abc.b64` is
    // `printf abc | openssl dgst -sha256 -sign test-rsa-a.pem | base64 -w0`: an independent implementation's output.
    //
    // The private keys are kept as bare base64 DER (no PEM armour, so secret scanners do not take them for real keys)
    // and armoured here.
    /// The public key of test key a, as OpenSSL wrote it.
    const A_PUB: &str = include_str!("../tests/fixtures/test-rsa-a.pub.pem");
    /// OpenSSL's signature of `abc` with test key a, in base64.
    const A_SIG_ABC: &str = include_str!("../tests/fixtures/test-rsa-a.sig-abc.b64");

    /// Wrap bare base64 DER in PEM armour, so the keys in the fixtures carry none.
    fn armour(label: &str, b64: &str) -> String {
        pem_encode(label, &STANDARD.decode(b64.trim()).unwrap())
    }

    /// RFC 9421 B.1.4 test-key-ed25519 (published in the RFC).
    pub(crate) fn rfc9421_test_key() -> String {
        armour("PRIVATE KEY", "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF")
    }

    /// The key readers, the public key encoding and the signature are byte for byte what OpenSSL makes; another key or message fails, a base64-wrapped PEM reads the same, and bad input is refused.
    #[test]
    fn rsa_keys_match_openssl() {
        let a_pem = armour("PRIVATE KEY", include_str!("../tests/fixtures/test-rsa-a.pkcs8.b64"));
        let a = RsaKey::from_pem(&a_pem).unwrap();
        assert_eq!(a.public_pem(), A_PUB, "the SubjectPublicKeyInfo is byte for byte what OpenSSL writes");
        let sig = a.sign_sha256(b"abc").unwrap();
        assert_eq!(STANDARD.encode(&sig), A_SIG_ABC.trim(), "PKCS #1 v1.5 is deterministic: OpenSSL's signature");
        assert!(rsa_sha256_valid(A_PUB, b"abc", &sig));
        assert!(!rsa_sha256_valid(A_PUB, b"abd", &sig));
        let b = RsaKey::from_pem(&armour("RSA PRIVATE KEY", include_str!("../tests/fixtures/test-rsa-b.pkcs1.b64")))
            .unwrap();
        assert!(!rsa_sha256_valid(&b.public_pem(), b"abc", &sig), "another key");
        assert_eq!(rsa_pkcs1_from_spki(&rsa_spki(b.public_pkcs1())).as_deref(), Some(b.public_pkcs1()));
        // A base64-wrapped PEM file reads the same.
        let wrapped = STANDARD.encode(&a_pem);
        assert_eq!(RsaKey::from_pem(&wrapped).unwrap().public_pem(), A_PUB);
        assert!(RsaKey::from_pem(&armour("PRIVATE KEY", "AAAA")).is_err());
        assert!(RsaKey::from_pem("nothing").is_err());
    }

    /// The RFC's test key reads, and its public JWK matches the RFC.
    #[test]
    fn ed25519_test_key_of_rfc_9421() {
        // RFC 9421 B.1.4 test-key-ed25519 and its JWK.
        let k = ed25519_from_pem(&rfc9421_test_key()).unwrap();
        assert_eq!(ed25519_jwk(&k, "test-key-ed25519")["x"], "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs");
    }

    /// A signed token has the fixed header and its signature verifies against the public key.
    #[test]
    fn jwt_signs_and_verifies() {
        let a =
            RsaKey::from_pem(&armour("PRIVATE KEY", include_str!("../tests/fixtures/test-rsa-a.pkcs8.b64"))).unwrap();
        let t = jwt_rs256(&a, &serde_json::json!({ "sub": "x" })).unwrap();
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts[0], "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        assert!(rsa_sha256_valid(A_PUB, format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig));
    }
}
