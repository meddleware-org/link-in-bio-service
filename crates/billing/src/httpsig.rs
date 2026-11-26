//! HTTP Message Signatures (RFC 9421) with ed25519, Content-Digest (RFC 9530) and the GNAP interaction hash
//! (RFC 9635 §4.2.3): what an Open Payments client needs to sign its requests and to check the authorization server's
//! redirect.
//!
//! Only what a client uses is here: derived components `@method`, `@target-uri`, `@authority`, `@path` and `@query`,
//! and header fields (lower-cased names, values trimmed; repeated fields joined with `", "`). Signature parameters are
//! kept in the order given, since their serialisation is part of what is signed.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

/// One signature parameter (`created`, `keyid`, `alg`, …), serialised as an sf-integer or an sf-string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    /// A parameter with an integer value, such as `created`.
    Int(&'static str, i64),
    /// A parameter with a string value, such as `keyid`; quotes and backslashes in it are escaped.
    Str(&'static str, String),
}

/// The `@signature-params` value: `("c1" "c2" …);p1=…;p2=…`.
pub fn signature_params(components: &[&str], params: &[Param]) -> String {
    // The list of covered components in quotes, then each parameter in the order given.
    let mut s = format!("({})", components.iter().map(|c| format!("\"{c}\"")).collect::<Vec<_>>().join(" "));
    for p in params {
        match p {
            Param::Int(k, v) => s.push_str(&format!(";{k}={v}")),
            // String values are quoted with backslash and quote escaped, as structured fields require.
            Param::Str(k, v) => s.push_str(&format!(";{k}=\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\""))),
        }
    }
    s
}

/// The signature base (RFC 9421 §2.5) for `(component, value)` pairs and the serialised parameters.
pub fn signature_base(components: &[(&str, String)], params: &str) -> String {
    // The base is one line per component, then the parameters.
    let mut s = String::new();
    for (name, value) in components {
        s.push_str(&format!("\"{name}\": {value}\n"));
    }
    // The last line of the base is the parameters themselves, which binds them into the signature.
    s.push_str(&format!("\"@signature-params\": {params}"));
    s
}

/// The `Content-Digest` field value with SHA-512 (what Open Payments uses).
pub fn content_digest_sha512(body: &[u8]) -> String {
    format!("sha-512=:{}:", STANDARD.encode(digest::digest(&digest::SHA512, body)))
}

/// The `Content-Digest` field value with SHA-256.
pub fn content_digest_sha256(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(digest::digest(&digest::SHA256, body)))
}

/// Whether a `Content-Digest` value holds a matching `sha-512` or `sha-256` digest of `body` (others are ignored;
/// at least one known one must be present, and every known one must match).
pub fn content_digest_valid(value: &str, body: &[u8]) -> bool {
    // At least one known digest must be present.
    let mut seen = false;
    for member in value.split(',') {
        let Some((alg, v)) = member.trim().split_once('=') else { return false };
        let want = match alg.trim() {
            "sha-512" => content_digest_sha512(body),
            "sha-256" => content_digest_sha256(body),
            // Digests of other algorithms are ignored, not failed.
            _ => continue,
        };
        seen = true;
        if format!("{}={}", alg.trim(), v.trim()) != want {
            return false;
        }
    }
    seen
}

/// The parts of a request a signature covers.
#[derive(Debug, Clone)]
pub struct Message<'a> {
    /// The request method.
    pub method: &'a str,
    /// The absolute request URI, as sent.
    pub target_uri: &'a str,
    /// Header fields with lower-case names (repeated names allowed).
    pub headers: &'a [(String, String)],
}

impl Message<'_> {
    /// The value of a component, or `None` when the message does not have it.
    pub fn component(&self, name: &str) -> Option<String> {
        // Derived components come from the parsed target address.
        let url = url::Url::parse(self.target_uri).ok();
        match name {
            "@method" => Some(self.method.to_ascii_uppercase()),
            "@target-uri" => Some(self.target_uri.to_string()),
            // The authority is the lower-case host, with the port only when it is not the default.
            "@authority" => url.as_ref().and_then(|u| {
                let host = u.host_str()?.to_ascii_lowercase();
                Some(match u.port() {
                    Some(p) => format!("{host}:{p}"),
                    None => host,
                })
            }),
            "@path" => url.map(|u| u.path().to_string()),
            // The query component always starts with a question mark, even when it is empty.
            "@query" => url.map(|u| format!("?{}", u.query().unwrap_or(""))),
            // A header field: its values trimmed and, if repeated, joined with a comma and a space.
            h if !h.starts_with('@') => {
                let values: Vec<&str> = self.headers.iter().filter(|(k, _)| k == h).map(|(_, v)| v.trim()).collect();
                (!values.is_empty()).then(|| values.join(", "))
            }
            _ => None,
        }
    }

    /// The signature base for these components and parameters.
    pub fn base(&self, components: &[&str], params: &[Param]) -> Option<(String, String)> {
        // The covered components and their values, in order.
        let mut pairs = Vec::new();
        // A component the message does not have makes the whole base impossible.
        for c in components {
            pairs.push((*c, self.component(c)?));
        }
        let p = signature_params(components, params);
        Some((signature_base(&pairs, &p), p))
    }
}

/// Signs a message with ed25519 under `label`: returns the `Signature-Input` and `Signature` field values.
pub fn sign_ed25519(
    key: &Ed25519KeyPair,
    label: &str,
    msg: &Message<'_>,
    components: &[&str],
    params: &[Param],
) -> Option<(String, String)> {
    let (base, p) = msg.base(components, params)?;
    // Ed25519 signs the base as bytes.
    let sig = key.sign(base.as_bytes());
    Some((format!("{label}={p}"), format!("{label}=:{}:", STANDARD.encode(sig.as_ref()))))
}

/// A parsed `Signature-Input` member: the label, the covered components, the serialised parameters (as signed) and
/// the `keyid` and `created` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMember {
    /// The member's label, which names its signature in the `Signature` field.
    pub label: String,
    /// The covered components, in order.
    pub components: Vec<String>,
    /// The component list and parameters exactly as they were serialised, because that text is part of what was signed.
    pub params: String,
    /// The key the signer says it used.
    pub keyid: Option<String>,
    /// When the signer says it signed, in Unix seconds.
    pub created: Option<i64>,
}

/// Reads the members of a `Signature-Input` field (inner lists of plain component names; no component parameters).
pub fn parse_signature_input(value: &str) -> Vec<InputMember> {
    let mut out = Vec::new();
    // The part of the field not read yet.
    let mut rest = value.trim();
    while !rest.is_empty() {
        // Each member is `label=(components);params`, separated by commas.
        let Some((label, after)) = rest.split_once('=') else { break };
        let after = after.trim_start();
        let Some(close) = after.find(')') else { break };
        let list = &after[..=close];
        let tail = &after[close + 1..];
        // Parameters run to the next top-level comma (strings here never contain one in practice; keep it strict).
        let end = tail.find(',').unwrap_or(tail.len());
        let params_str = tail[..end].trim_end();
        // The component names without the quotes.
        let components: Vec<String> = list
            .trim_start_matches('(')
            .trim_end_matches(')')
            .split_whitespace()
            .map(|c| c.trim_matches('"').to_string())
            .collect();
        // The two parameters the verifier reads.
        let mut keyid = None;
        let mut created = None;
        // Only the two parameters the verifier needs are read out; the rest stay in the text that is signed.
        for p in params_str.split(';').filter(|p| !p.is_empty()) {
            match p.split_once('=') {
                Some(("keyid", v)) => keyid = Some(v.trim_matches('"').to_string()),
                Some(("created", v)) => created = v.parse().ok(),
                _ => {}
            }
        }
        out.push(InputMember {
            label: label.trim().to_string(),
            components,
            params: format!("{list}{params_str}"),
            keyid,
            created,
        });
        rest = tail[end..].trim_start_matches(',').trim_start();
    }
    out
}

/// The signature bytes for `label` in a `Signature` field.
pub fn signature_for(value: &str, label: &str) -> Option<Vec<u8>> {
    // The member with this label.
    value.split(',').find_map(|m| {
        let (l, v) = m.trim().split_once('=')?;
        if l.trim() != label {
            return None;
        }
        STANDARD.decode(v.trim().trim_matches(':')).ok()
    })
}

/// Verifies the signature labelled `label` on a message with an ed25519 public key (32 bytes). Returns the parsed
/// input member when it holds.
pub fn verify_ed25519(msg: &Message<'_>, label: &str, public: &[u8]) -> Option<InputMember> {
    // The signature is found through the message's own fields.
    let input = msg.component("signature-input")?;
    let member = parse_signature_input(&input).into_iter().find(|m| m.label == label)?;
    let sig = signature_for(&msg.component("signature")?, label)?;
    let mut pairs = Vec::new();
    for c in &member.components {
        pairs.push((c.as_str(), msg.component(c)?));
    }
    let base = signature_base(&pairs, &member.params);
    // Verification fails closed: any problem is `None`.
    UnparsedPublicKey::new(&ED25519, public).verify(base.as_bytes(), &sig).ok()?;
    Some(member)
}

/// The GNAP interaction hash (RFC 9635 §4.2.3) with `sha-256`, the default `hash_method`: the client's nonce, the
/// authorization server's nonce, the interaction reference and the grant endpoint URI, joined by single newlines,
/// hashed, and encoded as URL-safe base64 without padding.
pub fn interaction_hash(client_nonce: &str, server_nonce: &str, interact_ref: &str, grant_endpoint: &str) -> String {
    // The four values joined by newlines, as the RFC defines the hash input.
    let base = format!("{client_nonce}\n{server_nonce}\n{interact_ref}\n{grant_endpoint}");
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, base.as_bytes()))
}

/// Unit tests for signatures and digests, checked against the examples the RFCs publish.
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9421 B.1.4 test-key-ed25519.
    fn test_key() -> Ed25519KeyPair {
        crate::keys::ed25519_from_pem(&crate::keys::tests::rfc9421_test_key()).unwrap()
    }

    /// Header fields from name and value pairs.
    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    /// The signature base, the signature-input and the signature value equal the published example, it verifies as received, and changing a covered header breaks it.
    #[test]
    fn rfc_9421_b_2_6_ed25519() {
        // The test-request of RFC 9421 B.2, signed as in B.2.6.
        let h = headers(&[
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            (
                "content-digest",
                "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
            ),
            ("content-length", "18"),
        ]);
        let msg = Message { method: "POST", target_uri: "https://example.com/foo?param=Value&Pet=dog", headers: &h };
        let components = ["date", "@method", "@path", "@authority", "content-type", "content-length"];
        let params = [Param::Int("created", 1618884473), Param::Str("keyid", "test-key-ed25519".into())];
        let (base, _) = msg.base(&components, &params).unwrap();
        assert_eq!(
            base,
            "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\"@method\": POST\n\"@path\": /foo\n\"@authority\": example.com\n\
             \"content-type\": application/json\n\"content-length\": 18\n\"@signature-params\": (\"date\" \"@method\" \
             \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
        );
        let (input, sig) = sign_ed25519(&test_key(), "sig-b26", &msg, &components, &params).unwrap();
        assert_eq!(
            input,
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
        );
        assert_eq!(
            sig,
            "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
        );
        // And it verifies as received.
        let mut signed = h.clone();
        signed.push(("signature-input".into(), input));
        signed.push(("signature".into(), sig));
        let received = Message { headers: &signed, ..msg.clone() };
        let public = ring::signature::KeyPair::public_key(&test_key()).as_ref().to_vec();
        let m = verify_ed25519(&received, "sig-b26", &public).unwrap();
        assert_eq!((m.keyid.as_deref(), m.created), (Some("test-key-ed25519"), Some(1618884473)));
        let mut altered = signed.clone();
        altered[4].1 = "19".into();
        assert!(verify_ed25519(&Message { headers: &altered, ..msg }, "sig-b26", &public).is_none());
    }

    /// The published example holds when uncovered parts change (a parameter added, a header added), and repeated Accept fields are joined before they are signed.
    #[test]
    fn rfc_9421_b_4_transformations() {
        // B.4: the same signature holds when uncovered parts change; repeated Accept fields are joined.
        let sig_input =
            "transform=(\"@method\" \"@path\" \"@authority\" \"accept\");created=1618884473;keyid=\"test-key-ed25519\"";
        let sig =
            "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:";
        let public = ring::signature::KeyPair::public_key(&test_key()).as_ref().to_vec();
        for (uri, extra) in [
            ("https://example.org/demo?name1=Value1&Name2=value2", None),
            (
                "https://example.org/demo?name1=Value1&Name2=value2&param=added",
                Some(("accept-language", "en-US,en;q=0.5")),
            ),
        ] {
            let mut h = headers(&[
                ("host", "example.org"),
                ("date", "Fri, 15 Jul 2022 14:24:55 GMT"),
                ("accept", "application/json"),
                ("accept", "*/*"),
                ("signature-input", sig_input),
                ("signature", sig),
            ]);
            if let Some((k, v)) = extra {
                h.push((k.into(), v.into()));
            }
            let msg = Message { method: "GET", target_uri: uri, headers: &h };
            assert!(verify_ed25519(&msg, "transform", &public).is_some(), "{uri}");
        }
    }

    /// The digests equal the published values; a list with a matching known digest is valid, one that does not match is not, and a value with no known digest is not.
    #[test]
    fn content_digests_of_rfc_9530_and_9421() {
        let body = br#"{"hello": "world"}"#;
        assert_eq!(content_digest_sha256(body), "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:");
        assert_eq!(
            content_digest_sha512(body),
            "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
        );
        assert!(content_digest_valid(&content_digest_sha512(body), body));
        assert!(content_digest_valid(
            &format!("sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:, {}", content_digest_sha512(body)),
            body
        ));
        assert!(!content_digest_valid(&content_digest_sha512(b"{}"), body));
        assert!(!content_digest_valid("md5=:AAAA:", body), "no known digest");
    }

    /// The interaction hash equals the value the RFC publishes for its example.
    #[test]
    fn gnap_interaction_hash_of_rfc_9635() {
        assert_eq!(
            interaction_hash(
                "VJLO6A4CATR0KRO",
                "MBDOFXG4Y5CVJCX821LH",
                "4IFWWIKYB2PQ6U56NL1",
                "https://server.example.com/tx"
            ),
            "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY"
        );
    }

    /// A field with two members parses into both, with the parameters as they were written.
    #[test]
    fn signature_input_parsing() {
        let v = "sig1=(\"@method\" \"@target-uri\");created=1;keyid=\"k\", sig2=(\"@method\");created=2";
        let m = parse_signature_input(v);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].params, "(\"@method\" \"@target-uri\");created=1;keyid=\"k\"");
        assert_eq!((m[1].label.as_str(), m[1].created), ("sig2", Some(2)));
    }
}
