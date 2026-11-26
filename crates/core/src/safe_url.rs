//! Link targets: `https:` and `mailto:` only. Everything else (including `http:`, `javascript:`, `data:`, `file:`,
//! relative URLs and credentials in the authority) is refused at the trust boundary.

use url::{Host, Url};

/// Longest accepted URL, in bytes after normalisation.
pub const MAX_URL_BYTES: usize = 2048;

/// Why a link target was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    /// It does not parse, or holds a space, a control character or a backslash.
    Invalid,
    /// It is neither `https:` nor `mailto:`.
    Scheme,
    /// It has a user name or password in its authority.
    Credentials,
    /// It has no host, or a host with no dot.
    NoHost,
    /// Its host is a numeric address.
    IpHost,
    /// It is longer than the limit.
    TooLong,
    /// A `mailto:` link that is not exactly one address with an optional subject.
    Mailto,
}

impl UrlError {
    /// The stable code other software can match on.
    pub fn code(self) -> &'static str {
        match self {
            Self::Invalid => "url_invalid",
            Self::Scheme => "url_scheme",
            Self::Credentials => "url_credentials",
            Self::NoHost => "url_no_host",
            Self::IpHost => "url_ip_host",
            Self::TooLong => "url_too_long",
            Self::Mailto => "mailto_invalid",
        }
    }
    /// A sentence for the person editing the page, saying what is wrong and how to fix it.
    pub fn message(self) -> String {
        match self {
            Self::Invalid => "This is not a valid web address. Copy it from your browser's address bar.".into(),
            Self::Scheme => {
                "Only secure web addresses (starting with https://) and email links (mailto:) are allowed.".into()
            }
            Self::Credentials => "Web addresses cannot contain a user name or password.".into(),
            Self::NoHost => "This web address has no site name.".into(),
            Self::IpHost => "Use the site's name, not a numeric IP address.".into(),
            Self::TooLong => format!("This web address is too long: at most {MAX_URL_BYTES} characters."),
            Self::Mailto => {
                "Email links must be mailto: followed by one address (an optional subject is allowed).".into()
            }
        }
    }
}

/// What kind of link a checked URL is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    /// An `https:` web address.
    Https,
    /// A `mailto:` link.
    Mailto,
}

/// Parses, normalises and checks a link target. Returns the normalised form (IDN hosts in punycode).
pub fn check_link(input: &str) -> Result<(String, UrlKind), UrlError> {
    // The length is checked before the parser runs, so a huge value costs nothing.
    let input = input.trim();
    if input.len() > MAX_URL_BYTES {
        return Err(UrlError::TooLong);
    }
    // Reject control characters, spaces and backslashes before the parser silently strips or rewrites them.
    if input.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return Err(UrlError::Invalid);
    }
    // The parser is strict about the scheme; everything that is not allowed is refused by name below.
    let url = Url::parse(input).map_err(|_| UrlError::Invalid)?;
    match url.scheme() {
        "https" => {
            if !url.username().is_empty() || url.password().is_some() {
                return Err(UrlError::Credentials);
            }
            match url.host() {
                None => return Err(UrlError::NoHost),
                Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(UrlError::IpHost),
                // A bare name such as `localhost` is refused: a link must point at a public site name.
                Some(Host::Domain(d)) if !d.contains('.') => return Err(UrlError::NoHost),
                Some(Host::Domain(_)) => {}
            }
        }
        // A mail link has its own rules.
        "mailto" => check_mailto(&url)?,
        // Any other scheme is refused, whatever its case or spelling (the parser has already lower-cased it).
        _ => return Err(UrlError::Scheme),
    }
    // The normalised form can be longer than the input (percent-encoding), so the limit is checked again.
    let out = url.to_string();
    if out.len() > MAX_URL_BYTES {
        return Err(UrlError::TooLong);
    }
    let kind = if url.scheme() == "https" { UrlKind::Https } else { UrlKind::Mailto };
    Ok((out, kind))
}

/// Only `https:`; used where a mail link makes no sense (call-to-action, profile URLs).
pub fn check_https(input: &str) -> Result<String, UrlError> {
    match check_link(input)? {
        (u, UrlKind::Https) => Ok(u),
        (_, UrlKind::Mailto) => Err(UrlError::Scheme),
    }
}

/// Check a `mailto:` link: one address, and at most a subject in the query.
fn check_mailto(url: &Url) -> Result<(), UrlError> {
    // The address is the path of a `mailto:` URL, percent-decoded before it is checked.
    let addr = percent_decode(url.path());
    // One address only: a comma would address several people.
    if addr.contains(',') || !is_valid_address(&addr) {
        return Err(UrlError::Mailto);
    }
    // Only a subject may follow the address; any other field (a copy, a body) is refused.
    if let Some(q) = url.query() {
        for pair in q.split('&') {
            let key = pair.split('=').next().unwrap_or("");
            if !key.eq_ignore_ascii_case("subject") {
                return Err(UrlError::Mailto);
            }
        }
    }
    Ok(())
}

/// Percent-decode a string by running it through the form-encoded parser.
fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("a={s}").as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()
}

/// A deliberately simple address check: one `@`, a non-empty local part without spaces or angle brackets, and a
/// domain with a dot. (Deliverability is the mail system's job; the point here is "one address, nothing else".)
pub fn is_valid_address(addr: &str) -> bool {
    // Exactly one `@`, splitting the address into a local part and a domain.
    let mut parts = addr.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else { return false };
    // Characters that have no place in a plain address.
    let bad = |c: char| c.is_whitespace() || c.is_control() || "<>()[]\\,;:\"".contains(c);
    !local.is_empty()
        && local.len() <= 64
        && !local.chars().any(bad)
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain.len() <= 253
        && domain.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '-')
}

/// The host of an `https:` URL, for display ("example.org").
pub fn display_host(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(|h| h.trim_start_matches("www.").to_string())
}

/// Unit tests for this module.
#[cfg(test)]
mod tests {
    use super::*;

    /// Valid web and email links pass, and an internationalised host is kept in punycode.
    #[test]
    fn accepts_https_and_mailto() {
        assert_eq!(check_link("https://example.org/a?b=1#c").unwrap().0, "https://example.org/a?b=1#c");
        assert_eq!(check_link("mailto:hello@example.org").unwrap().1, UrlKind::Mailto);
        assert!(check_link("mailto:hello@example.org?subject=Hi%20there").is_ok());
        // IDN hosts are kept in punycode.
        // The host is stored as punycode, so what is compared and linked is ASCII.
        assert_eq!(check_link("https://bücher.example/").unwrap().0, "https://xn--bcher-kva.example/");
    }

    /// Other schemes, plain http, relative links, credentials, numeric and bare hosts, spaces, backslashes, over-long links, and mail links with more than one address or any other field are refused.
    #[test]
    fn refuses_everything_else() {
        // Each of these has been used to attack a page of links or is a mistake that looks like a link.
        for bad in [
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://example.org",
            "ftp://example.org",
            "file:///etc/passwd",
            "/relative",
            "example.org",
            "https://user:pw@example.org/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://exa mple.org/",
            "https://example.org/\\evil",
            "mailto:a@example.org,b@example.org",
            "mailto:a@example.org?cc=b@example.org",
            "mailto:a@example.org?body=x",
            "mailto:not-an-address",
            "vbscript:msgbox",
        ] {
            assert!(check_link(bad).is_err(), "{bad} should be refused");
        }
        assert_eq!(check_link(&format!("https://example.org/{}", "a".repeat(3000))), Err(UrlError::TooLong));
        assert_eq!(check_https("mailto:a@example.org"), Err(UrlError::Scheme));
    }

    /// A leading `www.` is dropped from the displayed host.
    #[test]
    fn display_host_strips_www() {
        assert_eq!(display_host("https://www.example.org/x").as_deref(), Some("example.org"));
    }
}
