//! Link targets: `https:` and `mailto:` only. Everything else (including `http:`, `javascript:`, `data:`, `file:`,
//! relative URLs and credentials in the authority) is refused at the trust boundary.

use url::{Host, Url};

/// Longest accepted URL, in bytes after normalisation.
pub const MAX_URL_BYTES: usize = 2048;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlError {
    Invalid,
    Scheme,
    Credentials,
    NoHost,
    IpHost,
    TooLong,
    Mailto,
}

impl UrlError {
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
    Https,
    Mailto,
}

/// Parses, normalises and checks a link target. Returns the normalised form (IDN hosts in punycode).
pub fn check_link(input: &str) -> Result<(String, UrlKind), UrlError> {
    let input = input.trim();
    if input.len() > MAX_URL_BYTES {
        return Err(UrlError::TooLong);
    }
    // Reject control characters, spaces and backslashes before the parser silently strips or rewrites them.
    if input.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return Err(UrlError::Invalid);
    }
    let url = Url::parse(input).map_err(|_| UrlError::Invalid)?;
    match url.scheme() {
        "https" => {
            if !url.username().is_empty() || url.password().is_some() {
                return Err(UrlError::Credentials);
            }
            match url.host() {
                None => return Err(UrlError::NoHost),
                Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(UrlError::IpHost),
                Some(Host::Domain(d)) if !d.contains('.') => return Err(UrlError::NoHost),
                Some(Host::Domain(_)) => {}
            }
        }
        "mailto" => check_mailto(&url)?,
        _ => return Err(UrlError::Scheme),
    }
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

fn check_mailto(url: &Url) -> Result<(), UrlError> {
    let addr = percent_decode(url.path());
    if addr.contains(',') || !is_valid_address(&addr) {
        return Err(UrlError::Mailto);
    }
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

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("a={s}").as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()
}

/// A deliberately simple address check: one `@`, a non-empty local part without spaces or angle brackets, and a
/// domain with a dot. (Deliverability is the mail system's job; the point here is "one address, nothing else".)
pub fn is_valid_address(addr: &str) -> bool {
    let mut parts = addr.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else { return false };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_and_mailto() {
        assert_eq!(check_link("https://example.org/a?b=1#c").unwrap().0, "https://example.org/a?b=1#c");
        assert_eq!(check_link("mailto:hello@example.org").unwrap().1, UrlKind::Mailto);
        assert!(check_link("mailto:hello@example.org?subject=Hi%20there").is_ok());
        // IDN hosts are kept in punycode.
        assert_eq!(check_link("https://bücher.example/").unwrap().0, "https://xn--bcher-kva.example/");
    }

    #[test]
    fn refuses_everything_else() {
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

    #[test]
    fn display_host_strips_www() {
        assert_eq!(display_host("https://www.example.org/x").as_deref(), Some("example.org"));
    }
}
