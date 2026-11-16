//! Sessions: a 256-bit random token in a host-only cookie; the server keeps only its SHA-256. And the CSRF rule every
//! state-changing request of the app API must pass.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Duration;
use sha2::{Digest, Sha256};

/// The cookie name. `__Host-` makes the browser refuse it unless it is `Secure`, has `Path=/` and no `Domain`: it is
/// sent only to the app host, never to a tenant page on a sibling host.
pub const COOKIE: &str = "__Host-lib_session";
/// The header a state-changing request must carry (a cross-site form cannot set it; a cross-site `fetch` with it needs
/// CORS, which the app API never grants).
pub const CSRF_HEADER: &str = "x-link-in-bio-request";
/// A session ends after this long without use.
pub const IDLE: Duration = Duration::days(14);
/// And after this long in any case.
pub const ABSOLUTE: Duration = Duration::days(60);

/// A new token: the cookie value and the hash to store.
pub fn new_token() -> (String, Vec<u8>) {
    let raw = crate::random_bytes::<32>();
    let value = URL_SAFE_NO_PAD.encode(raw);
    let hash = hash(&value);
    (value, hash)
}

/// The stored form of a cookie value.
pub fn hash(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

/// A cookie value has the shape [`new_token`] makes (43 characters of base64url); anything else is not looked up.
pub fn plausible(value: &str) -> bool {
    value.len() == 43 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The `Set-Cookie` value for a session (`max_age` seconds), or for clearing it (`None`).
pub fn set_cookie(value: Option<&str>, max_age: i64) -> String {
    match value {
        Some(v) => format!("{COOKIE}={v}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={max_age}"),
        None => format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0"),
    }
}

/// The session cookie's value in a `Cookie` header.
pub fn from_cookie_header(header: &str) -> Option<&str> {
    header.split(';').map(str::trim).find_map(|c| c.strip_prefix(COOKIE)?.strip_prefix('=')).filter(|v| plausible(v))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CsrfError {
    #[error("the request did not come from the app")]
    Origin,
    #[error("the request header {CSRF_HEADER} is missing")]
    Header,
}

/// The CSRF rule for a state-changing method: `Origin` must be the app's origin exactly and the custom header must be
/// present. (Safe methods are not checked; they change nothing.)
pub fn check_csrf(origin: Option<&str>, has_header: bool, app_origin: &str) -> Result<(), CsrfError> {
    if origin != Some(app_origin) {
        return Err(CsrfError::Origin);
    }
    if !has_header {
        return Err(CsrfError::Header);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_and_cookies() {
        let (v, h) = new_token();
        assert!(plausible(&v));
        assert_eq!(hash(&v), h);
        assert_ne!(new_token().0, v);
        let header = format!("other=1; {COOKIE}={v}; x=y");
        assert_eq!(from_cookie_header(&header), Some(v.as_str()));
        assert_eq!(from_cookie_header(&format!("{COOKIE}=short")), None);
        assert_eq!(from_cookie_header(&format!("{COOKIE}x={v}")), None);
        assert!(set_cookie(Some(&v), 60).contains("SameSite=Strict"));
        assert!(set_cookie(None, 0).contains("Max-Age=0"));
    }

    #[test]
    fn csrf() {
        let app = "https://app.example.link";
        assert_eq!(check_csrf(Some(app), true, app), Ok(()));
        assert_eq!(check_csrf(Some("https://alice.example.link"), true, app), Err(CsrfError::Origin));
        assert_eq!(check_csrf(None, true, app), Err(CsrfError::Origin));
        assert_eq!(check_csrf(Some(app), false, app), Err(CsrfError::Header));
    }
}
