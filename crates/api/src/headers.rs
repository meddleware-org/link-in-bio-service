//! Response headers every page response carries. Pages run no script but their own same-origin enhancement, load
//! nothing from elsewhere, cannot be framed, send no referrer, and never set a cookie.

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

/// The page Content-Security-Policy. Every resource is same-origin and relative, and the edge serves HTTPS only, so
/// `upgrade-insecure-requests` would add nothing (and breaks plain-HTTP loopback in WebKit, which upgrades localhost).
pub fn page_csp() -> &'static str {
    "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; manifest-src 'self'; \
     base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}

/// Adds the security headers to a response.
pub fn secure(h: &mut HeaderMap, local: bool, hsts: bool) {
    let set = |h: &mut HeaderMap, k: HeaderName, v: &str| {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(k, v);
        }
    };
    set(h, header::CONTENT_SECURITY_POLICY, page_csp());
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(h, header::X_FRAME_OPTIONS, "DENY");
    set(h, HeaderName::from_static("cross-origin-opener-policy"), "same-origin");
    set(
        h,
        HeaderName::from_static("permissions-policy"),
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()",
    );
    if hsts && !local {
        set(h, header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains");
    }
    // Never a cookie, whatever a handler did.
    h.remove(header::SET_COOKIE);
}

pub const CACHE_PAGE: &str = "public, max-age=300";
pub const CACHE_IMMUTABLE: &str = "public, max-age=31536000, immutable";
pub const CACHE_NONE: &str = "no-store";
