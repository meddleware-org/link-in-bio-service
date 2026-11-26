//! Tenant pages by host: `<handle>.<PAGES_DOMAIN>`, or a verified custom domain when custom domains are on. Each page
//! is built once from its published document (through the same parser and renderer as the operator's page) and
//! served by the static router; the built page is reused for a short time, so a suspension, a flagged link or a new
//! version shows within that time.
//!
//! What a visitor sees when there is no page to show: 404 (no such page, not published, not paid, or third-party
//! pages switched off), 410 (removed under the acceptable use policy, or deleted), 451 (withheld on legal grounds),
//! 403 (suspended for a time). Every response carries the page security headers and never a cookie.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderValue, Request, StatusCode, header};
use axum::response::Response;
use tokio::sync::Mutex;
use tower::ServiceExt;

use link_in_bio_assets::Avatar as Picture;
use link_in_bio_core::manifest::Item;
use link_in_bio_store::{AssetRow, sha256};

use super::{Shared, metrics::Metrics};
use crate::headers::{CACHE_NONE, secure};
use crate::site::Site;
use crate::static_mode;

/// What a host resolves to.
#[derive(Clone)]
enum Built {
    /// A page: the router that serves its documents.
    Page(Router),
    /// No page: the status and the words to answer with.
    Status(StatusCode, &'static str),
}

/// The page cache: what each host showed when it was last built, reused for a short time (the TTL).
pub struct PageCache {
    /// How long a built page is reused.
    ttl: Duration,
    /// The built result by host name, with when it was built.
    entries: Mutex<HashMap<String, (Instant, Built)>>,
}

impl PageCache {
    /// A cache that reuses a built page for `ttl`.
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Mutex::new(HashMap::new()) }
    }

    /// Drops what this process remembers about a host (its own changes show at once; other replicas within the TTL).
    pub async fn forget(&self, host: &str) {
        self.entries.lock().await.remove(host);
    }

    /// Remembers what a host shows. The cache holds at most [`MAX_HOSTS`] hosts: past that, expired entries go, and if
    /// every entry is still fresh (a flood of made-up host names) the cache starts again, so memory stays bounded.
    async fn insert(&self, host: &str, built: Built) {
        let mut entries = self.entries.lock().await;
        if entries.len() >= MAX_HOSTS {
            entries.retain(|_, (at, _)| at.elapsed() < self.ttl);
            if entries.len() >= MAX_HOSTS {
                entries.clear();
            }
        }
        entries.insert(host.to_string(), (Instant::now(), built));
    }
}

/// The most hosts the page cache remembers at once.
pub const MAX_HOSTS: usize = 10_000;

/// A plain-text answer with the page security headers (and strict transport security), never cached.
fn status(code: StatusCode, text: &'static str) -> Response {
    let mut r = Response::new(Body::from(format!("{text}\n")));
    *r.status_mut() = code;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    secure(h, false, true);
    r
}

/// A stored picture as the renderer takes it.
pub fn picture_of(a: AssetRow) -> Option<Picture> {
    // Only the three picture types the pipeline can produce are accepted, so anything else in the store is ignored.
    let mime = match a.mime.as_str() {
        "image/png" => "image/png",
        "image/jpeg" => "image/jpeg",
        "image/svg+xml" => "image/svg+xml",
        _ => return None,
    };
    let ext = match a.ext.as_str() {
        "png" => "png",
        "jpg" => "jpg",
        "svg" => "svg",
        _ => return None,
    };
    Some(Picture { bytes: a.bytes, mime, ext, width: a.width as u32, height: a.height as u32, sha256: a.sha256 })
}

/// Builds what a host shows now.
async fn build(app: &Shared, host: &str) -> Result<Built, link_in_bio_store::DbError> {
    // Resolve the host to an account, apply what the account's state allows, parse the published document with the same rules as at publish time, hide links screening flagged, and build the page.
    // The configuration holds the pages domain, the switches and the grace period.
    let c = &app.config;
    // A host on the pages domain names its handle; otherwise it may be a verified custom domain.
    let handle = match c.handle_of_host(host) {
        Some(h) => h.to_string(),
        None if c.custom_hostname_cap > 0 => match app.store.view_domain(host).await? {
            Some(h) => h,
            None => return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here.")),
        },
        None => return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here.")),
    };
    let Some(p) = app.store.view_page(&handle).await? else {
        return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here."));
    };
    // Each state of the account has its own answer: deleted, legal, timed, or removed.
    match (p.status.as_str(), p.suspension_kind.as_deref(), p.suspended_until) {
        ("deleted", _, _) => return Ok(Built::Status(StatusCode::GONE, "This page has been deleted.")),
        ("suspended", Some("legal"), _) => {
            return Ok(Built::Status(
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                "This page is not available for legal reasons.",
            ));
        }
        ("suspended", _, Some(_)) => {
            return Ok(Built::Status(StatusCode::FORBIDDEN, "This page is suspended for now."));
        }
        ("suspended", _, None) => {
            return Ok(Built::Status(StatusCode::GONE, "This page was removed under the acceptable use policy."));
        }
        _ => {}
    }
    let now = super::now();
    // Free and operator accounts are always entitled; others must be paid up within the grace period.
    let entitled = p.free || p.operator || p.paid_until.is_some_and(|u| u + time::Duration::days(c.grace_days) > now);
    // While third-party pages are off only the operator's own pages are served.
    if (!c.third_party_pages && !p.operator) || !entitled {
        return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here."));
    }
    // An account with no published document has no page.
    let Some(doc) = p.published else { return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here.")) };
    let parsed = match link_in_bio_core::parse(doc.as_bytes(), super::account_page_options()) {
        Ok(p) => p,
        Err(issues) => {
            // A stored document the current parser refuses (a rule tightened after it was published): not served.
            tracing::warn!(handle, problems = issues.len(), "published page no longer parses");
            return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here."));
        }
    };
    // Work on the parsed document, which the screening can change in memory only.
    let mut manifest = parsed.manifest;
    // Hide links screening flagged.
    // Only the hashes of the links go to the view, never the page.
    let hashes: Vec<Vec<u8>> = manifest.visible_links().map(|l| sha256(l.url.as_bytes())).collect();
    let flagged = app.store.view_flagged(&hashes).await?;
    if !flagged.is_empty() {
        for item in &mut manifest.items {
            let links: Vec<&mut link_in_bio_core::manifest::Link> = match item {
                Item::Link(l) => vec![l],
                Item::Group(g) => g.items.iter_mut().collect(),
            };
            for l in links {
                if flagged.contains(&sha256(l.url.as_bytes())) {
                    l.hidden = true;
                }
            }
        }
    }
    // A hosted picture is named by its hash and read from the public view.
    let picture = match manifest.identity.avatar.as_deref().and_then(|a| a.strip_prefix("sha256:")) {
        Some(hex) => app.store.view_asset(hex).await?.and_then(picture_of),
        None => None,
    };
    // The site configuration for this handle and host.
    let site_config = match c.site_for(&handle, host) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "tenant site configuration");
            return Ok(Built::Status(StatusCode::SERVICE_UNAVAILABLE, "This page is unavailable right now."));
        }
    };
    let site =
        Site::from_parts(site_config, manifest, parsed.warnings, picture, None, now.unix_timestamp().max(0) as u64);
    // The same router as the operator's page serves every document of the page.
    Ok(Built::Page(static_mode::router(Arc::new(site))))
}

/// Resolve a host to what it shows now, from the cache while it is fresh.
async fn resolve(app: &Shared, host: &str) -> Built {
    {
        // The lock is held only for the lookup, not for the build.
        let entries = app.pages.entries.lock().await;
        if let Some((at, b)) = entries.get(host)
            && at.elapsed() < app.pages.ttl
        {
            return b.clone();
        }
    }
    let built = match build(app, host).await {
        Ok(b) => b,
        // The database is down: say so, and do not remember it.
        // A database failure is not cached.
        Err(_) => return Built::Status(StatusCode::SERVICE_UNAVAILABLE, "This page is unavailable right now."),
    };
    app.pages.insert(host, built.clone()).await;
    built
}

/// The Host a request names, lower-case and without a port.
pub fn request_host(req: &Request<Body>) -> Option<String> {
    // The port is dropped and the name lower-cased, so the same host always has one cache key.
    let h = req.headers().get(header::HOST)?.to_str().ok()?;
    let h = h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(h, |(h, _)| h);
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    (!h.is_empty() && h.len() <= 253).then_some(h)
}

/// Answer a request: a status for a host with no page, otherwise the page's own router.
async fn serve(State(app): State<Shared>, req: Request<Body>) -> Response {
    // Anything else a page serves is handled by the same router as the operator's page.
    // A request without a host cannot be routed.
    let Some(host) = request_host(&req) else { return status(StatusCode::BAD_REQUEST, "No host.") };
    // The probe needs no database.
    if req.uri().path() == "/healthz" {
        return status(StatusCode::OK, "ok");
    }
    match resolve(&app, &host).await {
        Built::Status(code, text) => status(code, text),
        Built::Page(router) => {
            Metrics::inc(&app.metrics.pages_served);
            match router.oneshot(req).await {
                Ok(r) => r,
                Err(never) => match never {},
            }
        }
    }
}

/// The page process's router: every path of every tenant host.
pub fn router(app: Shared) -> Router {
    // Bodies are at most 64 KiB (the inbox, which reads none) and 16 KiB at the ingress.
    super::bounded(Router::new().fallback(serve).with_state(app), super::REQUEST_TIMEOUT, 128)
}

/// Unit tests for the page cache.
#[cfg(test)]
mod cache_tests {
    use super::*;

    /// Far more fresh hosts than the limit never grow the cache past it, and the newest host is always remembered.
    #[tokio::test]
    async fn the_cache_stays_bounded_under_a_flood_of_fresh_hosts() {
        // A cache that does not expire during the test.
        let cache = PageCache::new(Duration::from_secs(600));
        for i in 0..(MAX_HOSTS * 3) {
            cache.insert(&format!("h{i}.example.link"), Built::Status(StatusCode::NOT_FOUND, "none")).await;
            assert!(cache.entries.lock().await.len() <= MAX_HOSTS);
        }
        // The newest host is always remembered.
        assert!(cache.entries.lock().await.contains_key(&format!("h{}.example.link", MAX_HOSTS * 3 - 1)));
    }
}
