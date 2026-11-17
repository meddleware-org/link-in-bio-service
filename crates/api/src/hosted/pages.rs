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
    Page(Router),
    Status(StatusCode, &'static str),
}

pub struct PageCache {
    ttl: Duration,
    entries: Mutex<HashMap<String, (Instant, Built)>>,
}

impl PageCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ttl, entries: Mutex::new(HashMap::new()) }
    }

    /// Drops what this process remembers about a host (its own changes show at once; other replicas within the TTL).
    pub async fn forget(&self, host: &str) {
        self.entries.lock().await.remove(host);
    }
}

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
    let c = &app.config;
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
    let entitled = p.free || p.operator || p.paid_until.is_some_and(|u| u + chrono::Duration::days(c.grace_days) > now);
    if (!c.third_party_pages && !p.operator) || !entitled {
        return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here."));
    }
    let Some(doc) = p.published else { return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here.")) };
    let parsed = match link_in_bio_core::parse(doc.as_bytes(), super::account_page_options()) {
        Ok(p) => p,
        Err(issues) => {
            // A stored document the current parser refuses (a rule tightened after it was published): not served.
            tracing::warn!(handle, problems = issues.len(), "published page no longer parses");
            return Ok(Built::Status(StatusCode::NOT_FOUND, "There is no page here."));
        }
    };
    let mut manifest = parsed.manifest;
    // Hide links screening flagged.
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
    let picture = match manifest.identity.avatar.as_deref().and_then(|a| a.strip_prefix("sha256:")) {
        Some(hex) => app.store.view_asset(hex).await?.and_then(picture_of),
        None => None,
    };
    let site_config = match c.site_for(&handle, host) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "tenant site configuration");
            return Ok(Built::Status(StatusCode::SERVICE_UNAVAILABLE, "This page is unavailable right now."));
        }
    };
    let site = Site::from_parts(site_config, manifest, parsed.warnings, picture, None, now.timestamp().max(0) as u64);
    Ok(Built::Page(static_mode::router(Arc::new(site))))
}

async fn resolve(app: &Shared, host: &str) -> Built {
    {
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
        Err(_) => return Built::Status(StatusCode::SERVICE_UNAVAILABLE, "This page is unavailable right now."),
    };
    let mut entries = app.pages.entries.lock().await;
    if entries.len() > 10_000 {
        entries.retain(|_, (at, _)| at.elapsed() < app.pages.ttl);
    }
    entries.insert(host.to_string(), (Instant::now(), built.clone()));
    built
}

/// The Host a request names, lower-case and without a port.
pub fn request_host(req: &Request<Body>) -> Option<String> {
    let h = req.headers().get(header::HOST)?.to_str().ok()?;
    let h = h.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(h, |(h, _)| h);
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    (!h.is_empty() && h.len() <= 253).then_some(h)
}

async fn serve(State(app): State<Shared>, req: Request<Body>) -> Response {
    let Some(host) = request_host(&req) else { return status(StatusCode::BAD_REQUEST, "No host.") };
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
    Router::new().fallback(serve).with_state(app)
}
