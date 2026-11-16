//! `serve --mode static`: one page from a manifest file, no database, read-only routes (the federation inbox accepts
//! and drops). Used for the operator's own page.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Deserialize;

use link_in_bio_core::assets::{self, Bundle};
use link_in_bio_core::interop;

use crate::headers::{CACHE_IMMUTABLE, CACHE_NONE, CACHE_PAGE, secure};
use crate::site::Site;

pub type Shared = Arc<Site>;

fn respond(status: StatusCode, content_type: &str, cache: &str, body: impl Into<Body>) -> Response {
    let mut r = Response::new(body.into());
    *r.status_mut() = status;
    let h = r.headers_mut();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    r
}

fn public_json(content_type: &str, body: String) -> Response {
    let mut r = respond(StatusCode::OK, content_type, CACHE_PAGE, body);
    r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    r
}

pub fn not_found() -> Response {
    respond(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", CACHE_NONE, "Not found.\n")
}

async fn page(State(s): State<Shared>) -> Response {
    let mut r = respond(StatusCode::OK, "text/html; charset=utf-8", CACHE_PAGE, s.html.clone());
    if let Ok(v) = HeaderValue::from_str(&s.linkset_header) {
        r.headers_mut().insert(header::LINK, v);
    }
    r
}

async fn linkset(State(s): State<Shared>) -> Response {
    public_json(&format!(r#"{}; profile="{}""#, interop::LINKSET_TYPE, s.config.profile_uri), s.linkset.clone())
}

#[derive(Deserialize)]
struct WebfingerQuery {
    resource: Option<String>,
}

async fn webfinger(State(s): State<Shared>, Query(q): Query<WebfingerQuery>) -> Response {
    match q.resource {
        Some(r) if s.answers_webfinger(&r) => public_json("application/jrd+json", s.webfinger.clone()),
        Some(_) => not_found(),
        None => respond(StatusCode::BAD_REQUEST, "text/plain; charset=utf-8", CACHE_NONE, "resource is required\n"),
    }
}

async fn actor(State(s): State<Shared>) -> Response {
    match &s.actor {
        Some(a) => public_json(interop::ACTIVITY_TYPE, a.clone()),
        None => not_found(),
    }
}

async fn outbox(State(s): State<Shared>) -> Response {
    if s.actor.is_none() {
        return not_found();
    }
    let actor_url = format!("{}actor", s.config.base_url);
    public_json(interop::ACTIVITY_TYPE, interop::outbox(&actor_url).to_string())
}

/// Activities sent to the read-only actor are accepted and dropped: the page follows no one and approves no one.
async fn inbox(State(s): State<Shared>) -> Response {
    if s.actor.is_none() {
        return not_found();
    }
    respond(StatusCode::ACCEPTED, "text/plain; charset=utf-8", CACHE_NONE, "")
}

#[derive(Deserialize)]
struct NostrQuery {
    name: Option<String>,
}

async fn nostr(State(s): State<Shared>, Query(q): Query<NostrQuery>) -> Response {
    let id = &s.manifest.identity;
    match (&id.nostr_pubkey, q.name.as_deref()) {
        (Some(key), Some(name)) if name == id.handle || name == "_" => {
            public_json("application/json", interop::nostr_json(name, key).to_string())
        }
        _ => not_found(),
    }
}

async fn atproto(State(s): State<Shared>) -> Response {
    match &s.manifest.identity.atproto_did {
        Some(did) => respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, did.clone()),
        None => not_found(),
    }
}

async fn security_txt(State(s): State<Shared>) -> Response {
    match &s.security_txt {
        Some(t) => respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, t.clone()),
        None => not_found(),
    }
}

async fn robots(State(s): State<Shared>) -> Response {
    let body = if s.manifest.meta.indexable { "User-agent: *\nAllow: /\n" } else { "User-agent: *\nDisallow: /\n" };
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, body)
}

async fn spec(State(s): State<Shared>) -> Response {
    if !s.config.serve_spec {
        return not_found();
    }
    respond(StatusCode::OK, "text/html; charset=utf-8", CACHE_PAGE, assets::spec_html())
}

/// Hashed assets under `/_/` (stylesheet, script, sprite, the picture).
pub async fn asset(State(s): State<Shared>, req: Request<Body>) -> Response {
    let path = req.uri().path();
    if let Some(a) = Bundle::get().find(path) {
        return respond(StatusCode::OK, a.content_type, CACHE_IMMUTABLE, a.body.clone());
    }
    if let Some((p, pic)) = &s.avatar
        && p == path
    {
        return respond(StatusCode::OK, pic.mime, CACHE_IMMUTABLE, pic.bytes.clone());
    }
    not_found()
}

async fn brand(State(s): State<Shared>, req: Request<Body>) -> Response {
    if !s.config.brand_icons {
        return not_found();
    }
    let (ct, body): (&str, Vec<u8>) = match req.uri().path() {
        "/favicon.svg" => ("image/svg+xml", assets::FAVICON_SVG.to_vec()),
        "/favicon.ico" => ("image/x-icon", assets::FAVICON_ICO.to_vec()),
        "/apple-touch-icon.png" => ("image/png", assets::APPLE_TOUCH_ICON.to_vec()),
        "/icon-192.png" => ("image/png", assets::ICON_192.to_vec()),
        "/icon-512.png" => ("image/png", assets::ICON_512.to_vec()),
        "/site.webmanifest" => {
            ("application/manifest+json", assets::webmanifest(&s.manifest.identity.display_name).into_bytes())
        }
        _ => return not_found(),
    };
    respond(StatusCode::OK, ct, "public, max-age=86400", body)
}

async fn healthz() -> Response {
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_NONE, "ok\n")
}

async fn version() -> Response {
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_NONE, concat!(env!("CARGO_PKG_VERSION"), "\n"))
}

/// Only GET and HEAD anywhere, except POST to the inbox; security headers on every response.
async fn guard(State(s): State<Shared>, req: Request<Body>, next: Next) -> Response {
    let allowed = matches!(*req.method(), Method::GET | Method::HEAD)
        || (req.method() == Method::POST && req.uri().path() == "/actor/inbox");
    let mut r = if allowed {
        next.run(req).await
    } else {
        let mut r =
            respond(StatusCode::METHOD_NOT_ALLOWED, "text/plain; charset=utf-8", CACHE_NONE, "Method not allowed.\n");
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        r
    };
    secure(r.headers_mut(), s.config.local, s.config.hsts);
    r
}

/// Routes shared by the static and local modes (the page and its documents).
pub fn page_routes() -> Router<Shared> {
    Router::new()
        .route("/", get(page))
        .route("/links.json", get(linkset))
        .route("/.well-known/webfinger", get(webfinger))
        .route("/.well-known/nostr.json", get(nostr))
        .route("/.well-known/atproto-did", get(atproto))
        .route("/.well-known/security.txt", get(security_txt))
        .route("/actor", get(actor))
        .route("/actor/outbox", get(outbox))
        .route("/actor/inbox", post(inbox))
        .route("/robots.txt", get(robots))
        .route("/spec/profile-links/v1", get(spec))
        .route("/favicon.svg", get(brand))
        .route("/favicon.ico", get(brand))
        .route("/apple-touch-icon.png", get(brand))
        .route("/icon-192.png", get(brand))
        .route("/icon-512.png", get(brand))
        .route("/site.webmanifest", get(brand))
        .route("/_/{file}", get(asset))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
}

pub fn router(site: Shared) -> Router {
    page_routes()
        .fallback(|| async { not_found() })
        .layer(middleware::from_fn_with_state(site.clone(), guard))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(site)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SiteConfig;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn site() -> Shared {
        let config = SiteConfig::from_json(
            br#"{"baseUrl":"https://meddleware.link/","owner":"operator","serveSpec":true,"brandIcons":true,"securityContact":"mailto:security@example.org"}"#,
        )
        .unwrap();
        let manifest = br#"{"schema":1,"identity":{"kind":"organization","displayName":"Meddleware","handle":"meddleware","nostrPubkey":"0000000000000000000000000000000000000000000000000000000000000001","atprotoDid":"did:plc:abcdefghijklmnopqrstuvwx"},
            "items":[{"id":"gh","title":"GitHub","url":"https://github.com/meddleware-org","identity":true}]}"#;
        Arc::new(Site::build(config, manifest, std::path::Path::new("."), None, 1_794_787_200).unwrap())
    }

    async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let r = router(site()).oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        let (parts, body) = r.into_parts();
        (parts.status, parts.headers, String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    #[tokio::test]
    async fn page_has_security_headers_and_the_linkset_link() {
        let (st, h, body) = get("/").await;
        assert_eq!(st, StatusCode::OK);
        assert!(h[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains("default-src 'none'"));
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
        assert!(h.get(header::SET_COOKIE).is_none());
        assert!(h[header::LINK].to_str().unwrap().contains(r#"rel="linkset""#));
        assert!(body.contains("rel=\"me noopener noreferrer\""));
    }

    #[tokio::test]
    async fn documents() {
        let (st, h, body) = get("/links.json").await;
        assert_eq!(st, StatusCode::OK);
        assert!(h[header::CONTENT_TYPE].to_str().unwrap().starts_with("application/linkset+json; profile="));
        assert!(body.contains("rel-me"));
        assert_eq!(get("/.well-known/webfinger?resource=acct:meddleware@meddleware.link").await.0, StatusCode::OK);
        assert_eq!(get("/.well-known/webfinger?resource=acct:other@meddleware.link").await.0, StatusCode::NOT_FOUND);
        assert_eq!(get("/.well-known/nostr.json?name=meddleware").await.0, StatusCode::OK);
        assert_eq!(get("/.well-known/atproto-did").await.2, "did:plc:abcdefghijklmnopqrstuvwx");
        assert!(get("/.well-known/security.txt").await.2.contains("Expires: 2027-11-16"));
        assert_eq!(get("/actor").await.0, StatusCode::OK);
        assert_eq!(get("/spec/profile-links/v1").await.0, StatusCode::OK);
        assert_eq!(get("/favicon.svg").await.0, StatusCode::OK);
        let css = Bundle::get().css.path.clone();
        let (st, h, _) = get(&css).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h[header::CACHE_CONTROL], CACHE_IMMUTABLE);
    }

    #[tokio::test]
    async fn refuses_other_methods_and_unknown_paths() {
        let r = router(site()).oneshot(Request::post("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(get("/.env").await.0, StatusCode::NOT_FOUND);
        assert_eq!(get("/_/page.css").await.0, StatusCode::NOT_FOUND);
        let r = router(site()).oneshot(Request::post("/actor/inbox").body(Body::from("{}")).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::ACCEPTED);
    }
}
