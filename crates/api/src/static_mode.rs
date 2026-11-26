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
// The documents the router serves are built by the core crate.
use link_in_bio_core::interop;

use crate::headers::{CACHE_IMMUTABLE, CACHE_NONE, CACHE_PAGE, secure};
use crate::site::Site;

/// The built site, shared between requests; it is read-only after it is built.
pub type Shared = Arc<Site>;

/// An answer with a status, a content type, a cache rule and a body.
fn respond(status: StatusCode, content_type: &str, cache: &str, body: impl Into<Body>) -> Response {
    // The status and the two headers are set on the answer.
    // The body, then the status and the headers.
    let mut r = Response::new(body.into());
    *r.status_mut() = status;
    let h = r.headers_mut();
    // A value that is not a valid header value is skipped, never a panic.
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(cache) {
        h.insert(header::CACHE_CONTROL, v);
    }
    r
}

/// A public document, readable from any origin (so other software in a browser can read the page's interop documents).
fn public_json(content_type: &str, body: String) -> Response {
    let mut r = respond(StatusCode::OK, content_type, CACHE_PAGE, body);
    // Public documents are readable by any origin.
    r.headers_mut().insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    r
}

/// The one 404 answer.
pub fn not_found() -> Response {
    respond(StatusCode::NOT_FOUND, "text/plain; charset=utf-8", CACHE_NONE, "Not found.\n")
}

/// The page, with the `Link` header that points software at the Profile Links document.
async fn page(State(s): State<Shared>) -> Response {
    let mut r = respond(StatusCode::OK, "text/html; charset=utf-8", CACHE_PAGE, s.html.clone());
    if let Ok(v) = HeaderValue::from_str(&s.linkset_header) {
        r.headers_mut().insert(header::LINK, v);
    }
    r
}

/// The Profile Links document with its media type and profile.
async fn linkset(State(s): State<Shared>) -> Response {
    // The media type carries the profile, as RFC 9264 allows.
    public_json(&format!(r#"{}; profile="{}""#, interop::LINKSET_TYPE, s.config.profile_uri), s.linkset.clone())
}

/// The query of a WebFinger request.
#[derive(Deserialize)]
struct WebfingerQuery {
    /// The account the caller asks about (`acct:handle@host`) or the page's address.
    resource: Option<String>,
}

/// The WebFinger answer for the page's own account only; no `resource` is a bad request.
async fn webfinger(State(s): State<Shared>, Query(q): Query<WebfingerQuery>) -> Response {
    // Only this page's own account and address are answered; anything else is a 404, so nothing about other names leaks.
    // No resource is a bad request; a resource that is not this account is not found.
    match q.resource {
        Some(r) if s.answers_webfinger(&r) => public_json("application/jrd+json", s.webfinger.clone()),
        Some(_) => not_found(),
        None => respond(StatusCode::BAD_REQUEST, "text/plain; charset=utf-8", CACHE_NONE, "resource is required\n"),
    }
}

/// The read-only ActivityPub actor, when federation is on.
async fn actor(State(s): State<Shared>) -> Response {
    match &s.actor {
        Some(a) => public_json(interop::ACTIVITY_TYPE, a.clone()),
        None => not_found(),
    }
}

/// The actor's empty outbox, when federation is on.
async fn outbox(State(s): State<Shared>) -> Response {
    if s.actor.is_none() {
        return not_found();
    }
    // The outbox is an empty collection that belongs to the actor.
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

/// The query of a NIP-05 request.
#[derive(Deserialize)]
struct NostrQuery {
    /// The name the caller asks about.
    name: Option<String>,
}

/// The NIP-05 answer for the page's handle (or `_`), when a key is set.
async fn nostr(State(s): State<Shared>, Query(q): Query<NostrQuery>) -> Response {
    // The identity holds the handle and the key.
    let id = &s.manifest.identity;
    match (&id.nostr_pubkey, q.name.as_deref()) {
        // The handle, or the special name `_` for the whole domain, is answered.
        (Some(key), Some(name)) if name == id.handle || name == "_" => {
            public_json("application/json", interop::nostr_json(name, key).to_string())
        }
        _ => not_found(),
    }
}

/// The AT Protocol handle file: the DID, as plain text, when set.
async fn atproto(State(s): State<Shared>) -> Response {
    match &s.manifest.identity.atproto_did {
        Some(did) => respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, did.clone()),
        None => not_found(),
    }
}

/// The security.txt, when a contact is configured.
async fn security_txt(State(s): State<Shared>) -> Response {
    match &s.security_txt {
        Some(t) => respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, t.clone()),
        None => not_found(),
    }
}

/// Allow or disallow all crawling, from the page's own indexing choice.
async fn robots(State(s): State<Shared>) -> Response {
    // The same choice the page makes in its own markup.
    let body = if s.manifest.meta.indexable { "User-agent: *\nAllow: /\n" } else { "User-agent: *\nDisallow: /\n" };
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_PAGE, body)
}

/// The Profile Links specification as an HTML page, when the site serves it.
async fn spec(State(s): State<Shared>) -> Response {
    // The specification is served only where it is configured.
    if !s.config.serve_spec {
        return not_found();
    }
    respond(StatusCode::OK, "text/html; charset=utf-8", CACHE_PAGE, assets::spec_html())
}

/// Hashed assets under `/_/` (stylesheet, script, sprite, the picture).
pub async fn asset(State(s): State<Shared>, req: Request<Body>) -> Response {
    // Hashed paths are immutable, so they are cached for a year.
    let path = req.uri().path();
    if let Some(a) = Bundle::get().find(path) {
        return respond(StatusCode::OK, a.content_type, CACHE_IMMUTABLE, a.body.clone());
    }
    // The page's own picture is served at its content-hashed path.
    if let Some((p, pic)) = &s.avatar
        && p == path
    {
        return respond(StatusCode::OK, pic.mime, CACHE_IMMUTABLE, pic.bytes.clone());
    }
    not_found()
}

/// The brand icons and the web app manifest, only when the site uses them.
async fn brand(State(s): State<Shared>, req: Request<Body>) -> Response {
    // A path that is not one of the six files is a 404 even though the route is shared.
    if !s.config.brand_icons {
        return not_found();
    }
    // Each path gives its media type and bytes.
    let (ct, body): (&str, Vec<u8>) = match req.uri().path() {
        "/favicon.svg" => ("image/svg+xml", assets::FAVICON_SVG.to_vec()),
        "/favicon.ico" => ("image/x-icon", assets::FAVICON_ICO.to_vec()),
        "/apple-touch-icon.png" => ("image/png", assets::APPLE_TOUCH_ICON.to_vec()),
        "/icon-192.png" => ("image/png", assets::ICON_192.to_vec()),
        "/icon-512.png" => ("image/png", assets::ICON_512.to_vec()),
        // The web app manifest is built from the page's name.
        "/site.webmanifest" => {
            ("application/manifest+json", assets::webmanifest(&s.manifest.identity.display_name).into_bytes())
        }
        _ => return not_found(),
    };
    // Icons are cached for a day, because their names are not hashed.
    respond(StatusCode::OK, ct, "public, max-age=86400", body)
}

/// Liveness: the process is up.
async fn healthz() -> Response {
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_NONE, "ok\n")
}

/// The version of the binary.
async fn version() -> Response {
    // The version is compiled in.
    respond(StatusCode::OK, "text/plain; charset=utf-8", CACHE_NONE, concat!(env!("CARGO_PKG_VERSION"), "\n"))
}

/// Only GET and HEAD anywhere, except POST to the inbox; security headers on every response.
async fn guard(State(s): State<Shared>, req: Request<Body>, next: Next) -> Response {
    // Reads, and the one write the read-only actor accepts.
    let allowed = matches!(*req.method(), Method::GET | Method::HEAD)
        || (req.method() == Method::POST && req.uri().path() == "/actor/inbox");
    let mut r = if allowed {
        next.run(req).await
    } else {
        let mut r =
            respond(StatusCode::METHOD_NOT_ALLOWED, "text/plain; charset=utf-8", CACHE_NONE, "Method not allowed.\n");
        // A 405 names the methods that are allowed.
        r.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        r
    };
    // Security headers go on every answer, including the refusals.
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

/// The static router: the page routes, a 404 for everything else, the guard, and a small body limit.
pub fn router(site: Shared) -> Router {
    page_routes()
        .fallback(|| async { not_found() })
        .layer(middleware::from_fn_with_state(site.clone(), guard))
        // A small body limit: the only thing accepted is an inbox activity, which is dropped.
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(site)
}

/// Unit tests for the static router.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SiteConfig;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A site for the tests: the operator's page with an organisation identity, a Nostr key, a DID and one profile link.
    fn site() -> Shared {
        let config = SiteConfig::from_json(
            br#"{"baseUrl":"https://meddleware.link/","owner":"operator","serveSpec":true,"brandIcons":true,"securityContact":"mailto:security@example.org"}"#,
        )
        .unwrap();
        // An organisation page with a Nostr key, a DID and one profile link.
        let manifest = br#"{"schema":1,"identity":{"kind":"organization","displayName":"Meddleware","handle":"meddleware","nostrPubkey":"0000000000000000000000000000000000000000000000000000000000000001","atprotoDid":"did:plc:abcdefghijklmnopqrstuvwx"},
            "items":[{"id":"gh","title":"GitHub","url":"https://github.com/meddleware-org","identity":true}]}"#;
        Arc::new(Site::build(config, manifest, std::path::Path::new("."), None, 1_794_787_200).unwrap())
    }

    /// Request a path from a fresh router and return the status, the headers and the body.
    async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let r = router(site()).oneshot(Request::get(path).body(Body::empty()).unwrap()).await.unwrap();
        let (parts, body) = r.into_parts();
        (parts.status, parts.headers, String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    /// The page carries the content policy, the no-referrer policy and no cookie, advertises its link set, and marks the person's own profile with `rel="me"`.
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

    /// The interop documents answer: the link set with its media type, WebFinger for the page's account only, NIP-05, the DID, security.txt with its expiry, the actor, the specification, the icons and an immutable hashed stylesheet.
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
        // The expiry is a year after the fixed build time.
        assert!(get("/.well-known/security.txt").await.2.contains("Expires: 2027-11-16"));
        assert_eq!(get("/actor").await.0, StatusCode::OK);
        assert_eq!(get("/spec/profile-links/v1").await.0, StatusCode::OK);
        assert_eq!(get("/favicon.svg").await.0, StatusCode::OK);
        let css = Bundle::get().css.path.clone();
        let (st, h, _) = get(&css).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h[header::CACHE_CONTROL], CACHE_IMMUTABLE);
    }

    /// Other methods are refused with 405, unknown and unhashed paths are 404, and the inbox accepts and drops.
    #[tokio::test]
    async fn refuses_other_methods_and_unknown_paths() {
        let r = router(site()).oneshot(Request::post("/").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(get("/.env").await.0, StatusCode::NOT_FOUND);
        // An unhashed name is not served.
        assert_eq!(get("/_/page.css").await.0, StatusCode::NOT_FOUND);
        let r = router(site()).oneshot(Request::post("/actor/inbox").body(Body::from("{}")).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::ACCEPTED);
    }
}
