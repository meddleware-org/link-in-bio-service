//! `serve --mode local`: the editor's backend on the operator's own machine. It binds loopback only (the CLI refuses
//! anything else), answers only requests addressed to a loopback host (no DNS rebinding), keeps the page's files in one
//! directory, and makes no outbound request at all.

// The editor keeps its pictures in a map by path, and its site behind locks, because requests run concurrently.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
// The guard is middleware, so it wraps every route, including the fallback.
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use serde_json::{Value, json};

use link_in_bio_assets::Avatar as Picture;
use link_in_bio_core::assets::Bundle;
use link_in_bio_core::{Issue, Owner, limits, render, theme};

use crate::config::SiteConfig;
use crate::headers::{CACHE_IMMUTABLE, CACHE_NONE, secure};
use crate::site::{Site, avatar_path, context, load_avatar, parse_options};
use crate::static_mode;

/// The header every write must carry: a cross-site form or image cannot set it, and a cross-origin script would
/// need a CORS preflight this server never grants.
pub const EDITOR_HEADER: &str = "x-link-in-bio-editor";
/// The file the page document is kept in, inside the page's directory.
pub const MANIFEST_FILE: &str = "manifest.json";

/// The editor's state: the directory that holds the page's files, the port it listens on, whose page it is, the built site and the pictures it can serve.
pub struct Local {
    /// The directory holding `manifest.json` and the page's pictures.
    pub dir: PathBuf,
    /// The loopback port; a request must be addressed to it.
    pub port: u16,
    /// Whose page the editor edits.
    pub owner: Owner,
    /// The current built site, replaced whole when the document is saved.
    site: RwLock<Arc<Site>>,
    /// Normalised pictures by the path they are served at, including ones uploaded but not yet saved into a page.
    pictures: Mutex<HashMap<String, Picture>>,
}

/// The editor state, shared between requests.
pub type SharedLocal = Arc<Local>;

/// A document to start from when the directory has none.
pub fn starter_manifest() -> Value {
    json!({
        "schema": 1,
        // A page that parses as it stands, so the editor opens with something valid.
        "identity": { "displayName": "Your name", "handle": "yourname", "bio": "One line about you." },
        "items": [ { "id": "website", "title": "My website", "url": "https://example.org/" } ],
        "theme": {},
        "meta": { "lang": "en" }
    })
}

impl Local {
    /// Open a page directory: read its document (or start from the starter one), build the site, and refuse a document that is not valid, listing every problem.
    pub fn open(dir: PathBuf, port: u16, owner: Owner, now: u64) -> Result<SharedLocal, String> {
        // A missing file starts the starter document; any other read error stops the start-up.
        let path = dir.join(MANIFEST_FILE);
        // Read the document, or start from the starter if the directory has none.
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                serde_json::to_vec_pretty(&starter_manifest()).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        // The loopback configuration for this port and owner.
        let config = SiteConfig::local(port, owner);
        // A document that is not valid is an error that lists every problem, so the person can fix the file.
        let site = Site::build(config, &bytes, &dir, None, now).map_err(|e| match e {
            crate::site::SiteError::Manifest(issues) => {
                format!(
                    "{} is not valid:\n{}",
                    path.display(),
                    issues.iter().map(|i| format!("  {i}")).collect::<Vec<_>>().join("\n")
                )
            }
            other => other.to_string(),
        })?;
        // The state starts with the site and no extra pictures.
        let local = Local { dir, port, owner, site: RwLock::new(Arc::new(site)), pictures: Mutex::new(HashMap::new()) };
        local.remember_site_picture();
        Ok(Arc::new(local))
    }

    /// The current site (a poisoned lock still gives the last good one).
    fn site(&self) -> Arc<Site> {
        self.site.read().map(|s| s.clone()).unwrap_or_else(|p| p.into_inner().clone())
    }

    /// Keep the saved page's picture so it can be served.
    fn remember_site_picture(&self) {
        if let Some((path, pic)) = &self.site().avatar
            && let Ok(mut m) = self.pictures.lock()
        {
            m.insert(path.clone(), pic.clone());
        }
    }

    /// Keep a picture so it can be served at its path.
    fn remember(&self, pic: &Picture) {
        if let Ok(mut m) = self.pictures.lock() {
            m.insert(avatar_path(pic), pic.clone());
        }
    }
}

/// A JSON answer that is never cached.
fn json_response(status: StatusCode, v: Value) -> Response {
    let mut r = Response::new(Body::from(v.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

/// The errors and warnings in the shape the editor reads: `ok` is true when there are no errors.
fn issues_json(errors: &[Issue], warnings: &[Issue]) -> Value {
    json!({ "ok": errors.is_empty(), "errors": errors, "warnings": warnings })
}

/// The saved document.
async fn get_manifest(State(l): State<SharedLocal>) -> Response {
    // The manifest as the parser read it, which is what the editor edits.
    json_response(StatusCode::OK, serde_json::to_value(&l.site().manifest).unwrap_or(Value::Null))
}

/// Parse a request body as a page document for this owner.
fn parse_body(l: &Local, body: &Bytes) -> Result<link_in_bio_core::Parsed, Vec<Issue>> {
    link_in_bio_core::parse(body, parse_options(l.owner))
}

/// Check a document without saving it: refused with every error, or accepted with the warnings and the document as the parser read it.
async fn validate(State(l): State<SharedLocal>, body: Bytes) -> Response {
    match parse_body(&l, &body) {
        Ok(p) => {
            // Accepted: no errors, the warnings, and the document as read.
            let mut v = issues_json(&[], &p.warnings);
            v["manifest"] = serde_json::to_value(&p.manifest).unwrap_or(Value::Null);
            json_response(StatusCode::OK, v)
        }
        // Refused: every error, with the status 422.
        Err(errors) => json_response(StatusCode::UNPROCESSABLE_ENTITY, issues_json(&errors, &[])),
    }
}

/// Check, save and rebuild: the document is written to a temporary file and renamed, so a crash never leaves half a document, and the site is replaced only after the save succeeded.
async fn put_manifest(State(l): State<SharedLocal>, body: Bytes) -> Response {
    // The picture is loaded before anything is written, so a missing one is an error and not a half-saved page.
    let parsed = match parse_body(&l, &body) {
        Ok(p) => p,
        Err(errors) => return json_response(StatusCode::UNPROCESSABLE_ENTITY, issues_json(&errors, &[])),
    };
    let picture = match load_avatar(&parsed.manifest, &l.dir, l.owner) {
        Ok(p) => p,
        Err(e) => {
            let issue = Issue::new("identity/avatar", "avatar_invalid", e.to_string());
            return json_response(StatusCode::UNPROCESSABLE_ENTITY, issues_json(&[issue], &[]));
        }
    };
    // What is saved is the canonical form, not the bytes that were sent.
    let canonical = parsed.manifest.to_json();
    let path = l.dir.join(MANIFEST_FILE);
    // Written beside the real file and then renamed over it.
    let tmp = l.dir.join(".manifest.json.tmp");
    if let Err(e) = std::fs::write(&tmp, canonical.as_bytes()).and_then(|_| std::fs::rename(&tmp, &path)) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("cannot save: {e}") }),
        );
    }
    // The same configuration, with the new document and picture.
    let config = l.site().config.clone();
    let site = Site::from_parts(config, parsed.manifest, parsed.warnings.clone(), picture, None, 0);
    // The new site replaces the old one in one step.
    if let Ok(mut s) = l.site.write() {
        *s = Arc::new(site);
    }
    l.remember_site_picture();
    json_response(StatusCode::OK, issues_json(&[], &parsed.warnings))
}

/// Renders an unsaved document exactly as the page will look, with the sprite inlined (the editor shows it in a
/// sandboxed frame, which cannot load an external sprite).
async fn preview(State(l): State<SharedLocal>, body: Bytes) -> Response {
    let parsed = match parse_body(&l, &body) {
        Ok(p) => p,
        Err(errors) => return json_response(StatusCode::UNPROCESSABLE_ENTITY, issues_json(&errors, &[])),
    };
    // A missing picture is not an error in a preview: the page just shows none.
    let picture = load_avatar(&parsed.manifest, &l.dir, l.owner).ok().flatten();
    if let Some(p) = &picture {
        l.remember(p);
    }
    let site = l.site();
    // The context asks for the sprite to be inlined.
    let cx = context(&site.config, picture.as_ref(), true);
    let html = render::render_page(&parsed.manifest, &cx);
    let mut r = Response::new(Body::from(html));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

/// The theme's choices and the contrast table, so the editor offers only what passes.
async fn theme_options() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "options": {
                "colorMode": theme::ColorMode::names(),
                "season": theme::Season::names(),
                "accent": theme::Accent::names(),
                "buttons": theme::Buttons::names(),
                "radius": theme::Radius::names(),
                "density": theme::Density::names(),
                "layout": theme::Layout::names(),
                "font": theme::Font::names(),
            },
            "contrast": theme::option_table(),
            "textMin": theme::TEXT_MIN,
        }),
    )
}

/// Every limit, for the editor's hints.
async fn get_limits() -> Response {
    json_response(StatusCode::OK, limits::limits_json())
}

/// Accepts a picture, normalises it and stores it next to the manifest. Returns the file name to put in
/// `identity.avatar`.
async fn upload_avatar(State(l): State<SharedLocal>, headers: HeaderMap, body: Bytes) -> Response {
    // Only the operator's page may upload an SVG, and the picture is re-encoded either way before it is kept.
    let svg =
        headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("image/svg+xml"));
    // A tenant's upload is always treated as a raster picture.
    let result = if svg && l.owner == Owner::Operator {
        link_in_bio_assets::normalise_operator_svg(&body)
    } else {
        link_in_bio_assets::normalise_raster(&body)
    };
    let pic = match result {
        Ok(p) => p,
        Err(e) => {
            return json_response(StatusCode::UNPROCESSABLE_ENTITY, json!({ "ok": false, "error": e.to_string() }));
        }
    };
    // The name comes from the content hash, so the same picture is stored once.
    let name = format!("avatar-{}.{}", &pic.sha256[..12], pic.ext);
    // The picture is saved next to the document.
    if let Err(e) = std::fs::write(l.dir.join(&name), &pic.bytes) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("cannot save: {e}") }),
        );
    }
    l.remember(&pic);
    json_response(StatusCode::OK, json!({ "ok": true, "avatar": name, "bytes": pic.bytes.len(), "mime": pic.mime }))
}

/// Serve an embedded file (by its hashed path) or a picture the editor knows; anything else is a 404.
async fn local_asset(State(l): State<SharedLocal>, req: Request<Body>) -> Response {
    // Embedded files first, then the pictures the editor knows.
    let path = req.uri().path().to_string();
    if let Some(a) = Bundle::get().find(&path) {
        let mut r = Response::new(Body::from(a.body.clone()));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(a.content_type));
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_IMMUTABLE));
        return r;
    }
    let pic = l.pictures.lock().ok().and_then(|m| m.get(&path).cloned());
    match pic {
        Some(p) => {
            let mut r = Response::new(Body::from(p.bytes));
            if let Ok(v) = HeaderValue::from_str(p.mime) {
                r.headers_mut().insert(header::CONTENT_TYPE, v);
            }
            r
        }
        None => static_mode::not_found(),
    }
}

/// Loopback hosts only; writes need the editor header and, when the browser sends one, a loopback Origin.
fn allowed(l: &Local, req: &Request<Body>) -> Result<(), (StatusCode, &'static str)> {
    // The `Host` header must be a loopback address with this port, which stops a page on another site reaching the editor through DNS rebinding.
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let port = l.port;
    // The three spellings of the loopback address, with the port.
    let loopback_host = [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")];
    if !loopback_host.iter().any(|h| h == host) {
        return Err((StatusCode::MISDIRECTED_REQUEST, "This editor answers only on its loopback address.\n"));
    }
    // Only reads are free; every other method is a write.
    let write = !matches!(*req.method(), Method::GET | Method::HEAD);
    if write {
        if req.headers().get(EDITOR_HEADER).is_none() {
            return Err((StatusCode::FORBIDDEN, "Missing the editor header.\n"));
        }
        // A browser sends an `Origin`; it must be a loopback one.
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let ok = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"].iter().any(|p| origin.starts_with(p));
            if !ok {
                return Err((StatusCode::FORBIDDEN, "Cross-origin writes are refused.\n"));
            }
        }
    }
    Ok(())
}

/// The middleware around every request: the loopback and write rules first, then the security headers on whatever answer comes back.
async fn guard(State(l): State<SharedLocal>, req: Request<Body>, next: Next) -> Response {
    // The rules are checked before the request reaches any handler.
    let mut r = match allowed(&l, &req) {
        Ok(()) => next.run(req).await,
        Err((status, msg)) => {
            let mut r = Response::new(Body::from(msg));
            *r.status_mut() = status;
            r
        }
    };
    // Local mode: no HSTS.
    secure(r.headers_mut(), true, false);
    r
}

/// The saved page and its documents, served by the static router over the current site.
async fn page_from_local(State(l): State<SharedLocal>, req: Request<Body>) -> Response {
    // The saved page and its documents are served by the same router as the static mode.
    // The saved page and its documents, served by the static router over the current site.
    use tower::ServiceExt;
    // The page routes over the current site.
    let app = static_mode::page_routes().with_state(l.site());
    match app.oneshot(req).await {
        Ok(r) => r,
        Err(never) => match never {},
    }
}

/// The editor's router: its API, the embedded files, and the saved page for everything else, inside the guard and with the body limits.
pub fn router(local: SharedLocal) -> Router {
    // The editor's API, then the embedded files; the picture upload has its own, larger body limit.
    let api = Router::new()
        .route("/api/v1/manifest", get(get_manifest).put(put_manifest))
        .route("/api/v1/validate", post(validate))
        .route("/api/v1/preview", post(preview))
        .route("/api/v1/theme/options", get(theme_options))
        .route("/api/v1/limits", get(get_limits))
        .route("/api/v1/avatar", post(upload_avatar).layer(DefaultBodyLimit::max(link_in_bio_assets::MAX_INPUT_BYTES)))
        // The embedded and picture files.
        .route("/_/{file}", get(local_asset));
    // Everything that is not the API is the page itself.
    api.fallback(page_from_local)
        .layer(middleware::from_fn_with_state(local.clone(), guard))
        // Every other body is at most one page document.
        .layer(DefaultBodyLimit::max(limits::MAX_MANIFEST_BYTES))
        .with_state(local)
}

/// Unit tests for the editor's backend: saving and reloading, the loopback rules, invalid documents and the preview.
#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// A new empty directory for a test.
    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("lib-local-test-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A number that differs between calls, from the clock.
    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    /// A request to the editor, addressed to its loopback host and carrying the editor header when asked.
    fn req(method: Method, path: &str, body: &str, editor: bool) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, "127.0.0.1:4299");
        if editor {
            b = b.header(EDITOR_HEADER, "1");
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    /// Send a request through the router and return the status and the body text.
    async fn send(app: &Router, r: Request<Body>) -> (StatusCode, String) {
        let r = app.clone().oneshot(r).await.unwrap();
        let st = r.status();
        (st, String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    /// A saved document is written canonically, read back identically (also after reopening the directory) and rendered on the page.
    #[tokio::test]
    async fn round_trip_save_and_reload() {
        let dir = tmp();
        let app = router(Local::open(dir.clone(), 4299, Owner::Operator, 0).unwrap());
        // A small valid document.
        let doc = r#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada"},"items":[{"id":"a","title":"A","url":"https://example.org/"}]}"#;
        assert_eq!(send(&app, req(Method::PUT, "/api/v1/manifest", doc, true)).await.0, StatusCode::OK);
        // What was written to the directory.
        let saved: Value = serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(saved["identity"]["handle"], "ada");
        let (st, body) = send(&app, req(Method::GET, "/api/v1/manifest", "", false)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), saved);
        // Reopening the directory gives the same document.
        // A second editor over the same directory.
        let again = router(Local::open(dir.clone(), 4299, Owner::Operator, 0).unwrap());
        let (_, body2) = send(&again, req(Method::GET, "/api/v1/manifest", "", false)).await;
        assert_eq!(body, body2);
        let (st, html) = send(&app, req(Method::GET, "/", "", false)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(html.contains("Ada"));
    }

    /// A request for another host, a write without the editor header and a write from another origin are each refused.
    #[tokio::test]
    async fn refuses_rebinding_cross_origin_and_headerless_writes() {
        let app = router(Local::open(tmp(), 4299, Owner::Tenant, 0).unwrap());
        let mut r = req(Method::GET, "/api/v1/manifest", "", false);
        // A request addressed to another host, as DNS rebinding would make.
        r.headers_mut().insert(header::HOST, HeaderValue::from_static("evil.example:4299"));
        assert_eq!(send(&app, r).await.0, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(send(&app, req(Method::PUT, "/api/v1/manifest", "{}", false)).await.0, StatusCode::FORBIDDEN);
        let mut r = req(Method::PUT, "/api/v1/manifest", "{}", true);
        // A write from another origin, even with the header.
        r.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);
    }

    /// A document with a script link is refused with its code, nothing is written, and a preview of it is refused too.
    #[tokio::test]
    async fn invalid_documents_are_reported_and_not_saved() {
        let dir = tmp();
        let app = router(Local::open(dir.clone(), 4299, Owner::Tenant, 0).unwrap());
        // A document with a script link.
        let bad = r#"{"schema":1,"identity":{"displayName":"A","handle":"a"},"items":[{"id":"x","title":"X","url":"javascript:alert(1)"}]}"#;
        let (st, body) = send(&app, req(Method::PUT, "/api/v1/manifest", bad, true)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("url_scheme"));
        assert!(!dir.join(MANIFEST_FILE).exists());
        let (st, _) = send(&app, req(Method::POST, "/api/v1/preview", bad, true)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

    /// The preview carries the icon sprite inside the page.
    #[tokio::test]
    async fn preview_inlines_the_sprite() {
        let app = router(Local::open(tmp(), 4299, Owner::Tenant, 0).unwrap());
        let doc = r#"{"schema":1,"identity":{"displayName":"A","handle":"a"},"items":[{"id":"x","title":"X","url":"https://github.com/a"}]}"#;
        let (st, html) = send(&app, req(Method::POST, "/api/v1/preview", doc, true)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(html.contains(r##"<use href="#i-github">"##));
        assert!(html.contains("<symbol id=\"i-github\""));
    }
}
