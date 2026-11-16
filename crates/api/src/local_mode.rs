//! `serve --mode local`: the editor's backend on the operator's own machine. It binds loopback only (the CLI refuses
//! anything else), answers only requests addressed to a loopback host (no DNS rebinding), keeps the page's files in one
//! directory, and makes no outbound request at all.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
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
pub const MANIFEST_FILE: &str = "manifest.json";

pub struct Local {
    pub dir: PathBuf,
    pub port: u16,
    pub owner: Owner,
    site: RwLock<Arc<Site>>,
    pictures: Mutex<HashMap<String, Picture>>,
}

pub type SharedLocal = Arc<Local>;

/// A document to start from when the directory has none.
pub fn starter_manifest() -> Value {
    json!({
        "schema": 1,
        "identity": { "displayName": "Your name", "handle": "yourname", "bio": "One line about you." },
        "items": [ { "id": "website", "title": "My website", "url": "https://example.org/" } ],
        "theme": {},
        "meta": { "lang": "en" }
    })
}

impl Local {
    pub fn open(dir: PathBuf, port: u16, owner: Owner, now: u64) -> Result<SharedLocal, String> {
        let path = dir.join(MANIFEST_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                serde_json::to_vec_pretty(&starter_manifest()).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let config = SiteConfig::local(port, owner);
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
        let local = Local { dir, port, owner, site: RwLock::new(Arc::new(site)), pictures: Mutex::new(HashMap::new()) };
        local.remember_site_picture();
        Ok(Arc::new(local))
    }

    fn site(&self) -> Arc<Site> {
        self.site.read().map(|s| s.clone()).unwrap_or_else(|p| p.into_inner().clone())
    }

    fn remember_site_picture(&self) {
        if let Some((path, pic)) = &self.site().avatar
            && let Ok(mut m) = self.pictures.lock()
        {
            m.insert(path.clone(), pic.clone());
        }
    }

    fn remember(&self, pic: &Picture) {
        if let Ok(mut m) = self.pictures.lock() {
            m.insert(avatar_path(pic), pic.clone());
        }
    }
}

fn json_response(status: StatusCode, v: Value) -> Response {
    let mut r = Response::new(Body::from(v.to_string()));
    *r.status_mut() = status;
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

fn issues_json(errors: &[Issue], warnings: &[Issue]) -> Value {
    json!({ "ok": errors.is_empty(), "errors": errors, "warnings": warnings })
}

async fn get_manifest(State(l): State<SharedLocal>) -> Response {
    json_response(StatusCode::OK, serde_json::to_value(&l.site().manifest).unwrap_or(Value::Null))
}

fn parse_body(l: &Local, body: &Bytes) -> Result<link_in_bio_core::Parsed, Vec<Issue>> {
    link_in_bio_core::parse(body, parse_options(l.owner))
}

async fn validate(State(l): State<SharedLocal>, body: Bytes) -> Response {
    match parse_body(&l, &body) {
        Ok(p) => {
            let mut v = issues_json(&[], &p.warnings);
            v["manifest"] = serde_json::to_value(&p.manifest).unwrap_or(Value::Null);
            json_response(StatusCode::OK, v)
        }
        Err(errors) => json_response(StatusCode::UNPROCESSABLE_ENTITY, issues_json(&errors, &[])),
    }
}

async fn put_manifest(State(l): State<SharedLocal>, body: Bytes) -> Response {
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
    let canonical = parsed.manifest.to_json();
    let path = l.dir.join(MANIFEST_FILE);
    let tmp = l.dir.join(".manifest.json.tmp");
    if let Err(e) = std::fs::write(&tmp, canonical.as_bytes()).and_then(|_| std::fs::rename(&tmp, &path)) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("cannot save: {e}") }),
        );
    }
    let config = l.site().config.clone();
    let site = Site::from_parts(config, parsed.manifest, parsed.warnings.clone(), picture, None, 0);
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
    let picture = load_avatar(&parsed.manifest, &l.dir, l.owner).ok().flatten();
    if let Some(p) = &picture {
        l.remember(p);
    }
    let site = l.site();
    let cx = context(&site.config, picture.as_ref(), true);
    let html = render::render_page(&parsed.manifest, &cx);
    let mut r = Response::new(Body::from(html));
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE_NONE));
    r
}

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

async fn get_limits() -> Response {
    json_response(StatusCode::OK, limits::limits_json())
}

/// Accepts a picture, normalises it and stores it next to the manifest. Returns the file name to put in
/// `identity.avatar`.
async fn upload_avatar(State(l): State<SharedLocal>, headers: HeaderMap, body: Bytes) -> Response {
    let svg =
        headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.starts_with("image/svg+xml"));
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
    let name = format!("avatar-{}.{}", &pic.sha256[..12], pic.ext);
    if let Err(e) = std::fs::write(l.dir.join(&name), &pic.bytes) {
        return json_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "ok": false, "error": format!("cannot save: {e}") }),
        );
    }
    l.remember(&pic);
    json_response(StatusCode::OK, json!({ "ok": true, "avatar": name, "bytes": pic.bytes.len(), "mime": pic.mime }))
}

async fn local_asset(State(l): State<SharedLocal>, req: Request<Body>) -> Response {
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
    let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    let port = l.port;
    let loopback_host = [format!("127.0.0.1:{port}"), format!("localhost:{port}"), format!("[::1]:{port}")];
    if !loopback_host.iter().any(|h| h == host) {
        return Err((StatusCode::MISDIRECTED_REQUEST, "This editor answers only on its loopback address.\n"));
    }
    let write = !matches!(*req.method(), Method::GET | Method::HEAD);
    if write {
        if req.headers().get(EDITOR_HEADER).is_none() {
            return Err((StatusCode::FORBIDDEN, "Missing the editor header.\n"));
        }
        if let Some(origin) = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
            let ok = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"].iter().any(|p| origin.starts_with(p));
            if !ok {
                return Err((StatusCode::FORBIDDEN, "Cross-origin writes are refused.\n"));
            }
        }
    }
    Ok(())
}

async fn guard(State(l): State<SharedLocal>, req: Request<Body>, next: Next) -> Response {
    let mut r = match allowed(&l, &req) {
        Ok(()) => next.run(req).await,
        Err((status, msg)) => {
            let mut r = Response::new(Body::from(msg));
            *r.status_mut() = status;
            r
        }
    };
    secure(r.headers_mut(), true, false);
    r
}

async fn page_from_local(State(l): State<SharedLocal>, req: Request<Body>) -> Response {
    // The saved page and its documents, served by the static router over the current site.
    use tower::ServiceExt;
    let app = static_mode::page_routes().with_state(l.site());
    match app.oneshot(req).await {
        Ok(r) => r,
        Err(never) => match never {},
    }
}

pub fn router(local: SharedLocal) -> Router {
    let api = Router::new()
        .route("/api/v1/manifest", get(get_manifest).put(put_manifest))
        .route("/api/v1/validate", post(validate))
        .route("/api/v1/preview", post(preview))
        .route("/api/v1/theme/options", get(theme_options))
        .route("/api/v1/limits", get(get_limits))
        .route("/api/v1/avatar", post(upload_avatar).layer(DefaultBodyLimit::max(link_in_bio_assets::MAX_INPUT_BYTES)))
        .route("/_/{file}", get(local_asset));
    api.fallback(page_from_local)
        .layer(middleware::from_fn_with_state(local.clone(), guard))
        .layer(DefaultBodyLimit::max(limits::MAX_MANIFEST_BYTES))
        .with_state(local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("lib-local-test-{}-{}", std::process::id(), rand_suffix()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    }

    fn req(method: Method, path: &str, body: &str, editor: bool) -> Request<Body> {
        let mut b = Request::builder().method(method).uri(path).header(header::HOST, "127.0.0.1:4299");
        if editor {
            b = b.header(EDITOR_HEADER, "1");
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    async fn send(app: &Router, r: Request<Body>) -> (StatusCode, String) {
        let r = app.clone().oneshot(r).await.unwrap();
        let st = r.status();
        (st, String::from_utf8(r.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    #[tokio::test]
    async fn round_trip_save_and_reload() {
        let dir = tmp();
        let app = router(Local::open(dir.clone(), 4299, Owner::Operator, 0).unwrap());
        let doc = r#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada"},"items":[{"id":"a","title":"A","url":"https://example.org/"}]}"#;
        assert_eq!(send(&app, req(Method::PUT, "/api/v1/manifest", doc, true)).await.0, StatusCode::OK);
        let saved: Value = serde_json::from_slice(&std::fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(saved["identity"]["handle"], "ada");
        let (st, body) = send(&app, req(Method::GET, "/api/v1/manifest", "", false)).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(serde_json::from_str::<Value>(&body).unwrap(), saved);
        // Reopening the directory gives the same document.
        let again = router(Local::open(dir.clone(), 4299, Owner::Operator, 0).unwrap());
        let (_, body2) = send(&again, req(Method::GET, "/api/v1/manifest", "", false)).await;
        assert_eq!(body, body2);
        let (st, html) = send(&app, req(Method::GET, "/", "", false)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(html.contains("Ada"));
    }

    #[tokio::test]
    async fn refuses_rebinding_cross_origin_and_headerless_writes() {
        let app = router(Local::open(tmp(), 4299, Owner::Tenant, 0).unwrap());
        let mut r = req(Method::GET, "/api/v1/manifest", "", false);
        r.headers_mut().insert(header::HOST, HeaderValue::from_static("evil.example:4299"));
        assert_eq!(send(&app, r).await.0, StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(send(&app, req(Method::PUT, "/api/v1/manifest", "{}", false)).await.0, StatusCode::FORBIDDEN);
        let mut r = req(Method::PUT, "/api/v1/manifest", "{}", true);
        r.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://evil.example"));
        assert_eq!(send(&app, r).await.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invalid_documents_are_reported_and_not_saved() {
        let dir = tmp();
        let app = router(Local::open(dir.clone(), 4299, Owner::Tenant, 0).unwrap());
        let bad = r#"{"schema":1,"identity":{"displayName":"A","handle":"a"},"items":[{"id":"x","title":"X","url":"javascript:alert(1)"}]}"#;
        let (st, body) = send(&app, req(Method::PUT, "/api/v1/manifest", bad, true)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(body.contains("url_scheme"));
        assert!(!dir.join(MANIFEST_FILE).exists());
        let (st, _) = send(&app, req(Method::POST, "/api/v1/preview", bad, true)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    }

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
