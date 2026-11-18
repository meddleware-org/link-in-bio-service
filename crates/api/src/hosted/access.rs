//! The operator console's gate, on every admin `/api/v1/admin` request (the same rule as the content hub's):
//!
//! 1. **CSRF** (state-changing methods): the `X-Link-In-Bio-Request` header and `Origin` = the admin origin. → 403
//! 2. **Identity**: `Cf-Access-Jwt-Assertion` verifies against the Access team's JWKS (cached; refreshed when a token
//!    names an unknown key, at most every 30 s). → 401
//! 3. **Role**: Keto says `LinkInBio:admin#member@<subject>` (cached 30 s allowed, 5 s denied). → 403; Keto down → 503.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

use super::Shared;
use super::error::ApiError;
use super::jwt::{self, JwkSet, JwtError};

pub const ACCESS_JWT_HEADER: &str = "cf-access-jwt-assertion";
pub use link_in_bio_auth::session::CSRF_HEADER;

const JWKS_MIN_REFRESH: Duration = Duration::from_secs(30);
const JWKS_MAX_AGE: Duration = Duration::from_secs(3600);
const ROLE_ALLOWED_TTL: Duration = Duration::from_secs(30);
const ROLE_DENIED_TTL: Duration = Duration::from_secs(5);
const MAX_JWKS_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub enum JwksSource {
    Remote(String),
    /// Tests only.
    Static(JwkSet),
}

#[derive(Debug, Clone)]
pub enum RoleSource {
    Keto(String),
    /// Tests only.
    Static(BTreeSet<String>),
}

#[derive(Debug, Clone)]
pub struct AccessConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks: JwksSource,
    pub roles: RoleSource,
    pub admin_origin: String,
}

/// The operator, attached to each admin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    pub subject: String,
    pub display_name: String,
}

pub struct Admins {
    cfg: AccessConfig,
    http: reqwest::Client,
    keys: RwLock<(JwkSet, Option<Instant>)>,
    last_refresh: Mutex<Option<Instant>>,
    roles: Mutex<HashMap<String, (bool, Instant)>>,
}

#[derive(Deserialize)]
struct KetoCheck {
    allowed: bool,
}

impl Admins {
    pub fn new(cfg: AccessConfig) -> Arc<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        let keys = match &cfg.jwks {
            JwksSource::Static(k) => (k.clone(), Some(Instant::now())),
            JwksSource::Remote(_) => (JwkSet { keys: Vec::new() }, None),
        };
        Arc::new(Self {
            cfg,
            http,
            keys: RwLock::new(keys),
            last_refresh: Mutex::new(None),
            roles: Mutex::new(HashMap::new()),
        })
    }

    async fn refresh_keys(&self, force: bool) -> Result<(), ApiError> {
        let JwksSource::Remote(url) = &self.cfg.jwks else { return Ok(()) };
        {
            let mut last = self.last_refresh.lock().await;
            if !force && last.is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH) {
                return Ok(());
            }
            *last = Some(Instant::now());
        }
        let unavailable = || ApiError::Unavailable("identity keys unavailable");
        let resp = self.http.get(url).send().await.map_err(|_| unavailable())?;
        if !resp.status().is_success() {
            return Err(unavailable());
        }
        let body = resp.bytes().await.map_err(|_| unavailable())?;
        if body.len() > MAX_JWKS_BYTES {
            return Err(unavailable());
        }
        let set: JwkSet = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        *self.keys.write().await = (set, Some(Instant::now()));
        Ok(())
    }

    pub async fn identify(&self, token: &str) -> Result<Operator, ApiError> {
        let stale = self.keys.read().await.1.is_none_or(|t| t.elapsed() > JWKS_MAX_AGE);
        if stale {
            self.refresh_keys(true).await?;
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let attempt = {
            let keys = self.keys.read().await;
            jwt::verify(token, &keys.0, &self.cfg.issuer, &self.cfg.audience, now)
        };
        let verified = match attempt {
            Err(JwtError::UnknownKey) if jwt::key_id(token).is_some() => {
                self.refresh_keys(false).await?;
                let keys = self.keys.read().await;
                jwt::verify(token, &keys.0, &self.cfg.issuer, &self.cfg.audience, now)
            }
            other => other,
        }
        .map_err(|e| {
            tracing::info!(reason = %e, "access token refused");
            ApiError::Unauthorized
        })?;
        Ok(Operator { subject: verified.subject, display_name: verified.display_name })
    }

    pub async fn is_admin(&self, subject: &str) -> Result<bool, ApiError> {
        if let Some((allowed, at)) = self.roles.lock().await.get(subject).copied() {
            let ttl = if allowed { ROLE_ALLOWED_TTL } else { ROLE_DENIED_TTL };
            if at.elapsed() < ttl {
                return Ok(allowed);
            }
        }
        let allowed = match &self.cfg.roles {
            RoleSource::Static(admins) => admins.contains(subject),
            RoleSource::Keto(base) => {
                let unavailable = || ApiError::Unavailable("authorisation service unavailable");
                let mut url = url::Url::parse(&format!("{}/relation-tuples/check/openapi", base.trim_end_matches('/')))
                    .map_err(|_| unavailable())?;
                url.query_pairs_mut()
                    .append_pair("namespace", "LinkInBio")
                    .append_pair("object", "admin")
                    .append_pair("relation", "member")
                    .append_pair("subject_id", subject);
                let resp = self.http.get(url).send().await.map_err(|_| unavailable())?;
                if !resp.status().is_success() {
                    return Err(unavailable());
                }
                resp.json::<KetoCheck>().await.map_err(|_| unavailable())?.allowed
            }
        };
        self.roles.lock().await.insert(subject.to_owned(), (allowed, Instant::now()));
        Ok(allowed)
    }
}

pub fn csrf_ok(method: &Method, headers: &HeaderMap, origin: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    headers.contains_key(CSRF_HEADER) && headers.get("origin").and_then(|o| o.to_str().ok()) == Some(origin)
}

/// The middleware of every admin route. Without an Access configuration the console is closed (503).
pub async fn require_admin(State(app): State<Shared>, mut req: Request, next: Next) -> Response {
    let Some(admins) = app.access.clone() else {
        return ApiError::Unavailable("the console is not configured").into_response();
    };
    if !csrf_ok(req.method(), req.headers(), &admins.cfg.admin_origin) {
        return ApiError::Forbidden("cross-site request refused").into_response();
    }
    let Some(token) = req.headers().get(ACCESS_JWT_HEADER).and_then(|v| v.to_str().ok()).map(str::to_owned) else {
        return ApiError::Unauthorized.into_response();
    };
    let op = match admins.identify(&token).await {
        Ok(o) => o,
        Err(e) => return e.into_response(),
    };
    match admins.is_admin(&op.subject).await {
        Ok(true) => {}
        Ok(false) => return ApiError::Forbidden("not an operator of Link in Bio").into_response(),
        Err(e) => return e.into_response(),
    }
    req.extensions_mut().insert(op);
    next.run(req).await
}
