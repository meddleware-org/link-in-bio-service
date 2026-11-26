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

/// The header Cloudflare Access puts the signed token in, lower-cased.
pub const ACCESS_JWT_HEADER: &str = "cf-access-jwt-assertion";
/// The CSRF header is the same one the app uses.
pub use link_in_bio_auth::session::CSRF_HEADER;

/// The key set is asked for at most this often, so unknown key ids cannot make the service hammer the provider.
const JWKS_MIN_REFRESH: Duration = Duration::from_secs(30);
/// A cached key set older than this is fetched again before use.
const JWKS_MAX_AGE: Duration = Duration::from_secs(3600);
/// How long a "yes" is remembered.
const ROLE_ALLOWED_TTL: Duration = Duration::from_secs(30);
/// How long a "no" is remembered (short, so a new operator is let in quickly).
const ROLE_DENIED_TTL: Duration = Duration::from_secs(5);
/// The most bytes read from the key set.
const MAX_JWKS_BYTES: usize = 64 * 1024;
/// The most bytes read from the role check.
const MAX_KETO_BYTES: usize = 4 * 1024;

/// Where the keys that sign the operator's tokens come from.
#[derive(Debug, Clone)]
pub enum JwksSource {
    /// The team's key set address, fetched and cached.
    Remote(String),
    /// Tests only.
    Static(JwkSet),
}

/// Where the operator role is decided.
#[derive(Debug, Clone)]
pub enum RoleSource {
    /// The authorisation service's read address.
    Keto(String),
    /// Tests only.
    Static(BTreeSet<String>),
}

/// How the operator's sign-in is checked.
#[derive(Debug, Clone)]
pub struct AccessConfig {
    /// The team domain the tokens must name as their issuer.
    pub issuer: String,
    /// The audience tag the tokens must carry.
    pub audience: String,
    /// Where the signing keys come from.
    pub jwks: JwksSource,
    /// Where the role is decided.
    pub roles: RoleSource,
    /// The console's origin, which a write must come from.
    pub admin_origin: String,
}

/// The operator, attached to each admin request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// The identity provider's stable id for the operator.
    pub subject: String,
    /// The name to show.
    pub display_name: String,
}

/// The operator sign-in checker: it verifies tokens, caches the keys and the role answers, and refreshes the keys when a token names one it does not know.
pub struct Admins {
    /// The settings.
    cfg: AccessConfig,
    /// The client for the key set and the role check, with short timeouts and no redirects.
    http: reqwest::Client,
    /// The cached key set and when it was fetched.
    keys: RwLock<(JwkSet, Option<Instant>)>,
    /// When the key set was last asked for, to limit how often it is.
    last_refresh: Mutex<Option<Instant>>,
    /// Role answers by subject, with when each was made.
    roles: Mutex<HashMap<String, (bool, Instant)>>,
}

/// The authorisation service's answer to a check.
#[derive(Deserialize)]
struct KetoCheck {
    /// Whether the subject has the role.
    allowed: bool,
}

impl Admins {
    /// The checker for a configuration: keys start empty for a remote set and loaded for a fixed one.
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

    /// Fetch the key set (at most every 30 seconds unless forced); a fixed set needs no fetch.
    async fn refresh_keys(&self, force: bool) -> Result<(), ApiError> {
        let JwksSource::Remote(url) = &self.cfg.jwks else { return Ok(()) };
        {
            let mut last = self.last_refresh.lock().await;
            if !force && last.is_some_and(|t| t.elapsed() < JWKS_MIN_REFRESH) {
                return Ok(());
            }
            *last = Some(Instant::now());
        }
        // Every failure to get the keys is the same answer, with no detail from the provider.
        let unavailable = || ApiError::Unavailable("identity keys unavailable");
        let resp = self.http.get(url).send().await.map_err(|_| unavailable())?;
        if !resp.status().is_success() {
            return Err(unavailable());
        }
        let body = link_in_bio_billing::read_limited(resp, MAX_JWKS_BYTES).await.map_err(|_| unavailable())?;
        let set: JwkSet = serde_json::from_slice(&body).map_err(|_| unavailable())?;
        *self.keys.write().await = (set, Some(Instant::now()));
        Ok(())
    }

    /// Verify an Access token and return the operator it names.
    pub async fn identify(&self, token: &str) -> Result<Operator, ApiError> {
        // Keys never fetched, or older than the limit, are fetched first.
        let stale = self.keys.read().await.1.is_none_or(|t| t.elapsed() > JWKS_MAX_AGE);
        if stale {
            self.refresh_keys(true).await?;
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // Verification uses the cached keys; the lock is released before any refresh.
        let attempt = {
            let keys = self.keys.read().await;
            jwt::verify(token, &keys.0, &self.cfg.issuer, &self.cfg.audience, now)
        };
        let verified = match attempt {
            // A token that names an unknown key may be signed with a rotated one: refresh once (rate limited) and try again.
            Err(JwtError::UnknownKey) if jwt::key_id(token).is_some() => {
                self.refresh_keys(false).await?;
                let keys = self.keys.read().await;
                jwt::verify(token, &keys.0, &self.cfg.issuer, &self.cfg.audience, now)
            }
            other => other,
        }
        .map_err(|e| {
            // The reason is logged; the caller only learns that they are not authenticated.
            tracing::info!(reason = %e, "access token refused");
            ApiError::Unauthorized
        })?;
        Ok(Operator { subject: verified.subject, display_name: verified.display_name })
    }

    /// Whether the subject has the operator role, from the cache or from Keto; a role service that is down is an error, not a "no".
    pub async fn is_admin(&self, subject: &str) -> Result<bool, ApiError> {
        // A recent answer is reused, "yes" for longer than "no".
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
                    // The question is whether the subject is a member of the Link in Bio operators.
                    .append_pair("namespace", "LinkInBio")
                    .append_pair("object", "admin")
                    .append_pair("relation", "member")
                    .append_pair("subject_id", subject);
                let resp = self.http.get(url).send().await.map_err(|_| unavailable())?;
                if !resp.status().is_success() {
                    return Err(unavailable());
                }
                let body = link_in_bio_billing::read_limited(resp, MAX_KETO_BYTES).await.map_err(|_| unavailable())?;
                serde_json::from_slice::<KetoCheck>(&body).map_err(|_| unavailable())?.allowed
            }
        };
        // The answer is remembered.
        self.roles.lock().await.insert(subject.to_owned(), (allowed, Instant::now()));
        Ok(allowed)
    }
}

/// The CSRF rule: a write must carry the custom header and come from the console's own origin.
pub fn csrf_ok(method: &Method, headers: &HeaderMap, origin: &str) -> bool {
    // Reads need no CSRF check.
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return true;
    }
    headers.contains_key(CSRF_HEADER) && headers.get("origin").and_then(|o| o.to_str().ok()) == Some(origin)
}

/// The middleware of every admin route. Without an Access configuration the console is closed (503).
pub async fn require_admin(State(app): State<Shared>, mut req: Request, next: Next) -> Response {
    // Without a sign-in configuration the console is closed.
    let Some(admins) = app.access.clone() else {
        return ApiError::Unavailable("the console is not configured").into_response();
    };
    if !csrf_ok(req.method(), req.headers(), &admins.cfg.admin_origin) {
        return ApiError::Forbidden("cross-site request refused").into_response();
    }
    // No token means not authenticated.
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
    // The handlers read the operator from the request.
    req.extensions_mut().insert(op);
    next.run(req).await
}
