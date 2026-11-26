//! The hosted service: tenant pages by host (`pages`), the account API on the app host (`app`), the operator's console
//! API behind Cloudflare Access (`admin`), provider notifications and metrics inside the cluster (`internal`), and the
//! worker's duties (`jobs`). One process role per Deployment:
//!
//! | role | listens | database role |
//! | --- | --- | --- |
//! | `pages` | tenant hosts | read-only (`public.*_v1` views) |
//! | `app` | the app host's `/api/` + the internal port | writer |
//! | `admin` | the admin host's `/api/` | writer |
//! | `worker` | metrics only | writer |

/// The operator's sign-in: Access tokens and roles.
pub mod access;
/// The operator console's API.
pub mod admin;
/// The account API on the app host.
pub mod app;
/// The hosted service's configuration from the environment.
pub mod config;
/// The API's error type and its answers.
pub mod error;
/// Provider notifications and metrics, inside the cluster.
pub mod internal;
/// The worker's periodic duties.
pub mod jobs;
/// Verification of the operator's tokens.
pub mod jwt;
/// Per-account daily limits.
pub mod limits;
/// The counters behind `/metrics`.
pub mod metrics;
/// The OpenAPI documents, built from the route tables.
pub mod openapi;
/// Tenant pages by host.
pub mod pages;
/// Refund requests on the app and in the console.
pub mod refunds;
/// The tables of every app and admin route.
pub mod routes;

/// The hosted service's router tests, which run against a real database and the stand-ins for the providers.
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use link_in_bio_auth::passkey::Passkeys;
use link_in_bio_billing::chain_payments::{self, ChainPayments};
use link_in_bio_billing::{BillingProvider, Router as Billing, RouterConfig};
use link_in_bio_safety::{Screener, WebRiskLookup, WebRiskUpdate};
use link_in_bio_store::Store;

pub use config::{AccountLimits, HostedConfig, Keys, LimitsPreset, SignupMode, WebRiskMode};
pub use error::{ApiError, ApiResult};

/// The state every process role of the hosted service shares: the store, the configuration, billing, passkeys, the link screener and the caches. Roles use only the parts they need.
pub struct App {
    /// The database.
    pub store: Store,
    /// The configuration, read once at start-up.
    pub config: HostedConfig,
    /// The billing router: which payment methods are offered.
    pub billing: Billing,
    /// The WebAuthn relying party for the app host.
    pub passkeys: Passkeys,
    /// The link screener, with its Web Risk mode if one is on.
    pub screener: Screener,
    /// The counters behind `/metrics`.
    pub metrics: metrics::Metrics,
    /// The cache of built tenant pages.
    pub pages: pages::PageCache,
    /// The operator's sign-in, when the console is configured.
    pub access: Option<Arc<access::Admins>>,
    /// The Open Payments adapter (also in `billing`), for the steps of its checkout beyond the port.
    pub open_payments: Option<Arc<link_in_bio_billing::open_payments::OpenPayments>>,
    /// Pictures are decoded one at a time per process, off the async workers: one decode may use up to twice
    /// `link_in_bio_assets::MAX_DECODE_BYTES`, which the pod's memory holds once.
    pub pictures: tokio::sync::Semaphore,
}

/// The application state, shared between requests.
pub type Shared = Arc<App>;

/// Read a secret from its mounted file, trimmed; the error names the file, never its contents.
fn read_secret(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).map_err(|e| format!("{path}: {e}"))
}

impl App {
    /// Builds the state for any role. `page_cache` is how long a built tenant page is reused (and so how soon a
    /// suspension or a new version shows).
    pub fn new(store: Store, config: HostedConfig, page_cache: Duration) -> Result<Self, String> {
        let passkeys =
            Passkeys::new(&config.app_host, &config.app_origin, &config.product_name).map_err(|e| e.to_string())?;
        // The manual provider is always present; the others are added below when configured.
        let mut providers: Vec<Box<dyn BillingProvider>> = vec![Box::new(link_in_bio_billing::manual::Manual)];
        // A process without keys (the console, the page server) builds no provider and no screener: it reads no key
        // file, and shows the switches from the configuration.
        // Whether this process reads key files at all.
        let keys = config.keys == config::Keys::Read;
        // Each provider is built only when configured and when this process may read keys.
        if let Some(cp) = config.chain_payments.as_ref().filter(|_| keys) {
            let key = read_secret(&cp.api_key_file)?;
            let p = ChainPayments::new(
                chain_payments::Config {
                    merchant_api: cp.merchant_api.clone(),
                    public_api: cp.public_api.clone(),
                    checkout_origin: cp.checkout_origin.clone(),
                    api_key: key,
                    methods: cp.methods.clone(),
                    webhook_key: cp.webhook_key.clone(),
                },
                ChainPayments::http_client(),
            )
            .map_err(|e| e.to_string())?;
            providers.push(Box::new(p));
        }
        // A secret read from its mounted file.
        let file = |f: &str| read_secret(f);
        if let Some(c) = config.square.as_ref().filter(|_| keys) {
            providers.push(Box::new(link_in_bio_billing::square::Square::new(
                link_in_bio_billing::square::Config {
                    api_base: c.api_base.clone(),
                    access_token: file(&c.access_token_file)?,
                    location_id: c.location_id.clone(),
                    signature_key: file(&c.signature_key_file)?,
                    // Square signs the address it was told to call, so it is built from the app's own origin.
                    notification_url: format!("{}/api/v1/webhooks/square", config.app_origin),
                    fixed_pence: c.fixed_pence,
                    percent_bps: c.percent_bps,
                },
                link_in_bio_billing::http_client(),
            )));
        }
        if let Some(c) = config.gocardless.as_ref().filter(|_| keys) {
            providers.push(Box::new(link_in_bio_billing::gocardless::GoCardless::new(
                link_in_bio_billing::gocardless::Config {
                    api_base: c.api_base.clone(),
                    access_token: file(&c.access_token_file)?,
                    webhook_secret: file(&c.webhook_secret_file)?,
                    fixed_pence: c.fixed_pence,
                    percent_bps: c.percent_bps,
                },
                link_in_bio_billing::http_client(),
            )));
        }
        if let Some(c) = config.paddle.as_ref().filter(|_| keys) {
            providers.push(Box::new(link_in_bio_billing::paddle::Paddle::new(
                link_in_bio_billing::paddle::Config {
                    api_base: c.api_base.clone(),
                    api_key: file(&c.api_key_file)?,
                    webhook_secret: file(&c.webhook_secret_file)?,
                    price_id: c.price_id.clone(),
                    fixed_pence: c.fixed_pence,
                    percent_bps: c.percent_bps,
                },
                link_in_bio_billing::http_client(),
            )));
        }
        if let Some(c) = &config.bank_transfer {
            providers.push(Box::new(
                link_in_bio_billing::bank_transfer::BankTransfer::new(link_in_bio_billing::bank_transfer::Config {
                    payee: c.payee.clone(),
                    scheme: c.scheme.clone(),
                })
                .map_err(|e| e.to_string())?,
            ));
        }
        // The Open Payments adapter is also kept by itself, for the steps of its flow beyond the port.
        let mut open_payments = None;
        if let Some(c) = config.open_payments.as_ref().filter(|_| keys) {
            let p = Arc::new(
                link_in_bio_billing::open_payments::OpenPayments::new(
                    link_in_bio_billing::open_payments::Config {
                        wallet_address: c.wallet_address.clone(),
                        key_id: c.key_id.clone(),
                        private_key_pem: file(&c.key_file)?,
                        asset_code: c.asset_code.clone(),
                        asset_scale: c.asset_scale,
                        minor_per_month: c.minor_per_month,
                    },
                    link_in_bio_billing::open_payments::OpenPayments::http_client(),
                )
                .map_err(|e| e.to_string())?,
            );
            providers.push(Box::new(p.clone()));
            open_payments = Some(p);
        }
        // The router decides which methods are offered, from the switches and the countries.
        let billing = Billing::new(
            RouterConfig {
                price_pence: config.price_pence,
                enabled: config.billing_providers.clone(),
                countries: config.billing_countries.clone(),
            },
            providers,
        );
        // One Web Risk mode, never both: the lists are built and loaded in update mode only.
        let mut screener = Screener::default();
        if let Some(f) = config.web_risk_key_file.as_ref().filter(|_| keys && config.web_risk_monthly_cap > 0) {
            let key = read_secret(f)?;
            match config.web_risk_mode {
                config::WebRiskMode::Lookup => {
                    screener.lookup =
                        Some(WebRiskLookup::new(key, config.web_risk_monthly_cap, config.web_risk_paid_monthly_calls));
                }
                config::WebRiskMode::Update => {
                    screener.update = Some(WebRiskUpdate::new(
                        key,
                        config.web_risk_monthly_cap,
                        config.web_risk_confirm_monthly_cap,
                        config.web_risk_max_entries,
                    ));
                }
            }
        }
        // The operator's sign-in, when the console is configured: tokens from the team's key set, roles from Keto.
        let access = config.access.as_ref().map(|a| {
            access::Admins::new(access::AccessConfig {
                issuer: a.team_domain.clone(),
                audience: a.audience.clone(),
                jwks: access::JwksSource::Remote(format!("{}/cdn-cgi/access/certs", a.team_domain)),
                roles: access::RoleSource::Keto(a.keto_read_url.clone()),
                admin_origin: a.admin_origin.clone(),
            })
        });
        // Pictures are decoded one at a time.
        Ok(Self {
            store,
            config,
            billing,
            passkeys,
            screener,
            metrics: metrics::Metrics::default(),
            pages: pages::PageCache::new(page_cache),
            access,
            open_payments,
            pictures: tokio::sync::Semaphore::new(1),
        })
    }
}

/// How long one request may take: the app's publish screens up to 60 links first, so its routes get the longer bound.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The longer bound for routes that screen up to 60 links first.
pub const SLOW_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounds a router in time (`408` past `timeout`, waiting for a turn included) and in requests at once, across all of
/// its routes (axum layers each route separately, so the limit is a shared one). Memory per process is then about
/// `concurrent` × the router's body limit.
pub fn bounded(router: axum::Router, timeout: Duration, concurrent: usize) -> axum::Router {
    router
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(concurrent))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(axum::http::StatusCode::REQUEST_TIMEOUT, timeout))
}

/// The current time (one place, so tests can reason about it).
pub fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}

/// The rules an account's page document is parsed with, by the app when it is saved and published and by the page
/// server when it is shown (the same rules on both sides, so a page the app published is a page that is served). The
/// handle is not checked against the reserved list here: the account's handle passed that check at sign-up (or is the
/// operator's own, created by the operator), and the app requires the document to carry exactly that handle.
pub fn account_page_options() -> link_in_bio_core::ParseOptions {
    link_in_bio_core::ParseOptions { owner: link_in_bio_core::Owner::Tenant, check_reserved: false }
}

/// Unit tests for the time and concurrency bounds.
#[cfg(test)]
mod bounds_tests {
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    /// A router with two routes that each take `hold` to answer.
    fn slow(hold: Duration) -> axum::Router {
        axum::Router::new()
            .route("/a", get(move || async move { tokio::time::sleep(hold).await }))
            .route("/b", get(move || async move { tokio::time::sleep(hold).await }))
    }

    /// A request that takes longer than the bound ends with 408.
    #[tokio::test]
    async fn a_slow_request_ends_in_408() {
        // A five-second route with a 50 ms bound.
        let r = super::bounded(slow(Duration::from_secs(5)), Duration::from_millis(50), 4);
        let resp = r.oneshot(Request::get("/a").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
    }

    /// One permit is shared by both routes, so two simultaneous requests run one after the other.
    #[tokio::test]
    async fn the_limit_is_shared_by_every_route() {
        let r = super::bounded(slow(Duration::from_millis(200)), Duration::from_secs(5), 1);
        let started = Instant::now();
        let (a, b) = tokio::join!(
            r.clone().oneshot(Request::get("/a").body(Body::empty()).unwrap()),
            r.clone().oneshot(Request::get("/b").body(Body::empty()).unwrap()),
        );
        assert_eq!(a.unwrap().status(), StatusCode::OK);
        assert_eq!(b.unwrap().status(), StatusCode::OK);
        assert!(started.elapsed() >= Duration::from_millis(400), "two routes, one turn: they ran one after the other");
    }
}
