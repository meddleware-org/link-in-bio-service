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

pub mod access;
pub mod admin;
pub mod app;
pub mod config;
pub mod error;
pub mod internal;
pub mod jobs;
pub mod jwt;
pub mod metrics;
pub mod openapi;
pub mod pages;
pub mod routes;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use link_in_bio_auth::passkey::Passkeys;
use link_in_bio_billing::chain_payments::{self, ChainPayments};
use link_in_bio_billing::{BillingProvider, Router as Billing, RouterConfig};
use link_in_bio_safety::{Screener, WebRisk};
use link_in_bio_store::Store;

pub use config::{HostedConfig, SignupMode};
pub use error::{ApiError, ApiResult};

pub struct App {
    pub store: Store,
    pub config: HostedConfig,
    pub billing: Billing,
    pub passkeys: Passkeys,
    pub screener: Screener,
    pub metrics: metrics::Metrics,
    pub pages: pages::PageCache,
    pub access: Option<Arc<access::Admins>>,
    /// The Open Payments adapter (also in `billing`), for the steps of its checkout beyond the port.
    pub open_payments: Option<Arc<link_in_bio_billing::open_payments::OpenPayments>>,
}

pub type Shared = Arc<App>;

fn read_secret(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map(|s| s.trim().to_string()).map_err(|e| format!("{path}: {e}"))
}

impl App {
    /// Builds the state for any role. `page_cache` is how long a built tenant page is reused (and so how soon a
    /// suspension or a new version shows).
    pub fn new(store: Store, config: HostedConfig, page_cache: Duration) -> Result<Self, String> {
        let passkeys =
            Passkeys::new(&config.app_host, &config.app_origin, &config.product_name).map_err(|e| e.to_string())?;
        let mut providers: Vec<Box<dyn BillingProvider>> = vec![Box::new(link_in_bio_billing::manual::Manual)];
        if let Some(cp) = &config.chain_payments {
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
        let file = |f: &str| read_secret(f);
        if let Some(c) = &config.square {
            providers.push(Box::new(link_in_bio_billing::square::Square::new(
                link_in_bio_billing::square::Config {
                    api_base: c.api_base.clone(),
                    access_token: file(&c.access_token_file)?,
                    location_id: c.location_id.clone(),
                    signature_key: file(&c.signature_key_file)?,
                    notification_url: format!("{}/api/v1/webhooks/square", config.app_origin),
                    fixed_pence: c.fixed_pence,
                    percent_bps: c.percent_bps,
                },
                link_in_bio_billing::http_client(),
            )));
        }
        if let Some(c) = &config.gocardless {
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
        if let Some(c) = &config.paddle {
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
        let mut open_payments = None;
        if let Some(c) = &config.open_payments {
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
                    link_in_bio_billing::http_client(),
                )
                .map_err(|e| e.to_string())?,
            );
            providers.push(Box::new(p.clone()));
            open_payments = Some(p);
        }
        let billing = Billing::new(
            RouterConfig {
                price_pence: config.price_pence,
                enabled: config.billing_providers.clone(),
                countries: config.billing_countries.clone(),
            },
            providers,
        );
        let web_risk = match &config.web_risk_key_file {
            Some(f) if config.web_risk_monthly_cap > 0 => {
                Some(WebRisk::new(read_secret(f)?, config.web_risk_monthly_cap))
            }
            _ => None,
        };
        let access = config.access.as_ref().map(|a| {
            access::Admins::new(access::AccessConfig {
                issuer: a.team_domain.clone(),
                audience: a.audience.clone(),
                jwks: access::JwksSource::Remote(format!("{}/cdn-cgi/access/certs", a.team_domain)),
                roles: access::RoleSource::Keto(a.keto_read_url.clone()),
                admin_origin: a.admin_origin.clone(),
            })
        });
        Ok(Self {
            store,
            config,
            billing,
            passkeys,
            screener: Screener { web_risk },
            metrics: metrics::Metrics::default(),
            pages: pages::PageCache::new(page_cache),
            access,
            open_payments,
        })
    }
}

/// The current time (one place, so tests can reason about it).
pub fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// The rules an account's page document is parsed with, by the app when it is saved and published and by the page
/// server when it is shown (the same rules on both sides, so a page the app published is a page that is served). The
/// handle is not checked against the reserved list here: the account's handle passed that check at sign-up (or is the
/// operator's own, created by the operator), and the app requires the document to carry exactly that handle.
pub fn account_page_options() -> link_in_bio_core::ParseOptions {
    link_in_bio_core::ParseOptions { owner: link_in_bio_core::Owner::Tenant, check_reserved: false }
}
