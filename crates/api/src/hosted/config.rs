//! The hosted service's configuration, from the environment (a ConfigMap; secrets come as files). Every switch defaults
//! to its safest value and each one can only close the service further: nobody else can sign up, no third-party page
//! is served, no payment is taken, unless a switch says so.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{SiteConfig, SiteConfigFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignupMode {
    /// Nobody can create an account (the operator's own accounts are made with the CLI).
    Closed,
    /// Only with an operator-issued invite code.
    Invite,
    /// Anyone (18+) can sign up; publishing needs a paid period.
    Open,
}

#[derive(Debug, thiserror::Error)]
pub enum HostedConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{0}: {1}")]
    Invalid(&'static str, String),
}

#[derive(Debug, Clone)]
pub struct HostedConfig {
    /// The domain tenant pages live under (`<handle>.<pages_domain>`), e.g. `meddleware.link`.
    pub pages_domain: String,
    /// The app host (the passkey RP ID), e.g. `app.meddleware.link`.
    pub app_host: String,
    pub app_origin: String,
    pub product_name: String,
    pub signup: SignupMode,
    pub third_party_pages: bool,
    pub federation: bool,
    pub terms_version: String,
    pub price_pence: u32,
    pub grace_days: i64,
    pub billing_providers: BTreeSet<String>,
    pub billing_countries: BTreeMap<String, BTreeSet<String>>,
    /// Custom domains allowed in total (0 = custom domains off). Hard stop at 100.
    pub custom_hostname_cap: i64,
    pub web_risk_key_file: Option<String>,
    pub web_risk_monthly_cap: i64,
    pub threatfox_key_file: Option<String>,
    pub sui_network: String,
    /// Bytes of pictures one account may store.
    pub asset_quota_bytes: i64,
    /// The page-site template (footer, contact, security policy) every tenant page uses.
    pub site: SiteConfigFile,
    pub chain_payments: Option<ChainPaymentsEnv>,
    pub square: Option<SquareEnv>,
    pub gocardless: Option<GoCardlessEnv>,
    pub paddle: Option<PaddleEnv>,
    pub bank_transfer: Option<BankTransferEnv>,
    pub open_payments: Option<OpenPaymentsEnv>,
    /// The receiving banks' APIs the worker polls for bank-transfer credits (`BANK_FEEDS`); none by default.
    pub bank_feeds: Vec<BankFeedEnv>,
    pub bank_feed_poll_secs: u64,
    pub access: Option<AccessEnv>,
}

/// Provider credentials are files (mounted from Secrets); the API bases default to each provider's sandbox.
#[derive(Debug, Clone)]
pub struct SquareEnv {
    pub api_base: String,
    pub access_token_file: String,
    pub location_id: String,
    pub signature_key_file: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

#[derive(Debug, Clone)]
pub struct GoCardlessEnv {
    pub api_base: String,
    pub access_token_file: String,
    pub webhook_secret_file: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

#[derive(Debug, Clone)]
pub struct PaddleEnv {
    pub api_base: String,
    pub api_key_file: String,
    pub webhook_secret_file: String,
    pub price_id: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

#[derive(Debug, Clone)]
pub struct BankTransferEnv {
    pub payee: String,
    pub scheme: link_in_bio_billing::bank_transfer::Scheme,
}

/// One bank feed's settings (keys and tokens are files; the API bases default to each bank's sandbox).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BankFeedEnv {
    Wise { api_base: String, api_version: String, token_file: String, profile_id: u64, sca_key_file: Option<String> },
    Bunq { api_base: String, api_key_file: String, key_file: String, permitted_ips: Vec<String> },
    Revolut { api_base: String, client_id: String, issuer: String, key_file: String, refresh_token_file: String },
}

/// Open Payments: the operator's wallet address (the payee and the client), the client key's id at the wallet provider
/// and its file, and the wallet's asset.
#[derive(Debug, Clone)]
pub struct OpenPaymentsEnv {
    pub wallet_address: String,
    pub key_id: String,
    pub key_file: String,
    pub asset_code: String,
    pub asset_scale: u8,
    pub minor_per_month: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ChainPaymentsEnv {
    pub merchant_api: String,
    pub public_api: String,
    pub checkout_origin: String,
    pub api_key_file: String,
    pub methods: Vec<(String, String)>,
    pub webhook_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AccessEnv {
    pub team_domain: String,
    pub audience: String,
    pub keto_read_url: String,
    pub admin_origin: String,
}

fn host(var: &'static str, v: &str) -> Result<String, HostedConfigError> {
    let h = v.trim().trim_end_matches('.').to_ascii_lowercase();
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').count() >= 2
        && h.split('.')
            .all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok { Ok(h) } else { Err(HostedConfigError::Invalid(var, "not a host name".into())) }
}

fn countries(v: &str) -> BTreeSet<String> {
    v.split(',')
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()))
        .collect()
}

fn on(get: &impl Fn(&str) -> Option<String>, var: &str, default: bool) -> Result<bool, HostedConfigError> {
    match get(var).as_deref().map(str::trim) {
        None | Some("") => Ok(default),
        Some("on" | "true" | "1") => Ok(true),
        Some("off" | "false" | "0") => Ok(false),
        Some(_) => Err(HostedConfigError::Invalid("switch", format!("{var} must be on or off"))),
    }
}

fn number<T: std::str::FromStr + PartialOrd>(
    get: &impl Fn(&str) -> Option<String>,
    var: &'static str,
    default: T,
    min: T,
    max: T,
) -> Result<T, HostedConfigError> {
    match get(var) {
        None => Ok(default),
        Some(v) => match v.trim().parse::<T>() {
            Ok(n) if n >= min && n <= max => Ok(n),
            _ => Err(HostedConfigError::Invalid(var, "out of range".into())),
        },
    }
}

impl HostedConfig {
    pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Result<Self, HostedConfigError> {
        let pages_domain =
            host("PAGES_DOMAIN", &get("PAGES_DOMAIN").ok_or(HostedConfigError::Missing("PAGES_DOMAIN"))?)?;
        let app_host = host("APP_HOST", &get("APP_HOST").ok_or(HostedConfigError::Missing("APP_HOST"))?)?;
        let signup = match get("SIGNUP_MODE").as_deref().map(str::trim) {
            None | Some("") | Some("closed") => SignupMode::Closed,
            Some("invite") => SignupMode::Invite,
            Some("open") => SignupMode::Open,
            Some(o) => {
                return Err(HostedConfigError::Invalid("SIGNUP_MODE", format!("{o} is not closed, invite or open")));
            }
        };
        let mut billing_providers: BTreeSet<String> = get("BILLING_PROVIDERS")
            .unwrap_or_else(|| "manual".into())
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        billing_providers.insert("manual".into());
        for p in &billing_providers {
            if !["manual", "chain-payments", "square", "gocardless", "paddle", "bank-transfer", "open-payments"]
                .contains(&p.as_str())
            {
                return Err(HostedConfigError::Invalid("BILLING_PROVIDERS", format!("{p} is not a built-in provider")));
            }
        }
        let mut billing_countries = BTreeMap::new();
        for p in &billing_providers {
            let var = format!("{}_COUNTRIES", p.to_ascii_uppercase().replace('-', "_"));
            if let Some(v) = get(&var) {
                billing_countries.insert(p.clone(), countries(&v));
            }
        }
        let chain_payments = if billing_providers.contains("chain-payments") {
            let need = |v: &'static str| get(v).ok_or(HostedConfigError::Missing(v));
            let methods: Vec<(String, String)> = need("CHAIN_PAYMENTS_METHODS")?
                .split(',')
                .filter_map(|m| m.split_once('=').map(|(id, label)| (id.trim().to_string(), label.trim().to_string())))
                .filter(|(id, label)| !id.is_empty() && !label.is_empty())
                .collect();
            if methods.is_empty() {
                return Err(HostedConfigError::Invalid(
                    "CHAIN_PAYMENTS_METHODS",
                    "id=label pairs, comma separated".into(),
                ));
            }
            let checkout_origin = need("CHAIN_PAYMENTS_ORIGIN")?;
            if !checkout_origin.starts_with("https://") {
                return Err(HostedConfigError::Invalid("CHAIN_PAYMENTS_ORIGIN", "must be https".into()));
            }
            Some(ChainPaymentsEnv {
                merchant_api: need("CHAIN_PAYMENTS_MERCHANT_API")?,
                public_api: need("CHAIN_PAYMENTS_PUBLIC_API")?,
                checkout_origin,
                api_key_file: need("CHAIN_PAYMENTS_KEY_FILE")?,
                methods,
                webhook_key: get("CHAIN_PAYMENTS_WEBHOOK_KEY").filter(|k| !k.trim().is_empty()),
            })
        } else {
            None
        };
        let need = |v: &'static str| get(v).filter(|x| !x.trim().is_empty()).ok_or(HostedConfigError::Missing(v));
        let base = |v: &'static str, sandbox: &str| -> Result<String, HostedConfigError> {
            let b = get(v).unwrap_or_else(|| sandbox.to_string());
            if b.starts_with("https://") || b.starts_with("http://127.0.0.1:") {
                Ok(b)
            } else {
                Err(HostedConfigError::Invalid(v, "must be https".into()))
            }
        };
        let square = if billing_providers.contains("square") {
            Some(SquareEnv {
                api_base: base("SQUARE_API_BASE", "https://connect.squareupsandbox.com")?,
                access_token_file: need("SQUARE_ACCESS_TOKEN_FILE")?,
                location_id: need("SQUARE_LOCATION_ID")?,
                signature_key_file: need("SQUARE_SIGNATURE_KEY_FILE")?,
                fixed_pence: number(&get, "SQUARE_FIXED_PENCE", 25u32, 0, 1000)?,
                percent_bps: number(&get, "SQUARE_PERCENT_BPS", 140u32, 0, 2000)?,
            })
        } else {
            None
        };
        let gocardless = if billing_providers.contains("gocardless") {
            Some(GoCardlessEnv {
                api_base: base("GOCARDLESS_API_BASE", "https://api-sandbox.gocardless.com")?,
                access_token_file: need("GOCARDLESS_ACCESS_TOKEN_FILE")?,
                webhook_secret_file: need("GOCARDLESS_WEBHOOK_SECRET_FILE")?,
                fixed_pence: number(&get, "GOCARDLESS_FIXED_PENCE", 20u32, 0, 1000)?,
                percent_bps: number(&get, "GOCARDLESS_PERCENT_BPS", 100u32, 0, 2000)?,
            })
        } else {
            None
        };
        let paddle = if billing_providers.contains("paddle") {
            Some(PaddleEnv {
                api_base: base("PADDLE_API_BASE", "https://sandbox-api.paddle.com")?,
                api_key_file: need("PADDLE_API_KEY_FILE")?,
                webhook_secret_file: need("PADDLE_WEBHOOK_SECRET_FILE")?,
                price_id: need("PADDLE_PRICE_ID")?,
                fixed_pence: number(&get, "PADDLE_FIXED_PENCE", 40u32, 0, 1000)?,
                percent_bps: number(&get, "PADDLE_PERCENT_BPS", 500u32, 0, 2000)?,
            })
        } else {
            None
        };
        let bank_transfer = if billing_providers.contains("bank-transfer") {
            use link_in_bio_billing::bank_transfer::Scheme;
            let scheme = match need("BANK_TRANSFER_SCHEME")?.as_str() {
                "sepa" => Scheme::Sepa {
                    iban: need("BANK_TRANSFER_IBAN")?,
                    bic: get("BANK_TRANSFER_BIC").filter(|b| !b.is_empty()),
                    eur_cents_per_month: number(&get, "BANK_TRANSFER_EUR_CENTS_PER_MONTH", 0u64, 1, 100_000)?,
                },
                "faster-payments" => Scheme::FasterPayments {
                    sort_code: need("BANK_TRANSFER_SORT_CODE")?,
                    account_number: need("BANK_TRANSFER_ACCOUNT_NUMBER")?,
                },
                o => {
                    return Err(HostedConfigError::Invalid(
                        "BANK_TRANSFER_SCHEME",
                        format!("{o} is not sepa or faster-payments"),
                    ));
                }
            };
            Some(BankTransferEnv { payee: need("BANK_TRANSFER_PAYEE")?, scheme })
        } else {
            None
        };
        let open_payments = if billing_providers.contains("open-payments") {
            let wallet_address = need("OPEN_PAYMENTS_WALLET_ADDRESS")?;
            if !(wallet_address.starts_with("https://") || wallet_address.starts_with("http://127.0.0.1:")) {
                return Err(HostedConfigError::Invalid("OPEN_PAYMENTS_WALLET_ADDRESS", "must be https".into()));
            }
            let minor_per_month = match get("OPEN_PAYMENTS_MINOR_PER_MONTH") {
                Some(_) => Some(number(&get, "OPEN_PAYMENTS_MINOR_PER_MONTH", 0u64, 1, 1_000_000_000_000)?),
                None => None,
            };
            Some(OpenPaymentsEnv {
                wallet_address,
                key_id: need("OPEN_PAYMENTS_KEY_ID")?,
                key_file: need("OPEN_PAYMENTS_KEY_FILE")?,
                asset_code: get("OPEN_PAYMENTS_ASSET_CODE").unwrap_or_else(|| "GBP".into()).trim().to_string(),
                asset_scale: number(&get, "OPEN_PAYMENTS_ASSET_SCALE", 2u8, 0, 18)?,
                minor_per_month,
            })
        } else {
            None
        };
        let mut bank_feeds = Vec::new();
        let feeds: BTreeSet<String> = get("BANK_FEEDS")
            .unwrap_or_default()
            .split(',')
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty())
            .collect();
        if !feeds.is_empty() && bank_transfer.is_none() {
            return Err(HostedConfigError::Invalid(
                "BANK_FEEDS",
                "bank feeds reconcile bank transfers: add bank-transfer to BILLING_PROVIDERS".into(),
            ));
        }
        for f in &feeds {
            bank_feeds.push(match f.as_str() {
                "wise" => BankFeedEnv::Wise {
                    api_base: base("WISE_API_BASE", link_in_bio_billing::bank_feed::wise::SANDBOX)?,
                    api_version: get("WISE_API_VERSION")
                        .filter(|v| !v.trim().is_empty())
                        .unwrap_or_else(|| link_in_bio_billing::bank_feed::wise::VERSION.into()),
                    token_file: need("WISE_TOKEN_FILE")?,
                    profile_id: number(&get, "WISE_PROFILE_ID", 0u64, 1, u64::MAX)?,
                    sca_key_file: get("WISE_SCA_KEY_FILE").filter(|v| !v.trim().is_empty()),
                },
                "bunq" => BankFeedEnv::Bunq {
                    api_base: base("BUNQ_API_BASE", link_in_bio_billing::bank_feed::bunq::SANDBOX)?,
                    api_key_file: need("BUNQ_API_KEY_FILE")?,
                    key_file: need("BUNQ_KEY_FILE")?,
                    permitted_ips: get("BUNQ_PERMITTED_IPS")
                        .unwrap_or_default()
                        .split(',')
                        .map(|i| i.trim().to_string())
                        .filter(|i| !i.is_empty())
                        .collect(),
                },
                "revolut" => BankFeedEnv::Revolut {
                    api_base: base("REVOLUT_API_BASE", link_in_bio_billing::bank_feed::revolut::SANDBOX)?,
                    client_id: need("REVOLUT_CLIENT_ID")?,
                    issuer: need("REVOLUT_ISSUER")?,
                    key_file: need("REVOLUT_KEY_FILE")?,
                    refresh_token_file: need("REVOLUT_REFRESH_TOKEN_FILE")?,
                },
                o => return Err(HostedConfigError::Invalid("BANK_FEEDS", format!("{o} is not wise, bunq or revolut"))),
            });
        }
        if bank_feeds.iter().any(|f| matches!(f, BankFeedEnv::Wise { profile_id: 0, .. })) {
            return Err(HostedConfigError::Missing("WISE_PROFILE_ID"));
        }
        let bank_feed_poll_secs = number(&get, "BANK_FEED_POLL_SECS", 900u64, 300, 86_400)?;
        let access = match (get("ACCESS_TEAM_DOMAIN"), get("ACCESS_AUD")) {
            // The team domain is both the token issuer and where its signing keys are fetched: https only, or the keys
            // could be swapped on the way.
            (Some(team), Some(_)) if !team.trim().starts_with("https://") => {
                return Err(HostedConfigError::Invalid("ACCESS_TEAM_DOMAIN", "must be https".into()));
            }
            (Some(team), Some(aud)) if !aud.trim().is_empty() => Some(AccessEnv {
                team_domain: team.trim().trim_end_matches('/').to_string(),
                audience: aud.trim().to_string(),
                keto_read_url: get("KETO_READ_URL").ok_or(HostedConfigError::Missing("KETO_READ_URL"))?,
                admin_origin: get("ADMIN_ORIGIN").ok_or(HostedConfigError::Missing("ADMIN_ORIGIN"))?,
            }),
            _ => None,
        };
        let site: SiteConfigFile = match get("SITE_CONFIG") {
            Some(path) => {
                let bytes =
                    std::fs::read(&path).map_err(|e| HostedConfigError::Invalid("SITE_CONFIG", e.to_string()))?;
                serde_json::from_slice(&bytes).map_err(|e| HostedConfigError::Invalid("SITE_CONFIG", e.to_string()))?
            }
            None => serde_json::from_value(serde_json::json!({ "baseUrl": format!("https://{pages_domain}/") }))
                .map_err(|e| HostedConfigError::Invalid("SITE_CONFIG", e.to_string()))?,
        };
        let custom_hostname_cap = number(&get, "CUSTOM_HOSTNAME_CAP", 0i64, 0, 100)?;
        Ok(Self {
            app_origin: format!("https://{app_host}"),
            product_name: get("PRODUCT_NAME").unwrap_or_else(|| "Link in Bio".into()),
            signup,
            third_party_pages: on(&get, "THIRD_PARTY_PAGES", false)?,
            federation: on(&get, "FEDERATION", true)?,
            terms_version: get("TERMS_VERSION").unwrap_or_else(|| "unset".into()),
            price_pence: number(&get, "PRICE_PENCE", 300u32, 1, 100_000)?,
            grace_days: number(&get, "GRACE_DAYS", 7i64, 0, 60)?,
            billing_providers,
            billing_countries,
            custom_hostname_cap,
            web_risk_key_file: get("WEB_RISK_KEY_FILE").filter(|v| !v.is_empty()),
            web_risk_monthly_cap: number(&get, "WEB_RISK_MONTHLY_CAP", 90_000i64, 0, 100_000)?,
            threatfox_key_file: get("THREATFOX_KEY_FILE").filter(|v| !v.is_empty()),
            sui_network: get("SUI_NETWORK").unwrap_or_else(|| "testnet".into()),
            asset_quota_bytes: number(&get, "ASSET_QUOTA_BYTES", 512 * 1024i64, 64 * 1024, 16 * 1024 * 1024)?,
            pages_domain,
            app_host,
            site,
            chain_payments,
            square,
            gocardless,
            paddle,
            bank_transfer,
            open_payments,
            bank_feeds,
            bank_feed_poll_secs,
            access,
        })
    }

    /// A refusal to sign up is the default: an instance that has not chosen its terms cannot take accounts.
    pub fn signup_open_to_public(&self) -> bool {
        self.signup != SignupMode::Closed && self.terms_version != "unset"
    }

    /// The page-site configuration of one tenant page.
    pub fn site_for(&self, handle: &str, host: &str) -> Result<SiteConfig, crate::config::ConfigError> {
        let mut f = self.site.clone();
        f.base_url = format!("https://{host}/");
        f.federation = self.federation && f.federation;
        f.footer.report_url = Some(format!("{}/report?page={handle}", self.app_origin));
        SiteConfig::from_file(f)
    }

    /// The handle a page host names (`<handle>.<pages_domain>`), if it is one.
    pub fn handle_of_host<'a>(&self, host: &'a str) -> Option<&'a str> {
        let h = host.strip_suffix(&self.pages_domain)?.strip_suffix('.')?;
        (!h.is_empty() && !h.contains('.')).then_some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| pairs.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn defaults_are_closed() {
        let c =
            HostedConfig::from_env(env(&[("PAGES_DOMAIN", "example.link"), ("APP_HOST", "app.example.link")])).unwrap();
        assert_eq!(c.signup, SignupMode::Closed);
        assert!(!c.third_party_pages);
        assert_eq!(c.billing_providers, BTreeSet::from(["manual".to_string()]));
        assert_eq!(c.custom_hostname_cap, 0);
        assert!(c.bank_feeds.is_empty() && c.open_payments.is_none());
        assert!(!c.signup_open_to_public());
        assert_eq!(c.handle_of_host("alice.example.link"), Some("alice"));
        assert_eq!(c.handle_of_host("a.b.example.link"), None);
        assert_eq!(c.handle_of_host("example.link"), None);
        assert_eq!(c.handle_of_host("evilexample.link"), None);
        let s = c.site_for("alice", "alice.example.link").unwrap();
        assert_eq!(s.base_url, "https://alice.example.link/");
        assert_eq!(s.footer.report_url.as_deref(), Some("https://app.example.link/report?page=alice"));
    }

    #[test]
    fn bank_feeds_default_to_the_sandboxes() {
        let c = HostedConfig::from_env(env(&[
            ("PAGES_DOMAIN", "example.link"),
            ("APP_HOST", "app.example.link"),
            ("BILLING_PROVIDERS", "bank-transfer"),
            ("BANK_TRANSFER_SCHEME", "faster-payments"),
            ("BANK_TRANSFER_PAYEE", "Example Ltd"),
            ("BANK_TRANSFER_SORT_CODE", "12-34-56"),
            ("BANK_TRANSFER_ACCOUNT_NUMBER", "12345678"),
            ("BANK_FEEDS", "wise, bunq,revolut"),
            ("WISE_TOKEN_FILE", "/s/wise"),
            ("WISE_PROFILE_ID", "12345"),
            ("BUNQ_API_KEY_FILE", "/s/bunq"),
            ("BUNQ_KEY_FILE", "/s/bunq.pem"),
            ("REVOLUT_CLIENT_ID", "c"),
            ("REVOLUT_ISSUER", "example.org"),
            ("REVOLUT_KEY_FILE", "/s/rev.pem"),
            ("REVOLUT_REFRESH_TOKEN_FILE", "/s/rev.token"),
        ]))
        .unwrap();
        let bases: Vec<String> = c
            .bank_feeds
            .iter()
            .map(|f| match f {
                BankFeedEnv::Wise { api_base, .. }
                | BankFeedEnv::Bunq { api_base, .. }
                | BankFeedEnv::Revolut { api_base, .. } => api_base.clone(),
            })
            .collect();
        assert_eq!(
            bases,
            vec![
                "https://public-api.sandbox.bunq.com/v1",
                "https://sandbox-b2b.revolut.com/api/1.0",
                "https://api.wise-sandbox.com"
            ]
        );
        assert_eq!(c.bank_feed_poll_secs, 900);
    }

    #[test]
    fn refuses_doubtful_values() {
        let base = [("PAGES_DOMAIN", "example.link"), ("APP_HOST", "app.example.link")];
        let with = |extra: (&'static str, &'static str)| {
            let mut v = base.to_vec();
            v.push(extra);
            HostedConfig::from_env(env(&v))
        };
        assert!(with(("SIGNUP_MODE", "everyone")).is_err());
        assert!(with(("THIRD_PARTY_PAGES", "yes")).is_err());
        assert!(with(("BILLING_PROVIDERS", "stripe")).is_err());
        assert!(with(("BILLING_PROVIDERS", "chain-payments")).is_err(), "needs its settings");
        for p in ["square", "gocardless", "paddle", "bank-transfer", "open-payments"] {
            assert!(with(("BILLING_PROVIDERS", p)).is_err(), "{p} needs its settings");
        }
        assert!(with(("BANK_FEEDS", "wise")).is_err(), "bank feeds need bank transfer");
        assert!(with(("CUSTOM_HOSTNAME_CAP", "101")).is_err(), "hard stop at 100");
        assert!(with(("WEB_RISK_MONTHLY_CAP", "100001")).is_err(), "never past the free tier");
        let access = |team: &'static str| {
            let mut v = base.to_vec();
            v.extend([
                ("ACCESS_TEAM_DOMAIN", team),
                ("ACCESS_AUD", "aud"),
                ("KETO_READ_URL", "http://keto.auth.svc.cluster.local:4466"),
                ("ADMIN_ORIGIN", "https://admin.example.org"),
            ]);
            HostedConfig::from_env(env(&v))
        };
        assert!(access("http://team.cloudflareaccess.com").is_err(), "the identity keys come over https only");
        let ok = access("https://team.cloudflareaccess.com/").unwrap().access.unwrap();
        assert_eq!(ok.team_domain, "https://team.cloudflareaccess.com");
        assert!(HostedConfig::from_env(env(&[("PAGES_DOMAIN", "x"), ("APP_HOST", "app.example.link")])).is_err());
    }
}
