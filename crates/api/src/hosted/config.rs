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
    pub access: Option<AccessEnv>,
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
            if !["manual", "chain-payments"].contains(&p.as_str()) {
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
        let access = match (get("ACCESS_TEAM_DOMAIN"), get("ACCESS_AUD")) {
            (Some(team), Some(aud)) if !aud.trim().is_empty() => Some(AccessEnv {
                team_domain: team.trim_end_matches('/').to_string(),
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
        assert!(with(("CUSTOM_HOSTNAME_CAP", "101")).is_err(), "hard stop at 100");
        assert!(with(("WEB_RISK_MONTHLY_CAP", "100001")).is_err(), "never past the free tier");
        assert!(HostedConfig::from_env(env(&[("PAGES_DOMAIN", "x"), ("APP_HOST", "app.example.link")])).is_err());
    }
}
