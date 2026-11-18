//! Wise: the incoming credits of every standard balance of the operator's business profile, from its balance
//! statements in ISO 20022 camt.053 (`statement.xml`), read by the same parser as an imported statement.
//!
//! Statements are SCA protected for profiles outside a few regions (the UK and EEA included): the first request is
//! refused with `403` and a one-time token in `x-2fa-approval`; the request is repeated with that token and
//! `X-Signature`, the token signed with the operator's RSA key (SHA-256, PKCS #1 v1.5, base64) whose public key was
//! uploaded to Wise. Wise asks for this at most once every 90 days per token.
//!
//! Wise's documentation (2026) says personal API tokens of UK and EEA business accounts may not read balance statements
//! at all; such an account needs Wise's partner access. The sandbox is where this adapter was checked against.

use serde_json::{Value, json};
use time::OffsetDateTime;

use super::{BankFeed, FeedBatch, FeedState, rfc3339, window_start};
use crate::keys::RsaKey;
use crate::{BillingError, bank_transfer};

pub const ID: &str = "wise";
pub const SANDBOX: &str = "https://api.wise-sandbox.com";
/// The API version in Wise's paths (`/<version>/profiles/…`).
pub const VERSION: &str = "2026Q4";
/// Wise refuses statement intervals longer than this.
pub const MAX_INTERVAL_DAYS: i64 = 469;

#[derive(Debug)]
pub struct Config {
    pub api_base: String,
    pub api_version: String,
    pub token: String,
    pub profile_id: u64,
    /// The key whose public half is uploaded to Wise, for SCA. Without it an SCA challenge is an error.
    pub sca_key: Option<RsaKey>,
}

pub struct Wise {
    config: Config,
    http: reqwest::Client,
}

fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

impl Wise {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}{path}", self.config.api_base.trim_end_matches('/'), self.config.api_version)
    }

    /// The `X-Signature` for a one-time token.
    pub fn sca_signature(key: &RsaKey, one_time_token: &str) -> Result<String, BillingError> {
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(key.sign_sha256(one_time_token.as_bytes())?))
    }

    /// A GET, answering Wise's SCA challenge once if it makes one. Returns the body text.
    async fn get(&self, url: &str) -> Result<String, BillingError> {
        let send = |ott: Option<(&str, &str)>| {
            let mut r = self.http.get(url).bearer_auth(&self.config.token);
            if let Some((t, sig)) = ott {
                r = r.header("x-2fa-approval", t).header("X-Signature", sig);
            }
            r.send()
        };
        let mut resp = send(None).await.map_err(unavailable)?;
        if resp.status() == reqwest::StatusCode::FORBIDDEN
            && let Some(ott) = resp.headers().get("x-2fa-approval").and_then(|v| v.to_str().ok()).map(String::from)
        {
            let key = self.config.sca_key.as_ref().ok_or_else(|| {
                BillingError::Refused("Wise asks for strong customer authentication; set WISE_SCA_KEY_FILE".into())
            })?;
            let sig = Self::sca_signature(key, &ott)?;
            resp = send(Some((&ott, &sig))).await.map_err(unavailable)?;
        }
        let status = resp.status();
        let text = String::from_utf8(crate::read_limited(resp, crate::MAX_STATEMENT_BYTES).await?)
            .map_err(|_| BillingError::Malformed("Wise answered something that is not UTF-8 text".into()))?;
        if status.is_success() {
            Ok(text)
        } else if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Err(BillingError::Unavailable(format!("Wise answered HTTP {}", status.as_u16())))
        } else {
            let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
            Err(BillingError::Refused(format!(
                "Wise answered HTTP {}: {}",
                status.as_u16(),
                crate::provider_message(&v)
            )))
        }
    }
}

#[async_trait::async_trait]
impl BankFeed for Wise {
    fn id(&self) -> &'static str {
        ID
    }

    async fn fetch(&self, from: &FeedState, now: OffsetDateTime) -> Result<FeedBatch, BillingError> {
        let start = window_start(from.cursor.as_deref(), now).max(now - time::Duration::days(MAX_INTERVAL_DAYS));
        let balances: Value = serde_json::from_str(
            &self.get(&self.url(&format!("/profiles/{}/balances?types=STANDARD", self.config.profile_id))).await?,
        )
        .map_err(|_| BillingError::Malformed("Wise's balances are not JSON".into()))?;
        let mut credits = Vec::new();
        for b in balances.as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(id), Some(currency)) = (b["id"].as_u64(), b["currency"].as_str()) else { continue };
            if currency.len() != 3 || !currency.bytes().all(|c| c.is_ascii_uppercase()) {
                continue;
            }
            let mut u = url::Url::parse(
                &self.url(&format!("/profiles/{}/balance-statements/{id}/statement.xml", self.config.profile_id)),
            )
            .map_err(|_| BillingError::Malformed("WISE_API_BASE".into()))?;
            u.query_pairs_mut()
                .append_pair("currency", currency)
                .append_pair("intervalStart", &rfc3339(start))
                .append_pair("intervalEnd", &rfc3339(now))
                .append_pair("type", "COMPACT");
            let xml = self.get(u.as_str()).await?;
            for mut c in bank_transfer::credits_from_camt(&xml)? {
                c.entry = format!("wise-{id}-{}", c.entry);
                credits.push(c);
            }
        }
        Ok(FeedBatch { credits, cursor: Some(rfc3339(now)), state: json!({}) })
    }
}
