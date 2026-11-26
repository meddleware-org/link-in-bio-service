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

/// The feed's id, as stored with its cursor.
pub const ID: &str = "wise";
/// Wise's sandbox address, the default until a live address is configured.
pub const SANDBOX: &str = "https://api.wise-sandbox.com";
/// The API version in Wise's paths (`/<version>/profiles/…`).
pub const VERSION: &str = "2026Q4";
/// Wise refuses statement intervals longer than this.
pub const MAX_INTERVAL_DAYS: i64 = 469;

/// How to reach Wise and which profile to read.
#[derive(Debug)]
pub struct Config {
    /// The API's base address.
    pub api_base: String,
    /// The API version used in the paths.
    pub api_version: String,
    /// The API token, sent as a bearer token.
    pub token: String,
    /// The business profile whose balances are read.
    pub profile_id: u64,
    /// The key whose public half is uploaded to Wise, for SCA. Without it an SCA challenge is an error.
    pub sca_key: Option<RsaKey>,
}

/// The feed.
pub struct Wise {
    /// The settings.
    config: Config,
    /// The HTTP client.
    http: reqwest::Client,
}

impl Wise {
    /// A feed from its settings and a client.
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    /// An API address for a path, with the version.
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
        // One request, optionally with the one-time token and its signature.
        let send = |ott: Option<(&str, &str)>| {
            let mut r = self.http.get(url).bearer_auth(&self.config.token);
            if let Some((t, sig)) = ott {
                r = r.header("x-2fa-approval", t).header("X-Signature", sig);
            }
            r.send()
        };
        // The first request carries no token; Wise answers 403 with one if it wants strong customer authentication.
        let mut resp = send(None).await.map_err(crate::transport)?;
        if resp.status() == reqwest::StatusCode::FORBIDDEN
            && let Some(ott) = resp.headers().get("x-2fa-approval").and_then(|v| v.to_str().ok()).map(String::from)
        {
            // Without a key to sign with, the challenge cannot be answered, and the error names the setting to fix.
            let key = self.config.sca_key.as_ref().ok_or_else(|| {
                BillingError::Refused("Wise asks for strong customer authentication; set WISE_SCA_KEY_FILE".into())
            })?;
            let sig = Self::sca_signature(key, &ott)?;
            resp = send(Some((&ott, &sig))).await.map_err(crate::transport)?;
        }
        // The body is read with a limit, because a statement can be large but not unbounded.
        let status = resp.status();
        let text = String::from_utf8(crate::read_limited(resp, crate::MAX_STATEMENT_BYTES).await?)
            .map_err(|_| BillingError::Malformed("Wise answered something that is not UTF-8 text".into()))?;
        if status.is_success() {
            Ok(text)
        // A server error or a rate limit is worth trying again later; any other failure is a refusal.
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
    /// The feed's id.
    fn id(&self) -> &'static str {
        ID
    }

    /// Read the statement of every standard balance for the window and collect the credits in them, naming each entry after its balance so the same entry in two currencies cannot collide.
    async fn fetch(&self, from: &FeedState, now: OffsetDateTime) -> Result<FeedBatch, BillingError> {
        // The window starts at the cursor less the overlap, and never before Wise's longest interval.
        let start = window_start(from.cursor.as_deref(), now).max(now - time::Duration::days(MAX_INTERVAL_DAYS));
        let balances: Value = serde_json::from_str(
            &self.get(&self.url(&format!("/profiles/{}/balances?types=STANDARD", self.config.profile_id))).await?,
        )
        .map_err(|_| BillingError::Malformed("Wise's balances are not JSON".into()))?;
        let mut credits = Vec::new();
        for b in balances.as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(id), Some(currency)) = (b["id"].as_u64(), b["currency"].as_str()) else { continue };
            // A currency code is three capital letters; anything else is skipped rather than put in a request.
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
                // The compact statement type keeps the answer small.
                .append_pair("type", "COMPACT");
            let xml = self.get(u.as_str()).await?;
            for mut c in bank_transfer::credits_from_camt(&xml)? {
                // The ledger id carries the balance id, so entries of different balances never collide.
                c.entry = format!("wise-{id}-{}", c.entry);
                credits.push(c);
            }
        }
        // The next poll starts from now (less the overlap); Wise keeps no state here.
        Ok(FeedBatch { credits, cursor: Some(rfc3339(now)), state: json!({}) })
    }
}
