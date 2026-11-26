//! Revolut Business: the incoming legs of completed transactions.
//!
//! Access is OAuth 2.0 with a client assertion (RFC 7523): a JWT signed RS256 with the private key whose certificate
//! was uploaded in Revolut Business (API settings), `iss` the redirect URI's host, `sub` the client id, `aud`
//! `https://revolut.com`. The operator consents once in Revolut's page and exchanges the code for a refresh token
//! ([`exchange_code`], `link-in-bio bank-feed revolut-token`); the feed then refreshes short-lived access tokens with
//! it. When Revolut answers a refresh with a new refresh token, the feed keeps that one in its state.

use std::time::{Duration, Instant};

use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::{BankFeed, Credit, FeedBatch, FeedState, positive_minor, rfc3339, window_start};
use crate::keys::{RsaKey, jwt_rs256};
use crate::{BillingError, bank_transfer};

/// The feed's id, as stored with its cursor.
pub const ID: &str = "revolut";
/// Revolut Business's sandbox address, the default until a live address is configured.
pub const SANDBOX: &str = "https://sandbox-b2b.revolut.com/api/1.0";
/// The client-assertion type for a JWT bearer assertion (RFC 7523).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Transactions per request (Revolut's maximum), and requests per poll.
pub const COUNT: u32 = 1000;
/// The most pages read in one poll.
pub const MAX_PAGES: usize = 10;

/// How to reach Revolut Business and authenticate.
#[derive(Debug)]
pub struct Config {
    /// The API's base address.
    pub api_base: String,
    /// The client id from the API settings.
    pub client_id: String,
    /// The host of the redirect URI registered with the certificate (the assertion's `iss`).
    pub issuer: String,
    /// The private key that signs the assertion.
    pub key: RsaKey,
    /// The refresh token from the one-time consent exchange.
    pub refresh_token: String,
}

/// The feed.
pub struct Revolut {
    /// The settings.
    config: Config,
    /// The HTTP client.
    http: reqwest::Client,
    /// The current access token and when it expires.
    access: Mutex<Option<(String, Instant)>>,
}

/// The client assertion: valid for five minutes.
pub fn client_assertion(
    key: &RsaKey,
    client_id: &str,
    issuer: &str,
    now: OffsetDateTime,
) -> Result<String, BillingError> {
    jwt_rs256(
        key,
        &json!({ "iss": issuer, "sub": client_id, "aud": "https://revolut.com", "iat": now.unix_timestamp(), "exp": now.unix_timestamp() + 300 }),
    )
}

/// A form-encoded body from name and value pairs, escaped.
fn form(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

/// Post a token request and read the answer; a failure carries Revolut's own description, shortened.
async fn token_request(http: &reqwest::Client, api_base: &str, body: String) -> Result<Value, BillingError> {
    let resp = http
        .post(format!("{}/auth/token", api_base.trim_end_matches('/')))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(crate::transport)?;
    let status = resp.status();
    let v: Value = crate::read_json_or_null(resp, crate::MAX_STATEMENT_BYTES).await?;
    if status.is_success() {
        Ok(v)
    } else if status.is_server_error() {
        Err(BillingError::Unavailable(format!("Revolut answered HTTP {}", status.as_u16())))
    } else {
        let m: String =
            v["error_description"].as_str().or(v["error"].as_str()).unwrap_or("refused").chars().take(200).collect();
        Err(BillingError::Refused(format!("Revolut answered HTTP {}: {m}", status.as_u16())))
    }
}

/// The one-time exchange of the consent page's authorisation code for a refresh token.
pub async fn exchange_code(
    http: &reqwest::Client,
    api_base: &str,
    client_id: &str,
    issuer: &str,
    key: &RsaKey,
    code: &str,
) -> Result<String, BillingError> {
    let assertion = client_assertion(key, client_id, issuer, OffsetDateTime::now_utc())?;
    let v = token_request(
        http,
        api_base,
        form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ]),
    )
    .await?;
    v["refresh_token"].as_str().map(String::from).ok_or_else(|| BillingError::Malformed("no refresh token".into()))
}

/// The credits in a transactions list: incoming legs of completed transactions whose reference (or the leg's
/// description) holds a creditor reference. Also the earliest `created_at` seen (Revolut lists the newest first).
pub fn credits_from_transactions(list: &Value) -> (Vec<Credit>, Option<OffsetDateTime>) {
    let mut out = Vec::new();
    // The earliest creation time on the page, for the next page.
    let mut earliest: Option<OffsetDateTime> = None;
    for t in list.as_array().map(Vec::as_slice).unwrap_or_default() {
        // Track the earliest time seen, so the next page continues from there.
        let created = t["created_at"].as_str().and_then(crate::parse_rfc3339);
        if let Some(c) = created {
            earliest = Some(earliest.map_or(c, |e| e.min(c)));
        }
        // Only completed transactions count, and a currency exchange is not a payment.
        if t["state"].as_str() != Some("completed") || t["type"].as_str() == Some("exchange") {
            continue;
        }
        // The transaction id, for the ledger entry.
        let id = t["id"].as_str().unwrap_or("");
        // A transaction has legs; the incoming ones with a positive amount are the credits.
        for leg in t["legs"].as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(minor), Some(currency)) = (positive_minor(&leg["amount"]), leg["currency"].as_str()) else {
                continue;
            };
            let text =
                format!("{} {}", t["reference"].as_str().unwrap_or(""), leg["description"].as_str().unwrap_or(""));
            // Only a whole, valid creditor reference pays a checkout.
            let Some(reference) = bank_transfer::reference_in_text(&text) else { continue };
            out.push(Credit {
                reference,
                amount_minor: minor,
                currency: currency.to_string(),
                booked: t["completed_at"].as_str().and_then(|c| c.get(..10)).map(String::from),
                entry: format!("revolut-{id}-{}", leg["leg_id"].as_str().unwrap_or("")),
                debtor: None,
            });
        }
    }
    (out, earliest)
}

impl Revolut {
    /// A feed from its settings and a client.
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http, access: Mutex::new(None) }
    }

    /// An access token, refreshed when it is about to expire. A new refresh token, if Revolut sends one, goes into
    /// `state`.
    async fn access_token(&self, state: &mut Value) -> Result<String, BillingError> {
        // A token with more than a minute left is reused.
        if let Some((t, until)) = self.access.lock().await.clone()
            && until > Instant::now() + Duration::from_secs(60)
        {
            return Ok(t);
        }
        let refresh =
            state["refreshToken"].as_str().map(String::from).unwrap_or_else(|| self.config.refresh_token.clone());
        let assertion =
            client_assertion(&self.config.key, &self.config.client_id, &self.config.issuer, OffsetDateTime::now_utc())?;
        let v = token_request(
            &self.http,
            &self.config.api_base,
            form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &self.config.client_id),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ]),
        )
        .await?;
        // The answer must hold an access token; its lifetime defaults to ten minutes if the answer gives none.
        let token = v["access_token"].as_str().ok_or_else(|| BillingError::Malformed("no access token".into()))?;
        let ttl = Duration::from_secs(v["expires_in"].as_u64().unwrap_or(600));
        // A replaced refresh token is kept in the feed's state, because the old one no longer works.
        if let Some(r) = v["refresh_token"].as_str().filter(|r| *r != refresh) {
            state["refreshToken"] = json!(r);
        }
        *self.access.lock().await = Some((token.to_string(), Instant::now() + ttl));
        Ok(token.to_string())
    }
}

#[async_trait::async_trait]
impl BankFeed for Revolut {
    /// The feed's id.
    fn id(&self) -> &'static str {
        ID
    }

    /// Read the transactions of the window, page by page, newest first, and collect the credits.
    async fn fetch(&self, from: &FeedState, now: OffsetDateTime) -> Result<FeedBatch, BillingError> {
        // The feed's state is an object; anything else is replaced by an empty one.
        let mut state = if from.state.is_object() { from.state.clone() } else { json!({}) };
        let token = self.access_token(&mut state).await?;
        let start = window_start(from.cursor.as_deref(), now);
        let mut credits = Vec::new();
        let mut to: Option<OffsetDateTime> = None;
        // At most ten pages a poll.
        for _ in 0..MAX_PAGES {
            let mut u = url::Url::parse(&format!("{}/transactions", self.config.api_base.trim_end_matches('/')))
                .map_err(|_| BillingError::Malformed("REVOLUT_API_BASE".into()))?;
            u.query_pairs_mut().append_pair("from", &rfc3339(start)).append_pair("count", &COUNT.to_string());
            if let Some(t) = to {
                u.query_pairs_mut().append_pair("to", &rfc3339(t));
            }
            let resp = self.http.get(u).bearer_auth(&token).send().await.map_err(crate::transport)?;
            let status = resp.status();
            // A rejected token is forgotten, so the next call refreshes it.
            if status == reqwest::StatusCode::UNAUTHORIZED {
                *self.access.lock().await = None;
            }
            let v: Value = crate::read_json_or_null(resp, crate::MAX_STATEMENT_BYTES).await?;
            if !status.is_success() {
                return Err(if status.is_server_error() || status.as_u16() == 429 {
                    BillingError::Unavailable(format!("Revolut answered HTTP {}", status.as_u16()))
                } else {
                    BillingError::Refused(format!(
                        "Revolut answered HTTP {}: {}",
                        status.as_u16(),
                        crate::provider_message(&v)
                    ))
                });
            }
            let (found, earliest) = credits_from_transactions(&v);
            credits.extend(found);
            // A full page: the older ones of the window are on the next (newest first).
            match earliest {
                Some(e) if v.as_array().map(Vec::len).unwrap_or(0) >= COUNT as usize && to != Some(e) => to = Some(e),
                _ => break,
            }
        }
        // The next poll starts from now (less the overlap).
        let cursor = rfc3339(now);
        Ok(FeedBatch { credits, cursor: Some(cursor), state })
    }
}
