//! Revolut Business: the incoming legs of completed transactions.
//!
//! Access is OAuth 2.0 with a client assertion (RFC 7523): a JWT signed RS256 with the private key whose certificate
//! was uploaded in Revolut Business (API settings), `iss` the redirect URI's host, `sub` the client id, `aud`
//! `https://revolut.com`. The operator consents once in Revolut's page and exchanges the code for a refresh token
//! ([`exchange_code`], `link-in-bio bank-feed revolut-token`); the feed then refreshes short-lived access tokens with
//! it. When Revolut answers a refresh with a new refresh token, the feed keeps that one in its state.

use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::{BankFeed, Credit, FeedBatch, FeedState, positive_minor, rfc3339, window_start};
use crate::keys::{RsaKey, jwt_rs256};
use crate::{BillingError, bank_transfer};

pub const ID: &str = "revolut";
pub const SANDBOX: &str = "https://sandbox-b2b.revolut.com/api/1.0";
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// Transactions per request (Revolut's maximum), and requests per poll.
pub const COUNT: u32 = 1000;
pub const MAX_PAGES: usize = 10;

#[derive(Debug)]
pub struct Config {
    pub api_base: String,
    pub client_id: String,
    /// The host of the redirect URI registered with the certificate (the assertion's `iss`).
    pub issuer: String,
    pub key: RsaKey,
    pub refresh_token: String,
}

pub struct Revolut {
    config: Config,
    http: reqwest::Client,
    access: Mutex<Option<(String, Instant)>>,
}

fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

/// The client assertion: valid for five minutes.
pub fn client_assertion(
    key: &RsaKey,
    client_id: &str,
    issuer: &str,
    now: DateTime<Utc>,
) -> Result<String, BillingError> {
    jwt_rs256(
        key,
        &json!({ "iss": issuer, "sub": client_id, "aud": "https://revolut.com", "iat": now.timestamp(), "exp": now.timestamp() + 300 }),
    )
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut s = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

async fn token_request(http: &reqwest::Client, api_base: &str, body: String) -> Result<Value, BillingError> {
    let resp = http
        .post(format!("{}/auth/token", api_base.trim_end_matches('/')))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(unavailable)?;
    let status = resp.status();
    let v: Value = resp.json().await.unwrap_or(Value::Null);
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
    let assertion = client_assertion(key, client_id, issuer, Utc::now())?;
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
pub fn credits_from_transactions(list: &Value) -> (Vec<Credit>, Option<DateTime<Utc>>) {
    let mut out = Vec::new();
    let mut earliest: Option<DateTime<Utc>> = None;
    for t in list.as_array().map(Vec::as_slice).unwrap_or_default() {
        let created =
            t["created_at"].as_str().and_then(|c| DateTime::parse_from_rfc3339(c).ok()).map(|c| c.with_timezone(&Utc));
        if let Some(c) = created {
            earliest = Some(earliest.map_or(c, |e| e.min(c)));
        }
        if t["state"].as_str() != Some("completed") || t["type"].as_str() == Some("exchange") {
            continue;
        }
        let id = t["id"].as_str().unwrap_or("");
        for leg in t["legs"].as_array().map(Vec::as_slice).unwrap_or_default() {
            let (Some(minor), Some(currency)) = (positive_minor(&leg["amount"]), leg["currency"].as_str()) else {
                continue;
            };
            let text =
                format!("{} {}", t["reference"].as_str().unwrap_or(""), leg["description"].as_str().unwrap_or(""));
            let Some(reference) = bank_transfer::reference_in_text(&text) else { continue };
            out.push(Credit {
                reference,
                amount_minor: minor,
                currency: currency.to_string(),
                booked: t["completed_at"].as_str().and_then(|c| c.get(..10)).map(String::from),
                entry: format!("revolut-{id}-{}", leg["leg_id"].as_str().unwrap_or("")),
            });
        }
    }
    (out, earliest)
}

impl Revolut {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http, access: Mutex::new(None) }
    }

    /// An access token, refreshed when it is about to expire. A new refresh token, if Revolut sends one, goes into
    /// `state`.
    async fn access_token(&self, state: &mut Value) -> Result<String, BillingError> {
        if let Some((t, until)) = self.access.lock().await.clone()
            && until > Instant::now() + Duration::from_secs(60)
        {
            return Ok(t);
        }
        let refresh =
            state["refreshToken"].as_str().map(String::from).unwrap_or_else(|| self.config.refresh_token.clone());
        let assertion = client_assertion(&self.config.key, &self.config.client_id, &self.config.issuer, Utc::now())?;
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
        let token = v["access_token"].as_str().ok_or_else(|| BillingError::Malformed("no access token".into()))?;
        let ttl = Duration::from_secs(v["expires_in"].as_u64().unwrap_or(600));
        if let Some(r) = v["refresh_token"].as_str().filter(|r| *r != refresh) {
            state["refreshToken"] = json!(r);
        }
        *self.access.lock().await = Some((token.to_string(), Instant::now() + ttl));
        Ok(token.to_string())
    }
}

#[async_trait::async_trait]
impl BankFeed for Revolut {
    fn id(&self) -> &'static str {
        ID
    }

    async fn fetch(&self, from: &FeedState, now: DateTime<Utc>) -> Result<FeedBatch, BillingError> {
        let mut state = if from.state.is_object() { from.state.clone() } else { json!({}) };
        let token = self.access_token(&mut state).await?;
        let start = window_start(from.cursor.as_deref(), now);
        let mut credits = Vec::new();
        let mut to: Option<DateTime<Utc>> = None;
        for _ in 0..MAX_PAGES {
            let mut u = url::Url::parse(&format!("{}/transactions", self.config.api_base.trim_end_matches('/')))
                .map_err(|_| BillingError::Malformed("REVOLUT_API_BASE".into()))?;
            u.query_pairs_mut().append_pair("from", &rfc3339(start)).append_pair("count", &COUNT.to_string());
            if let Some(t) = to {
                u.query_pairs_mut().append_pair("to", &rfc3339(t));
            }
            let resp = self.http.get(u).bearer_auth(&token).send().await.map_err(unavailable)?;
            let status = resp.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                *self.access.lock().await = None;
            }
            let v: Value = resp.json().await.unwrap_or(Value::Null);
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
        let cursor = rfc3339(now);
        Ok(FeedBatch { credits, cursor: Some(cursor), state })
    }
}
