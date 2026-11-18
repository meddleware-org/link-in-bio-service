//! bunq: the incoming payments of the operator's monetary accounts.
//!
//! bunq's API context is three steps, the first two once per key:
//!
//! 1. `POST /installation` with the client's RSA public key: an installation token and bunq's server public key
//!    (kept in the feed's state).
//! 2. `POST /device-server` with the API key: registers this installation as a device (optionally only for some IPs).
//! 3. `POST /session-server` with the API key: a session token and the user's id (kept in memory).
//!
//! Every request body is signed (`X-Bunq-Client-Signature`: SHA-256 RSA PKCS #1 v1.5 over the body, base64), and every
//! answer after the installation must carry bunq's signature of its body (`X-Bunq-Server-Signature`), checked with the
//! server key. Payments are read with `newer_id`, one cursor per monetary account; an incoming payment's reference is
//! the `RF…` in its description.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use super::{BankFeed, Credit, FeedBatch, FeedState, positive_minor};
use crate::keys::{self, RsaKey};
use crate::{BillingError, bank_transfer};

pub const ID: &str = "bunq";
pub const SANDBOX: &str = "https://public-api.sandbox.bunq.com/v1";
/// Payments per page, bunq's maximum.
pub const PAGE: usize = 200;
/// Pages read per account per poll.
pub const MAX_PAGES: usize = 10;

#[derive(Debug)]
pub struct Config {
    pub api_base: String,
    pub api_key: String,
    pub key: RsaKey,
    /// The IPs the device may call from (empty: bunq binds it to the address it is registered from).
    pub permitted_ips: Vec<String>,
    pub description: String,
}

#[derive(Clone)]
struct Session {
    token: String,
    user_id: u64,
}

pub struct Bunq {
    config: Config,
    http: reqwest::Client,
    session: Mutex<Option<Session>>,
}

fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

fn bad(m: &str) -> BillingError {
    BillingError::Malformed(m.into())
}

/// The object under `key` in a bunq `Response` array.
pub fn item<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v["Response"].as_array()?.iter().find_map(|o| o.get(key))
}

/// The user id in a session-server answer (whichever kind of user the API key belongs to).
fn user_id(v: &Value) -> Option<u64> {
    ["UserCompany", "UserPerson", "UserApiKey", "UserPaymentServiceProvider"]
        .iter()
        .find_map(|k| item(v, k).and_then(|u| u["id"].as_u64()))
}

/// The credits in a page of bunq payments: incoming (positive) amounts whose description holds a reference.
pub fn credits_from_payments(account: u64, page: &Value) -> (Vec<Credit>, Option<u64>) {
    let mut out = Vec::new();
    let mut newest = None;
    for p in page["Response"].as_array().map(Vec::as_slice).unwrap_or_default().iter().filter_map(|o| o.get("Payment"))
    {
        let Some(id) = p["id"].as_u64() else { continue };
        newest = newest.max(Some(id));
        let (Some(minor), Some(currency)) = (positive_minor(&p["amount"]["value"]), p["amount"]["currency"].as_str())
        else {
            continue;
        };
        let Some(reference) = bank_transfer::reference_in_text(p["description"].as_str().unwrap_or("")) else {
            continue;
        };
        out.push(Credit {
            reference,
            amount_minor: minor,
            currency: currency.to_string(),
            booked: p["created"].as_str().and_then(|c| c.get(..10)).map(String::from),
            entry: format!("bunq-{account}-{id}"),
        });
    }
    (out, newest)
}

impl Bunq {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http, session: Mutex::new(None) }
    }

    /// One request. `auth` is the installation or session token; `server_key` checks the answer's signature.
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        auth: Option<&str>,
        body: Option<&Value>,
        server_key: Option<&str>,
    ) -> Result<Value, BillingError> {
        let url = format!("{}{path}", self.config.api_base.trim_end_matches('/'));
        let mut r = self
            .http
            .request(method, url)
            .header("cache-control", "no-cache")
            .header("x-bunq-language", "en_US")
            .header("x-bunq-region", "nl_NL")
            .header("x-bunq-geolocation", "0 0 0 0 000")
            .header("x-bunq-client-request-id", uuid::Uuid::new_v4().to_string());
        if let Some(a) = auth {
            r = r.header("x-bunq-client-authentication", a);
        }
        if let Some(b) = body {
            let bytes = b.to_string().into_bytes();
            let sig = STANDARD.encode(self.config.key.sign_sha256(&bytes)?);
            r = r.header("content-type", "application/json").header("x-bunq-client-signature", sig).body(bytes);
        }
        let resp = r.send().await.map_err(unavailable)?;
        let status = resp.status();
        let sig = resp.headers().get("x-bunq-server-signature").and_then(|v| v.to_str().ok()).map(String::from);
        let bytes = crate::read_limited(resp, crate::MAX_STATEMENT_BYTES).await?;
        if status == reqwest::StatusCode::UNAUTHORIZED {
            *self.session.lock().await = None;
        }
        if !status.is_success() {
            let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let m =
                v["Error"][0]["error_description"].as_str().unwrap_or("refused").chars().take(200).collect::<String>();
            return Err(if status.is_server_error() || status.as_u16() == 429 {
                BillingError::Unavailable(format!("bunq answered HTTP {}", status.as_u16()))
            } else {
                BillingError::Refused(format!("bunq answered HTTP {}: {m}", status.as_u16()))
            });
        }
        if let Some(k) = server_key {
            let valid =
                sig.and_then(|s| STANDARD.decode(s).ok()).is_some_and(|s| keys::rsa_sha256_valid(k, &bytes, &s));
            if !valid {
                return Err(BillingError::Unauthentic);
            }
        }
        serde_json::from_slice(&bytes).map_err(|_| bad("bunq's answer is not JSON"))
    }

    /// Steps 1 and 2, once: the installation token and server key, kept in the state.
    async fn installation(&self, state: &mut Value) -> Result<(String, String), BillingError> {
        if let (Some(t), Some(k)) = (state["installationToken"].as_str(), state["serverPublicKey"].as_str())
            && state["device"].as_bool() == Some(true)
        {
            return Ok((t.to_string(), k.to_string()));
        }
        let (token, server_key) = match (state["installationToken"].as_str(), state["serverPublicKey"].as_str()) {
            (Some(t), Some(k)) => (t.to_string(), k.to_string()),
            _ => {
                let v = self
                    .call(
                        reqwest::Method::POST,
                        "/installation",
                        None,
                        Some(&json!({ "client_public_key": self.config.key.public_pem() })),
                        None,
                    )
                    .await?;
                let t =
                    item(&v, "Token").and_then(|t| t["token"].as_str()).ok_or_else(|| bad("no installation token"))?;
                let k = item(&v, "ServerPublicKey")
                    .and_then(|k| k["server_public_key"].as_str())
                    .ok_or_else(|| bad("no server public key"))?;
                state["installationToken"] = json!(t);
                state["serverPublicKey"] = json!(k);
                (t.to_string(), k.to_string())
            }
        };
        let mut device = json!({ "description": self.config.description, "secret": self.config.api_key });
        if !self.config.permitted_ips.is_empty() {
            device["permitted_ips"] = json!(self.config.permitted_ips);
        }
        self.call(reqwest::Method::POST, "/device-server", Some(&token), Some(&device), Some(&server_key)).await?;
        state["device"] = json!(true);
        Ok((token, server_key))
    }

    /// Step 3: a session (reused until bunq answers 401).
    async fn session(&self, installation: &str, server_key: &str) -> Result<Session, BillingError> {
        if let Some(s) = self.session.lock().await.clone() {
            return Ok(s);
        }
        let v = self
            .call(
                reqwest::Method::POST,
                "/session-server",
                Some(installation),
                Some(&json!({ "secret": self.config.api_key })),
                Some(server_key),
            )
            .await?;
        let token = item(&v, "Token").and_then(|t| t["token"].as_str()).ok_or_else(|| bad("no session token"))?;
        let user_id = user_id(&v).ok_or_else(|| bad("no user in the session"))?;
        let session = Session { token: token.to_string(), user_id };
        *self.session.lock().await = Some(session.clone());
        Ok(session)
    }
}

#[async_trait::async_trait]
impl BankFeed for Bunq {
    fn id(&self) -> &'static str {
        ID
    }

    async fn fetch(&self, from: &FeedState, _now: OffsetDateTime) -> Result<FeedBatch, BillingError> {
        let mut state = if from.state.is_object() { from.state.clone() } else { json!({}) };
        let (installation, server_key) = self.installation(&mut state).await?;
        let session = self.session(&installation, &server_key).await?;
        let mut cursors: BTreeMap<String, u64> =
            from.cursor.as_deref().and_then(|c| serde_json::from_str(c).ok()).unwrap_or_default();
        let accounts = self
            .call(
                reqwest::Method::GET,
                &format!("/user/{}/monetary-account", session.user_id),
                Some(&session.token),
                None,
                Some(&server_key),
            )
            .await?;
        let mut credits = Vec::new();
        for a in accounts["Response"].as_array().map(Vec::as_slice).unwrap_or_default() {
            // Each entry is `{"MonetaryAccountBank": {…}}`, `{"MonetaryAccountSavings": {…}}`, …
            let Some(acc) = a.as_object().and_then(|o| o.values().next()) else { continue };
            let Some(id) = acc["id"].as_u64() else { continue };
            if acc["status"].as_str().is_some_and(|s| s != "ACTIVE") {
                continue;
            }
            for _ in 0..MAX_PAGES {
                let newer = cursors.get(&id.to_string()).copied();
                let q = match newer {
                    Some(n) => format!("?count={PAGE}&newer_id={n}"),
                    None => format!("?count={PAGE}"),
                };
                let page = self
                    .call(
                        reqwest::Method::GET,
                        &format!("/user/{}/monetary-account/{id}/payment{q}", session.user_id),
                        Some(&session.token),
                        None,
                        Some(&server_key),
                    )
                    .await?;
                let n = page["Response"].as_array().map(Vec::len).unwrap_or(0);
                let (found, newest) = credits_from_payments(id, &page);
                credits.extend(found);
                if let Some(newest) = newest {
                    cursors.insert(id.to_string(), newest.max(newer.unwrap_or(0)));
                }
                // The first poll reads the latest page only; later polls read on while pages are full.
                if newer.is_none() || n < PAGE {
                    break;
                }
            }
        }
        Ok(FeedBatch { credits, cursor: Some(serde_json::to_string(&cursors).map_err(|_| bad("cursor"))?), state })
    }
}
