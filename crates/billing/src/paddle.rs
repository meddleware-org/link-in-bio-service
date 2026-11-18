//! Paddle Billing, the merchant of record for buyers outside the UK (Paddle sells to them and handles VAT, GST and
//! sales tax). A checkout is a transaction for a catalog price (one month) times the months (`POST /transactions`);
//! the buyer pays on Paddle's hosted checkout (the transaction's `checkout.url`, from the default payment link set in
//! Paddle) and comes back. Paddle notifies `transaction.completed` (and `adjustment.updated` for refunds) signed with
//! `Paddle-Signature: ts=<unix>;h1=<hex HMAC-SHA256(secret, "<ts>:<body>")>`.
//!
//! Fees: 5 % + 50¢ (verify at sign-up); the fixed part is configured in pence.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller,
    hmac_sha256, same, send_json,
};

pub const ID: &str = "paddle";
pub const SIGNATURE_HEADER: &str = "paddle-signature";
/// Notifications older (or newer) than this are refused.
pub const MAX_AGE_SECS: i64 = 300;

#[derive(Debug, Clone)]
pub struct Config {
    /// `https://sandbox-api.paddle.com` or `https://api.paddle.com`.
    pub api_base: String,
    pub api_key: String,
    pub webhook_secret: String,
    /// The catalog price of one month (`pri_…`).
    pub price_id: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

pub struct Paddle {
    config: Config,
    http: reqwest::Client,
}

impl Paddle {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(m, format!("{}{path}", self.config.api_base.trim_end_matches('/')))
            .bearer_auth(&self.config.api_key)
    }
}

/// The `h1` value for a timestamp and body.
pub fn h1(secret: &str, ts: &str, body: &[u8]) -> String {
    let mut msg = format!("{ts}:").into_bytes();
    msg.extend_from_slice(body);
    hex::encode(hmac_sha256(secret.as_bytes(), &msg))
}

#[async_trait::async_trait]
impl BillingProvider for Paddle {
    fn id(&self) -> &'static str {
        ID
    }

    fn methods(&self) -> Vec<Method> {
        vec![Method {
            id: format!("{ID}:checkout"),
            provider: ID.into(),
            label: "Card, PayPal and local methods (Paddle handles tax)".into(),
            seller: Seller::MerchantOfRecord,
            fees: Fees { fixed_pence: self.config.fixed_pence, percent_bps: self.config.percent_bps },
            recurring: false,
        }]
    }

    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        if req.method != format!("{ID}:checkout") {
            return Err(BillingError::NotOffered);
        }
        let v = send_json(self.req(reqwest::Method::POST, "/transactions").json(&json!({
            "items": [{ "price_id": self.config.price_id, "quantity": req.months }],
            "custom_data": { "checkout": req.checkout_id.to_string(), "ref": req.billing_ref },
        })))
        .await?;
        let d = &v["data"];
        let (Some(id), Some(url)) = (d["id"].as_str(), d["checkout"]["url"].as_str()) else {
            return Err(BillingError::Malformed(
                "no transaction id or checkout url (is a default payment link set?)".into(),
            ));
        };
        // Paddle's link opens its overlay or page for the transaction; the return is set on the price's checkout settings.
        Ok(CheckoutStart { provider_ref: id.into(), client: json!({ "kind": "redirect", "provider": ID, "url": url }) })
    }

    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        let header = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        let mut ts = None;
        let mut sigs = Vec::new();
        for part in header.split(';') {
            match part.trim().split_once('=') {
                Some(("ts", v)) => ts = Some(v.to_string()),
                Some(("h1", v)) => sigs.push(v.to_string()),
                _ => {}
            }
        }
        let ts = ts.ok_or(BillingError::Unauthentic)?;
        let t: i64 = ts.parse().map_err(|_| BillingError::Unauthentic)?;
        if (now.unix_timestamp() - t).abs() > MAX_AGE_SECS {
            return Err(BillingError::Unauthentic);
        }
        let want = h1(&self.config.webhook_secret, &ts, body);
        if !sigs.iter().any(|s| same(s.as_bytes(), want.as_bytes())) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        let event = v["event_id"].as_str().unwrap_or("").to_string();
        let d = &v["data"];
        match v["event_type"].as_str() {
            Some("transaction.completed") | Some("transaction.paid") => {
                let id = d["id"].as_str().ok_or_else(|| BillingError::Malformed("no transaction id".into()))?;
                Ok(vec![ProviderEvent {
                    event_id: self.paid_event_id(id),
                    provider_ref: id.into(),
                    outcome: Outcome::Paid,
                    months: None,
                    evidence: json!({
                        "event": event, "currency": d["currency_code"], "totals": d["details"]["totals"],
                        "customer": d["customer_id"], "address": d["address_id"],
                    }),
                }])
            }
            Some("transaction.canceled") => {
                let id = d["id"].as_str().ok_or_else(|| BillingError::Malformed("no transaction id".into()))?;
                Ok(vec![ProviderEvent {
                    event_id: format!("paddle:{event}"),
                    provider_ref: id.into(),
                    outcome: Outcome::Expired,
                    months: None,
                    evidence: json!({ "event": event }),
                }])
            }
            Some("adjustment.updated") | Some("adjustment.created")
                if d["action"].as_str() == Some("refund") && d["status"].as_str() == Some("approved") =>
            {
                let id =
                    d["transaction_id"].as_str().ok_or_else(|| BillingError::Malformed("no transaction id".into()))?;
                Ok(vec![ProviderEvent {
                    event_id: format!("refund:{}", d["id"].as_str().unwrap_or(&event)),
                    provider_ref: id.into(),
                    outcome: Outcome::Refunded,
                    months: None,
                    evidence: json!({ "event": event, "adjustment": d["id"], "totals": d["totals"] }),
                }])
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        if !provider_ref.starts_with("txn_") || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(BillingError::Malformed("not a transaction id".into()));
        }
        let v = send_json(self.req(reqwest::Method::GET, &format!("/transactions/{provider_ref}"))).await?;
        Ok(match v["data"]["status"].as_str() {
            Some("completed") | Some("paid") => Outcome::Paid,
            Some("canceled") => Outcome::Expired,
            _ => Outcome::Open,
        })
    }
}
