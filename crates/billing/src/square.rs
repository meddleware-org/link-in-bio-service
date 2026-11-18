//! Square (UK cards, Apple Pay and Google Pay on Square's hosted checkout page). A checkout is a payment link
//! (`POST /v2/online-checkout/payment-links`, quick pay in GBP); the buyer pays on Square's page and comes back. Square
//! notifies `payment.updated` (and `refund.updated`) signed with
//! `x-square-hmacsha256-signature = base64(HMAC-SHA256(signature key, notification URL + body))`.
//! The checkout's reference is the payment link's order id, which both events carry.
//!
//! The operator is the seller (UK only by default). Fees: 1.4 % + 25p for UK cards (verify at sign-up).

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller,
    hmac_sha256, same, send_json,
};

pub const ID: &str = "square";
pub const SIGNATURE_HEADER: &str = "x-square-hmacsha256-signature";
/// The Square API version this adapter is written against.
pub const VERSION: &str = "2025-10-16";

#[derive(Debug, Clone)]
pub struct Config {
    /// `https://connect.squareupsandbox.com` (sandbox) or `https://connect.squareup.com`.
    pub api_base: String,
    pub access_token: String,
    pub location_id: String,
    pub signature_key: String,
    /// The notification URL exactly as registered in Square's dashboard (it is part of what Square signs).
    pub notification_url: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

pub struct Square {
    config: Config,
    http: reqwest::Client,
}

impl Square {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base.trim_end_matches('/'))
    }

    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(&self.config.access_token).header("Square-Version", VERSION)
    }
}

/// Square's signature over `notification URL + body`.
pub fn signature(key: &str, notification_url: &str, body: &[u8]) -> String {
    let mut msg = notification_url.as_bytes().to_vec();
    msg.extend_from_slice(body);
    STANDARD.encode(hmac_sha256(key.as_bytes(), &msg))
}

#[async_trait::async_trait]
impl BillingProvider for Square {
    fn id(&self) -> &'static str {
        ID
    }

    fn methods(&self) -> Vec<Method> {
        vec![Method {
            id: format!("{ID}:card"),
            provider: ID.into(),
            label: "Card, Apple Pay or Google Pay".into(),
            seller: Seller::Operator,
            fees: Fees { fixed_pence: self.config.fixed_pence, percent_bps: self.config.percent_bps },
            recurring: false,
        }]
    }

    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        if req.method != format!("{ID}:card") {
            return Err(BillingError::NotOffered);
        }
        let body = json!({
            "idempotency_key": req.checkout_id,
            "quick_pay": {
                "name": req.description,
                "price_money": { "amount": req.amount_pence, "currency": "GBP" },
                "location_id": self.config.location_id,
            },
            "checkout_options": { "redirect_url": req.return_url, "ask_for_shipping_address": false },
            "payment_note": req.billing_ref,
        });
        let v = send_json(
            self.http
                .post(self.url("/v2/online-checkout/payment-links"))
                .bearer_auth(&self.config.access_token)
                .header("Square-Version", VERSION)
                .json(&body),
        )
        .await?;
        let link = &v["payment_link"];
        let (Some(url), Some(order)) = (link["url"].as_str(), link["order_id"].as_str()) else {
            return Err(BillingError::Malformed("no payment link url or order id".into()));
        };
        Ok(CheckoutStart {
            provider_ref: order.into(),
            client: json!({ "kind": "redirect", "provider": ID, "url": url }),
        })
    }

    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        _now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        let got = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        let want = signature(&self.config.signature_key, &self.config.notification_url, body);
        if !same(got.trim().as_bytes(), want.as_bytes()) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        let event = v["event_id"].as_str().unwrap_or("").to_string();
        match v["type"].as_str() {
            Some("payment.updated") | Some("payment.created") => {
                let p = &v["data"]["object"]["payment"];
                let (Some(order), Some(status)) = (p["order_id"].as_str(), p["status"].as_str()) else {
                    return Err(BillingError::Malformed("no order id or status".into()));
                };
                let outcome = match status {
                    "COMPLETED" => Outcome::Paid,
                    "FAILED" | "CANCELED" => Outcome::Failed,
                    _ => return Ok(Vec::new()),
                };
                Ok(vec![ProviderEvent {
                    event_id: if outcome == Outcome::Paid {
                        self.paid_event_id(order)
                    } else {
                        format!("square:{event}")
                    },
                    provider_ref: order.into(),
                    outcome,
                    months: None,
                    evidence: json!({
                        "event": event, "payment": p["id"], "amount": p["amount_money"], "status": status,
                        "cardBrand": p["card_details"]["card"]["card_brand"], "receipt": p["receipt_url"],
                    }),
                }])
            }
            Some("refund.updated") | Some("refund.created") => {
                let r = &v["data"]["object"]["refund"];
                if r["status"].as_str() != Some("COMPLETED") {
                    return Ok(Vec::new());
                }
                let order = r["order_id"].as_str().ok_or_else(|| BillingError::Malformed("no order id".into()))?;
                Ok(vec![ProviderEvent {
                    event_id: format!("refund:{}", r["id"].as_str().unwrap_or(&event)),
                    provider_ref: order.into(),
                    outcome: Outcome::Refunded,
                    months: None,
                    evidence: json!({ "event": event, "refund": r["id"], "amount": r["amount_money"] }),
                }])
            }
            _ => Ok(Vec::new()),
        }
    }

    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        if provider_ref.is_empty() || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(BillingError::Malformed("not an order id".into()));
        }
        let v = send_json(self.get(&format!("/v2/orders/{provider_ref}"))).await?;
        Ok(match v["order"]["state"].as_str() {
            Some("COMPLETED") => Outcome::Paid,
            Some("CANCELED") => Outcome::Expired,
            _ => Outcome::Open,
        })
    }
}
