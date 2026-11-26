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
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, Paid, ProviderEvent,
    Refunded, Seller, hmac_sha256, same, send_json,
};

/// The provider id recorded in the ledger and used as the prefix of the method id.
pub const ID: &str = "square";
/// The webhook header that carries the signature, lower-cased as the router passes header names.
pub const SIGNATURE_HEADER: &str = "x-square-hmacsha256-signature";
/// The Square API version this adapter is written against.
pub const VERSION: &str = "2025-10-16";

/// How to reach Square and what the method costs.
#[derive(Debug, Clone)]
pub struct Config {
    /// `https://connect.squareupsandbox.com` (sandbox) or `https://connect.squareup.com`.
    pub api_base: String,
    /// The access token, sent as a bearer token on every API call.
    pub access_token: String,
    /// The Square location the payments are made at.
    pub location_id: String,
    /// The key the webhook signature is made with.
    pub signature_key: String,
    /// The notification URL exactly as registered in Square's dashboard (it is part of what Square signs).
    pub notification_url: String,
    /// The method's fixed fee in pence, used to work out the minimum months.
    pub fixed_pence: u32,
    /// The method's percentage fee in basis points.
    pub percent_bps: u32,
}

/// The adapter.
pub struct Square {
    /// The settings.
    config: Config,
    /// The HTTP client for API calls.
    http: reqwest::Client,
}

impl Square {
    /// An adapter from its settings and a client.
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    /// An API address for a path.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base.trim_end_matches('/'))
    }

    /// A GET request with the access token and the API version.
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(&self.config.access_token).header("Square-Version", VERSION)
    }
}

/// A Square `Money` object (`{ "amount": 1200, "currency": "GBP" }`) as what was paid.
fn money(m: &Value) -> Option<Paid> {
    Some(Paid::Amount { minor: m["amount"].as_u64()?, currency: m["currency"].as_str()?.to_string() })
}

/// Square's signature over `notification URL + body`.
pub fn signature(key: &str, notification_url: &str, body: &[u8]) -> String {
    let mut msg = notification_url.as_bytes().to_vec();
    msg.extend_from_slice(body);
    STANDARD.encode(hmac_sha256(key.as_bytes(), &msg))
}

#[async_trait::async_trait]
impl BillingProvider for Square {
    /// The provider id.
    fn id(&self) -> &'static str {
        ID
    }

    /// One method, a card or a wallet on Square's page, sold by the operator.
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

    /// Create a payment link in pounds with the checkout id as the idempotency key; the buyer pays on Square's page and the order id is the checkout's reference.
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
        // The link's address and its order id, both required.
        let link = &v["payment_link"];
        let (Some(url), Some(order)) = (link["url"].as_str(), link["order_id"].as_str()) else {
            return Err(BillingError::Malformed("no payment link url or order id".into()));
        };
        Ok(CheckoutStart {
            provider_ref: order.into(),
            client: json!({ "kind": "redirect", "provider": ID, "url": url }),
        })
    }

    /// Verify the signature over the notification address and the body, then read a payment (completed is paid, failed or cancelled is failed) or a completed refund. Other states are ignored.
    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        _now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        let got = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        // Square signs the address it was told to call plus the body, so the address in the settings must be exactly the one registered.
        let want = signature(&self.config.signature_key, &self.config.notification_url, body);
        if !same(got.trim().as_bytes(), want.as_bytes()) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        // The event's id, for idempotency of the events that are not payments.
        let event = v["event_id"].as_str().unwrap_or("").to_string();
        match v["type"].as_str() {
            // A payment, new or changed.
            Some("payment.updated") | Some("payment.created") => {
                let p = &v["data"]["object"]["payment"];
                let (Some(order), Some(status)) = (p["order_id"].as_str(), p["status"].as_str()) else {
                    return Err(BillingError::Malformed("no order id or status".into()));
                };
                // Only terminal states matter; a payment still pending reports nothing yet.
                let outcome = match status {
                    "COMPLETED" => Outcome::Paid,
                    "FAILED" | "CANCELED" => Outcome::Failed,
                    _ => return Ok(Vec::new()),
                };
                Ok(vec![ProviderEvent {
                    // A paid event uses the shared ledger key, so a payment seen by notification and by reconciliation extends the period once.
                    event_id: if outcome == Outcome::Paid {
                        self.paid_event_id(order)
                    } else {
                        format!("square:{event}")
                    },
                    provider_ref: order.into(),
                    paid: if outcome == Outcome::Paid { money(&p["amount_money"]) } else { None },
                    outcome,
                    refunded: None,
                    evidence: json!({
                        "event": event, "payment": p["id"], "amount": p["amount_money"], "status": status,
                        "cardBrand": p["card_details"]["card"]["card_brand"], "receipt": p["receipt_url"],
                    }),
                }])
            }
            // A refund, new or changed.
            Some("refund.updated") | Some("refund.created") => {
                let r = &v["data"]["object"]["refund"];
                // A refund counts only once it has completed.
                if r["status"].as_str() != Some("COMPLETED") {
                    return Ok(Vec::new());
                }
                let order = r["order_id"].as_str().ok_or_else(|| BillingError::Malformed("no order id".into()))?;
                Ok(vec![ProviderEvent {
                    event_id: format!("refund:{}", r["id"].as_str().unwrap_or(&event)),
                    provider_ref: order.into(),
                    outcome: Outcome::Refunded,
                    paid: None,
                    // A refund is in the payment's currency (GBP), so it is measured against the checkout's pence.
                    refunded: Some(Refunded {
                        minor: r["amount_money"]["amount"]
                            .as_u64()
                            .ok_or_else(|| BillingError::Malformed("no refund amount".into()))?,
                        of_minor: None,
                    }),
                    evidence: json!({ "event": event, "refund": r["id"], "amount": r["amount_money"] }),
                }])
            }
            // Anything else is acknowledged and ignored.
            _ => Ok(Vec::new()),
        }
    }

    /// Ask Square how an order stands.
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        // An order id is alphanumeric with underscore and hyphen; anything else is not put in a request path.
        if provider_ref.is_empty() || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(BillingError::Malformed("not an order id".into()));
        }
        // The order's state or its total.
        let v = send_json(self.get(&format!("/v2/orders/{provider_ref}"))).await?;
        Ok(match v["order"]["state"].as_str() {
            Some("COMPLETED") => Outcome::Paid,
            Some("CANCELED") => Outcome::Expired,
            _ => Outcome::Open,
        })
    }

    /// The total Square says the order is for, so the app can check the payment covers the checkout.
    async fn paid_facts(&self, provider_ref: &str) -> Result<Option<Paid>, BillingError> {
        if provider_ref.is_empty() || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(BillingError::Malformed("not an order id".into()));
        }
        let v = send_json(self.get(&format!("/v2/orders/{provider_ref}"))).await?;
        Ok(money(&v["order"]["total_money"]))
    }
}
