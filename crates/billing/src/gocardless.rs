//! GoCardless (UK bank payments: Instant Bank Pay over Open Banking, or Bacs). A checkout is a billing request with a
//! one-off payment request in GBP and a hosted flow (`POST /billing_requests`, then `POST /billing_request_flows`); the
//! buyer authorises in their own bank and comes back. GoCardless notifies batches of events signed with
//! `Webhook-Signature = hex(HMAC-SHA256(webhook secret, body))`. A checkout is paid when its billing request is
//! `fulfilled` (the payment is created and, for Instant Bank Pay, initiated); a payment that later fails is reported
//! as `payments.failed` and taken back.
//!
//! The operator is the seller (UK only by default). Fees: 1 % + 20p, capped at £4 (verify at sign-up).

use std::collections::BTreeMap;

use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, Paid, ProviderEvent, Seller,
    hmac_sha256, same, send_json,
};

/// The provider id recorded in the ledger and used as the prefix of the method id.
pub const ID: &str = "gocardless";
/// The webhook header that carries the signature, lower-cased as the router passes header names.
pub const SIGNATURE_HEADER: &str = "webhook-signature";
/// The API version the requests ask for, sent in the `GoCardless-Version` header.
pub const VERSION: &str = "2015-07-06";

/// How to reach GoCardless and what the method costs.
#[derive(Debug, Clone)]
pub struct Config {
    /// `https://api-sandbox.gocardless.com` or `https://api.gocardless.com`.
    pub api_base: String,
    /// The access token, sent as a bearer token on every API call.
    pub access_token: String,
    /// The shared secret the webhook signature is made with.
    pub webhook_secret: String,
    /// The method's fixed fee in pence, used to work out the minimum months.
    pub fixed_pence: u32,
    /// The method's percentage fee in basis points.
    pub percent_bps: u32,
}

/// The adapter.
pub struct GoCardless {
    /// The settings.
    config: Config,
    /// The HTTP client for API calls.
    http: reqwest::Client,
}

impl GoCardless {
    /// An adapter from its settings and a client.
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    /// A request to the API with the access token and the version header.
    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(m, format!("{}{path}", self.config.api_base.trim_end_matches('/')))
            .bearer_auth(&self.config.access_token)
            .header("GoCardless-Version", VERSION)
    }
}

/// The signature GoCardless makes: the hex of the HMAC-SHA256 of the body with the webhook secret.
pub fn signature(secret: &str, body: &[u8]) -> String {
    hex::encode(hmac_sha256(secret.as_bytes(), body))
}

#[async_trait::async_trait]
impl BillingProvider for GoCardless {
    /// The provider id.
    fn id(&self) -> &'static str {
        ID
    }

    /// One method, paying from a bank account, sold by the operator.
    fn methods(&self) -> Vec<Method> {
        vec![Method {
            id: format!("{ID}:bank"),
            provider: ID.into(),
            label: "Pay from your bank account".into(),
            seller: Seller::Operator,
            fees: Fees { fixed_pence: self.config.fixed_pence, percent_bps: self.config.percent_bps },
            recurring: false,
        }]
    }

    /// Create a billing request with a one-off payment request in GBP, then a hosted flow; the buyer is sent to the flow's authorisation address to approve in their bank. The checkout id is the idempotency key, so a retry does not create a second request.
    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        // Only this provider's one method is accepted.
        if req.method != format!("{ID}:bank") {
            return Err(BillingError::NotOffered);
        }
        // The billing request, with the checkout and billing reference as metadata for the notification.
        let br = send_json(
            self.req(reqwest::Method::POST, "/billing_requests")
                .header("Idempotency-Key", req.checkout_id.to_string())
                .json(&json!({ "billing_requests": {
                    "payment_request": { "amount": req.amount_pence, "currency": "GBP", "description": req.description },
                    "metadata": { "checkout": req.checkout_id.to_string(), "ref": req.billing_ref },
                }})),
        )
        .await?;
        let id = br["billing_requests"]["id"]
            .as_str()
            .ok_or_else(|| BillingError::Malformed("no billing request id".into()))?;
        // The hosted flow the buyer completes, coming back to the same address on success or on exit.
        let flow = send_json(self.req(reqwest::Method::POST, "/billing_request_flows").json(
            &json!({ "billing_request_flows": {
                "redirect_uri": req.return_url, "exit_uri": req.return_url, "links": { "billing_request": id },
            }}),
        ))
        .await?;
        let url = flow["billing_request_flows"]["authorisation_url"]
            .as_str()
            .ok_or_else(|| BillingError::Malformed("no authorisation url".into()))?;
        Ok(CheckoutStart { provider_ref: id.into(), client: json!({ "kind": "redirect", "provider": ID, "url": url }) })
    }

    /// Verify the signature, then read the batch of events: a fulfilled billing request is paid (its amount is read from GoCardless), a cancelled one is expired, and a failed or charged-back payment gives back the whole purchase.
    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        _now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        // No signature means not authentic.
        let got = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        // Constant-time comparison with the signature this side computes.
        if !same(got.trim().as_bytes(), signature(&self.config.webhook_secret, body).as_bytes()) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        let mut out = Vec::new();
        // A notification carries a batch of events; each is read on its own.
        for e in v["events"].as_array().into_iter().flatten() {
            let id = e["id"].as_str().unwrap_or("");
            let br = e["links"]["billing_request"].as_str();
            // Only the three combinations this adapter acts on are read; everything else is ignored.
            match (e["resource_type"].as_str(), e["action"].as_str(), br) {
                (Some("billing_requests"), Some("fulfilled"), Some(br)) => out.push(ProviderEvent {
                    event_id: self.paid_event_id(br),
                    provider_ref: br.into(),
                    outcome: Outcome::Paid,
                    // The event names the billing request only; its amount is read from GoCardless.
                    paid: self.paid_facts(br).await?,
                    refunded: None,
                    evidence: json!({ "event": id, "payment": e["links"]["payment_request_payment"], "cause": e["details"]["cause"] }),
                }),
                (Some("billing_requests"), Some("cancelled"), Some(br)) => out.push(ProviderEvent {
                    event_id: format!("gocardless:{id}"),
                    provider_ref: br.into(),
                    outcome: Outcome::Expired,
                    paid: None,
                    refunded: None,
                    evidence: json!({ "event": id }),
                }),
                (Some("payments"), Some("failed" | "charged_back"), Some(br)) => out.push(ProviderEvent {
                    event_id: format!("gocardless:{id}"),
                    provider_ref: br.into(),
                    outcome: Outcome::Refunded,
                    paid: None,
                    // A failed or charged-back payment gives back the whole purchase.
                    refunded: None,
                    evidence: json!({ "event": id, "payment": e["links"]["payment"], "cause": e["details"]["cause"] }),
                }),
                _ => {}
            }
        }
        Ok(out)
    }

    /// Ask GoCardless how a billing request stands.
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        // A billing request id starts with `BRQ` and is alphanumeric; anything else is not put in a request path.
        if !provider_ref.starts_with("BRQ") || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(BillingError::Malformed("not a billing request id".into()));
        }
        let v = send_json(self.req(reqwest::Method::GET, &format!("/billing_requests/{provider_ref}"))).await?;
        Ok(match v["billing_requests"]["status"].as_str() {
            Some("fulfilled") => Outcome::Paid,
            Some("cancelled") => Outcome::Expired,
            _ => Outcome::Open,
        })
    }

    /// The amount and currency GoCardless says the billing request is for, so the app can check the payment covers the checkout.
    async fn paid_facts(&self, provider_ref: &str) -> Result<Option<Paid>, BillingError> {
        if !provider_ref.starts_with("BRQ") || !provider_ref.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(BillingError::Malformed("not a billing request id".into()));
        }
        let v = send_json(self.req(reqwest::Method::GET, &format!("/billing_requests/{provider_ref}"))).await?;
        // The payment request holds the amount and currency.
        let pr = &v["billing_requests"]["payment_request"];
        Ok(match (pr["amount"].as_u64(), pr["currency"].as_str()) {
            (Some(minor), Some(currency)) => Some(Paid::Amount { minor, currency: currency.to_string() }),
            _ => None,
        })
    }
}
