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
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller,
    hmac_sha256, same, send_json,
};

pub const ID: &str = "gocardless";
pub const SIGNATURE_HEADER: &str = "webhook-signature";
pub const VERSION: &str = "2015-07-06";

#[derive(Debug, Clone)]
pub struct Config {
    /// `https://api-sandbox.gocardless.com` or `https://api.gocardless.com`.
    pub api_base: String,
    pub access_token: String,
    pub webhook_secret: String,
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

pub struct GoCardless {
    config: Config,
    http: reqwest::Client,
}

impl GoCardless {
    pub fn new(config: Config, http: reqwest::Client) -> Self {
        Self { config, http }
    }

    fn req(&self, m: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.http
            .request(m, format!("{}{path}", self.config.api_base.trim_end_matches('/')))
            .bearer_auth(&self.config.access_token)
            .header("GoCardless-Version", VERSION)
    }
}

pub fn signature(secret: &str, body: &[u8]) -> String {
    hex::encode(hmac_sha256(secret.as_bytes(), body))
}

#[async_trait::async_trait]
impl BillingProvider for GoCardless {
    fn id(&self) -> &'static str {
        ID
    }

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

    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        if req.method != format!("{ID}:bank") {
            return Err(BillingError::NotOffered);
        }
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

    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        _now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        let got = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        if !same(got.trim().as_bytes(), signature(&self.config.webhook_secret, body).as_bytes()) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        let mut out = Vec::new();
        for e in v["events"].as_array().into_iter().flatten() {
            let id = e["id"].as_str().unwrap_or("");
            let br = e["links"]["billing_request"].as_str();
            match (e["resource_type"].as_str(), e["action"].as_str(), br) {
                (Some("billing_requests"), Some("fulfilled"), Some(br)) => out.push(ProviderEvent {
                    event_id: self.paid_event_id(br),
                    provider_ref: br.into(),
                    outcome: Outcome::Paid,
                    months: None,
                    evidence: json!({ "event": id, "payment": e["links"]["payment_request_payment"], "cause": e["details"]["cause"] }),
                }),
                (Some("billing_requests"), Some("cancelled"), Some(br)) => out.push(ProviderEvent {
                    event_id: format!("gocardless:{id}"),
                    provider_ref: br.into(),
                    outcome: Outcome::Expired,
                    months: None,
                    evidence: json!({ "event": id }),
                }),
                (Some("payments"), Some("failed" | "charged_back"), Some(br)) => out.push(ProviderEvent {
                    event_id: format!("gocardless:{id}"),
                    provider_ref: br.into(),
                    outcome: Outcome::Refunded,
                    months: None,
                    evidence: json!({ "event": id, "payment": e["links"]["payment"], "cause": e["details"]["cause"] }),
                }),
                _ => {}
            }
        }
        Ok(out)
    }

    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
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
}
