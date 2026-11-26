//! The Chain Payments adapter (ADR-0011): Link in Bio is a merchant of the self-hosted Chain Payments service. A
//! checkout is a Chain Payments session (amount in GBP, `units` = months, `subscriptionRef` = the account's billing
//! reference so the on-chain ledger extends the same period); the buyer pays in the kit (`ChainCheckout`) against
//! the service's public origin; the service tells us with an ed25519-signed webhook
//! (`Chain-Payments-Signature: t=<unix>,ed25519=<base64 of "<t>.<body>">`).
//!
//! The operator is the seller of these payments, so the router offers them only where the operator may sell.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::OnceCell;

use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller,
};

/// The provider id recorded in the ledger and used as the prefix of the method ids.
pub const ID: &str = "chain-payments";
/// The webhook header that carries the signature, lower-cased as the router passes header names.
pub const SIGNATURE_HEADER: &str = "chain-payments-signature";
/// Notifications older (or newer) than this are refused.
pub const MAX_AGE_SECS: u64 = 300;
/// The period one unit buys, the same average month as the on-chain ledger and the store.
pub const MONTH_MS: u64 = 2_629_800_000;

/// How to reach Chain Payments and which of its methods to offer.
#[derive(Debug, Clone)]
pub struct Config {
    /// The merchant API (in-cluster), e.g. `http://chain-payments-api.chain-payments.svc.cluster.local:8081`.
    pub merchant_api: String,
    /// The public session API as this process reaches it (for `/v1/webhook-key`), e.g. the Service's port 80.
    pub public_api: String,
    /// The origin the buyer's browser calls (the kit's `baseUrl`), e.g. `https://chain-payments.meddleware.dev`.
    pub checkout_origin: String,
    /// The merchant API key, sent as a bearer token to the merchant API only.
    pub api_key: String,
    /// The Chain Payments method ids to offer and their labels, e.g. `("sui-testnet:SUI", "SUI")`.
    pub methods: Vec<(String, String)>,
    /// The webhook public key (64 hex). When unset it is fetched once from `/v1/webhook-key`.
    pub webhook_key: Option<String>,
}

/// The adapter.
pub struct ChainPayments {
    /// The settings.
    config: Config,
    /// The client for the merchant and public APIs.
    http: reqwest::Client,
    /// The webhook's public key: set at start from the configuration, or fetched once on first use.
    key: OnceCell<Vec<u8>>,
}

/// Wrap any error as a provider-unavailable error (its text, never a request body).
fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

impl ChainPayments {
    /// Build the adapter. A configured webhook key must be 32 bytes in hex, which is checked here so a typo stops the start-up.
    pub fn new(config: Config, http: reqwest::Client) -> Result<Self, BillingError> {
        let key = OnceCell::new();
        if let Some(k) = &config.webhook_key {
            let bytes = hex::decode(k).ok().filter(|b| b.len() == 32).ok_or_else(|| {
                BillingError::Malformed("the Chain Payments webhook key must be 64 hex characters".into())
            })?;
            key.set(bytes).map_err(|_| BillingError::Malformed("key".into()))?;
        }
        Ok(Self { config, http, key })
    }

    /// An HTTP client for in-cluster calls: no proxy, no redirects, short timeouts.
    pub fn http_client() -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default()
    }

    /// The webhook public key: the configured one, or the one the service publishes, fetched once and kept.
    async fn webhook_key(&self) -> Result<&Vec<u8>, BillingError> {
        self.key
            .get_or_try_init(|| async {
                let url = format!("{}/v1/webhook-key", self.config.public_api.trim_end_matches('/'));
                let resp = self.http.get(&url).send().await.map_err(crate::transport)?;
                let v: Value = serde_json::from_slice(&crate::read_limited(resp, crate::MAX_ANSWER_BYTES).await?)
                    .map_err(unavailable)?;
                v["publicKey"]
                    .as_str()
                    .and_then(|k| hex::decode(k).ok())
                    .filter(|b| b.len() == 32)
                    .ok_or_else(|| BillingError::Malformed("no publicKey in /v1/webhook-key".into()))
            })
            .await
    }

    /// A merchant API address for a path.
    fn merchant(&self, path: &str) -> String {
        format!("{}{path}", self.config.merchant_api.trim_end_matches('/'))
    }
}

/// What the Chain Payments package keeps of each payment for the platform treasury, in basis points (0.2 %).
pub const PLATFORM_FEE_BPS: u32 = 20;

/// The ledger's event id for a paid session.
pub fn paid_event_id(session: &str) -> String {
    format!("paid:{session}")
}

/// Checks a `Chain-Payments-Signature` header against a body.
pub fn signature_valid(public: &[u8], header: &str, body: &[u8], now_unix: u64) -> bool {
    // The timestamp and the signature, both required.
    let mut t = None;
    let mut sig = None;
    for part in header.split(',') {
        match part.trim().split_once('=') {
            Some(("t", v)) => t = v.parse::<u64>().ok(),
            Some(("ed25519", v)) => sig = STANDARD.decode(v).ok(),
            _ => {}
        }
    }
    let (Some(t), Some(sig)) = (t, sig) else { return false };
    // A signature too old or too far in the future is refused, which stops a recorded webhook being replayed later.
    if now_unix.abs_diff(t) > MAX_AGE_SECS {
        return false;
    }
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    // Ed25519 over `<t>.<body>`.
    UnparsedPublicKey::new(&ED25519, public).verify(&msg, &sig).is_ok()
}

#[async_trait::async_trait]
impl BillingProvider for ChainPayments {
    /// The provider id.
    fn id(&self) -> &'static str {
        ID
    }

    /// One method for each configured coin, sold by the operator, with the platform fee as its only fee.
    fn methods(&self) -> Vec<Method> {
        self.config
            .methods
            .iter()
            .map(|(id, label)| Method {
                id: format!("{ID}:{id}"),
                provider: ID.into(),
                label: label.clone(),
                seller: Seller::Operator,
                // The payer pays the network fee; the package sends 0.2 % of the coin amount to the platform treasury
                // (the webhook's `platformFee`), so the recipient receives 99.8 %. No fixed fee: `min_months` stays 1.
                fees: Fees { fixed_pence: 0, percent_bps: PLATFORM_FEE_BPS },
                recurring: false,
            })
            .collect()
    }

    /// Start a Chain Payments session: the amount in pence, the months as units and the account's billing reference as the subscription reference; the service returns the session the buyer pays in the browser.
    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        // The method must be this provider's and one the configuration offers.
        let method = req.method.strip_prefix(&format!("{ID}:")).ok_or(BillingError::NotOffered)?;
        if !self.config.methods.iter().any(|(m, _)| m == method) {
            return Err(BillingError::NotOffered);
        }
        let body = json!({
            "amountPence": req.amount_pence,
            "description": req.description,
            "units": req.months,
            "subscriptionRef": req.billing_ref,
            "periodMs": MONTH_MS,
            "methods": [method],
            "metadata": { "checkout": req.checkout_id },
        });
        let r = self
            .http
            // The merchant API creates the session; it is reached in-cluster.
            .post(self.merchant("/v1/merchant/sessions"))
            .bearer_auth(&self.config.api_key)
            .json(&body)
            .send()
            .await
            .map_err(crate::transport)?;
        let status = r.status();
        let v: Value =
            serde_json::from_slice(&crate::read_limited(r, crate::MAX_ANSWER_BYTES).await?).map_err(unavailable)?;
        // A refusal carries the service's own message (an error string), never the request.
        if !status.is_success() {
            return Err(BillingError::Refused(v["error"].as_str().unwrap_or("refused").to_string()));
        }
        let id = v["id"].as_str().ok_or_else(|| BillingError::Malformed("no session id".into()))?.to_string();
        Ok(CheckoutStart {
            client: json!({ "kind": "chain-payments", "sessionId": id, "baseUrl": self.config.checkout_origin }),
            provider_ref: id,
        })
    }

    /// Verify and read a webhook: a paid session, or a payment that arrived for a session already closed. Any other event is acknowledged and ignored.
    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        // A request without the signature is not authentic.
        let header = headers.get(SIGNATURE_HEADER).ok_or(BillingError::Unauthentic)?;
        // The key is fetched only if it was not configured.
        let key = self.webhook_key().await?;
        if !signature_valid(key, header, body, now.unix_timestamp().max(0) as u64) {
            return Err(BillingError::Unauthentic);
        }
        let v: Value = serde_json::from_slice(body).map_err(|e| BillingError::Malformed(e.to_string()))?;
        let webhook_id = v["id"].as_str().ok_or_else(|| BillingError::Malformed("no event id".into()))?.to_string();
        let data = &v["data"];
        let session = data["sessionId"].as_str().ok_or_else(|| BillingError::Malformed("no sessionId".into()))?;
        let outcome = match v["event"].as_str() {
            Some("session.paid") => Outcome::Paid,
            Some("payment.unapplied") => Outcome::Unapplied,
            // Events this adapter does not act on are acknowledged and ignored.
            _ => return Ok(Vec::new()),
        };
        // What the service says about the payment, kept as tax and accounting evidence.
        let evidence = json!({
            "webhook": webhook_id,
            "method": data["method"], "coinType": data["coinType"], "amount": data["amount"], "price": data["price"],
            "digest": data["digest"], "payer": data["payer"], "paidUntilMs": data["paidUntilMs"],
            "amountPence": data["amountPence"], "units": data["units"], "sessionStatus": data["sessionStatus"],
            "platformFee": data["platformFee"],
        });
        // A session is paid at most once, so the session is the idempotency key (the worker's reconciliation of a
        // checkout whose webhook never came uses the same key: the period is never extended twice).
        // An unapplied payment is its own event (one session may receive several): keyed by the webhook's id, which
        // Chain Payments keeps across delivery attempts.
        let event_id =
            if outcome == Outcome::Unapplied { format!("unapplied:{webhook_id}") } else { paid_event_id(session) };
        Ok(vec![ProviderEvent {
            event_id,
            provider_ref: session.to_string(),
            outcome,
            paid: None,
            refunded: None,
            evidence,
        }])
    }

    /// Ask the service how a session stands: a session the service no longer knows counts as expired.
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        // A session id is 32 hex characters; checking it here keeps anything else out of the request path.
        if !provider_ref.bytes().all(|b| b.is_ascii_hexdigit()) || provider_ref.len() != 32 {
            return Err(BillingError::Malformed("not a session id".into()));
        }
        let r = self
            .http
            .get(self.merchant(&format!("/v1/merchant/sessions/{provider_ref}")))
            .bearer_auth(&self.config.api_key)
            .send()
            .await
            .map_err(crate::transport)?;
        // A session the service has forgotten can no longer be paid.
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Outcome::Expired);
        }
        let v: Value =
            serde_json::from_slice(&crate::read_limited(r, crate::MAX_ANSWER_BYTES).await?).map_err(unavailable)?;
        Ok(match v["status"].as_str() {
            Some("paid") => Outcome::Paid,
            // A cancelled session is the same as an expired one for the account.
            Some("expired") | Some("cancelled") => Outcome::Expired,
            _ => Outcome::Open,
        })
    }
}
