//! `link-in-bio-billing`: how a paid period is bought, behind one port.
//!
//! - [`BillingProvider`]: what every payment provider adapter implements (start a checkout, read its signed
//!   notifications, ask how a checkout ended). Each adapter passes the same conformance checks (`tests/`).
//! - [`Router`]: which methods a buyer is offered, from the switches, the buyer's country evidence and each method's
//!   fees: methods where the operator is the seller only when the declared country and the request's country agree
//!   and are on that method's list (UK only by default); a merchant of record anywhere.
//! - [`min_months`]: the fewest months a purchase with a method may buy, so its fixed fee stays at most 3 % of one
//!   month's price (with a 25 % buffer for exchange rates and fee changes).
//! - The adapters: [`manual`] (operator grants), [`chain_payments`] (Chain Payments, SUI and native USDC), [`square`]
//!   (UK cards), [`gocardless`] (UK bank payments, Open Banking), [`paddle`] (merchant of record for other countries),
//!   [`bank_transfer`] (SEPA with an EPC QR code, or Faster Payments, matched by an ISO 11649 reference from the
//!   bank's ISO 20022 statements) and [`open_payments`] (Interledger Open Payments: GNAP grants and RFC 9421 signed
//!   requests, the buyer approving in their own wallet). The fiat ones send the buyer to the provider's own hosted
//!   page (a redirect, never a provider script in the app).
//! - [`bank_feed`]: the receiving banks' APIs (Wise, bunq, Revolut Business) as sources of the same credits a camt
//!   statement gives.
//! - [`keys`] and [`httpsig`]: the key files, signatures and digests the signing adapters share.

pub mod bank_feed;
pub mod bank_transfer;
pub mod chain_payments;
pub mod gocardless;
pub mod httpsig;
pub mod keys;
pub mod manual;
pub mod open_payments;
pub mod paddle;
pub mod square;

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Months one purchase may buy at most, and how far ahead an account may be paid.
pub const MAX_MONTHS_PER_PURCHASE: u32 = 12;
pub const MAX_MONTHS_AHEAD: u32 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Seller {
    /// The operator sells (and owes the tax where the buyer is).
    Operator,
    /// The provider is the merchant of record (it sells to the buyer and handles their tax).
    MerchantOfRecord,
}

/// A method's fees in pence (fixed) and basis points (percentage), per purchase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Fees {
    pub fixed_pence: u32,
    pub percent_bps: u32,
}

/// `ceil(fixed × 1.25 / (0.03 × price))`, at least 1: the fixed fee of one purchase spread over its months is at most
/// 3 % of one month's price. Paddle's 50¢ (≈ 40p) at £3 gives 6; Square's 25p gives 4; GoCardless's 20p gives 3; a
/// method without a fixed fee gives 1.
pub fn min_months(fixed_pence: u32, price_pence: u32) -> u32 {
    if price_pence == 0 {
        return MAX_MONTHS_PER_PURCHASE;
    }
    let num = u64::from(fixed_pence) * 125;
    let den = 3 * u64::from(price_pence);
    (num.div_ceil(den) as u32).max(1)
}

/// One way to pay that an adapter offers (a provider may offer several: one per coin, card and bank).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Method {
    /// `<provider>:<method>`, e.g. `chain-payments:sui-testnet:SUI`.
    pub id: String,
    pub provider: String,
    pub label: String,
    pub seller: Seller,
    pub fees: Fees,
    /// Can renew without the buyer (a mandate or a saved card). Never on by default.
    pub recurring: bool,
}

#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    pub checkout_id: Uuid,
    pub method: String,
    /// The opaque reference a provider may record (never the handle).
    pub billing_ref: String,
    pub months: u32,
    pub amount_pence: u64,
    pub description: String,
    /// Where the provider sends the buyer back to (the app's billing view for this checkout).
    pub return_url: String,
}

/// What a started checkout gives back: the provider's reference and what the app's checkout page needs (a session id
/// and the provider's public origin, a redirect URL, …).
#[derive(Debug, Clone, PartialEq)]
pub struct CheckoutStart {
    pub provider_ref: String,
    pub client: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Paid,
    /// A real payment for a checkout that was already paid or closed (Chain Payments' `payment.unapplied`). It is
    /// credited as the months its quote was for; a refund is the buyer's request and the operator's manual act.
    Unapplied,
    Refunded,
    Failed,
    Expired,
    Open,
}

/// What a provider says was paid for a checkout, compared with the checkout before a payment is applied
/// ([`paid_covers`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paid {
    /// An amount in minor units of a currency (Square, GoCardless).
    Amount { minor: u64, currency: String },
    /// A quantity of one catalog price (Paddle: the currency is the buyer's, so the quantity and price are what count).
    Quantity { quantity: u32, price_id: String },
}

/// How much of a purchase a refund gave back, in the provider's minor units of one currency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Refunded {
    /// This refund's amount.
    pub minor: u64,
    /// What the purchase was paid, in the same currency; `None` means the checkout's own amount in pence.
    pub of_minor: Option<u64>,
}

/// One verified notification from a provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderEvent {
    /// The provider's id of this event (each is applied once).
    pub event_id: String,
    /// The checkout it is about (`CheckoutStart::provider_ref`).
    pub provider_ref: String,
    pub outcome: Outcome,
    /// For a payment: what the provider says was paid (required by the card and bank providers, see [`paid_covers`]).
    pub paid: Option<Paid>,
    /// For a refund: how much was refunded; `None` is the whole purchase (a failed or charged-back payment).
    pub refunded: Option<Refunded>,
    /// What the provider says about the payment (kept as tax and accounting evidence).
    pub evidence: Value,
}

/// Whether what a provider says was paid covers the checkout: for Square and GoCardless at least the checkout's amount in
/// GBP; for Paddle exactly the checkout's months of the configured price (`paddle_price_id`). Other providers verify the
/// amount themselves (Chain Payments on-chain, Open Payments from the operator's own incoming payment, bank transfer from
/// the credit), so their events need no `paid`. A provider that needs one and sends none is not covered.
pub fn paid_covers(
    provider: &str,
    paid: Option<&Paid>,
    months: u32,
    amount_pence: u64,
    paddle_price_id: Option<&str>,
) -> bool {
    match provider {
        square::ID | gocardless::ID => {
            matches!(paid, Some(Paid::Amount { minor, currency }) if currency == "GBP" && *minor >= amount_pence)
        }
        paddle::ID => matches!(
            paid,
            Some(Paid::Quantity { quantity, price_id }) if *quantity == months && Some(price_id.as_str()) == paddle_price_id
        ),
        _ => true,
    }
}

/// The months a purchase of `months` months, paid `paid_minor`, has given back once refunds totalling `refunded_minor`
/// (same currency) are made: pro rata, rounded down, and all of them once the whole amount is refunded. Applying each
/// refund as the difference between this before and after it means the months taken back never exceed the purchase's,
/// and partial refunds that add up to the whole take all of them.
pub fn months_refunded(months: u32, paid_minor: u64, refunded_minor: u64) -> u32 {
    if paid_minor == 0 || refunded_minor >= paid_minor {
        return months;
    }
    (u128::from(months) * u128::from(refunded_minor) / u128::from(paid_minor)) as u32
}

#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("this payment method is not available")]
    NotOffered,
    #[error("the notification is not authentic")]
    Unauthentic,
    #[error("the notification could not be read: {0}")]
    Malformed(String),
    #[error("the payment provider did not answer: {0}")]
    Unavailable(String),
    #[error("the payment provider refused: {0}")]
    Refused(String),
}

/// A payment provider adapter. Implementations hold their own credentials and talk to exactly their provider.
#[async_trait::async_trait]
pub trait BillingProvider: Send + Sync {
    fn id(&self) -> &'static str;
    fn methods(&self) -> Vec<Method>;
    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError>;
    /// Verifies a notification's signature and reads it. `headers` are lower-case names.
    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError>;
    /// Asks the provider how a checkout stands (the worker's reconciliation of checkouts no notification closed).
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError>;
    /// The ledger key of a checkout's payment. A `Paid` event from a notification must carry this same id, so a
    /// payment seen both by notification and by reconciliation extends the period once.
    fn paid_event_id(&self, provider_ref: &str) -> String {
        format!("paid:{provider_ref}")
    }
    /// What the provider says was paid for a checkout it reports `Paid` (the reconciliation's [`ProviderEvent::paid`]).
    async fn paid_facts(&self, _provider_ref: &str) -> Result<Option<Paid>, BillingError> {
        Ok(None)
    }
}

/// A shared adapter is an adapter (the app keeps a typed handle to one whose flow has steps beyond the port).
#[async_trait::async_trait]
impl<T: BillingProvider + ?Sized> BillingProvider for std::sync::Arc<T> {
    fn id(&self) -> &'static str {
        (**self).id()
    }
    fn methods(&self) -> Vec<Method> {
        (**self).methods()
    }
    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        (**self).create_checkout(req).await
    }
    async fn verify_notification(
        &self,
        headers: &BTreeMap<String, String>,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        (**self).verify_notification(headers, body, now).await
    }
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        (**self).checkout_outcome(provider_ref).await
    }
    fn paid_event_id(&self, provider_ref: &str) -> String {
        (**self).paid_event_id(provider_ref)
    }
    async fn paid_facts(&self, provider_ref: &str) -> Result<Option<Paid>, BillingError> {
        (**self).paid_facts(provider_ref).await
    }
}

/// The buyer's country evidence for one purchase.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evidence {
    /// What the account holder declared (ISO 3166-1 alpha-2).
    pub declared: Option<String>,
    /// The request's country (Cloudflare `CF-IPCountry`; `XX`/`T1` mean unknown or Tor).
    pub request: Option<String>,
}

impl Evidence {
    /// The country both pieces of evidence agree on, if they do.
    pub fn agreed(&self) -> Option<&str> {
        match (&self.declared, &self.request) {
            (Some(d), Some(r)) if d == r && d.len() == 2 && d.bytes().all(|b| b.is_ascii_uppercase()) => Some(d),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offer {
    #[serde(flatten)]
    pub method: Method,
    pub min_months: u32,
    pub max_months: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offers {
    pub price_pence: u32,
    pub offers: Vec<Offer>,
    /// Why nothing (or less) is offered, in plain words, when that is the case.
    pub notes: Vec<String>,
}

/// Which methods are switched on and where they may be offered.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub price_pence: u32,
    /// Providers switched on (`BILLING_PROVIDERS`); `manual` is always on and never offered at checkout.
    pub enabled: BTreeSet<String>,
    /// Countries each operator-as-seller provider may sell to (`<PROVIDER>_COUNTRIES`); default `GB` only.
    pub countries: BTreeMap<String, BTreeSet<String>>,
}

pub struct Router {
    config: RouterConfig,
    providers: Vec<Box<dyn BillingProvider>>,
}

impl Router {
    pub fn new(config: RouterConfig, providers: Vec<Box<dyn BillingProvider>>) -> Self {
        Self { config, providers }
    }

    pub fn price_pence(&self) -> u32 {
        self.config.price_pence
    }

    pub fn provider(&self, id: &str) -> Option<&dyn BillingProvider> {
        self.providers.iter().find(|p| p.id() == id && self.config.enabled.contains(id)).map(|p| p.as_ref())
    }

    fn countries_for(&self, provider: &str) -> BTreeSet<String> {
        self.config.countries.get(provider).cloned().unwrap_or_else(|| BTreeSet::from(["GB".to_string()]))
    }

    /// What a buyer may use now: `months_ahead` is how many whole months the account is already paid beyond now.
    pub fn offers(&self, evidence: &Evidence, months_ahead: u32) -> Offers {
        let mut notes = Vec::new();
        let room = MAX_MONTHS_AHEAD.saturating_sub(months_ahead).min(MAX_MONTHS_PER_PURCHASE);
        if room == 0 {
            notes.push(format!("This account is already paid {MAX_MONTHS_AHEAD} months ahead."));
        }
        let agreed = evidence.agreed();
        if agreed.is_none() {
            notes.push(
                "Your declared country and the country of this connection differ, so only payment methods that \
                 handle tax in your country are offered."
                    .into(),
            );
        }
        let mut offers = Vec::new();
        for p in &self.providers {
            if !self.config.enabled.contains(p.id()) {
                continue;
            }
            for m in p.methods() {
                let allowed = match m.seller {
                    Seller::MerchantOfRecord => true,
                    Seller::Operator => agreed.is_some_and(|c| self.countries_for(p.id()).contains(c)),
                };
                if !allowed {
                    continue;
                }
                let min = min_months(m.fees.fixed_pence, self.config.price_pence);
                if room >= min {
                    offers.push(Offer { method: m, min_months: min, max_months: room });
                }
            }
        }
        if offers.is_empty() && room > 0 {
            notes.push("No payment method is available for your country yet.".into());
        }
        Offers { price_pence: self.config.price_pence, offers, notes }
    }

    /// The offer for one method, if this buyer may use it for `months`.
    pub fn check(&self, evidence: &Evidence, months_ahead: u32, method: &str, months: u32) -> Option<Offer> {
        self.offers(evidence, months_ahead)
            .offers
            .into_iter()
            .find(|o| o.method.id == method && (o.min_months..=o.max_months).contains(&months))
    }
}

/// An HTTP client for provider APIs: no redirects followed, short timeouts.
pub fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default()
}

/// HMAC-SHA256 of `msg` with `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, msg).as_ref().to_vec()
}

/// Constant-time comparison of a received signature with the expected one.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

/// The longest answer read from a provider, bank or wallet API (their JSON documents are a few kilobytes; a buyer's
/// Open Payments wallet is a server the buyer chooses, so this is what stops one from streaming without end).
pub const MAX_ANSWER_BYTES: usize = 1024 * 1024;
/// The longest bank statement read from a bank feed (a camt.053 of a busy month).
pub const MAX_STATEMENT_BYTES: usize = 16 * 1024 * 1024;

/// Reads a response body of at most `max` bytes: refused on the declared length before reading, and while reading
/// (a chunked answer has none), so an upstream can never make this process buffer without bound.
pub async fn read_limited(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, BillingError> {
    let too_long = || BillingError::Malformed(format!("the answer is longer than {max} bytes"));
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(too_long());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(unavailable)? {
        if out.len() + chunk.len() > max {
            return Err(too_long());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// A JSON answer of at most `max` bytes, or `Null` when it is not JSON (an error page); too long is an error.
pub async fn read_json_or_null(resp: reqwest::Response, max: usize) -> Result<Value, BillingError> {
    Ok(serde_json::from_slice(&read_limited(resp, max).await?).unwrap_or(Value::Null))
}

/// Sends a request and reads a JSON answer; a non-success status is `Refused` with the provider's message.
pub(crate) async fn send_json(r: reqwest::RequestBuilder) -> Result<Value, BillingError> {
    let resp = r.send().await.map_err(unavailable)?;
    let status = resp.status();
    let v: Value = read_json_or_null(resp, MAX_ANSWER_BYTES).await?;
    if status.is_success() {
        Ok(v)
    } else if status.is_server_error() {
        Err(BillingError::Unavailable(format!("HTTP {}", status.as_u16())))
    } else {
        Err(BillingError::Refused(format!("HTTP {}: {}", status.as_u16(), crate::provider_message(&v))))
    }
}

/// The human part of a provider's error answer (each names it differently).
pub(crate) fn provider_message(v: &Value) -> String {
    for p in ["/errors/0/detail", "/errors/0/message", "/error/message", "/error/detail", "/message"] {
        if let Some(m) = v.pointer(p).and_then(Value::as_str) {
            return m.chars().take(200).collect();
        }
    }
    "refused".into()
}

/// Whole months strictly ahead of now that an account is already paid for.
pub fn months_ahead(paid_until: Option<OffsetDateTime>, now: OffsetDateTime) -> u32 {
    let Some(p) = paid_until else { return 0 };
    if p <= now {
        return 0;
    }
    let month_ms = 2_629_800_000i128;
    ((p - now).whole_milliseconds() / month_ms) as u32
}

/// An RFC 3339 time in UTC with milliseconds and `Z` (`2026-11-17T09:41:07.123Z`), as the banks' and Open Payments'
/// APIs take it.
pub fn rfc3339(t: OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .unwrap_or_default()
}

/// An RFC 3339 time (any offset) as UTC, or `None`.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|t| t.to_offset(time::UtcOffset::UTC))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-request HTTP server that answers with `head` then `body` (written by hand, so the test chooses the framing).
    async fn answer_once(head: &'static str, body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", l.local_addr().unwrap());
        tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = c.read(&mut buf).await;
            let _ = c.write_all(head.as_bytes()).await;
            let _ = c.write_all(&body).await;
        });
        url
    }

    fn chunked(parts: usize, size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..parts {
            out.extend_from_slice(format!("{size:x}\r\n").as_bytes());
            out.extend(std::iter::repeat_n(b'a', size));
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        out
    }

    #[tokio::test]
    async fn answers_are_read_up_to_a_limit() {
        let http = http_client();
        // Declared too long: refused before reading.
        let url = answer_once("HTTP/1.1 200 OK\r\ncontent-length: 5000\r\n\r\n", vec![b'a'; 5000]).await;
        let r = http.get(&url).send().await.unwrap();
        assert!(matches!(read_limited(r, 4096).await, Err(BillingError::Malformed(_))));
        // No declared length (chunked): refused while reading, once past the limit.
        let url = answer_once("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", chunked(8, 1000)).await;
        let r = http.get(&url).send().await.unwrap();
        assert!(matches!(read_limited(r, 4096).await, Err(BillingError::Malformed(_))));
        // Within the limit: read whole.
        let url = answer_once("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n", chunked(4, 1000)).await;
        let r = http.get(&url).send().await.unwrap();
        assert_eq!(read_limited(r, 4096).await.unwrap().len(), 4000);
        let url = answer_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n", b"{}".to_vec()).await;
        let r = http.get(&url).send().await.unwrap();
        assert_eq!(read_json_or_null(r, 4096).await.unwrap(), serde_json::json!({}));
    }

    #[test]
    fn rfc3339_with_milliseconds() {
        use time::macros::datetime;
        assert_eq!(rfc3339(datetime!(2026-11-17 09:41:07 UTC)), "2026-11-17T09:41:07.000Z");
        assert_eq!(rfc3339(datetime!(2026-11-17 09:41:07.123987 UTC)), "2026-11-17T09:41:07.123Z", "truncated");
        assert_eq!(rfc3339(datetime!(2026-11-17 10:41:07.5 +01:00)), "2026-11-17T09:41:07.500Z");
        let t = parse_rfc3339("2026-11-17T10:41:07.123456+01:00").unwrap();
        assert_eq!(t, datetime!(2026-11-17 09:41:07.123456 UTC));
        assert_eq!(t.offset(), time::UtcOffset::UTC);
        assert_eq!(parse_rfc3339("2026-11-17"), None);
    }

    #[test]
    fn refunds_give_back_months_pro_rata_rounded_down() {
        // A partial refund: a third of 12 months paid 3600 is 4; a little less is 3.
        assert_eq!(months_refunded(12, 3600, 1200), 4);
        assert_eq!(months_refunded(12, 3600, 1199), 3);
        // The whole amount (or more) gives back every month.
        assert_eq!(months_refunded(12, 3600, 3600), 12);
        assert_eq!(months_refunded(12, 3600, 5000), 12);
        // Two partials that add up to the whole: counted on the running total, so 3 + 9 = 12 (not 3 + 8).
        let first = months_refunded(12, 3600, 1000);
        let second = months_refunded(12, 3600, 1000 + 2600) - first;
        assert_eq!((first, second), (3, 9));
        assert_eq!(months_refunded(1, 300, 299), 0);
        assert_eq!(months_refunded(5, 0, 0), 5, "nothing was paid: a refund takes everything");
    }

    #[test]
    fn a_payment_counts_only_when_it_covers_the_checkout() {
        let gbp = |minor| Paid::Amount { minor, currency: "GBP".into() };
        assert!(paid_covers(square::ID, Some(&gbp(1200)), 4, 1200, None));
        assert!(paid_covers(gocardless::ID, Some(&gbp(1300)), 4, 1200, None), "more is fine");
        assert!(!paid_covers(square::ID, Some(&gbp(1199)), 4, 1200, None), "short");
        assert!(!paid_covers(square::ID, Some(&Paid::Amount { minor: 1200, currency: "EUR".into() }), 4, 1200, None));
        assert!(!paid_covers(square::ID, None, 4, 1200, None), "a card payment says what it paid");
        let q = |quantity, price_id: &str| Paid::Quantity { quantity, price_id: price_id.into() };
        assert!(paid_covers(paddle::ID, Some(&q(6, "pri_1")), 6, 1800, Some("pri_1")));
        assert!(!paid_covers(paddle::ID, Some(&q(1, "pri_1")), 6, 1800, Some("pri_1")), "fewer months");
        assert!(!paid_covers(paddle::ID, Some(&q(6, "pri_cheap")), 6, 1800, Some("pri_1")), "another price");
        assert!(!paid_covers(paddle::ID, Some(&gbp(1800)), 6, 1800, Some("pri_1")));
        for p in [chain_payments::ID, open_payments::ID, bank_transfer::ID, manual::ID] {
            assert!(paid_covers(p, None, 1, 300, None), "{p} verifies the amount itself");
        }
    }

    #[test]
    fn minimum_months_follow_the_three_percent_rule() {
        assert_eq!(min_months(40, 300), 6, "Paddle 50¢");
        assert_eq!(min_months(25, 300), 4, "Square 25p");
        assert_eq!(min_months(20, 300), 3, "GoCardless 20p");
        assert_eq!(min_months(0, 300), 1, "no fixed fee");
        for (fixed, price) in [(40u32, 300u32), (25, 300), (20, 300), (7, 300), (100, 500)] {
            let m = min_months(fixed, price);
            assert!(f64::from(fixed) * 1.25 / f64::from(m) <= 0.03 * f64::from(price) + 1e-9);
            assert!(m == 1 || f64::from(fixed) * 1.25 / f64::from(m - 1) > 0.03 * f64::from(price));
        }
    }

    struct Fake(&'static str, Seller, u32);

    #[async_trait::async_trait]
    impl BillingProvider for Fake {
        fn id(&self) -> &'static str {
            self.0
        }
        fn methods(&self) -> Vec<Method> {
            vec![Method {
                id: format!("{}:x", self.0),
                provider: self.0.into(),
                label: self.0.into(),
                seller: self.1,
                fees: Fees { fixed_pence: self.2, percent_bps: 100 },
                recurring: false,
            }]
        }
        async fn create_checkout(&self, _: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
            Err(BillingError::NotOffered)
        }
        async fn verify_notification(
            &self,
            _: &BTreeMap<String, String>,
            _: &[u8],
            _: OffsetDateTime,
        ) -> Result<Vec<ProviderEvent>, BillingError> {
            Err(BillingError::Unauthentic)
        }
        async fn checkout_outcome(&self, _: &str) -> Result<Outcome, BillingError> {
            Ok(Outcome::Open)
        }
    }

    fn router(enabled: &[&str]) -> Router {
        Router::new(
            RouterConfig {
                price_pence: 300,
                enabled: enabled.iter().map(|s| s.to_string()).collect(),
                countries: BTreeMap::new(),
            },
            vec![
                Box::new(Fake("crypto", Seller::Operator, 0)),
                Box::new(Fake("card", Seller::Operator, 25)),
                Box::new(Fake("mor", Seller::MerchantOfRecord, 40)),
            ],
        )
    }

    fn ev(d: &str, r: &str) -> Evidence {
        Evidence { declared: Some(d.into()), request: Some(r.into()) }
    }

    #[test]
    fn routing_by_country_and_switches() {
        let r = router(&["crypto", "card", "mor"]);
        let uk: Vec<_> =
            r.offers(&ev("GB", "GB"), 0).offers.into_iter().map(|o| (o.method.provider, o.min_months)).collect();
        assert_eq!(uk, vec![("crypto".into(), 1), ("card".into(), 4), ("mor".into(), 6)]);
        let de: Vec<_> = r.offers(&ev("DE", "DE"), 0).offers.into_iter().map(|o| o.method.provider).collect();
        assert_eq!(de, vec!["mor".to_string()], "operator-as-seller methods are UK only by default");
        let mixed = r.offers(&ev("GB", "FR"), 0);
        assert_eq!(mixed.offers.len(), 1, "disagreeing evidence: merchant of record only");
        assert!(!mixed.notes.is_empty());
        assert!(router(&["crypto"]).offers(&ev("DE", "DE"), 0).offers.is_empty());
        assert!(router(&[]).offers(&ev("GB", "GB"), 0).offers.is_empty(), "nothing on, nothing offered");
    }

    #[test]
    fn months_are_bounded() {
        let r = router(&["crypto", "mor"]);
        let o = r.offers(&ev("GB", "GB"), 20);
        assert_eq!(o.offers.iter().map(|o| o.max_months).collect::<Vec<_>>(), vec![4], "mor needs 6; only 4 fit");
        assert!(r.offers(&ev("GB", "GB"), 24).offers.is_empty());
        assert!(r.check(&ev("GB", "GB"), 0, "crypto:x", 12).is_some());
        assert!(r.check(&ev("GB", "GB"), 0, "crypto:x", 13).is_none());
        assert!(r.check(&ev("GB", "GB"), 0, "mor:x", 5).is_none(), "below the minimum");
        assert!(r.check(&ev("GB", "GB"), 0, "nope", 1).is_none());
    }

    #[test]
    fn whole_months_ahead() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(months_ahead(None, now), 0);
        assert_eq!(months_ahead(Some(now - time::Duration::days(1)), now), 0);
        assert_eq!(months_ahead(Some(now + time::Duration::days(95)), now), 3);
    }
}
