//! Open Payments (Interledger), on open standards end to end: GNAP grants (RFC 9635) at the authorization servers the
//! wallet addresses name, every request signed with HTTP Message Signatures (RFC 9421, ed25519, `Content-Digest` per
//! RFC 9530) under the client's key id, and the Open Payments resource APIs (incoming payments, quotes, outgoing
//! payments) as openpayments.dev documents them. The client is the operator's own wallet address; its public key is
//! the one its wallet provider publishes at `<wallet address>/jwks.json`.
//!
//! A checkout:
//!
//! 1. [`BillingProvider::create_checkout`] asks the operator's authorization server for an incoming-payment grant
//!    (non-interactive) and creates an incoming payment on the operator's wallet address for the amount. Its URL is
//!    the checkout's reference.
//! 2. The buyer gives their wallet address (a URL, or a `$` payment pointer).
//! 3. [`OpenPayments::start_payment`] gets a quote grant and a quote for that incoming payment on the buyer's servers,
//!    then asks the buyer's authorization server for an outgoing-payment grant limited to the quote's debit amount and
//!    to our incoming payment, with an interactive redirect whose `finish` URI returns to the app.
//! 4. [`OpenPayments::finish_payment`] checks the GNAP interaction hash, continues the grant and creates the outgoing
//!    payment. The checkout is paid only when the operator's incoming payment reports a received amount at least the
//!    expected one ([`BillingProvider::checkout_outcome`], which the app and the worker poll).
//!
//! There are no notifications. The operator is the seller; fees depend on the wallets (none fixed here).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::{Mutex, OnceCell};

use crate::httpsig::{self, Message, Param};
use crate::{
    BillingError, BillingProvider, CheckoutRequest, CheckoutStart, Fees, Method, Outcome, ProviderEvent, Seller, keys,
    provider_message, same,
};

/// The provider id recorded in the ledger.
pub const ID: &str = "open-payments";
/// The one method this provider offers, as the buyer chooses it.
pub const METHOD: &str = "open-payments:wallet";
/// How long the operator's incoming payment for a checkout stays open.
pub const INCOMING_PAYMENT_LIFETIME: time::Duration = time::Duration::days(2);

/// The operator's wallet and key, and what a month costs in its asset.
#[derive(Debug, Clone)]
pub struct Config {
    /// The operator's wallet address: the payee, and the client every grant request names.
    pub wallet_address: String,
    /// The key id the wallet provider lists for the client's key in `<wallet address>/jwks.json`.
    pub key_id: String,
    /// The client's ed25519 private key (PKCS #8 PEM, or base64 of it).
    pub private_key_pem: String,
    /// The operator's wallet's asset, e.g. `GBP` with scale 2.
    pub asset_code: String,
    /// The number of decimal places the asset has (2 for pounds and pence).
    pub asset_scale: u8,
    /// Minor units of the asset per month. Required unless the asset is GBP (then the price in pence is used).
    pub minor_per_month: Option<u64>,
}

/// What a wallet address document says (`GET <wallet address>` with `Accept: application/json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAddress {
    /// The wallet address' own URL.
    pub id: String,
    /// The authorization server that grants access to the wallet.
    pub auth_server: String,
    /// The server that holds the wallet's payments and quotes.
    pub resource_server: String,
    /// The asset's code, three capital letters.
    pub asset_code: String,
    /// The number of decimal places the asset has.
    pub asset_scale: u8,
}

/// An outgoing-payment grant waiting for the buyer's approval: what [`OpenPayments::finish_payment`] needs. The
/// continuation token is a credential; the app keeps this only until the grant is continued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPayment {
    /// The operator's incoming payment the buyer is paying.
    pub incoming_payment: String,
    /// The buyer's wallet address.
    pub buyer_wallet: String,
    /// The server the outgoing payment is created on.
    pub buyer_resource_server: String,
    /// The grant endpoint exactly as the request was sent to it (part of the interaction hash).
    pub grant_endpoint: String,
    /// The nonce this side chose for the interaction hash.
    pub client_nonce: String,
    /// The nonce the authorization server chose for the interaction hash.
    pub server_nonce: String,
    /// Where the buyer goes to approve (their wallet's page).
    pub redirect: String,
    /// Where the grant is continued once the buyer has approved.
    pub continue_uri: String,
    /// The token for continuing the grant; a credential.
    pub continue_token: String,
    /// The quote the outgoing payment is made from.
    pub quote_id: String,
    /// What leaves the buyer's wallet, as the quote states it.
    pub debit_amount: Value,
    /// What the operator's wallet receives, as the quote states it.
    pub receive_amount: Value,
}

/// The adapter. It acts as a client of the operator's own wallet and of the buyers' wallets.
pub struct OpenPayments {
    /// The settings.
    config: Config,
    /// The HTTP client (it refuses non-public addresses when it connects).
    http: reqwest::Client,
    /// The client's signing key.
    key: Ed25519KeyPair,
    /// The operator's wallet address is on loopback over plain HTTP: a test set-up, where buyers' wallets may be too.
    local: bool,
    /// The operator's wallet address document, read once.
    operator: OnceCell<WalletAddress>,
    /// The operator's incoming-payment token and when it expires, reused between checkouts.
    token: Mutex<Option<(String, Instant)>>,
}

/// A malformed-input error from a fixed message.
fn bad(m: impl Into<String>) -> BillingError {
    BillingError::Malformed(m.into())
}

/// Wrap any error as a provider-unavailable error (its text, never a request body).
fn unavailable(e: impl std::fmt::Display) -> BillingError {
    BillingError::Unavailable(e.to_string())
}

/// Formats minor units with the asset's scale (`300`, 2 → `3.00`).
pub fn format_amount(minor: u128, scale: u8) -> String {
    if scale == 0 {
        return minor.to_string();
    }
    let p = 10u128.pow(u32::from(scale));
    format!("{}.{:0width$}", minor / p, minor % p, width = usize::from(scale))
}

/// The numeric value of an Open Payments amount object, whose value is a string.
fn amount_value(v: &Value) -> Option<u128> {
    v["value"].as_str()?.parse().ok()
}

/// A wallet address from what a buyer typed: an `https://` URL, or a payment pointer (`$wallet.example/alice`).
pub fn wallet_address_url(input: &str) -> Result<String, BillingError> {
    let s = input.trim();
    if s.is_empty() || s.len() > 300 || s.chars().any(char::is_whitespace) {
        return Err(bad("a wallet address is a URL such as https://wallet.example/alice"));
    }
    if let Some(p) = s.strip_prefix('$') {
        return Ok(if p.contains('/') { format!("https://{p}") } else { format!("https://{p}/.well-known/pay") });
    }
    Ok(s.to_string())
}

/// Whether an address is one an outside service may be reached at (not loopback, private, link-local, shared,
/// documentation, multicast or unspecified).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_broadcast()
                || a.is_documentation()
                || a.is_unspecified()
                || a.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240)
        }
        // IPv6 has its own special ranges, and some forms carry an IPv4 address.
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_public(IpAddr::V4(v4));
            }
            let s = a.segments();
            // An address that embeds an IPv4 one (NAT64, 6to4) reaches that IPv4 address: judge it by that.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = s[6].to_be_bytes();
                let [c, d] = s[7].to_be_bytes();
                return is_public(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)));
            }
            if s[0] == 0x2002 {
                let [a, b] = s[1].to_be_bytes();
                let [c, d] = s[2].to_be_bytes();
                return is_public(IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d)));
            }
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

/// The resolver of the Open Payments client: a name that resolves to any address that is not public is refused when
/// the connection is made, not only when [`OpenPayments::checked`] looked it up first. A buyer's wallet is a server the
/// buyer chooses, and a name can answer differently the second time (DNS rebinding); this closes that gap. Addresses
/// written as IP literals never reach a resolver, and `checked` refuses them (except 127.0.0.1 on a test set-up).
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicOnly;

impl reqwest::dns::Resolve for PublicOnly {
    /// Resolve a name and refuse the connection unless every address is public.
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // The name is resolved here, and every address it gives must be public.
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addrs.is_empty() || !addrs.iter().all(|a| is_public(a.ip())) {
                let refused = std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{host} resolves to an address that is not public"),
                );
                return Err(Box::new(refused) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

impl OpenPayments {
    /// The HTTP client for Open Payments: the shared provider client's rules (no redirects, short timeouts) and the
    /// [`PublicOnly`] resolver.
    pub fn http_client() -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::builder()
            .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            // The resolver refuses non-public addresses at connection time, so a name that changes its answer between the check and the connection (DNS rebinding) cannot reach one.
            .dns_resolver(PublicOnly)
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default()
    }

    /// An adapter from its settings, which are checked now so a mistake stops the start-up: the key, the key id, the asset, the price per month and that the wallet address is https (or local plain http for a test set-up).
    pub fn new(config: Config, http: reqwest::Client) -> Result<Self, BillingError> {
        // The key is read first, so a bad key stops the start-up.
        let key = keys::ed25519_from_pem(&config.private_key_pem)?;
        // The key id is required: it is how the wallet provider finds the public key.
        if config.key_id.trim().is_empty() || config.key_id.len() > 200 {
            return Err(bad("the Open Payments key id is not set"));
        }
        // The asset code is three capital letters.
        if config.asset_code.len() != 3 || !config.asset_code.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(bad("the asset code is three capital letters, e.g. GBP"));
        }
        if config.asset_scale > 18 {
            return Err(bad("the asset scale is at most 18"));
        }
        // The price per month: required for any asset but pounds, where it can be worked out from the pence price.
        match config.minor_per_month {
            Some(0) => return Err(bad("the price of a month in the wallet's asset must be above 0")),
            None if config.asset_code != "GBP" || config.asset_scale < 2 => {
                return Err(bad("an asset other than GBP (scale 2 or more) needs its price per month"));
            }
            _ => {}
        }
        // The operator's address must be https; plain http only to the loopback address of a test set-up.
        let u = url::Url::parse(&config.wallet_address).map_err(|_| bad("the wallet address is not a URL"))?;
        // A test set-up may use plain HTTP to the loopback address.
        let local = u.scheme() == "http" && u.host_str() == Some("127.0.0.1");
        if u.scheme() != "https" && !local {
            return Err(bad("the wallet address must be https"));
        }
        Ok(Self { config, http, key, local, operator: OnceCell::new(), token: Mutex::new(None) })
    }

    /// The client's public key as a JWK (what the wallet provider must list for `key_id`).
    pub fn jwk(&self) -> Value {
        keys::ed25519_jwk(&self.key, &self.config.key_id)
    }

    /// A URL this client may call: `https` to a DNS name that resolves only to public addresses (on a test set-up,
    /// plain HTTP to 127.0.0.1 too). Every URL a buyer's wallet hands us passes this before it is called.
    async fn checked(&self, s: &str) -> Result<url::Url, BillingError> {
        let u = url::Url::parse(s).map_err(|_| bad("not a URL"))?;
        if self.local && u.scheme() == "http" && u.host_str() == Some("127.0.0.1") {
            return Ok(u);
        }
        // A plain https address only: no user name, password or fragment.
        if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
            return Err(bad("wallet URLs must be plain https URLs"));
        }
        // A name, not an address literal, because only names go through the resolver check.
        let Some(url::Host::Domain(host)) = u.host() else {
            return Err(bad("wallet URLs must name a host, not an address"));
        };
        let h = host.to_ascii_lowercase();
        if h == "localhost"
            || [".localhost", ".local", ".internal", ".svc", ".cluster.local", ".home.arpa"]
                .iter()
                .any(|s| h.ends_with(s))
            || !h.contains('.')
            || u.port().is_some_and(|p| p != 443)
        {
            return Err(bad("that wallet host is not reachable from here"));
        }
        // The name is also resolved here, so a bad name is refused before any request is signed.
        let addrs: Vec<_> = tokio::net::lookup_host((h.as_str(), 443)).await.map_err(unavailable)?.collect();
        if addrs.is_empty() || !addrs.iter().all(|a| is_public(a.ip())) {
            return Err(bad("that wallet host is not reachable from here"));
        }
        Ok(u)
    }

    /// Reads a wallet address document.
    pub async fn wallet(&self, address: &str) -> Result<WalletAddress, BillingError> {
        let u = self.checked(address).await?;
        let r = self.http.get(u).header("accept", "application/json").send().await.map_err(crate::transport)?;
        if !r.status().is_success() {
            return Err(BillingError::Refused(format!("the wallet address answered HTTP {}", r.status().as_u16())));
        }
        let body = crate::read_limited(r, crate::MAX_ANSWER_BYTES).await?;
        let w: WalletAddress = serde_json::from_slice(&body).map_err(|_| bad("not a wallet address document"))?;
        // The servers the document names are held to the same rule as the document's own address.
        for s in [&w.auth_server, &w.resource_server] {
            self.checked(s).await?;
        }
        Ok(w)
    }

    /// The operator's wallet address document, read once and kept.
    async fn operator(&self) -> Result<&WalletAddress, BillingError> {
        self.operator.get_or_try_init(|| self.wallet(&self.config.wallet_address)).await
    }

    /// A signed request (RFC 9421 under `sig1`): `@method`, `@target-uri`, and `authorization`, `content-digest`,
    /// `content-length` and `content-type` when present. Returns the status and the JSON answer.
    async fn signed(
        &self,
        method: reqwest::Method,
        url: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<(u16, Value), BillingError> {
        let u = self.checked(url).await?;
        // The address as the signature will cover it.
        let target = u.as_str().to_string();
        // The body, serialised once, so the digest and what is sent are the same bytes.
        let bytes = body.map(|b| b.to_string().into_bytes());
        let mut headers: Vec<(String, String)> = Vec::new();
        // The method and the address are always signed; the rest depend on what the request has.
        let mut components = vec!["@method", "@target-uri"];
        if let Some(t) = token {
            headers.push(("authorization".into(), format!("GNAP {t}")));
            components.push("authorization");
        }
        if let Some(b) = &bytes {
            headers.push(("content-digest".into(), httpsig::content_digest_sha512(b)));
            headers.push(("content-length".into(), b.len().to_string()));
            headers.push(("content-type".into(), "application/json".into()));
            components.extend(["content-digest", "content-length", "content-type"]);
        }
        // The signature parameters: the algorithm, the key id the wallet provider lists, and the time.
        let params = [
            Param::Str("alg", "ed25519".into()),
            Param::Str("keyid", self.config.key_id.clone()),
            Param::Int("created", OffsetDateTime::now_utc().unix_timestamp()),
        ];
        // The message the signature covers.
        let msg = Message { method: method.as_str(), target_uri: &target, headers: &headers };
        let (input, sig) =
            httpsig::sign_ed25519(&self.key, "sig1", &msg, &components, &params).ok_or_else(|| bad("signature"))?;
        let mut r = self.http.request(method, u).header("accept", "application/json");
        for (k, v) in &headers {
            r = r.header(k.as_str(), v.as_str());
        }
        r = r.header("signature-input", input).header("signature", sig);
        if let Some(b) = bytes {
            r = r.body(b);
        }
        let resp = r.send().await.map_err(crate::transport)?;
        // The status and the JSON body, which may be absent in an error.
        let status = resp.status().as_u16();
        let v: Value = crate::read_json_or_null(resp, crate::MAX_ANSWER_BYTES).await?;
        Ok((status, v))
    }

    /// A signed request that must succeed: a server error is unavailable, any other failure is a refusal with the provider's message.
    async fn signed_ok(
        &self,
        method: reqwest::Method,
        url: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, BillingError> {
        let (status, v) = self.signed(method, url, token, body).await?;
        match status {
            // Success.
            200..=299 => Ok(v),
            // A server error: try again later.
            500.. => Err(BillingError::Unavailable(format!("HTTP {status}"))),
            _ => Err(BillingError::Refused(format!("HTTP {status}: {}", grant_error(&v)))),
        }
    }

    /// A non-interactive grant: the access token's value and lifetime.
    async fn grant(&self, auth_server: &str, access: Value) -> Result<(String, Duration), BillingError> {
        // A grant request names the access wanted and the client.
        let body = json!({ "access_token": { "access": [access] }, "client": self.config.wallet_address });
        let v = self.signed_ok(reqwest::Method::POST, auth_server, None, Some(&body)).await?;
        let token = v["access_token"]["value"].as_str().ok_or_else(|| bad("the grant holds no access token"))?;
        // A token without a stated lifetime is assumed to last five minutes.
        let ttl = v["access_token"]["expires_in"].as_u64().unwrap_or(300);
        Ok((token.to_string(), Duration::from_secs(ttl)))
    }

    /// The operator's incoming-payment token (create and read), reused until shortly before it expires.
    async fn incoming_token(&self, fresh: bool) -> Result<String, BillingError> {
        // One token at a time is created, so concurrent checkouts share it.
        let mut t = self.token.lock().await;
        if !fresh
            && let Some((v, until)) = t.as_ref()
            && *until > Instant::now() + Duration::from_secs(30)
        {
            return Ok(v.clone());
        }
        let op = self.operator().await?;
        // A new token with its lifetime.
        let (v, ttl) =
            self.grant(&op.auth_server, json!({ "type": "incoming-payment", "actions": ["create", "read"] })).await?;
        *t = Some((v.clone(), Instant::now() + ttl));
        Ok(v)
    }

    /// The amount of a checkout in the wallet's asset: the configured price per month times the months, or, for pounds, the price in pence scaled to the asset's decimals. `None` on overflow.
    fn amount_minor(&self, req: &CheckoutRequest) -> Option<u128> {
        match self.config.minor_per_month {
            // A configured price per month, times the months.
            Some(m) => u128::from(m).checked_mul(u128::from(req.months)),
            // Pounds: the pence amount scaled up to the asset's decimal places.
            None => u128::from(req.amount_pence)
                .checked_mul(10u128.checked_pow(u32::from(self.config.asset_scale).checked_sub(2)?)?),
        }
    }

    /// Whether an incoming payment is on the operator's own resource server, so a buyer cannot make the service poll another address.
    fn is_ours(&self, op: &WalletAddress, incoming_payment: &str) -> bool {
        incoming_payment.len() <= 200
            && incoming_payment
                .strip_prefix(op.resource_server.trim_end_matches('/'))
                .is_some_and(|rest| rest.starts_with("/incoming-payments/"))
    }

    /// Steps 2 and 3: the buyer's wallet address, a quote for our incoming payment, and the interactive outgoing-payment
    /// grant whose `finish` redirect comes back to `finish_uri`.
    pub async fn start_payment(
        &self,
        incoming_payment: &str,
        buyer: &str,
        finish_uri: &str,
    ) -> Result<PendingPayment, BillingError> {
        let op = self.operator().await?;
        if !self.is_ours(op, incoming_payment) {
            return Err(bad("not an incoming payment of the operator's wallet"));
        }
        // The buyer's address is read and checked before anything is requested of it.
        let buyer = self.wallet(&wallet_address_url(buyer)?).await?;
        // A quote grant on the buyer's authorization server.
        let (quote_token, _) =
            self.grant(&buyer.auth_server, json!({ "type": "quote", "actions": ["create", "read"] })).await?;
        let quote = self
            .signed_ok(
                reqwest::Method::POST,
                &format!("{}/quotes", buyer.resource_server.trim_end_matches('/')),
                Some(&quote_token),
                Some(&json!({ "walletAddress": buyer.id, "receiver": incoming_payment, "method": "ilp" })),
            )
            .await?;
        // The quote must have an id and a debit amount, and be for the operator's asset.
        let quote_id = quote["id"].as_str().ok_or_else(|| bad("the quote has no id"))?.to_string();
        // What the buyer would pay, according to their own wallet.
        let debit = quote["debitAmount"].clone();
        if amount_value(&debit).is_none() {
            return Err(bad("the quote has no debit amount"));
        }
        if quote["receiveAmount"]["assetCode"].as_str() != Some(self.config.asset_code.as_str()) {
            return Err(bad("the quote is not for the operator's asset"));
        }
        // The nonce binds the buyer's return to this grant.
        let client_nonce = keys::random_hex(16)?;
        let body = json!({
            "access_token": { "access": [{
                "type": "outgoing-payment", "actions": ["create", "read"], "identifier": buyer.id,
                // The grant is limited to the quote's debit amount and to this one incoming payment.
                "limits": { "debitAmount": debit, "receiver": incoming_payment },
            }] },
            "client": self.config.wallet_address,
            "interact": {
                "start": ["redirect"],
                "finish": { "method": "redirect", "uri": finish_uri, "nonce": client_nonce },
            },
        });
        let g = self.signed_ok(reqwest::Method::POST, &buyer.auth_server, None, Some(&body)).await?;
        let (Some(redirect), Some(server_nonce), Some(continue_uri), Some(continue_token)) = (
            g["interact"]["redirect"].as_str(),
            g["interact"]["finish"].as_str(),
            g["continue"]["uri"].as_str(),
            g["continue"]["access_token"]["value"].as_str(),
        ) else {
            return Err(bad("the wallet did not offer an interactive grant"));
        };
        // The addresses the wallet hands back are checked before the buyer is sent to one or the service calls one.
        self.checked(redirect).await?;
        self.checked(continue_uri).await?;
        Ok(PendingPayment {
            incoming_payment: incoming_payment.to_string(),
            buyer_wallet: buyer.id.clone(),
            buyer_resource_server: buyer.resource_server.clone(),
            grant_endpoint: buyer.auth_server.clone(),
            client_nonce,
            server_nonce: server_nonce.to_string(),
            redirect: redirect.to_string(),
            continue_uri: continue_uri.to_string(),
            continue_token: continue_token.to_string(),
            quote_id,
            debit_amount: debit,
            receive_amount: quote["receiveAmount"].clone(),
        })
    }

    /// Whether the `hash` the authorization server sent back with the buyer is the one RFC 9635 §4.2.3 defines for
    /// this grant and `interact_ref`.
    pub fn finish_hash_valid(p: &PendingPayment, hash: &str, interact_ref: &str) -> bool {
        let want = httpsig::interaction_hash(&p.client_nonce, &p.server_nonce, interact_ref, &p.grant_endpoint);
        same(want.as_bytes(), hash.as_bytes())
    }

    /// Step 4: checks the interaction hash, continues the grant with the interaction reference and creates the
    /// outgoing payment. Returns the outgoing payment's id.
    pub async fn finish_payment(
        &self,
        p: &PendingPayment,
        hash: &str,
        interact_ref: &str,
    ) -> Result<String, BillingError> {
        // The interaction reference is short printable text, so it can be put in a request safely.
        if interact_ref.is_empty() || interact_ref.len() > 200 || !interact_ref.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(bad("not an interaction reference"));
        }
        // The hash proves the return came from the authorization server that was asked, for this grant.
        if !Self::finish_hash_valid(p, hash, interact_ref) {
            return Err(BillingError::Unauthentic);
        }
        let c = self
            .signed_ok(
                reqwest::Method::POST,
                &p.continue_uri,
                Some(&p.continue_token),
                Some(&json!({ "interact_ref": interact_ref })),
            )
            .await?;
        // The continued grant yields the token that allows the outgoing payment.
        let token = c["access_token"]["value"].as_str().ok_or_else(|| bad("the grant was not approved"))?;
        let out = self
            .signed_ok(
                reqwest::Method::POST,
                &format!("{}/outgoing-payments", p.buyer_resource_server.trim_end_matches('/')),
                Some(token),
                Some(&json!({ "walletAddress": p.buyer_wallet, "quoteId": p.quote_id })),
            )
            .await?;
        // The outgoing payment's id is the result.
        out["id"].as_str().map(String::from).ok_or_else(|| bad("the outgoing payment has no id"))
    }
}

/// The error text of a GNAP or Open Payments refusal.
fn grant_error(v: &Value) -> String {
    for p in ["/error/description", "/error/code", "/error"] {
        if let Some(m) = v.pointer(p).and_then(Value::as_str) {
            return m.chars().take(200).collect();
        }
    }
    provider_message(v)
}

#[async_trait::async_trait]
impl BillingProvider for OpenPayments {
    /// The provider id.
    fn id(&self) -> &'static str {
        ID
    }

    /// One method, paying from an Open Payments wallet, sold by the operator, with no fixed fee.
    fn methods(&self) -> Vec<Method> {
        vec![Method {
            id: METHOD.into(),
            provider: ID.into(),
            label: "Open Payments wallet (Interledger)".into(),
            seller: Seller::Operator,
            fees: Fees { fixed_pence: 0, percent_bps: 0 },
            recurring: false,
        }]
    }

    /// Create an incoming payment on the operator's wallet for the amount; its address is the checkout's reference. The buyer's wallet address is asked for next.
    async fn create_checkout(&self, req: &CheckoutRequest) -> Result<CheckoutStart, BillingError> {
        if req.method != METHOD {
            return Err(BillingError::NotOffered);
        }
        // The amount in the wallet's asset.
        let minor = self.amount_minor(req).ok_or_else(|| bad("amount"))?;
        let op = self.operator().await?.clone();
        if op.asset_code != self.config.asset_code || op.asset_scale != self.config.asset_scale {
            return Err(bad(format!(
                "the operator's wallet holds {} (scale {}), not the configured asset",
                op.asset_code, op.asset_scale
            )));
        }
        let body = json!({
            "walletAddress": op.id,
            "incomingAmount": {
                "value": minor.to_string(), "assetCode": self.config.asset_code, "assetScale": self.config.asset_scale,
            },
            "expiresAt": crate::rfc3339(OffsetDateTime::now_utc() + INCOMING_PAYMENT_LIFETIME),
            "metadata": { "description": req.description, "externalRef": req.checkout_id },
        });
        // The incoming payment is created on the operator's own resource server.
        let url = format!("{}/incoming-payments", op.resource_server.trim_end_matches('/'));
        let mut token = self.incoming_token(false).await?;
        let mut answer = self.signed(reqwest::Method::POST, &url, Some(&token), Some(&body)).await?;
        // An expired or revoked token is replaced once and the request repeated.
        if matches!(answer.0, 401 | 403) {
            token = self.incoming_token(true).await?;
            answer = self.signed(reqwest::Method::POST, &url, Some(&token), Some(&body)).await?;
        }
        let v = match answer {
            (200..=299, v) => v,
            (s @ 500.., _) => return Err(BillingError::Unavailable(format!("HTTP {s}"))),
            (s, v) => return Err(BillingError::Refused(format!("HTTP {s}: {}", grant_error(&v)))),
        };
        let id = v["id"].as_str().ok_or_else(|| bad("the incoming payment has no id"))?;
        // The id the wallet returned must be on the operator's own resource server.
        if !self.is_ours(&op, id) {
            return Err(bad("the incoming payment is not on the operator's resource server"));
        }
        Ok(CheckoutStart {
            provider_ref: id.to_string(),
            client: json!({
                "kind": "open-payments", "step": "wallet-address", "payee": op.id, "incomingPayment": id,
                "assetCode": self.config.asset_code, "assetScale": self.config.asset_scale,
                "amount": format_amount(minor, self.config.asset_scale), "amountMinor": minor.to_string(),
            }),
        })
    }

    /// Always refused: a client receives no notifications, so the incoming payment is read instead.
    async fn verify_notification(
        &self,
        _: &BTreeMap<String, String>,
        _: &[u8],
        _: OffsetDateTime,
    ) -> Result<Vec<ProviderEvent>, BillingError> {
        // Open Payments has no notifications for a client: the incoming payment is read instead.
        Err(BillingError::Unauthentic)
    }

    /// Read the incoming payment: paid once it has received at least its amount, expired when its time has passed or it is gone, otherwise open.
    async fn checkout_outcome(&self, provider_ref: &str) -> Result<Outcome, BillingError> {
        let op = self.operator().await?.clone();
        if !self.is_ours(&op, provider_ref) {
            return Err(bad("not an incoming payment of the operator's wallet"));
        }
        let mut token = self.incoming_token(false).await?;
        let mut answer = self.signed(reqwest::Method::GET, provider_ref, Some(&token), None).await?;
        if matches!(answer.0, 401 | 403) {
            token = self.incoming_token(true).await?;
            answer = self.signed(reqwest::Method::GET, provider_ref, Some(&token), None).await?;
        }
        let v = match answer {
            (200..=299, v) => v,
            (404, _) => return Ok(Outcome::Expired),
            (s @ 500.., _) => return Err(BillingError::Unavailable(format!("HTTP {s}"))),
            (s, v) => return Err(BillingError::Refused(format!("HTTP {s}: {}", grant_error(&v)))),
        };
        // The amount asked for and the amount received so far.
        let (want, got) = (&v["incomingAmount"], &v["receivedAmount"]);
        // Both amounts must be in the configured asset and scale.
        for a in [want, got] {
            if a["assetCode"].as_str() != Some(self.config.asset_code.as_str())
                || a["assetScale"].as_u64() != Some(u64::from(self.config.asset_scale))
            {
                return Err(bad("the incoming payment is not in the configured asset"));
            }
        }
        let (Some(want), Some(got)) = (amount_value(want), amount_value(got)) else {
            return Err(bad("the incoming payment has no amounts"));
        };
        // Paid only when something was asked for and at least that was received.
        if want > 0 && got >= want {
            return Ok(Outcome::Paid);
        }
        let expired =
            v["expiresAt"].as_str().and_then(crate::parse_rfc3339).is_some_and(|t| t < OffsetDateTime::now_utc());
        // Not yet paid: expired if its time has passed, otherwise still open.
        Ok(if expired { Outcome::Expired } else { Outcome::Open })
    }
}

/// Unit tests for amounts, payment pointers, which addresses are public and the resolver.
#[cfg(test)]
mod tests {
    use super::*;

    /// Amounts are written with the asset's scale, payment pointers become addresses, and spaces and empty input are refused.
    #[test]
    fn amounts_and_pointers() {
        assert_eq!(format_amount(300, 2), "3.00");
        assert_eq!(format_amount(5, 2), "0.05");
        assert_eq!(format_amount(1_234_500, 4), "123.4500");
        assert_eq!(format_amount(7, 0), "7");
        assert_eq!(wallet_address_url("$ilp.example/alice").unwrap(), "https://ilp.example/alice");
        assert_eq!(wallet_address_url("$ilp.example").unwrap(), "https://ilp.example/.well-known/pay");
        assert_eq!(wallet_address_url(" https://ilp.example/bob ").unwrap(), "https://ilp.example/bob");
        assert!(wallet_address_url("https://ilp.example/a b").is_err());
        assert!(wallet_address_url("").is_err());
    }

    /// Private, loopback, link-local, shared and mapped addresses are refused, public ones pass, and addresses that embed a private IPv4 address (NAT64, 6to4) or are in the old site-local range are refused.
    #[test]
    fn only_public_addresses() {
        for a in [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.1.1",
            "192.168.1.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(a.parse().unwrap()), "{a}");
        }
        for a in ["1.1.1.1", "2606:4700:4700::1111", "64:ff9b::101:101", "2002:101:101::1"] {
            assert!(is_public(a.parse().unwrap()), "{a}");
        }
        // Addresses that carry a private IPv4 address inside them, and the old site-local range.
        for a in
            ["64:ff9b::a00:1", "64:ff9b::7f00:1", "2002:a9fe:a9fe::1", "2002:c0a8:101::", "fec0::1", "64:ff9b:1::1"]
        {
            assert!(!is_public(a.parse().unwrap()), "{a}");
        }
    }

    /// A name that resolves to a private address is refused by the resolver, and a client built with it never connects to one.
    #[tokio::test]
    async fn the_resolver_refuses_names_of_private_addresses_at_connect_time() {
        use reqwest::dns::Resolve;
        use std::str::FromStr;
        // `localhost` resolves to loopback on every system: refused by the resolver itself, whatever `checked` said.
        let r = PublicOnly.resolve(reqwest::dns::Name::from_str("localhost").unwrap()).await;
        assert!(r.is_err());
        // And a client built with it never connects there.
        let e = OpenPayments::http_client().get("http://localhost:9/").send().await.unwrap_err();
        assert!(e.is_connect() || e.is_request(), "{e}");
        let mut source: Option<&dyn std::error::Error> = Some(&e);
        let mut said = false;
        while let Some(s) = source {
            said |= s.to_string().contains("not public");
            source = s.source();
        }
        assert!(said, "the refusal is the resolver's: {e}");
    }
}
