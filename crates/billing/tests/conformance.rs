//! The conformance checks every billing adapter passes, run here against the Chain Payments adapter and an in-process
//! stand-in for the Chain Payments merchant API (which also signs the webhooks, as the real service does).
//!
//! Every adapter must: offer only its own methods; start a checkout and return a reference and client data; refuse a
//! notification that is unsigned, signed by another key, altered or stale; read a genuine one into an event about the
//! same checkout with a stable id (so the ledger applies it once); and report a checkout's outcome.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use link_in_bio_billing::chain_payments::{self, ChainPayments, Config};
use link_in_bio_billing::{BillingError, BillingProvider, CheckoutRequest, Outcome};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use uuid::Uuid;

const KEY: &str = "cpk_test_000000000000000000000000000000";

#[derive(Default)]
struct Mock {
    sessions: Mutex<BTreeMap<String, (Value, String)>>,
}

async fn create(State(m): State<Arc<Mock>>, headers: HeaderMap, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(&format!("Bearer {KEY}")) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "unknown API key"})));
    }
    if body["units"].as_u64().unwrap_or(0) == 0 || body["subscriptionRef"].as_str().unwrap_or("").is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": "bad request"})));
    }
    let id = format!("{:032x}", Uuid::new_v4().as_u128());
    m.sessions.lock().unwrap().insert(id.clone(), (body, "open".into()));
    (StatusCode::CREATED, Json(json!({"id": id})))
}

async fn session(State(m): State<Arc<Mock>>, Path(id): Path<String>) -> (StatusCode, Json<Value>) {
    match m.sessions.lock().unwrap().get(&id) {
        Some((_, status)) => (StatusCode::OK, Json(json!({"id": id, "status": status}))),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "not found"}))),
    }
}

async fn serve(mock: Arc<Mock>, public_hex: String) -> String {
    let app = Router::new()
        .route("/v1/merchant/sessions", post(create))
        .route("/v1/merchant/sessions/{id}", get(session))
        .route(
            "/v1/webhook-key",
            get(move || async move { Json(json!({"algorithm": "ed25519", "publicKey": public_hex})) }),
        )
        .with_state(mock);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

fn sign(kp: &Ed25519KeyPair, t: i64, body: &[u8]) -> String {
    let mut msg = format!("{t}.").into_bytes();
    msg.extend_from_slice(body);
    format!("t={t},ed25519={}", STANDARD.encode(kp.sign(&msg)))
}

fn headers(sig: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(chain_payments::SIGNATURE_HEADER.to_string(), sig.to_string())])
}

#[tokio::test]
async fn chain_payments_adapter_conforms() {
    let kp = Ed25519KeyPair::from_seed_unchecked(&[5u8; 32]).unwrap();
    let other = Ed25519KeyPair::from_seed_unchecked(&[6u8; 32]).unwrap();
    let mock = Arc::new(Mock::default());
    let base = serve(mock.clone(), hex::encode(kp.public_key().as_ref())).await;
    let config = Config {
        merchant_api: base.clone(),
        public_api: base.clone(),
        checkout_origin: "https://chain-payments.example.dev".into(),
        api_key: KEY.into(),
        methods: vec![("sui-testnet:SUI".into(), "SUI".into()), ("sui-testnet:USDC".into(), "USDC".into())],
        webhook_key: None,
    };
    let p = ChainPayments::new(config.clone(), ChainPayments::http_client()).unwrap();

    // Methods: its own, namespaced by the provider id.
    let methods: Vec<String> = p.methods().into_iter().map(|m| m.id).collect();
    assert_eq!(methods, vec!["chain-payments:sui-testnet:SUI", "chain-payments:sui-testnet:USDC"]);

    // A checkout.
    let req = CheckoutRequest {
        checkout_id: Uuid::new_v4(),
        method: "chain-payments:sui-testnet:SUI".into(),
        billing_ref: "ref-alice-000000001".into(),
        months: 3,
        amount_pence: 900,
        description: "Link in Bio, 3 months".into(),
        return_url: "https://app.example.link/billing?checkout=x".into(),
    };
    let start = p.create_checkout(&req).await.unwrap();
    assert_eq!(start.client["sessionId"], start.provider_ref);
    assert_eq!(start.client["baseUrl"], "https://chain-payments.example.dev");
    let sent = mock.sessions.lock().unwrap()[&start.provider_ref].0.clone();
    assert_eq!((sent["units"].as_u64(), sent["amountPence"].as_u64()), (Some(3), Some(900)));
    assert_eq!(sent["methods"], json!(["sui-testnet:SUI"]));
    assert!(matches!(
        p.create_checkout(&CheckoutRequest { method: "chain-payments:eth:ETH".into(), ..req.clone() }).await,
        Err(BillingError::NotOffered)
    ));
    let wrong_key = ChainPayments::new(
        Config { api_key: "cpk_wrong_00000000000000000000000000000".into(), ..config },
        ChainPayments::http_client(),
    )
    .unwrap();
    assert!(matches!(wrong_key.create_checkout(&req).await, Err(BillingError::Refused(_))));

    // Notifications.
    let now = Utc::now();
    let body = serde_json::to_vec(&json!({
        "id": Uuid::new_v4().to_string(), "event": "session.paid",
        "data": {"type": "session.paid", "sessionId": start.provider_ref, "units": 3, "amountPence": 900,
                 "method": "sui-testnet:SUI", "coinType": "0x2::sui::SUI", "amount": "5500000000",
                 "digest": "7AkSLeZf", "payer": "0xabc", "paidUntilMs": 1}
    }))
    .unwrap();
    let good = sign(&kp, now.timestamp(), &body);
    let events = p.verify_notification(&headers(&good), &body, now).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, Outcome::Paid);
    assert_eq!(events[0].provider_ref, start.provider_ref);
    assert_eq!(events[0].event_id, chain_payments::paid_event_id(&start.provider_ref), "stable: the session");
    assert_eq!(events[0].evidence["digest"], "7AkSLeZf");
    // A second delivery of the same event reads the same id.
    assert_eq!(p.verify_notification(&headers(&good), &body, now).await.unwrap()[0].event_id, events[0].event_id);

    let unauthentic = |r: Result<_, BillingError>| matches!(r, Err(BillingError::Unauthentic));
    assert!(unauthentic(p.verify_notification(&BTreeMap::new(), &body, now).await), "unsigned");
    assert!(
        unauthentic(p.verify_notification(&headers(&sign(&other, now.timestamp(), &body)), &body, now).await),
        "other key"
    );
    let mut altered = body.clone();
    altered[10] ^= 1;
    assert!(unauthentic(p.verify_notification(&headers(&good), &altered, now).await), "altered");
    let stale = sign(&kp, now.timestamp() - 3600, &body);
    assert!(unauthentic(p.verify_notification(&headers(&stale), &body, now).await), "stale");

    // An event the adapter does not act on is acknowledged and produces nothing.
    let other_event =
        serde_json::to_vec(&json!({"id": "x", "event": "session.expired", "data": {"sessionId": start.provider_ref}}))
            .unwrap();
    assert!(
        p.verify_notification(&headers(&sign(&kp, now.timestamp(), &other_event)), &other_event, now)
            .await
            .unwrap()
            .is_empty()
    );

    // Outcomes.
    assert_eq!(p.checkout_outcome(&start.provider_ref).await.unwrap(), Outcome::Open);
    mock.sessions.lock().unwrap().get_mut(&start.provider_ref).unwrap().1 = "paid".into();
    assert_eq!(p.checkout_outcome(&start.provider_ref).await.unwrap(), Outcome::Paid);
    assert_eq!(p.checkout_outcome(&"0".repeat(32)).await.unwrap(), Outcome::Expired);
    assert!(p.checkout_outcome("../etc").await.is_err());
}

#[test]
fn a_configured_key_must_be_well_formed() {
    let c = Config {
        merchant_api: "http://x".into(),
        public_api: "http://x".into(),
        checkout_origin: "https://x".into(),
        api_key: KEY.into(),
        methods: vec![],
        webhook_key: Some("abcd".into()),
    };
    assert!(ChainPayments::new(c, ChainPayments::http_client()).is_err());
}

// ── The fiat adapters, each against a stand-in for its provider's API ───────────────────────────────────────────────

use link_in_bio_billing::{bank_transfer, gocardless, paddle, square};

/// Serves fixed JSON answers by path (the stand-in records nothing; the adapters' requests are checked by shape).
async fn stand_in(routes: Vec<(&'static str, Value)>) -> String {
    let mut app = Router::new();
    for (path, body) in routes {
        let b = body.clone();
        app = app.route(
            path,
            get({
                let b = b.clone();
                move || async move { Json(b) }
            })
            .post(move || async move { (StatusCode::CREATED, Json(b)) }),
        );
    }
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}")
}

fn request(method: &str, months: u32) -> CheckoutRequest {
    CheckoutRequest {
        checkout_id: Uuid::new_v4(),
        method: method.into(),
        billing_ref: "ref-alice-000000001".into(),
        months,
        amount_pence: 300 * u64::from(months),
        description: "Link in Bio".into(),
        return_url: "https://app.example.link/billing?checkout=x".into(),
    }
}

fn h(k: &str, v: &str) -> BTreeMap<String, String> {
    BTreeMap::from([(k.to_string(), v.to_string())])
}

#[tokio::test]
async fn square_adapter_conforms() {
    let base = stand_in(vec![
        (
            "/v2/online-checkout/payment-links",
            json!({ "payment_link": { "id": "PL1", "url": "https://square.link/u/abc", "order_id": "ORD1" } }),
        ),
        ("/v2/orders/{id}", json!({ "order": { "id": "ORD1", "state": "COMPLETED" } })),
    ])
    .await;
    let c = square::Config {
        api_base: base,
        access_token: "t".into(),
        location_id: "L1".into(),
        signature_key: "sk".into(),
        notification_url: "https://app.example.link/api/v1/webhooks/square".into(),
        fixed_pence: 25,
        percent_bps: 140,
    };
    let p = square::Square::new(c.clone(), link_in_bio_billing::http_client());
    assert_eq!(p.methods()[0].id, "square:card");
    assert!(matches!(p.create_checkout(&request("square:other", 4)).await, Err(BillingError::NotOffered)));
    let s = p.create_checkout(&request("square:card", 4)).await.unwrap();
    assert_eq!(
        (s.provider_ref.as_str(), s.client["kind"].as_str(), s.client["url"].as_str()),
        ("ORD1", Some("redirect"), Some("https://square.link/u/abc"))
    );
    let body = serde_json::to_vec(&json!({ "type": "payment.updated", "event_id": "E1", "data": { "object": { "payment": {
        "id": "P1", "order_id": "ORD1", "status": "COMPLETED", "amount_money": { "amount": 1200, "currency": "GBP" } } } } })).unwrap();
    let sig = square::signature(&c.signature_key, &c.notification_url, &body);
    let now = Utc::now();
    let e = p.verify_notification(&h(square::SIGNATURE_HEADER, &sig), &body, now).await.unwrap();
    assert_eq!((e[0].outcome.clone(), e[0].event_id.clone()), (Outcome::Paid, p.paid_event_id("ORD1")));
    assert!(matches!(p.verify_notification(&BTreeMap::new(), &body, now).await, Err(BillingError::Unauthentic)));
    let other_url = square::signature(&c.signature_key, "https://elsewhere.example/hook", &body);
    assert!(matches!(
        p.verify_notification(&h(square::SIGNATURE_HEADER, &other_url), &body, now).await,
        Err(BillingError::Unauthentic)
    ));
    let mut altered = body.clone();
    altered[5] ^= 1;
    assert!(matches!(
        p.verify_notification(&h(square::SIGNATURE_HEADER, &sig), &altered, now).await,
        Err(BillingError::Unauthentic)
    ));
    assert_eq!(p.checkout_outcome("ORD1").await.unwrap(), Outcome::Paid);
    assert!(p.checkout_outcome("../x").await.is_err());
}

#[tokio::test]
async fn gocardless_adapter_conforms() {
    let base = stand_in(vec![
        ("/billing_requests", json!({ "billing_requests": { "id": "BRQ123", "status": "pending" } })),
        ("/billing_request_flows", json!({ "billing_request_flows": { "authorisation_url": "https://pay.gocardless.com/billing/static/flow?id=BRF1" } })),
        ("/billing_requests/{id}", json!({ "billing_requests": { "id": "BRQ123", "status": "fulfilled" } })),
    ])
    .await;
    let c = gocardless::Config {
        api_base: base,
        access_token: "t".into(),
        webhook_secret: "ws".into(),
        fixed_pence: 20,
        percent_bps: 100,
    };
    let p = gocardless::GoCardless::new(c.clone(), link_in_bio_billing::http_client());
    let s = p.create_checkout(&request("gocardless:bank", 3)).await.unwrap();
    assert_eq!(s.provider_ref, "BRQ123");
    assert!(s.client["url"].as_str().unwrap().starts_with("https://pay.gocardless.com/"));
    let body = serde_json::to_vec(&json!({ "events": [
        { "id": "EV1", "resource_type": "billing_requests", "action": "fulfilled", "links": { "billing_request": "BRQ123" } },
        { "id": "EV2", "resource_type": "mandates", "action": "created", "links": {} }
    ] })).unwrap();
    let now = Utc::now();
    let e = p
        .verify_notification(&h(gocardless::SIGNATURE_HEADER, &gocardless::signature("ws", &body)), &body, now)
        .await
        .unwrap();
    assert_eq!(e.len(), 1, "events it does not act on are acknowledged and ignored");
    assert_eq!((e[0].outcome.clone(), e[0].event_id.clone()), (Outcome::Paid, p.paid_event_id("BRQ123")));
    assert!(matches!(
        p.verify_notification(&h(gocardless::SIGNATURE_HEADER, &gocardless::signature("other", &body)), &body, now)
            .await,
        Err(BillingError::Unauthentic)
    ));
    assert_eq!(p.checkout_outcome("BRQ123").await.unwrap(), Outcome::Paid);
    assert!(p.checkout_outcome("PM123").await.is_err());
}

#[tokio::test]
async fn paddle_adapter_conforms() {
    let base = stand_in(vec![
        ("/transactions", json!({ "data": { "id": "txn_01", "status": "ready", "checkout": { "url": "https://pay.example.org/?_ptxn=txn_01" } } })),
        ("/transactions/{id}", json!({ "data": { "id": "txn_01", "status": "completed" } })),
    ])
    .await;
    let c = paddle::Config {
        api_base: base,
        api_key: "k".into(),
        webhook_secret: "pw".into(),
        price_id: "pri_1".into(),
        fixed_pence: 40,
        percent_bps: 500,
    };
    let p = paddle::Paddle::new(c, link_in_bio_billing::http_client());
    assert_eq!(p.methods()[0].seller, link_in_bio_billing::Seller::MerchantOfRecord);
    let s = p.create_checkout(&request("paddle:checkout", 6)).await.unwrap();
    assert_eq!(s.provider_ref, "txn_01");
    let body = serde_json::to_vec(&json!({ "event_id": "evt_1", "event_type": "transaction.completed", "data": { "id": "txn_01", "currency_code": "EUR" } })).unwrap();
    let now = Utc::now();
    let ts = now.timestamp().to_string();
    let sig = format!("ts={ts};h1={}", paddle::h1("pw", &ts, &body));
    let e = p.verify_notification(&h(paddle::SIGNATURE_HEADER, &sig), &body, now).await.unwrap();
    assert_eq!((e[0].outcome.clone(), e[0].event_id.clone()), (Outcome::Paid, p.paid_event_id("txn_01")));
    let old = (now.timestamp() - 3600).to_string();
    let stale = format!("ts={old};h1={}", paddle::h1("pw", &old, &body));
    assert!(matches!(
        p.verify_notification(&h(paddle::SIGNATURE_HEADER, &stale), &body, now).await,
        Err(BillingError::Unauthentic)
    ));
    let forged = format!("ts={ts};h1={}", paddle::h1("nope", &ts, &body));
    assert!(matches!(
        p.verify_notification(&h(paddle::SIGNATURE_HEADER, &forged), &body, now).await,
        Err(BillingError::Unauthentic)
    ));
    assert_eq!(p.checkout_outcome("txn_01").await.unwrap(), Outcome::Paid);
}

#[tokio::test]
async fn bank_transfer_adapter_conforms() {
    let sepa = bank_transfer::BankTransfer::new(bank_transfer::Config {
        payee: "Example Ltd".into(),
        scheme: bank_transfer::Scheme::Sepa {
            iban: "DE89370400440532013000".into(),
            bic: None,
            eur_cents_per_month: 350,
        },
    })
    .unwrap();
    let s = sepa.create_checkout(&request("bank-transfer:sepa", 2)).await.unwrap();
    assert!(bank_transfer::reference_valid(&s.provider_ref));
    assert_eq!(s.client["amount"], "7.00");
    assert!(s.client["qr"].as_str().unwrap().starts_with("BCD\n002\n1\nSCT\n"));
    assert_eq!(bank_transfer::expected(&s.client), Some((700, "EUR".into())));
    assert!(matches!(
        sepa.verify_notification(&BTreeMap::new(), b"{}", Utc::now()).await,
        Err(BillingError::Unauthentic)
    ));
    let camt = format!(
        r#"<Document><BkToCstmrDbtCdtNtfctn><Ntfctn><Ntry><Amt Ccy="EUR">7.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
        <NtryDtls><TxDtls><RmtInf><Strd><CdtrRefInf><Ref>{}</Ref></CdtrRefInf></Strd></RmtInf></TxDtls></NtryDtls></Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn></Document>"#,
        s.provider_ref
    );
    let credits = bank_transfer::credits_from_camt(&camt).unwrap();
    let e = bank_transfer::paid_event(&credits[0]);
    assert_eq!(e.provider_ref, s.provider_ref);
    assert_eq!(e.event_id, sepa.paid_event_id(&s.provider_ref), "the same key as reconciliation would use");
    assert!(
        bank_transfer::BankTransfer::new(bank_transfer::Config {
            payee: "X".into(),
            scheme: bank_transfer::Scheme::Sepa {
                iban: "DE00370400440532013000".into(),
                bic: None,
                eur_cents_per_month: 350
            },
        })
        .is_err(),
        "a bad IBAN is refused at start"
    );
    let fp = bank_transfer::BankTransfer::new(bank_transfer::Config {
        payee: "Example Ltd".into(),
        scheme: bank_transfer::Scheme::FasterPayments {
            sort_code: "12-34-56".into(),
            account_number: "12345678".into(),
        },
    })
    .unwrap();
    let s = fp.create_checkout(&request("bank-transfer:faster-payments", 1)).await.unwrap();
    assert_eq!((s.client["currency"].as_str(), s.client["amount"].as_str()), (Some("GBP"), Some("3.00")));
}

// ── Open Payments, against a stand-in account servicing entity that checks every signature ────────────────────────

#[path = "support/open_payments.rs"]
mod op_stand_in;

use link_in_bio_billing::open_payments::{self, OpenPayments};
use ring::signature::Ed25519KeyPair as Ed;

fn op_config(wallet: &str, key: &str) -> open_payments::Config {
    open_payments::Config {
        wallet_address: wallet.into(),
        key_id: "test-key-ed25519".into(),
        private_key_pem: key.into(),
        asset_code: "GBP".into(),
        asset_scale: 2,
        minor_per_month: None,
    }
}

#[tokio::test]
async fn open_payments_adapter_conforms() {
    let public = link_in_bio_billing::keys::ed25519_from_pem(&op_stand_in::test_key_pem())
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    let ase = op_stand_in::Ase::start(&public, "test-key-ed25519", ("GBP", 2)).await;
    let p =
        OpenPayments::new(op_config(&ase.operator(), &op_stand_in::test_key_pem()), link_in_bio_billing::http_client())
            .unwrap();
    assert_eq!(p.methods().into_iter().map(|m| m.id).collect::<Vec<_>>(), vec![open_payments::METHOD]);
    assert_eq!(p.jwk()["x"], "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs");
    assert!(matches!(p.create_checkout(&request("open-payments:other", 2)).await, Err(BillingError::NotOffered)));

    // Step 1: an incoming payment on the operator's wallet for the amount.
    let s = p.create_checkout(&request(open_payments::METHOD, 2)).await.unwrap();
    assert!(s.provider_ref.starts_with(&format!("{}/rs/incoming-payments/", ase.base)), "{}", s.provider_ref);
    assert_eq!(s.client["kind"], "open-payments");
    assert_eq!(s.client["step"], "wallet-address");
    assert_eq!((s.client["amount"].as_str(), s.client["amountMinor"].as_str()), (Some("6.00"), Some("600")));
    assert_eq!(p.checkout_outcome(&s.provider_ref).await.unwrap(), Outcome::Open);

    // Steps 2 and 3: the buyer's wallet address, a quote and an interactive grant limited to our incoming payment.
    let finish = "https://app.example.link/billing?checkout=x&openPayments=finish";
    let pending = p.start_payment(&s.provider_ref, &ase.buyer(), finish).await.unwrap();
    assert_eq!(pending.redirect, format!("{}/interact/1", ase.base));
    assert_eq!(pending.grant_endpoint, format!("{}/auth/", ase.base));
    assert_eq!(ase.pending_receiver().as_deref(), Some(s.provider_ref.as_str()));
    assert_eq!(pending.debit_amount["value"], "600");
    let (redirect_back, hash, interact_ref) = ase.approve();
    assert!(redirect_back.starts_with(finish));

    // Step 4: a wrong hash is refused before anything is sent; the right one continues the grant and pays.
    assert!(matches!(
        p.finish_payment(&pending, "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY", &interact_ref).await,
        Err(BillingError::Unauthentic)
    ));
    let mut other = pending.clone();
    other.client_nonce = "another".into();
    assert!(!OpenPayments::finish_hash_valid(&other, &hash, &interact_ref), "the hash binds our nonce");
    assert_eq!(ase.received(&s.provider_ref), 0);
    let out = p.finish_payment(&pending, &hash, &interact_ref).await.unwrap();
    assert!(out.starts_with(&format!("{}/rs/outgoing-payments/", ase.base)));
    assert_eq!(ase.received(&s.provider_ref), 600);
    assert_eq!(p.checkout_outcome(&s.provider_ref).await.unwrap(), Outcome::Paid);
    assert!(
        matches!(p.finish_payment(&pending, &hash, &interact_ref).await, Err(BillingError::Refused(_))),
        "the interaction is used up"
    );

    // A short payment is not a payment.
    ase.set_underpay(true);
    let s2 = p.create_checkout(&request(open_payments::METHOD, 1)).await.unwrap();
    let pending = p.start_payment(&s2.provider_ref, &ase.buyer(), finish).await.unwrap();
    let (_, hash, interact_ref) = ase.approve();
    p.finish_payment(&pending, &hash, &interact_ref).await.unwrap();
    assert_eq!(ase.received(&s2.provider_ref), 299);
    assert_eq!(p.checkout_outcome(&s2.provider_ref).await.unwrap(), Outcome::Open);

    // Every request was signed and verified; an unsigned one is refused by the stand-in, and so is another key.
    let (refused, ok) = ase.signatures();
    assert_eq!(refused, 0);
    assert!(ok >= 12, "{ok}");
    let unsigned = reqwest::Client::new().post(format!("{}/auth/", ase.base)).json(&json!({})).send().await.unwrap();
    assert_eq!(unsigned.status(), reqwest::StatusCode::UNAUTHORIZED);
    let other_key = Ed::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pem = link_in_bio_billing::keys::pem_encode("PRIVATE KEY", other_key.as_ref());
    let impostor = OpenPayments::new(op_config(&ase.operator(), &pem), link_in_bio_billing::http_client()).unwrap();
    assert!(matches!(
        impostor.create_checkout(&request(open_payments::METHOD, 1)).await,
        Err(BillingError::Refused(_))
    ));

    // References and wallets it will not touch.
    assert!(p.checkout_outcome("https://elsewhere.example/incoming-payments/1").await.is_err());
    for buyer in
        ["http://10.0.0.1/alice", "https://10.0.0.1/alice", "https://localhost/alice", "https://wallet.example:8443/a"]
    {
        assert!(p.start_payment(&s.provider_ref, buyer, finish).await.is_err(), "{buyer}");
    }
    assert!(matches!(p.verify_notification(&BTreeMap::new(), b"{}", Utc::now()).await, Err(BillingError::Unauthentic)));
}

#[test]
fn open_payments_settings_are_checked() {
    let ok = op_config("https://wallet.example/operator", &op_stand_in::test_key_pem());
    assert!(OpenPayments::new(ok.clone(), link_in_bio_billing::http_client()).is_ok());
    let bad = |c: open_payments::Config| OpenPayments::new(c, link_in_bio_billing::http_client()).is_err();
    assert!(bad(open_payments::Config { wallet_address: "http://wallet.example/op".into(), ..ok.clone() }));
    assert!(bad(open_payments::Config { private_key_pem: "nope".into(), ..ok.clone() }));
    assert!(bad(open_payments::Config { asset_code: "USD".into(), ..ok.clone() }), "another asset needs its price");
    assert!(!bad(open_payments::Config { asset_code: "USD".into(), minor_per_month: Some(400), ..ok.clone() }));
    assert!(bad(open_payments::Config { key_id: " ".into(), ..ok }));
}
