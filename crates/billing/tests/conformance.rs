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
