//! An in-process stand-in for an Open Payments account servicing entity (wallet addresses, a GNAP authorization server
//! and a resource server), shared by the billing conformance tests and the hosted tests (`#[path]`-included).
//!
//! It checks what a real one checks of a client: every grant and resource request carries an RFC 9421 signature by the
//! client's ed25519 key under its key id, covering `@method`, `@target-uri`, `authorization` when present and
//! `content-digest` (which must match the body) when there is a body; tokens are bound to what they were granted for.
//! Interactive grants follow RFC 9635: the finish redirect carries the interaction hash and reference.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use link_in_bio_billing::httpsig::{self, Message};
use serde_json::{Value, json};

/// RFC 9421 B.1.4 test-key-ed25519 (published in the RFC), armoured here: kept unarmoured so secret scanners do not
/// take it for a real key.
pub fn test_key_pem() -> String {
    link_in_bio_billing::keys::pem_encode(
        "PRIVATE KEY",
        &base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF",
        )
        .unwrap(),
    )
}

/// The stand-in's state: the client it expects, its payments, tokens and quotes, and counters of what it has seen.
#[derive(Default)]
struct Inner {
    /// Its own address.
    base: String,
    /// The client's public key, which every signature must verify against.
    client_key: Vec<u8>,
    /// The key id every signature must name.
    key_id: String,
    /// The asset code and scale the wallets hold.
    asset: (String, u8),
    /// Incoming payments: id → (incoming value, received value, expiresAt).
    incoming: BTreeMap<String, (u128, u128, String)>,
    /// The tokens it issued and what each is for.
    tokens: BTreeMap<String, &'static str>,
    /// The interactive grant waiting for the buyer: (client nonce, finish uri, server nonce, receiver).
    pending: Option<(String, String, String, String)>,
    /// The interaction reference of the approved grant, until it is continued.
    interact_ref: Option<String>,
    /// The quotes it issued: the receiver and the amount.
    quotes: BTreeMap<String, (String, u128)>,
    /// The buyer's wallet pays one unit less than asked (a short payment).
    pub underpay: bool,
    /// How many requests it refused for a missing or bad signature.
    refused: u32,
    /// How many requests carried a valid signature.
    signed_ok: u32,
    /// A counter for the ids and tokens it makes.
    next: u32,
}

/// A running stand-in.
#[derive(Clone)]
pub struct Ase {
    /// Its address.
    pub base: String,
    /// Its state, shared with the server task.
    inner: Arc<Mutex<Inner>>,
}

/// An Open Payments style error answer.
fn err(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({ "error": { "code": code, "description": code } }))).into_response()
}

/// Checks the request's signature; on success returns the GNAP token it presents (if any).
fn verify(
    s: &mut Inner,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<String>, Box<Response>> {
    // The request's headers with lower-case names, as the signature check wants them.
    let hs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_ascii_lowercase(), v.to_string())))
        .collect();
    // The signed address is the stand-in's own address plus the path and query.
    let target = format!("{}{}", s.base, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));
    let msg = Message { method: method.as_str(), target_uri: &target, headers: &hs };
    let Some(m) = httpsig::verify_ed25519(&msg, "sig1", &s.client_key) else {
        s.refused += 1;
        return Err(Box::new(err(StatusCode::UNAUTHORIZED, "invalid_client")));
    };
    // Whether the signature covers a component.
    let covers = |c: &str| m.components.iter().any(|x| x == c);
    let auth = msg.component("authorization");
    // The key id must be the client's, the signature must cover the method and address, the token when there is one, and the body's digest when there is a body.
    let ok = m.keyid.as_deref() == Some(s.key_id.as_str())
        && covers("@method")
        && covers("@target-uri")
        && (auth.is_none() || covers("authorization"))
        && (body.is_empty()
            || (covers("content-digest")
                && msg.component("content-digest").is_some_and(|d| httpsig::content_digest_valid(&d, body))));
    if !ok {
        s.refused += 1;
        return Err(Box::new(err(StatusCode::UNAUTHORIZED, "invalid_client")));
    }
    s.signed_ok += 1;
    // The GNAP token the request presented, if any.
    Ok(auth.and_then(|a| a.strip_prefix("GNAP ").map(String::from)))
}

/// Issue a token of a kind and remember it.
fn token(s: &mut Inner, kind: &'static str) -> String {
    s.next += 1;
    let t = format!("{kind}-token-{}", s.next);
    s.tokens.insert(t.clone(), kind);
    t
}

/// A wallet address document: the same asset, and the stand-in's own authorization and resource servers.
async fn wallet(State(a): State<Ase>, uri: Uri) -> Response {
    let s = a.inner.lock().unwrap();
    axum::Json(json!({
        "id": format!("{}{}", s.base, uri.path()), "publicName": "Test", "assetCode": s.asset.0, "assetScale": s.asset.1,
        "authServer": format!("{}/auth/", s.base), "resourceServer": format!("{}/rs", s.base),
    }))
    .into_response()
}

/// The grant endpoint: a verified request for an incoming-payment, quote or outgoing-payment grant. An outgoing one is interactive and answers with a redirect and the server's nonce.
async fn grant(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    if let Err(r) = verify(&mut s, &method, &uri, &headers, &body) {
        return *r;
    }
    let Ok(b) = serde_json::from_slice::<Value>(&body) else { return err(StatusCode::BAD_REQUEST, "invalid_request") };
    if b["client"].as_str() != Some(&format!("{}/operator", s.base)) {
        return err(StatusCode::BAD_REQUEST, "invalid_client");
    }
    let access = &b["access_token"]["access"][0];
    match access["type"].as_str() {
        Some("incoming-payment") => {
            let t = token(&mut s, "incoming");
            axum::Json(json!({ "access_token": { "value": t, "manage": format!("{}/auth/token/1", s.base), "expires_in": 600, "access": [access] } })).into_response()
        }
        Some("quote") => {
            let t = token(&mut s, "quote");
            axum::Json(json!({ "access_token": { "value": t, "manage": format!("{}/auth/token/2", s.base), "access": [access] } })).into_response()
        }
        Some("outgoing-payment") => {
            let finish = &b["interact"]["finish"];
            let (Some(nonce), Some(uri)) = (finish["nonce"].as_str(), finish["uri"].as_str()) else {
                return err(StatusCode::BAD_REQUEST, "invalid_interaction");
            };
            let receiver = access["limits"]["receiver"].as_str().unwrap_or("").to_string();
            s.next += 1;
            let server_nonce = format!("SERVERNONCE{}", s.next);
            s.pending = Some((nonce.to_string(), uri.to_string(), server_nonce.clone(), receiver));
            let base = s.base.clone();
            axum::Json(json!({
                "interact": { "redirect": format!("{base}/interact/1"), "finish": server_nonce },
                "continue": { "access_token": { "value": "continue-token-1" }, "uri": format!("{base}/auth/continue/1"), "wait": 30 },
            }))
            .into_response()
        }
        _ => err(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

/// The continuation endpoint: needs the continuation token and the interaction reference the buyer's approval produced, and answers with the outgoing-payment token.
async fn continue_grant(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    let presented = match verify(&mut s, &method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    if presented.as_deref() != Some("continue-token-1") {
        return err(StatusCode::UNAUTHORIZED, "invalid_continuation");
    }
    let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if s.interact_ref.is_none() || b["interact_ref"].as_str() != s.interact_ref.as_deref() {
        return err(StatusCode::BAD_REQUEST, "invalid_interaction");
    }
    s.interact_ref = None;
    let t = token(&mut s, "outgoing");
    axum::Json(json!({ "access_token": { "value": t, "manage": format!("{}/auth/token/3", s.base) } })).into_response()
}

/// Whether a request presented a token of the given kind.
fn needs(s: &Inner, t: &Option<String>, kind: &str) -> bool {
    t.as_ref().and_then(|t| s.tokens.get(t)).is_some_and(|k| *k == kind)
}

/// Create an incoming payment for the amount asked, with an incoming-payment token.
async fn incoming_create(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    let t = match verify(&mut s, &method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    if !needs(&s, &t, "incoming") {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let want: u128 = b["incomingAmount"]["value"].as_str().and_then(|v| v.parse().ok()).unwrap_or(0);
    s.next += 1;
    let id = format!("{}/rs/incoming-payments/{:08}", s.base, s.next);
    let expires = b["expiresAt"].as_str().unwrap_or("").to_string();
    s.incoming.insert(id.clone(), (want, 0, expires));
    (StatusCode::CREATED, axum::Json(incoming_json(&s, &id))).into_response()
}

/// An incoming payment as the resource server reports it.
fn incoming_json(s: &Inner, id: &str) -> Value {
    let (want, got, expires) = &s.incoming[id];
    json!({
        "id": id, "walletAddress": format!("{}/operator", s.base), "completed": got >= want,
        "incomingAmount": { "value": want.to_string(), "assetCode": s.asset.0, "assetScale": s.asset.1 },
        "receivedAmount": { "value": got.to_string(), "assetCode": s.asset.0, "assetScale": s.asset.1 },
        "expiresAt": expires,
    })
}

/// Read an incoming payment, with an incoming-payment token.
async fn incoming_get(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    let t = match verify(&mut s, &method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    if !needs(&s, &t, "incoming") {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let id = format!("{}{}", s.base, uri.path());
    if !s.incoming.contains_key(&id) {
        return err(StatusCode::NOT_FOUND, "not_found");
    }
    axum::Json(incoming_json(&s, &id)).into_response()
}

/// Quote an incoming payment: the amount still to be paid, in both directions.
async fn quote(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    let t = match verify(&mut s, &method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    if !needs(&s, &t, "quote") {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let receiver = b["receiver"].as_str().unwrap_or("").to_string();
    let Some((want, got, _)) = s.incoming.get(&receiver).cloned() else {
        return err(StatusCode::BAD_REQUEST, "invalid_receiver");
    };
    let left = want.saturating_sub(got);
    s.next += 1;
    let id = format!("{}/rs/quotes/{}", s.base, s.next);
    s.quotes.insert(id.clone(), (receiver.clone(), left));
    let amount = json!({ "value": left.to_string(), "assetCode": s.asset.0, "assetScale": s.asset.1 });
    (StatusCode::CREATED, axum::Json(json!({ "id": id, "walletAddress": b["walletAddress"], "receiver": receiver, "debitAmount": amount, "receiveAmount": amount, "method": "ilp" }))).into_response()
}

/// Create an outgoing payment from a quote: the receiver is credited (one unit short when told to underpay).
async fn outgoing(State(a): State<Ase>, method: Method, uri: Uri, headers: HeaderMap, body: Bytes) -> Response {
    let mut s = a.inner.lock().unwrap();
    let t = match verify(&mut s, &method, &uri, &headers, &body) {
        Ok(t) => t,
        Err(r) => return *r,
    };
    if !needs(&s, &t, "outgoing") {
        return err(StatusCode::UNAUTHORIZED, "invalid_token");
    }
    let b: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some((receiver, amount)) = b["quoteId"].as_str().and_then(|q| s.quotes.remove(q)) else {
        return err(StatusCode::BAD_REQUEST, "invalid_quote");
    };
    let pay = if s.underpay { amount.saturating_sub(1) } else { amount };
    if let Some(p) = s.incoming.get_mut(&receiver) {
        p.1 += pay;
    }
    s.next += 1;
    (
        StatusCode::CREATED,
        axum::Json(json!({ "id": format!("{}/rs/outgoing-payments/{}", s.base, s.next), "quoteId": b["quoteId"] })),
    )
        .into_response()
}

impl Ase {
    /// Serves a stand-in on 127.0.0.1 for a client with this public key and key id; the wallets hold `asset`.
    pub async fn start(client_public: &[u8], key_id: &str, asset: (&str, u8)) -> Self {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner {
            base: base.clone(),
            client_key: client_public.to_vec(),
            key_id: key_id.into(),
            asset: (asset.0.into(), asset.1),
            ..Default::default()
        }));
        let a = Ase { base, inner };
        let app = Router::new()
            .route("/operator", get(wallet))
            .route("/buyer", get(wallet))
            .route("/auth/", post(grant))
            .route("/auth/continue/1", post(continue_grant))
            .route("/rs/incoming-payments", post(incoming_create))
            .route("/rs/incoming-payments/{id}", get(incoming_get))
            .route("/rs/quotes", post(quote))
            .route("/rs/outgoing-payments", post(outgoing))
            .with_state(a.clone());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        a
    }

    /// The operator's wallet address.
    pub fn operator(&self) -> String {
        format!("{}/operator", self.base)
    }

    /// The buyer's wallet address.
    pub fn buyer(&self) -> String {
        format!("{}/buyer", self.base)
    }

    /// Make the buyer's wallet pay one unit less than asked, or stop.
    pub fn set_underpay(&self, on: bool) {
        self.inner.lock().unwrap().underpay = on;
    }

    /// What the buyer's wallet does when they approve: the finish URI it redirects to, with `hash` and `interact_ref`
    /// (computed as RFC 9635 §4.2.3 says, over the grant endpoint `<base>/auth/`).
    pub fn approve(&self) -> (String, String, String) {
        let mut s = self.inner.lock().unwrap();
        let (client_nonce, finish, server_nonce, _) = s.pending.clone().expect("an interactive grant");
        let interact_ref = "4IFWWIKYB2PQ6U56NL1".to_string();
        s.interact_ref = Some(interact_ref.clone());
        let hash = httpsig::interaction_hash(&client_nonce, &server_nonce, &interact_ref, &format!("{}/auth/", s.base));
        let sep = if finish.contains('?') { '&' } else { '?' };
        (format!("{finish}{sep}hash={hash}&interact_ref={interact_ref}"), hash, interact_ref)
    }

    /// The receiver the pending grant is limited to.
    pub fn pending_receiver(&self) -> Option<String> {
        self.inner.lock().unwrap().pending.as_ref().map(|p| p.3.clone())
    }

    /// The amount an incoming payment has received.
    pub fn received(&self, id: &str) -> u128 {
        self.inner.lock().unwrap().incoming.get(id).map(|p| p.1).unwrap_or(0)
    }

    /// Requests refused for a missing or bad signature, and requests whose signature held.
    pub fn signatures(&self) -> (u32, u32) {
        let s = self.inner.lock().unwrap();
        (s.refused, s.signed_ok)
    }
}
