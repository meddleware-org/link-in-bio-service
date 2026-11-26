//! In-process stand-ins for the banks' APIs (Wise, bunq, Revolut Business), shared by the billing conformance tests
//! and the hosted tests (`#[path]`-included). Each checks what the bank checks of a client:
//!
//! - Wise: the bearer token, and the SCA flow (403 with a one-time token, then the token signed with the key whose
//!   public half was "uploaded").
//! - bunq: the installation key, every body's `X-Bunq-Client-Signature`, the installation and session tokens; and it
//!   signs every answer with its server key (`X-Bunq-Server-Signature`), or forges one when told to.
//! - Revolut: the RS256 client assertion (signature, `iss`, `sub`, `aud`, `exp`), the refresh token and the bearer
//!   token.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use link_in_bio_billing::keys::{self, RsaKey};
use serde_json::{Value, json};

/// Wrap bare base64 DER in PEM armour, so the key fixtures carry none.
fn armour(label: &str, b64: &str) -> String {
    keys::pem_encode(label, &STANDARD.decode(b64.trim()).unwrap())
}

/// The operator's throwaway key (crates/billing/tests/fixtures; PKCS #8), as a PEM file's text.
pub fn operator_key_pem() -> String {
    armour("PRIVATE KEY", include_str!("../fixtures/test-rsa-a.pkcs8.b64"))
}

/// The operator's key.
pub fn operator_key() -> RsaKey {
    RsaKey::from_pem(&operator_key_pem()).unwrap()
}

/// The banks' throwaway server key (PKCS #1).
fn bank_key() -> RsaKey {
    RsaKey::from_pem(&armour("RSA PRIVATE KEY", include_str!("../fixtures/test-rsa-b.pkcs1.b64"))).unwrap()
}

/// A request header as text, if it is present and readable.
fn header(h: &HeaderMap, k: &str) -> Option<String> {
    h.get(k).and_then(|v| v.to_str().ok()).map(String::from)
}

/// Serve a router on a free local port and return its address.
async fn serve(app: Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    base
}

/// A camt.053 statement with the given credits (entry, currency, amount, reference) and one debit, which a reader must ignore.
fn camt053(credits: &[(String, String, String, String)]) -> String {
    let entries: String = credits
        .iter()
        .map(|(entry, ccy, amount, reference)| {
            format!(
                r#"<Ntry><Amt Ccy="{ccy}">{amount}</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts><BookgDt><Dt>2026-11-17</Dt></BookgDt><AcctSvcrRef>{entry}</AcctSvcrRef><NtryDtls><TxDtls><RmtInf><Ustrd>{reference}</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry>"#
            )
        })
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.02"><BkToCstmrStmt><Stmt>{entries}<Ntry><Amt Ccy="EUR">1.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts></Ntry></Stmt></BkToCstmrStmt></Document>"#
    )
}

// ── Wise ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/// What the Wise stand-in holds and has seen.
#[derive(Default)]
pub struct WiseState {
    /// Per balance currency: (entry, currency, amount, reference).
    pub credits: Vec<(String, String, String, String)>,
    /// How many times it refused a request for lack of a valid one-time token.
    pub sca_challenges: u32,
    /// How many statements it served after a valid challenge response.
    pub sca_passed: u32,
    /// The interval of every statement request, start and end.
    pub intervals: Vec<(String, String)>,
}

/// A running Wise stand-in.
#[derive(Clone)]
pub struct WiseBank {
    /// Its address.
    pub base: String,
    /// Its state, shared with the server task.
    pub state: Arc<Mutex<WiseState>>,
}

/// The API token the stand-in accepts.
pub const WISE_TOKEN: &str = "wise-test-token";
/// The profile id the stand-in serves.
pub const WISE_PROFILE: u64 = 12345;

impl WiseBank {
    /// A Wise stand-in on a free local port.
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(WiseState::default()));
        // The stand-in checks SCA signatures with the operator's public key, as Wise does with the uploaded one.
        let public = operator_key().public_pem();
        let s2 = state.clone();
        let app = Router::new()
            .route(
                "/2026Q4/profiles/{p}/balances",
                get(|Path(p): Path<u64>, h: HeaderMap, Query(q): Query<BTreeMap<String, String>>| async move {
                    if header(&h, "authorization").as_deref() != Some(&format!("Bearer {WISE_TOKEN}"))
                        || p != WISE_PROFILE
                        || q.get("types").map(String::as_str) != Some("STANDARD")
                    {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    axum::Json(json!([
                        { "id": 1, "currency": "EUR", "type": "STANDARD" },
                        { "id": 2, "currency": "GBP", "type": "STANDARD" },
                    ]))
                    .into_response()
                }),
            )
            .route(
                "/2026Q4/profiles/{p}/balance-statements/{b}/statement.xml",
                get(move |Path((_p, b)): Path<(u64, u64)>, h: HeaderMap, Query(q): Query<BTreeMap<String, String>>| {
                    let public = public.clone();
                    async move {
                        let mut s = s2.lock().unwrap();
                        if header(&h, "authorization").as_deref() != Some(&format!("Bearer {WISE_TOKEN}")) {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                        // The one-time token for this balance.
                        let ott = format!("ott-{b}");
                        let signed = header(&h, "x-signature").and_then(|v| STANDARD.decode(v).ok());
                        // The challenge is answered when the token comes back with a signature of it by the operator's key.
                        let ok = header(&h, "x-2fa-approval").as_deref() == Some(ott.as_str())
                            && signed.is_some_and(|sig| keys::rsa_sha256_valid(&public, ott.as_bytes(), &sig));
                        if !ok {
                            s.sca_challenges += 1;
                            // Not answered: refuse with the one-time token, as Wise does.
                            let mut r = StatusCode::FORBIDDEN.into_response();
                            r.headers_mut().insert("x-2fa-approval", HeaderValue::from_str(&ott).unwrap());
                            r.headers_mut().insert("x-2fa-approval-result", HeaderValue::from_static("REJECTED"));
                            return r;
                        }
                        s.sca_passed += 1;
                        let (Some(ccy), Some(start), Some(end)) =
                            (q.get("currency"), q.get("intervalStart"), q.get("intervalEnd"))
                        else {
                            return StatusCode::BAD_REQUEST.into_response();
                        };
                        s.intervals.push((start.clone(), end.clone()));
                        let mine: Vec<_> = s.credits.iter().filter(|c| &c.1 == ccy).cloned().collect();
                        let mut r = camt053(&mine).into_response();
                        r.headers_mut().insert("x-2fa-approval-result", HeaderValue::from_static("APPROVED"));
                        r
                    }
                }),
            );
        WiseBank { base: serve(app).await, state }
    }

    /// Add a credit that the next statement of its currency will contain.
    pub fn credit(&self, entry: &str, currency: &str, amount: &str, reference: &str) {
        self.state.lock().unwrap().credits.push((entry.into(), currency.into(), amount.into(), reference.into()));
    }
}

// ── bunq ─────────────────────────────────────────────────────────────────────────────────────────────────────────

/// What the bunq stand-in holds and has seen.
#[derive(Default)]
pub struct BunqState {
    /// The public key the client installed.
    pub client_key: Option<String>,
    /// How many installations it has seen.
    pub installations: u32,
    /// How many devices it has registered.
    pub devices: u32,
    /// How many sessions it has opened.
    pub sessions: u32,
    /// How many requests failed the signature or header checks.
    pub bad_signatures: u32,
    /// (id, amount, currency, description), any order.
    pub payments: Vec<(u64, String, String, String)>,
    /// Whether to sign answers with the wrong key, to check that the client rejects them.
    pub forge: bool,
}

/// A running bunq stand-in.
#[derive(Clone)]
pub struct BunqBank {
    pub base: String,
    pub state: Arc<Mutex<BunqState>>,
}

/// The API key the stand-in accepts.
pub const BUNQ_API_KEY: &str = "sandbox_test_api_key";

/// An answer signed with the bank's key (or with the wrong key when told to forge).
fn bunq_answer(s: &BunqState, status: StatusCode, v: Value) -> Response {
    let body = v.to_string();
    let sig = if s.forge {
        STANDARD.encode(operator_key().sign_sha256(body.as_bytes()).unwrap())
    } else {
        STANDARD.encode(bank_key().sign_sha256(body.as_bytes()).unwrap())
    };
    let mut r = (status, body).into_response();
    r.headers_mut().insert("x-bunq-server-signature", HeaderValue::from_str(&sig).unwrap());
    r.headers_mut().insert("content-type", HeaderValue::from_static("application/json"));
    r
}

/// Whether a request body carries a valid client signature and the headers bunq requires; counts the failures.
fn bunq_signed(s: &mut BunqState, h: &HeaderMap, body: &[u8]) -> bool {
    let ok = s.client_key.as_ref().is_some_and(|k| {
        header(h, "x-bunq-client-signature")
            .and_then(|v| STANDARD.decode(v).ok())
            .is_some_and(|sig| keys::rsa_sha256_valid(k, body, &sig))
    }) && header(h, "x-bunq-client-request-id").is_some()
        && header(h, "cache-control").as_deref() == Some("no-cache");
    if !ok {
        s.bad_signatures += 1;
    }
    ok
}

/// The installation call: stores the client's key and answers with a token and the server key.
async fn bunq_installation(State(b): State<BunqBank>, body: Bytes) -> Response {
    let mut s = b.state.lock().unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let Some(k) = v["client_public_key"].as_str() else { return StatusCode::BAD_REQUEST.into_response() };
    s.client_key = Some(k.to_string());
    s.installations += 1;
    let answer = json!({ "Response": [ { "Id": { "id": 1 } }, { "Token": { "id": 1, "token": "installation-token-1" } },
        { "ServerPublicKey": { "server_public_key": bank_key().public_pem() } } ] });
    bunq_answer(&s, StatusCode::OK, answer)
}

/// The device registration: needs the installation token, a signed body and the API key.
async fn bunq_device(State(b): State<BunqBank>, h: HeaderMap, body: Bytes) -> Response {
    let mut s = b.state.lock().unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if !bunq_signed(&mut s, &h, &body)
        || header(&h, "x-bunq-client-authentication").as_deref() != Some("installation-token-1")
        || v["secret"].as_str() != Some(BUNQ_API_KEY)
    {
        return bunq_answer(&s, StatusCode::UNAUTHORIZED, json!({ "Error": [{ "error_description": "refused" }] }));
    }
    s.devices += 1;
    bunq_answer(&s, StatusCode::OK, json!({ "Response": [{ "Id": { "id": 9 } }] }))
}

/// The session call: needs the installation token, a signed body, the API key and a registered device.
async fn bunq_session(State(b): State<BunqBank>, h: HeaderMap, body: Bytes) -> Response {
    let mut s = b.state.lock().unwrap();
    let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if !bunq_signed(&mut s, &h, &body)
        || header(&h, "x-bunq-client-authentication").as_deref() != Some("installation-token-1")
        || v["secret"].as_str() != Some(BUNQ_API_KEY)
        || s.devices == 0
    {
        return bunq_answer(&s, StatusCode::UNAUTHORIZED, json!({ "Error": [{ "error_description": "refused" }] }));
    }
    s.sessions += 1;
    bunq_answer(
        &s,
        StatusCode::OK,
        json!({ "Response": [ { "Id": { "id": 3 } }, { "Token": { "token": "session-token-1" } }, { "UserCompany": { "id": 42 } } ] }),
    )
}

/// The account list: one active account and one cancelled one.
async fn bunq_accounts(State(b): State<BunqBank>, Path(u): Path<u64>, h: HeaderMap) -> Response {
    let s = b.state.lock().unwrap();
    if u != 42 || header(&h, "x-bunq-client-authentication").as_deref() != Some("session-token-1") {
        return bunq_answer(&s, StatusCode::UNAUTHORIZED, json!({ "Error": [{ "error_description": "no session" }] }));
    }
    bunq_answer(
        &s,
        StatusCode::OK,
        json!({ "Response": [
            { "MonetaryAccountBank": { "id": 7, "currency": "EUR", "status": "ACTIVE" } },
            { "MonetaryAccountSavings": { "id": 8, "currency": "EUR", "status": "CANCELLED" } },
        ] }),
    )
}

/// The payments of the active account: those newer than the cursor, the oldest `count` of them, listed newest first.
async fn bunq_payments(
    State(b): State<BunqBank>,
    Path((u, a)): Path<(u64, u64)>,
    h: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    let s = b.state.lock().unwrap();
    if u != 42 || a != 7 || header(&h, "x-bunq-client-authentication").as_deref() != Some("session-token-1") {
        return bunq_answer(&s, StatusCode::UNAUTHORIZED, json!({ "Error": [{ "error_description": "no session" }] }));
    }
    let newer: u64 = q.get("newer_id").and_then(|n| n.parse().ok()).unwrap_or(0);
    let count: usize = q.get("count").and_then(|n| n.parse().ok()).unwrap_or(10);
    // Payments newer than the cursor.
    let mut list: Vec<_> = s.payments.iter().filter(|p| p.0 > newer).cloned().collect();
    // The oldest `count` newer than the cursor, listed newest first (as bunq lists).
    // Take the oldest `count` of them, as bunq does when paging forwards, then list them newest first.
    list.sort_by_key(|p| p.0);
    list.truncate(count);
    list.reverse();
    let items: Vec<Value> = list
        .iter()
        .map(|(id, amount, ccy, desc)| {
            json!({ "Payment": { "id": id, "created": "2026-11-17 10:00:00.000000", "monetary_account_id": 7,
                                  "amount": { "value": amount, "currency": ccy }, "description": desc, "type": "EBA_SCT" } })
        })
        .collect();
    bunq_answer(&s, StatusCode::OK, json!({ "Response": items, "Pagination": {} }))
}

impl BunqBank {
    /// A Revolut stand-in on a free local port, holding the given refresh token.
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(BunqState::default()));
        let b = BunqBank { base: String::new(), state };
        let app = Router::new()
            .route("/v1/installation", post(bunq_installation))
            .route("/v1/device-server", post(bunq_device))
            .route("/v1/session-server", post(bunq_session))
            .route("/v1/user/{u}/monetary-account", get(bunq_accounts))
            .route("/v1/user/{u}/monetary-account/{a}/payment", get(bunq_payments))
            .with_state(b.clone());
        BunqBank { base: format!("{}/v1", serve(app).await), state: b.state }
    }

    /// Add a payment that the account will list.
    pub fn pay(&self, id: u64, amount: &str, currency: &str, description: &str) {
        self.state.lock().unwrap().payments.push((id, amount.into(), currency.into(), description.into()));
    }

    /// Switch forged answer signatures on or off.
    pub fn forge(&self, on: bool) {
        self.state.lock().unwrap().forge = on;
    }
}

// ── Revolut ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// What the Revolut stand-in holds and has seen.
#[derive(Default)]
pub struct RevolutState {
    /// The refresh token currently valid.
    pub refresh_token: String,
    /// Whether a refresh replaces the refresh token, as Revolut may.
    pub rotate: bool,
    /// The access tokens issued so far.
    pub access: Vec<String>,
    /// How many token requests failed the client-assertion check.
    pub bad_assertions: u32,
    /// The transactions the list returns.
    pub transactions: Vec<Value>,
    /// The `from` of every transactions request.
    pub froms: Vec<String>,
}

/// A running Revolut stand-in.
#[derive(Clone)]
pub struct RevolutBank {
    pub base: String,
    pub state: Arc<Mutex<RevolutState>>,
}

/// The client id the stand-in accepts.
pub const REVOLUT_CLIENT: &str = "test-client-id";
/// The assertion issuer the stand-in accepts.
pub const REVOLUT_ISSUER: &str = "example.org";
/// The one-time authorisation code the stand-in accepts.
pub const REVOLUT_CODE: &str = "oa_sand_code_1";

/// Whether a client assertion is an RS256 token signed by the operator's key with the expected issuer, subject and audience, and not expired.
fn assertion_valid(jwt: &str) -> bool {
    // Three parts, the first being the fixed header.
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts[0] != URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#) {
        return false;
    }
    let Ok(sig) = URL_SAFE_NO_PAD.decode(parts[2]) else { return false };
    if !keys::rsa_sha256_valid(&operator_key().public_pem(), format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig) {
        return false;
    }
    let Some(claims) = URL_SAFE_NO_PAD.decode(parts[1]).ok().and_then(|c| serde_json::from_slice::<Value>(&c).ok())
    else {
        return false;
    };
    claims["iss"] == REVOLUT_ISSUER
        && claims["sub"] == REVOLUT_CLIENT
        && claims["aud"] == "https://revolut.com"
        && claims["exp"].as_i64().is_some_and(|e| e > time::OffsetDateTime::now_utc().unix_timestamp())
}

/// The token endpoint: checks the assertion, then exchanges the authorisation code once or refreshes with the current refresh token.
async fn revolut_token(State(b): State<RevolutBank>, body: Bytes) -> Response {
    let mut s = b.state.lock().unwrap();
    let f: BTreeMap<String, String> = url::form_urlencoded::parse(&body).into_owned().collect();
    // A form field by name.
    let get = |k: &str| f.get(k).map(String::as_str);
    if get("client_id") != Some(REVOLUT_CLIENT)
        || get("client_assertion_type") != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        || !get("client_assertion").is_some_and(assertion_valid)
    {
        s.bad_assertions += 1;
        return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": "invalid_client" }))).into_response();
    }
    // Exchange the code, or refresh; anything else is a bad grant.
    match get("grant_type") {
        Some("authorization_code") if get("code") == Some(REVOLUT_CODE) => {
            s.refresh_token = "oa_sand_refresh_1".into();
            axum::Json(json!({ "access_token": "oa_sand_access_0", "token_type": "bearer", "expires_in": 2399, "refresh_token": s.refresh_token })).into_response()
        }
        Some("refresh_token") if get("refresh_token") == Some(s.refresh_token.as_str()) => {
            let access = format!("oa_sand_access_{}", s.access.len() + 1);
            s.access.push(access.clone());
            let mut answer = json!({ "access_token": access, "token_type": "bearer", "expires_in": 2399 });
            // A rotating stand-in replaces the refresh token and says so.
            if s.rotate {
                s.refresh_token = format!("oa_sand_refresh_{}", s.access.len() + 1);
                answer["refresh_token"] = json!(s.refresh_token);
            }
            axum::Json(answer).into_response()
        }
        _ => (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({ "error": "invalid_grant", "error_description": "Incorrect refresh token" })),
        )
            .into_response(),
    }
}

/// The transactions list: needs an access token it issued.
async fn revolut_transactions(
    State(b): State<RevolutBank>,
    h: HeaderMap,
    Query(q): Query<BTreeMap<String, String>>,
) -> Response {
    let mut s = b.state.lock().unwrap();
    let ok = header(&h, "authorization")
        .and_then(|a| a.strip_prefix("Bearer ").map(String::from))
        .is_some_and(|t| s.access.contains(&t));
    if !ok {
        return (StatusCode::UNAUTHORIZED, axum::Json(json!({ "message": "unauthorised" }))).into_response();
    }
    s.froms.push(q.get("from").cloned().unwrap_or_default());
    axum::Json(Value::Array(s.transactions.clone())).into_response()
}

impl RevolutBank {
    /// A stand-in whose current refresh token is the given one.
    pub async fn start(refresh_token: &str) -> Self {
        let state = Arc::new(Mutex::new(RevolutState { refresh_token: refresh_token.into(), ..Default::default() }));
        let b = RevolutBank { base: String::new(), state };
        let app = Router::new()
            .route("/api/1.0/auth/token", post(revolut_token))
            .route("/api/1.0/transactions", get(revolut_transactions))
            .with_state(b.clone());
        RevolutBank { base: format!("{}/api/1.0", serve(app).await), state: b.state }
    }

    /// A completed incoming transfer (the reference as the payer typed it).
    pub fn incoming(&self, id: &str, amount: f64, currency: &str, reference: &str) {
        self.state.lock().unwrap().transactions.push(json!({
            "id": id, "type": "transfer", "state": "completed", "created_at": "2026-11-17T10:00:00.000Z",
            "completed_at": "2026-11-17T10:00:01.000Z", "reference": reference,
            "legs": [{ "leg_id": format!("{id}-leg"), "account_id": "acc-1", "amount": amount, "currency": currency, "description": "From A Payer" }],
        }));
    }

    /// Add any transaction.
    pub fn push(&self, tx: Value) {
        self.state.lock().unwrap().transactions.push(tx);
    }
}
