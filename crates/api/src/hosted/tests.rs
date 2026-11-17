//! The hosted service end to end, against a real PostgreSQL over TLS (`scripts/test-postgres.sh`): the switches fail
//! closed, an operator-issued invite, sign-up with a software passkey and with a Sui wallet key, CSRF, publishing,
//! what a tenant host serves (third-party pages off, the operator's own page, suspension within the cache time,
//! federation documents), the account-free report reaching the operator, a Chain Payments checkout paid by a signed
//! webhook (applied once), and the OpenAPI documents matching the route tables.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use tower::ServiceExt;
use url::Url;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use super::access::{AccessConfig, Admins, JwksSource, RoleSource};
use super::{App, HostedConfig, Shared};
use link_in_bio_store::Store;
use link_in_bio_store::config::{Access, DatabaseSettings};

const APP: &str = "https://app.example.link";
const ADMIN: &str = "https://admin.example.co.uk";
const ISS: &str = "https://team.cloudflareaccess.com";
const AUD: &str = "aud-tag";

async fn store() -> Option<Store> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
        eprintln!("SKIPPED: no TEST_DATABASE_URL");
        return None;
    };
    let admin = DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
    let name = format!("lib_hosted_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
    let pool = DatabaseSettings::parse(&url.replacen("/postgres?", &format!("/{name}?"), 1), false)
        .unwrap()
        .lazy_pool(6, Access::ReadWrite)
        .unwrap();
    let s = Store::new(pool);
    s.migrate().await.unwrap();
    Some(s)
}

fn config(extra: &[(&str, String)]) -> HostedConfig {
    let mut env: Vec<(String, String)> = vec![
        ("PAGES_DOMAIN".into(), "example.link".into()),
        ("APP_HOST".into(), "app.example.link".into()),
        ("TERMS_VERSION".into(), "2026-11".into()),
    ];
    env.extend(extra.iter().map(|(k, v)| (k.to_string(), v.clone())));
    HostedConfig::from_env(move |k| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())).unwrap()
}

fn app(store: Store, c: HostedConfig) -> Shared {
    let mut a = App::new(store, c, Duration::from_millis(200)).unwrap();
    a.access = Some(Admins::new(AccessConfig {
        issuer: ISS.into(),
        audience: AUD.into(),
        jwks: JwksSource::Static(super::jwt::testing::jwks("k1")),
        roles: RoleSource::Static(BTreeSet::from(["op-1".to_string()])),
        admin_origin: ADMIN.into(),
    }));
    Arc::new(a)
}

fn operator_token() -> String {
    let now = chrono::Utc::now().timestamp();
    super::jwt::testing::sign(
        &json!({ "alg": "RS256", "kid": "k1", "typ": "JWT" }),
        &json!({ "iss": ISS, "aud": [AUD], "sub": "op-1", "email": "op@example.org", "exp": now + 600, "nbf": now - 10 }),
    )
}

struct Resp {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
    fn cookie(&self) -> Option<String> {
        self.headers.get(header::SET_COOKIE)?.to_str().ok()?.split(';').next().map(String::from)
    }
}

async fn send(router: &Router, req: Request<Body>) -> Resp {
    let r = router.clone().oneshot(req).await.unwrap();
    let (p, b) = r.into_parts();
    Resp { status: p.status, headers: p.headers, body: b.collect().await.unwrap().to_bytes().to_vec() }
}

/// A request from the app (Origin + the CSRF header), with a session cookie when given.
fn call(method: &str, path: &str, body: Option<Value>, cookie: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "app.example.link")
        .header(header::ORIGIN, APP)
        .header("x-link-in-bio-request", "1")
        .header("cf-ipcountry", "GB");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    match body {
        Some(v) => b.header(header::CONTENT_TYPE, "application/json").body(Body::from(v.to_string())).unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

fn admin_call(method: &str, path: &str, body: Option<Value>) -> Request<Body> {
    let b = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ORIGIN, ADMIN)
        .header("x-link-in-bio-request", "1")
        .header("cf-access-jwt-assertion", operator_token());
    match body {
        Some(v) => b.header(header::CONTENT_TYPE, "application/json").body(Body::from(v.to_string())).unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

fn page_get(host: &str, path: &str) -> Request<Body> {
    Request::get(path).header(header::HOST, host).body(Body::empty()).unwrap()
}

/// What a Sui wallet does for an ed25519 key.
fn wallet_sign(seed: &[u8; 32], message: &[u8]) -> (String, String) {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let pk = kp.public_key().as_ref().to_vec();
    let address = access_gate_like_address(&pk);
    let digest = link_in_bio_auth_digest(message);
    let mut raw = vec![0u8];
    raw.extend_from_slice(kp.sign(&digest).as_ref());
    raw.extend_from_slice(&pk);
    (address, STANDARD.encode(raw))
}

fn access_gate_like_address(pk: &[u8]) -> String {
    access_gate_gateway_core::sig::derive_address(0, pk)
}

fn link_in_bio_auth_digest(message: &[u8]) -> [u8; 32] {
    access_gate_gateway_core::sig::signing_digest(message)
}

async fn signup_with_passkey(app_r: &Router, device: &mut SoftPasskey, handle: &str, invite: Option<&str>) -> Resp {
    let start = send(
        app_r,
        call(
            "POST",
            "/api/v1/signup/start",
            Some(json!({ "handle": handle, "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11",
                         "country": "GB", "invite": invite, "method": "passkey" })),
            None,
        ),
    )
    .await;
    assert_eq!(start.status, StatusCode::OK, "{}", start.text());
    let s = start.json();
    let cred = device
        .do_registration(Url::parse(APP).unwrap(), serde_json::from_value(s["options"].clone()).unwrap())
        .unwrap();
    send(
        app_r,
        call(
            "POST",
            "/api/v1/signup/finish",
            Some(json!({ "challenge": s["challenge"], "credential": cred, "passkeyName": "Test" })),
            None,
        ),
    )
    .await
}

#[tokio::test]
async fn switches_fail_closed() {
    let Some(s) = store().await else { return };
    let a = app(s, config(&[]));
    let r = super::app::router(a.clone());
    let i = send(&r, call("GET", "/api/v1/instance", None, None)).await.json();
    assert_eq!((i["signup"].as_str(), i["thirdPartyPages"].as_bool()), (Some("closed"), Some(false)));
    assert_eq!(i["billingProviders"], json!(["manual"]));
    let start = send(&r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "x", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "method": "passkey" })), None)).await;
    assert_eq!(start.status, StatusCode::FORBIDDEN, "sign-up is closed by default");
    // CSRF: no Origin, a foreign Origin, or no header.
    let no_origin =
        Request::post("/api/v1/logout").header(header::HOST, "app.example.link").body(Body::empty()).unwrap();
    assert_eq!(send(&r, no_origin).await.status, StatusCode::FORBIDDEN);
    let foreign = Request::post("/api/v1/logout")
        .header(header::ORIGIN, "https://alice.example.link")
        .header("x-link-in-bio-request", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&r, foreign).await.status, StatusCode::FORBIDDEN);
    let unmarked = Request::post("/api/v1/logout").header(header::ORIGIN, APP).body(Body::empty()).unwrap();
    assert_eq!(send(&r, unmarked).await.status, StatusCode::FORBIDDEN);
    // The console refuses without an Access token, and without the role.
    let admin = super::admin::router(a);
    let bare = Request::get("/api/v1/admin/overview").body(Body::empty()).unwrap();
    assert_eq!(send(&admin, bare).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&admin, admin_call("GET", "/api/v1/admin/overview", None)).await.status, StatusCode::OK);
    // An unknown method is configured nowhere.
    assert!(
        HostedConfig::from_env(|k| match k {
            "PAGES_DOMAIN" => Some("example.link".into()),
            "APP_HOST" => Some("app.example.link".into()),
            "BILLING_PROVIDERS" => Some("stripe".into()),
            _ => None,
        })
        .is_err()
    );
}

#[tokio::test]
async fn invite_signup_publish_serve_suspend_report() {
    let Some(s) = store().await else { return };
    let a = app(s.clone(), config(&[("SIGNUP_MODE", "invite".into())]));
    let app_r = super::app::router(a.clone());
    let admin = super::admin::router(a.clone());
    let pages = super::pages::router(a.clone());

    // Without an invite, invite mode refuses.
    let mut device = SoftPasskey::new(true);
    let r = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "alice", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "method": "passkey" })), None)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    // Under 18 or without the terms: refused.
    let r = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "alice", "ageConfirmed": false, "termsAccepted": true, "termsVersion": "2026-11", "invite": "x", "method": "passkey" })), None)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // The operator issues a code (shown once) and alice signs up with it and a passkey.
    let issued =
        send(&admin, admin_call("POST", "/api/v1/admin/invites", Some(json!({ "count": 1, "note": "first" })))).await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.text());
    let code = issued.json()["codes"][0].as_str().unwrap().to_string();
    let done = signup_with_passkey(&app_r, &mut device, "alice", Some(&code)).await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(done.json()["recoveryCodes"].as_array().unwrap().len(), 10);
    assert_eq!(done.json()["account"]["free"], true);
    let cookie = done.cookie().unwrap();
    assert!(done.headers[header::SET_COOKIE].to_str().unwrap().contains("__Host-lib_session="));
    // The code was single-use.
    let again = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "bobby", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "invite": code, "method": "passkey" })), None)).await;
    let finish = if again.status == StatusCode::OK {
        let s2 = again.json();
        let mut d2 = SoftPasskey::new(true);
        let c2 = d2
            .do_registration(Url::parse(APP).unwrap(), serde_json::from_value(s2["options"].clone()).unwrap())
            .unwrap();
        send(
            &app_r,
            call(
                "POST",
                "/api/v1/signup/finish",
                Some(json!({ "challenge": s2["challenge"], "credential": c2 })),
                None,
            ),
        )
        .await
        .status
    } else {
        again.status
    };
    assert_eq!(finish, StatusCode::UNPROCESSABLE_ENTITY);
    // A look-alike of a reserved handle is refused.
    let r = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "adrnin", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "invite": "0000-0000-0000-0000", "method": "passkey" })), None)).await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);

    // Sign in again with the passkey, by handle.
    let st = send(&app_r, call("POST", "/api/v1/login/passkey/start", Some(json!({ "handle": "alice" })), None))
        .await
        .json();
    let assertion = device
        .do_authentication(Url::parse(APP).unwrap(), serde_json::from_value(st["options"].clone()).unwrap())
        .unwrap();
    let signed_in = send(
        &app_r,
        call(
            "POST",
            "/api/v1/login/passkey/finish",
            Some(json!({ "challenge": st["challenge"], "credential": assertion })),
            None,
        ),
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.text());

    // Edit and publish.
    let doc = json!({ "schema": 1, "identity": { "displayName": "Alice", "handle": "alice", "bio": "Hello" },
        "items": [ { "kind": "link", "id": "gh", "title": "GitHub", "url": "https://github.com/alice", "identity": true },
                   { "kind": "link", "id": "short", "title": "Short", "url": "https://bit.ly/abc" } ] });
    let saved = send(&app_r, call("PUT", "/api/v1/page", Some(doc.clone()), Some(&cookie))).await;
    assert_eq!(saved.status, StatusCode::OK, "{}", saved.text());
    let mut wrong = doc.clone();
    wrong["identity"]["handle"] = json!("mallory");
    assert_eq!(
        send(&app_r, call("PUT", "/api/v1/page", Some(wrong), Some(&cookie))).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let preview = send(&app_r, call("GET", "/api/v1/page/preview", None, Some(&cookie))).await;
    assert_eq!(preview.status, StatusCode::OK);
    assert!(preview.text().contains("Alice"));
    assert!(
        preview.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().contains(&format!("frame-ancestors {APP}"))
    );
    let published = send(&app_r, call("POST", "/api/v1/page/publish", None, Some(&cookie))).await;
    assert_eq!(published.status, StatusCode::OK, "{}", published.text());
    assert_eq!(published.json()["hidden"].as_array().unwrap().len(), 1, "the shortener is hidden");
    assert_eq!(published.json()["online"], false, "third-party pages are off");

    // Third-party pages off: alice's host is a 404.
    assert_eq!(send(&pages, page_get("alice.example.link", "/")).await.status, StatusCode::NOT_FOUND);
    // The operator marks alice as one of their own accounts: served (with federation documents).
    let id = s.account_by_handle("alice").await.unwrap().unwrap().id;
    assert_eq!(
        send(
            &admin,
            admin_call(
                "PUT",
                &format!("/api/v1/admin/accounts/{id}/flags"),
                Some(json!({ "operator": true, "free": true, "maySharInvites": true }))
            )
        )
        .await
        .status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown field"
    );
    assert_eq!(
        send(
            &admin,
            admin_call(
                "PUT",
                &format!("/api/v1/admin/accounts/{id}/flags"),
                Some(json!({ "operator": true, "free": true, "mayShareInvites": true }))
            )
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    let page = send(&pages, page_get("alice.example.link", "/")).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    let html = page.text();
    assert!(html.contains("https://github.com/alice") && !html.contains("bit.ly"));
    assert!(html.contains("https://app.example.link/report?page=alice"), "every tenant page links to the report form");
    assert!(page.headers.get(header::SET_COOKIE).is_none());
    assert!(page.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().starts_with("default-src 'none'"));
    assert_eq!(
        send(&pages, page_get("alice.example.link", "/.well-known/webfinger?resource=acct:alice@alice.example.link"))
            .await
            .status,
        StatusCode::OK
    );
    let actor = send(&pages, page_get("alice.example.link", "/actor")).await.json();
    assert_eq!(actor["type"], "Person");
    assert!(send(&pages, page_get("alice.example.link", "/links.json")).await.text().contains("github.com/alice"));
    assert_eq!(send(&pages, page_get("nobody.example.link", "/")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        send(&pages, page_get("example.link", "/")).await.status,
        StatusCode::NOT_FOUND,
        "the apex is the operator's static page, not here"
    );

    // A report without an account reaches the operator's queue.
    let rep = send(&app_r, call("POST", "/api/v1/reports", Some(json!({ "page": "alice", "url": "https://github.com/alice", "reason": "impersonation", "details": "Not the real Alice." })), None)).await;
    assert_eq!(rep.status, StatusCode::CREATED, "{}", rep.text());
    let queue = send(&admin, admin_call("GET", "/api/v1/admin/reports", None)).await.json();
    let report_id = queue["reports"][0]["id"].as_str().unwrap().to_string();

    // Suspension shows within one cache time (200 ms here); the statement of reasons reaches the account.
    let sus = send(&admin, admin_call("POST", &format!("/api/v1/admin/accounts/{id}/suspend"), Some(json!({ "kind": "policy", "reason": "impersonation", "report": report_id, "statement": "The page impersonated someone." })))).await;
    assert_eq!(sus.status, StatusCode::NO_CONTENT, "{}", sus.text());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(send(&pages, page_get("alice.example.link", "/")).await.status, StatusCode::GONE);
    assert_eq!(
        send(&app_r, call("GET", "/api/v1/me", None, Some(&cookie))).await.status,
        StatusCode::UNAUTHORIZED,
        "suspension ends sessions"
    );
    assert_eq!(s.statements_for(id).await.unwrap().len(), 1);
    // Legal: 451.
    send(&admin, admin_call("POST", &format!("/api/v1/admin/accounts/{id}/unsuspend"), None)).await;
    send(
        &admin,
        admin_call(
            "POST",
            &format!("/api/v1/admin/accounts/{id}/suspend"),
            Some(json!({ "kind": "legal", "reason": "court order", "statement": "Withheld on a court order." })),
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        send(&pages, page_get("alice.example.link", "/")).await.status,
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
    );
    let audit = send(&admin, admin_call("GET", &format!("/api/v1/admin/audit?subject={id}"), None)).await.json();
    assert!(
        audit["entries"].as_array().unwrap().iter().any(|e| e["action"] == "suspend" && e["actor"] == "operator:op-1")
    );
}

#[tokio::test]
async fn wallet_signup_recovery_and_chain_payments_checkout() {
    let Some(s) = store().await else { return };
    // A stand-in for the Chain Payments merchant API that signs its webhooks with a known key.
    let kp = Ed25519KeyPair::from_seed_unchecked(&[5u8; 32]).unwrap();
    let mock = axum::Router::new().route(
        "/v1/merchant/sessions",
        axum::routing::post(|axum::Json(b): axum::Json<Value>| async move {
            assert_eq!(b["units"], 3);
            (StatusCode::CREATED, axum::Json(json!({ "id": "ab".repeat(16) })))
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, mock).await.unwrap() });
    let dir = std::env::temp_dir().join(format!("lib-hosted-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cp.key"), "cpk_test_000000000000000000000000000000").unwrap();
    let a = app(
        s.clone(),
        config(&[
            ("SIGNUP_MODE", "open".into()),
            ("BILLING_PROVIDERS", "chain-payments".into()),
            ("CHAIN_PAYMENTS_MERCHANT_API", base.clone()),
            ("CHAIN_PAYMENTS_PUBLIC_API", base.clone()),
            ("CHAIN_PAYMENTS_ORIGIN", "https://chain-payments.example.dev".into()),
            ("CHAIN_PAYMENTS_KEY_FILE", dir.join("cp.key").display().to_string()),
            ("CHAIN_PAYMENTS_METHODS", "sui-testnet:SUI=SUI".into()),
            ("CHAIN_PAYMENTS_WEBHOOK_KEY", hex::encode(kp.public_key().as_ref())),
        ]),
    );
    let app_r = super::app::router(a.clone());
    let internal = super::internal::router(a.clone());

    // Sign up with a wallet: the message is signed, not a transaction.
    let seed = [9u8; 32];
    let (address, _) = wallet_sign(&seed, b"");
    let st = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "carol", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "country": "GB", "method": "sui-wallet", "address": address })), None)).await;
    assert_eq!(st.status, StatusCode::OK, "{}", st.text());
    let msg = st.json()["message"].as_str().unwrap().to_string();
    assert!(msg.contains("Chain ID: sui:testnet"));
    let (_, wrong_sig) = wallet_sign(&[1u8; 32], msg.as_bytes());
    let bad = send(
        &app_r,
        call(
            "POST",
            "/api/v1/signup/finish",
            Some(json!({ "challenge": st.json()["challenge"], "signature": wrong_sig })),
            None,
        ),
    )
    .await;
    assert_eq!(bad.status, StatusCode::UNPROCESSABLE_ENTITY);
    // The challenge was used up by the failed attempt; start again and sign properly.
    let st = send(&app_r, call("POST", "/api/v1/signup/start", Some(json!({ "handle": "carol", "ageConfirmed": true, "termsAccepted": true, "termsVersion": "2026-11", "country": "GB", "method": "sui-wallet", "address": address })), None)).await.json();
    let (_, sig) = wallet_sign(&seed, st["message"].as_str().unwrap().as_bytes());
    let done = send(
        &app_r,
        call("POST", "/api/v1/signup/finish", Some(json!({ "challenge": st["challenge"], "signature": sig })), None),
    )
    .await;
    assert_eq!(done.status, StatusCode::OK, "{}", done.text());
    assert_eq!(done.json()["account"]["free"], false, "open sign-up without an invite: a paid account");
    let codes = done.json()["recoveryCodes"].clone();
    let cookie = done.cookie().unwrap();

    // Not paid: publishing is refused.
    assert_eq!(
        send(&app_r, call("POST", "/api/v1/page/publish", None, Some(&cookie))).await.status,
        StatusCode::CONFLICT
    );

    // Wallet sign-in, and a recovery code (once).
    let w = send(&app_r, call("POST", "/api/v1/login/wallet/start", Some(json!({ "address": address })), None))
        .await
        .json();
    let (_, sig) = wallet_sign(&seed, w["message"].as_str().unwrap().as_bytes());
    assert_eq!(
        send(
            &app_r,
            call(
                "POST",
                "/api/v1/login/wallet/finish",
                Some(json!({ "challenge": w["challenge"], "signature": sig })),
                None
            )
        )
        .await
        .status,
        StatusCode::OK
    );
    let code = codes[0].as_str().unwrap().to_uppercase();
    assert_eq!(
        send(&app_r, call("POST", "/api/v1/login/recovery", Some(json!({ "handle": "carol", "code": code })), None))
            .await
            .status,
        StatusCode::OK
    );
    assert_eq!(
        send(&app_r, call("POST", "/api/v1/login/recovery", Some(json!({ "handle": "carol", "code": code })), None))
            .await
            .status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    // Billing: GB declared and GB request → Chain Payments offered from 1 month.
    let b = send(&app_r, call("GET", "/api/v1/billing", None, Some(&cookie))).await.json();
    assert_eq!(b["offers"][0]["id"], "chain-payments:sui-testnet:SUI");
    assert_eq!(b["offers"][0]["minMonths"], 1);
    // From another country (the request says FR): not offered.
    let fr = Request::get("/api/v1/billing")
        .header(header::COOKIE, &cookie)
        .header("cf-ipcountry", "FR")
        .body(Body::empty())
        .unwrap();
    assert!(send(&app_r, fr).await.json()["offers"].as_array().unwrap().is_empty());
    let co = send(
        &app_r,
        call(
            "POST",
            "/api/v1/billing/checkouts",
            Some(json!({ "method": "chain-payments:sui-testnet:SUI", "months": 3 })),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(co.status, StatusCode::OK, "{}", co.text());
    assert_eq!(co.json()["client"]["baseUrl"], "https://chain-payments.example.dev");
    assert_eq!(co.json()["amountPence"], 900);
    let checkout = co.json()["checkout"].as_str().unwrap().to_string();

    // The signed webhook pays it; a second delivery changes nothing; a forged one is refused.
    let body = serde_json::to_vec(&json!({ "id": uuid::Uuid::new_v4().to_string(), "event": "session.paid",
        "data": { "sessionId": "ab".repeat(16), "units": 3, "amountPence": 900, "method": "sui-testnet:SUI", "digest": "D1", "payer": "0x1" } })).unwrap();
    let t = chrono::Utc::now().timestamp();
    let mut m = format!("{t}.").into_bytes();
    m.extend_from_slice(&body);
    let sig = format!("t={t},ed25519={}", STANDARD.encode(kp.sign(&m)));
    let hook = |sig: String, body: Vec<u8>| {
        Request::post("/internal/v1/payments/chain-payments")
            .header("chain-payments-signature", sig)
            .body(Body::from(body))
            .unwrap()
    };
    assert_eq!(send(&internal, hook(sig.clone(), body.clone())).await.status, StatusCode::NO_CONTENT);
    let after = s.account_by_handle("carol").await.unwrap().unwrap().paid_until.unwrap();
    assert_eq!(send(&internal, hook(sig, body.clone())).await.status, StatusCode::NO_CONTENT);
    assert_eq!(s.account_by_handle("carol").await.unwrap().unwrap().paid_until.unwrap(), after, "applied once");
    assert_eq!(send(&internal, hook(format!("t={t},ed25519=AAAA"), body)).await.status, StatusCode::BAD_REQUEST);
    let state =
        send(&app_r, call("GET", &format!("/api/v1/billing/checkouts/{checkout}"), None, Some(&cookie))).await.json();
    assert_eq!(state["status"], "paid");
    let events = s.billing_events(s.account_by_handle("carol").await.unwrap().unwrap().id).await.unwrap();
    assert_eq!(events.len(), 1);
    // Now publishing works.
    assert_eq!(send(&app_r, call("POST", "/api/v1/page/publish", None, Some(&cookie))).await.status, StatusCode::OK);
    // Metrics answer on the internal port.
    let metrics = send(&internal, Request::get("/metrics").body(Body::empty()).unwrap()).await.text();
    assert!(metrics.contains("link_in_bio_payments_total 1"));
    assert!(metrics.contains("link_in_bio_accounts_paid 1"));
    std::fs::remove_dir_all(dir).ok();
}

#[tokio::test]
async fn every_route_in_the_tables_exists_and_the_openapi_documents_match() {
    let Some(s) = store().await else { return };
    let a = app(s, config(&[]));
    let app_r = super::app::router(a.clone());
    let admin = super::admin::router(a);
    let concrete = |p: &str| {
        p.replace("{id}", "00000000-0000-0000-0000-000000000000")
            .replace("{address}", "0x1")
            .replace("{version}", "1")
            .replace("{hostname}", "example.org")
            .replace("{file}", "x.png")
    };
    for r in super::routes::APP_ROUTES {
        let resp =
            send(&app_r, call(&r.method.as_str().to_uppercase(), &concrete(r.path), Some(json!({})), None)).await;
        assert_ne!(resp.json()["code"], "no_route", "{} {}", r.method.as_str(), r.path);
    }
    for r in super::routes::ADMIN_ROUTES {
        let resp =
            send(&admin, admin_call(&r.method.as_str().to_uppercase(), &concrete(r.path), Some(json!({})))).await;
        assert_ne!(resp.json()["code"], "no_route", "{} {}", r.method.as_str(), r.path);
    }
    assert_eq!(send(&app_r, call("GET", "/api/v1/nope", None, None)).await.json()["code"], "no_route");

    for (file, doc) in [("app.json", super::openapi::app_document()), ("admin.json", super::openapi::admin_document())]
    {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../openapi").join(file);
        let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
        if std::env::var("UPDATE_OPENAPI").as_deref() == Ok("1") {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &text).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(committed, text, "openapi/{file} is out of date: UPDATE_OPENAPI=1 cargo test -p link-in-bio-api");
    }
}

#[tokio::test]
async fn bank_transfer_paid_by_an_imported_statement() {
    let Some(s) = store().await else { return };
    let a = app(
        s.clone(),
        config(&[
            ("BILLING_PROVIDERS", "bank-transfer".into()),
            ("BANK_TRANSFER_SCHEME", "faster-payments".into()),
            ("BANK_TRANSFER_PAYEE", "Example Ltd".into()),
            ("BANK_TRANSFER_SORT_CODE", "12-34-56".into()),
            ("BANK_TRANSFER_ACCOUNT_NUMBER", "12345678".into()),
        ]),
    );
    let app_r = super::app::router(a.clone());
    let admin = super::admin::router(a.clone());
    // An operator account (sign-up is closed) with a session.
    let id = uuid::Uuid::new_v4();
    s.create_account(
        &link_in_bio_store::NewAccount {
            id,
            handle: "dora",
            handle_skeleton: "dora",
            terms_version: "2026-11",
            country_declared: Some("GB"),
            billing_ref: "ref-dora-0000000001",
            operator: false,
            draft: r#"{"schema":1,"identity":{"displayName":"Dora","handle":"dora"},"items":[]}"#,
            invite_hash: None,
        },
        chrono::Utc::now(),
    )
    .await
    .unwrap();
    let (value, hash) = link_in_bio_auth::session::new_token();
    s.create_session(&hash, id, chrono::Utc::now() + chrono::Duration::days(1)).await.unwrap();
    let cookie = format!("{}={value}", link_in_bio_auth::session::COOKIE);

    let b = send(&app_r, call("GET", "/api/v1/billing", None, Some(&cookie))).await.json();
    assert_eq!(b["offers"][0]["id"], "bank-transfer:faster-payments");
    let co = send(
        &app_r,
        call(
            "POST",
            "/api/v1/billing/checkouts",
            Some(json!({ "method": "bank-transfer:faster-payments", "months": 2 })),
            Some(&cookie),
        ),
    )
    .await;
    assert_eq!(co.status, StatusCode::OK, "{}", co.text());
    let client = co.json()["client"].clone();
    assert_eq!((client["kind"].as_str(), client["amount"].as_str()), (Some("bank-transfer"), Some("6.00")));
    let reference = client["reference"].as_str().unwrap().to_string();

    let statement = |amount: &str| {
        format!(
            r#"<Document><BkToCstmrDbtCdtNtfctn><Ntfctn><Ntry><Amt Ccy="GBP">{amount}</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts><AcctSvcrRef>B{amount}</AcctSvcrRef>
            <NtryDtls><TxDtls><RmtInf><Ustrd>{reference}</Ustrd></RmtInf></TxDtls></NtryDtls></Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn></Document>"#
        )
    };
    let post = |xml: String| {
        Request::post("/api/v1/admin/bank-statements")
            .header(header::ORIGIN, ADMIN)
            .header("x-link-in-bio-request", "1")
            .header("cf-access-jwt-assertion", operator_token())
            .body(Body::from(xml))
            .unwrap()
    };
    let short = send(&admin, post(statement("5.00"))).await.json();
    assert_eq!(short["short"].as_array().unwrap().len(), 1, "an underpayment is reported, not applied");
    assert!(s.account(id).await.unwrap().unwrap().paid_until.is_none());
    let ok = send(&admin, post(statement("6.00"))).await.json();
    assert_eq!(ok["paid"].as_array().unwrap().len(), 1, "{ok}");
    let until = s.account(id).await.unwrap().unwrap().paid_until.unwrap();
    send(&admin, post(statement("6.00"))).await;
    assert_eq!(
        s.account(id).await.unwrap().unwrap().paid_until.unwrap(),
        until,
        "a statement imported twice pays once"
    );

    // The public webhook route takes only the internet-facing providers, without the app's CSRF rule.
    let hook = |p: &str| Request::post(format!("/api/v1/webhooks/{p}")).body(Body::from("{}")).unwrap();
    assert_eq!(send(&app_r, hook("chain-payments")).await.status, StatusCode::NOT_FOUND);
    assert_eq!(send(&app_r, hook("square")).await.status, StatusCode::NOT_FOUND, "square is not switched on here");
}
