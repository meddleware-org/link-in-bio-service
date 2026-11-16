//! The account API on the app host (`/api/v1/…`), for the Link in Bio app. Every state-changing request passes the
//! CSRF rule (`Origin` is the app origin and `X-Link-In-Bio-Request` is set); signed-in requests carry the
//! `__Host-` session cookie. Nothing here is reachable from a tenant page host.

use std::collections::BTreeMap;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use chrono::Duration;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use link_in_bio_auth::passkey::{LoginState, Passkeys};
use link_in_bio_auth::{recovery, session, wallet};
use link_in_bio_billing::{CheckoutRequest, Evidence, months_ahead};
use link_in_bio_core::assets::Bundle;
use link_in_bio_core::limits::{handle_skeleton, limits_json, looks_reserved};
use link_in_bio_core::manifest::check_handle;
use link_in_bio_core::{Issue, Manifest, Owner, ParseOptions};
use link_in_bio_store::{Account, AssetRow, Checkout, CreateError, NewAccount, sha256};

use super::error::{ApiError, ApiResult};
use super::metrics::Metrics;
use super::{Shared, SignupMode, now};
use crate::site::Site;

const CHALLENGE_TTL: Duration = Duration::minutes(5);

// ── plumbing ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// CSRF on every state-changing request, and `no-store` on every answer.
async fn guard(State(app): State<Shared>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
        let marked = req.headers().contains_key(session::CSRF_HEADER);
        if let Err(e) = session::check_csrf(origin, marked, &app.config.app_origin) {
            return ApiError::Forbidden(match e {
                session::CsrfError::Origin => "the request did not come from the app",
                session::CsrfError::Header => "the request is missing its app header",
            })
            .into_response();
        }
    }
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(session::from_cookie_header)
}

/// The signed-in account (an active one), or 401.
async fn account(app: &Shared, headers: &HeaderMap) -> ApiResult<Account> {
    let value = cookie_value(headers).ok_or(ApiError::Unauthorized)?;
    let id = app
        .store
        .session_account(&session::hash(value), now(), session::IDLE, session::ABSOLUTE)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    app.store.account(id).await?.ok_or(ApiError::Unauthorized)
}

/// Starts a session: returns the `Set-Cookie` value.
async fn start_session(app: &Shared, account: Uuid) -> ApiResult<HeaderValue> {
    let (value, hash) = session::new_token();
    app.store.create_session(&hash, account, now() + session::IDLE).await?;
    HeaderValue::from_str(&session::set_cookie(Some(&value), session::IDLE.num_seconds()))
        .map_err(|_| ApiError::Internal)
}

fn with_cookie(cookie: HeaderValue, body: Value) -> Response {
    let mut r = Json(body).into_response();
    r.headers_mut().insert(header::SET_COOKIE, cookie);
    r
}

fn country(v: Option<&str>) -> ApiResult<Option<String>> {
    match v.map(|c| c.trim().to_ascii_uppercase()) {
        None => Ok(None),
        Some(c) if c.is_empty() => Ok(None),
        Some(c) if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) => Ok(Some(c)),
        Some(_) => Err(ApiError::BadRequest("country must be a two-letter ISO 3166 code".into())),
    }
}

/// The request's country, as the edge reports it (`CF-IPCountry`).
fn request_country(headers: &HeaderMap) -> Option<String> {
    headers
        .get("cf-ipcountry")
        .and_then(|v| v.to_str().ok())
        .map(|c| c.trim().to_ascii_uppercase())
        .filter(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_alphanumeric()))
}

fn page_url(app: &Shared, handle: &str) -> String {
    format!("https://{handle}.{}/", app.config.pages_domain)
}

fn account_json(app: &Shared, a: &Account) -> Value {
    let n = now();
    json!({
        "id": a.id, "handle": a.handle, "status": a.status, "free": a.free, "paidUntil": a.paid_until,
        "entitled": a.entitled(n, Duration::days(app.config.grace_days)), "country": a.country_declared,
        "createdAt": a.created_at, "pageUrl": page_url(app, &a.handle), "termsVersion": a.terms_version,
        "suspension": (a.status == "suspended").then(|| json!({ "kind": a.suspension_kind, "until": a.suspended_until })),
    })
}

/// The first document of a new page.
fn starter_manifest(handle: &str) -> String {
    json!({ "schema": 1, "identity": { "displayName": handle, "handle": handle }, "items": [] }).to_string()
}

// ── instance ─────────────────────────────────────────────────────────────────────────────────────────────────────

async fn instance(State(app): State<Shared>) -> Json<Value> {
    let c = &app.config;
    Json(json!({
        "product": c.product_name,
        "version": env!("CARGO_PKG_VERSION"),
        "appHost": c.app_host,
        "pagesDomain": c.pages_domain,
        "signup": if c.signup_open_to_public() { serde_json::to_value(c.signup).unwrap_or_default() } else { json!("closed") },
        "thirdPartyPages": c.third_party_pages,
        "termsVersion": c.terms_version,
        "minimumAge": 18,
        "pricePence": c.price_pence,
        "currency": "GBP",
        "billingProviders": c.billing_providers,
        "customDomains": c.custom_hostname_cap > 0,
        "federation": c.federation,
        "authenticators": ["passkey", "sui-wallet", "recovery-code"],
        "suiNetwork": c.sui_network,
    }))
}

async fn limits() -> Json<Value> {
    Json(limits_json())
}

// ── sign-up ──────────────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignupStart {
    handle: String,
    age_confirmed: bool,
    terms_accepted: bool,
    terms_version: String,
    country: Option<String>,
    invite: Option<String>,
    method: String,
    address: Option<String>,
}

fn invite_hash(code: &str) -> Option<Vec<u8>> {
    recovery::normalise(code).map(|c| recovery::hash(&c))
}

async fn signup_start(State(app): State<Shared>, Json(b): Json<SignupStart>) -> ApiResult<Json<Value>> {
    let c = &app.config;
    if !c.signup_open_to_public() {
        return Err(ApiError::Forbidden("sign-up is closed"));
    }
    if !b.age_confirmed {
        return Err(ApiError::Unprocessable("You must be 18 or over to have an account.".into()));
    }
    if !b.terms_accepted || b.terms_version != c.terms_version {
        return Err(ApiError::Unprocessable("Accept the current terms to continue.".into()));
    }
    let invite = match (c.signup, b.invite.as_deref()) {
        (SignupMode::Invite, None) => {
            return Err(ApiError::Unprocessable("An invite code is needed to sign up.".into()));
        }
        (_, Some(code)) => {
            Some(invite_hash(code).ok_or_else(|| ApiError::Unprocessable("That invite code is not valid.".into()))?)
        }
        (_, None) => None,
    };
    let handle = check_handle(&b.handle, true).map_err(|(_, m)| ApiError::Unprocessable(m))?;
    if looks_reserved(&handle) {
        return Err(ApiError::Unprocessable("This handle is reserved. Choose another.".into()));
    }
    let skeleton = handle_skeleton(&handle);
    if !app.store.handle_available(&handle, &skeleton).await? {
        return Err(ApiError::Conflict("That handle is taken or too close to one that exists.".into()));
    }
    let id = Uuid::new_v4();
    let pending = json!({
        "id": id, "handle": handle, "skeleton": skeleton, "country": country(b.country.as_deref())?,
        "invite": invite.map(hex::encode), "terms": c.terms_version,
    });
    let challenge = link_in_bio_auth::random_hex(16);
    let n = now();
    match b.method.as_str() {
        "passkey" => {
            let (options, state) = app.passkeys.start_register(id, &handle, &[]).map_err(|_| ApiError::Internal)?;
            app.store
                .put_challenge(
                    &challenge,
                    "passkey-register",
                    None,
                    &json!({ "signup": pending, "state": state }),
                    n + CHALLENGE_TTL,
                )
                .await?;
            Ok(Json(json!({ "challenge": challenge, "options": options })))
        }
        "sui-wallet" => {
            let address = b.address.as_deref().ok_or_else(|| ApiError::BadRequest("address is required".into()))?;
            let w = wallet::Challenge::new(
                &c.app_host,
                &c.app_origin,
                &c.sui_network,
                address,
                &format!("Create my {} account.", c.product_name),
                n,
            )
            .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
            if app.store.wallet_owner(&w.address).await?.is_some() {
                return Err(ApiError::Conflict("That wallet already signs in to an account.".into()));
            }
            let message = w.message();
            app.store
                .put_challenge(
                    &challenge,
                    "wallet-link",
                    None,
                    &json!({ "signup": pending, "wallet": w }),
                    w.expires_at,
                )
                .await?;
            Ok(Json(json!({ "challenge": challenge, "message": message })))
        }
        _ => Err(ApiError::BadRequest("method must be passkey or sui-wallet".into())),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignupFinish {
    challenge: String,
    credential: Option<Value>,
    signature: Option<String>,
    passkey_name: Option<String>,
}

async fn signup_finish(State(app): State<Shared>, Json(b): Json<SignupFinish>) -> ApiResult<Response> {
    let n = now();
    let (kind, taken) = match (&b.credential, &b.signature) {
        (Some(_), None) => ("passkey-register", app.store.take_challenge(&b.challenge, "passkey-register", n).await?),
        (None, Some(_)) => ("wallet-link", app.store.take_challenge(&b.challenge, "wallet-link", n).await?),
        _ => return Err(ApiError::BadRequest("send either a credential or a signature".into())),
    };
    let Some((None, state)) = taken else {
        return Err(ApiError::Unprocessable("The sign-up expired; start again.".into()));
    };
    let p = &state["signup"];
    let id: Uuid = serde_json::from_value(p["id"].clone()).map_err(|_| ApiError::Internal)?;
    let handle = p["handle"].as_str().ok_or(ApiError::Internal)?;
    // Verify the sign-in method before anything is created.
    let method: (Option<(Vec<u8>, Value)>, Option<String>) = if kind == "passkey-register" {
        let reg = app
            .passkeys
            .finish_register(b.credential.as_ref().ok_or(ApiError::Internal)?, &state["state"])
            .map_err(|_| ApiError::Unprocessable("The passkey could not be verified.".into()))?;
        (Some(reg), None)
    } else {
        let w: wallet::Challenge = serde_json::from_value(state["wallet"].clone()).map_err(|_| ApiError::Internal)?;
        w.verify(b.signature.as_deref().unwrap_or(""), n).map_err(|e| ApiError::Unprocessable(e.to_string()))?;
        (None, Some(w.address))
    };
    let invite = p["invite"].as_str().and_then(|h| hex::decode(h).ok());
    let billing_ref = link_in_bio_auth::random_hex(16);
    let draft = starter_manifest(handle);
    let created = app
        .store
        .create_account(
            &NewAccount {
                id,
                handle,
                handle_skeleton: p["skeleton"].as_str().unwrap_or(handle),
                terms_version: p["terms"].as_str().unwrap_or("unset"),
                country_declared: p["country"].as_str(),
                billing_ref: &billing_ref,
                operator: false,
                draft: &draft,
                invite_hash: invite.as_deref(),
            },
            n,
        )
        .await;
    let account = match created {
        Ok(a) => a,
        Err(CreateError::HandleTaken) => return Err(ApiError::Conflict("That handle was just taken.".into())),
        Err(CreateError::InviteInvalid) => {
            return Err(ApiError::Unprocessable("That invite code is not valid.".into()));
        }
        Err(CreateError::Db(e)) => return Err(e.into()),
    };
    match method {
        (Some((cred, passkey)), _) => {
            let name = b
                .passkey_name
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && s.len() <= 60)
                .unwrap_or("Passkey");
            app.store.add_passkey(account.id, &cred, &passkey, name).await?;
        }
        (_, Some(address)) => {
            if !app.store.add_wallet(account.id, &address).await? {
                app.store.delete_account(account.id, n).await?;
                return Err(ApiError::Conflict("That wallet already signs in to an account.".into()));
            }
        }
        _ => return Err(ApiError::Internal),
    }
    let (codes, hashes) = recovery::generate();
    app.store.set_recovery_codes(account.id, &hashes).await?;
    app.store
        .audit(
            &format!("account:{}", account.id),
            "signup",
            &account.id.to_string(),
            &json!({ "invited": account.free, "terms": account.terms_version }),
        )
        .await?;
    Metrics::inc(&app.metrics.signups);
    let cookie = start_session(&app, account.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &account), "recoveryCodes": codes })))
}

// ── sign-in ──────────────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyLoginStart {
    handle: Option<String>,
}

async fn passkey_login_start(State(app): State<Shared>, Json(b): Json<PasskeyLoginStart>) -> ApiResult<Json<Value>> {
    let (options, state) = match b.handle.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => {
            // An unknown handle gets a ceremony too (a discoverable one), so the answer does not say who has an account.
            let a = app.store.account_by_handle(&h.to_ascii_lowercase()).await?.filter(|a| a.status == "active");
            let keys = match &a {
                Some(a) => app.store.passkeys(a.id).await?.into_iter().map(|(_, p, _)| p).collect(),
                None => Vec::new(),
            };
            match a {
                Some(a) if !keys.is_empty() => app.passkeys.start_login(a.id, &keys),
                _ => app.passkeys.start_discoverable(),
            }
        }
        None => app.passkeys.start_discoverable(),
    }
    .map_err(|_| ApiError::Internal)?;
    let challenge = link_in_bio_auth::random_hex(16);
    let state = serde_json::to_value(&state).map_err(|_| ApiError::Internal)?;
    app.store.put_challenge(&challenge, "passkey-login", None, &state, now() + CHALLENGE_TTL).await?;
    Ok(Json(json!({ "challenge": challenge, "options": options })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyFinish {
    challenge: String,
    credential: Value,
}

fn refused(app: &Shared) -> ApiError {
    Metrics::inc(&app.metrics.signin_failures);
    ApiError::Unprocessable("That did not sign you in.".into())
}

async fn passkey_login_finish(State(app): State<Shared>, Json(b): Json<PasskeyFinish>) -> ApiResult<Response> {
    let n = now();
    let Some((_, state)) = app.store.take_challenge(&b.challenge, "passkey-login", n).await? else {
        return Err(ApiError::Unprocessable("The sign-in expired; start again.".into()));
    };
    let state: LoginState = serde_json::from_value(state).map_err(|_| ApiError::Internal)?;
    let (cred, _) = Passkeys::credential_of(&b.credential).map_err(|_| refused(&app))?;
    let Some((account, stored)) = app.store.passkey_owner(&cred).await? else { return Err(refused(&app)) };
    let updated = app.passkeys.finish_login(&b.credential, &state, account, &stored).map_err(|_| refused(&app))?;
    app.store.update_passkey(&cred, &updated, n).await?;
    let a = app.store.account(account).await?.filter(|a| a.status == "active").ok_or_else(|| refused(&app))?;
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletStart {
    address: String,
}

async fn wallet_login_start(State(app): State<Shared>, Json(b): Json<WalletStart>) -> ApiResult<Json<Value>> {
    let c = &app.config;
    let w = wallet::Challenge::new(
        &c.app_host,
        &c.app_origin,
        &c.sui_network,
        &b.address,
        &format!("Sign in to {}.", c.product_name),
        now(),
    )
    .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let challenge = link_in_bio_auth::random_hex(16);
    let message = w.message();
    app.store
        .put_challenge(
            &challenge,
            "wallet-login",
            None,
            &serde_json::to_value(&w).map_err(|_| ApiError::Internal)?,
            w.expires_at,
        )
        .await?;
    Ok(Json(json!({ "challenge": challenge, "message": message })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletFinish {
    challenge: String,
    signature: String,
}

async fn wallet_login_finish(State(app): State<Shared>, Json(b): Json<WalletFinish>) -> ApiResult<Response> {
    let n = now();
    let Some((_, state)) = app.store.take_challenge(&b.challenge, "wallet-login", n).await? else {
        return Err(ApiError::Unprocessable("The sign-in expired; start again.".into()));
    };
    let w: wallet::Challenge = serde_json::from_value(state).map_err(|_| ApiError::Internal)?;
    w.verify(&b.signature, n).map_err(|_| refused(&app))?;
    let account = app.store.wallet_owner(&w.address).await?.ok_or_else(|| refused(&app))?;
    let a = app.store.account(account).await?.filter(|a| a.status == "active").ok_or_else(|| refused(&app))?;
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a) })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryLogin {
    handle: String,
    code: String,
}

async fn recovery_login(State(app): State<Shared>, Json(b): Json<RecoveryLogin>) -> ApiResult<Response> {
    let code = recovery::normalise(&b.code).ok_or_else(|| refused(&app))?;
    let account = app
        .store
        .use_recovery_code(&b.handle.trim().to_ascii_lowercase(), &recovery::hash(&code), now())
        .await?
        .ok_or_else(|| refused(&app))?;
    let a = app.store.account(account).await?.ok_or_else(|| refused(&app))?;
    app.store.audit(&format!("account:{}", a.id), "recovery-code-used", &a.id.to_string(), &json!({})).await?;
    let left = app.store.recovery_codes_left(a.id).await?;
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a), "recoveryCodesLeft": left })))
}

async fn logout(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(v) = cookie_value(&headers) {
        app.store.delete_session(&session::hash(v)).await?;
    }
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session::set_cookie(None, 0)).map_err(|_| ApiError::Internal)?,
    );
    Ok(r)
}

// ── the account ──────────────────────────────────────────────────────────────────────────────────────────────────

async fn me(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let passkeys: Vec<Value> = app
        .store
        .passkeys(a.id)
        .await?
        .into_iter()
        .map(|(id, _, name)| json!({ "id": hex::encode(id), "name": name }))
        .collect();
    let mut body = account_json(&app, &a);
    body["passkeys"] = json!(passkeys);
    body["wallets"] = json!(app.store.wallets(a.id).await?);
    body["recoveryCodesLeft"] = json!(app.store.recovery_codes_left(a.id).await?);
    Ok(Json(body))
}

/// The invite codes the operator gave this account to pass on.
async fn me_invites(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let (codes, redeemed) = app.store.held_codes(a.id, now()).await?;
    let codes: Vec<Value> = codes.into_iter().map(|(c, exp)| json!({ "code": c, "expiresAt": exp })).collect();
    Ok(Json(json!({ "codes": if a.may_share_invites { codes } else { Vec::new() }, "redeemed": redeemed })))
}

async fn me_passkey_start(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let existing: Vec<Value> = app.store.passkeys(a.id).await?.into_iter().map(|(_, p, _)| p).collect();
    if existing.len() >= 10 {
        return Err(ApiError::Conflict("An account can have at most 10 passkeys.".into()));
    }
    let (options, state) = app.passkeys.start_register(a.id, &a.handle, &existing).map_err(|_| ApiError::Internal)?;
    let challenge = link_in_bio_auth::random_hex(16);
    app.store
        .put_challenge(&challenge, "passkey-register", Some(a.id), &json!({ "state": state }), now() + CHALLENGE_TTL)
        .await?;
    Ok(Json(json!({ "challenge": challenge, "options": options })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyAdd {
    challenge: String,
    credential: Value,
    name: Option<String>,
}

async fn me_passkey_finish(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<PasskeyAdd>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    let Some((Some(owner), state)) = app.store.take_challenge(&b.challenge, "passkey-register", now()).await? else {
        return Err(ApiError::Unprocessable("That expired; start again.".into()));
    };
    if owner != a.id {
        return Err(ApiError::Forbidden("that ceremony belongs to another account"));
    }
    let (cred, passkey) = app
        .passkeys
        .finish_register(&b.credential, &state["state"])
        .map_err(|_| ApiError::Unprocessable("The passkey could not be verified.".into()))?;
    let name = b.name.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.len() <= 60).unwrap_or("Passkey");
    app.store.add_passkey(a.id, &cred, &passkey, name).await?;
    app.store.audit(&format!("account:{}", a.id), "passkey-added", &a.id.to_string(), &json!({ "name": name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me_passkey_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    let cred = hex::decode(&id).map_err(|_| ApiError::NotFound)?;
    if app.store.delete_passkey(a.id, &cred).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict("Keep at least one way to sign in.".into()))
    }
}

async fn me_wallet_start(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<WalletStart>,
) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let c = &app.config;
    let w = wallet::Challenge::new(
        &c.app_host,
        &c.app_origin,
        &c.sui_network,
        &b.address,
        &format!("Link this wallet to {} on {}.", a.handle, c.product_name),
        now(),
    )
    .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let challenge = link_in_bio_auth::random_hex(16);
    let message = w.message();
    app.store.put_challenge(&challenge, "wallet-link", Some(a.id), &json!({ "wallet": w }), w.expires_at).await?;
    Ok(Json(json!({ "challenge": challenge, "message": message })))
}

async fn me_wallet_finish(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<WalletFinish>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    let n = now();
    let Some((Some(owner), state)) = app.store.take_challenge(&b.challenge, "wallet-link", n).await? else {
        return Err(ApiError::Unprocessable("That expired; start again.".into()));
    };
    if owner != a.id {
        return Err(ApiError::Forbidden("that request belongs to another account"));
    }
    let w: wallet::Challenge = serde_json::from_value(state["wallet"].clone()).map_err(|_| ApiError::Internal)?;
    w.verify(&b.signature, n).map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    if !app.store.add_wallet(a.id, &w.address).await? {
        return Err(ApiError::Conflict("That wallet already signs in to an account.".into()));
    }
    app.store
        .audit(&format!("account:{}", a.id), "wallet-linked", &a.id.to_string(), &json!({ "address": w.address }))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn me_wallet_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(address): Path<String>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    let address = wallet::canonical_address(&address).ok_or(ApiError::NotFound)?;
    if app.store.delete_wallet(a.id, &address).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict("Keep at least one way to sign in.".into()))
    }
}

async fn me_recovery_codes(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let (codes, hashes) = recovery::generate();
    app.store.set_recovery_codes(a.id, &hashes).await?;
    app.store.audit(&format!("account:{}", a.id), "recovery-codes-replaced", &a.id.to_string(), &json!({})).await?;
    Ok(Json(json!({ "recoveryCodes": codes })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CountryBody {
    country: Option<String>,
}

async fn me_country(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<CountryBody>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    app.store.set_country(a.id, country(b.country.as_deref())?.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteBody {
    confirm: String,
}

async fn me_delete(State(app): State<Shared>, headers: HeaderMap, Json(b): Json<DeleteBody>) -> ApiResult<Response> {
    let a = account(&app, &headers).await?;
    if b.confirm != a.handle {
        return Err(ApiError::Unprocessable("Type your handle to confirm.".into()));
    }
    app.store.delete_account(a.id, now()).await?;
    app.store
        .audit(&format!("account:{}", a.id), "account-deleted", &a.id.to_string(), &json!({ "handle": a.handle }))
        .await?;
    app.pages.forget(&page_host(&app, &a.handle)).await;
    let mut r = StatusCode::NO_CONTENT.into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&session::set_cookie(None, 0)).map_err(|_| ApiError::Internal)?,
    );
    Ok(r)
}

async fn me_export(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    let a = account(&app, &headers).await?;
    let page = app.store.page(a.id).await?;
    let body = json!({
        "exportedAt": now(),
        "account": account_json(&app, &a),
        "page": page.map(|p| json!({
            "draft": serde_json::from_str::<Value>(&p.draft).unwrap_or(Value::Null),
            "published": p.published.and_then(|x| serde_json::from_str::<Value>(&x).ok()),
            "version": p.version, "publishedAt": p.published_at,
        })),
        "versions": app.store.page_versions(a.id).await?.into_iter().map(|(v, t)| json!({ "version": v, "at": t })).collect::<Vec<_>>(),
        "passkeys": app.store.passkeys(a.id).await?.into_iter().map(|(id, _, name)| json!({ "id": hex::encode(id), "name": name })).collect::<Vec<_>>(),
        "wallets": app.store.wallets(a.id).await?,
        "domains": app.store.domains(a.id).await?.into_iter().map(|d| json!({ "hostname": d.hostname, "status": d.status })).collect::<Vec<_>>(),
        "billing": app.store.billing_events(a.id).await?.into_iter().map(|e| json!({
            "provider": e.provider, "kind": e.kind, "months": e.months, "amountPence": e.amount_pence, "at": e.created_at,
        })).collect::<Vec<_>>(),
        "statements": app.store.statements_for(a.id).await?.into_iter().map(|r| json!({
            "decision": r.decision, "statement": r.statement, "at": r.decided_at,
        })).collect::<Vec<_>>(),
        "appeals": app.store.appeals_of(a.id).await?.into_iter().map(|x| json!({ "text": x.text, "status": x.status, "statement": x.statement })).collect::<Vec<_>>(),
    });
    let mut r = Json(body).into_response();
    r.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"link-in-bio-{}.json\"", a.handle))
            .map_err(|_| ApiError::Internal)?,
    );
    Ok(r)
}

// ── the page ─────────────────────────────────────────────────────────────────────────────────────────────────────

fn page_host(app: &Shared, handle: &str) -> String {
    format!("{handle}.{}", app.config.pages_domain)
}

fn tenant_options() -> ParseOptions {
    // The account's own handle passed the reserved check at sign-up; the document must carry exactly that handle.
    ParseOptions { owner: Owner::Tenant, check_reserved: false }
}

/// Parses an edited document for an account: the parser's rules, plus the account's own handle and pictures.
async fn check_document(app: &Shared, a: &Account, bytes: &[u8]) -> ApiResult<(Manifest, Vec<Issue>)> {
    let parsed = link_in_bio_core::parse(bytes, tenant_options()).map_err(ApiError::Issues)?;
    let mut issues = Vec::new();
    if parsed.manifest.identity.handle != a.handle {
        issues.push(Issue::new("identity/handle", "handle_mismatch", "The handle must be your account's handle."));
    }
    if let Some(avatar) = &parsed.manifest.identity.avatar {
        let own = match avatar.strip_prefix("sha256:") {
            Some(hex) => app.store.owns_asset(a.id, hex).await?,
            None => false,
        };
        if !own {
            issues.push(Issue::new("identity/avatar", "avatar_unknown", "Upload the picture first."));
        }
    }
    if !issues.is_empty() {
        return Err(ApiError::Issues(issues));
    }
    Ok((parsed.manifest, parsed.warnings))
}

async fn screening_of(app: &Shared, m: &Manifest) -> ApiResult<Vec<Value>> {
    let urls: Vec<String> = m.visible_links().map(|l| l.url.clone()).collect();
    let hashes: Vec<Vec<u8>> = urls.iter().map(|u| sha256(u.as_bytes())).collect();
    let screens = app.store.screens(&hashes).await?;
    Ok(urls
        .iter()
        .map(|u| {
            let s = screens.iter().find(|s| &s.url == u);
            json!({ "url": u, "verdict": s.map_or("unchecked", |s| s.verdict.as_str()), "detail": s.map(|s| s.detail.clone()) })
        })
        .collect())
}

async fn page_get(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    let draft: Value = serde_json::from_str(&p.draft).unwrap_or(Value::Null);
    let (warnings, screening) = match check_document(&app, &a, p.draft.as_bytes()).await {
        Ok((m, w)) => (w, screening_of(&app, &m).await?),
        Err(ApiError::Issues(i)) => (i, Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(Json(json!({
        "draft": draft, "published": p.published.is_some(), "version": p.version, "updatedAt": p.updated_at,
        "publishedAt": p.published_at, "url": page_url(&app, &a.handle), "issues": warnings, "screening": screening,
        "changed": p.published.as_deref() != Some(p.draft.as_str()),
    })))
}

async fn page_put(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let (m, warnings) = check_document(&app, &a, &body).await?;
    app.store.save_draft(a.id, &m.to_json(), now()).await?;
    Ok(Json(json!({ "saved": true, "warnings": warnings })))
}

/// The draft rendered by the real renderer, for the editor's sandboxed preview frame. Pictures are served by hash
/// from `/api/v1/assets/` (the frame is sandboxed, so it carries no cookie).
async fn page_preview(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    let a = account(&app, &headers).await?;
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    let (manifest, warnings) = check_document(&app, &a, p.draft.as_bytes()).await?;
    let host = page_host(&app, &a.handle);
    let config = app.config.site_for(&a.handle, &host).map_err(|_| ApiError::Internal)?;
    let picture = match manifest.identity.avatar.as_deref().and_then(|x| x.strip_prefix("sha256:")) {
        Some(hex) => app.store.view_asset(hex).await?,
        None => None,
    };
    let pic = picture.clone().and_then(super::pages::picture_of);
    let site = Site::from_parts(config, manifest, warnings, pic.clone(), None, now().timestamp().max(0) as u64);
    let mut html = site.html.clone();
    if let Some(p) = &pic {
        let base = format!("https://{host}");
        let path = crate::site::avatar_path(p);
        let to = format!("/api/v1/assets/{}.{}", p.sha256, p.ext);
        html = html.replace(&format!("{base}{path}"), &to).replace(&path, &to);
    }
    let mut r = Response::new(Body::from(html));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    crate::headers::secure(h, false, true);
    // The preview may be framed by the app itself, and only by it.
    h.remove(header::X_FRAME_OPTIONS);
    let csp = crate::headers::page_csp()
        .replace("frame-ancestors 'none'", &format!("frame-ancestors {}", app.config.app_origin));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&csp).map_err(|_| ApiError::Internal)?);
    Ok(r)
}

async fn page_publish(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let n = now();
    if !a.entitled(n, Duration::days(app.config.grace_days)) {
        return Err(ApiError::Conflict("Buy a paid period to publish your page.".into()));
    }
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    let (m, _) = check_document(&app, &a, p.draft.as_bytes()).await?;
    // Screen every link not screened yet before the page goes out (at most 60 links: the parser's limit).
    let screens = screening_of(&app, &m).await?;
    for s in &screens {
        if s["verdict"] == "unchecked"
            && let Some(u) = s["url"].as_str()
        {
            app.screener.screen_and_record(&app.store, u, n).await?;
            Metrics::inc(&app.metrics.screenings);
        }
    }
    let version = app.store.publish(a.id, &m.to_json(), n).await?;
    app.store.audit(&format!("account:{}", a.id), "publish", &a.id.to_string(), &json!({ "version": version })).await?;
    app.pages.forget(&page_host(&app, &a.handle)).await;
    Metrics::inc(&app.metrics.publishes);
    let screening = screening_of(&app, &m).await?;
    let hidden: Vec<&Value> = screening.iter().filter(|s| s["verdict"] == "flagged").collect();
    Ok(Json(json!({
        "version": version, "url": page_url(&app, &a.handle), "hidden": hidden,
        "online": app.config.third_party_pages || a.operator,
    })))
}

async fn page_unpublish(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    app.store.unpublish(a.id).await?;
    app.pages.forget(&page_host(&app, &a.handle)).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn page_versions(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let v: Vec<Value> =
        app.store.page_versions(a.id).await?.into_iter().map(|(v, t)| json!({ "version": v, "at": t })).collect();
    Ok(Json(json!({ "versions": v })))
}

async fn page_restore(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(version): Path<i32>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    let doc = app.store.page_version(a.id, version).await?.ok_or(ApiError::NotFound)?;
    app.store.save_draft(a.id, &doc, now()).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn avatar_upload(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let pic = link_in_bio_assets::normalise_raster(&body).map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    if app.store.asset_bytes(a.id).await? + pic.bytes.len() as i64 > app.config.asset_quota_bytes {
        return Err(ApiError::Conflict(
            "You have stored as many pictures as an account may; remove an old one first.".into(),
        ));
    }
    let row = AssetRow {
        sha256: pic.sha256.clone(),
        mime: pic.mime.into(),
        ext: pic.ext.into(),
        width: pic.width as i32,
        height: pic.height as i32,
        bytes: pic.bytes,
    };
    app.store.put_asset(a.id, &row).await?;
    Ok(Json(
        json!({ "avatar": format!("sha256:{}", row.sha256), "url": format!("/api/v1/assets/{}.{}", row.sha256, row.ext) }),
    ))
}

/// Pictures by full hash (public: the hash is the name; the editor's sandboxed preview loads them without a cookie).
async fn asset(State(app): State<Shared>, Path(file): Path<String>) -> ApiResult<Response> {
    let (hex, ext) = file.split_once('.').ok_or(ApiError::NotFound)?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::NotFound);
    }
    let a = app.store.view_asset(hex).await?.filter(|a| a.ext == ext).ok_or(ApiError::NotFound)?;
    let mut r = Response::new(Body::from(a.bytes));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&a.mime).map_err(|_| ApiError::Internal)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(crate::headers::CACHE_IMMUTABLE));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    Ok(r)
}

/// The page stylesheet, script and sprite on the app host (the preview frame loads them from here).
async fn bundle(req: Request) -> Response {
    match Bundle::get().find(req.uri().path()) {
        Some(a) => {
            let mut r = Response::new(Body::from(a.body.clone()));
            let h = r.headers_mut();
            if let Ok(v) = HeaderValue::from_str(a.content_type) {
                h.insert(header::CONTENT_TYPE, v);
            }
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static(crate::headers::CACHE_IMMUTABLE));
            r
        }
        None => ApiError::NotFound.into_response(),
    }
}

// ── billing ──────────────────────────────────────────────────────────────────────────────────────────────────────

fn evidence(a: &Account, headers: &HeaderMap) -> Evidence {
    Evidence { declared: a.country_declared.clone(), request: request_country(headers) }
}

async fn billing(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let n = now();
    let offers = app.billing.offers(&evidence(&a, &headers), months_ahead(a.paid_until, n));
    let events: Vec<Value> = app
        .store
        .billing_events(a.id)
        .await?
        .into_iter()
        .map(|e| json!({ "provider": e.provider, "kind": e.kind, "months": e.months, "amountPence": e.amount_pence, "at": e.created_at, "paidUntil": e.paid_until_after }))
        .collect();
    Ok(Json(json!({
        "free": a.free, "paidUntil": a.paid_until, "entitled": a.entitled(n, Duration::days(app.config.grace_days)),
        "pricePence": offers.price_pence, "currency": "GBP", "offers": offers.offers, "notes": offers.notes, "events": events,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckoutBody {
    method: String,
    months: u32,
}

async fn checkout_create(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<CheckoutBody>,
) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let n = now();
    let ev = evidence(&a, &headers);
    let offer = app.billing.check(&ev, months_ahead(a.paid_until, n), &b.method, b.months).ok_or_else(|| {
        ApiError::Unprocessable("That payment method or number of months is not available to you.".into())
    })?;
    let provider = app
        .billing
        .provider(&offer.method.provider)
        .ok_or(ApiError::Unavailable("that payment method is switched off"))?;
    let id = Uuid::new_v4();
    let amount = u64::from(app.billing.price_pence()) * u64::from(b.months);
    let start = provider
        .create_checkout(&CheckoutRequest {
            checkout_id: id,
            method: b.method.clone(),
            billing_ref: a.billing_ref.clone(),
            months: b.months,
            amount_pence: amount,
            description: format!(
                "{}, {} month{}",
                app.config.product_name,
                b.months,
                if b.months == 1 { "" } else { "s" }
            ),
        })
        .await
        .map_err(|e| {
            tracing::warn!(provider = %offer.method.provider, error = %e, "checkout");
            ApiError::Unavailable("the payment provider is unavailable; try again shortly")
        })?;
    app.store
        .create_checkout(&Checkout {
            id,
            account_id: a.id,
            provider: offer.method.provider.clone(),
            provider_ref: start.provider_ref.clone(),
            method: b.method,
            months: b.months as i32,
            amount_pence: amount as i64,
            status: "open".into(),
            country_declared: ev.declared,
            country_request: ev.request,
            created_at: n,
            completed_at: None,
        })
        .await?;
    Metrics::inc(&app.metrics.checkouts);
    Ok(Json(json!({ "checkout": id, "amountPence": amount, "client": start.client })))
}

async fn checkout_get(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let c = app.store.checkout(id).await?.filter(|c| c.account_id == a.id).ok_or(ApiError::NotFound)?;
    let fresh = app.store.account(a.id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "checkout": c.id, "status": c.status, "months": c.months, "paidUntil": fresh.paid_until })))
}

// ── custom domains ───────────────────────────────────────────────────────────────────────────────────────────────

pub const DOMAIN_TXT_LABEL: &str = "_link-in-bio";

async fn domains(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let d: Vec<Value> = app
        .store
        .domains(a.id)
        .await?
        .into_iter()
        .map(|d| {
            json!({
                "hostname": d.hostname, "status": d.status, "verifiedAt": d.verified_at,
                "record": { "name": format!("{DOMAIN_TXT_LABEL}.{}", d.hostname), "type": "TXT", "value": d.token },
            })
        })
        .collect();
    Ok(Json(json!({ "enabled": app.config.custom_hostname_cap > 0, "domains": d })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DomainBody {
    hostname: String,
}

async fn domain_add(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<DomainBody>,
) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    if app.config.custom_hostname_cap == 0 {
        return Err(ApiError::Forbidden("custom domains are not available"));
    }
    if app.store.count_domains().await? >= app.config.custom_hostname_cap {
        return Err(ApiError::Conflict("No more custom domains can be added right now.".into()));
    }
    let h = b.hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = h.len() <= 253
        && h.split('.').count() >= 2
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        });
    if !valid || h == app.config.pages_domain || h.ends_with(&format!(".{}", app.config.pages_domain)) {
        return Err(ApiError::Unprocessable("That is not a domain you can add.".into()));
    }
    let token = link_in_bio_auth::random_hex(16);
    if !app.store.add_domain(a.id, &h, "dns-txt", &token).await? {
        return Err(ApiError::Conflict("That domain is already in use.".into()));
    }
    Ok(Json(
        json!({ "hostname": h, "record": { "name": format!("{DOMAIN_TXT_LABEL}.{h}"), "type": "TXT", "value": token } }),
    ))
}

async fn domain_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(hostname): Path<String>,
) -> ApiResult<StatusCode> {
    let a = account(&app, &headers).await?;
    if app.store.delete_domain(a.id, &hostname.to_ascii_lowercase()).await? {
        app.pages.forget(&hostname.to_ascii_lowercase()).await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ── reports and appeals ──────────────────────────────────────────────────────────────────────────────────────────

pub const REPORT_REASONS: &[&str] = &[
    "illegal",
    "csam",
    "terrorism",
    "fraud",
    "malware",
    "harassment",
    "impersonation",
    "intellectual-property",
    "adult",
    "spam",
    "other",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportBody {
    page: String,
    url: Option<String>,
    reason: String,
    #[serde(default)]
    details: String,
    contact: Option<String>,
}

/// A report about a page or one of its links. No account is needed; nobody learns who reported.
async fn report(State(app): State<Shared>, Json(b): Json<ReportBody>) -> ApiResult<(StatusCode, Json<Value>)> {
    let handle =
        check_handle(&b.page, false).map_err(|_| ApiError::Unprocessable("Name the page by its handle.".into()))?;
    if !REPORT_REASONS.contains(&b.reason.as_str()) {
        return Err(ApiError::Unprocessable("Choose a reason from the list.".into()));
    }
    let details = b.details.trim();
    if details.chars().count() > 4000 || details.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::Unprocessable("The details are too long (4000 characters at most).".into()));
    }
    let url = match b.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) if u.len() <= 2048 && (u.starts_with("https://") || u.starts_with("mailto:")) => Some(u.to_string()),
        Some(_) => return Err(ApiError::Unprocessable("The link must start with https:// or mailto:.".into())),
        None => None,
    };
    let contact = b.contact.as_deref().map(str::trim).filter(|c| !c.is_empty());
    if contact.is_some_and(|c| c.len() > 320 || !c.contains('@')) {
        return Err(ApiError::Unprocessable("The contact must be an email address (or left empty).".into()));
    }
    let id = app.store.create_report(&handle, url.as_deref(), &b.reason, details, contact, now()).await?;
    Metrics::inc(&app.metrics.reports);
    Ok((StatusCode::CREATED, Json(json!({ "report": id }))))
}

async fn statements(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let a = account(&app, &headers).await?;
    let s: Vec<Value> = app
        .store
        .statements_for(a.id)
        .await?
        .into_iter()
        .map(|r| json!({ "report": r.id, "reason": r.reason, "decision": r.decision, "statement": r.statement, "decidedAt": r.decided_at }))
        .collect();
    let appeals: Vec<Value> = app
        .store
        .appeals_of(a.id)
        .await?
        .into_iter()
        .map(|x| json!({ "appeal": x.id, "report": x.report_id, "status": x.status, "statement": x.statement, "at": x.created_at }))
        .collect();
    Ok(Json(json!({ "statements": s, "appeals": appeals })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppealBody {
    report: Option<Uuid>,
    text: String,
}

/// An appeal against a decision. A suspended account cannot sign in, so it can also appeal by email (the appeals
/// address in the statement of reasons); this is the route for everyone else.
async fn appeal(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<AppealBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let a = account(&app, &headers).await?;
    let text = b.text.trim();
    if text.is_empty() || text.chars().count() > 4000 {
        return Err(ApiError::Unprocessable("Say why, in 4000 characters at most.".into()));
    }
    if let Some(r) = b.report
        && app.store.report(r).await?.is_none_or(|r| r.account_id != Some(a.id))
    {
        return Err(ApiError::NotFound);
    }
    let id = app.store.create_appeal(a.id, b.report, text).await?;
    Ok((StatusCode::CREATED, Json(json!({ "appeal": id }))))
}

// ── router ───────────────────────────────────────────────────────────────────────────────────────────────────────

pub fn router(app: Shared) -> Router {
    let api = Router::new()
        .route("/api/v1/instance", get(instance))
        .route("/api/v1/limits", get(limits))
        .route("/api/v1/signup/start", post(signup_start))
        .route("/api/v1/signup/finish", post(signup_finish))
        .route("/api/v1/login/passkey/start", post(passkey_login_start))
        .route("/api/v1/login/passkey/finish", post(passkey_login_finish))
        .route("/api/v1/login/wallet/start", post(wallet_login_start))
        .route("/api/v1/login/wallet/finish", post(wallet_login_finish))
        .route("/api/v1/login/recovery", post(recovery_login))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me).delete(me_delete))
        .route("/api/v1/me/export", get(me_export))
        .route("/api/v1/me/country", put(me_country))
        .route("/api/v1/me/passkeys/start", post(me_passkey_start))
        .route("/api/v1/me/passkeys/finish", post(me_passkey_finish))
        .route("/api/v1/me/passkeys/{id}", delete(me_passkey_delete))
        .route("/api/v1/me/wallets/start", post(me_wallet_start))
        .route("/api/v1/me/wallets/finish", post(me_wallet_finish))
        .route("/api/v1/me/wallets/{address}", delete(me_wallet_delete))
        .route("/api/v1/me/recovery-codes", post(me_recovery_codes))
        .route("/api/v1/me/statements", get(statements))
        .route("/api/v1/me/invites", get(me_invites))
        .route("/api/v1/page", get(page_get).put(page_put))
        .route("/api/v1/page/preview", get(page_preview))
        .route("/api/v1/page/publish", post(page_publish))
        .route("/api/v1/page/unpublish", post(page_unpublish))
        .route("/api/v1/page/versions", get(page_versions))
        .route("/api/v1/page/versions/{version}/restore", post(page_restore))
        .route("/api/v1/billing", get(billing))
        .route("/api/v1/billing/checkouts", post(checkout_create))
        .route("/api/v1/billing/checkouts/{id}", get(checkout_get))
        .route("/api/v1/domains", get(domains).post(domain_add))
        .route("/api/v1/domains/{hostname}", delete(domain_delete))
        .route("/api/v1/reports", post(report))
        .route("/api/v1/appeals", post(appeal))
        .route("/api/v1/assets/{file}", get(asset))
        .layer(DefaultBodyLimit::max(64 * 1024));
    // Pictures are uploaded as their bytes (up to 5 MiB; re-encoded to at most 64 KiB).
    let upload = Router::new()
        .route("/api/v1/page/avatar", post(avatar_upload))
        .layer(DefaultBodyLimit::max(link_in_bio_assets::MAX_INPUT_BYTES));
    api.merge(upload)
        .route("/_/{file}", get(bundle))
        .route("/healthz", get(|| async { "ok\n" }))
        .fallback(|| async { ApiError::NoRoute.into_response() })
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app)
}

/// Headers as a lower-case map (what billing adapters read).
pub fn header_map(h: &HeaderMap) -> BTreeMap<String, String> {
    h.iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))).collect()
}
