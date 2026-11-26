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
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

// The sign-in crate does the ceremonies; this module stores their state and answers the browser.
use link_in_bio_auth::passkey::{LoginState, Passkeys};
use link_in_bio_auth::{recovery, session, wallet};
// Billing types the checkout and refund routes use.
use link_in_bio_billing::{BillingError, CheckoutRequest, Evidence, months_ahead, open_payments};
use link_in_bio_core::assets::Bundle;
use link_in_bio_core::limits::{handle_skeleton, limits_json, looks_reserved};
use link_in_bio_core::manifest::check_handle;
use link_in_bio_core::{Issue, Manifest, ParseOptions};
use link_in_bio_store::{Account, AssetRow, Checkout, CreateError, NewAccount, sha256};

use super::error::{ApiError, ApiResult};
use super::metrics::Metrics;
use super::{Shared, SignupMode, now};
use crate::site::Site;
use crate::time::rfc3339_full as ts;

/// How long a sign-up, sign-in or linking ceremony may take.
const CHALLENGE_TTL: Duration = Duration::minutes(5);

// ── plumbing ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// CSRF on every state-changing request, and `no-store` on every answer.
async fn guard(State(app): State<Shared>, req: Request, next: Next) -> Response {
    // Reads and preflights pass; every other method needs the app's origin and the custom header, and every answer is stamped no-store, no-sniff and no-referrer.
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        // The two things a cross-site request cannot forge: the origin and the custom header.
        let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
        let marked = req.headers().contains_key(session::CSRF_HEADER);
        if let Err(e) = session::check_csrf(origin, marked, &app.config.app_origin) {
            // The refusal says which of the two is missing.
            return ApiError::Forbidden(match e {
                session::CsrfError::Origin => "the request did not come from the app",
                session::CsrfError::Header => "the request is missing its app header",
            })
            .into_response();
        }
    }
    // The answer is stamped after the handler has run.
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    // A handler that sets its own cache rule keeps it; everything else is not stored.
    h.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    // Nothing the API sends is to be sniffed into another type.
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // No answer is sent on as a referrer.
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}

/// The session cookie's value in the request, if it has the right shape.
fn cookie_value(headers: &HeaderMap) -> Option<&str> {
    // Every cookie header is searched for the session cookie.
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(session::from_cookie_header)
}

/// The signed-in account (an active one), or 401.
async fn account(app: &Shared, headers: &HeaderMap) -> ApiResult<Account> {
    // The session is found by the hash of the cookie, which also slides its expiry; an account that is not active has no session.
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
    // A new random token: only its hash is stored, and the cookie value goes to the browser.
    // The cookie value goes to the browser; only its hash is stored.
    let (value, hash) = session::new_token();
    // A new session is idle for at most the idle limit.
    app.store.create_session(&hash, account, now() + session::IDLE).await?;
    HeaderValue::from_str(&session::set_cookie(Some(&value), session::IDLE.whole_seconds()))
        .map_err(|_| ApiError::Internal)
}

/// A JSON answer that also sets the session cookie.
fn with_cookie(cookie: HeaderValue, body: Value) -> Response {
    let mut r = Json(body).into_response();
    r.headers_mut().insert(header::SET_COOKIE, cookie);
    r
}

/// A country from the caller: empty is none, two capital letters is a code, anything else is refused.
fn country(v: Option<&str>) -> ApiResult<Option<String>> {
    // An empty value is none, a two-letter code is kept, anything else is refused.
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

/// The address of an account's page.
fn page_url(app: &Shared, handle: &str) -> String {
    format!("https://{handle}.{}/", app.config.pages_domain)
}

/// An account as the app shows it, including whether it is entitled to a page online now.
fn account_json(app: &Shared, a: &Account) -> Value {
    let n = now();
    json!({
        "id": a.id, "handle": a.handle, "status": a.status, "free": a.free, "paidUntil": a.paid_until.map(ts),
        // Whether the account may have a page online now.
        "entitled": a.entitled(n, Duration::days(app.config.grace_days)), "country": a.country_declared,
        "createdAt": ts(a.created_at), "pageUrl": page_url(app, &a.handle), "termsVersion": a.terms_version,
        "suspension": (a.status == "suspended").then(|| json!({ "kind": a.suspension_kind, "until": a.suspended_until.map(ts) })),
    })
}

/// The first document of a new page.
fn starter_manifest(handle: &str) -> String {
    // The handle is the first display name, which the holder changes.
    json!({ "schema": 1, "identity": { "displayName": handle, "handle": handle }, "items": [] }).to_string()
}

// ── instance ─────────────────────────────────────────────────────────────────────────────────────────────────────

/// What this instance offers, public, so a sign-up page can show it: sign-up mode (closed until the terms are set), price, switches, sign-in methods and the Sui network.
async fn instance(State(app): State<Shared>) -> Json<Value> {
    // The configuration, read once at start-up.
    let c = &app.config;
    Json(json!({
        "product": c.product_name,
        "version": env!("CARGO_PKG_VERSION"),
        "appHost": c.app_host,
        "pagesDomain": c.pages_domain,
        "signup": if c.signup_open_to_public() { serde_json::to_value(c.signup).unwrap_or_default() } else { json!("closed") },
        "thirdPartyPages": c.third_party_pages,
        "termsVersion": c.terms_version,
        // The sign-up age.
        "minimumAge": 18,
        "pricePence": c.price_pence,
        "currency": "GBP",
        "billingProviders": c.billing_providers,
        "customDomains": c.custom_hostname_cap > 0,
        "federation": c.federation,
        // The sign-in methods this service offers.
        "authenticators": ["passkey", "sui-wallet", "recovery-code"],
        "suiNetwork": c.sui_network,
        // The full node the wallet uses for that network (SUI_RPC_URL; the public one by default; null for localnet).
        "suiRpcUrl": c.sui_rpc_url,
    }))
}

/// Every bound the page parser enforces, public, so the editor shows the same limits.
async fn limits() -> Json<Value> {
    Json(limits_json())
}

// ── sign-up ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// The body that begins sign-up.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignupStart {
    /// The handle wanted.
    handle: String,
    /// The 18+ declaration.
    age_confirmed: bool,
    /// Whether the terms were accepted.
    terms_accepted: bool,
    /// The version of the terms accepted, which must be the current one.
    terms_version: String,
    /// The country declared (ISO 3166 alpha-2), optional.
    country: Option<String>,
    /// An invite code, when sign-up needs one.
    invite: Option<String>,
    /// `passkey` or `sui-wallet`.
    method: String,
    /// The wallet address, for the wallet method.
    address: Option<String>,
}

/// The stored form of an invite code typed by a person, or `None` if it cannot be one.
fn invite_hash(code: &str) -> Option<Vec<u8>> {
    // The same normalisation as for recovery codes, then the stored form.
    recovery::normalise(code).map(|c| recovery::hash(&c))
}

/// Begin sign-up: check everything that can be checked without writing (sign-up open, 18+, the current terms, an invite when required, a valid unreserved handle that is free), then start the passkey or wallet ceremony and keep its state server-side.
async fn signup_start(State(app): State<Shared>, Json(b): Json<SignupStart>) -> ApiResult<Json<Value>> {
    // Every rule that can be checked without a database write is checked first: sign-up open, 18+, the current terms, an invite when required, a valid and unreserved handle, then that it is free; the ceremony state is stored server-side, never sent to the browser.
    let c = &app.config;
    // Sign-up is closed unless a mode is set and the terms are chosen.
    if !c.signup_open_to_public() {
        return Err(ApiError::Forbidden("sign-up is closed"));
    }
    // The 18+ declaration is required.
    if !b.age_confirmed {
        return Err(ApiError::Unprocessable("You must be 18 or over to have an account.".into()));
    }
    // The terms accepted must be the current version.
    if !b.terms_accepted || b.terms_version != c.terms_version {
        return Err(ApiError::Unprocessable("Accept the current terms to continue.".into()));
    }
    // An invite is required in invite mode, and checked for its shape whenever one is given.
    let invite = match (c.signup, b.invite.as_deref()) {
        (SignupMode::Invite, None) => {
            return Err(ApiError::Unprocessable("An invite code is needed to sign up.".into()));
        }
        (_, Some(code)) => {
            Some(invite_hash(code).ok_or_else(|| ApiError::Unprocessable("That invite code is not valid.".into()))?)
        }
        (_, None) => None,
    };
    // The handle must be valid and not reserved.
    let handle = check_handle(&b.handle, true).map_err(|(_, m)| ApiError::Unprocessable(m))?;
    // A look-alike of a reserved name is refused too.
    if looks_reserved(&handle) {
        return Err(ApiError::Unprocessable("This handle is reserved. Choose another.".into()));
    }
    // The skeleton is what makes look-alike handles unique.
    let skeleton = handle_skeleton(&handle);
    if !app.store.handle_available(&handle, &skeleton).await? {
        return Err(ApiError::Conflict("That handle is taken or too close to one that exists.".into()));
    }
    let id = Uuid::new_v4();
    // What the ceremony must carry to the second step; it is stored server-side.
    let pending = json!({
        // The id is chosen now, because the passkey ceremony needs the user id first.
        "id": id, "handle": handle, "skeleton": skeleton, "country": country(b.country.as_deref())?,
        "invite": invite.map(hex::encode), "terms": c.terms_version,
    });
    let challenge = link_in_bio_auth::random_hex(16);
    let n = now();
    // The two sign-in methods an account can start with.
    match b.method.as_str() {
        // A passkey ceremony: the browser is given its options, the server keeps the state.
        "passkey" => {
            // The browser gets the options; the state stays here.
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
        // A wallet ceremony: the wallet is given a message to sign.
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
            // A wallet signs in to one account only.
            if app.store.wallet_owner(&w.address).await?.is_some() {
                return Err(ApiError::Conflict("That wallet already signs in to an account.".into()));
            }
            // The text the wallet will show and sign.
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

/// The body that finishes sign-up with the browser's answer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignupFinish {
    /// The id of the ceremony begun by the first step.
    challenge: String,
    /// The passkey credential, for the passkey method.
    credential: Option<Value>,
    /// The wallet's signature, for the wallet method.
    signature: Option<String>,
    /// A name for the passkey, optional.
    passkey_name: Option<String>,
}

/// Finish sign-up with the browser's answer: verify the sign-in method first, then create the account, its sign-in method and its recovery codes, audit it and start a session.
async fn signup_finish(State(app): State<Shared>, Json(b): Json<SignupFinish>) -> ApiResult<Response> {
    // The sign-in method is verified before anything is created; then the account, the sign-in method and the recovery codes are made, audited, and a session starts. A wallet that was taken in the meantime undoes the account.
    let n = now();
    // Exactly one of a credential and a signature, which decides the ceremony kind.
    let (kind, taken) = match (&b.credential, &b.signature) {
        (Some(_), None) => ("passkey-register", app.store.take_challenge(&b.challenge, "passkey-register", n).await?),
        (None, Some(_)) => ("wallet-link", app.store.take_challenge(&b.challenge, "wallet-link", n).await?),
        _ => return Err(ApiError::BadRequest("send either a credential or a signature".into())),
    };
    // The challenge must exist, be unexpired and belong to no account yet.
    let Some((None, state)) = taken else {
        return Err(ApiError::Unprocessable("The sign-up expired; start again.".into()));
    };
    // What the first step stored.
    let p = &state["signup"];
    let id: Uuid = serde_json::from_value(p["id"].clone()).map_err(|_| ApiError::Internal)?;
    let handle = p["handle"].as_str().ok_or(ApiError::Internal)?;
    // Verify the sign-in method before anything is created.
    // The method is verified before anything is created.
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
    // The invite's hash, carried from the first step.
    let invite = p["invite"].as_str().and_then(|h| hex::decode(h).ok());
    // An opaque reference for payment providers, never the handle.
    let billing_ref = link_in_bio_auth::random_hex(16);
    // The first draft is a page with only a name.
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
        // A race with another sign-up for the same handle.
        Err(CreateError::HandleTaken) => return Err(ApiError::Conflict("That handle was just taken.".into())),
        Err(CreateError::InviteInvalid) => {
            return Err(ApiError::Unprocessable("That invite code is not valid.".into()));
        }
        Err(CreateError::Db(e)) => return Err(e.into()),
    };
    // Store the sign-in method that was verified.
    match method {
        // A passkey account stores the credential and its name.
        (Some((cred, passkey)), _) => {
            let name = b
                .passkey_name
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && s.len() <= 60)
                .unwrap_or("Passkey");
            app.store.add_passkey(account.id, &cred, &passkey, name).await?;
        }
        // A wallet account links the wallet, which must still be free.
        (_, Some(address)) => {
            if !app.store.add_wallet(account.id, &address).await? {
                app.store.delete_account(account.id, n).await?;
                return Err(ApiError::Conflict("That wallet already signs in to an account.".into()));
            }
        }
        _ => return Err(ApiError::Internal),
    }
    // Ten recovery codes, shown once; only their hashes are stored.
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
    // Counted once the account exists.
    Metrics::inc(&app.metrics.signups);
    // The new account is signed in at once.
    let cookie = start_session(&app, account.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &account), "recoveryCodes": codes })))
}

// ── sign-in ──────────────────────────────────────────────────────────────────────────────────────────────────────

/// The body that begins a passkey sign-in.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyLoginStart {
    /// The handle, or none for a sign-in the browser chooses the passkey for.
    handle: Option<String>,
}

/// Begin a passkey sign-in. Whether the handle exists is not revealed: an unknown handle gets a ceremony just like a known one.
async fn passkey_login_start(State(app): State<Shared>, Json(b): Json<PasskeyLoginStart>) -> ApiResult<Json<Value>> {
    // Whether the handle exists is not revealed: an unknown handle gets a ceremony just like a known one.
    // With a handle the account's passkeys are offered; without one the browser chooses.
    let (options, state) = match b.handle.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => {
            // An unknown handle gets a ceremony too (a discoverable one), so the answer does not say who has an account.
            // An unknown handle gets a discoverable ceremony too.
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
    // The login state is kept server-side until the answer comes back.
    let state = serde_json::to_value(&state).map_err(|_| ApiError::Internal)?;
    app.store.put_challenge(&challenge, "passkey-login", None, &state, now() + CHALLENGE_TTL).await?;
    Ok(Json(json!({ "challenge": challenge, "options": options })))
}

/// The body that finishes a passkey sign-in.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyFinish {
    /// The id of the ceremony.
    challenge: String,
    /// The browser's signed answer.
    credential: Value,
}

/// One answer for every sign-in failure, counted, so a caller cannot tell a missing account from a wrong credential.
fn refused(app: &Shared) -> ApiError {
    Metrics::inc(&app.metrics.signin_failures);
    ApiError::Unprocessable("That did not sign you in.".into())
}

/// Finish a passkey sign-in: the challenge is taken once, the credential is checked against its stored passkey (whose counter is updated), and a session starts for an active account.
async fn passkey_login_finish(State(app): State<Shared>, Json(b): Json<PasskeyFinish>) -> ApiResult<Response> {
    let n = now();
    // The ceremony is taken once, and must not have expired.
    let Some((_, state)) = app.store.take_challenge(&b.challenge, "passkey-login", n).await? else {
        return Err(ApiError::Unprocessable("The sign-in expired; start again.".into()));
    };
    // The state the first step stored.
    let state: LoginState = serde_json::from_value(state).map_err(|_| ApiError::Internal)?;
    // The credential id the answer names.
    let (cred, _) = Passkeys::credential_of(&b.credential).map_err(|_| refused(&app))?;
    // An unknown credential is the same failure as a wrong one.
    let Some((account, stored)) = app.store.passkey_owner(&cred).await? else { return Err(refused(&app)) };
    let updated = app.passkeys.finish_login(&b.credential, &state, account, &stored).map_err(|_| refused(&app))?;
    // The counter moved, so the stored passkey is replaced.
    app.store.update_passkey(&cred, &updated, n).await?;
    // A suspended or deleted account cannot sign in.
    let a = app.store.account(account).await?.filter(|a| a.status == "active").ok_or_else(|| refused(&app))?;
    // Counted after the checks.
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a) })))
}

/// The body that begins a wallet sign-in or linking.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletStart {
    /// The wallet's address.
    address: String,
}

/// Begin a wallet sign-in: the message the wallet signs, tied to this host, network and time.
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

/// The body that finishes a wallet sign-in or linking.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletFinish {
    /// The id of the ceremony.
    challenge: String,
    /// The wallet's signature of the message.
    signature: String,
}

/// Finish a wallet sign-in: the signature must be for the stored message and the address must belong to an active account.
async fn wallet_login_finish(State(app): State<Shared>, Json(b): Json<WalletFinish>) -> ApiResult<Response> {
    let n = now();
    let Some((_, state)) = app.store.take_challenge(&b.challenge, "wallet-login", n).await? else {
        return Err(ApiError::Unprocessable("The sign-in expired; start again.".into()));
    };
    let w: wallet::Challenge = serde_json::from_value(state).map_err(|_| ApiError::Internal)?;
    // A bad signature, an expired message and a wrong key are one failure.
    w.verify(&b.signature, n).map_err(|_| refused(&app))?;
    // A wallet with no account is the same failure too.
    let account = app.store.wallet_owner(&w.address).await?.ok_or_else(|| refused(&app))?;
    let a = app.store.account(account).await?.filter(|a| a.status == "active").ok_or_else(|| refused(&app))?;
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a) })))
}

/// The body of a sign-in with a recovery code.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryLogin {
    /// The account's handle.
    handle: String,
    /// The recovery code, in any case and with or without hyphens.
    code: String,
}

/// Sign in with a one-use recovery code (audited); the answer says how many remain.
async fn recovery_login(State(app): State<Shared>, Json(b): Json<RecoveryLogin>) -> ApiResult<Response> {
    // A code that cannot be one is refused like a wrong one.
    let code = recovery::normalise(&b.code).ok_or_else(|| refused(&app))?;
    let account = app
        .store
        // The code is used up in the same statement that finds it.
        .use_recovery_code(&b.handle.trim().to_ascii_lowercase(), &recovery::hash(&code), now())
        .await?
        .ok_or_else(|| refused(&app))?;
    let a = app.store.account(account).await?.ok_or_else(|| refused(&app))?;
    app.store.audit(&format!("account:{}", a.id), "recovery-code-used", &a.id.to_string(), &json!({})).await?;
    // So the holder knows when to replace them.
    let left = app.store.recovery_codes_left(a.id).await?;
    Metrics::inc(&app.metrics.signins);
    let cookie = start_session(&app, a.id).await?;
    Ok(with_cookie(cookie, json!({ "account": account_json(&app, &a), "recoveryCodesLeft": left })))
}

/// End this session and clear the cookie.
async fn logout(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    // Signing out with no session is not an error.
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

/// The signed-in account with its sign-in methods and how many recovery codes are left.
async fn me(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // Only the signed-in account's own details are shown.
    let a = account(&app, &headers).await?;
    // The passkeys' ids and names, never their keys.
    let passkeys: Vec<Value> = app
        .store
        .passkeys(a.id)
        .await?
        .into_iter()
        .map(|(id, _, name)| json!({ "id": hex::encode(id), "name": name }))
        .collect();
    // The account's own view, with its sign-in methods added.
    let mut body = account_json(&app, &a);
    body["passkeys"] = json!(passkeys);
    body["wallets"] = json!(app.store.wallets(a.id).await?);
    body["recoveryCodesLeft"] = json!(app.store.recovery_codes_left(a.id).await?);
    Ok(Json(body))
}

/// The invite codes the operator gave this account to pass on.
async fn me_invites(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The account holder's own invites only.
    let a = account(&app, &headers).await?;
    // The codes still to pass on, and how many were used.
    let (codes, redeemed) = app.store.held_codes(a.id, now()).await?;
    let codes: Vec<Value> = codes.into_iter().map(|(c, exp)| json!({ "code": c, "expiresAt": ts(exp) })).collect();
    // An account that may no longer share invites is shown none.
    Ok(Json(json!({ "codes": if a.may_share_invites { codes } else { Vec::new() }, "redeemed": redeemed })))
}

/// Begin adding a passkey to the account (at most ten; existing ones are excluded so the authenticator does not make a second).
async fn me_passkey_start(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // At most ten passkeys; the existing ones are excluded so the authenticator does not make a second.
    // Adding a passkey needs a session.
    let a = account(&app, &headers).await?;
    let existing: Vec<Value> = app.store.passkeys(a.id).await?.into_iter().map(|(_, p, _)| p).collect();
    // A cap on passkeys per account.
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

/// The body that finishes adding a passkey.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasskeyAdd {
    /// The id of the ceremony.
    challenge: String,
    /// The browser's answer.
    credential: Value,
    /// A name for the passkey.
    name: Option<String>,
}

/// Finish adding a passkey; the ceremony must be this account's own.
async fn me_passkey_finish(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<PasskeyAdd>,
) -> ApiResult<StatusCode> {
    // The ceremony is bound to the signed-in account.
    let a = account(&app, &headers).await?;
    let Some((Some(owner), state)) = app.store.take_challenge(&b.challenge, "passkey-register", now()).await? else {
        return Err(ApiError::Unprocessable("That expired; start again.".into()));
    };
    // A ceremony cannot be finished by another account.
    if owner != a.id {
        return Err(ApiError::Forbidden("that ceremony belongs to another account"));
    }
    let (cred, passkey) = app
        .passkeys
        .finish_register(&b.credential, &state["state"])
        .map_err(|_| ApiError::Unprocessable("The passkey could not be verified.".into()))?;
    // A bounded name, or the default.
    let name = b.name.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.len() <= 60).unwrap_or("Passkey");
    app.store.add_passkey(a.id, &cred, &passkey, name).await?;
    app.store.audit(&format!("account:{}", a.id), "passkey-added", &a.id.to_string(), &json!({ "name": name })).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove a passkey, unless it is the last way to sign in.
async fn me_passkey_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    // A passkey is removed only by its owner.
    let a = account(&app, &headers).await?;
    // The credential id is its hex form in the path.
    let cred = hex::decode(&id).map_err(|_| ApiError::NotFound)?;
    if app.store.delete_passkey(a.id, &cred).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict("Keep at least one way to sign in.".into()))
    }
}

/// Begin linking a wallet: the message to sign names the account.
async fn me_wallet_start(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<WalletStart>,
) -> ApiResult<Json<Value>> {
    // Linking a wallet needs a session.
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

/// Finish linking a wallet; the ceremony must be this account's own and the wallet must not belong to another account.
async fn me_wallet_finish(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<WalletFinish>,
) -> ApiResult<StatusCode> {
    // The ceremony is bound to the signed-in account.
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

/// Unlink a wallet, unless it is the last way to sign in.
async fn me_wallet_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(address): Path<String>,
) -> ApiResult<StatusCode> {
    // A wallet is unlinked only by its owner.
    let a = account(&app, &headers).await?;
    // The address in its canonical form.
    let address = wallet::canonical_address(&address).ok_or(ApiError::NotFound)?;
    if app.store.delete_wallet(a.id, &address).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::Conflict("Keep at least one way to sign in.".into()))
    }
}

/// Replace the recovery codes; the new ones are shown once.
async fn me_recovery_codes(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // Replacing the codes needs a session.
    let a = account(&app, &headers).await?;
    let (codes, hashes) = recovery::generate();
    app.store.set_recovery_codes(a.id, &hashes).await?;
    app.store.audit(&format!("account:{}", a.id), "recovery-codes-replaced", &a.id.to_string(), &json!({})).await?;
    Ok(Json(json!({ "recoveryCodes": codes })))
}

/// The body that declares the account's country.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CountryBody {
    /// The country, or none to clear it.
    country: Option<String>,
}

/// Declare, change or clear the account's country.
async fn me_country(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<CountryBody>,
) -> ApiResult<StatusCode> {
    // Declaring a country needs a session.
    let a = account(&app, &headers).await?;
    app.store.set_country(a.id, country(b.country.as_deref())?.as_deref()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The body that deletes the account.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteBody {
    /// The account's own handle, typed to confirm.
    confirm: String,
}

/// Delete the account at its holder's request: they must type their own handle, the account is erased, its page forgotten and the cookie cleared.
async fn me_delete(State(app): State<Shared>, headers: HeaderMap, Json(b): Json<DeleteBody>) -> ApiResult<Response> {
    // The holder must type their own handle; the account is erased, the page forgotten and the cookie cleared.
    // Deleting needs a session.
    let a = account(&app, &headers).await?;
    // The holder types their own handle to confirm.
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

/// Everything stored about the account that is theirs to take (the draft and published pages, versions, sign-in method names, domains, billing, decisions and appeals) as one JSON download.
async fn me_export(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    // The export is of the signed-in account only.
    let a = account(&app, &headers).await?;
    let page = app.store.page(a.id).await?;
    let body = json!({
        // Everything below is the account's own data.
        "exportedAt": ts(now()),
        "account": account_json(&app, &a),
        "page": page.map(|p| json!({
            "draft": serde_json::from_str::<Value>(&p.draft).unwrap_or(Value::Null),
            "published": p.published.and_then(|x| serde_json::from_str::<Value>(&x).ok()),
            "version": p.version, "publishedAt": p.published_at.map(ts),
        })),
        // Older versions are listed by number and time only; their documents are not in the export yet (audit F36, FU-0206).
        "versions": app.store.page_versions(a.id).await?.into_iter().map(|(v, t)| json!({ "version": v, "at": ts(t) })).collect::<Vec<_>>(),
        // The names of the sign-in methods, never their keys: a passkey id and its label are enough to recognise it.
        "passkeys": app.store.passkeys(a.id).await?.into_iter().map(|(id, _, name)| json!({ "id": hex::encode(id), "name": name })).collect::<Vec<_>>(),
        "wallets": app.store.wallets(a.id).await?,
        // The custom domains the account asked for and how far each got.
        "domains": app.store.domains(a.id).await?.into_iter().map(|d| json!({ "hostname": d.hostname, "status": d.status })).collect::<Vec<_>>(),
        // What was paid for: provider, kind, months and amount, and nothing else about the payment.
        "billing": app.store.billing_events(a.id).await?.into_iter().map(|e| json!({
            "provider": e.provider, "kind": e.kind, "months": e.months, "amountPence": e.amount_pence, "at": ts(e.created_at),
        })).collect::<Vec<_>>(),
        // Moderation decisions about the account, with their statements of reasons.
        "statements": app.store.statements_for(a.id).await?.into_iter().map(|r| json!({
            "decision": r.decision, "statement": r.statement, "at": r.decided_at.map(ts),
        })).collect::<Vec<_>>(),
        // The account's own appeals and their outcomes.
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

/// The host name of an account's page.
fn page_host(app: &Shared, handle: &str) -> String {
    format!("{handle}.{}", app.config.pages_domain)
}

/// The rules an account's page is parsed with.
fn tenant_options() -> ParseOptions {
    super::account_page_options()
}

/// Parses an edited document for an account: the parser's rules, plus the account's own handle and pictures.
async fn check_document(app: &Shared, a: &Account, bytes: &[u8]) -> ApiResult<(Manifest, Vec<Issue>)> {
    // The parser's rules first; its errors are the answer.
    let parsed = link_in_bio_core::parse(bytes, tenant_options()).map_err(ApiError::Issues)?;
    let mut issues = Vec::new();
    // The page must carry the account's own handle.
    if parsed.manifest.identity.handle != a.handle {
        issues.push(Issue::new("identity/handle", "handle_mismatch", "The handle must be your account's handle."));
    }
    // A picture must be one this account uploaded.
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

/// The screening verdict of each shown link, or "unchecked".
async fn screening_of(app: &Shared, m: &Manifest) -> ApiResult<Vec<Value>> {
    let urls: Vec<String> = m.visible_links().map(|l| l.url.clone()).collect();
    let hashes: Vec<Vec<u8>> = urls.iter().map(|u| sha256(u.as_bytes())).collect();
    // The stored verdicts for those hashes.
    let screens = app.store.screens(&hashes).await?;
    Ok(urls
        .iter()
        .map(|u| {
            let s = screens.iter().find(|s| &s.url == u);
            json!({ "url": u, "verdict": s.map_or("unchecked", |s| s.verdict.as_str()), "detail": s.map(|s| s.detail.clone()) })
        })
        .collect())
}

/// The draft, its problems and its links' screening. The draft is checked again each time, so the editor always shows the current problems.
async fn page_get(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The draft is checked again each time, so the editor always shows the current problems and the links' screening.
    // The editor's view of the draft.
    let a = account(&app, &headers).await?;
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    // The draft as JSON for the editor.
    let draft: Value = serde_json::from_str(&p.draft).unwrap_or(Value::Null);
    // Problems in the stored draft are shown, not fatal here.
    let (warnings, screening) = match check_document(&app, &a, p.draft.as_bytes()).await {
        Ok((m, w)) => (w, screening_of(&app, &m).await?),
        Err(ApiError::Issues(i)) => (i, Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(Json(json!({
        "draft": draft, "published": p.published.is_some(), "version": p.version, "updatedAt": ts(p.updated_at),
        "publishedAt": p.published_at.map(ts), "url": page_url(&app, &a.handle), "issues": warnings, "screening": screening,
        "changed": p.published.as_deref() != Some(p.draft.as_str()),
    })))
}

/// Save the draft after checking it; what is stored is the canonical form.
async fn page_put(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> ApiResult<Json<Value>> {
    // Saving a draft needs a session.
    let a = account(&app, &headers).await?;
    let (m, warnings) = check_document(&app, &a, &body).await?;
    app.store.save_draft(a.id, &m.to_json(), now()).await?;
    Ok(Json(json!({ "saved": true, "warnings": warnings })))
}

/// The draft rendered by the real renderer, for the editor's sandboxed preview frame. Pictures are served by hash
/// from `/api/v1/assets/` (the frame is sandboxed, so it carries no cookie).
async fn page_preview(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Response> {
    // The preview is of the signed-in account's own draft.
    let a = account(&app, &headers).await?;
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    let (manifest, warnings) = check_document(&app, &a, p.draft.as_bytes()).await?;
    // The host the page would have.
    let host = page_host(&app, &a.handle);
    let config = app.config.site_for(&a.handle, &host).map_err(|_| ApiError::Internal)?;
    let picture = match manifest.identity.avatar.as_deref().and_then(|x| x.strip_prefix("sha256:")) {
        Some(hex) => app.store.view_asset(hex).await?,
        None => None,
    };
    // The picture as the renderer takes it.
    let pic = picture.clone().and_then(super::pages::picture_of);
    let site = Site::from_parts(config, manifest, warnings, pic.clone(), None, now().unix_timestamp().max(0) as u64);
    // The preview loads pictures from the app host, so their addresses are rewritten.
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
    // The usual page headers, then the preview's own policy below.
    crate::headers::secure(h, false, true);
    // The preview may be framed by the app itself, and only by it.
    // The editor frames the preview.
    h.remove(header::X_FRAME_OPTIONS);
    // `sandbox`: the draft runs with an opaque origin and no script even if it is opened outside the editor's frame
    // (which is sandboxed the same way), so a tenant's document never runs as the app's origin.
    let csp = crate::headers::page_csp()
        .replace("frame-ancestors 'none'", &format!("frame-ancestors {}; sandbox", app.config.app_origin));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&csp).map_err(|_| ApiError::Internal)?);
    Ok(r)
}

/// Publish the draft as the next version: the account must be entitled, its budgets are taken first, and every link not screened (or due, or stale) is screened before the page goes out.
async fn page_publish(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // Entitlement and the account's budgets come first; then every link not screened, due or stale is screened before the page goes out; the page is published as the next version.
    // Publishing needs a session.
    let a = account(&app, &headers).await?;
    let n = now();
    // Publishing needs a paid period or a free account.
    if !a.entitled(n, Duration::days(app.config.grace_days)) {
        return Err(ApiError::Conflict("Buy a paid period to publish your page.".into()));
    }
    let p = app.store.page(a.id).await?.ok_or(ApiError::NotFound)?;
    let (m, _) = check_document(&app, &a, p.draft.as_bytes()).await?;
    // The account's budgets (CHANGES_PER_ACCOUNT_HOUR, NEW_LINKS_PER_ACCOUNT_DAY), taken before anything is screened.
    // A publish that only removes or hides links is never limited.
    let published = p
        .published
        .as_deref()
        .and_then(|d| link_in_bio_core::parse(d.as_bytes(), tenant_options()).ok())
        .map(|x| x.manifest);
    // A publish that only removes or hides links is never limited.
    let removes_only = published.as_ref().is_some_and(|o| super::limits::only_removes(o, &m));
    // Links the published page did not show are what the daily budget counts.
    let new_links = super::limits::new_urls(published.as_ref(), &m).len();
    if !removes_only && let Err(e) = super::limits::take(&app, a.id, new_links, false, n).await {
        Metrics::inc(&app.metrics.limited);
        return Err(e);
    }
    // Screen every link not screened yet, due, or stale before the page goes out (at most 60 links: the parser's
    // limit). Stale: older than a clean verdict holds (lookup mode's rechecks skip links no published page shows).
    let urls: Vec<String> = m.visible_links().map(|l| l.url.clone()).collect();
    let hashes: Vec<Vec<u8>> = urls.iter().map(|u| sha256(u.as_bytes())).collect();
    let known = app.store.screens(&hashes).await?;
    // Each link is screened unless its verdict is fresh or an operator's.
    for u in &urls {
        let fresh = known.iter().find(|s| &s.url == u).is_some_and(|s| {
            s.overridden_by.is_some() || (s.next_check_at > n && s.checked_at + app.screener.clean_for() > n)
        });
        if !fresh {
            app.screener.screen_and_record(&app.store, u, n).await?;
            Metrics::inc(&app.metrics.screenings);
        }
    }
    // The canonical document becomes the next version.
    let version = app.store.publish(a.id, &m.to_json(), n).await?;
    app.store
        .audit(
            &format!("account:{}", a.id),
            "publish",
            &a.id.to_string(),
            &json!({ "version": version, "newLinks": new_links, "removesOnly": removes_only }),
        )
        .await?;
    app.pages.forget(&page_host(&app, &a.handle)).await;
    Metrics::inc(&app.metrics.publishes);
    let screening = screening_of(&app, &m).await?;
    // Links screening flagged are hidden from the page; the holder is told which.
    let hidden: Vec<&Value> = screening.iter().filter(|s| s["verdict"] == "flagged").collect();
    Ok(Json(json!({
        "version": version, "url": page_url(&app, &a.handle), "hidden": hidden,
        "online": app.config.third_party_pages || a.operator,
    })))
}

/// Take the page offline (audited).
async fn page_unpublish(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<StatusCode> {
    // Unpublishing needs a session.
    let a = account(&app, &headers).await?;
    app.store.unpublish(a.id).await?;
    // Recorded like a publish, so the console shows who took a page offline and when.
    app.store.audit(&format!("account:{}", a.id), "unpublish", &a.id.to_string(), &json!({})).await?;
    app.pages.forget(&page_host(&app, &a.handle)).await;
    Ok(StatusCode::NO_CONTENT)
}

/// The numbers and times of the kept versions.
async fn page_versions(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The versions of the signed-in account's own page.
    let a = account(&app, &headers).await?;
    let v: Vec<Value> =
        app.store.page_versions(a.id).await?.into_iter().map(|(v, t)| json!({ "version": v, "at": ts(t) })).collect();
    Ok(Json(json!({ "versions": v })))
}

/// Copy a kept version into the draft; nothing is published.
async fn page_restore(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(version): Path<i32>,
) -> ApiResult<StatusCode> {
    // Restoring needs a session.
    let a = account(&app, &headers).await?;
    let doc = app.store.page_version(a.id, version).await?.ok_or(ApiError::NotFound)?;
    app.store.save_draft(a.id, &doc, now()).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Upload a picture: it counts as a change, is decoded off the async workers one at a time, and must fit the account's picture quota; what is stored is the re-encoded picture.
async fn avatar_upload(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> ApiResult<Json<Value>> {
    // The upload counts as a change, is decoded off the async workers one at a time, and must fit the account's picture quota.
    // Uploads need a session.
    let a = account(&app, &headers).await?;
    // Uploads are changes too (CHANGES_PER_ACCOUNT_HOUR, one count with publishes), taken before the picture is decoded.
    if let Err(e) = super::limits::take(&app, a.id, 0, true, now()).await {
        Metrics::inc(&app.metrics.limited);
        return Err(e);
    }
    let pic = {
        // One decode at a time in this process, so memory stays bounded.
        let _turn = app.pictures.acquire().await.map_err(|_| ApiError::Internal)?;
        tokio::task::spawn_blocking(move || link_in_bio_assets::normalise_raster(&body))
            .await
            .map_err(|_| ApiError::Internal)?
            .map_err(|e| ApiError::Unprocessable(e.to_string()))?
    };
    // The account's picture quota.
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
    // The file name is the picture's full hash and its extension; it is cached for a year and served inside its own sandbox.
    let (hex, ext) = file.split_once('.').ok_or(ApiError::NotFound)?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::NotFound);
    }
    let a = app.store.view_asset(hex).await?.filter(|a| a.ext == ext).ok_or(ApiError::NotFound)?;
    let mut r = Response::new(Body::from(a.bytes));
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&a.mime).map_err(|_| ApiError::Internal)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(crate::headers::CACHE_IMMUTABLE));
    // A picture served on its own can run nothing.
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

/// The two pieces of country evidence for a purchase.
fn evidence(a: &Account, headers: &HeaderMap) -> Evidence {
    Evidence { declared: a.country_declared.clone(), request: request_country(headers) }
}

/// The billing view: the paid period, the methods on offer now, past payments with the refund state of each, and the account's refund requests.
async fn billing(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The paid period, the methods on offer now, past payments with the refund state of each, and the holder's refund requests.
    // The billing view is the account's own.
    let a = account(&app, &headers).await?;
    let n = now();
    // What this buyer may use now, from their country evidence and their period.
    let offers = app.billing.offers(&evidence(&a, &headers), months_ahead(a.paid_until, n));
    let all_requests = app.store.refund_requests_of(a.id).await?;
    let lines = app.store.refund_lines(&all_requests.iter().map(|r| r.id).collect::<Vec<_>>()).await?;
    // The old-style requests by the late payment they name.
    let requests: BTreeMap<Uuid, &link_in_bio_store::RefundRequest> =
        all_requests.iter().filter_map(|r| r.event_id.map(|e| (e, r))).collect();
    let events: Vec<Value> = app
        .store
        .billing_events(a.id)
        .await?
        .into_iter()
        .map(|e| {
            let request = requests.get(&e.id).map(|r| {
                json!({ "id": r.id, "status": r.status, "refundReference": r.refund_reference, "at": ts(r.created_at), "decidedAt": r.decided_at.map(ts) })
            });
            // A late payment can be asked back until the window closes, once.
            let refundable_until = (request.is_none() && refundable(&e, n)).then(|| e.created_at + REFUND_WINDOW);
            json!({
                "id": e.id, "provider": e.provider, "kind": e.kind, "months": e.months, "amountPence": e.amount_pence,
                "at": ts(e.created_at), "paidUntil": e.paid_until_after.map(ts), "unapplied": e.unapplied,
                "refundableUntil": refundable_until.map(ts), "refundRequest": request,
            })
        })
        .collect();
    Ok(Json(json!({
        "free": a.free, "paidUntil": a.paid_until.map(ts), "entitled": a.entitled(n, Duration::days(app.config.grace_days)),
        "pricePence": offers.price_pence, "currency": "GBP", "offers": offers.offers, "notes": offers.notes, "events": events,
        "refundRequests": all_requests.iter().map(|r| request_json(r, &lines)).collect::<Vec<_>>(),
    })))
}

/// A refund request as its account holder sees it.
fn request_json(r: &link_in_bio_store::RefundRequest, lines: &[link_in_bio_store::RefundLine]) -> Value {
    json!({
        "id": r.id, "kind": r.kind, "status": r.status, "reason": r.reason, "at": ts(r.created_at),
        "decidedAt": r.decided_at.map(ts), "refundReference": r.refund_reference, "details": r.details,
        "lines": lines.iter().filter(|l| l.request_id == r.id).map(super::refunds::line_json).collect::<Vec<_>>(),
    })
}

/// How long after an unapplied payment its account holder may ask for a refund instead of the months.
pub const REFUND_WINDOW: Duration = link_in_bio_billing::refunds::UNAPPLIED_WINDOW;

/// An unapplied Chain Payments payment, credited as months, within the refund window.
fn refundable(e: &link_in_bio_store::BillingEvent, n: time::OffsetDateTime) -> bool {
    e.unapplied
        && e.provider == link_in_bio_billing::chain_payments::ID
        && e.kind == "purchase"
        && e.created_at + REFUND_WINDOW > n
}

/// What the signed-in account may ask back now, worked out exactly: each purchase it may cancel (within 14 days), its
/// unstarted months (newest purchases first), late payments it may have back whole, and its open request if any.
async fn refunds(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    use link_in_bio_billing::refunds as r;
    // The refund view is the account's own.
    let a = account(&app, &headers).await?;
    let n = now();
    // Every purchase as a refund entry.
    let history = super::refunds::history(&app, &a).await?;
    // The account's one open request, if any.
    let open = app.store.refund_requests_of(a.id).await?.into_iter().find(|q| q.status == "open");
    let open_lines = match &open {
        Some(q) => app.store.refund_lines(&[q.id]).await?,
        None => Vec::new(),
    };
    let answer = |o: Result<r::Offer, r::Refusal>| match o {
        Ok(o) => json!({ "offer": super::refunds::offer_json(&o) }),
        Err(e) => json!({ "refused": e.0 }),
    };
    // Each purchase still inside the 14-day window.
    let cancel: Vec<Value> = history
        .iter()
        .filter(|e| e.kind == "purchase" && !e.unapplied && e.at + r::CANCEL_WINDOW > n)
        .map(|e| {
            let mut v = answer(r::cancel(e, n));
            v["purchase"] = json!(e.id);
            v["at"] = json!(ts(e.at));
            v
        })
        .collect();
    // Each late payment still inside its 30-day window.
    let unapplied: Vec<Value> = history
        .iter()
        .filter(|e| e.unapplied && e.at + r::UNAPPLIED_WINDOW > n)
        .map(|e| {
            let mut v = answer(r::unapplied(e, n));
            v["purchase"] = json!(e.id);
            v
        })
        .collect();
    Ok(Json(json!({
        "openRequest": open.as_ref().map(|q| request_json(q, &open_lines)),
        "cancel": cancel,
        "unstarted": {
            "months": r::refundable_unstarted(&history, a.paid_until, n),
            "all": answer(r::unstarted(&history, a.paid_until, n, None)),
        },
        "unapplied": unapplied,
        "rules": {
            "cancelDays": r::CANCEL_WINDOW.whole_days(), "unappliedDays": r::UNAPPLIED_WINDOW.whole_days(),
            "daysPerMonth": r::DAYS_PER_MONTH,
        },
    })))
}

/// The body that asks for a refund.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundAsk {
    /// `cancel` (one purchase, within 14 days), `unstarted` (months that have not begun) or `unapplied` (a late
    /// payment, whole).
    kind: String,
    /// The purchase, for `cancel` and `unapplied`.
    #[serde(default)]
    purchase: Option<Uuid>,
    /// For `unstarted`: how many (all of them when absent).
    #[serde(default)]
    months: Option<u32>,
    /// Why, in up to 1000 characters.
    #[serde(default)]
    reason: String,
}

/// A refund reason: at most 1000 characters of text.
fn clean_reason(reason: &str) -> ApiResult<&str> {
    let reason = reason.trim();
    if reason.chars().count() > 1000 || reason.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::Unprocessable("The reason is at most 1000 characters of text.".into()));
    }
    Ok(reason)
}

/// Works out the refund asked for, now, and records it as one open request (the account's only one) for the operator,
/// who sends it by hand. Nothing is refunded and no month is taken back until then.
async fn ask_refund(app: &Shared, a: &Account, b: &RefundAsk) -> ApiResult<(StatusCode, Json<Value>)> {
    use link_in_bio_billing::refunds as r;
    // The reason is bounded text.
    let reason = clean_reason(&b.reason)?;
    let n = now();
    let history = super::refunds::history(app, a).await?;
    // The purchase the holder named, from their own history.
    let purchase = || -> ApiResult<&r::Entry> {
        let id = b.purchase.ok_or_else(|| ApiError::BadRequest("name the purchase".into()))?;
        history.iter().find(|e| e.id == id).ok_or(ApiError::NotFound)
    };
    // Each kind of refund has its own rule; the offer is worked out now.
    let (offer, event) = match b.kind.as_str() {
        "cancel" => (r::cancel(purchase()?, n), None),
        "unapplied" => {
            let p = purchase()?;
            (r::unapplied(p, n), Some(p.id))
        }
        "unstarted" => (r::unstarted(&history, a.paid_until, n, b.months), None),
        _ => return Err(ApiError::BadRequest("kind is cancel, unstarted or unapplied".into())),
    };
    let offer = offer.map_err(|e| ApiError::Unprocessable(e.0))?;
    // What each purchase gives back, as rows to store.
    let lines = super::refunds::new_lines(&offer);
    let id = match app
        .store
        .create_refund_request_lines(
            a.id,
            offer.kind.as_str(),
            event,
            reason,
            &super::refunds::details(&offer, n),
            &lines,
            n,
        )
        .await?
    {
        Ok(id) => id,
        // One open request per account.
        Err(link_in_bio_store::RefundConflict::OpenRequest) => {
            return Err(ApiError::Conflict(
                "You already have an open refund request: withdraw it, or wait for the operator to send it.".into(),
            ));
        }
        Err(link_in_bio_store::RefundConflict::AlreadyAsked) => {
            return Err(ApiError::Conflict("A refund was already asked for this payment.".into()));
        }
    };
    let offer_json = super::refunds::offer_json(&offer);
    app.store
        .audit(
            &format!("account:{}", a.id),
            "refund-requested",
            &a.id.to_string(),
            &json!({ "request": id, "kind": offer.kind, "months": offer.months, "lines": offer_json["lines"], "reason": reason }),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(json!({ "refundRequest": id, "status": "open", "offer": offer_json }))))
}

/// Ask for a refund (cancel, unstarted months or a late payment).
async fn refund_ask(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<RefundAsk>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // Asking for a refund needs a session.
    let a = account(&app, &headers).await?;
    ask_refund(&app, &a, &b).await
}

/// Withdraws the account's open request (before the operator has refunded any of it).
async fn refund_withdraw(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    // Withdrawing needs a session.
    let a = account(&app, &headers).await?;
    let lines = app.store.refund_lines(&[id]).await?;
    // A request part-refunded cannot be withdrawn.
    if lines.iter().any(|l| l.status == "refunded") {
        return Err(ApiError::Conflict("Part of this request has been refunded already; ask the operator.".into()));
    }
    let actor = format!("account:{}", a.id);
    if !app.store.close_refund_request(id, Some(a.id), "withdrawn", &actor, "", now()).await? {
        return Err(ApiError::NotFound);
    }
    app.store.audit(&actor, "refund-withdrawn", &a.id.to_string(), &json!({ "request": id })).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The optional body of the older refund-request route.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RefundRequestBody {
    /// Why, optional.
    #[serde(default)]
    reason: String,
}

/// Asks for a refund of an unapplied payment instead of the months it was credited as (once per payment, within 30
/// days): the same as `POST /api/v1/billing/refund-requests` with `kind: unapplied`.
async fn refund_request(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(event): Path<Uuid>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // The older route: the same as asking for `unapplied`, with an optional reason.
    // The older refund route needs a session too.
    let a = account(&app, &headers).await?;
    // An empty body is a request with no reason.
    let b: RefundRequestBody = if body.iter().all(u8::is_ascii_whitespace) {
        RefundRequestBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| ApiError::BadRequest(format!("not a refund request: {e}")))?
    };
    let ask = RefundAsk { kind: "unapplied".into(), purchase: Some(event), months: None, reason: b.reason };
    let (status, Json(mut v)) = ask_refund(&app, &a, &ask).await?;
    v["event"] = json!(event);
    Ok((status, Json(v)))
}

/// The body that starts a checkout.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckoutBody {
    /// The method chosen, as the billing view lists it.
    method: String,
    /// How many months to buy.
    months: u32,
}

/// Start a checkout: the method and months must be on offer to this buyer; it is created at the provider first and then recorded with the method's fees as they are now.
async fn checkout_create(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<CheckoutBody>,
) -> ApiResult<Json<Value>> {
    // The method and months must be on offer to this buyer; the checkout is created at the provider first, then recorded with the method's fees as they are now.
    // Starting a checkout needs a session.
    let a = account(&app, &headers).await?;
    let n = now();
    // The two countries at purchase time, kept with the checkout.
    let ev = evidence(&a, &headers);
    // The method and months must be on offer to this buyer.
    let offer = app.billing.check(&ev, months_ahead(a.paid_until, n), &b.method, b.months).ok_or_else(|| {
        ApiError::Unprocessable("That payment method or number of months is not available to you.".into())
    })?;
    let provider = app
        .billing
        .provider(&offer.method.provider)
        .ok_or(ApiError::Unavailable("that payment method is switched off"))?;
    let id = Uuid::new_v4();
    // The price is the configured month price times the months, in pence.
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
            return_url: format!("{}/billing?checkout={id}", app.config.app_origin),
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
            // The method's fees now: a refund's fee share uses these, whatever is configured later.
            fee_fixed_pence: Some(offer.method.fees.fixed_pence as i32),
            fee_percent_bps: Some(offer.method.fees.percent_bps as i32),
        })
        .await?;
    Metrics::inc(&app.metrics.checkouts);
    Ok(Json(json!({ "checkout": id, "amountPence": amount, "client": start.client })))
}

/// How a checkout stands. An Open Payments checkout whose payment was sent is settled by asking the operator's wallet, so the page shows the result without a notification.
async fn checkout_get(State(app): State<Shared>, headers: HeaderMap, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    // A checkout is shown only to the account that made it.
    let a = account(&app, &headers).await?;
    // Another account's checkout is not found.
    let mut c = app.store.checkout(id).await?.filter(|c| c.account_id == a.id).ok_or(ApiError::NotFound)?;
    // An Open Payments checkout whose outgoing payment was sent: ask the operator's wallet whether it has arrived.
    if c.status == "open"
        && c.provider == open_payments::ID
        && app.store.open_payments_grant(c.id).await?.is_some_and(|(status, _)| status == "sent")
    {
        open_payments_settle(&app, &c, json!({ "source": "poll" })).await?;
        c = app.store.checkout(id).await?.ok_or(ApiError::NotFound)?;
    }
    // The account again, for its new paid period.
    let fresh = app.store.account(a.id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "checkout": c.id, "status": c.status, "months": c.months, "paidUntil": fresh.paid_until.map(ts) })))
}

// ── Open Payments: the steps after the checkout ──────────────────────────────────────────────────────────────────

/// An open Open Payments checkout of the signed-in account, and the adapter.
async fn open_payments_checkout(
    app: &Shared,
    headers: &HeaderMap,
    id: Uuid,
) -> ApiResult<(Checkout, std::sync::Arc<open_payments::OpenPayments>)> {
    let a = account(app, headers).await?;
    let c = app
        .store
        .checkout(id)
        .await?
        .filter(|c| c.account_id == a.id && c.provider == open_payments::ID)
        .ok_or(ApiError::NotFound)?;
    // A closed checkout cannot continue.
    if c.status != "open" {
        return Err(ApiError::Conflict(format!("This checkout is {}.", c.status)));
    }
    let p = app.open_payments.clone().ok_or(ApiError::Unavailable("Open Payments is switched off"))?;
    Ok((c, p))
}

/// A wallet failure as the buyer is told it: unavailable, not this payment's answer, a wallet that cannot be used, or a refusal.
fn wallet_error(e: BillingError) -> ApiError {
    tracing::info!(error = %e, "open payments");
    match e {
        BillingError::Unavailable(_) => ApiError::Unavailable("the wallet did not answer; try again shortly"),
        BillingError::Unauthentic => {
            ApiError::BadRequest("The wallet's answer does not belong to this payment.".into())
        }
        BillingError::Malformed(m) => ApiError::Unprocessable(format!("That wallet cannot be used: {m}.")),
        BillingError::Refused(m) => ApiError::Unprocessable(format!("The wallet refused: {m}.")),
        BillingError::NotOffered => ApiError::Unprocessable("That payment method is not available.".into()),
    }
}

/// Asks the operator's wallet how the checkout's incoming payment stands, and applies the payment once it has
/// arrived in full.
async fn open_payments_settle(app: &Shared, c: &Checkout, evidence: Value) -> ApiResult<link_in_bio_billing::Outcome> {
    let Some(p) = app.billing.provider(open_payments::ID) else { return Ok(link_in_bio_billing::Outcome::Open) };
    // Ask the operator's wallet how the incoming payment stands.
    let outcome = p.checkout_outcome(&c.provider_ref).await.map_err(wallet_error)?;
    if outcome == link_in_bio_billing::Outcome::Paid {
        let e = link_in_bio_billing::ProviderEvent {
            event_id: p.paid_event_id(&c.provider_ref),
            provider_ref: c.provider_ref.clone(),
            outcome: link_in_bio_billing::Outcome::Paid,
            paid: None,
            refunded: None,
            evidence,
        };
        super::internal::apply_event(app, open_payments::ID, &e).await?;
    }
    Ok(outcome)
}

/// The body that gives the buyer's wallet address.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenPaymentsStart {
    /// The buyer's wallet address or payment pointer.
    wallet_address: String,
}

/// The buyer's wallet address: a quote and an outgoing-payment grant there, approved on the wallet's own page.
async fn open_payments_start(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<OpenPaymentsStart>,
) -> ApiResult<Json<Value>> {
    let (c, p) = open_payments_checkout(&app, &headers, id).await?;
    // Where the wallet sends the buyer back.
    let finish = format!("{}/billing?checkout={id}&openPayments=finish", app.config.app_origin);
    let pending = p.start_payment(&c.provider_ref, &b.wallet_address, &finish).await.map_err(wallet_error)?;
    // The pending grant holds a continuation token, so it is kept only until the grant is finished.
    let stored = serde_json::to_value(&pending).map_err(|_| ApiError::Internal)?;
    if !app.store.put_open_payments_grant(c.id, &pending.buyer_wallet, &stored).await? {
        return Err(ApiError::Conflict("A payment was already sent for this checkout.".into()));
    }
    Ok(Json(json!({
        "kind": "open-payments", "step": "redirect", "redirect": pending.redirect, "wallet": pending.buyer_wallet,
        "debitAmount": pending.debit_amount, "receiveAmount": pending.receive_amount,
    })))
}

/// The body that comes back from the wallet.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenPaymentsFinish {
    /// The interaction hash the wallet's redirect carried.
    hash: String,
    /// The interaction reference the redirect carried.
    interact_ref: String,
}

/// Back from the wallet (the `hash` and `interact_ref` of the finish redirect): the hash is checked, the grant
/// continued and the outgoing payment created; the checkout is paid once the operator's wallet has received it all.
async fn open_payments_finish(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(b): Json<OpenPaymentsFinish>,
) -> ApiResult<Json<Value>> {
    // The hash proves the return is the wallet's answer to this grant; the grant is taken once, so two returns cannot both continue it; a failure marks the grant failed.
    let (c, p) = open_payments_checkout(&app, &headers, id).await?;
    // There must be a grant waiting.
    let Some((status, stored)) = app.store.open_payments_grant(c.id).await? else {
        return Err(ApiError::Conflict("No wallet approval is waiting for this checkout.".into()));
    };
    let pending: open_payments::PendingPayment = match status.as_str() {
        "pending" => serde_json::from_value(stored).map_err(|_| ApiError::Internal)?,
        "sent" => return Err(ApiError::Conflict("The payment was already sent; it is being checked.".into())),
        _ => return Err(ApiError::Conflict("No wallet approval is waiting for this checkout.".into())),
    };
    // A redirect that is not the wallet's answer to this grant changes nothing (the real one still works).
    // A redirect that is not the wallet's answer to this grant changes nothing.
    if !open_payments::OpenPayments::finish_hash_valid(&pending, &b.hash, &b.interact_ref) {
        return Err(wallet_error(BillingError::Unauthentic));
    }
    // Taken once, so two returns cannot both continue the grant.
    if app.store.take_open_payments_grant(c.id).await?.is_none() {
        return Err(ApiError::Conflict("This approval is already being used.".into()));
    }
    let outgoing = match p.finish_payment(&pending, &b.hash, &b.interact_ref).await {
        Ok(o) => o,
        Err(e) => {
            app.store.finish_open_payments_grant(c.id, None, now()).await?;
            return Err(wallet_error(e));
        }
    };
    // The grant is sent; the pending data is removed.
    app.store.finish_open_payments_grant(c.id, Some(&outgoing), now()).await?;
    let evidence = json!({ "source": "open-payments", "outgoingPayment": outgoing, "buyerWallet": pending.buyer_wallet,
                           "debitAmount": pending.debit_amount, "receiveAmount": pending.receive_amount });
    let outcome = open_payments_settle(&app, &c, evidence).await?;
    Ok(Json(json!({
        "checkout": c.id, "status": if outcome == link_in_bio_billing::Outcome::Paid { "paid" } else { "open" },
        "outgoingPayment": outgoing,
    })))
}

// ── custom domains ───────────────────────────────────────────────────────────────────────────────────────────────

/// The label under a custom domain where its verification record is published.
pub const DOMAIN_TXT_LABEL: &str = "_link-in-bio";

/// The account's custom domains with the TXT record that verifies each.
async fn domains(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The account's own domains.
    let a = account(&app, &headers).await?;
    let d: Vec<Value> = app
        .store
        .domains(a.id)
        .await?
        .into_iter()
        .map(|d| {
            json!({
                "hostname": d.hostname, "status": d.status, "verifiedAt": d.verified_at.map(ts),
                "record": { "name": format!("{DOMAIN_TXT_LABEL}.{}", d.hostname), "type": "TXT", "value": d.token },
            })
        })
        .collect();
    Ok(Json(json!({ "enabled": app.config.custom_hostname_cap > 0, "domains": d })))
}

/// The body that adds a custom domain.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DomainBody {
    /// The host name.
    hostname: String,
}

/// Add a custom domain: a valid public name that is not under the pages domain; the token to publish in DNS is random.
async fn domain_add(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<DomainBody>,
) -> ApiResult<Json<Value>> {
    // A valid public name that is not under the pages domain; the token to publish is random.
    // Adding a domain needs a session.
    let a = account(&app, &headers).await?;
    // Custom domains are off.
    if app.config.custom_hostname_cap == 0 {
        return Err(ApiError::Forbidden("custom domains are not available"));
    }
    // The service-wide cap on custom domains.
    if app.store.count_domains().await? >= app.config.custom_hostname_cap {
        return Err(ApiError::Conflict("No more custom domains can be added right now.".into()));
    }
    // The host name, normalised.
    let h = b.hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    // A valid public name.
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
    // A host name belongs to one account.
    if !app.store.add_domain(a.id, &h, "dns-txt", &token).await? {
        return Err(ApiError::Conflict("That domain is already in use.".into()));
    }
    Ok(Json(
        json!({ "hostname": h, "record": { "name": format!("{DOMAIN_TXT_LABEL}.{h}"), "type": "TXT", "value": token } }),
    ))
}

/// Remove a domain and forget its cached page.
async fn domain_delete(
    State(app): State<Shared>,
    headers: HeaderMap,
    Path(hostname): Path<String>,
) -> ApiResult<StatusCode> {
    // Removing a domain needs a session.
    let a = account(&app, &headers).await?;
    if app.store.delete_domain(a.id, &hostname.to_ascii_lowercase()).await? {
        app.pages.forget(&hostname.to_ascii_lowercase()).await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

// ── reports and appeals ──────────────────────────────────────────────────────────────────────────────────────────

/// The reasons a report may give; anything else is refused.
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

/// The body of a report.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReportBody {
    /// The page's handle.
    page: String,
    /// The link reported, if one.
    url: Option<String>,
    /// One of the listed reasons.
    reason: String,
    /// What the reporter wrote.
    #[serde(default)]
    details: String,
    /// An optional email address to answer.
    contact: Option<String>,
}

/// A report about a page or one of its links. No account is needed; nobody learns who reported.
async fn report(State(app): State<Shared>, Json(b): Json<ReportBody>) -> ApiResult<(StatusCode, Json<Value>)> {
    // No account is needed and the reporter is not recorded; the details, link and contact are bounded.
    let handle =
        check_handle(&b.page, false).map_err(|_| ApiError::Unprocessable("Name the page by its handle.".into()))?;
    // A reason from the list.
    if !REPORT_REASONS.contains(&b.reason.as_str()) {
        return Err(ApiError::Unprocessable("Choose a reason from the list.".into()));
    }
    // Bounded text.
    let details = b.details.trim();
    if details.chars().count() > 4000 || details.chars().any(|c| c.is_control() && c != '\n') {
        return Err(ApiError::Unprocessable("The details are too long (4000 characters at most).".into()));
    }
    // The link, if any, must be https or mailto.
    let url = match b.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) if u.len() <= 2048 && (u.starts_with("https://") || u.starts_with("mailto:")) => Some(u.to_string()),
        Some(_) => return Err(ApiError::Unprocessable("The link must start with https:// or mailto:.".into())),
        None => None,
    };
    // The contact is optional and only an email address.
    let contact = b.contact.as_deref().map(str::trim).filter(|c| !c.is_empty());
    if contact.is_some_and(|c| c.len() > 320 || !c.contains('@')) {
        return Err(ApiError::Unprocessable("The contact must be an email address (or left empty).".into()));
    }
    let id = app.store.create_report(&handle, url.as_deref(), &b.reason, details, contact, now()).await?;
    // A report is counted, never traced to its sender.
    Metrics::inc(&app.metrics.reports);
    Ok((StatusCode::CREATED, Json(json!({ "report": id }))))
}

/// Decisions about the account's page and the account's appeals.
async fn statements(State(app): State<Shared>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    // The account's own statements.
    let a = account(&app, &headers).await?;
    let s: Vec<Value> = app
        .store
        .statements_for(a.id)
        .await?
        .into_iter()
        .map(|r| json!({ "report": r.id, "reason": r.reason, "decision": r.decision, "statement": r.statement, "decidedAt": r.decided_at.map(ts) }))
        .collect();
    let appeals: Vec<Value> = app
        .store
        .appeals_of(a.id)
        .await?
        .into_iter()
        .map(|x| json!({ "appeal": x.id, "report": x.report_id, "status": x.status, "statement": x.statement, "at": ts(x.created_at) }))
        .collect();
    Ok(Json(json!({ "statements": s, "appeals": appeals })))
}

/// The body of an appeal.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AppealBody {
    /// The report the decision was about, if any.
    report: Option<Uuid>,
    /// Why, in up to 4000 characters.
    text: String,
}

/// An appeal against a decision. A suspended account cannot sign in, so it can also appeal by email (the appeals
/// address in the statement of reasons); this is the route for everyone else.
async fn appeal(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(b): Json<AppealBody>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    // Appealing needs a session.
    let a = account(&app, &headers).await?;
    // The appeal's words.
    let text = b.text.trim();
    if text.is_empty() || text.chars().count() > 4000 {
        return Err(ApiError::Unprocessable("Say why, in 4000 characters at most.".into()));
    }
    if let Some(r) = b.report
        && app.store.report(r).await?.is_none_or(|r| r.account_id != Some(a.id))
    {
        return Err(ApiError::NotFound);
    }
    // An appeal about a report must be about one of the account's own.
    let id = app.store.create_appeal(a.id, b.report, text).await?;
    Ok((StatusCode::CREATED, Json(json!({ "appeal": id }))))
}

// ── router ───────────────────────────────────────────────────────────────────────────────────────────────────────

/// The app's router: the API behind the CSRF guard, the picture upload with its own limit, the providers' webhooks outside the guard, the embedded files and the probe, bounded in time and concurrency.
pub fn router(app: Shared) -> Router {
    // The account API, behind the CSRF guard and a small body limit.
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
        .route("/api/v1/billing/events/{id}/refund-request", post(refund_request))
        .route("/api/v1/billing/refunds", get(refunds))
        .route("/api/v1/billing/refund-requests", post(refund_ask))
        .route("/api/v1/billing/refund-requests/{id}/withdraw", post(refund_withdraw))
        .route("/api/v1/billing/checkouts/{id}", get(checkout_get))
        .route("/api/v1/billing/checkouts/{id}/open-payments", post(open_payments_start))
        .route("/api/v1/billing/checkouts/{id}/open-payments/finish", post(open_payments_finish))
        .route("/api/v1/domains", get(domains).post(domain_add))
        .route("/api/v1/domains/{hostname}", delete(domain_delete))
        .route("/api/v1/reports", post(report))
        .route("/api/v1/appeals", post(appeal))
        .route("/api/v1/assets/{file}", get(asset))
        .layer(DefaultBodyLimit::max(64 * 1024));
    // Pictures are uploaded as their bytes (up to 5 MiB; re-encoded to at most 64 KiB), two at once per process (and
    // decoded one at a time, `App::pictures`).
    // The picture upload has its own, larger limit and a concurrency bound.
    let upload = Router::new()
        .route("/api/v1/page/avatar", post(avatar_upload))
        .layer(DefaultBodyLimit::max(link_in_bio_assets::MAX_INPUT_BYTES))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(2));
    // Payment providers' notifications come from the providers' servers (no Origin, no app header): outside the CSRF
    // guard, authenticated by each adapter's signature check instead.
    // The providers' webhooks: no Origin and no app header, so outside the guard; each adapter's signature check authenticates them.
    let hooks = Router::new()
        .route("/api/v1/webhooks/{provider}", post(provider_notification))
        .layer(DefaultBodyLimit::max(64 * 1024));
    let router = api
        // Merged in before the guard is applied.
        .merge(upload)
        .route("/_/{file}", get(bundle))
        .route("/healthz", get(|| async { "ok\n" }))
        // Any other path is a JSON 404.
        .fallback(|| async { ApiError::NoRoute.into_response() })
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .merge(hooks)
        .with_state(app);
    // 64 requests of at most 64 KiB, plus two pictures of 5 MiB, within the pod's 192 MiB.
    super::bounded(router, super::SLOW_REQUEST_TIMEOUT, 64)
}

/// A notification from a fiat provider over the internet. Chain Payments notifies on the internal port only, and the
/// manual provider never notifies.
async fn provider_notification(
    State(app): State<Shared>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    // Only the fiat providers notify over the internet.
    if !["square", "gocardless", "paddle"].contains(&provider.as_str()) {
        return Err(ApiError::NotFound);
    }
    super::internal::notification(State(app), Path(provider), headers, body).await
}

/// Headers as a lower-case map (what billing adapters read).
pub fn header_map(h: &HeaderMap) -> BTreeMap<String, String> {
    // Headers that are not text are skipped.
    h.iter().filter_map(|(k, v)| v.to_str().ok().map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))).collect()
}
