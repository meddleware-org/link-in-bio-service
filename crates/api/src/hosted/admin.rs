//! The operator console's API (`/api/v1/admin/…` on the admin host, behind Cloudflare Access and the Keto role):
//! accounts, invites (issued only here, never automatically), saved selections, reports and appeals with statements
//! of reasons, suspension, operator grants, the blocklist, link verdicts and the audit log. Every change is audited
//! with the operator's Access subject.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router, middleware};
use serde::Deserialize;
use serde_json::{Value, json};
use time::Duration;
use uuid::Uuid;

use link_in_bio_auth::recovery;
use link_in_bio_store::{Account, Criteria, PeriodChange};

use super::access::{Operator, require_admin};
use super::error::{ApiError, ApiResult};
use super::{Shared, now};
use crate::time::rfc3339_full as ts;

/// Codes one request may issue.
pub const MAX_CODES_PER_REQUEST: usize = 100;

fn actor(op: &Operator) -> String {
    format!("operator:{}", op.subject)
}

fn account_row(a: &Account) -> Value {
    json!({
        "id": a.id, "handle": a.handle, "status": a.status, "suspensionKind": a.suspension_kind,
        "suspensionReason": a.suspension_reason, "suspendedUntil": a.suspended_until.map(ts), "free": a.free,
        "operator": a.operator, "mayShareInvites": a.may_share_invites, "invitedBy": a.invited_by, "tags": a.tags,
        "country": a.country_declared, "paidUntil": a.paid_until.map(ts), "createdAt": ts(a.created_at),
    })
}

async fn me(Extension(op): Extension<Operator>) -> Json<Value> {
    Json(json!({ "subject": op.subject, "name": op.display_name }))
}

async fn overview(State(app): State<Shared>) -> ApiResult<Json<Value>> {
    let s = app.store.stats(now()).await?;
    let c = &app.config;
    Ok(Json(json!({
        "accounts": { "active": s.accounts_active, "suspended": s.accounts_suspended, "free": s.accounts_free, "paid": s.accounts_paid },
        "pagesPublished": s.pages_published,
        "reports": { "open": s.reports_open, "openOver24h": s.reports_open_over_24h },
        "appealsOpen": s.appeals_open,
        "links": { "flagged": s.links_flagged, "unknown": s.links_unknown },
        "storageBytes": s.storage_bytes,
        "checkoutsOpen": s.checkouts_open,
        // Where each bank feed left off (never its stored state, which holds the feed's own credentials).
        "bankFeeds": app.store.bank_feeds().await?.into_iter().map(|f| json!({
            "feed": f.feed, "polledAt": f.polled_at.map(ts), "lastError": f.last_error, "creditsSeen": f.credits_seen,
        })).collect::<Vec<_>>(),
        "switches": {
            "signup": c.signup, "thirdPartyPages": c.third_party_pages, "billingProviders": c.billing_providers,
            "customHostnameCap": c.custom_hostname_cap, "webRisk": app.screener.web_risk.is_some(), "federation": c.federation,
            "bankFeeds": c.bank_feeds.iter().map(|f| match f {
                super::config::BankFeedEnv::Wise { .. } => "wise",
                super::config::BankFeedEnv::Bunq { .. } => "bunq",
                super::config::BankFeedEnv::Revolut { .. } => "revolut",
            }).collect::<Vec<_>>(),
        },
    })))
}

#[derive(Deserialize)]
struct ListQuery {
    q: Option<String>,
    #[serde(default)]
    offset: i64,
}

async fn accounts(State(app): State<Shared>, Query(q): Query<ListQuery>) -> ApiResult<Json<Value>> {
    let rows = app.store.accounts(q.q.as_deref().unwrap_or(""), 100, q.offset.max(0)).await?;
    Ok(Json(json!({ "accounts": rows.iter().map(account_row).collect::<Vec<_>>() })))
}

async fn account(State(app): State<Shared>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let a = app.store.account(id).await?.ok_or(ApiError::NotFound)?;
    let page = app.store.page(id).await?;
    Ok(Json(json!({
        "account": account_row(&a),
        "page": page.map(|p| json!({ "published": p.published.is_some(), "version": p.version, "publishedAt": p.published_at.map(ts),
                                     "document": p.published.and_then(|d| serde_json::from_str::<Value>(&d).ok()) })),
        "invitees": app.store.invitees(id).await?.iter().map(account_row).collect::<Vec<_>>(),
        "invites": app.store.invites(Some(id), 100).await?.into_iter().map(|i| json!({
            "id": i.id, "createdAt": ts(i.created_at), "expiresAt": ts(i.expires_at), "redeemedBy": i.redeemed_by, "revokedAt": i.revoked_at.map(ts),
        })).collect::<Vec<_>>(),
        "billing": app.store.billing_events(id).await?.into_iter().map(|e| json!({
            "provider": e.provider, "kind": e.kind, "months": e.months, "amountPence": e.amount_pence, "at": ts(e.created_at),
        })).collect::<Vec<_>>(),
        "domains": app.store.domains(id).await?.into_iter().map(|d| json!({ "hostname": d.hostname, "status": d.status })).collect::<Vec<_>>(),
        "audit": app.store.audit_log(Some(&id.to_string()), 50).await?.into_iter().map(|e| json!({
            "at": ts(e.at), "actor": e.actor, "action": e.action, "details": e.details,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Flags {
    operator: bool,
    free: bool,
    may_share_invites: bool,
    #[serde(default)]
    tags: Vec<String>,
}

async fn flags(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(f): Json<Flags>,
) -> ApiResult<StatusCode> {
    let tags: Vec<String> = f
        .tags
        .iter()
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty() && t.len() <= 32)
        .take(16)
        .collect();
    if !app.store.set_flags(id, f.operator, f.free, f.may_share_invites, &tags).await? {
        return Err(ApiError::NotFound);
    }
    app.store
        .audit(
            &actor(&op),
            "flags",
            &id.to_string(),
            &json!({ "operator": f.operator, "free": f.free, "mayShareInvites": f.may_share_invites, "tags": tags }),
        )
        .await?;
    forget_account(&app, id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn forget_account(app: &Shared, id: Uuid) {
    if let Ok(Some(a)) = app.store.account(id).await {
        app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Suspend {
    /// `policy` (410) or `legal` (451).
    kind: String,
    reason: String,
    /// Days, for a temporary suspension; none for an indefinite one.
    days: Option<i64>,
    /// The report this acts on (recorded as actioned with the statement of reasons).
    report: Option<Uuid>,
    /// The statement of reasons the account holder is shown.
    statement: String,
}

async fn suspend(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<Suspend>,
) -> ApiResult<StatusCode> {
    if !["policy", "legal"].contains(&b.kind.as_str()) {
        return Err(ApiError::Unprocessable("kind is policy or legal".into()));
    }
    if b.reason.trim().is_empty() || b.statement.trim().is_empty() {
        return Err(ApiError::Unprocessable("A reason and a statement of reasons are required.".into()));
    }
    let n = now();
    let until = b.days.filter(|d| (1..=365).contains(d)).map(|d| n + Duration::days(d));
    if !app.store.suspend(id, &b.kind, b.reason.trim(), until).await? {
        return Err(ApiError::NotFound);
    }
    if let Some(r) = b.report {
        app.store
            .decide_report(r, "actioned", &actor(&op), &format!("suspended ({})", b.kind), Some(b.statement.trim()), n)
            .await?;
    }
    app.store
        .audit(
            &actor(&op),
            "suspend",
            &id.to_string(),
            &json!({ "kind": b.kind, "reason": b.reason, "until": until.map(ts), "report": b.report }),
        )
        .await?;
    forget_account(&app, id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn unsuspend(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !app.store.unsuspend(id).await? {
        return Err(ApiError::NotFound);
    }
    app.store.audit(&actor(&op), "unsuspend", &id.to_string(), &json!({})).await?;
    forget_account(&app, id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Grant {
    months: i32,
    reason: String,
}

/// Months given (or, negative, taken back) by the operator: the manual provider.
async fn grant(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<Grant>,
) -> ApiResult<Json<Value>> {
    if b.months == 0 || b.months.abs() > 24 || b.reason.trim().is_empty() {
        return Err(ApiError::Unprocessable("1 to 24 months (negative to take back), with a reason".into()));
    }
    app.store.account(id).await?.ok_or(ApiError::NotFound)?;
    let event = format!("grant:{}", Uuid::new_v4());
    let until = app
        .store
        .change_period(
            &PeriodChange {
                account_id: id,
                provider: link_in_bio_billing::manual::ID,
                provider_event: &event,
                kind: if b.months > 0 { "grant" } else { "refund" },
                months: b.months,
                amount_pence: 0,
                evidence: json!({ "operator": op.subject, "reason": b.reason }),
                checkout: None,
            },
            now(),
        )
        .await?;
    app.store
        .audit(
            &actor(&op),
            "grant",
            &id.to_string(),
            &json!({ "months": b.months, "reason": b.reason, "paidUntil": until.map(ts) }),
        )
        .await?;
    forget_account(&app, id).await;
    Ok(Json(json!({ "paidUntil": until.map(ts) })))
}

// ── invites ──────────────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Issue {
    count: usize,
    /// The account the codes are given to (to pass on), or none for codes the operator hands out.
    held_by: Option<Uuid>,
    note: Option<String>,
    #[serde(default = "thirty")]
    expires_in_days: i64,
}

fn thirty() -> i64 {
    30
}

/// New codes: shown once, stored only as hashes.
fn new_codes(n: usize) -> (Vec<String>, Vec<Vec<u8>>) {
    let mut codes = Vec::with_capacity(n);
    let mut hashes = Vec::with_capacity(n);
    while codes.len() < n {
        let (c, h) = recovery::generate();
        for (c, h) in c.into_iter().zip(h) {
            if codes.len() < n {
                codes.push(c);
                hashes.push(h);
            }
        }
    }
    (codes, hashes)
}

async fn issue(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Json(b): Json<Issue>,
) -> ApiResult<Json<Value>> {
    if b.count == 0 || b.count > MAX_CODES_PER_REQUEST || !(1..=365).contains(&b.expires_in_days) {
        return Err(ApiError::Unprocessable(format!("1 to {MAX_CODES_PER_REQUEST} codes, valid 1 to 365 days")));
    }
    if let Some(h) = b.held_by {
        app.store.account(h).await?.filter(|a| a.status == "active").ok_or(ApiError::NotFound)?;
    }
    let (codes, hashes) = new_codes(b.count);
    let expires = now() + Duration::days(b.expires_in_days);
    let note =
        b.note.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(200).collect::<String>());
    let pairs: Vec<(Vec<u8>, String)> = hashes.into_iter().zip(codes.iter().cloned()).collect();
    app.store.create_invites(&pairs, b.held_by, None, note.as_deref(), &actor(&op), expires).await?;
    app.store
        .audit(
            &actor(&op),
            "invites-issued",
            &b.held_by.map_or("operator".into(), |h| h.to_string()),
            &json!({ "count": b.count, "expires": ts(expires) }),
        )
        .await?;
    // Codes given to an account are shown to its holder in the app; codes for the operator are shown here, once.
    let shown = if b.held_by.is_some() { Vec::new() } else { codes };
    Ok(Json(json!({ "codes": shown, "issued": b.count, "expiresAt": ts(expires) })))
}

async fn invites(State(app): State<Shared>) -> ApiResult<Json<Value>> {
    let rows = app.store.invites(None, 500).await?;
    Ok(Json(json!({ "invites": rows.into_iter().map(|i| json!({
        "id": i.id, "heldBy": i.held_by, "selection": i.selection_id, "note": i.note, "createdBy": i.created_by,
        "createdAt": ts(i.created_at), "expiresAt": ts(i.expires_at), "redeemedBy": i.redeemed_by,
        "redeemedAt": i.redeemed_at.map(ts), "revokedAt": i.revoked_at.map(ts),
    })).collect::<Vec<_>>() })))
}

async fn revoke(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    if !app.store.revoke_invite(id, now()).await? {
        return Err(ApiError::Conflict("That invite is redeemed or already revoked.".into()));
    }
    app.store.audit(&actor(&op), "invite-revoked", &id.to_string(), &json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NewSelection {
    name: String,
    criteria: Criteria,
}

async fn selections(State(app): State<Shared>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "selections": app.store.selections().await?.into_iter().map(|s| json!({
        "id": s.id, "name": s.name, "criteria": s.criteria, "createdBy": s.created_by, "createdAt": ts(s.created_at),
    })).collect::<Vec<_>>() })))
}

async fn selection_create(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Json(b): Json<NewSelection>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(ApiError::Unprocessable("A name of 1 to 80 characters".into()));
    }
    let id = app.store.create_selection(name, &b.criteria, &actor(&op)).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

async fn selection_delete(State(app): State<Shared>, Path(id): Path<Uuid>) -> ApiResult<StatusCode> {
    if app.store.delete_selection(id).await? { Ok(StatusCode::NO_CONTENT) } else { Err(ApiError::NotFound) }
}

async fn selection_matches(State(app): State<Shared>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let s = app.store.selection(id).await?.ok_or(ApiError::NotFound)?;
    let c: Criteria = serde_json::from_value(s.criteria).map_err(|_| ApiError::Internal)?;
    let rows = app.store.match_selection(&c, now()).await?;
    Ok(Json(json!({ "accounts": rows.iter().map(account_row).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueToSelection {
    per_account: usize,
    #[serde(default = "thirty")]
    expires_in_days: i64,
}

/// "Issue K codes" to every account a saved selection matches now: the codes are given to those accounts to pass on.
async fn selection_issue(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<IssueToSelection>,
) -> ApiResult<Json<Value>> {
    let s = app.store.selection(id).await?.ok_or(ApiError::NotFound)?;
    let c: Criteria = serde_json::from_value(s.criteria).map_err(|_| ApiError::Internal)?;
    let accounts: Vec<Account> =
        app.store.match_selection(&c, now()).await?.into_iter().filter(|a| a.may_share_invites).collect();
    if b.per_account == 0
        || b.per_account * accounts.len().max(1) > MAX_CODES_PER_REQUEST * 10
        || !(1..=365).contains(&b.expires_in_days)
    {
        return Err(ApiError::Unprocessable("Too many codes in one go, or an invalid expiry.".into()));
    }
    let expires = now() + Duration::days(b.expires_in_days);
    let mut issued = 0;
    for a in &accounts {
        let (codes, hashes) = new_codes(b.per_account);
        let pairs: Vec<(Vec<u8>, String)> = hashes.into_iter().zip(codes).collect();
        app.store.create_invites(&pairs, Some(a.id), Some(id), None, &actor(&op), expires).await?;
        issued += pairs.len();
    }
    app.store
        .audit(
            &actor(&op),
            "invites-issued-to-selection",
            &id.to_string(),
            &json!({ "accounts": accounts.len(), "codes": issued }),
        )
        .await?;
    // The holders read their codes in the app; the operator does not see them.
    Ok(Json(json!({ "accounts": accounts.len(), "codes": issued, "expiresAt": ts(expires) })))
}

// ── reports, appeals ─────────────────────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct StatusQuery {
    status: Option<String>,
}

async fn reports(State(app): State<Shared>, Query(q): Query<StatusQuery>) -> ApiResult<Json<Value>> {
    let st = q.status.unwrap_or_else(|| "open".into());
    let rows = app.store.reports(&st, 200).await?;
    Ok(Json(json!({ "reports": rows.into_iter().map(|r| json!({
        "id": r.id, "page": r.handle, "account": r.account_id, "url": r.url, "reason": r.reason, "details": r.details,
        "contact": r.contact, "status": r.status, "createdAt": ts(r.created_at), "decidedAt": r.decided_at.map(ts),
        "decidedBy": r.decided_by, "decision": r.decision, "statement": r.statement,
    })).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Decide {
    /// `actioned` or `dismissed`.
    status: String,
    decision: String,
    statement: Option<String>,
    /// Hide the reported link (`url` of the report) on every page.
    #[serde(default)]
    hide_link: bool,
}

async fn decide(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<Decide>,
) -> ApiResult<StatusCode> {
    if !["actioned", "dismissed"].contains(&b.status.as_str()) || b.decision.trim().is_empty() {
        return Err(ApiError::Unprocessable("status is actioned or dismissed, with a decision".into()));
    }
    let r = app.store.report(id).await?.ok_or(ApiError::NotFound)?;
    let n = now();
    if b.hide_link
        && let Some(u) = &r.url
    {
        app.store.override_screen(u, Some("flagged"), &actor(&op), n).await?;
    }
    if !app
        .store
        .decide_report(id, &b.status, &actor(&op), b.decision.trim(), b.statement.as_deref().map(str::trim), n)
        .await?
    {
        return Err(ApiError::Conflict("That report is already decided.".into()));
    }
    app.store
        .audit(
            &actor(&op),
            "report-decided",
            &id.to_string(),
            &json!({ "status": b.status, "decision": b.decision, "hideLink": b.hide_link }),
        )
        .await?;
    app.pages.forget(&format!("{}.{}", r.handle, app.config.pages_domain)).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn appeals(State(app): State<Shared>, Query(q): Query<StatusQuery>) -> ApiResult<Json<Value>> {
    let st = q.status.unwrap_or_else(|| "open".into());
    Ok(Json(json!({ "appeals": app.store.appeals(&st, 200).await?.into_iter().map(|x| json!({
        "id": x.id, "account": x.account_id, "report": x.report_id, "text": x.text, "status": x.status,
        "createdAt": ts(x.created_at), "decidedAt": x.decided_at.map(ts), "decidedBy": x.decided_by, "statement": x.statement,
    })).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecideAppeal {
    /// `upheld` (the decision is reversed) or `rejected`.
    status: String,
    statement: String,
    /// When upheld: lift the account's suspension too.
    #[serde(default)]
    reinstate: bool,
}

async fn decide_appeal(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<DecideAppeal>,
) -> ApiResult<StatusCode> {
    if !["upheld", "rejected"].contains(&b.status.as_str()) || b.statement.trim().is_empty() {
        return Err(ApiError::Unprocessable("status is upheld or rejected, with a statement".into()));
    }
    let account = app
        .store
        .decide_appeal(id, &b.status, &actor(&op), b.statement.trim(), now())
        .await?
        .ok_or(ApiError::NotFound)?;
    if b.status == "upheld" && b.reinstate {
        app.store.unsuspend(account).await?;
        forget_account(&app, account).await;
    }
    app.store
        .audit(&actor(&op), "appeal-decided", &id.to_string(), &json!({ "status": b.status, "reinstate": b.reinstate }))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── screening ────────────────────────────────────────────────────────────────────────────────────────────────────

async fn blocklist(State(app): State<Shared>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "entries": app.store.blocklist().await?.into_iter().map(|b| json!({
        "pattern": b.pattern, "kind": b.kind, "reason": b.reason, "addedBy": b.added_by, "addedAt": ts(b.added_at),
    })).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Block {
    pattern: String,
    kind: String,
    reason: String,
}

async fn block_add(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Json(b): Json<Block>,
) -> ApiResult<StatusCode> {
    let pattern = match b.kind.as_str() {
        "host" => b.pattern.trim().trim_end_matches('.').to_ascii_lowercase(),
        "url" => {
            link_in_bio_core::safe_url::check_link(b.pattern.trim())
                .map_err(|e| ApiError::Unprocessable(e.message()))?
                .0
        }
        _ => return Err(ApiError::Unprocessable("kind is host or url".into())),
    };
    if pattern.is_empty() || pattern.len() > 253 || b.reason.trim().is_empty() {
        return Err(ApiError::Unprocessable("A pattern and a reason are required.".into()));
    }
    app.store.add_block(&pattern, &b.kind, b.reason.trim(), &actor(&op)).await?;
    app.store.audit(&actor(&op), "block", &pattern, &json!({ "kind": b.kind, "reason": b.reason })).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PatternQuery {
    pattern: String,
}

async fn block_remove(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Query(q): Query<PatternQuery>,
) -> ApiResult<StatusCode> {
    if !app.store.remove_block(&q.pattern).await? {
        return Err(ApiError::NotFound);
    }
    app.store.audit(&actor(&op), "unblock", &q.pattern, &json!({})).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkVerdict {
    url: String,
    /// `clean`, `flagged`, or null to return the link to automatic screening.
    verdict: Option<String>,
}

async fn link_verdict(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Json(b): Json<LinkVerdict>,
) -> ApiResult<StatusCode> {
    if b.verdict.as_deref().is_some_and(|v| !["clean", "flagged"].contains(&v)) {
        return Err(ApiError::Unprocessable("verdict is clean, flagged or null".into()));
    }
    app.store.override_screen(&b.url, b.verdict.as_deref(), &actor(&op), now()).await?;
    app.store.audit(&actor(&op), "link-verdict", &b.url, &json!({ "verdict": b.verdict })).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AuditQuery {
    subject: Option<String>,
}

async fn audit(State(app): State<Shared>, Query(q): Query<AuditQuery>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "entries": app.store.audit_log(q.subject.as_deref(), 200).await?.into_iter().map(|e| json!({
        "id": e.id, "at": ts(e.at), "actor": e.actor, "action": e.action, "subject": e.subject, "details": e.details,
    })).collect::<Vec<_>>() })))
}

// ── refunds ──────────────────────────────────────────────────────────────────────────────────────────────────────

fn refund_row(r: &link_in_bio_store::RefundRequest) -> Value {
    let e = &r.evidence;
    json!({
        "id": r.id, "account": r.account_id, "handle": r.handle, "event": r.event_id, "provider": r.provider,
        "months": r.months, "amountPence": r.amount_pence, "paidAt": ts(r.paid_at), "reason": r.reason, "status": r.status,
        "createdAt": ts(r.created_at), "refundReference": r.refund_reference, "refundEvent": r.refund_event,
        "decidedBy": r.decided_by, "decidedAt": r.decided_at.map(ts),
        // What the refund must match: the same coin and amount, back to the paying address.
        "payment": { "digest": e["digest"], "payer": e["payer"], "coinType": e["coinType"], "amount": e["amount"],
                     "method": e["method"], "checkout": e["checkout"] },
    })
}

/// The refund requests (`?status=open`, the default, or `refunded`), oldest first.
async fn refund_requests(State(app): State<Shared>, Query(q): Query<StatusQuery>) -> ApiResult<Json<Value>> {
    let st = q.status.unwrap_or_else(|| "open".into());
    if !["open", "refunded"].contains(&st.as_str()) {
        return Err(ApiError::BadRequest("status is open or refunded".into()));
    }
    let rows = app.store.refund_requests(&st, 200).await?;
    Ok(Json(json!({ "requests": rows.iter().map(refund_row).collect::<Vec<_>>() })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Refunded {
    /// The refund transaction's reference (for Chain Payments, its digest).
    reference: String,
    #[serde(default)]
    note: String,
}

/// The operator sent the refund: records its reference and takes the months back (a `refund` billing event), once.
async fn refunded(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    Path(id): Path<Uuid>,
    Json(b): Json<Refunded>,
) -> ApiResult<Json<Value>> {
    let reference = b.reference.trim();
    if reference.is_empty() || reference.len() > 200 || !reference.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(ApiError::Unprocessable(
            "The refund's transaction reference is 1 to 200 visible characters.".into(),
        ));
    }
    let note = b.note.trim();
    if note.chars().count() > 1000 {
        return Err(ApiError::Unprocessable("The note is at most 1000 characters.".into()));
    }
    let existing = app.store.refund_request(id).await?.ok_or(ApiError::NotFound)?;
    let Some(done) = app.store.record_refund(id, reference, &actor(&op), note, now()).await? else {
        return Err(ApiError::Conflict(format!("This request is already {}.", existing.status)));
    };
    app.store
        .audit(
            &actor(&op),
            "refund-recorded",
            &done.account_id.to_string(),
            &json!({ "request": id, "event": existing.event_id, "refundEvent": done.event_id, "months": -done.months,
                     "reference": reference, "note": note, "paidUntil": ts(done.paid_until) }),
        )
        .await?;
    forget_account(&app, done.account_id).await;
    let after = app.store.refund_request(id).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(json!({ "request": refund_row(&after), "paidUntil": ts(done.paid_until) })))
}

/// An ISO 20022 statement from the receiving bank: each booked credit whose creditor reference names a bank-transfer
/// checkout, in its currency and for at least its amount, pays it (once). The rest is reported, never applied.
async fn bank_statement(
    State(app): State<Shared>,
    Extension(op): Extension<Operator>,
    body: axum::body::Bytes,
) -> ApiResult<Json<Value>> {
    if app.config.bank_transfer.is_none() {
        return Err(ApiError::Unavailable("bank transfer is not switched on"));
    }
    let xml =
        std::str::from_utf8(&body).map_err(|_| ApiError::Unprocessable("the statement is not UTF-8 text".into()))?;
    let credits = link_in_bio_billing::bank_transfer::credits_from_camt(xml)
        .map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let super::internal::Matched { paid, short, unknown } = super::internal::match_credits(&app, &credits).await?;
    app.store
        .audit(
            &actor(&op),
            "bank-statement-imported",
            "bank-transfer",
            &json!({ "credits": credits.len(), "paid": paid.len(), "short": short.len(), "unknown": unknown.len() }),
        )
        .await?;
    Ok(Json(json!({ "credits": credits.len(), "paid": paid, "short": short, "unknown": unknown })))
}

pub fn router(app: Shared) -> Router {
    let router = Router::new()
        .route("/api/v1/admin/me", get(me))
        .route("/api/v1/admin/overview", get(overview))
        .route("/api/v1/admin/accounts", get(accounts))
        .route("/api/v1/admin/accounts/{id}", get(account))
        .route("/api/v1/admin/accounts/{id}/flags", put(flags))
        .route("/api/v1/admin/accounts/{id}/suspend", post(suspend))
        .route("/api/v1/admin/accounts/{id}/unsuspend", post(unsuspend))
        .route("/api/v1/admin/accounts/{id}/grant", post(grant))
        .route("/api/v1/admin/invites", get(invites).post(issue))
        .route("/api/v1/admin/invites/{id}", delete(revoke))
        .route("/api/v1/admin/selections", get(selections).post(selection_create))
        .route("/api/v1/admin/selections/{id}", delete(selection_delete))
        .route("/api/v1/admin/selections/{id}/matches", get(selection_matches))
        .route("/api/v1/admin/selections/{id}/issue", post(selection_issue))
        .route("/api/v1/admin/reports", get(reports))
        .route("/api/v1/admin/reports/{id}/decide", post(decide))
        .route("/api/v1/admin/appeals", get(appeals))
        .route("/api/v1/admin/appeals/{id}/decide", post(decide_appeal))
        .route("/api/v1/admin/blocklist", get(blocklist).post(block_add).delete(block_remove))
        .route("/api/v1/admin/links", put(link_verdict))
        .route("/api/v1/admin/audit", get(audit))
        .route("/api/v1/admin/refund-requests", get(refund_requests))
        .route("/api/v1/admin/refund-requests/{id}/refunded", post(refunded))
        .route(
            "/api/v1/admin/bank-statements",
            post(bank_statement).layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024)),
        )
        .layer(middleware::from_fn_with_state(app.clone(), require_admin))
        .route("/healthz", get(|| async { "ok\n" }))
        .fallback(|| async { ApiError::NoRoute.into_response() })
        .layer(middleware::from_fn(no_store))
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(app);
    // Eight requests at once: a 4 MiB statement each at most, within the pod's 128 MiB.
    super::bounded(router, super::SLOW_REQUEST_TIMEOUT, 8)
}

/// Console answers hold personal data (reports' contacts, the audit log): never stored by a cache, never sniffed, never
/// sent on as a referrer.
async fn no_store(req: axum::extract::Request, next: middleware::Next) -> axum::response::Response {
    use axum::http::{HeaderValue, header};
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    r
}
