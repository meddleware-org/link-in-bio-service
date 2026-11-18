//! The internal port (cluster only; the NetworkPolicy admits Chain Payments' worker and monitoring): payment
//! provider notifications, `/metrics`, health. Provider notifications that arrive over the internet (the fiat
//! providers, later) use the same handler behind the app host's `/api/v1/webhooks/<provider>`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

use link_in_bio_billing::Paid;
use link_in_bio_billing::bank_transfer::{self, Credit, Scheme};
use link_in_bio_billing::{Outcome, ProviderEvent};
use link_in_bio_store::{PeriodChange, RefundChange};

/// What a provider said was paid, for the audit log.
fn paid_json(p: Option<&Paid>) -> Value {
    match p {
        Some(Paid::Amount { minor, currency }) => json!({ "amountMinor": minor, "currency": currency }),
        Some(Paid::Quantity { quantity, price_id }) => json!({ "quantity": quantity, "priceId": price_id }),
        None => Value::Null,
    }
}

use super::error::{ApiError, ApiResult};
use super::metrics::Metrics;
use super::{Shared, now};

/// Applies one verified provider event to the ledger. Idempotent: an event applied before changes nothing.
pub async fn apply_event(app: &Shared, provider: &str, e: &ProviderEvent) -> ApiResult<()> {
    let Some(c) = app.store.checkout_by_ref(provider, &e.provider_ref).await? else {
        tracing::warn!(provider, reference = %e.provider_ref, "notification for an unknown checkout");
        return Ok(());
    };
    let n = now();
    match e.outcome {
        Outcome::Paid => {
            // What the provider says was paid must cover the checkout (amount and currency, or Paddle's quantity and
            // price). If it does not, nothing is applied: the checkout stays open and the operator sees why, once.
            let price_id = app.config.paddle.as_ref().map(|p| p.price_id.as_str());
            if !link_in_bio_billing::paid_covers(
                provider,
                e.paid.as_ref(),
                c.months as u32,
                c.amount_pence as u64,
                price_id,
            ) {
                Metrics::inc(&app.metrics.payment_mismatches);
                tracing::warn!(provider, checkout = %c.id, "a payment notification does not cover its checkout");
                app.store
                    .audit_once(
                        &format!("provider:{provider}"),
                        "payment-not-covering",
                        &c.account_id.to_string(),
                        &json!({ "event": format!("{provider}:{}", e.event_id), "checkout": c.id, "months": c.months,
                                 "amountPence": c.amount_pence, "paid": paid_json(e.paid.as_ref()), "evidence": e.evidence }),
                    )
                    .await?;
                return Ok(());
            }
            let mut evidence = e.evidence.clone();
            evidence["countryDeclared"] = json!(c.country_declared);
            evidence["countryRequest"] = json!(c.country_request);
            evidence["method"] = json!(c.method);
            // What the provider says was paid, kept: a refund on request is worked out from it.
            if e.paid.is_some() {
                evidence["paid"] = paid_json(e.paid.as_ref());
            }
            let applied = app
                .store
                .change_period(
                    &PeriodChange {
                        account_id: c.account_id,
                        provider,
                        provider_event: &e.event_id,
                        kind: "purchase",
                        months: c.months,
                        amount_pence: c.amount_pence,
                        evidence,
                        checkout: Some(c.id),
                        checkout_id: Some(c.id),
                        refund_of: None,
                    },
                    n,
                )
                .await?;
            if let Some(until) = applied {
                Metrics::inc(&app.metrics.payments);
                app.store
                    .audit(
                        &format!("provider:{provider}"),
                        "paid",
                        &c.account_id.to_string(),
                        &json!({ "checkout": c.id, "months": c.months, "paidUntil": crate::time::rfc3339_full(until) }),
                    )
                    .await?;
                if let Some(a) = app.store.account(c.account_id).await? {
                    app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
                }
            }
        }
        Outcome::Unapplied => {
            // Paid on-chain after the checkout was paid or closed: credited as the months its quote was for. No money
            // moves, so nothing here can be used to make the operator pay network fees. A refund instead is the account
            // holder's request, sent by the operator by hand from the recipient (then recorded as a refund).
            let mut evidence = e.evidence.clone();
            evidence["unapplied"] = json!(true);
            evidence["checkout"] = json!(c.id);
            let applied = app
                .store
                .change_period(
                    &PeriodChange {
                        account_id: c.account_id,
                        provider,
                        provider_event: &e.event_id,
                        kind: "purchase",
                        months: c.months,
                        amount_pence: c.amount_pence,
                        evidence,
                        checkout: None,
                        checkout_id: Some(c.id),
                        refund_of: None,
                    },
                    n,
                )
                .await?;
            if let Some(until) = applied {
                Metrics::inc(&app.metrics.payments);
                app.store
                    .audit(
                        &format!("provider:{provider}"),
                        "late-payment-credited",
                        &c.account_id.to_string(),
                        &json!({ "checkout": c.id, "months": c.months, "paidUntil": crate::time::rfc3339_full(until), "digest": e.evidence["digest"] }),
                    )
                    .await?;
                if let Some(a) = app.store.account(c.account_id).await? {
                    app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
                }
            }
        }
        Outcome::Refunded => {
            // The refund an open request asked for, for exactly its amount: that request's months, exactly.
            if super::refunds::match_provider_refund(app, provider, c.id, e).await? {
                return Ok(());
            }
            // Any other refund (an operator's own, one the provider made): pro rata, rounded down, counted over every
            // refund of this purchase (FU-0139), so a refund of the whole amount, or partial refunds that add up to it,
            // take back every month, and never more.
            let (refunded, of) = match e.refunded {
                Some(r) => (r.minor, r.of_minor.unwrap_or(c.amount_pence as u64)),
                None => (c.amount_pence as u64, c.amount_pence as u64),
            };
            let applied = app
                .store
                .refund_purchase(
                    &RefundChange {
                        account_id: c.account_id,
                        provider,
                        provider_event: &e.event_id,
                        checkout: c.id,
                        months: c.months as u32,
                        paid_minor: of,
                        refunded_minor: refunded,
                        amount_pence: c.amount_pence,
                        evidence: e.evidence.clone(),
                    },
                    link_in_bio_billing::months_refunded,
                    n,
                )
                .await?;
            if let Some(r) = applied {
                app.store
                    .audit(
                        &format!("provider:{provider}"),
                        "refunded",
                        &c.account_id.to_string(),
                        &json!({ "checkout": c.id, "refundedMinor": refunded, "ofMinor": of, "monthsTaken": r.months_taken,
                                 "paidUntil": r.paid_until.map(crate::time::rfc3339_full) }),
                    )
                    .await?;
                if let Some(a) = app.store.account(c.account_id).await? {
                    app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
                }
            }
        }
        Outcome::Expired | Outcome::Failed => {
            app.store.close_checkout(c.id, "expired", n).await?;
        }
        Outcome::Open => {}
    }
    Ok(())
}

/// What matching bank credits against bank-transfer checkouts found.
#[derive(Debug, Default)]
pub struct Matched {
    pub paid: Vec<Value>,
    pub short: Vec<Value>,
    pub unknown: Vec<Value>,
}

/// Bank credits (from an imported statement or a bank feed) against bank-transfer checkouts: a credit whose creditor
/// reference names a checkout, in its currency and for at least its amount, pays it (once: the ledger key is the
/// reference). Underpayments, other currencies and unknown references are reported, never applied.
pub async fn match_credits(app: &Shared, credits: &[Credit]) -> ApiResult<Matched> {
    let Some(bt) = &app.config.bank_transfer else {
        return Err(ApiError::Unavailable("bank transfer is not switched on"));
    };
    let mut m = Matched::default();
    for c in credits {
        let Some(co) = app.store.checkout_by_ref(bank_transfer::ID, &c.reference).await? else {
            m.unknown.push(json!({ "reference": c.reference, "amountMinor": c.amount_minor, "currency": c.currency }));
            continue;
        };
        let want = match &bt.scheme {
            Scheme::Sepa { eur_cents_per_month, .. } => (eur_cents_per_month * co.months as u64, "EUR"),
            Scheme::FasterPayments { .. } => (co.amount_pence as u64, "GBP"),
        };
        if c.currency != want.1 || c.amount_minor < want.0 {
            m.short.push(json!({ "reference": c.reference, "checkout": co.id, "got": c.amount_minor, "currency": c.currency, "want": want.0, "wantCurrency": want.1 }));
            continue;
        }
        apply_event(app, bank_transfer::ID, &bank_transfer::paid_event(c)).await?;
        m.paid.push(json!({ "reference": c.reference, "checkout": co.id }));
    }
    Ok(m)
}

/// A provider's notification: verified by its adapter, then applied. 2xx tells the provider to stop retrying.
pub async fn notification(
    State(app): State<Shared>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let p = app.billing.provider(&provider).ok_or(ApiError::NotFound)?;
    let events = p.verify_notification(&super::app::header_map(&headers), &body, now()).await.map_err(|e| {
        Metrics::inc(&app.metrics.notification_failures);
        tracing::warn!(provider, error = %e, "notification refused");
        match e {
            link_in_bio_billing::BillingError::Unavailable(_) => {
                ApiError::Unavailable("cannot verify notifications right now")
            }
            _ => ApiError::BadRequest("not an authentic notification".into()),
        }
    })?;
    for e in &events {
        apply_event(&app, p.id(), e).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn metrics(State(app): State<Shared>) -> Response {
    let n = now();
    let stats = app.store.stats(n).await.ok();
    let wr = match &app.screener.web_risk {
        Some(w) => {
            let month = link_in_bio_safety::period(n);
            match (app.store.counter("webrisk", &month).await, app.store.counter("webrisk-confirm", &month).await) {
                (Ok(calls), Ok(confirms)) => Some(super::metrics::WebRiskFigures {
                    calls,
                    cap: w.monthly_cap,
                    confirms,
                    confirm_cap: w.confirm_monthly_cap,
                    prefixes: w.entries(),
                }),
                _ => None,
            }
        }
        None => None,
    };
    let mut r = app.metrics.render(stats.as_ref(), wr).into_response();
    r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4"));
    r
}

async fn readyz(State(app): State<Shared>) -> Response {
    match app.store.ping().await {
        Ok(()) => "ready\n".into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database unavailable\n").into_response(),
    }
}

pub fn router(app: Shared) -> Router {
    let router = Router::new()
        .route("/internal/v1/payments/{provider}", post(notification))
        .route("/metrics", get(metrics))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(readyz))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app);
    super::bounded(router, super::REQUEST_TIMEOUT, 32)
}

/// The worker's port: metrics and health only.
pub fn worker_router(app: Shared) -> Router {
    let router =
        Router::new().route("/metrics", get(metrics)).route("/healthz", get(|| async { "ok\n" })).with_state(app);
    super::bounded(router, super::REQUEST_TIMEOUT, 8)
}
