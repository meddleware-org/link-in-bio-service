//! The internal port (cluster only; the NetworkPolicy admits Chain Payments' worker and monitoring): payment
//! provider notifications, `/metrics`, health. Provider notifications that arrive over the internet (the fiat
//! providers, later) use the same handler behind the app host's `/api/v1/webhooks/<provider>`.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use link_in_bio_billing::{Outcome, ProviderEvent};
use link_in_bio_store::PeriodChange;

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
            let mut evidence = e.evidence.clone();
            evidence["countryDeclared"] = json!(c.country_declared);
            evidence["countryRequest"] = json!(c.country_request);
            evidence["method"] = json!(c.method);
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
                        &json!({ "checkout": c.id, "months": c.months, "paidUntil": until }),
                    )
                    .await?;
                if let Some(a) = app.store.account(c.account_id).await? {
                    app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
                }
            }
        }
        Outcome::Refunded => {
            let months = -(e.months.unwrap_or(c.months as u32) as i32);
            app.store
                .change_period(
                    &PeriodChange {
                        account_id: c.account_id,
                        provider,
                        provider_event: &e.event_id,
                        kind: "refund",
                        months,
                        amount_pence: -c.amount_pence,
                        evidence: e.evidence.clone(),
                        checkout: None,
                    },
                    n,
                )
                .await?;
        }
        Outcome::Expired | Outcome::Failed => {
            app.store.close_checkout(c.id, "expired", n).await?;
        }
        Outcome::Open => {}
    }
    Ok(())
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
        Some(w) => app.store.counter("webrisk", &link_in_bio_safety::period(n)).await.ok().map(|u| (u, w.monthly_cap)),
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
    Router::new()
        .route("/internal/v1/payments/{provider}", post(notification))
        .route("/metrics", get(metrics))
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(readyz))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(app)
}

/// The worker's port: metrics and health only.
pub fn worker_router(app: Shared) -> Router {
    Router::new().route("/metrics", get(metrics)).route("/healthz", get(|| async { "ok\n" })).with_state(app)
}
