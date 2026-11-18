//! Refunds on request, between the ledger and [`link_in_bio_billing::refunds`]: an account's purchases as that
//! module's entries (what each received, its fees, where a refund goes), the answers' JSON, and matching a provider's
//! refund notification with the open request that names its purchase.
//!
//! Nothing here sends money: the operator refunds by hand (in the Square, GoCardless or Paddle dashboard, or a chain
//! or bank payment). A provider's refund notification of exactly a line's amount closes that line and takes back
//! exactly its months; the operator records the reference of any other refund. No process holds a key that can refund.

use serde_json::{Value, json};
use time::OffsetDateTime;

use link_in_bio_billing::refunds::{self, Entry, Line, Offer};
use link_in_bio_billing::{Fees, ProviderEvent, open_payments};
use link_in_bio_store::{Account, NewRefundLine, RefundLine};

use super::config::HostedConfig;
use super::error::ApiResult;
use super::{Shared, now};
use crate::time::rfc3339_full as ts;

/// A method's fees as configured now (what the providers keep when a payment is refunded): the fallback for checkouts
/// made before schema 6 recorded their own.
pub fn fees_for(config: &HostedConfig, provider: &str) -> Fees {
    let none = Fees { fixed_pence: 0, percent_bps: 0 };
    match provider {
        "square" => {
            config.square.as_ref().map_or(none, |c| Fees { fixed_pence: c.fixed_pence, percent_bps: c.percent_bps })
        }
        "gocardless" => {
            config.gocardless.as_ref().map_or(none, |c| Fees { fixed_pence: c.fixed_pence, percent_bps: c.percent_bps })
        }
        "paddle" => {
            config.paddle.as_ref().map_or(none, |c| Fees { fixed_pence: c.fixed_pence, percent_bps: c.percent_bps })
        }
        "chain-payments" => Fees { fixed_pence: 0, percent_bps: link_in_bio_billing::chain_payments::PLATFORM_FEE_BPS },
        _ => none,
    }
}

/// What sending one refund costs the operator, in pence (bank transfers and Open Payments; Sui gas is negligible).
pub fn refund_charge_for(config: &HostedConfig, provider: &str) -> u64 {
    match provider {
        "bank-transfer" => config.bank_transfer.as_ref().map_or(0, |c| u64::from(c.refund_fee_pence)),
        "open-payments" => config.open_payments.as_ref().map_or(0, |c| u64::from(c.refund_fee_pence)),
        _ => 0,
    }
}

/// An account's purchases and grants as refund entries, newest first.
pub async fn history(app: &Shared, a: &Account) -> ApiResult<Vec<Entry>> {
    let rows = app.store.extensions(a.id).await?;
    Ok(rows
        .into_iter()
        .map(|e| {
            let months = u32::try_from(e.months).unwrap_or(0);
            let pence = u64::try_from(e.amount_pence).unwrap_or(0);
            let received = refunds::received(&e.provider, &e.evidence, pence).or_else(|| {
                // An Open Payments purchase settled by a poll has no amount in its evidence: the checkout's, in the
                // configured asset.
                let op = app.config.open_payments.as_ref().filter(|_| e.provider == open_payments::ID)?;
                let minor = match op.minor_per_month {
                    Some(m) => m.checked_mul(u64::from(months))?,
                    None if op.asset_code == "GBP" && op.asset_scale == 2 => pence,
                    None => return None,
                };
                Some(refunds::Received { minor, unit: op.asset_code.clone(), scale: Some(u32::from(op.asset_scale)) })
            });
            Entry {
                id: e.id,
                provider: e.provider.clone(),
                kind: e.kind.clone(),
                months,
                held: u32::try_from(e.held.clamp(0, i64::from(e.months))).unwrap_or(0),
                at: e.created_at,
                start: e.paid_until_after.map_or(e.created_at, |u| u - refunds::MONTH * months),
                unapplied: e.evidence["unapplied"].as_bool().unwrap_or(false),
                amount_pence: pence,
                received,
                // The fees recorded on the checkout when it was made; the configured ones for older checkouts.
                fees: match (e.fee_fixed_pence, e.fee_percent_bps) {
                    (Some(f), Some(b)) => {
                        Fees { fixed_pence: u32::try_from(f).unwrap_or(0), percent_bps: u32::try_from(b).unwrap_or(0) }
                    }
                    _ => fees_for(&app.config, &e.provider),
                },
                refund_charge_pence: refund_charge_for(&app.config, &e.provider),
                destination: refunds::destination(&e.provider, &e.evidence, e.provider_ref.as_deref()),
                checkout: e.checkout_id,
            }
        })
        .collect())
}

/// `minor` in units of `scale` decimals (`3494`, 2 → `34.94`).
pub fn decimal(minor: i64, scale: Option<i32>) -> String {
    match scale.and_then(|s| u32::try_from(s).ok()).filter(|s| *s > 0 && *s <= 18) {
        Some(s) => {
            let d = 10i128.pow(s);
            let m = i128::from(minor);
            format!("{}{}.{:0width$}", if m < 0 { "-" } else { "" }, m.abs() / d, m.abs() % d, width = s as usize)
        }
        None => minor.to_string(),
    }
}

pub fn offer_line_json(l: &Line) -> Value {
    let scale = l.scale.map(|s| s as i32);
    json!({
        "purchase": l.purchase, "provider": l.provider, "months": l.months,
        "amountMinor": l.amount_minor, "amount": decimal(l.amount_minor as i64, scale), "unit": l.unit, "scale": l.scale,
        "feeMinor": l.fee_minor, "chargeMinor": l.charge_minor, "usedMinor": l.used_minor, "daysUsed": l.days_used,
        "destination": l.destination,
    })
}

pub fn offer_json(o: &Offer) -> Value {
    json!({
        "kind": o.kind, "months": o.months, "until": o.until.map(ts),
        "lines": o.lines.iter().map(offer_line_json).collect::<Vec<_>>(),
    })
}

pub fn line_json(l: &RefundLine) -> Value {
    json!({
        "purchase": l.purchase_id, "checkout": l.checkout_id, "provider": l.provider, "months": l.months,
        "amountMinor": l.amount_minor, "amount": decimal(l.amount_minor, l.scale), "unit": l.unit, "scale": l.scale,
        "feeMinor": l.fee_minor, "chargeMinor": l.charge_minor, "usedMinor": l.used_minor, "daysUsed": l.days_used,
        "amountPence": l.amount_pence,
        "destination": l.destination, "status": l.status, "refundReference": l.refund_reference,
        "refundEvent": l.refund_event, "refundedAt": l.refunded_at.map(ts),
        // The months its purchase still gives: a line can take back at most these.
        "purchaseMonthsLeft": l.held,
    })
}

pub fn new_lines(o: &Offer) -> Vec<NewRefundLine> {
    o.lines
        .iter()
        .map(|l| NewRefundLine {
            purchase_id: l.purchase,
            checkout_id: l.checkout,
            provider: l.provider.clone(),
            months: l.months as i32,
            amount_minor: i64::try_from(l.amount_minor).unwrap_or(i64::MAX),
            unit: l.unit.clone(),
            scale: l.scale.map(|s| s as i32),
            fee_minor: i64::try_from(l.fee_minor).unwrap_or(i64::MAX),
            charge_minor: i64::try_from(l.charge_minor).unwrap_or(i64::MAX),
            used_minor: i64::try_from(l.used_minor).unwrap_or(i64::MAX),
            days_used: l.days_used as i32,
            amount_pence: l.amount_pence,
            destination: l.destination.clone(),
        })
        .collect()
}

/// What a request's details record: when it was worked out and until when it holds.
pub fn details(o: &Offer, at: OffsetDateTime) -> Value {
    json!({ "computedAt": ts(at), "until": o.until.map(ts), "months": o.months })
}

/// A provider's refund of a checkout whose purchase an open request names: when the refund is exactly the line's
/// amount, it closes the line (and the request, once every line is), taking back exactly the line's months, and
/// `true` is returned. Otherwise `false`, and the refund is applied pro rata as one no request names; a refund of
/// another amount is recorded in the audit log for the operator.
pub async fn match_provider_refund(
    app: &Shared,
    provider: &str,
    checkout: uuid::Uuid,
    e: &ProviderEvent,
) -> ApiResult<bool> {
    let Some(line) = app.store.open_refund_line_for_checkout(checkout).await? else { return Ok(false) };
    let Some(r) = e.refunded else { return Ok(false) };
    if i64::try_from(r.minor).ok() != Some(line.amount_minor) {
        app.store
            .audit_once(
                &format!("provider:{provider}"),
                "refund-not-matching-request",
                &line.request_id.to_string(),
                &json!({ "event": format!("{provider}:{}", e.event_id), "request": line.request_id, "purchase": line.purchase_id,
                         "refundedMinor": r.minor, "requestedMinor": line.amount_minor, "unit": line.unit }),
            )
            .await?;
        return Ok(false);
    }
    let done = app
        .store
        .refund_line(
            line.request_id,
            line.purchase_id,
            &e.event_id,
            &format!("provider:{provider}"),
            Some(&e.event_id),
            json!({ "notification": e.evidence }),
            now(),
        )
        .await?;
    let Some(done) = done else { return Ok(true) };
    app.store
        .audit(
            &format!("provider:{provider}"),
            "refund-matched",
            &done.account_id.to_string(),
            &json!({ "request": line.request_id, "purchase": line.purchase_id, "months": done.months_taken,
                     "amountMinor": line.amount_minor, "unit": line.unit, "requestClosed": done.request_closed,
                     "paidUntil": done.paid_until.map(ts) }),
        )
        .await?;
    if let Some(a) = app.store.account(done.account_id).await? {
        app.pages.forget(&format!("{}.{}", a.handle, app.config.pages_domain)).await;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn decimals() {
        assert_eq!(super::decimal(3494, Some(2)), "34.94");
        assert_eq!(super::decimal(7_123_456_789, Some(9)), "7.123456789");
        assert_eq!(super::decimal(5, Some(2)), "0.05");
        assert_eq!(super::decimal(500, Some(0)), "500");
        assert_eq!(super::decimal(500, None), "500");
    }
}
