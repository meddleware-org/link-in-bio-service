//! Refunds on request: what an account holder may ask back, and exactly how much, so that a refund costs the operator
//! nothing beyond their time.
//!
//! - **Cancel** ([`cancel`]): within [`CANCEL_WINDOW`] of a purchase, all of it comes back, less the days already used
//!   (what the purchase paid per month ÷ 30, per day begun since its first month started) and less its share of the
//!   provider's fee. Every month it still holds is taken back. This also meets the UK 14-day right to cancel a service.
//! - **Unstarted months** ([`unstarted`]): later, only whole months that have not begun, taken from the newest purchases
//!   first (months are stacked, so the newest purchase's months are the last ones of the paid period); the month in
//!   progress is kept. Each month is valued at what its own purchase paid per month.
//! - **Unapplied payment** ([`unapplied`]): a Chain Payments payment that arrived after its checkout was paid or closed
//!   comes back whole within [`UNAPPLIED_WINDOW`] (the buyer never meant to buy those months).
//!
//! The fee share of a refund of `k` of a purchase's `m` months is `(fixed + percent × paid) × k ÷ m`, with the method's
//! [`Fees`] as recorded on its checkout (providers keep their fee when a payment is refunded; Chain Payments' 0.2 % stays
//! with the platform treasury). What the operator pays to send a refund (a bank transfer's or a wallet's outgoing
//! charge, [`Entry::refund_charge_pence`]) is deducted once per line; a Sui transaction's gas is negligible and not
//! charged. Money is counted in the unit the purchase was paid in
//! (pence, cents, a coin's smallest unit), so a refund carries no exchange-rate exposure: the gross is rounded down and
//! each deduction up, so a refund is never more than its exact value. A refund that would be 0 or less is refused.

use serde::Serialize;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::Fees;

/// The ledger's month (a twelfth of 365.25 days), as `link_in_bio_store::MONTH`.
pub const MONTH: Duration = Duration::milliseconds(2_629_800_000);
/// How long after a purchase it may be cancelled in full (less the days used).
pub const CANCEL_WINDOW: Duration = Duration::days(14);
/// How long after an unapplied payment it may be asked back whole.
pub const UNAPPLIED_WINDOW: Duration = Duration::days(30);
/// A month's days, for the price of one day used.
pub const DAYS_PER_MONTH: u64 = 30;

/// What a purchase received, in the unit it was paid in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Received {
    /// In the unit's smallest denomination (pence, cents, MIST, …).
    pub minor: u64,
    /// An ISO 4217 currency code, or a coin type.
    pub unit: String,
    /// Decimals of `unit`, when known (2 for most currencies, 9 for SUI, 6 for USDC).
    pub scale: Option<u32>,
}

/// One ledger entry that lengthened the paid period, with what is left of it.
#[derive(Debug, Clone)]
pub struct Entry {
    /// The billing event.
    pub id: Uuid,
    pub provider: String,
    /// `purchase` or `grant`.
    pub kind: String,
    pub months: u32,
    /// The months it still gives (its months less what refunds took back from it).
    pub held: u32,
    pub at: OffsetDateTime,
    /// When its first month began, or begins (each purchase starts where the paid period ended).
    pub start: OffsetDateTime,
    /// A Chain Payments payment credited after its checkout was paid or closed.
    pub unapplied: bool,
    /// The checkout's amount in pence (the ledger's unit).
    pub amount_pence: u64,
    /// What was received; `None` when the ledger does not say (such a purchase cannot be refunded on request).
    pub received: Option<Received>,
    pub fees: Fees,
    /// What sending a refund of this purchase costs the operator, in pence, once per line
    /// (`BANK_TRANSFER_REFUND_FEE_PENCE`, `OPEN_PAYMENTS_REFUND_FEE_PENCE`).
    pub refund_charge_pence: u64,
    /// Where a refund goes (provider payment, payer address, the debtor's account), for the operator.
    pub destination: Value,
    pub checkout: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Cancel,
    Unstarted,
    Unapplied,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Cancel => "cancel",
            Kind::Unstarted => "unstarted",
            Kind::Unapplied => "unapplied",
        }
    }
}

/// What one purchase gives back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub purchase: Uuid,
    pub provider: String,
    pub checkout: Option<Uuid>,
    /// The months taken back when this line is refunded (exactly these, never pro rata).
    pub months: u32,
    /// What to send, in `unit`'s smallest denomination.
    pub amount_minor: u64,
    pub unit: String,
    pub scale: Option<u32>,
    /// The deductions, in the same unit: the fee share, the outgoing charge and the days used.
    pub fee_minor: u64,
    pub charge_minor: u64,
    pub used_minor: u64,
    pub days_used: u32,
    /// The refund's value in pence, for the ledger.
    pub amount_pence: i64,
    pub destination: Value,
}

/// What an account holder may ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    pub kind: Kind,
    pub lines: Vec<Line>,
    pub months: u32,
    /// Cancel and unapplied: until when it may be asked. Unstarted: when the first month on it begins (after that
    /// the request no longer matches what is unstarted).
    pub until: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(pub String);

fn refuse<T>(why: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(why.into()))
}

/// `ceil(a × b / c)` and `floor(a × b / c)` without overflow.
fn ceil_div(n: u128, d: u128) -> u128 {
    n.div_ceil(d)
}

/// One purchase's refund of `k` of its `m` months, `d` days used: `(gross, fee, used)` in the received unit. The gross is
/// rounded down and each deduction up.
fn parts(p: u64, m: u32, k: u32, d: u32, amount_pence: u64, fees: Fees) -> Result<(u64, u64, u64), Refusal> {
    if m == 0 || k == 0 || k > m {
        return refuse("There are no months to give back.");
    }
    let (p, m, k, d) = (u128::from(p), u128::from(m), u128::from(k), u128::from(d));
    let gross = p * k / m;
    let used = ceil_div(p * d, u128::from(DAYS_PER_MONTH) * m);
    // The fee as a share of what was paid: (10000 × fixed + bps × amount) ÷ (10000 × amount), the amount in pence. In
    // the unit paid, so a purchase paid in euros or a coin is charged the same share without an exchange rate.
    let fee = if fees.fixed_pence == 0 && fees.percent_bps == 0 {
        0
    } else if amount_pence == 0 {
        return refuse("This purchase's amount is not on record, so its fee share cannot be worked out.");
    } else {
        let a = u128::from(amount_pence);
        let f = 10_000 * u128::from(fees.fixed_pence) + u128::from(fees.percent_bps) * a;
        ceil_div(p * f * k, 10_000 * a * m)
    };
    let cap = |v: u128| u64::try_from(v).unwrap_or(u64::MAX);
    Ok((cap(gross), cap(fee), cap(used)))
}

fn line(e: &Entry, k: u32, d: u32, with_fee: bool) -> Result<Line, Refusal> {
    let Some(r) = &e.received else {
        return refuse("What this purchase received is not on record; ask the operator.");
    };
    let fees = if with_fee { e.fees } else { Fees { fixed_pence: 0, percent_bps: 0 } };
    let (gross, fee, used) = parts(r.minor, e.months, k, d, e.amount_pence, fees)?;
    // The outgoing charge, in pence, as a share of what was paid in its unit (rounded up), once for the line.
    let charge = match (e.refund_charge_pence, e.amount_pence) {
        (0, _) => 0,
        (_, 0) => {
            return refuse("This purchase's amount is not on record, so the refund's charge cannot be worked out.");
        }
        (c, a) => u64::try_from(ceil_div(u128::from(r.minor) * u128::from(c), u128::from(a))).unwrap_or(u64::MAX),
    };
    let net = gross.saturating_sub(fee).saturating_sub(used).saturating_sub(charge);
    if net == 0 {
        return refuse(
            "After the days already used, the payment provider's fee and the cost of sending it, nothing would be left \
             to refund.",
        );
    }
    let pence =
        if r.minor == 0 { 0 } else { (u128::from(e.amount_pence) * u128::from(net) / u128::from(r.minor)) as i64 };
    Ok(Line {
        purchase: e.id,
        provider: e.provider.clone(),
        checkout: e.checkout,
        months: k,
        amount_minor: net,
        unit: r.unit.clone(),
        scale: r.scale,
        fee_minor: fee,
        charge_minor: charge,
        used_minor: used,
        days_used: d,
        amount_pence: pence,
        destination: e.destination.clone(),
    })
}

/// Days begun since `start` (0 if it has not started).
fn days_begun(start: OffsetDateTime, now: OffsetDateTime) -> u32 {
    if start >= now {
        return 0;
    }
    let ms = (now - start).whole_milliseconds();
    let day = Duration::DAY.whole_milliseconds();
    u32::try_from((ms + day - 1) / day).unwrap_or(u32::MAX)
}

/// Cancelling one purchase within [`CANCEL_WINDOW`]: every month it still holds back, less the days used and its fee
/// share.
pub fn cancel(e: &Entry, now: OffsetDateTime) -> Result<Offer, Refusal> {
    if e.kind != "purchase" {
        return refuse("Only a purchase can be cancelled.");
    }
    if e.at + CANCEL_WINDOW <= now {
        return refuse(
            "A purchase can be cancelled within 14 days; after that, months that have not started can be refunded.",
        );
    }
    if e.held == 0 {
        return refuse("This purchase has already been refunded.");
    }
    let d = days_begun(e.start, now);
    let l = line(e, e.held, d, true)?;
    Ok(Offer { kind: Kind::Cancel, months: l.months, lines: vec![l], until: Some(e.at + CANCEL_WINDOW) })
}

/// An unapplied Chain Payments payment within [`UNAPPLIED_WINDOW`]: whole.
pub fn unapplied(e: &Entry, now: OffsetDateTime) -> Result<Offer, Refusal> {
    if !e.unapplied || e.kind != "purchase" {
        return refuse("Only a payment that arrived after its checkout was paid or closed can be refunded whole.");
    }
    if e.at + UNAPPLIED_WINDOW <= now {
        return refuse("A refund of a late payment can be asked for within 30 days of it.");
    }
    if e.held < e.months {
        return refuse("Part of this payment has already been refunded.");
    }
    let l = line(e, e.held, 0, false)?;
    Ok(Offer { kind: Kind::Unapplied, months: l.months, lines: vec![l], until: Some(e.at + UNAPPLIED_WINDOW) })
}

/// Whole months of the paid period that have not begun: the month in progress (counted back from the period's end)
/// is kept.
pub fn unstarted_months(paid_until: Option<OffsetDateTime>, now: OffsetDateTime) -> u32 {
    match paid_until {
        Some(p) if p > now => {
            u32::try_from((p - now).whole_milliseconds() / MONTH.whole_milliseconds()).unwrap_or(u32::MAX)
        }
        _ => 0,
    }
}

/// The unstarted months of the paid period that purchases gave, newest first: `(entry, months)`. Months a grant gave
/// are unstarted too but not refundable; they still take their place at the end of the period.
fn unstarted_shares(history: &[Entry], paid_until: Option<OffsetDateTime>, now: OffsetDateTime) -> Vec<(&Entry, u32)> {
    let mut left = unstarted_months(paid_until, now);
    let mut out = Vec::new();
    let mut newest_first: Vec<&Entry> = history.iter().filter(|e| e.held > 0).collect();
    newest_first.sort_by_key(|e| std::cmp::Reverse(e.at));
    for e in newest_first {
        if left == 0 {
            break;
        }
        let c = e.held.min(left);
        left -= c;
        if e.kind == "purchase" {
            out.push((e, c));
        }
    }
    out
}

/// How many unstarted months purchases gave (what [`unstarted`] may refund).
pub fn refundable_unstarted(history: &[Entry], paid_until: Option<OffsetDateTime>, now: OffsetDateTime) -> u32 {
    unstarted_shares(history, paid_until, now).iter().map(|(_, c)| c).sum()
}

/// A refund of `want` unstarted months (all of them when `None`), newest purchases first.
pub fn unstarted(
    history: &[Entry],
    paid_until: Option<OffsetDateTime>,
    now: OffsetDateTime,
    want: Option<u32>,
) -> Result<Offer, Refusal> {
    let shares = unstarted_shares(history, paid_until, now);
    let available: u32 = shares.iter().map(|(_, c)| c).sum();
    if available == 0 {
        return refuse("No paid month has yet to start: the month in progress is kept.");
    }
    let want = want.unwrap_or(available);
    if want == 0 || want > available {
        return refuse(format!("{available} paid month(s) have not started; ask for 1 to {available}."));
    }
    let mut left = want;
    let mut lines = Vec::new();
    for (e, c) in shares {
        if left == 0 {
            break;
        }
        let k = c.min(left);
        left -= k;
        lines.push(line(e, k, 0, true)?);
    }
    // The first month on the request begins `want` months before the period ends.
    let until = paid_until.map(|p| p - MONTH * want);
    Ok(Offer { kind: Kind::Unstarted, months: want, lines, until })
}

/// Decimals of a currency or coin, when known.
pub fn scale_of(unit: &str) -> Option<u32> {
    if unit.ends_with("::sui::SUI") {
        return Some(9);
    }
    if unit.ends_with("::usdc::USDC") {
        return Some(6);
    }
    if unit.len() == 3 && unit.bytes().all(|b| b.is_ascii_uppercase()) {
        // ISO 4217 currencies without minor units that a buyer could pay in.
        return Some(if ["JPY", "KRW", "VND", "CLP", "ISK", "HUF", "TWD", "UGX"].contains(&unit) { 0 } else { 2 });
    }
    None
}

fn number(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// What a purchase received, from its ledger evidence (`paid` is recorded by the ledger from what the provider
/// reported). `amount_pence` is the checkout's amount, the fallback for providers paid in pence.
pub fn received(provider: &str, evidence: &Value, amount_pence: u64) -> Option<Received> {
    let gbp = || Some(Received { minor: amount_pence, unit: "GBP".into(), scale: Some(2) });
    match provider {
        crate::square::ID | crate::gocardless::ID => {
            match (number(&evidence["paid"]["amountMinor"]), evidence["paid"]["currency"].as_str()) {
                (Some(minor), Some(c)) => Some(Received { minor, unit: c.into(), scale: scale_of(c) }),
                _ => gbp(),
            }
        }
        crate::paddle::ID => {
            let c = evidence["currency"].as_str()?;
            Some(Received { minor: number(&evidence["totals"]["grand_total"])?, unit: c.into(), scale: scale_of(c) })
        }
        crate::chain_payments::ID => {
            let coin = evidence["coinType"].as_str()?;
            Some(Received { minor: number(&evidence["amount"])?, unit: coin.into(), scale: scale_of(coin) })
        }
        crate::bank_transfer::ID => {
            let c = evidence["currency"].as_str()?;
            Some(Received { minor: number(&evidence["amountMinor"])?, unit: c.into(), scale: Some(2) })
        }
        crate::open_payments::ID => {
            let a = &evidence["receiveAmount"];
            match (number(&a["value"]), a["assetCode"].as_str(), a["assetScale"].as_u64()) {
                (Some(minor), Some(code), Some(scale)) => {
                    Some(Received { minor, unit: code.into(), scale: u32::try_from(scale).ok() })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Where a refund of a purchase goes and how the operator sends it, from its ledger evidence.
pub fn destination(provider: &str, evidence: &Value, provider_ref: Option<&str>) -> Value {
    match provider {
        crate::square::ID => json!({
            "how": "Refund the payment in the Square Dashboard (Transactions), for exactly the amount shown.",
            "payment": evidence["payment"], "order": provider_ref, "receipt": evidence["receipt"],
        }),
        crate::gocardless::ID => json!({
            "how": "Refund the payment in the GoCardless dashboard, for exactly the amount shown.",
            "payment": evidence["payment"], "billingRequest": provider_ref,
        }),
        crate::paddle::ID => json!({
            "how": "Refund the transaction in the Paddle dashboard (a partial refund of exactly the amount shown, in the buyer's currency).",
            "transaction": provider_ref, "customer": evidence["customer"],
        }),
        crate::chain_payments::ID => json!({
            "how": "Send exactly the amount shown, in the same coin, from the recipient address to the payer.",
            "payer": evidence["payer"], "coinType": evidence["coinType"], "digest": evidence["digest"],
        }),
        crate::bank_transfer::ID => json!({
            "how": "Send a bank transfer of exactly the amount shown to the account that paid (from the statement entry).",
            "debtor": evidence["debtor"], "entry": evidence["entry"], "booked": evidence["booked"],
        }),
        crate::open_payments::ID => json!({
            "how": "Send exactly the amount shown from the operator's wallet to the buyer's wallet address.",
            "wallet": evidence["buyerWallet"], "outgoingPayment": evidence["outgoingPayment"],
        }),
        _ => json!({ "how": "Send the refund by hand." }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    const NOW: OffsetDateTime = datetime!(2026-11-18 12:00 UTC);
    const SQUARE: Fees = Fees { fixed_pence: 25, percent_bps: 140 };
    const NONE: Fees = Fees { fixed_pence: 0, percent_bps: 0 };

    fn purchase(months: u32, pence: u64, at: OffsetDateTime, start: OffsetDateTime, fees: Fees) -> Entry {
        Entry {
            id: Uuid::new_v4(),
            provider: "square".into(),
            kind: "purchase".into(),
            months,
            held: months,
            at,
            start,
            unapplied: false,
            amount_pence: pence,
            received: Some(Received { minor: pence, unit: "GBP".into(), scale: Some(2) }),
            fees,
            refund_charge_pence: 0,
            destination: json!({}),
            checkout: Some(Uuid::new_v4()),
        }
    }

    #[test]
    fn a_cancellation_gives_back_all_but_the_days_used_and_the_fee_share() {
        // 12 months for £36, bought 3 days ago and started then: 3 days at £3 ÷ 30 = 30p; the fee 25p + 1.4 % of
        // £36 = 75.4p, rounded up 76p; the refund £36 − 30p − 76p = £34.94.
        let e = purchase(12, 3600, NOW - Duration::days(3), NOW - Duration::days(3), SQUARE);
        let o = cancel(&e, NOW).unwrap();
        assert_eq!(o.months, 12);
        let l = &o.lines[0];
        assert_eq!((l.days_used, l.used_minor, l.fee_minor, l.amount_minor), (3, 30, 76, 3494));
        assert_eq!(l.amount_pence, 3494);
        // A day begun counts as used.
        let o = cancel(&e, NOW + Duration::minutes(1)).unwrap();
        assert_eq!(o.lines[0].days_used, 4);
    }

    #[test]
    fn a_purchase_that_has_not_started_loses_no_days() {
        // Stacked after months already paid: it starts in two months, so no day of it is used.
        let e = purchase(6, 1800, NOW - Duration::days(1), NOW + MONTH * 2, SQUARE);
        let l = &cancel(&e, NOW).unwrap().lines[0];
        assert_eq!(l.days_used, 0);
        // 25p + 1.4 % of £18 = 50.2p → 51p.
        assert_eq!((l.fee_minor, l.amount_minor), (51, 1749));
    }

    #[test]
    fn cancelling_is_only_within_14_days_and_once() {
        let mut e = purchase(12, 3600, NOW - Duration::days(14), NOW - Duration::days(14), SQUARE);
        assert!(cancel(&e, NOW).unwrap_err().0.contains("14 days"));
        e.at = NOW - Duration::days(13);
        e.held = 0;
        assert!(cancel(&e, NOW).unwrap_err().0.contains("already"));
    }

    #[test]
    fn nothing_left_is_refused() {
        // One month bought for 30p (a made-up price), 13 days used and Square's fee: nothing is left.
        let e = purchase(1, 30, NOW - Duration::days(13), NOW - Duration::days(13), SQUARE);
        assert!(cancel(&e, NOW).unwrap_err().0.contains("nothing would be left"));
    }

    #[test]
    fn unstarted_months_come_from_the_newest_purchases_first() {
        // Three stacked purchases: 3 months at £3 (old), 6 months at £2.50 (middle), 2 months at £3 (newest). The
        // period ends 7.5 months from now, so 7 months have not started.
        let a = purchase(3, 900, NOW - Duration::days(60), NOW - Duration::days(60), SQUARE);
        let b = purchase(6, 1500, NOW - Duration::days(30), NOW - Duration::days(30), SQUARE);
        let c = purchase(2, 600, NOW - Duration::days(20), NOW + MONTH * 5, SQUARE);
        let until = Some(NOW + MONTH * 7 + MONTH / 2);
        let history = vec![a, b.clone(), c.clone()];
        assert_eq!(refundable_unstarted(&history, until, NOW), 7);
        let o = unstarted(&history, until, NOW, None).unwrap();
        assert_eq!(o.months, 7);
        assert_eq!(o.lines.len(), 2, "the newest gives its 2, the middle one 5: the oldest is all started");
        assert_eq!((o.lines[0].purchase, o.lines[0].months), (c.id, 2));
        assert_eq!((o.lines[1].purchase, o.lines[1].months), (b.id, 5));
        // Each month at what its purchase paid per month: 5 × £2.50 = £12.50, less (25p + 1.4 % × £15) × 5/6 =
        // 38.33p → 39p.
        assert_eq!((o.lines[1].amount_minor, o.lines[1].fee_minor), (1250 - 39, 39));
        assert_eq!(o.until, Some(NOW + MONTH / 2), "the first month on the request begins then");
        // Fewer than all of them.
        let o = unstarted(&history, until, NOW, Some(3)).unwrap();
        assert_eq!(o.lines.iter().map(|l| l.months).collect::<Vec<_>>(), vec![2, 1]);
        assert!(unstarted(&history, until, NOW, Some(8)).is_err());
    }

    #[test]
    fn the_month_in_progress_is_kept_and_granted_months_are_not_refunded() {
        let p = purchase(3, 900, NOW - Duration::days(1), NOW - Duration::days(1), SQUARE);
        let mut grant = purchase(2, 0, NOW - Duration::hours(1), NOW + MONTH * 3, NONE);
        grant.kind = "grant".into();
        grant.received = None;
        // 3 months bought a day ago then 2 granted: 4 whole months have not started; the 2 at the end are the grant's.
        let until = Some(NOW - Duration::days(1) + MONTH * 5);
        let history = vec![p.clone(), grant];
        assert_eq!(unstarted_months(until, NOW), 4);
        assert_eq!(refundable_unstarted(&history, until, NOW), 2);
        let o = unstarted(&history, until, NOW, None).unwrap();
        assert_eq!((o.lines[0].purchase, o.lines[0].months), (p.id, 2));
        // Nothing unstarted: refused.
        assert!(unstarted(&history[..1], Some(NOW + MONTH / 2), NOW, None).is_err());
    }

    #[test]
    fn coins_are_refunded_in_the_same_coin_pro_rata_of_what_was_received() {
        let mut e = purchase(6, 1800, NOW - Duration::days(2), NOW + MONTH, NONE);
        e.provider = "chain-payments".into();
        e.received = received("chain-payments", &json!({ "coinType": "0x2::sui::SUI", "amount": "7123456789" }), 1800);
        let l = &cancel(&e, NOW).unwrap().lines[0];
        assert_eq!(
            (l.amount_minor, l.unit.as_str(), l.scale, l.fee_minor),
            (7_123_456_789, "0x2::sui::SUI", Some(9), 0)
        );
        let o = unstarted(&[e], Some(NOW + MONTH * 7 + Duration::days(3)), NOW, Some(1)).unwrap();
        assert_eq!(o.lines[0].amount_minor, 7_123_456_789 / 6, "one sixth, rounded down to the smallest unit");
    }

    #[test]
    fn a_fee_is_charged_as_a_share_of_what_was_paid_in_any_currency() {
        // Paddle: 12 months for £36 paid as €41.00; fee 40p + 5 % of £36 = £2.20, so 2.20/36 of what was paid.
        let mut e = purchase(
            12,
            3600,
            NOW - Duration::days(1),
            NOW - Duration::days(1),
            Fees { fixed_pence: 40, percent_bps: 500 },
        );
        e.provider = "paddle".into();
        e.received = received("paddle", &json!({ "currency": "EUR", "totals": { "grand_total": "4100" } }), 3600);
        let l = &cancel(&e, NOW).unwrap().lines[0];
        // ceil(4100 × 2.20/36) = ceil(250.55) = 251; one day of €41/12/30 = 11.38 → 12.
        assert_eq!((l.unit.as_str(), l.fee_minor, l.used_minor, l.amount_minor), ("EUR", 251, 12, 4100 - 251 - 12));
    }

    #[test]
    fn chain_payments_fee_share_is_its_platform_fee_and_bank_refunds_carry_their_charge() {
        // 0.2 % of 7.5 SUI stays with the platform treasury: the recipient received 99.8 %, and that comes back.
        let mut e = purchase(6, 1800, NOW - Duration::days(1), NOW + MONTH, Fees { fixed_pence: 0, percent_bps: 20 });
        e.provider = "chain-payments".into();
        e.received = received("chain-payments", &json!({ "coinType": "0x2::sui::SUI", "amount": "7500000000" }), 1800);
        let l = &cancel(&e, NOW).unwrap().lines[0];
        assert_eq!((l.fee_minor, l.amount_minor), (15_000_000, 7_485_000_000));
        // A SEPA refund costing the operator 30p, once, as a share of what was paid (€3.50 for £3): ceil(350 × 30/300).
        let mut b = purchase(1, 300, NOW - Duration::days(1), NOW + MONTH, NONE);
        b.provider = "bank-transfer".into();
        b.received = received("bank-transfer", &json!({ "amountMinor": 350, "currency": "EUR" }), 300);
        b.refund_charge_pence = 30;
        let l = &cancel(&b, NOW).unwrap().lines[0];
        assert_eq!((l.charge_minor, l.amount_minor), (35, 315));
        // A charge larger than what would come back: refused.
        b.refund_charge_pence = 400;
        assert!(cancel(&b, NOW).unwrap_err().0.contains("nothing would be left"));
    }

    #[test]
    fn a_late_payment_comes_back_whole_within_30_days() {
        let mut e = purchase(3, 900, NOW - Duration::days(29), NOW + MONTH * 3, SQUARE);
        e.unapplied = true;
        let l = &unapplied(&e, NOW).unwrap().lines[0];
        assert_eq!((l.months, l.amount_minor, l.fee_minor), (3, 900, 0));
        assert!(unapplied(&e, NOW + Duration::days(2)).is_err());
        e.unapplied = false;
        assert!(unapplied(&e, NOW).is_err());
    }

    #[test]
    fn what_was_received_is_read_from_the_evidence() {
        assert_eq!(received("square", &json!({}), 900).unwrap().minor, 900);
        assert_eq!(
            received("square", &json!({ "paid": { "amountMinor": 905, "currency": "GBP" } }), 900).unwrap().minor,
            905
        );
        assert_eq!(
            received("bank-transfer", &json!({ "amountMinor": 350, "currency": "EUR" }), 300).unwrap().unit,
            "EUR"
        );
        assert!(received("open-payments", &json!({ "source": "poll" }), 300).is_none());
        assert_eq!(scale_of("JPY"), Some(0));
        assert_eq!(scale_of("0xdba3::usdc::USDC"), Some(6));
        assert_eq!(scale_of("0xabc::thing::THING"), None);
    }
}
