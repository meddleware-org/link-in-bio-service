//! Bank feeds: the receiving bank's own API as a source of incoming credits, the same [`Credit`] values a camt.053/054
//! statement gives, so the worker can reconcile bank transfers without the operator importing a file.
//!
//! - [`wise`]: Wise balance statements in camt.053, with Wise's SCA signature of the one-time token.
//! - [`bunq`]: bunq's installation, device and session flow, RSA-signed requests and verified answers; the payments
//!   list.
//! - [`revolut`]: Revolut Business with an RS256 client-assertion JWT and a refresh token; the transactions list.
//!
//! Each feed reads from a cursor it keeps (opaque to the caller, stored per feed) and may keep a little state of its
//! own (bunq's installation). Overlapping windows are fine: a credit pays its checkout once (the ledger key is the
//! reference). Each feed is off unless configured; the API bases default to each bank's sandbox.

pub mod bunq;
pub mod revolut;
pub mod wise;

use serde_json::Value;
use time::{Duration, OffsetDateTime};

use crate::BillingError;
pub use crate::bank_transfer::Credit;

/// Where a feed left off: its cursor and its own state.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeedState {
    pub cursor: Option<String>,
    pub state: Value,
}

/// What one poll found, and where to go on from.
#[derive(Debug, Clone, PartialEq)]
pub struct FeedBatch {
    pub credits: Vec<Credit>,
    pub cursor: Option<String>,
    pub state: Value,
}

#[async_trait::async_trait]
pub trait BankFeed: Send + Sync {
    /// `wise`, `bunq` or `revolut`.
    fn id(&self) -> &'static str;
    /// The incoming credits since the cursor (with some overlap), and the new cursor and state.
    async fn fetch(&self, from: &FeedState, now: OffsetDateTime) -> Result<FeedBatch, BillingError>;
}

/// How far back a feed looks again on every poll (bookings can arrive late), and how far back its first poll looks.
pub const OVERLAP: Duration = Duration::days(2);
pub const FIRST_LOOK_BACK: Duration = Duration::days(7);

/// The start of the next window: the cursor (an RFC 3339 time) less the overlap, or the first look-back.
pub fn window_start(cursor: Option<&str>, now: OffsetDateTime) -> OffsetDateTime {
    cursor.and_then(crate::parse_rfc3339).map(|t| t - OVERLAP).unwrap_or(now - FIRST_LOOK_BACK).min(now)
}

pub use crate::rfc3339;

/// A JSON number or string amount (`3`, `3.5`, `"3.50"`) in minor units, if it is positive.
pub fn positive_minor(v: &Value) -> Option<u64> {
    let s = match v {
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        _ => return None,
    };
    crate::bank_transfer::amount_minor(&s).filter(|m| *m > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn windows_and_amounts() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(window_start(None, now), now - FIRST_LOOK_BACK);
        let c = rfc3339(now - Duration::days(1));
        assert!(window_start(Some(&c), now) < now - Duration::days(2));
        assert_eq!(window_start(Some("nonsense"), now), now - FIRST_LOOK_BACK);
        assert_eq!(positive_minor(&json!(3)), Some(300));
        assert_eq!(positive_minor(&json!(3.5)), Some(350));
        assert_eq!(positive_minor(&json!("12.05")), Some(1205));
        assert_eq!(positive_minor(&json!(-3)), None);
        assert_eq!(positive_minor(&json!("-3.00")), None);
        assert_eq!(positive_minor(&json!(0)), None);
        assert_eq!(positive_minor(&json!(1.005)), None, "more than two decimals is not a bank amount");
    }
}
