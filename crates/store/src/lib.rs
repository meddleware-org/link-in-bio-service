//! `link-in-bio-store`: every SQL statement of the hosted service. Runtime-checked queries (`sqlx::query`), each covered
//! by the real-PostgreSQL tests in `tests/store.rs` (TLS, `verify-full`, `scripts/test-postgres.sh`).
//!
//! The writer role (app, admin, worker) uses the `lib.*` tables; the page process uses only the `public.*_v1` views
//! ([`Store::view_page`] and the other `view_*` methods), which the read-only role can read and nothing else.

/// The connection settings.
pub mod config;

use std::collections::HashSet;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Row, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// The database error type, as `sqlx` defines it.
pub use sqlx::Error as DbError;

/// The embedded migrations, checked by checksum and run by the `migrate` subcommand.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SHA-256, the only form a secret (session cookie, invite code, recovery code) or a link URL is stored or looked up in.
pub fn sha256(v: &[u8]) -> Vec<u8> {
    Sha256::digest(v).to_vec()
}

/// The average month the paid period is extended by (365.25 / 12 days), the same as the on-chain ledger's.
pub const MONTH: Duration = Duration::milliseconds(2_629_800_000);

/// The day a per-account daily counter counts in (`2026-11-18`, UTC).
pub fn day(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
}

/// The database handle: every statement of the hosted service is a method of it. It owns a connection pool and nothing else.
#[derive(Clone)]
pub struct Store {
    /// The pool of connections, created lazily by the settings.
    pool: PgPool,
}

/// An account as the writer role reads it (`lib.accounts`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Account {
    /// The account's id.
    pub id: Uuid,
    /// The handle, which is also the page's host name.
    pub handle: String,
    /// `active`, `suspended` or `deleted`.
    pub status: String,
    /// `legal` (a page withheld on legal grounds, 451) or `policy` (removed under the acceptable use policy, 410) when suspended.
    pub suspension_kind: Option<String>,
    /// The reason given to the account holder, up to 2000 characters.
    pub suspension_reason: Option<String>,
    /// When the suspension ends, if it does.
    pub suspended_until: Option<OffsetDateTime>,
    /// A free account (from an operator-issued invite); a paid one carries `paid_until` instead.
    pub free: bool,
    /// One of the operator's own accounts: the only tenant pages served while third-party pages are off.
    pub operator: bool,
    /// Whether invite codes the operator gave this account may still be redeemed.
    pub may_share_invites: bool,
    /// The account that invited this one.
    pub invited_by: Option<Uuid>,
    /// Free-form tags the operator attaches.
    pub tags: Vec<String>,
    /// The version of the terms accepted at sign-up.
    pub terms_version: String,
    /// The country the holder declared (ISO 3166-1 alpha-2), kept as tax evidence.
    pub country_declared: Option<String>,
    /// The opaque reference given to payment providers, never the handle or the id.
    pub billing_ref: String,
    /// The end of the paid period.
    pub paid_until: Option<OffsetDateTime>,
    /// When the account was made.
    pub created_at: OffsetDateTime,
}

impl Account {
    /// Whether the account may have a page online now (free, operator, or paid up within the grace period).
    pub fn entitled(&self, now: OffsetDateTime, grace: Duration) -> bool {
        self.free || self.operator || self.paid_until.is_some_and(|p| p + grace > now)
    }
}

/// The column list that [`Account`] reads, written once so every query selects the same columns.
macro_rules! account_columns {
    () => {
        "id, handle, status, suspension_kind, suspension_reason, suspended_until, free, operator, may_share_invites, \
         invited_by, tags, terms_version, country_declared, billing_ref, paid_until, created_at"
    };
}

/// What creating an account needs.
#[derive(Debug, Clone)]
pub struct NewAccount<'a> {
    /// Chosen before the account exists (a passkey ceremony needs the user id first).
    pub id: Uuid,
    /// The chosen handle.
    pub handle: &'a str,
    /// The handle's confusable skeleton: two handles that look alike cannot both exist.
    pub handle_skeleton: &'a str,
    /// The version of the terms accepted.
    pub terms_version: &'a str,
    /// The country the holder declared.
    pub country_declared: Option<&'a str>,
    /// The opaque reference for payment providers.
    pub billing_ref: &'a str,
    /// Whether this is an operator account.
    pub operator: bool,
    /// The initial (unpublished) page document.
    pub draft: &'a str,
    /// SHA-256 of an invite code to redeem in the same transaction (the account is then free).
    pub invite_hash: Option<&'a [u8]>,
}

/// Why an account could not be created.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    /// The handle exists or is too close to one that does.
    #[error("that handle is taken or too close to one that exists")]
    HandleTaken,
    /// The invite code does not exist, is used, is revoked or has expired.
    #[error("that invite code is not valid")]
    InviteInvalid,
    /// The database failed.
    #[error(transparent)]
    Db(#[from] DbError),
}

/// A page as its owner sees it (`lib.pages`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct PageRow {
    /// The draft document, canonical JSON.
    pub draft: String,
    /// The published document, if any.
    pub published: Option<String>,
    /// The number of the current version.
    pub version: i32,
    /// When the draft last changed.
    pub updated_at: OffsetDateTime,
    /// When it was last published.
    pub published_at: Option<OffsetDateTime>,
}

/// What the page process reads about a handle (`public.page_v1`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct PublicPage {
    /// The handle.
    pub handle: String,
    /// The account's status.
    pub status: String,
    /// The kind of suspension, if any.
    pub suspension_kind: Option<String>,
    /// When the suspension ends.
    pub suspended_until: Option<OffsetDateTime>,
    /// Whether the account is free.
    pub free: bool,
    /// Whether it is an operator account.
    pub operator: bool,
    /// The end of the paid period.
    pub paid_until: Option<OffsetDateTime>,
    /// The published document.
    pub published: Option<String>,
    /// When it was published.
    pub published_at: Option<OffsetDateTime>,
}

/// A stored picture (`lib.assets`), addressed by its content hash.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AssetRow {
    /// The hex SHA-256 of the bytes.
    pub sha256: String,
    /// The media type.
    pub mime: String,
    /// The file extension.
    pub ext: String,
    /// The width in pixels.
    pub width: i32,
    /// The height in pixels.
    pub height: i32,
    /// The re-encoded picture.
    pub bytes: Vec<u8>,
}

/// An invite code's record (`lib.invites`); the code itself is looked up by its hash.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Invite {
    /// The invite's id.
    pub id: Uuid,
    /// The account the operator gave the code to, to pass on.
    pub held_by: Option<Uuid>,
    /// The saved selection the code was issued for.
    pub selection_id: Option<Uuid>,
    /// The operator's note.
    pub note: Option<String>,
    /// Who issued it.
    pub created_by: String,
    /// When it was issued.
    pub created_at: OffsetDateTime,
    /// When it stops being valid.
    pub expires_at: OffsetDateTime,
    /// The account that used it.
    pub redeemed_by: Option<Uuid>,
    /// When it was used.
    pub redeemed_at: Option<OffsetDateTime>,
    /// When it was revoked.
    pub revoked_at: Option<OffsetDateTime>,
}

/// A saved set of criteria for issuing invites to a group of accounts (`lib.selections`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Selection {
    /// The selection's id.
    pub id: Uuid,
    /// Its unique name.
    pub name: String,
    /// The criteria as JSON (see [`Criteria`]).
    pub criteria: Value,
    /// Who saved it.
    pub created_by: String,
    /// When it was saved.
    pub created_at: OffsetDateTime,
}

/// The criteria a saved selection matches accounts by (every given criterion must hold).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Criteria {
    /// Account at least this many days old.
    pub min_age_days: Option<i32>,
    /// Has a published page.
    pub published: Option<bool>,
    /// Paid now (or free when `false`).
    pub paid: Option<bool>,
    /// None of the accounts it invited is suspended.
    pub invitees_in_good_standing: Option<bool>,
    /// Carries this tag.
    pub tag: Option<String>,
}

/// A started purchase (`lib.checkouts`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Checkout {
    /// The checkout's id.
    pub id: Uuid,
    /// The buyer's account.
    pub account_id: Uuid,
    /// The payment provider.
    pub provider: String,
    /// The provider's reference for it.
    pub provider_ref: String,
    /// The method the buyer chose.
    pub method: String,
    /// The months being bought.
    pub months: i32,
    /// The price in pence.
    pub amount_pence: i64,
    /// `open`, `paid`, `expired` or `cancelled`.
    pub status: String,
    /// The buyer's declared country, as tax evidence.
    pub country_declared: Option<String>,
    /// The country of the request (`CF-IPCountry`), as tax evidence.
    pub country_request: Option<String>,
    /// When it was started.
    pub created_at: OffsetDateTime,
    /// When it was paid or closed.
    pub completed_at: Option<OffsetDateTime>,
    /// The method's fees when the checkout was made (`None` before schema 6).
    pub fee_fixed_pence: Option<i32>,
    /// The method's percentage fee in basis points when the checkout was made (`None` before schema 6).
    pub fee_percent_bps: Option<i32>,
}

/// One change to an account's paid period (`lib.billing_events`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BillingEvent {
    /// The event's id.
    pub id: Uuid,
    /// The provider the change came from.
    pub provider: String,
    /// The provider's id of the event, unique per provider, which makes a change apply once.
    pub provider_event: String,
    /// `purchase`, `grant` or `refund`.
    pub kind: String,
    /// The months added (negative for a refund).
    pub months: i32,
    /// The amount in pence.
    pub amount_pence: i64,
    /// The end of the paid period after the change.
    pub paid_until_after: Option<OffsetDateTime>,
    /// When it was recorded.
    pub created_at: OffsetDateTime,
    /// A payment that arrived after its checkout was paid or closed (credited as months; refundable on request).
    pub unapplied: bool,
}

/// One billing event with its account and evidence.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BillingEventDetail {
    /// The event's id.
    pub id: Uuid,
    /// The account whose period changed.
    pub account_id: Uuid,
    /// The provider.
    pub provider: String,
    /// `purchase`, `grant` or `refund`.
    pub kind: String,
    /// The months added (negative for a refund).
    pub months: i32,
    /// The amount in pence.
    pub amount_pence: i64,
    /// What the provider said about the payment, as JSON.
    pub evidence: Value,
    /// When it was recorded.
    pub created_at: OffsetDateTime,
}

/// An account holder's refund request (`kind`: `cancel`, `unstarted` or `unapplied`). What each purchase gives back is
/// a [`RefundLine`]; a request made before schema 6 has none and names its one payment (`event_id`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct RefundRequest {
    /// The request's id.
    pub id: Uuid,
    /// The one payment a request made before schema 6 named.
    pub event_id: Option<Uuid>,
    /// The account asking.
    pub account_id: Uuid,
    /// The account's handle.
    pub handle: String,
    /// `cancel`, `unstarted` or `unapplied`.
    pub kind: String,
    /// The holder's reason.
    pub reason: String,
    /// The request's status.
    pub status: String,
    /// What the request was worked out from, as JSON.
    pub details: Value,
    /// The operator's reference for the refund they sent.
    pub refund_reference: Option<String>,
    /// The billing event that took the months back.
    pub refund_event: Option<Uuid>,
    /// Who decided.
    pub decided_by: Option<String>,
    /// When it was decided.
    pub decided_at: Option<OffsetDateTime>,
    /// When it was asked.
    pub created_at: OffsetDateTime,
    /// The provider of the one payment (older requests).
    pub provider: Option<String>,
    /// The months of the one payment (older requests).
    pub months: Option<i32>,
    /// The amount of the one payment (older requests).
    pub amount_pence: Option<i64>,
    /// The evidence of the one payment (older requests).
    pub evidence: Option<Value>,
    /// When the one payment was made (older requests).
    pub paid_at: Option<OffsetDateTime>,
}

/// What one purchase gives back on a refund request, exactly: the operator sends `amount_minor` of `unit` to
/// `destination`, and the ledger takes back `months`.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct RefundLine {
    /// The request it belongs to.
    pub request_id: Uuid,
    /// The purchase it refunds.
    pub purchase_id: Uuid,
    /// The purchase's checkout.
    pub checkout_id: Option<Uuid>,
    /// The provider of the purchase.
    pub provider: String,
    /// The months taken back.
    pub months: i32,
    /// What to send, in the unit's smallest denomination.
    pub amount_minor: i64,
    /// The unit of the amounts (a currency code or a coin type).
    pub unit: String,
    /// The unit's decimals, when known.
    pub scale: Option<i32>,
    /// The provider's fee share, in the same unit.
    pub fee_minor: i64,
    /// The cost of sending the refund, in the same unit.
    pub charge_minor: i64,
    /// The value of the days used, in the same unit.
    pub used_minor: i64,
    /// The days begun since the purchase's first month started.
    pub days_used: i32,
    /// The refund's value in pence, for the ledger.
    pub amount_pence: i64,
    /// Where and how to send it, as JSON.
    pub destination: Value,
    /// The line's status.
    pub status: String,
    /// The operator's reference.
    pub refund_reference: Option<String>,
    /// The billing event that took the months back.
    pub refund_event: Option<Uuid>,
    /// When it was refunded.
    pub refunded_at: Option<OffsetDateTime>,
    /// The months its purchase still gives now.
    pub held: i64,
}

/// A line to record with a new refund request.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRefundLine {
    /// The purchase to refund.
    pub purchase_id: Uuid,
    /// Its checkout.
    pub checkout_id: Option<Uuid>,
    /// Its provider.
    pub provider: String,
    /// The months to take back.
    pub months: i32,
    /// What to send, in the unit's smallest denomination.
    pub amount_minor: i64,
    /// The unit of the amounts.
    pub unit: String,
    /// The unit's decimals, when known.
    pub scale: Option<i32>,
    /// The provider's fee share.
    pub fee_minor: i64,
    /// The cost of sending.
    pub charge_minor: i64,
    /// The value of the days used.
    pub used_minor: i64,
    /// The days begun.
    pub days_used: i32,
    /// The value in pence.
    pub amount_pence: i64,
    /// Where and how to send it.
    pub destination: Value,
}

/// Why a refund request was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefundConflict {
    /// The account already has an open request.
    OpenRequest,
    /// This payment was asked about before (a late payment is asked back once).
    AlreadyAsked,
}

/// A line refunded: whose period changed, how many months it took back, and whether the request is now closed.
#[derive(Debug, Clone, PartialEq)]
pub struct LineRefunded {
    /// The account whose period changed.
    pub account_id: Uuid,
    /// The billing event of the refund.
    pub event_id: Uuid,
    /// The months it took back.
    pub months_taken: u32,
    /// The paid period after it.
    pub paid_until: Option<OffsetDateTime>,
    /// Whether every line of the request is now refunded.
    pub request_closed: bool,
}

/// A purchase or grant with the months it still gives (its months plus its refunds'), for refunds on request.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Extension {
    /// The purchase or grant's event id.
    pub id: Uuid,
    /// Its provider.
    pub provider: String,
    /// `purchase` or `grant`.
    pub kind: String,
    /// The months it added.
    pub months: i32,
    /// The months it still gives (its months less what refunds took back).
    pub held: i64,
    /// The amount in pence.
    pub amount_pence: i64,
    /// The provider's evidence, as JSON.
    pub evidence: Value,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// The end of the paid period after it.
    pub paid_until_after: Option<OffsetDateTime>,
    /// Its checkout, if any.
    pub checkout_id: Option<Uuid>,
    /// The checkout's method.
    pub method: Option<String>,
    /// The checkout's provider reference.
    pub provider_ref: Option<String>,
    /// The method's fees recorded on its checkout (`None` before schema 6).
    pub fee_fixed_pence: Option<i32>,
    /// The method's percentage fee recorded on its checkout.
    pub fee_percent_bps: Option<i32>,
}

/// One Web Risk threat list as the worker keeps it (`prefixes`: sorted, each a length byte and its bytes).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct WebRiskList {
    /// The list's threat type.
    pub threat_type: String,
    /// The version token for the next `computeDiff`.
    pub version_token: String,
    /// How many prefixes it holds.
    pub entries: i32,
    /// The prefixes, sorted, each as a length byte and its bytes.
    pub prefixes: Vec<u8>,
    /// The checksum of the list, base64.
    pub checksum: String,
    /// When Web Risk may next be asked.
    pub next_diff_at: Option<OffsetDateTime>,
    /// When the list last changed.
    pub updated_at: OffsetDateTime,
    /// The last failure's reason, if the last update failed.
    pub last_error: Option<String>,
}

/// A Web Risk list's state without its prefixes (what the app compares to decide whether to reload, and the console
/// shows).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct WebRiskListState {
    /// The list's threat type.
    pub threat_type: String,
    /// The version token.
    pub version_token: String,
    /// How many prefixes it holds.
    pub entries: i32,
    /// When Web Risk may next be asked.
    pub next_diff_at: Option<OffsetDateTime>,
    /// When the list last changed.
    pub updated_at: OffsetDateTime,
    /// The last failure's reason.
    pub last_error: Option<String>,
}

/// A recorded refund: whose period changed, to when, and the refund's own billing event.
#[derive(Debug, Clone, PartialEq)]
pub struct RefundDone {
    /// The account whose period changed.
    pub account_id: Uuid,
    /// The refund's billing event.
    pub event_id: Uuid,
    /// The months taken back.
    pub months: i32,
    /// The end of the paid period after it.
    pub paid_until: OffsetDateTime,
}

/// One change to an account's paid period.
#[derive(Debug, Clone)]
pub struct PeriodChange<'a> {
    /// The account whose period changes.
    pub account_id: Uuid,
    /// The provider.
    pub provider: &'a str,
    /// The provider's id of the event, which makes the change apply once.
    pub provider_event: &'a str,
    /// `purchase`, `grant` (positive months) or `refund` (negative months).
    pub kind: &'a str,
    /// The months to add (negative for a refund).
    pub months: i32,
    /// The amount in pence.
    pub amount_pence: i64,
    /// What the provider said, as JSON.
    pub evidence: Value,
    /// The checkout this settles, if any (marked paid in the same transaction).
    pub checkout: Option<Uuid>,
    /// The checkout a purchase paid (recorded on the event; a late payment names its checkout without settling it).
    pub checkout_id: Option<Uuid>,
    /// For a refund: the purchase it takes months back from.
    pub refund_of: Option<Uuid>,
}

/// A refund of (part of) a purchase made through a checkout ([`Store::refund_purchase`]).
#[derive(Debug, Clone)]
pub struct RefundChange<'a> {
    /// The account whose period changes.
    pub account_id: Uuid,
    /// The provider.
    pub provider: &'a str,
    /// The provider's id of the refund event, which makes it apply once.
    pub provider_event: &'a str,
    /// The purchase's checkout.
    pub checkout: Uuid,
    /// The months the purchase bought.
    pub months: u32,
    /// What the purchase was paid and what this refund gives back, in the provider's minor units of one currency.
    pub paid_minor: u64,
    /// What this refund gives back, in the same unit.
    pub refunded_minor: u64,
    /// The checkout's amount in pence (the ledger's amount column is in pence).
    pub amount_pence: i64,
    /// What the provider said, as JSON.
    pub evidence: Value,
}

/// What a refund changed: the months it took back (possibly 0) and the paid period after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefundApplied {
    /// The months it took back, possibly none.
    pub months_taken: u32,
    /// The paid period after it.
    pub paid_until: Option<OffsetDateTime>,
}

/// Where a bank feed left off (`state` holds credentials of the feed's own; never show it).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BankFeedRow {
    /// The feed's id.
    pub feed: String,
    /// The opaque position to resume from.
    pub cursor: Option<String>,
    /// The feed's own state, as JSON.
    pub state: Value,
    /// When it was last polled.
    pub polled_at: Option<OffsetDateTime>,
    /// The last failure's reason.
    pub last_error: Option<String>,
    /// How many credits it has read in all.
    pub credits_seen: i64,
}

/// A custom domain an account asked for (`lib.domains`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Domain {
    /// The host name.
    pub hostname: String,
    /// The account it belongs to.
    pub account_id: Uuid,
    /// How it is verified: `dns-txt` or `cloudflare-saas`.
    pub method: String,
    /// The token to publish for the verification.
    pub token: String,
    /// `pending`, `verified` or `failed`.
    pub status: String,
    /// When it was last checked.
    pub checked_at: Option<OffsetDateTime>,
    /// When it was verified.
    pub verified_at: Option<OffsetDateTime>,
}

/// A report about a page or a link (`lib.reports`); no account is needed to make one.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Report {
    /// The report's id.
    pub id: Uuid,
    /// The page's handle.
    pub handle: String,
    /// The account, if it still exists.
    pub account_id: Option<Uuid>,
    /// The link reported, if one.
    pub url: Option<String>,
    /// The category of the report.
    pub reason: String,
    /// What the reporter wrote.
    pub details: String,
    /// An optional way to answer the reporter.
    pub contact: Option<String>,
    /// `open`, `actioned` or `dismissed`.
    pub status: String,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it was decided.
    pub decided_at: Option<OffsetDateTime>,
    /// Who decided.
    pub decided_by: Option<String>,
    /// A short note of the decision.
    pub decision: Option<String>,
    /// The statement of reasons sent to the account holder when content is restricted.
    pub statement: Option<String>,
}

/// An account holder's appeal against a decision (`lib.appeals`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Appeal {
    /// The appeal's id.
    pub id: Uuid,
    /// The account appealing.
    pub account_id: Uuid,
    /// The report it is about.
    pub report_id: Option<Uuid>,
    /// What the holder wrote.
    pub text: String,
    /// `open`, `upheld` or `rejected`.
    pub status: String,
    /// When it was made.
    pub created_at: OffsetDateTime,
    /// When it was decided.
    pub decided_at: Option<OffsetDateTime>,
    /// Who decided.
    pub decided_by: Option<String>,
    /// The reasons given to the holder.
    pub statement: Option<String>,
}

/// One row of the audit log: who did what to whom (`lib.audit_log`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AuditEntry {
    /// The row's number.
    pub id: i64,
    /// When it happened.
    pub at: OffsetDateTime,
    /// Who did it.
    pub actor: String,
    /// What was done.
    pub action: String,
    /// What it was done to.
    pub subject: String,
    /// More, as JSON.
    pub details: Value,
}

/// The screening verdict of one link (`lib.link_screens`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Screen {
    /// The SHA-256 of the canonical URL.
    pub url_hash: Vec<u8>,
    /// The URL.
    pub url: String,
    /// `clean`, `flagged` or `unknown`.
    pub verdict: String,
    /// The layer that decided.
    pub source: String,
    /// What it found.
    pub detail: String,
    /// When it was checked.
    pub checked_at: OffsetDateTime,
    /// When it is checked again.
    pub next_check_at: OffsetDateTime,
    /// The operator whose decision overrides every automatic source until it is cleared.
    pub overridden_by: Option<String>,
}

/// An entry of the operator's blocklist (`lib.blocklist`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BlockEntry {
    /// The host or URL blocked.
    pub pattern: String,
    /// `host` or `url`.
    pub kind: String,
    /// Why.
    pub reason: String,
    /// Who added it.
    pub added_by: String,
    /// When.
    pub added_at: OffsetDateTime,
}

/// Figures for `/metrics` and the admin overview.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stats {
    /// Accounts that are active.
    pub accounts_active: i64,
    /// Accounts that are suspended.
    pub accounts_suspended: i64,
    /// Active accounts that are free.
    pub accounts_free: i64,
    /// Active accounts that are paid up.
    pub accounts_paid: i64,
    /// Pages that are published.
    pub pages_published: i64,
    /// Reports not yet decided.
    pub reports_open: i64,
    /// Open reports older than a day.
    pub reports_open_over_24h: i64,
    /// Appeals not yet decided.
    pub appeals_open: i64,
    /// Links flagged.
    pub links_flagged: i64,
    /// Links that could not be checked.
    pub links_unknown: i64,
    /// Bytes of pictures stored.
    pub storage_bytes: i64,
    /// Checkouts still open.
    pub checkouts_open: i64,
}

/// Whether an error is a unique-constraint violation (PostgreSQL code 23505).
fn unique_violation(e: &DbError) -> bool {
    matches!(e, DbError::Database(d) if d.code().as_deref() == Some("23505"))
}

impl Store {
    /// A store over a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for the pieces that run their own statements in tests.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run the embedded migrations.
    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    /// Whether the database answers: the readiness check.
    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map(|_| ())
    }

    // ── accounts ───────────────────────────────────────────────────────────

    /// Creates an account and its (unpublished) page; redeems the invite in the same transaction when one is given.
    pub async fn create_account(&self, n: &NewAccount<'_>, now: OffsetDateTime) -> Result<Account, CreateError> {
        // The invite, if any, is checked and locked first, so two sign-ups cannot use one code; the account, its page and the redemption are one transaction.
        let mut tx = self.pool.begin().await?;
        let id = n.id;
        let mut invited_by = None;
        if let Some(h) = n.invite_hash {
            let row = sqlx::query(
                "SELECT i.id, i.held_by, coalesce(a.may_share_invites AND a.status = 'active', true) AS ok
                   FROM lib.invites i LEFT JOIN lib.accounts a ON a.id = i.held_by
                  WHERE i.code_hash = $1 AND i.redeemed_by IS NULL AND i.revoked_at IS NULL AND i.expires_at > $2
                  FOR UPDATE OF i",
            )
            .bind(h)
            .bind(now)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else { return Err(CreateError::InviteInvalid) };
            if !row.try_get::<bool, _>("ok")? {
                return Err(CreateError::InviteInvalid);
            }
            invited_by = row.try_get::<Option<Uuid>, _>("held_by")?;
            let invite: Uuid = row.try_get("id")?;
            // The account row must exist before the invite can point at it; mark it after the insert below.
            insert_account(&mut tx, id, n, true, invited_by, now).await?;
            sqlx::query("UPDATE lib.invites SET redeemed_by = $2, redeemed_at = $3, code = NULL WHERE id = $1")
                .bind(invite)
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        } else {
            insert_account(&mut tx, id, n, false, invited_by, now).await?;
        }
        sqlx::query("INSERT INTO lib.pages (account_id, draft, updated_at) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(n.draft)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(self.account(id).await?.ok_or(DbError::RowNotFound)?)
    }

    /// An account by id.
    pub async fn account(&self, id: Uuid) -> Result<Option<Account>, DbError> {
        sqlx::query_as(concat!("SELECT ", account_columns!(), " FROM lib.accounts WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    /// An account by handle.
    pub async fn account_by_handle(&self, handle: &str) -> Result<Option<Account>, DbError> {
        sqlx::query_as(concat!("SELECT ", account_columns!(), " FROM lib.accounts WHERE handle = $1"))
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
    }

    /// Whether neither the handle nor its skeleton is taken, so no look-alike can be registered.
    pub async fn handle_available(&self, handle: &str, skeleton: &str) -> Result<bool, DbError> {
        // Either the handle or its confusable skeleton existing makes it unavailable.
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM lib.accounts WHERE handle = $1 OR handle_skeleton = $2")
            .bind(handle)
            .bind(skeleton)
            .fetch_one(&self.pool)
            .await?;
        Ok(n == 0)
    }

    /// Accounts for the admin list: by handle prefix (or all), newest first.
    pub async fn accounts(&self, prefix: &str, limit: i64, offset: i64) -> Result<Vec<Account>, DbError> {
        // Newest first, with a limit and an offset for paging.
        // The prefix is stripped of `%`, `_` and backslashes, so it cannot act as a pattern.
        sqlx::query_as(concat!(
            "SELECT ",
            account_columns!(),
            " FROM lib.accounts WHERE handle LIKE $1 || '%' ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        ))
        .bind(prefix.replace(['%', '_', '\\'], ""))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
    }

    /// Record the country the account holder declared, or clear it.
    pub async fn set_country(&self, id: Uuid, country: Option<&str>) -> Result<(), DbError> {
        // A null clears the declaration.
        sqlx::query("UPDATE lib.accounts SET country_declared = $2 WHERE id = $1")
            .bind(id)
            .bind(country)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Operator flags: whether the account is the operator's own (served while third-party pages are off), free, may
    /// pass on invites, and its tags.
    pub async fn set_flags(
        &self,
        id: Uuid,
        operator: bool,
        free: bool,
        may_share_invites: bool,
        tags: &[String],
    ) -> Result<bool, DbError> {
        let r = sqlx::query(
            "UPDATE lib.accounts SET operator = $2, free = $3, may_share_invites = $4, tags = $5 WHERE id = $1",
        )
        .bind(id)
        .bind(operator)
        .bind(free)
        .bind(may_share_invites)
        .bind(tags)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Suspends an account: its page stops being served (451 for `legal`, 410 for `policy`) and its sessions end.
    pub async fn suspend(
        &self,
        id: Uuid,
        kind: &str,
        reason: &str,
        until: Option<OffsetDateTime>,
    ) -> Result<bool, DbError> {
        // The suspension and the end of the account's sessions are one transaction, so a suspended account cannot stay signed in.
        let mut tx = self.pool.begin().await?;
        let r = sqlx::query(
            "UPDATE lib.accounts SET status = 'suspended', suspension_kind = $2, suspension_reason = $3,
                    suspended_until = $4
              WHERE id = $1 AND status <> 'deleted'",
        )
        .bind(id)
        .bind(kind)
        .bind(reason)
        .bind(until)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM lib.sessions WHERE account_id = $1").bind(id).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(r.rows_affected() == 1)
    }

    /// Lift a suspension by hand; false if the account was not suspended.
    pub async fn unsuspend(&self, id: Uuid) -> Result<bool, DbError> {
        // Clears every suspension field together, so the table's check constraint holds.
        let r = sqlx::query(
            "UPDATE lib.accounts SET status = 'active', suspension_kind = NULL, suspension_reason = NULL,
                    suspended_until = NULL
              WHERE id = $1 AND status = 'suspended'",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Lifts suspensions whose end has passed; returns the accounts reinstated.
    pub async fn lift_expired_suspensions(&self, now: OffsetDateTime) -> Result<Vec<Uuid>, DbError> {
        // Returns the ids so each reinstated account can be audited.
        sqlx::query_scalar(
            "UPDATE lib.accounts SET status = 'active', suspension_kind = NULL, suspension_reason = NULL,
                    suspended_until = NULL
              WHERE status = 'suspended' AND suspended_until IS NOT NULL AND suspended_until <= $1
             RETURNING id",
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await
    }

    /// Erases an account at its holder's request: sign-in methods, sessions, pictures, domains and the page go; the
    /// row stays as `deleted` (the handle is not reissued) with the billing records the law requires to be kept.
    pub async fn delete_account(&self, id: Uuid, now: OffsetDateTime) -> Result<bool, DbError> {
        // Everything a person put in or signed in with goes in one transaction; the row stays so the handle is not issued again and the records the law requires are kept.
        let mut tx = self.pool.begin().await?;
        for q in [
            "DELETE FROM lib.sessions WHERE account_id = $1",
            "DELETE FROM lib.passkeys WHERE account_id = $1",
            "DELETE FROM lib.wallets WHERE account_id = $1",
            "DELETE FROM lib.recovery_codes WHERE account_id = $1",
            "DELETE FROM lib.challenges WHERE account_id = $1",
            "DELETE FROM lib.assets WHERE account_id = $1",
            "DELETE FROM lib.domains WHERE account_id = $1",
            "DELETE FROM lib.page_versions WHERE account_id = $1",
            "UPDATE lib.pages SET draft = '{}', published = NULL, published_at = NULL WHERE account_id = $1",
        ] {
            sqlx::query(q).bind(id).execute(&mut *tx).await?;
        }
        let r = sqlx::query(
            "UPDATE lib.accounts SET status = 'deleted', suspension_kind = NULL, suspension_reason = NULL,
                    suspended_until = NULL, country_declared = NULL, tags = '{}', deleted_at = $2
              WHERE id = $1 AND status <> 'deleted'",
        )
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(r.rows_affected() == 1)
    }

    /// The accounts an account invited (one level of the invite tree).
    pub async fn invitees(&self, id: Uuid) -> Result<Vec<Account>, DbError> {
        // The accounts that name this one as their inviter, oldest first.
        sqlx::query_as(concat!(
            "SELECT ",
            account_columns!(),
            " FROM lib.accounts WHERE invited_by = $1 ORDER BY created_at"
        ))
        .bind(id)
        .fetch_all(&self.pool)
        .await
    }

    // ── passkeys, wallets, recovery codes ──────────────────────────────────

    /// Store a new passkey for an account (its public key and counter; no secret).
    pub async fn add_passkey(
        &self,
        account: Uuid,
        credential_id: &[u8],
        passkey: &Value,
        name: &str,
    ) -> Result<(), DbError> {
        // The passkey is the public key and counter, so a stolen database holds nothing that signs in.
        sqlx::query("INSERT INTO lib.passkeys (credential_id, account_id, passkey, name) VALUES ($1, $2, $3, $4)")
            .bind(credential_id)
            .bind(account)
            .bind(passkey)
            .bind(name)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// An account's passkeys, oldest first: credential id, passkey and name.
    pub async fn passkeys(&self, account: Uuid) -> Result<Vec<(Vec<u8>, Value, String)>, DbError> {
        let rows = sqlx::query(
            "SELECT credential_id, passkey, name FROM lib.passkeys WHERE account_id = $1 ORDER BY created_at",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok((r.try_get("credential_id")?, r.try_get("passkey")?, r.try_get("name")?))).collect()
    }

    /// The account and the passkey a credential id belongs to.
    pub async fn passkey_owner(&self, credential_id: &[u8]) -> Result<Option<(Uuid, Value)>, DbError> {
        // A passkey's credential id is unique, so at most one account matches.
        let r = sqlx::query("SELECT account_id, passkey FROM lib.passkeys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await?;
        r.map(|r| Ok((r.try_get("account_id")?, r.try_get("passkey")?))).transpose()
    }

    /// Store a passkey after a sign-in (its counter changed) and note when it was used.
    pub async fn update_passkey(
        &self,
        credential_id: &[u8],
        passkey: &Value,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // The counter changes with each use, so the stored passkey is replaced as a whole.
        sqlx::query("UPDATE lib.passkeys SET passkey = $2, last_used_at = $3 WHERE credential_id = $1")
            .bind(credential_id)
            .bind(passkey)
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Removes a passkey unless it is the account's last way to sign in.
    pub async fn delete_passkey(&self, account: Uuid, credential_id: &[u8]) -> Result<bool, DbError> {
        // The subquery refuses to remove the last way to sign in, so an account cannot lock itself out.
        let r = sqlx::query(
            "DELETE FROM lib.passkeys WHERE account_id = $1 AND credential_id = $2
               AND ((SELECT count(*) FROM lib.passkeys WHERE account_id = $1)
                  + (SELECT count(*) FROM lib.wallets WHERE account_id = $1)) > 1",
        )
        .bind(account)
        .bind(credential_id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Links a wallet address; false when another account already has it.
    pub async fn add_wallet(&self, account: Uuid, address: &str) -> Result<bool, DbError> {
        // A wallet address belongs to one account; a second link is a unique violation, which is the answer `false`.
        match sqlx::query("INSERT INTO lib.wallets (address, account_id) VALUES ($1, $2)")
            .bind(address)
            .bind(account)
            .execute(&self.pool)
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if unique_violation(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// The account a wallet address is linked to.
    pub async fn wallet_owner(&self, address: &str) -> Result<Option<Uuid>, DbError> {
        // The account a wallet address signs in to.
        sqlx::query_scalar("SELECT account_id FROM lib.wallets WHERE address = $1")
            .bind(address)
            .fetch_optional(&self.pool)
            .await
    }

    /// An account's linked wallet addresses, oldest first.
    pub async fn wallets(&self, account: Uuid) -> Result<Vec<String>, DbError> {
        // In the order they were linked.
        sqlx::query_scalar("SELECT address FROM lib.wallets WHERE account_id = $1 ORDER BY created_at")
            .bind(account)
            .fetch_all(&self.pool)
            .await
    }

    /// Unlinks a wallet unless it is the account's last way to sign in.
    pub async fn delete_wallet(&self, account: Uuid, address: &str) -> Result<bool, DbError> {
        // The same last-method rule as for passkeys: one count across both kinds.
        let r = sqlx::query(
            "DELETE FROM lib.wallets WHERE account_id = $1 AND address = $2
               AND ((SELECT count(*) FROM lib.passkeys WHERE account_id = $1)
                  + (SELECT count(*) FROM lib.wallets WHERE account_id = $1)) > 1",
        )
        .bind(account)
        .bind(address)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Replaces the account's recovery codes (SHA-256 of each).
    pub async fn set_recovery_codes(&self, account: Uuid, hashes: &[Vec<u8>]) -> Result<(), DbError> {
        // The old codes are deleted and the new ones inserted in one transaction, so there is never a mix.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM lib.recovery_codes WHERE account_id = $1").bind(account).execute(&mut *tx).await?;
        for h in hashes {
            sqlx::query("INSERT INTO lib.recovery_codes (account_id, code_hash) VALUES ($1, $2)")
                .bind(account)
                .bind(h)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await
    }

    /// Uses one recovery code of the account with this handle; returns the account when the code was unused.
    pub async fn use_recovery_code(
        &self,
        handle: &str,
        hash: &[u8],
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, DbError> {
        // Marks the code used only for an active account and only if it was unused, so one code works once.
        sqlx::query_scalar(
            "UPDATE lib.recovery_codes r SET used_at = $3
               FROM lib.accounts a
              WHERE a.id = r.account_id AND a.handle = $1 AND a.status = 'active'
                AND r.code_hash = $2 AND r.used_at IS NULL
             RETURNING r.account_id",
        )
        .bind(handle)
        .bind(hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
    }

    /// How many recovery codes an account has not used.
    pub async fn recovery_codes_left(&self, account: Uuid) -> Result<i64, DbError> {
        sqlx::query_scalar("SELECT count(*) FROM lib.recovery_codes WHERE account_id = $1 AND used_at IS NULL")
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    // ── sessions and challenges ────────────────────────────────────────────

    /// Store a session by the hash of its cookie value; the value itself is never kept.
    pub async fn create_session(
        &self,
        token_hash: &[u8],
        account: Uuid,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbError> {
        sqlx::query("INSERT INTO lib.sessions (token_hash, account_id, expires_at) VALUES ($1, $2, $3)")
            .bind(token_hash)
            .bind(account)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// The account of a live session (of an active account), sliding its expiry forward to `extend_to` (never past
    /// the absolute limit, which the caller encodes in `extend_to`).
    pub async fn session_account(
        &self,
        token_hash: &[u8],
        now: OffsetDateTime,
        idle: Duration,
        absolute: Duration,
    ) -> Result<Option<Uuid>, DbError> {
        // Looking a session up slides its idle expiry forward but never past the absolute limit, and an account that is not active has no session.
        sqlx::query_scalar(
            "UPDATE lib.sessions s SET last_seen_at = $2,
                    expires_at = least(s.created_at + $4, $2 + $3)
               FROM lib.accounts a
              WHERE s.token_hash = $1 AND s.expires_at > $2 AND a.id = s.account_id AND a.status = 'active'
             RETURNING s.account_id",
        )
        .bind(token_hash)
        .bind(now)
        .bind(idle)
        .bind(absolute)
        .fetch_optional(&self.pool)
        .await
    }

    /// End one session (sign out).
    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<(), DbError> {
        sqlx::query("DELETE FROM lib.sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// End every session of an account, returning how many there were.
    pub async fn delete_sessions(&self, account: Uuid) -> Result<u64, DbError> {
        Ok(sqlx::query("DELETE FROM lib.sessions WHERE account_id = $1")
            .bind(account)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    /// Store the server-side state of a passkey or wallet ceremony until it expires.
    pub async fn put_challenge(
        &self,
        id: &str,
        kind: &str,
        account: Option<Uuid>,
        state: &Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), DbError> {
        sqlx::query("INSERT INTO lib.challenges (id, kind, account_id, state, expires_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(id)
            .bind(kind)
            .bind(account)
            .bind(state)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Takes (deletes and returns) a live challenge of this kind: each can be answered once.
    pub async fn take_challenge(
        &self,
        id: &str,
        kind: &str,
        now: OffsetDateTime,
    ) -> Result<Option<(Option<Uuid>, Value)>, DbError> {
        // Delete-and-return in one statement, so a challenge is answered at most once.
        let r = sqlx::query(
            "DELETE FROM lib.challenges WHERE id = $1 AND kind = $2 AND expires_at > $3 RETURNING account_id, state",
        )
        .bind(id)
        .bind(kind)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        r.map(|r| Ok((r.try_get("account_id")?, r.try_get("state")?))).transpose()
    }

    // ── pages and pictures ─────────────────────────────────────────────────

    /// An account's page: draft, published document and versions.
    pub async fn page(&self, account: Uuid) -> Result<Option<PageRow>, DbError> {
        sqlx::query_as(
            "SELECT draft, published, version, updated_at, published_at FROM lib.pages WHERE account_id = $1",
        )
        .bind(account)
        .fetch_optional(&self.pool)
        .await
    }

    /// Save the draft document (already checked by the parser) without publishing it.
    pub async fn save_draft(&self, account: Uuid, manifest: &str, now: OffsetDateTime) -> Result<(), DbError> {
        sqlx::query("UPDATE lib.pages SET draft = $2, updated_at = $3 WHERE account_id = $1")
            .bind(account)
            .bind(manifest)
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Publishes a checked manifest as the next version (the draft becomes the same document). Returns the version.
    pub async fn publish(&self, account: Uuid, manifest: &str, now: OffsetDateTime) -> Result<i32, DbError> {
        // The page row and the version history change in one transaction.
        let mut tx = self.pool.begin().await?;
        let version: i32 = sqlx::query_scalar(
            "UPDATE lib.pages SET draft = $2, published = $2, version = version + 1, updated_at = $3, published_at = $3
              WHERE account_id = $1 RETURNING version",
        )
        .bind(account)
        .bind(manifest)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO lib.page_versions (account_id, version, manifest, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(account)
        .bind(version)
        .bind(manifest)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(version)
    }

    /// Takes the page offline (the draft and the versions stay); `updated_at` records when.
    pub async fn unpublish(&self, account: Uuid) -> Result<(), DbError> {
        // The draft and the kept versions stay; only the published document is cleared.
        sqlx::query(
            "UPDATE lib.pages SET published = NULL, published_at = NULL, updated_at = now() WHERE account_id = $1",
        )
        .bind(account)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// The numbers and times of an account's kept versions, newest first.
    pub async fn page_versions(&self, account: Uuid) -> Result<Vec<(i32, OffsetDateTime)>, DbError> {
        // Newest first.
        let rows = sqlx::query(
            "SELECT version, created_at FROM lib.page_versions WHERE account_id = $1 ORDER BY version DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok((r.try_get("version")?, r.try_get("created_at")?))).collect()
    }

    /// The document of one kept version.
    pub async fn page_version(&self, account: Uuid, version: i32) -> Result<Option<String>, DbError> {
        // The stored document of one version.
        sqlx::query_scalar("SELECT manifest FROM lib.page_versions WHERE account_id = $1 AND version = $2")
            .bind(account)
            .bind(version)
            .fetch_optional(&self.pool)
            .await
    }

    /// Keeps the newest `keep` versions of every page.
    pub async fn prune_versions(&self, keep: i64) -> Result<u64, DbError> {
        // Numbers the versions of each page from the newest and deletes those past `keep`.
        Ok(sqlx::query(
            "DELETE FROM lib.page_versions v USING (
                SELECT account_id, version, row_number() OVER (PARTITION BY account_id ORDER BY version DESC) AS n
                  FROM lib.page_versions) o
              WHERE v.account_id = o.account_id AND v.version = o.version AND o.n > $1",
        )
        .bind(keep)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    /// Store a picture for an account; the same picture stored again is ignored.
    pub async fn put_asset(&self, account: Uuid, a: &AssetRow) -> Result<(), DbError> {
        // Pictures are addressed by content, so the same file uploaded twice is stored once per account.
        sqlx::query(
            "INSERT INTO lib.assets (sha256, account_id, mime, ext, width, height, bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (sha256, account_id) DO NOTHING",
        )
        .bind(&a.sha256)
        .bind(account)
        .bind(&a.mime)
        .bind(&a.ext)
        .bind(a.width)
        .bind(a.height)
        .bind(&a.bytes)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// Whether this account stored the picture (a page may only use its own pictures).
    pub async fn owns_asset(&self, account: Uuid, sha256: &str) -> Result<bool, DbError> {
        // A page may use only its own account's pictures.
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM lib.assets WHERE sha256 = $1 AND account_id = $2)")
            .bind(sha256)
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    /// Bytes of pictures an account stored (its quota).
    pub async fn asset_bytes(&self, account: Uuid) -> Result<i64, DbError> {
        // The sum of the stored picture sizes, which is the account's quota use.
        sqlx::query_scalar("SELECT coalesce(sum(length(bytes)), 0)::bigint FROM lib.assets WHERE account_id = $1")
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    /// Deletes an account's pictures no draft, published page or kept version refers to.
    pub async fn prune_assets(&self) -> Result<u64, DbError> {
        // A picture goes when it is more than a day old and no draft, published page or kept version names its hash.
        Ok(sqlx::query(
            "DELETE FROM lib.assets a
              WHERE a.created_at < now() - interval '1 day'
                AND NOT EXISTS (SELECT 1 FROM lib.pages p WHERE p.account_id = a.account_id
                                  AND (strpos(p.draft, a.sha256) > 0 OR strpos(coalesce(p.published, ''), a.sha256) > 0))
                AND NOT EXISTS (SELECT 1 FROM lib.page_versions v WHERE v.account_id = a.account_id
                                  AND strpos(v.manifest, a.sha256) > 0)",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    // ── the page process (read-only role, public views only) ──────────────

    /// A page for the page process, from the public view only.
    pub async fn view_page(&self, handle: &str) -> Result<Option<PublicPage>, DbError> {
        // Reads the public view, which holds only what a page host may know.
        sqlx::query_as(
            "SELECT handle, status, suspension_kind, suspended_until, free, operator, paid_until, published, published_at
               FROM public.page_v1 WHERE handle = $1",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await
    }

    /// A picture for the page process, from the public view only.
    pub async fn view_asset(&self, sha256: &str) -> Result<Option<AssetRow>, DbError> {
        // The public view of a picture.
        sqlx::query_as("SELECT sha256, mime, ext, width, height, bytes FROM public.asset_v1 WHERE sha256 = $1")
            .bind(sha256)
            .fetch_optional(&self.pool)
            .await
    }

    /// The handle behind a verified custom domain, from the public view only.
    pub async fn view_domain(&self, hostname: &str) -> Result<Option<String>, DbError> {
        // Only a verified domain is in the view.
        sqlx::query_scalar("SELECT handle FROM public.domain_v1 WHERE hostname = $1")
            .bind(hostname)
            .fetch_optional(&self.pool)
            .await
    }

    /// Which of these link URL hashes are flagged.
    pub async fn view_flagged(&self, hashes: &[Vec<u8>]) -> Result<HashSet<Vec<u8>>, DbError> {
        // Only the flagged hashes of the ones asked about come back; the page process never sees the screening table.
        if hashes.is_empty() {
            return Ok(HashSet::new());
        }
        let rows: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT url_hash FROM public.flagged_link_v1 WHERE url_hash = ANY($1)")
                .bind(hashes)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows.into_iter().collect())
    }

    // ── invites ────────────────────────────────────────────────────────────

    /// Stores operator-issued invite codes: their hashes, and for codes given to an account (`held_by`) the codes
    /// themselves, readable by the holder until redeemed or revoked.
    pub async fn create_invites(
        &self,
        codes: &[(Vec<u8>, String)],
        held_by: Option<Uuid>,
        selection: Option<Uuid>,
        note: Option<&str>,
        created_by: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Vec<Uuid>, DbError> {
        // All codes of one issue are inserted in one transaction. Only a code given to an account keeps its text.
        let mut tx = self.pool.begin().await?;
        let mut ids = Vec::with_capacity(codes.len());
        for (h, code) in codes {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO lib.invites (id, code_hash, held_by, code, selection_id, note, created_by, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(id)
            .bind(h)
            .bind(held_by)
            .bind(held_by.map(|_| code.as_str()))
            .bind(selection)
            .bind(note)
            .bind(created_by)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
            ids.push(id);
        }
        tx.commit().await?;
        Ok(ids)
    }

    /// The unredeemed, unexpired codes an account holds (to pass on), and how many of its codes were redeemed.
    pub async fn held_codes(
        &self,
        account: Uuid,
        now: OffsetDateTime,
    ) -> Result<(Vec<(String, OffsetDateTime)>, i64), DbError> {
        // The codes an account may still pass on, and then how many of its codes were used.
        let rows = sqlx::query(
            "SELECT code, expires_at FROM lib.invites
              WHERE held_by = $1 AND code IS NOT NULL AND redeemed_by IS NULL AND revoked_at IS NULL AND expires_at > $2
              ORDER BY created_at",
        )
        .bind(account)
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let codes = rows
            .iter()
            .map(|r| Ok((r.try_get("code")?, r.try_get("expires_at")?)))
            .collect::<Result<Vec<_>, DbError>>()?;
        let used: i64 =
            sqlx::query_scalar("SELECT count(*) FROM lib.invites WHERE held_by = $1 AND redeemed_by IS NOT NULL")
                .bind(account)
                .fetch_one(&self.pool)
                .await?;
        Ok((codes, used))
    }

    /// The invites an operator issued, newest first, for one holder or for all (the code itself is never returned).
    pub async fn invites(&self, held_by: Option<Uuid>, limit: i64) -> Result<Vec<Invite>, DbError> {
        // A null holder means every invite.
        sqlx::query_as(
            "SELECT id, held_by, selection_id, note, created_by, created_at, expires_at, redeemed_by, redeemed_at,
                    revoked_at
               FROM lib.invites WHERE ($1::uuid IS NULL OR held_by = $1) ORDER BY created_at DESC LIMIT $2",
        )
        .bind(held_by)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Revoke an invite that is neither used nor already revoked, and forget its readable code; false if it was not open.
    pub async fn revoke_invite(&self, id: Uuid, now: OffsetDateTime) -> Result<bool, DbError> {
        let r = sqlx::query(
            "UPDATE lib.invites SET revoked_at = $2, code = NULL WHERE id = $1 AND redeemed_by IS NULL AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Save a named set of criteria; names are unique.
    pub async fn create_selection(&self, name: &str, criteria: &Criteria, by: &str) -> Result<Uuid, DbError> {
        // The criteria are stored as JSON, as `Criteria` serialises them.
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO lib.selections (id, name, criteria, created_by) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(name)
            .bind(serde_json::to_value(criteria).unwrap_or_default())
            .bind(by)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    /// Every saved selection, by name.
    pub async fn selections(&self) -> Result<Vec<Selection>, DbError> {
        // By name.
        sqlx::query_as("SELECT id, name, criteria, created_by, created_at FROM lib.selections ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    /// One saved selection.
    pub async fn selection(&self, id: Uuid) -> Result<Option<Selection>, DbError> {
        // One selection by id.
        sqlx::query_as("SELECT id, name, criteria, created_by, created_at FROM lib.selections WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    /// Delete a saved selection; invites already issued for it stay, without the link.
    pub async fn delete_selection(&self, id: Uuid) -> Result<bool, DbError> {
        // The invites keep their codes; the link to the selection is set to null by the schema.
        Ok(sqlx::query("DELETE FROM lib.selections WHERE id = $1").bind(id).execute(&self.pool).await?.rows_affected()
            == 1)
    }

    /// The active accounts a selection's criteria match now.
    pub async fn match_selection(&self, c: &Criteria, now: OffsetDateTime) -> Result<Vec<Account>, DbError> {
        // Each criterion that is not null must hold; null ones are ignored. Only active accounts match.
        sqlx::query_as(concat!(
            "SELECT ",
            account_columns!(),
            " FROM lib.accounts a WHERE a.status = 'active'
                AND ($1::int IS NULL OR a.created_at <= $6 - make_interval(days => $1))
                AND ($2::bool IS NULL OR $2 = EXISTS (SELECT 1 FROM lib.pages p WHERE p.account_id = a.id AND p.published IS NOT NULL))
                AND ($3::bool IS NULL OR $3 = (a.paid_until IS NOT NULL AND a.paid_until > $6))
                AND ($4::bool IS NULL OR $4 = NOT EXISTS (SELECT 1 FROM lib.accounts i WHERE i.invited_by = a.id AND i.status = 'suspended'))
                AND ($5::text IS NULL OR $5 = ANY(a.tags))
              ORDER BY a.created_at"
        ))
        .bind(c.min_age_days)
        .bind(c.published)
        .bind(c.paid)
        .bind(c.invitees_in_good_standing)
        .bind(c.tag.as_deref())
        .bind(now)
        .fetch_all(&self.pool)
        .await
    }

    // ── billing ────────────────────────────────────────────────────────────

    /// Record a started purchase, open, with the method's fees as they are now.
    pub async fn create_checkout(&self, c: &Checkout) -> Result<(), DbError> {
        // Always inserted as open; closing it is a separate, conditional step.
        sqlx::query(
            "INSERT INTO lib.checkouts (id, account_id, provider, provider_ref, method, months, amount_pence, status,
                                        country_declared, country_request, created_at, fee_fixed_pence, fee_percent_bps)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8, $9, $10, $11, $12)",
        )
        .bind(c.id)
        .bind(c.account_id)
        .bind(&c.provider)
        .bind(&c.provider_ref)
        .bind(&c.method)
        .bind(c.months)
        .bind(c.amount_pence)
        .bind(&c.country_declared)
        .bind(&c.country_request)
        .bind(c.created_at)
        .bind(c.fee_fixed_pence)
        .bind(c.fee_percent_bps)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// A checkout by id.
    pub async fn checkout(&self, id: Uuid) -> Result<Option<Checkout>, DbError> {
        // All the columns a purchase flow needs, including the fees recorded when it was made.
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at, fee_fixed_pence, fee_percent_bps FROM lib.checkouts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// A checkout by its provider and the provider's reference, which is how a notification finds it.
    pub async fn checkout_by_ref(&self, provider: &str, provider_ref: &str) -> Result<Option<Checkout>, DbError> {
        // The pair of provider and reference is unique, so at most one row matches.
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at, fee_fixed_pence, fee_percent_bps FROM lib.checkouts WHERE provider = $1 AND provider_ref = $2",
        )
        .bind(provider)
        .bind(provider_ref)
        .fetch_optional(&self.pool)
        .await
    }

    /// Open checkouts created before `before` (the worker asks their providers how they ended).
    pub async fn stale_checkouts(&self, before: OffsetDateTime, limit: i64) -> Result<Vec<Checkout>, DbError> {
        // Oldest first, so the worker reconciles the longest-waiting checkouts first.
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at, fee_fixed_pence, fee_percent_bps
               FROM lib.checkouts WHERE status = 'open' AND created_at < $1 ORDER BY created_at LIMIT $2",
        )
        .bind(before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Close an open checkout as expired or cancelled; false if it was not open.
    pub async fn close_checkout(&self, id: Uuid, status: &str, now: OffsetDateTime) -> Result<bool, DbError> {
        // Only an open checkout can be closed, so a paid one is never reopened or overwritten.
        let r =
            sqlx::query("UPDATE lib.checkouts SET status = $2, completed_at = $3 WHERE id = $1 AND status = 'open'")
                .bind(id)
                .bind(status)
                .bind(now)
                .execute(&self.pool)
                .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Applies a change to the paid period once per provider event: returns the new `paid_until`, or `None` when the
    /// event was already applied. A purchase or grant extends from the later of now and the current end; a refund
    /// shortens it (never below now).
    pub async fn change_period(
        &self,
        c: &PeriodChange<'_>,
        now: OffsetDateTime,
    ) -> Result<Option<OffsetDateTime>, DbError> {
        // One transaction: the event is recorded, the account's period moves, and the checkout is settled, or none of it happens.
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let applied = Self::change_period_in(&mut tx, c, now).await?;
        tx.commit().await?;
        Ok(applied.map(|(_, until)| until))
    }

    /// [`Store::change_period`] inside a transaction: the new event's id and `paid_until`, or `None` when the event
    /// was already applied.
    async fn change_period_in(
        tx: &mut Transaction<'_, Postgres>,
        c: &PeriodChange<'_>,
        now: OffsetDateTime,
    ) -> Result<Option<(Uuid, OffsetDateTime)>, DbError> {
        // The event's unique key (provider and provider event) makes this idempotent: a repeated notification inserts nothing and changes nothing.
        let id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO lib.billing_events (id, account_id, provider, provider_event, kind, months, amount_pence, evidence,
                                             checkout_id, refund_of)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (provider, provider_event) DO NOTHING",
        )
        .bind(id)
        .bind(c.account_id)
        .bind(c.provider)
        .bind(c.provider_event)
        .bind(c.kind)
        .bind(c.months)
        .bind(c.amount_pence)
        .bind(&c.evidence)
        .bind(c.checkout_id.or(if c.kind == "purchase" { c.checkout } else { None }))
        .bind(c.refund_of)
        .execute(&mut **tx)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            return Ok(None);
        }
        let span = MONTH * c.months;
        let until: OffsetDateTime = sqlx::query_scalar(
            "UPDATE lib.accounts SET paid_until = CASE
                    WHEN $2 >= interval '0' THEN greatest(coalesce(paid_until, $3), $3) + $2
                    ELSE greatest(coalesce(paid_until, $3) + $2, $3) END
              WHERE id = $1 RETURNING paid_until",
        )
        .bind(c.account_id)
        .bind(span)
        .bind(now)
        .fetch_one(&mut **tx)
        .await?;
        sqlx::query("UPDATE lib.billing_events SET paid_until_after = $2 WHERE id = $1")
            .bind(id)
            .bind(until)
            .execute(&mut **tx)
            .await?;
        if let Some(ch) = c.checkout {
            sqlx::query("UPDATE lib.checkouts SET status = 'paid', completed_at = $2 WHERE id = $1")
                .bind(ch)
                .bind(now)
                .execute(&mut **tx)
                .await?;
        }
        Ok(Some((id, until)))
    }

    /// The purchase event that paid a checkout (not a late payment credited against it).
    async fn purchase_of_checkout(tx: &mut Transaction<'_, Postgres>, checkout: Uuid) -> Result<Option<Uuid>, DbError> {
        sqlx::query_scalar(
            "SELECT id FROM lib.billing_events
              WHERE checkout_id = $1 AND kind = 'purchase' AND NOT coalesce((evidence->>'unapplied')::boolean, false)
              ORDER BY created_at LIMIT 1",
        )
        .bind(checkout)
        .fetch_optional(&mut **tx)
        .await
    }

    /// What refunds have given back of a purchase so far: `(minor units refunded, months taken back)`.
    async fn refunded_so_far(tx: &mut Transaction<'_, Postgres>, purchase: Uuid) -> Result<(u64, u32), DbError> {
        let row = sqlx::query(
            "SELECT coalesce(sum((evidence->>'refundedMinor')::bigint), 0)::bigint AS refunded,
                    coalesce(sum(-months), 0)::bigint AS taken
               FROM lib.billing_events WHERE kind = 'refund' AND refund_of = $1",
        )
        .bind(purchase)
        .fetch_one(&mut **tx)
        .await?;
        Ok((
            u64::try_from(row.try_get::<i64, _>("refunded")?).unwrap_or(0),
            u32::try_from(row.try_get::<i64, _>("taken")?).unwrap_or(0),
        ))
    }

    /// A refund that takes no month back (nothing left, or a checkout never paid), recorded once all the same.
    async fn record_zero_refund(
        tx: &mut Transaction<'_, Postgres>,
        c: &PeriodChange<'_>,
    ) -> Result<Option<(Uuid, Option<OffsetDateTime>)>, DbError> {
        let until: Option<OffsetDateTime> = sqlx::query_scalar("SELECT paid_until FROM lib.accounts WHERE id = $1")
            .bind(c.account_id)
            .fetch_one(&mut **tx)
            .await?;
        let id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO lib.billing_events (id, account_id, provider, provider_event, kind, months, amount_pence,
                                             paid_until_after, evidence, refund_of)
             VALUES ($1, $2, $3, $4, 'refund', 0, $5, $6, $7, $8) ON CONFLICT (provider, provider_event) DO NOTHING",
        )
        .bind(id)
        .bind(c.account_id)
        .bind(c.provider)
        .bind(c.provider_event)
        .bind(c.amount_pence)
        .bind(until)
        .bind(&c.evidence)
        .bind(c.refund_of)
        .execute(&mut **tx)
        .await?
        .rows_affected()
            == 1;
        Ok(inserted.then_some((id, until)))
    }

    /// Applies a provider's refund of a purchase that no refund request names (an operator's ad-hoc refund, one the
    /// provider made), once per provider event: the months it takes back are the difference
    /// `share(months, paid, refunded so far + this one) − months already taken back` (`share` is
    /// `link_in_bio_billing::months_refunded`: pro rata, rounded down, all of them for the whole amount), counted over
    /// every refund of the purchase (requests' included), so the refunds of one purchase never take back more than it
    /// bought. The checkout row is locked, so two refunds of one purchase are counted one after the other. A checkout
    /// that was never paid gives nothing back. `None` when this event was applied before.
    pub async fn refund_purchase(
        &self,
        r: &RefundChange<'_>,
        share: fn(u32, u64, u64) -> u32,
        now: OffsetDateTime,
    ) -> Result<Option<RefundApplied>, DbError> {
        // The checkout row is locked first, so two refunds of one purchase are counted one after the other and never take back more than it bought.
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM lib.checkouts WHERE id = $1 FOR UPDATE")
            .bind(r.checkout)
            .fetch_optional(&mut *tx)
            .await?;
        let seen: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM lib.billing_events WHERE provider = $1 AND provider_event = $2)",
        )
        .bind(r.provider)
        .bind(r.provider_event)
        .fetch_one(&mut *tx)
        .await?;
        if seen {
            return Ok(None);
        }
        let purchase = Self::purchase_of_checkout(&mut tx, r.checkout).await?;
        let (before_refunded, before_taken) = match purchase {
            Some(p) => Self::refunded_so_far(&mut tx, p).await?,
            None => (0, 0),
        };
        let total = if status.as_deref() == Some("paid") && purchase.is_some() {
            share(r.months, r.paid_minor, before_refunded.saturating_add(r.refunded_minor)).min(r.months)
        } else {
            0
        };
        let take = total.saturating_sub(before_taken);
        let pence = if r.paid_minor == 0 {
            r.amount_pence
        } else {
            (i128::from(r.amount_pence) * i128::from(r.refunded_minor.min(r.paid_minor)) / i128::from(r.paid_minor))
                as i64
        };
        let mut evidence = r.evidence.clone();
        evidence["refundOfCheckout"] = serde_json::json!(r.checkout);
        evidence["refundedMinor"] = serde_json::json!(r.refunded_minor);
        evidence["paidMinor"] = serde_json::json!(r.paid_minor);
        evidence["monthsTaken"] = serde_json::json!(take);
        let change = PeriodChange {
            account_id: r.account_id,
            provider: r.provider,
            provider_event: r.provider_event,
            kind: "refund",
            months: -(take as i32),
            amount_pence: -pence,
            evidence,
            checkout: None,
            checkout_id: None,
            refund_of: purchase,
        };
        let paid_until = if take > 0 {
            Self::change_period_in(&mut tx, &change, now).await?.map(|(_, until)| until)
        } else {
            Self::record_zero_refund(&mut tx, &change).await?.and_then(|(_, until)| until)
        };
        tx.commit().await?;
        Ok(Some(RefundApplied { months_taken: take, paid_until }))
    }

    /// An account's purchases and grants, newest first, with the months each still gives.
    pub async fn extensions(&self, account: Uuid) -> Result<Vec<Extension>, DbError> {
        sqlx::query_as(
            "SELECT e.id, e.provider, e.kind, e.months, e.amount_pence, e.evidence, e.created_at, e.paid_until_after,
                    e.checkout_id, c.method, c.provider_ref, c.fee_fixed_pence, c.fee_percent_bps,
                    (e.months + coalesce((SELECT sum(r.months) FROM lib.billing_events r WHERE r.refund_of = e.id), 0))::bigint
                      AS held
               FROM lib.billing_events e LEFT JOIN lib.checkouts c ON c.id = e.checkout_id
              WHERE e.account_id = $1 AND e.kind IN ('purchase', 'grant') AND e.months > 0
              ORDER BY e.created_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// An account's billing events, newest first.
    pub async fn billing_events(&self, account: Uuid) -> Result<Vec<BillingEvent>, DbError> {
        // Whether an event was a late payment is read out of its evidence, so the app can offer it back whole.
        sqlx::query_as(
            "SELECT id, provider, provider_event, kind, months, amount_pence, paid_until_after, created_at,
                    coalesce((evidence->>'unapplied')::boolean, false) AS unapplied
               FROM lib.billing_events WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// One billing event with its account and evidence.
    pub async fn billing_event(&self, id: Uuid) -> Result<Option<BillingEventDetail>, DbError> {
        // One event with its evidence, for the operator's view.
        sqlx::query_as(
            "SELECT id, account_id, provider, kind, months, amount_pence, evidence, created_at
               FROM lib.billing_events WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    // ── refund requests ────────────────────────────────────────────────────

    /// Records an account holder's refund request for a late payment (schema 4's kind, without lines): its id, or
    /// `None` when that event already has one or the account has an open request.
    pub async fn create_refund_request(
        &self,
        event: Uuid,
        account: Uuid,
        reason: &str,
    ) -> Result<Option<Uuid>, DbError> {
        // The unique indexes decide: `DO NOTHING` returns no row when either already exists.
        let r = sqlx::query_scalar(
            "INSERT INTO lib.refund_requests (id, event_id, account_id, reason) VALUES ($1, $2, $3, $4)
             ON CONFLICT DO NOTHING RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(event)
        .bind(account)
        .bind(reason)
        .fetch_optional(&self.pool)
        .await?;
        Ok(r)
    }

    /// Records a refund request with what each purchase gives back, in one transaction. `event` names the late payment
    /// of an `unapplied` request (asked once). Refused when the account has an open request already.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_refund_request_lines(
        &self,
        account: Uuid,
        kind: &str,
        event: Option<Uuid>,
        reason: &str,
        details: &Value,
        lines: &[NewRefundLine],
        now: OffsetDateTime,
    ) -> Result<Result<Uuid, RefundConflict>, DbError> {
        // The request and its lines go in together; the unique indexes turn a second open request, or a second ask about one late payment, into a conflict instead of an error.
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO lib.refund_requests (id, event_id, account_id, kind, reason, details, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(event)
        .bind(account)
        .bind(kind)
        .bind(reason)
        .bind(details)
        .bind(now)
        .execute(&mut *tx)
        .await;
        if let Err(sqlx::Error::Database(e)) = &inserted
            && e.code().as_deref() == Some("23505")
        {
            return Ok(Err(if e.constraint() == Some("refund_requests_one_open") {
                RefundConflict::OpenRequest
            } else {
                RefundConflict::AlreadyAsked
            }));
        }
        inserted?;
        for l in lines {
            sqlx::query(
                "INSERT INTO lib.refund_lines (request_id, purchase_id, checkout_id, provider, months, amount_minor, unit,
                                               scale, fee_minor, charge_minor, used_minor, days_used, amount_pence,
                                               destination)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(id)
            .bind(l.purchase_id)
            .bind(l.checkout_id)
            .bind(&l.provider)
            .bind(l.months)
            .bind(l.amount_minor)
            .bind(&l.unit)
            .bind(l.scale)
            .bind(l.fee_minor)
            .bind(l.charge_minor)
            .bind(l.used_minor)
            .bind(l.days_used)
            .bind(l.amount_pence)
            .bind(&l.destination)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Ok(id))
    }

    /// The columns of a refund request, with its late payment (if it names one) and its account's handle; each query adds its own `WHERE`.
    const REFUND_SELECT: &'static str =
        "SELECT r.id, r.event_id, r.account_id, a.handle, r.kind, r.reason, r.status, r.details, r.refund_reference,
                r.refund_event, r.decided_by, r.decided_at, r.created_at, e.provider, e.months, e.amount_pence,
                e.evidence, e.created_at AS paid_at
           FROM lib.refund_requests r LEFT JOIN lib.billing_events e ON e.id = r.event_id
           JOIN lib.accounts a ON a.id = r.account_id";

    /// Requests by status, oldest first (the console's queue).
    pub async fn refund_requests(&self, status: &str, limit: i64) -> Result<Vec<RefundRequest>, DbError> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{} WHERE r.status = $1 ORDER BY r.created_at LIMIT $2",
            Self::REFUND_SELECT
        )))
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// An account's requests (what its billing view shows).
    pub async fn refund_requests_of(&self, account: Uuid) -> Result<Vec<RefundRequest>, DbError> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{} WHERE r.account_id = $1 ORDER BY r.created_at DESC",
            Self::REFUND_SELECT
        )))
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// One refund request.
    pub async fn refund_request(&self, id: Uuid) -> Result<Option<RefundRequest>, DbError> {
        // A request with its late payment and account joined in.
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{} WHERE r.id = $1", Self::REFUND_SELECT)))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    /// The columns of a refund line, with the months its purchase still gives; each query adds its own `WHERE`.
    const LINE_SELECT: &'static str =
        "SELECT l.request_id, l.purchase_id, l.checkout_id, l.provider, l.months, l.amount_minor, l.unit, l.scale,
                l.fee_minor, l.charge_minor, l.used_minor, l.days_used, l.amount_pence, l.destination, l.status, l.refund_reference,
                l.refund_event, l.refunded_at,
                (p.months + coalesce((SELECT sum(x.months) FROM lib.billing_events x WHERE x.refund_of = p.id), 0))::bigint
                  AS held
           FROM lib.refund_lines l JOIN lib.billing_events p ON p.id = l.purchase_id";

    /// The lines of these requests, newest purchase first within each.
    pub async fn refund_lines(&self, requests: &[Uuid]) -> Result<Vec<RefundLine>, DbError> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{} WHERE l.request_id = ANY($1) ORDER BY l.request_id, p.created_at DESC",
            Self::LINE_SELECT
        )))
        .bind(requests)
        .fetch_all(&self.pool)
        .await
    }

    /// The open line of an open request for this checkout's purchase, if one waits (a provider's refund notification
    /// is matched against it).
    pub async fn open_refund_line_for_checkout(&self, checkout: Uuid) -> Result<Option<RefundLine>, DbError> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{} JOIN lib.refund_requests q ON q.id = l.request_id
              WHERE l.checkout_id = $1 AND l.status = 'open' AND q.status = 'open' LIMIT 1",
            Self::LINE_SELECT
        )))
        .bind(checkout)
        .fetch_optional(&self.pool)
        .await
    }

    /// One line was refunded (by the operator, who records its reference, or matched from the provider's refund
    /// notification, whose event id is then `provider_event`): takes back exactly the line's months (never more than
    /// the purchase still gives), once, and closes the request when no line is left open. `None` when the request or
    /// the line is not open, or the provider event was applied before.
    #[allow(clippy::too_many_arguments)]
    pub async fn refund_line(
        &self,
        request: Uuid,
        purchase: Uuid,
        reference: &str,
        by: &str,
        provider_event: Option<&str>,
        evidence: Value,
        now: OffsetDateTime,
    ) -> Result<Option<LineRefunded>, DbError> {
        // The request and the purchase's checkout are locked first, so this and a provider's own refund notification are counted one after the other.
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let account: Option<Uuid> = sqlx::query_scalar(
            "SELECT account_id FROM lib.refund_requests WHERE id = $1 AND status = 'open' FOR UPDATE",
        )
        .bind(request)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(account_id) = account else { return Ok(None) };
        let line = sqlx::query(
            "SELECT checkout_id, provider, months, amount_minor, unit, amount_pence FROM lib.refund_lines
              WHERE request_id = $1 AND purchase_id = $2 AND status = 'open' FOR UPDATE",
        )
        .bind(request)
        .bind(purchase)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(line) = line else { return Ok(None) };
        let checkout: Option<Uuid> = line.try_get("checkout_id")?;
        if let Some(c) = checkout {
            // The same lock as a provider's refund of this checkout, so the two are counted one after the other.
            sqlx::query("SELECT 1 FROM lib.checkouts WHERE id = $1 FOR UPDATE").bind(c).execute(&mut *tx).await?;
        }
        let provider: String = line.try_get("provider")?;
        let months: i32 = line.try_get("months")?;
        let amount_minor: i64 = line.try_get("amount_minor")?;
        let pence: i64 = line.try_get("amount_pence")?;
        let held: i64 = sqlx::query_scalar(
            "SELECT (p.months + coalesce((SELECT sum(x.months) FROM lib.billing_events x WHERE x.refund_of = p.id), 0))::bigint
               FROM lib.billing_events p WHERE p.id = $1",
        )
        .bind(purchase)
        .fetch_one(&mut *tx)
        .await?;
        let take = u32::try_from(i64::from(months).min(held).max(0)).unwrap_or(0);
        let key = provider_event.map(String::from).unwrap_or_else(|| format!("refund-line:{request}:{purchase}"));
        let mut evidence = evidence;
        evidence["refundRequest"] = serde_json::json!(request);
        evidence["reference"] = serde_json::json!(reference);
        evidence["operator"] = serde_json::json!(by);
        evidence["refundedMinor"] = serde_json::json!(amount_minor);
        evidence["unit"] = line.try_get::<String, _>("unit")?.into();
        evidence["monthsTaken"] = serde_json::json!(take);
        let change = PeriodChange {
            account_id,
            provider: &provider,
            provider_event: &key,
            kind: "refund",
            months: -(take as i32),
            amount_pence: -pence,
            evidence,
            checkout: None,
            checkout_id: None,
            refund_of: Some(purchase),
        };
        let applied = if take > 0 {
            Self::change_period_in(&mut tx, &change, now).await?.map(|(id, until)| (id, Some(until)))
        } else {
            Self::record_zero_refund(&mut tx, &change).await?
        };
        let Some((event_id, paid_until)) = applied else { return Ok(None) };
        sqlx::query(
            "UPDATE lib.refund_lines SET status = 'refunded', refund_reference = $3, refund_event = $4, refunded_at = $5
              WHERE request_id = $1 AND purchase_id = $2",
        )
        .bind(request)
        .bind(purchase)
        .bind(reference)
        .bind(event_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        let open_left: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM lib.refund_lines WHERE request_id = $1 AND status = 'open')",
        )
        .bind(request)
        .fetch_one(&mut *tx)
        .await?;
        if !open_left {
            sqlx::query(
                "UPDATE lib.refund_requests SET status = 'refunded', refund_reference = $2, refund_event = $3,
                        decided_by = $4, decided_at = $5 WHERE id = $1",
            )
            .bind(request)
            .bind(reference)
            .bind(event_id)
            .bind(by)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(Some(LineRefunded { account_id, event_id, months_taken: take, paid_until, request_closed: !open_left }))
    }

    /// Closes an open request without a refund: `withdrawn` by its account holder (`account` must match) or `declined`
    /// by the operator, with a note. `false` when it is not open.
    pub async fn close_refund_request(
        &self,
        id: Uuid,
        account: Option<Uuid>,
        status: &str,
        by: &str,
        note: &str,
        now: OffsetDateTime,
    ) -> Result<bool, DbError> {
        // A holder may only withdraw their own request; the operator may only decline.
        let r = sqlx::query(
            "UPDATE lib.refund_requests SET status = $2, decided_by = $3, decided_at = $4,
                    details = details || jsonb_build_object('note', $5::text)
              WHERE id = $1 AND status = 'open' AND ($6::uuid IS NULL OR account_id = $6)
                AND $2 IN ('withdrawn', 'declined')",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .bind(now)
        .bind(note)
        .bind(account)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The operator sent the refund of a request made before schema 6 (one late payment, no lines): records its
    /// reference and takes the payment's months back as a `refund` event, in one transaction and once (`None` when the
    /// request is not open or has lines, which [`Store::refund_line`] records).
    pub async fn record_refund(
        &self,
        request: Uuid,
        reference: &str,
        by: &str,
        note: &str,
        now: OffsetDateTime,
    ) -> Result<Option<RefundDone>, DbError> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let row = sqlx::query(
            "SELECT r.account_id, r.event_id, e.provider, e.months, e.amount_pence
               FROM lib.refund_requests r JOIN lib.billing_events e ON e.id = r.event_id
              WHERE r.id = $1 AND r.status = 'open'
                AND NOT EXISTS (SELECT 1 FROM lib.refund_lines l WHERE l.request_id = r.id)
                FOR UPDATE OF r",
        )
        .bind(request)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let account_id: Uuid = row.get("account_id");
        let original: Uuid = row.get("event_id");
        let provider: String = row.get("provider");
        let months: i32 = row.get("months");
        let amount: i64 = row.get("amount_pence");
        let event_key = format!("refund-request:{request}");
        let change = PeriodChange {
            account_id,
            provider: &provider,
            provider_event: &event_key,
            kind: "refund",
            months: -months,
            amount_pence: -amount,
            evidence: serde_json::json!({
                "refundRequest": request, "refundOf": original, "reference": reference, "operator": by, "note": note,
            }),
            checkout: None,
            checkout_id: None,
            refund_of: Some(original),
        };
        let Some((event_id, paid_until)) = Self::change_period_in(&mut tx, &change, now).await? else {
            return Ok(None);
        };
        sqlx::query(
            "UPDATE lib.refund_requests SET status = 'refunded', refund_reference = $2, refund_event = $3,
                    decided_by = $4, decided_at = $5 WHERE id = $1",
        )
        .bind(request)
        .bind(reference)
        .bind(event_id)
        .bind(by)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Some(RefundDone { account_id, event_id, months, paid_until }))
    }

    // ── Open Payments grants ───────────────────────────────────────────────

    /// Records (or replaces) the grant waiting for the buyer's approval of a checkout. Refused (`false`) once a payment
    /// was sent for it.
    pub async fn put_open_payments_grant(&self, checkout: Uuid, buyer: &str, pending: &Value) -> Result<bool, DbError> {
        let r = sqlx::query(
            "INSERT INTO lib.open_payments_grants (checkout_id, buyer_wallet, pending) VALUES ($1, $2, $3)
             ON CONFLICT (checkout_id) DO UPDATE
                SET buyer_wallet = EXCLUDED.buyer_wallet, pending = EXCLUDED.pending, status = 'pending',
                    outgoing_payment = NULL, created_at = now(), finished_at = NULL
              WHERE lib.open_payments_grants.status <> 'sent'",
        )
        .bind(checkout)
        .bind(buyer)
        .bind(pending)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// A checkout's grant: its status and what is pending.
    pub async fn open_payments_grant(&self, checkout: Uuid) -> Result<Option<(String, Value)>, DbError> {
        let row = sqlx::query("SELECT status, pending FROM lib.open_payments_grants WHERE checkout_id = $1")
            .bind(checkout)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| (r.get("status"), r.get("pending"))))
    }

    /// Takes a pending grant to continue it (once: a second caller gets `None`).
    pub async fn take_open_payments_grant(&self, checkout: Uuid) -> Result<Option<Value>, DbError> {
        // Moves the grant from pending to finishing in the same statement that reads it, so only one caller can continue it.
        sqlx::query_scalar(
            "UPDATE lib.open_payments_grants SET status = 'finishing'
              WHERE checkout_id = $1 AND status = 'pending' RETURNING pending",
        )
        .bind(checkout)
        .fetch_optional(&self.pool)
        .await
    }

    /// Ends a grant: `sent` with the outgoing payment's id, or `failed`. What was pending is removed either way.
    pub async fn finish_open_payments_grant(
        &self,
        checkout: Uuid,
        outgoing_payment: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // The pending data holds a continuation token, so it is cleared whether the grant was sent or failed.
        sqlx::query(
            "UPDATE lib.open_payments_grants
                SET status = CASE WHEN $2::text IS NULL THEN 'failed' ELSE 'sent' END, outgoing_payment = $2,
                    pending = '{}', finished_at = $3
              WHERE checkout_id = $1",
        )
        .bind(checkout)
        .bind(outgoing_payment)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    // ── bank feeds ─────────────────────────────────────────────────────────

    /// One bank feed's cursor and state.
    pub async fn bank_feed(&self, feed: &str) -> Result<Option<BankFeedRow>, DbError> {
        // One feed's row.
        sqlx::query_as(
            "SELECT feed, cursor, state, polled_at, last_error, credits_seen FROM lib.bank_feeds WHERE feed = $1",
        )
        .bind(feed)
        .fetch_optional(&self.pool)
        .await
    }

    /// Every bank feed, by name.
    pub async fn bank_feeds(&self) -> Result<Vec<BankFeedRow>, DbError> {
        // Every feed, by name.
        sqlx::query_as(
            "SELECT feed, cursor, state, polled_at, last_error, credits_seen FROM lib.bank_feeds ORDER BY feed",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// A successful poll: the new cursor and state, and how many credits it found.
    pub async fn save_bank_feed(
        &self,
        feed: &str,
        cursor: Option<&str>,
        state: &Value,
        credits: i64,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // The credits read are added to the running total; a successful poll clears the last error.
        sqlx::query(
            "INSERT INTO lib.bank_feeds (feed, cursor, state, polled_at, last_error, credits_seen)
             VALUES ($1, $2, $3, $4, NULL, $5)
             ON CONFLICT (feed) DO UPDATE SET cursor = EXCLUDED.cursor, state = EXCLUDED.state,
                 polled_at = EXCLUDED.polled_at, last_error = NULL,
                 credits_seen = lib.bank_feeds.credits_seen + EXCLUDED.credits_seen",
        )
        .bind(feed)
        .bind(cursor)
        .bind(state)
        .bind(now)
        .bind(credits)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// A failed poll: the cursor and state stay as they were.
    pub async fn bank_feed_failed(&self, feed: &str, error: &str, now: OffsetDateTime) -> Result<(), DbError> {
        // The error is cut to 500 characters, and the cursor and state are left alone, so the next poll resumes where this one should have.
        let error: String = error.chars().take(500).collect();
        sqlx::query(
            "INSERT INTO lib.bank_feeds (feed, polled_at, last_error) VALUES ($1, $2, $3)
             ON CONFLICT (feed) DO UPDATE SET polled_at = EXCLUDED.polled_at, last_error = EXCLUDED.last_error",
        )
        .bind(feed)
        .bind(now)
        .bind(error)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    // ── domains ────────────────────────────────────────────────────────────

    /// Register a custom domain for an account, pending verification; false when the host name is taken.
    pub async fn add_domain(&self, account: Uuid, hostname: &str, method: &str, token: &str) -> Result<bool, DbError> {
        // A host name is unique across accounts; the unique violation is the answer `false`.
        match sqlx::query("INSERT INTO lib.domains (hostname, account_id, method, token) VALUES ($1, $2, $3, $4)")
            .bind(hostname)
            .bind(account)
            .bind(method)
            .bind(token)
            .execute(&self.pool)
            .await
        {
            Ok(_) => Ok(true),
            Err(e) if unique_violation(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// An account's domains, oldest first.
    pub async fn domains(&self, account: Uuid) -> Result<Vec<Domain>, DbError> {
        // Oldest first.
        sqlx::query_as(
            "SELECT hostname, account_id, method, token, status, checked_at, verified_at
               FROM lib.domains WHERE account_id = $1 ORDER BY created_at",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// How many domains exist, for the cap on custom domains.
    pub async fn count_domains(&self) -> Result<i64, DbError> {
        // A count over every account, for the cap on custom domains.
        sqlx::query_scalar("SELECT count(*) FROM lib.domains").fetch_one(&self.pool).await
    }

    /// Domains to (re)check: pending ones, and verified ones last checked before `before`.
    pub async fn domains_due(&self, before: OffsetDateTime, limit: i64) -> Result<Vec<Domain>, DbError> {
        // Pending domains, never-checked ones, and verified ones last checked before the cut-off.
        sqlx::query_as(
            "SELECT hostname, account_id, method, token, status, checked_at, verified_at FROM lib.domains
              WHERE status = 'pending' OR checked_at IS NULL OR checked_at < $1 ORDER BY checked_at NULLS FIRST LIMIT $2",
        )
        .bind(before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Record a check's result; the verification time is set the first time a domain verifies and cleared when it stops.
    pub async fn set_domain_status(&self, hostname: &str, status: &str, now: OffsetDateTime) -> Result<(), DbError> {
        // Only the first verification sets the verified time.
        sqlx::query(
            "UPDATE lib.domains SET status = $2, checked_at = $3,
                    verified_at = CASE WHEN $2 = 'verified' THEN coalesce(verified_at, $3) ELSE NULL END
              WHERE hostname = $1",
        )
        .bind(hostname)
        .bind(status)
        .bind(now)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// Remove an account's domain; false if it was not theirs.
    pub async fn delete_domain(&self, account: Uuid, hostname: &str) -> Result<bool, DbError> {
        // Scoped to the account, so one account cannot remove another's domain.
        Ok(sqlx::query("DELETE FROM lib.domains WHERE account_id = $1 AND hostname = $2")
            .bind(account)
            .bind(hostname)
            .execute(&self.pool)
            .await?
            .rows_affected()
            == 1)
    }

    // ── reports, appeals, audit ────────────────────────────────────────────

    /// Record a report about a page or a link; the account is looked up by handle when it exists.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_report(
        &self,
        handle: &str,
        url: Option<&str>,
        reason: &str,
        details: &str,
        contact: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<Uuid, DbError> {
        // The account is looked up by handle in the same statement, so a report about a deleted page keeps the handle.
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO lib.reports (id, handle, account_id, url, reason, details, contact, created_at)
             VALUES ($1, $2, (SELECT id FROM lib.accounts WHERE handle = $2), $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(handle)
        .bind(url)
        .bind(reason)
        .bind(details)
        .bind(contact)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Reports with this status, oldest first.
    pub async fn reports(&self, status: &str, limit: i64) -> Result<Vec<Report>, DbError> {
        // Oldest first, so the queue is worked in order.
        sqlx::query_as(
            "SELECT id, handle, account_id, url, reason, details, contact, status, created_at, decided_at, decided_by,
                    decision, statement
               FROM lib.reports WHERE status = $1 ORDER BY created_at LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// One report.
    pub async fn report(&self, id: Uuid) -> Result<Option<Report>, DbError> {
        sqlx::query_as(
            "SELECT id, handle, account_id, url, reason, details, contact, status, created_at, decided_at, decided_by,
                    decision, statement FROM lib.reports WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    /// Records the decision on an open report (`actioned` or `dismissed`) with its statement of reasons.
    pub async fn decide_report(
        &self,
        id: Uuid,
        status: &str,
        by: &str,
        decision: &str,
        statement: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<bool, DbError> {
        // Only an open report can be decided, and only once.
        let r = sqlx::query(
            "UPDATE lib.reports SET status = $2, decided_by = $3, decision = $4, statement = $5, decided_at = $6
              WHERE id = $1 AND status = 'open'",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .bind(decision)
        .bind(statement)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// Reports decided about this account that carried a statement (what the holder is shown and may appeal).
    pub async fn statements_for(&self, account: Uuid) -> Result<Vec<Report>, DbError> {
        // The reporter's contact and details are not returned: the holder sees the decision and the statement, not who reported.
        sqlx::query_as(
            "SELECT id, handle, account_id, url, reason, '' AS details, NULL::text AS contact, status, created_at,
                    decided_at, NULL::text AS decided_by, decision, statement
               FROM lib.reports WHERE account_id = $1 AND status = 'actioned' ORDER BY decided_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// Record an account holder's appeal, about a report or in general.
    pub async fn create_appeal(&self, account: Uuid, report: Option<Uuid>, text: &str) -> Result<Uuid, DbError> {
        // A new appeal starts open.
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO lib.appeals (id, account_id, report_id, text) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(account)
            .bind(report)
            .bind(text)
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    /// Appeals with this status, oldest first.
    pub async fn appeals(&self, status: &str, limit: i64) -> Result<Vec<Appeal>, DbError> {
        // Oldest first, so the queue is worked in order.
        sqlx::query_as(
            "SELECT id, account_id, report_id, text, status, created_at, decided_at, decided_by, statement
               FROM lib.appeals WHERE status = $1 ORDER BY created_at LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// An account's own appeals, newest first, without who decided.
    pub async fn appeals_of(&self, account: Uuid) -> Result<Vec<Appeal>, DbError> {
        // Without who decided: the holder sees the outcome, not the person.
        sqlx::query_as(
            "SELECT id, account_id, report_id, text, status, created_at, decided_at, NULL::text AS decided_by, statement
               FROM lib.appeals WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    /// Record the decision on an open appeal; returns the account so it can be told.
    pub async fn decide_appeal(
        &self,
        id: Uuid,
        status: &str,
        by: &str,
        statement: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Uuid>, DbError> {
        // Returns the account so the holder can be told.
        sqlx::query_scalar(
            "UPDATE lib.appeals SET status = $2, decided_by = $3, statement = $4, decided_at = $5
              WHERE id = $1 AND status = 'open' RETURNING account_id",
        )
        .bind(id)
        .bind(status)
        .bind(by)
        .bind(statement)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
    }

    /// Append a row to the audit log.
    pub async fn audit(&self, actor: &str, action: &str, subject: &str, details: &Value) -> Result<(), DbError> {
        sqlx::query("INSERT INTO lib.audit_log (actor, action, subject, details) VALUES ($1, $2, $3, $4)")
            .bind(actor)
            .bind(action)
            .bind(subject)
            .bind(details)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Audits an entry once per `(action, subject, details.event)`: for findings the worker would otherwise repeat on
    /// every pass (a notification that does not cover its checkout). Returns whether it was written now.
    pub async fn audit_once(&self, actor: &str, action: &str, subject: &str, details: &Value) -> Result<bool, DbError> {
        let key = details["event"].as_str().unwrap_or_default();
        let r = sqlx::query(
            "INSERT INTO lib.audit_log (actor, action, subject, details)
             SELECT $1, $2, $3, $4
              WHERE NOT EXISTS (SELECT 1 FROM lib.audit_log WHERE subject = $3 AND action = $2 AND details->>'event' = $5)",
        )
        .bind(actor)
        .bind(action)
        .bind(subject)
        .bind(details)
        .bind(key)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    /// The audit log, newest first, for one subject or for all.
    pub async fn audit_log(&self, subject: Option<&str>, limit: i64) -> Result<Vec<AuditEntry>, DbError> {
        // A null subject means every subject.
        sqlx::query_as(
            "SELECT id, at, actor, action, subject, details FROM lib.audit_log
              WHERE ($1::text IS NULL OR subject = $1) ORDER BY id DESC LIMIT $2",
        )
        .bind(subject)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    // ── screening ──────────────────────────────────────────────────────────

    /// The stored verdicts of these link hashes.
    pub async fn screens(&self, hashes: &[Vec<u8>]) -> Result<Vec<Screen>, DbError> {
        // The verdicts for a set of link hashes in one query.
        sqlx::query_as(
            "SELECT url_hash, url, verdict, source, detail, checked_at, next_check_at, overridden_by
               FROM lib.link_screens WHERE url_hash = ANY($1)",
        )
        .bind(hashes)
        .fetch_all(&self.pool)
        .await
    }

    /// Records an automatic verdict, unless an operator has overridden this link.
    pub async fn put_screen(
        &self,
        url: &str,
        verdict: &str,
        source: &str,
        detail: &str,
        next_check_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // The `WHERE` on the conflict keeps an operator's override: an automatic verdict never replaces it.
        sqlx::query(
            "INSERT INTO lib.link_screens (url_hash, url, verdict, source, detail, checked_at, next_check_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (url_hash) DO UPDATE SET verdict = $3, source = $4, detail = $5, checked_at = $6,
                    next_check_at = $7
              WHERE lib.link_screens.overridden_by IS NULL",
        )
        .bind(sha256(url.as_bytes()))
        .bind(url)
        .bind(verdict)
        .bind(source)
        .bind(detail)
        .bind(now)
        .bind(next_check_at)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// An operator's verdict on a link (`clean` releases a flagged link, `flagged` hides one), or `None` to return the
    /// link to automatic screening.
    pub async fn override_screen(
        &self,
        url: &str,
        verdict: Option<&str>,
        by: &str,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // An operator's decision has a next check ten years away, so no automatic source revisits it until it is cleared.
        let h = sha256(url.as_bytes());
        match verdict {
            Some(v) => sqlx::query(
                "INSERT INTO lib.link_screens (url_hash, url, verdict, source, checked_at, next_check_at, overridden_by)
                 VALUES ($1, $2, $3, 'operator', $4, $4 + interval '3650 days', $5)
                 ON CONFLICT (url_hash) DO UPDATE SET verdict = $3, source = 'operator', checked_at = $4,
                        next_check_at = $4 + interval '3650 days', overridden_by = $5",
            )
            .bind(h)
            .bind(url)
            .bind(v)
            .bind(now)
            .bind(by)
            .execute(&self.pool)
            .await
            .map(|_| ()),
            None => sqlx::query(
                "UPDATE lib.link_screens SET overridden_by = NULL, verdict = 'unknown', next_check_at = $2
                  WHERE url_hash = $1",
            )
            .bind(h)
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ()),
        }
    }

    /// Screens that are due and not overridden, oldest first.
    pub async fn screens_due(&self, now: OffsetDateTime, limit: i64) -> Result<Vec<Screen>, DbError> {
        // Operator overrides are never rechecked automatically.
        sqlx::query_as(
            "SELECT url_hash, url, verdict, source, detail, checked_at, next_check_at, overridden_by
               FROM lib.link_screens WHERE next_check_at <= $1 AND overridden_by IS NULL ORDER BY next_check_at LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Lookup mode's rechecks: the due screens of links a published page of an active account shows (not hidden), up to
    /// `limit`, oldest first. Due screens of links no published page shows (only in drafts, removed, hidden) are not
    /// rechecked: their next check moves to `defer_until`, and a publish screens them again if they are stale by then.
    pub async fn screens_due_on_published(
        &self,
        now: OffsetDateTime,
        limit: i64,
        defer_until: OffsetDateTime,
    ) -> Result<Vec<Screen>, DbError> {
        // One statement finds the due screens, defers those no published page shows, and returns the rest, so no link is checked for nothing.
        sqlx::query_as(
            "WITH due AS (
                SELECT s.url_hash,
                       EXISTS (SELECT 1 FROM lib.pages p JOIN lib.accounts a ON a.id = p.account_id AND a.status = 'active'
                                WHERE p.published IS NOT NULL AND strpos(p.published, s.url) > 0
                                  AND (jsonb_path_exists(p.published::jsonb,
                                         '$.items[*] ? (@.url == $u && !(exists(@.hidden ? (@ == true))))',
                                         jsonb_build_object('u', s.url))
                                    OR jsonb_path_exists(p.published::jsonb,
                                         '$.items[*].items[*] ? (@.url == $u && !(exists(@.hidden ? (@ == true))))',
                                         jsonb_build_object('u', s.url)))) AS shown
                  FROM lib.link_screens s
                 WHERE s.next_check_at <= $1 AND s.overridden_by IS NULL
                 ORDER BY s.next_check_at LIMIT $2 * 5
             ), deferred AS (
                UPDATE lib.link_screens l SET next_check_at = $3 FROM due WHERE l.url_hash = due.url_hash AND NOT due.shown
                RETURNING l.url_hash
             )
             SELECT s.url_hash, s.url, s.verdict, s.source, s.detail, s.checked_at, s.next_check_at, s.overridden_by
               FROM lib.link_screens s JOIN due ON due.url_hash = s.url_hash
              WHERE due.shown ORDER BY s.next_check_at LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .bind(defer_until)
        .fetch_all(&self.pool)
        .await
    }

    /// Screened links no page (draft or published) contains any more.
    pub async fn prune_screens(&self) -> Result<u64, DbError> {
        // A verdict goes when no draft or published page contains its link any more, a week after it was last checked.
        Ok(sqlx::query(
            "DELETE FROM lib.link_screens s WHERE s.overridden_by IS NULL AND s.checked_at < now() - interval '7 days'
                AND NOT EXISTS (SELECT 1 FROM lib.pages p
                                 WHERE strpos(p.draft, s.url) > 0 OR strpos(coalesce(p.published, ''), s.url) > 0)",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    /// Add a host or URL to the blocklist, or change its reason.
    pub async fn add_block(&self, pattern: &str, kind: &str, reason: &str, by: &str) -> Result<(), DbError> {
        // Adding a pattern again updates its kind, reason and who added it.
        sqlx::query(
            "INSERT INTO lib.blocklist (pattern, kind, reason, added_by) VALUES ($1, $2, $3, $4)
             ON CONFLICT (pattern) DO UPDATE SET kind = $2, reason = $3, added_by = $4, added_at = now()",
        )
        .bind(pattern)
        .bind(kind)
        .bind(reason)
        .bind(by)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// Remove a blocklist entry; false if there was none.
    pub async fn remove_block(&self, pattern: &str) -> Result<bool, DbError> {
        // The row count says whether there was an entry.
        Ok(sqlx::query("DELETE FROM lib.blocklist WHERE pattern = $1")
            .bind(pattern)
            .execute(&self.pool)
            .await?
            .rows_affected()
            == 1)
    }

    /// The whole blocklist.
    pub async fn blocklist(&self) -> Result<Vec<BlockEntry>, DbError> {
        // Sorted by pattern, for a stable listing.
        sqlx::query_as("SELECT pattern, kind, reason, added_by, added_at FROM lib.blocklist ORDER BY pattern")
            .fetch_all(&self.pool)
            .await
    }

    /// The blocklist entry or ThreatFox indicator matching a URL: the URL itself, its host, or a parent domain of it.
    pub async fn blocked(&self, url: &str, hosts: &[String]) -> Result<Option<(String, String)>, DbError> {
        // The operator's blocklist and the ThreatFox indicators are searched together; the first match wins.
        let r = sqlx::query(
            "SELECT 'blocklist' AS source, reason FROM lib.blocklist
              WHERE (kind = 'url' AND pattern = $1) OR (kind = 'host' AND pattern = ANY($2))
             UNION ALL
             SELECT 'threatfox' AS source, threat AS reason FROM lib.threat_iocs
              WHERE (kind = 'url' AND ioc = $1) OR (kind = 'host' AND ioc = ANY($2))
             LIMIT 1",
        )
        .bind(url)
        .bind(hosts)
        .fetch_optional(&self.pool)
        .await?;
        r.map(|r| Ok((r.try_get("source")?, r.try_get("reason")?))).transpose()
    }

    /// Replaces the ThreatFox indicators with a fresh set (one transaction: matching never sees half a set).
    pub async fn replace_iocs(&self, iocs: &[(String, String, String)]) -> Result<u64, DbError> {
        // Deleting and inserting in one transaction means matching never sees an empty or half-filled set.
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM lib.threat_iocs").execute(&mut *tx).await?;
        let mut n = 0;
        for (ioc, kind, threat) in iocs {
            n += sqlx::query(
                "INSERT INTO lib.threat_iocs (ioc, kind, threat) VALUES ($1, $2, $3) ON CONFLICT (ioc) DO NOTHING",
            )
            .bind(ioc)
            .bind(kind)
            .bind(threat)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        }
        tx.commit().await?;
        Ok(n)
    }

    /// Adds `by` to a counter unless that would pass `cap`; returns whether it was added. Atomic across processes.
    pub async fn take_from_counter(&self, name: &str, period: &str, by: i64, cap: i64) -> Result<bool, DbError> {
        // One statement: the insert applies only if the amount fits under the cap, and the update only if the new total does, so concurrent callers cannot pass it.
        let v: Option<i64> = sqlx::query_scalar(
            "INSERT INTO lib.counters (name, period, value) SELECT $1, $2, $3 WHERE $3 <= $4
             ON CONFLICT (name, period) DO UPDATE SET value = lib.counters.value + $3
              WHERE lib.counters.value + $3 <= $4
             RETURNING value",
        )
        .bind(name)
        .bind(period)
        .bind(by)
        .bind(cap)
        .fetch_optional(&self.pool)
        .await?;
        Ok(v.is_some())
    }

    /// The value of a counter in a period (zero if it has none).
    pub async fn counter(&self, name: &str, period: &str) -> Result<i64, DbError> {
        // A counter that was never taken from reads as zero.
        Ok(sqlx::query_scalar("SELECT value FROM lib.counters WHERE name = $1 AND period = $2")
            .bind(name)
            .bind(period)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(0))
    }

    /// Takes from several counters at once, all or none (in one transaction): `None` when every take fitted under its
    /// cap, or the index of the first that did not (nothing is taken then). Each take is `(name, period, by, cap)`.
    pub async fn take_from_counters(&self, takes: &[(String, String, i64, i64)]) -> Result<Option<usize>, DbError> {
        // All or none: the first take that does not fit rolls everything back and names its index.
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        for (i, (name, period, by, cap)) in takes.iter().enumerate() {
            let v: Option<i64> = sqlx::query_scalar(
                "INSERT INTO lib.counters (name, period, value) SELECT $1, $2, $3 WHERE $3 <= $4
                 ON CONFLICT (name, period) DO UPDATE SET value = lib.counters.value + $3
                  WHERE lib.counters.value + $3 <= $4
                 RETURNING value",
            )
            .bind(name)
            .bind(period)
            .bind(by)
            .bind(cap)
            .fetch_optional(&mut *tx)
            .await?;
            if v.is_none() {
                tx.rollback().await?;
                return Ok(Some(i));
            }
        }
        tx.commit().await?;
        Ok(None)
    }

    // ── Web Risk lists ─────────────────────────────────────────────────────

    /// Every list's state, without its prefixes.
    pub async fn web_risk_lists(&self) -> Result<Vec<WebRiskListState>, DbError> {
        // Without the prefixes, which are large.
        sqlx::query_as(
            "SELECT threat_type, version_token, entries, next_diff_at, updated_at, last_error
               FROM lib.web_risk_lists ORDER BY threat_type",
        )
        .fetch_all(&self.pool)
        .await
    }

    /// One Web Risk list with its prefixes.
    pub async fn web_risk_list(&self, threat_type: &str) -> Result<Option<WebRiskList>, DbError> {
        // With the prefixes, for loading into memory.
        sqlx::query_as(
            "SELECT threat_type, version_token, entries, prefixes, checksum, next_diff_at, updated_at, last_error
               FROM lib.web_risk_lists WHERE threat_type = $1",
        )
        .bind(threat_type)
        .fetch_optional(&self.pool)
        .await
    }

    /// Stores a list after a verified update (the worker only).
    pub async fn put_web_risk_list(&self, l: &WebRiskList) -> Result<(), DbError> {
        // Upsert by threat type; this is the worker's write after a verified update.
        sqlx::query(
            "INSERT INTO lib.web_risk_lists (threat_type, version_token, entries, prefixes, checksum, next_diff_at,
                                             updated_at, last_error)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (threat_type) DO UPDATE SET version_token = $2, entries = $3, prefixes = $4, checksum = $5,
                    next_diff_at = $6, updated_at = $7, last_error = $8",
        )
        .bind(&l.threat_type)
        .bind(&l.version_token)
        .bind(l.entries)
        .bind(&l.prefixes)
        .bind(&l.checksum)
        .bind(l.next_diff_at)
        .bind(l.updated_at)
        .bind(&l.last_error)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// An update failed: keeps the list as it was, records why and when to try again; `full` asks for the whole list
    /// next time (a checksum mismatch). The list's `updated_at` is unchanged, so nobody reloads it.
    pub async fn web_risk_list_failed(
        &self,
        threat_type: &str,
        error: &str,
        next: OffsetDateTime,
        full: bool,
    ) -> Result<(), DbError> {
        // The prefixes and `updated_at` are left alone so nobody reloads a list that did not change; a mismatch also clears the version so the next ask is for the whole list.
        sqlx::query(
            "INSERT INTO lib.web_risk_lists (threat_type, next_diff_at, last_error, updated_at)
             VALUES ($1, $3, $2, 'epoch')
             ON CONFLICT (threat_type) DO UPDATE SET next_diff_at = $3, last_error = $2,
                    version_token = CASE WHEN $4 THEN '' ELSE lib.web_risk_lists.version_token END",
        )
        .bind(threat_type)
        .bind(error)
        .bind(next)
        .bind(full)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    // ── housekeeping ───────────────────────────────────────────────────────

    /// Deletes expired sessions, challenges, invites (90 days after expiry), audit entries older than `audit_keep`,
    /// and decided reports and appeals older than `cases_keep`. Returns the rows removed.
    pub async fn prune(&self, now: OffsetDateTime, audit_keep: Duration, cases_keep: Duration) -> Result<u64, DbError> {
        // Each kind of old row goes by its own rule; the total number removed is returned.
        let mut n = 0;
        n += sqlx::query("DELETE FROM lib.sessions WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        n += sqlx::query("DELETE FROM lib.challenges WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        n += sqlx::query("DELETE FROM lib.invites WHERE redeemed_by IS NULL AND expires_at <= $1 - interval '90 days'")
            .bind(now)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // Through the schema owner's function: no application role needs DELETE on the audit log (it also refuses to
        // remove anything younger than two years).
        let pruned: i64 =
            sqlx::query_scalar("SELECT lib.prune_audit_log($1)").bind(now - audit_keep).fetch_one(&self.pool).await?;
        n += u64::try_from(pruned).unwrap_or(0);
        // Per-account counters (`<name>:<account>`, by day or by hour) from before yesterday. Counters over every
        // account are named without a colon (`webrisk`, `webrisk-confirm`), so their months are kept.
        n += sqlx::query("DELETE FROM lib.counters WHERE name LIKE '%:%' AND period < $1")
            .bind(day(now - Duration::days(1)))
            .execute(&self.pool)
            .await?
            .rows_affected();
        n += sqlx::query("DELETE FROM lib.appeals WHERE status <> 'open' AND decided_at < $1")
            .bind(now - cases_keep)
            .execute(&self.pool)
            .await?
            .rows_affected();
        n += sqlx::query("DELETE FROM lib.reports WHERE status <> 'open' AND decided_at < $1")
            .bind(now - cases_keep)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(n)
    }

    /// The figures for the overview and `/metrics`, in one query.
    pub async fn stats(&self, now: OffsetDateTime) -> Result<Stats, DbError> {
        // One round trip: every figure is a sub-select, and storage is the pictures, the drafts and published documents, and the kept versions.
        let r = sqlx::query(
            "SELECT
               (SELECT count(*) FROM lib.accounts WHERE status = 'active') AS active,
               (SELECT count(*) FROM lib.accounts WHERE status = 'suspended') AS suspended,
               (SELECT count(*) FROM lib.accounts WHERE status = 'active' AND free) AS free,
               (SELECT count(*) FROM lib.accounts WHERE status = 'active' AND paid_until > $1) AS paid,
               (SELECT count(*) FROM lib.pages WHERE published IS NOT NULL) AS published,
               (SELECT count(*) FROM lib.reports WHERE status = 'open') AS reports_open,
               (SELECT count(*) FROM lib.reports WHERE status = 'open' AND created_at < $1 - interval '24 hours') AS reports_old,
               (SELECT count(*) FROM lib.appeals WHERE status = 'open') AS appeals_open,
               (SELECT count(*) FROM lib.link_screens WHERE verdict = 'flagged') AS flagged,
               (SELECT count(*) FROM lib.link_screens WHERE verdict = 'unknown') AS unknown,
               (SELECT coalesce(sum(length(bytes)), 0) FROM lib.assets)
                 + (SELECT coalesce(sum(length(draft) + length(coalesce(published, ''))), 0) FROM lib.pages)
                 + (SELECT coalesce(sum(length(manifest)), 0) FROM lib.page_versions) AS storage,
               (SELECT count(*) FROM lib.checkouts WHERE status = 'open') AS checkouts_open",
        )
        .bind(now)
        .fetch_one(&self.pool)
        .await?;
        Ok(Stats {
            accounts_active: r.try_get("active")?,
            accounts_suspended: r.try_get("suspended")?,
            accounts_free: r.try_get("free")?,
            accounts_paid: r.try_get("paid")?,
            pages_published: r.try_get("published")?,
            reports_open: r.try_get("reports_open")?,
            reports_open_over_24h: r.try_get("reports_old")?,
            appeals_open: r.try_get("appeals_open")?,
            links_flagged: r.try_get("flagged")?,
            links_unknown: r.try_get("unknown")?,
            storage_bytes: r.try_get::<i64, _>("storage")?,
            checkouts_open: r.try_get("checkouts_open")?,
        })
    }

    /// The worker's single-writer lock (held for the life of the returned connection).
    pub async fn try_worker_lock(&self) -> Result<Option<sqlx::pool::PoolConnection<Postgres>>, DbError> {
        // A session-level advisory lock: held for as long as the returned connection lives, so only one worker runs the housekeeping at a time.
        let mut c = self.pool.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(7_301_516_041)").fetch_one(&mut *c).await?;
        Ok(got.then_some(c))
    }
}

/// Insert an account row inside the caller's transaction: a unique violation means the handle or its skeleton is taken.
async fn insert_account(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    n: &NewAccount<'_>,
    free: bool,
    invited_by: Option<Uuid>,
    now: OffsetDateTime,
) -> Result<(), CreateError> {
    // The terms and the age declaration are accepted at the moment of sign-up, so one time stamps all of them.
    let r = sqlx::query(
        "INSERT INTO lib.accounts (id, handle, handle_skeleton, free, operator, invited_by, age_confirmed_at,
                                   terms_version, terms_accepted_at, country_declared, billing_ref, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $9, $10, $7)",
    )
    .bind(id)
    .bind(n.handle)
    .bind(n.handle_skeleton)
    .bind(free)
    .bind(n.operator)
    .bind(invited_by)
    .bind(now)
    .bind(n.terms_version)
    .bind(n.country_declared)
    .bind(n.billing_ref)
    .execute(&mut **tx)
    .await;
    match r {
        Ok(_) => Ok(()),
        Err(e) if unique_violation(&e) => Err(CreateError::HandleTaken),
        Err(e) => Err(e.into()),
    }
}

/// A sign-in of the operator console that the callback is completing (see [`Store::take_admin_login`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLogin {
    /// SHA-256 of the binding cookie's value.
    pub binding_hash: String,
    /// The `nonce` the ID token must carry.
    pub nonce: String,
    /// The PKCE verifier.
    pub verifier: String,
}

/// A live operator-console session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSession {
    /// The provider's `sub`.
    pub subject: String,
    /// The name shown.
    pub display_name: String,
    /// The ID token, for the provider's logout.
    pub id_token: String,
}

impl Store {
    // ── operator console sessions (schema 7) ───────────────────────────────

    /// Record a sign-in in progress.
    pub async fn begin_admin_login(
        &self,
        state_hash: &str,
        binding_hash: &str,
        nonce: &str,
        verifier: &str,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // One row per sign-in; the primary key (the state hash) makes a repeated state value impossible.
        // The time is the caller's, so tests can place a sign-in in the past.
        // The state and binding values are hashes; the nonce and verifier are the provider-bound secrets of this one sign-in.
        sqlx::query(
            "INSERT INTO lib.admin_login_attempts (state_hash, binding_hash, nonce, verifier, created_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(state_hash)
        .bind(binding_hash)
        .bind(nonce)
        .bind(verifier)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Consume a sign-in: the row is deleted whether or not it is still fresh, so a state value never works twice. `None` when there is no such row or it is older than `max_age`.
    pub async fn take_admin_login(
        &self,
        state_hash: &str,
        max_age: Duration,
        now: OffsetDateTime,
    ) -> Result<Option<AdminLogin>, DbError> {
        // DELETE ... RETURNING takes the row and removes it in one statement, so two racing callbacks cannot both use it.
        // Freshness is judged below, after the row is gone, so a stale row cannot be tried again either.
        let row = sqlx::query(
            "DELETE FROM lib.admin_login_attempts WHERE state_hash = $1 RETURNING binding_hash, nonce, verifier, created_at",
        )
        .bind(state_hash)
        .fetch_optional(&self.pool)
        .await?;
        // A stale row was consumed above but is reported as absent.
        Ok(row.and_then(|r| {
            let created: OffsetDateTime = r.get("created_at");
            (created > now - max_age).then(|| AdminLogin {
                binding_hash: r.get("binding_hash"),
                nonce: r.get("nonce"),
                verifier: r.get("verifier"),
            })
        }))
    }

    /// Create a session for a completed sign-in. Only the hash of the cookie's identifier is stored (the identifier itself exists only in the browser's cookie).
    pub async fn create_admin_session(
        &self,
        id_hash: &str,
        subject: &str,
        provider_sid: &str,
        display_name: &str,
        id_token: &str,
        now: OffsetDateTime,
    ) -> Result<(), DbError> {
        // Created and last-seen start equal (the same bound value), so a new session is idle for zero seconds.
        sqlx::query(
            "INSERT INTO lib.admin_sessions (id_hash, subject, provider_sid, display_name, id_token, created_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $5, $6, $6)",
        )
        .bind(id_hash)
        .bind(subject)
        .bind(provider_sid)
        .bind(display_name)
        .bind(id_token)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Find a session inside both its lifetimes (`absolute` since sign-in, `idle` since last use) and mark it used. `None` for an unknown or expired session.
    pub async fn use_admin_session(
        &self,
        id_hash: &str,
        idle: Duration,
        absolute: Duration,
        now: OffsetDateTime,
    ) -> Result<Option<AdminSession>, DbError> {
        // One statement checks both lifetimes and marks the session used: an expired session matches no row.
        let row = sqlx::query(
            "UPDATE lib.admin_sessions SET last_seen_at = $2
             WHERE id_hash = $1 AND created_at > $3 AND last_seen_at > $4
             RETURNING subject, display_name, id_token",
        )
        .bind(id_hash)
        .bind(now)
        .bind(now - absolute)
        .bind(now - idle)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| AdminSession {
            subject: r.get("subject"),
            display_name: r.get("display_name"),
            id_token: r.get("id_token"),
        }))
    }

    /// End one session (sign-out) and return what the provider's logout needs, or `None` when there was none.
    pub async fn end_admin_session(&self, id_hash: &str) -> Result<Option<AdminSession>, DbError> {
        // Delete and return in one statement: the provider's logout needs the stored ID token.
        let row =
            sqlx::query("DELETE FROM lib.admin_sessions WHERE id_hash = $1 RETURNING subject, display_name, id_token")
                .bind(id_hash)
                .fetch_optional(&self.pool)
                .await?;
        // The caller shows the name and uses the stored token for the provider's logout; nothing else is read back.
        Ok(row.map(|r| AdminSession {
            subject: r.get("subject"),
            display_name: r.get("display_name"),
            id_token: r.get("id_token"),
        }))
    }

    /// End the sessions of one provider session (back-channel logout naming a `sid`). An empty id never matches: sessions made without one must not all end because one logout token carried none.
    pub async fn end_admin_sessions_by_provider_session(&self, provider_sid: &str) -> Result<u64, DbError> {
        Ok(sqlx::query("DELETE FROM lib.admin_sessions WHERE provider_sid = $1 AND provider_sid <> ''")
            .bind(provider_sid)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    /// End every session of a person (back-channel logout naming only a `sub`).
    pub async fn end_admin_sessions_by_subject(&self, subject: &str) -> Result<u64, DbError> {
        // Every session of one person, whatever browser it is in.
        Ok(sqlx::query("DELETE FROM lib.admin_sessions WHERE subject = $1")
            .bind(subject)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    /// Delete what has expired: sign-ins older than `login_max_age` and sessions outside either lifetime. Returns the rows removed.
    pub async fn purge_admin_sessions(
        &self,
        login_max_age: Duration,
        idle: Duration,
        absolute: Duration,
        now: OffsetDateTime,
    ) -> Result<u64, DbError> {
        // Sign-ins that were started and never finished.
        // The sign-in lifetime is short (minutes), so what is found here was abandoned.
        let logins = sqlx::query("DELETE FROM lib.admin_login_attempts WHERE created_at <= $1")
            .bind(now - login_max_age)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // Sessions past their absolute or idle limit (they could not be used anyway; this keeps the table small).
        // Either limit alone is enough to delete one.
        let sessions = sqlx::query("DELETE FROM lib.admin_sessions WHERE created_at <= $1 OR last_seen_at <= $2")
            .bind(now - absolute)
            .bind(now - idle)
            .execute(&self.pool)
            .await?
            .rows_affected();
        // The caller only logs how many rows went.
        Ok(logins + sessions)
    }
}
