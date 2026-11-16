//! `link-in-bio-store`: every SQL statement of the hosted service. Runtime-checked queries (`sqlx::query`), each covered
//! by the real-PostgreSQL tests in `tests/store.rs` (TLS, `verify-full`, `scripts/test-postgres.sh`).
//!
//! The writer role (app, admin, worker) uses the `lib.*` tables; the page process uses only the `public.*_v1` views
//! ([`Store::view_page`] and the other `view_*` methods), which the read-only role can read and nothing else.

pub mod config;

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub use sqlx::Error as DbError;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// SHA-256, the only form a secret (session cookie, invite code, recovery code) or a link URL is stored or looked up in.
pub fn sha256(v: &[u8]) -> Vec<u8> {
    Sha256::digest(v).to_vec()
}

/// The average month the paid period is extended by (365.25 / 12 days), the same as the on-chain ledger's.
pub const MONTH: Duration = Duration::milliseconds(2_629_800_000);

#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Account {
    pub id: Uuid,
    pub handle: String,
    pub status: String,
    pub suspension_kind: Option<String>,
    pub suspension_reason: Option<String>,
    pub suspended_until: Option<DateTime<Utc>>,
    pub free: bool,
    pub operator: bool,
    pub may_share_invites: bool,
    pub invited_by: Option<Uuid>,
    pub tags: Vec<String>,
    pub terms_version: String,
    pub country_declared: Option<String>,
    pub billing_ref: String,
    pub paid_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl Account {
    /// Whether the account may have a page online now (free, operator, or paid up within the grace period).
    pub fn entitled(&self, now: DateTime<Utc>, grace: Duration) -> bool {
        self.free || self.operator || self.paid_until.is_some_and(|p| p + grace > now)
    }
}

macro_rules! account_columns {
    () => {
        "id, handle, status, suspension_kind, suspension_reason, suspended_until, free, operator, may_share_invites, \
         invited_by, tags, terms_version, country_declared, billing_ref, paid_until, created_at"
    };
}

#[derive(Debug, Clone)]
pub struct NewAccount<'a> {
    /// Chosen before the account exists (a passkey ceremony needs the user id first).
    pub id: Uuid,
    pub handle: &'a str,
    pub handle_skeleton: &'a str,
    pub terms_version: &'a str,
    pub country_declared: Option<&'a str>,
    pub billing_ref: &'a str,
    pub operator: bool,
    /// The initial (unpublished) page document.
    pub draft: &'a str,
    /// SHA-256 of an invite code to redeem in the same transaction (the account is then free).
    pub invite_hash: Option<&'a [u8]>,
}

#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("that handle is taken or too close to one that exists")]
    HandleTaken,
    #[error("that invite code is not valid")]
    InviteInvalid,
    #[error(transparent)]
    Db(#[from] DbError),
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct PageRow {
    pub draft: String,
    pub published: Option<String>,
    pub version: i32,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
}

/// What the page process reads about a handle (`public.page_v1`).
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct PublicPage {
    pub handle: String,
    pub status: String,
    pub suspension_kind: Option<String>,
    pub suspended_until: Option<DateTime<Utc>>,
    pub free: bool,
    pub operator: bool,
    pub paid_until: Option<DateTime<Utc>>,
    pub published: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AssetRow {
    pub sha256: String,
    pub mime: String,
    pub ext: String,
    pub width: i32,
    pub height: i32,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Invite {
    pub id: Uuid,
    pub held_by: Option<Uuid>,
    pub selection_id: Option<Uuid>,
    pub note: Option<String>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub redeemed_by: Option<Uuid>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Selection {
    pub id: Uuid,
    pub name: String,
    pub criteria: Value,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
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

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Checkout {
    pub id: Uuid,
    pub account_id: Uuid,
    pub provider: String,
    pub provider_ref: String,
    pub method: String,
    pub months: i32,
    pub amount_pence: i64,
    pub status: String,
    pub country_declared: Option<String>,
    pub country_request: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BillingEvent {
    pub id: Uuid,
    pub provider: String,
    pub provider_event: String,
    pub kind: String,
    pub months: i32,
    pub amount_pence: i64,
    pub paid_until_after: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// One change to an account's paid period.
#[derive(Debug, Clone)]
pub struct PeriodChange<'a> {
    pub account_id: Uuid,
    pub provider: &'a str,
    pub provider_event: &'a str,
    /// `purchase`, `grant` (positive months) or `refund` (negative months).
    pub kind: &'a str,
    pub months: i32,
    pub amount_pence: i64,
    pub evidence: Value,
    /// The checkout this settles, if any (marked paid in the same transaction).
    pub checkout: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Domain {
    pub hostname: String,
    pub account_id: Uuid,
    pub method: String,
    pub token: String,
    pub status: String,
    pub checked_at: Option<DateTime<Utc>>,
    pub verified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Report {
    pub id: Uuid,
    pub handle: String,
    pub account_id: Option<Uuid>,
    pub url: Option<String>,
    pub reason: String,
    pub details: String,
    pub contact: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub decision: Option<String>,
    pub statement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Appeal {
    pub id: Uuid,
    pub account_id: Uuid,
    pub report_id: Option<Uuid>,
    pub text: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub decided_at: Option<DateTime<Utc>>,
    pub decided_by: Option<String>,
    pub statement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct AuditEntry {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub subject: String,
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Screen {
    pub url_hash: Vec<u8>,
    pub url: String,
    pub verdict: String,
    pub source: String,
    pub detail: String,
    pub checked_at: DateTime<Utc>,
    pub next_check_at: DateTime<Utc>,
    pub overridden_by: Option<String>,
}

#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct BlockEntry {
    pub pattern: String,
    pub kind: String,
    pub reason: String,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
}

/// Figures for `/metrics` and the admin overview.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stats {
    pub accounts_active: i64,
    pub accounts_suspended: i64,
    pub accounts_free: i64,
    pub accounts_paid: i64,
    pub pages_published: i64,
    pub reports_open: i64,
    pub reports_open_over_24h: i64,
    pub appeals_open: i64,
    pub links_flagged: i64,
    pub links_unknown: i64,
    pub storage_bytes: i64,
    pub checkouts_open: i64,
}

fn unique_violation(e: &DbError) -> bool {
    matches!(e, DbError::Database(d) if d.code().as_deref() == Some("23505"))
}

impl Store {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }

    pub async fn ping(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map(|_| ())
    }

    // ── accounts ───────────────────────────────────────────────────────────

    /// Creates an account and its (unpublished) page; redeems the invite in the same transaction when one is given.
    pub async fn create_account(&self, n: &NewAccount<'_>, now: DateTime<Utc>) -> Result<Account, CreateError> {
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

    pub async fn account(&self, id: Uuid) -> Result<Option<Account>, DbError> {
        sqlx::query_as(concat!("SELECT ", account_columns!(), " FROM lib.accounts WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn account_by_handle(&self, handle: &str) -> Result<Option<Account>, DbError> {
        sqlx::query_as(concat!("SELECT ", account_columns!(), " FROM lib.accounts WHERE handle = $1"))
            .bind(handle)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn handle_available(&self, handle: &str, skeleton: &str) -> Result<bool, DbError> {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM lib.accounts WHERE handle = $1 OR handle_skeleton = $2")
            .bind(handle)
            .bind(skeleton)
            .fetch_one(&self.pool)
            .await?;
        Ok(n == 0)
    }

    /// Accounts for the admin list: by handle prefix (or all), newest first.
    pub async fn accounts(&self, prefix: &str, limit: i64, offset: i64) -> Result<Vec<Account>, DbError> {
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

    pub async fn set_country(&self, id: Uuid, country: Option<&str>) -> Result<(), DbError> {
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
        until: Option<DateTime<Utc>>,
    ) -> Result<bool, DbError> {
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

    pub async fn unsuspend(&self, id: Uuid) -> Result<bool, DbError> {
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
    pub async fn lift_expired_suspensions(&self, now: DateTime<Utc>) -> Result<Vec<Uuid>, DbError> {
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
    pub async fn delete_account(&self, id: Uuid, now: DateTime<Utc>) -> Result<bool, DbError> {
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

    pub async fn add_passkey(
        &self,
        account: Uuid,
        credential_id: &[u8],
        passkey: &Value,
        name: &str,
    ) -> Result<(), DbError> {
        sqlx::query("INSERT INTO lib.passkeys (credential_id, account_id, passkey, name) VALUES ($1, $2, $3, $4)")
            .bind(credential_id)
            .bind(account)
            .bind(passkey)
            .bind(name)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    pub async fn passkeys(&self, account: Uuid) -> Result<Vec<(Vec<u8>, Value, String)>, DbError> {
        let rows = sqlx::query(
            "SELECT credential_id, passkey, name FROM lib.passkeys WHERE account_id = $1 ORDER BY created_at",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok((r.try_get("credential_id")?, r.try_get("passkey")?, r.try_get("name")?))).collect()
    }

    pub async fn passkey_owner(&self, credential_id: &[u8]) -> Result<Option<(Uuid, Value)>, DbError> {
        let r = sqlx::query("SELECT account_id, passkey FROM lib.passkeys WHERE credential_id = $1")
            .bind(credential_id)
            .fetch_optional(&self.pool)
            .await?;
        r.map(|r| Ok((r.try_get("account_id")?, r.try_get("passkey")?))).transpose()
    }

    pub async fn update_passkey(
        &self,
        credential_id: &[u8],
        passkey: &Value,
        now: DateTime<Utc>,
    ) -> Result<(), DbError> {
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

    pub async fn wallet_owner(&self, address: &str) -> Result<Option<Uuid>, DbError> {
        sqlx::query_scalar("SELECT account_id FROM lib.wallets WHERE address = $1")
            .bind(address)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn wallets(&self, account: Uuid) -> Result<Vec<String>, DbError> {
        sqlx::query_scalar("SELECT address FROM lib.wallets WHERE account_id = $1 ORDER BY created_at")
            .bind(account)
            .fetch_all(&self.pool)
            .await
    }

    pub async fn delete_wallet(&self, account: Uuid, address: &str) -> Result<bool, DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<Option<Uuid>, DbError> {
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

    pub async fn recovery_codes_left(&self, account: Uuid) -> Result<i64, DbError> {
        sqlx::query_scalar("SELECT count(*) FROM lib.recovery_codes WHERE account_id = $1 AND used_at IS NULL")
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    // ── sessions and challenges ────────────────────────────────────────────

    pub async fn create_session(
        &self,
        token_hash: &[u8],
        account: Uuid,
        expires_at: DateTime<Utc>,
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
        now: DateTime<Utc>,
        idle: Duration,
        absolute: Duration,
    ) -> Result<Option<Uuid>, DbError> {
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

    pub async fn delete_session(&self, token_hash: &[u8]) -> Result<(), DbError> {
        sqlx::query("DELETE FROM lib.sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    pub async fn delete_sessions(&self, account: Uuid) -> Result<u64, DbError> {
        Ok(sqlx::query("DELETE FROM lib.sessions WHERE account_id = $1")
            .bind(account)
            .execute(&self.pool)
            .await?
            .rows_affected())
    }

    pub async fn put_challenge(
        &self,
        id: &str,
        kind: &str,
        account: Option<Uuid>,
        state: &Value,
        expires_at: DateTime<Utc>,
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
        now: DateTime<Utc>,
    ) -> Result<Option<(Option<Uuid>, Value)>, DbError> {
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

    pub async fn page(&self, account: Uuid) -> Result<Option<PageRow>, DbError> {
        sqlx::query_as(
            "SELECT draft, published, version, updated_at, published_at FROM lib.pages WHERE account_id = $1",
        )
        .bind(account)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn save_draft(&self, account: Uuid, manifest: &str, now: DateTime<Utc>) -> Result<(), DbError> {
        sqlx::query("UPDATE lib.pages SET draft = $2, updated_at = $3 WHERE account_id = $1")
            .bind(account)
            .bind(manifest)
            .bind(now)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    /// Publishes a checked manifest as the next version (the draft becomes the same document). Returns the version.
    pub async fn publish(&self, account: Uuid, manifest: &str, now: DateTime<Utc>) -> Result<i32, DbError> {
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

    pub async fn unpublish(&self, account: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE lib.pages SET published = NULL, published_at = NULL WHERE account_id = $1")
            .bind(account)
            .execute(&self.pool)
            .await
            .map(|_| ())
    }

    pub async fn page_versions(&self, account: Uuid) -> Result<Vec<(i32, DateTime<Utc>)>, DbError> {
        let rows = sqlx::query(
            "SELECT version, created_at FROM lib.page_versions WHERE account_id = $1 ORDER BY version DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(|r| Ok((r.try_get("version")?, r.try_get("created_at")?))).collect()
    }

    pub async fn page_version(&self, account: Uuid, version: i32) -> Result<Option<String>, DbError> {
        sqlx::query_scalar("SELECT manifest FROM lib.page_versions WHERE account_id = $1 AND version = $2")
            .bind(account)
            .bind(version)
            .fetch_optional(&self.pool)
            .await
    }

    /// Keeps the newest `keep` versions of every page.
    pub async fn prune_versions(&self, keep: i64) -> Result<u64, DbError> {
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

    pub async fn put_asset(&self, account: Uuid, a: &AssetRow) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO lib.assets (sha256, account_id, mime, ext, width, height, bytes)
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (sha256) DO NOTHING",
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
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM lib.assets WHERE sha256 = $1 AND account_id = $2)")
            .bind(sha256)
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    /// Bytes of pictures an account stored (its quota).
    pub async fn asset_bytes(&self, account: Uuid) -> Result<i64, DbError> {
        sqlx::query_scalar("SELECT coalesce(sum(length(bytes)), 0)::bigint FROM lib.assets WHERE account_id = $1")
            .bind(account)
            .fetch_one(&self.pool)
            .await
    }

    /// Deletes an account's pictures no draft, published page or kept version refers to.
    pub async fn prune_assets(&self) -> Result<u64, DbError> {
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

    pub async fn view_page(&self, handle: &str) -> Result<Option<PublicPage>, DbError> {
        sqlx::query_as(
            "SELECT handle, status, suspension_kind, suspended_until, free, operator, paid_until, published, published_at
               FROM public.page_v1 WHERE handle = $1",
        )
        .bind(handle)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn view_asset(&self, sha256: &str) -> Result<Option<AssetRow>, DbError> {
        sqlx::query_as("SELECT sha256, mime, ext, width, height, bytes FROM public.asset_v1 WHERE sha256 = $1")
            .bind(sha256)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn view_domain(&self, hostname: &str) -> Result<Option<String>, DbError> {
        sqlx::query_scalar("SELECT handle FROM public.domain_v1 WHERE hostname = $1")
            .bind(hostname)
            .fetch_optional(&self.pool)
            .await
    }

    /// Which of these link URL hashes are flagged.
    pub async fn view_flagged(&self, hashes: &[Vec<u8>]) -> Result<HashSet<Vec<u8>>, DbError> {
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
        expires_at: DateTime<Utc>,
    ) -> Result<Vec<Uuid>, DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<(Vec<(String, DateTime<Utc>)>, i64), DbError> {
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

    pub async fn invites(&self, held_by: Option<Uuid>, limit: i64) -> Result<Vec<Invite>, DbError> {
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

    pub async fn revoke_invite(&self, id: Uuid, now: DateTime<Utc>) -> Result<bool, DbError> {
        let r = sqlx::query(
            "UPDATE lib.invites SET revoked_at = $2, code = NULL WHERE id = $1 AND redeemed_by IS NULL AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() == 1)
    }

    pub async fn create_selection(&self, name: &str, criteria: &Criteria, by: &str) -> Result<Uuid, DbError> {
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

    pub async fn selections(&self) -> Result<Vec<Selection>, DbError> {
        sqlx::query_as("SELECT id, name, criteria, created_by, created_at FROM lib.selections ORDER BY name")
            .fetch_all(&self.pool)
            .await
    }

    pub async fn selection(&self, id: Uuid) -> Result<Option<Selection>, DbError> {
        sqlx::query_as("SELECT id, name, criteria, created_by, created_at FROM lib.selections WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
    }

    pub async fn delete_selection(&self, id: Uuid) -> Result<bool, DbError> {
        Ok(sqlx::query("DELETE FROM lib.selections WHERE id = $1").bind(id).execute(&self.pool).await?.rows_affected()
            == 1)
    }

    /// The active accounts a selection's criteria match now.
    pub async fn match_selection(&self, c: &Criteria, now: DateTime<Utc>) -> Result<Vec<Account>, DbError> {
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

    pub async fn create_checkout(&self, c: &Checkout) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO lib.checkouts (id, account_id, provider, provider_ref, method, months, amount_pence, status,
                                        country_declared, country_request, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8, $9, $10)",
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
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    pub async fn checkout(&self, id: Uuid) -> Result<Option<Checkout>, DbError> {
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at FROM lib.checkouts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
    }

    pub async fn checkout_by_ref(&self, provider: &str, provider_ref: &str) -> Result<Option<Checkout>, DbError> {
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at FROM lib.checkouts WHERE provider = $1 AND provider_ref = $2",
        )
        .bind(provider)
        .bind(provider_ref)
        .fetch_optional(&self.pool)
        .await
    }

    /// Open checkouts created before `before` (the worker asks their providers how they ended).
    pub async fn stale_checkouts(&self, before: DateTime<Utc>, limit: i64) -> Result<Vec<Checkout>, DbError> {
        sqlx::query_as(
            "SELECT id, account_id, provider, provider_ref, method, months, amount_pence, status, country_declared,
                    country_request, created_at, completed_at
               FROM lib.checkouts WHERE status = 'open' AND created_at < $1 ORDER BY created_at LIMIT $2",
        )
        .bind(before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn close_checkout(&self, id: Uuid, status: &str, now: DateTime<Utc>) -> Result<bool, DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, DbError> {
        let mut tx: Transaction<'_, Postgres> = self.pool.begin().await?;
        let id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO lib.billing_events (id, account_id, provider, provider_event, kind, months, amount_pence, evidence)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (provider, provider_event) DO NOTHING",
        )
        .bind(id)
        .bind(c.account_id)
        .bind(c.provider)
        .bind(c.provider_event)
        .bind(c.kind)
        .bind(c.months)
        .bind(c.amount_pence)
        .bind(&c.evidence)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            return Ok(None);
        }
        let span = MONTH * c.months;
        let until: DateTime<Utc> = sqlx::query_scalar(
            "UPDATE lib.accounts SET paid_until = CASE
                    WHEN $2 >= interval '0' THEN greatest(coalesce(paid_until, $3), $3) + $2
                    ELSE greatest(coalesce(paid_until, $3) + $2, $3) END
              WHERE id = $1 RETURNING paid_until",
        )
        .bind(c.account_id)
        .bind(span)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("UPDATE lib.billing_events SET paid_until_after = $2 WHERE id = $1")
            .bind(id)
            .bind(until)
            .execute(&mut *tx)
            .await?;
        if let Some(ch) = c.checkout {
            sqlx::query("UPDATE lib.checkouts SET status = 'paid', completed_at = $2 WHERE id = $1")
                .bind(ch)
                .bind(now)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(Some(until))
    }

    pub async fn billing_events(&self, account: Uuid) -> Result<Vec<BillingEvent>, DbError> {
        sqlx::query_as(
            "SELECT id, provider, provider_event, kind, months, amount_pence, paid_until_after, created_at
               FROM lib.billing_events WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    // ── domains ────────────────────────────────────────────────────────────

    pub async fn add_domain(&self, account: Uuid, hostname: &str, method: &str, token: &str) -> Result<bool, DbError> {
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

    pub async fn domains(&self, account: Uuid) -> Result<Vec<Domain>, DbError> {
        sqlx::query_as(
            "SELECT hostname, account_id, method, token, status, checked_at, verified_at
               FROM lib.domains WHERE account_id = $1 ORDER BY created_at",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn count_domains(&self) -> Result<i64, DbError> {
        sqlx::query_scalar("SELECT count(*) FROM lib.domains").fetch_one(&self.pool).await
    }

    /// Domains to (re)check: pending ones, and verified ones last checked before `before`.
    pub async fn domains_due(&self, before: DateTime<Utc>, limit: i64) -> Result<Vec<Domain>, DbError> {
        sqlx::query_as(
            "SELECT hostname, account_id, method, token, status, checked_at, verified_at FROM lib.domains
              WHERE status = 'pending' OR checked_at IS NULL OR checked_at < $1 ORDER BY checked_at NULLS FIRST LIMIT $2",
        )
        .bind(before)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn set_domain_status(&self, hostname: &str, status: &str, now: DateTime<Utc>) -> Result<(), DbError> {
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

    pub async fn delete_domain(&self, account: Uuid, hostname: &str) -> Result<bool, DbError> {
        Ok(sqlx::query("DELETE FROM lib.domains WHERE account_id = $1 AND hostname = $2")
            .bind(account)
            .bind(hostname)
            .execute(&self.pool)
            .await?
            .rows_affected()
            == 1)
    }

    // ── reports, appeals, audit ────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn create_report(
        &self,
        handle: &str,
        url: Option<&str>,
        reason: &str,
        details: &str,
        contact: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Uuid, DbError> {
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

    pub async fn reports(&self, status: &str, limit: i64) -> Result<Vec<Report>, DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<bool, DbError> {
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
        sqlx::query_as(
            "SELECT id, handle, account_id, url, reason, '' AS details, NULL::text AS contact, status, created_at,
                    decided_at, NULL::text AS decided_by, decision, statement
               FROM lib.reports WHERE account_id = $1 AND status = 'actioned' ORDER BY decided_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn create_appeal(&self, account: Uuid, report: Option<Uuid>, text: &str) -> Result<Uuid, DbError> {
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

    pub async fn appeals(&self, status: &str, limit: i64) -> Result<Vec<Appeal>, DbError> {
        sqlx::query_as(
            "SELECT id, account_id, report_id, text, status, created_at, decided_at, decided_by, statement
               FROM lib.appeals WHERE status = $1 ORDER BY created_at LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn appeals_of(&self, account: Uuid) -> Result<Vec<Appeal>, DbError> {
        sqlx::query_as(
            "SELECT id, account_id, report_id, text, status, created_at, decided_at, NULL::text AS decided_by, statement
               FROM lib.appeals WHERE account_id = $1 ORDER BY created_at DESC",
        )
        .bind(account)
        .fetch_all(&self.pool)
        .await
    }

    pub async fn decide_appeal(
        &self,
        id: Uuid,
        status: &str,
        by: &str,
        statement: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<Uuid>, DbError> {
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

    pub async fn audit_log(&self, subject: Option<&str>, limit: i64) -> Result<Vec<AuditEntry>, DbError> {
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

    pub async fn screens(&self, hashes: &[Vec<u8>]) -> Result<Vec<Screen>, DbError> {
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
        next_check_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<(), DbError> {
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
        now: DateTime<Utc>,
    ) -> Result<(), DbError> {
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

    pub async fn screens_due(&self, now: DateTime<Utc>, limit: i64) -> Result<Vec<Screen>, DbError> {
        sqlx::query_as(
            "SELECT url_hash, url, verdict, source, detail, checked_at, next_check_at, overridden_by
               FROM lib.link_screens WHERE next_check_at <= $1 AND overridden_by IS NULL ORDER BY next_check_at LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
    }

    /// Screened links no page (draft or published) contains any more.
    pub async fn prune_screens(&self) -> Result<u64, DbError> {
        Ok(sqlx::query(
            "DELETE FROM lib.link_screens s WHERE s.overridden_by IS NULL AND s.checked_at < now() - interval '7 days'
                AND NOT EXISTS (SELECT 1 FROM lib.pages p
                                 WHERE strpos(p.draft, s.url) > 0 OR strpos(coalesce(p.published, ''), s.url) > 0)",
        )
        .execute(&self.pool)
        .await?
        .rows_affected())
    }

    pub async fn add_block(&self, pattern: &str, kind: &str, reason: &str, by: &str) -> Result<(), DbError> {
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

    pub async fn remove_block(&self, pattern: &str) -> Result<bool, DbError> {
        Ok(sqlx::query("DELETE FROM lib.blocklist WHERE pattern = $1")
            .bind(pattern)
            .execute(&self.pool)
            .await?
            .rows_affected()
            == 1)
    }

    pub async fn blocklist(&self) -> Result<Vec<BlockEntry>, DbError> {
        sqlx::query_as("SELECT pattern, kind, reason, added_by, added_at FROM lib.blocklist ORDER BY pattern")
            .fetch_all(&self.pool)
            .await
    }

    /// The blocklist entry or ThreatFox indicator matching a URL: the URL itself, its host, or a parent domain of it.
    pub async fn blocked(&self, url: &str, hosts: &[String]) -> Result<Option<(String, String)>, DbError> {
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

    pub async fn counter(&self, name: &str, period: &str) -> Result<i64, DbError> {
        Ok(sqlx::query_scalar("SELECT value FROM lib.counters WHERE name = $1 AND period = $2")
            .bind(name)
            .bind(period)
            .fetch_optional(&self.pool)
            .await?
            .unwrap_or(0))
    }

    // ── housekeeping ───────────────────────────────────────────────────────

    /// Deletes expired sessions, challenges, invites (90 days after expiry), audit entries older than `audit_keep`,
    /// and decided reports and appeals older than `cases_keep`. Returns the rows removed.
    pub async fn prune(&self, now: DateTime<Utc>, audit_keep: Duration, cases_keep: Duration) -> Result<u64, DbError> {
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
        n += sqlx::query("DELETE FROM lib.audit_log WHERE at < $1")
            .bind(now - audit_keep)
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

    pub async fn stats(&self, now: DateTime<Utc>) -> Result<Stats, DbError> {
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
        let mut c = self.pool.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock(7_301_516_041)").fetch_one(&mut *c).await?;
        Ok(got.then_some(c))
    }
}

async fn insert_account(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    n: &NewAccount<'_>,
    free: bool,
    invited_by: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<(), CreateError> {
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
