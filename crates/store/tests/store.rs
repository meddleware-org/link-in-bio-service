//! The store against a real PostgreSQL over TLS (`scripts/test-postgres.sh start`, then `source <dir>/env.sh`). Each
//! test makes its own database. Without TEST_DATABASE_URL the tests skip (CI sets REQUIRE_TEST_DATABASE=1, so there they
//! fail instead).

use chrono::{Duration, TimeZone, Utc};
use link_in_bio_store::config::{Access, DatabaseSettings};
use link_in_bio_store::{CreateError, Criteria, NewAccount, PeriodChange, Store, sha256};
use serde_json::json;

async fn store() -> Option<Store> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
        eprintln!("SKIPPED: no TEST_DATABASE_URL");
        return None;
    };
    let admin = DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
    let name = format!("lib_store_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&admin).await.unwrap();
    let pool = DatabaseSettings::parse(&url.replacen("/postgres?", &format!("/{name}?"), 1), false)
        .unwrap()
        .lazy_pool(4, Access::ReadWrite)
        .unwrap();
    let s = Store::new(pool);
    s.migrate().await.unwrap();
    Some(s)
}

fn new<'a>(handle: &'a str, skeleton: &'a str, billing_ref: &'a str, invite: Option<&'a [u8]>) -> NewAccount<'a> {
    NewAccount {
        id: uuid::Uuid::new_v4(),
        handle,
        handle_skeleton: skeleton,
        terms_version: "2026-11",
        country_declared: Some("GB"),
        billing_ref,
        operator: false,
        draft: r#"{"schema":1}"#,
        invite_hash: invite,
    }
}

#[tokio::test]
async fn accounts_invites_and_handles() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    assert!(!a.free && a.invited_by.is_none());
    assert!(matches!(
        s.create_account(&new("a1ice", "allce", "ref-alice-000000002", None), now).await,
        Err(CreateError::HandleTaken)
    ));
    assert!(!s.handle_available("alice", "x").await.unwrap());

    // An operator-issued code given to alice: one use, makes the redeemer free and records the invite tree.
    let code = sha256(b"code-one");
    s.create_invites(
        &[(code.clone(), "code-one".into())],
        Some(a.id),
        None,
        Some("for a friend"),
        "operator",
        now + Duration::days(30),
    )
    .await
    .unwrap();
    assert_eq!(s.held_codes(a.id, now).await.unwrap().0[0].0, "code-one", "the holder can read it to pass it on");
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", Some(&code)), now).await.unwrap();
    assert!(b.free);
    assert_eq!(b.invited_by, Some(a.id));
    assert!(matches!(
        s.create_account(&new("carol", "carol", "ref-carol-000000001", Some(&code)), now).await,
        Err(CreateError::InviteInvalid)
    ));
    assert_eq!(s.invitees(a.id).await.unwrap().len(), 1);
    let (left, used) = s.held_codes(a.id, now).await.unwrap();
    assert!(left.is_empty(), "a redeemed code is no longer readable");
    assert_eq!(used, 1);

    // A holder whose right to pass on invites was revoked: their remaining codes stop working.
    let code2 = sha256(b"code-two");
    let ids = s
        .create_invites(
            &[(code2.clone(), "code-two".into())],
            Some(a.id),
            None,
            None,
            "operator",
            now + Duration::days(30),
        )
        .await
        .unwrap();
    s.set_flags(a.id, false, false, false, &[]).await.unwrap();
    assert!(matches!(
        s.create_account(&new("dave", "dave", "ref-dave-0000000001", Some(&code2)), now).await,
        Err(CreateError::InviteInvalid)
    ));
    assert!(s.revoke_invite(ids[0], now).await.unwrap());
    assert!(!s.revoke_invite(ids[0], now).await.unwrap());
    // Expired codes fail too.
    let code3 = sha256(b"code-three");
    s.create_invites(&[(code3.clone(), "code-three".into())], None, None, None, "operator", now - Duration::seconds(1))
        .await
        .unwrap();
    assert!(matches!(
        s.create_account(&new("erin", "erln", "ref-erin-0000000001", Some(&code3)), now).await,
        Err(CreateError::InviteInvalid)
    ));
}

#[tokio::test]
async fn sign_in_material_sessions_and_challenges() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    s.add_passkey(a.id, &[7u8; 16], &json!({"cred": 1}), "Laptop").await.unwrap();
    assert_eq!(s.passkey_owner(&[7u8; 16]).await.unwrap().unwrap().0, a.id);
    assert!(!s.delete_passkey(a.id, &[7u8; 16]).await.unwrap(), "the last sign-in method stays");
    let addr = format!("0x{}", "ab".repeat(32));
    assert!(s.add_wallet(a.id, &addr).await.unwrap());
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", None), now).await.unwrap();
    assert!(!s.add_wallet(b.id, &addr).await.unwrap(), "one account per wallet");
    assert!(s.delete_passkey(a.id, &[7u8; 16]).await.unwrap());
    assert_eq!(s.wallet_owner(&addr).await.unwrap(), Some(a.id));

    s.set_recovery_codes(a.id, &[sha256(b"r1"), sha256(b"r2")]).await.unwrap();
    assert_eq!(s.use_recovery_code("alice", &sha256(b"r1"), now).await.unwrap(), Some(a.id));
    assert_eq!(s.use_recovery_code("alice", &sha256(b"r1"), now).await.unwrap(), None);
    assert_eq!(s.use_recovery_code("bob", &sha256(b"r2"), now).await.unwrap(), None);
    assert_eq!(s.recovery_codes_left(a.id).await.unwrap(), 1);

    let t = sha256(b"token");
    s.create_session(&t, a.id, now + Duration::hours(1)).await.unwrap();
    let idle = Duration::days(7);
    let abs = Duration::days(30);
    assert_eq!(s.session_account(&t, now, idle, abs).await.unwrap(), Some(a.id));
    assert_eq!(s.session_account(&t, now + Duration::days(31), idle, abs).await.unwrap(), None, "absolute limit");
    s.suspend(a.id, "policy", "spam", None).await.unwrap();
    assert_eq!(s.session_account(&t, now, idle, abs).await.unwrap(), None, "suspension ends sessions");

    s.put_challenge(
        "0123456789abcdef0123456789abcdef",
        "wallet-login",
        None,
        &json!({"n": 1}),
        now + Duration::minutes(5),
    )
    .await
    .unwrap();
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "passkey-login", now).await.unwrap().is_none());
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "wallet-login", now).await.unwrap().is_some());
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "wallet-login", now).await.unwrap().is_none(), "once");
}

#[tokio::test]
async fn pages_versions_views_and_screening() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    assert!(s.view_page("alice").await.unwrap().unwrap().published.is_none());
    for i in 0..3 {
        assert_eq!(s.publish(a.id, &format!(r#"{{"v":{i}}}"#), now).await.unwrap(), i + 2);
    }
    assert_eq!(s.page_versions(a.id).await.unwrap().len(), 3);
    assert_eq!(s.prune_versions(2).await.unwrap(), 1);
    assert_eq!(s.page_version(a.id, 4).await.unwrap().as_deref(), Some(r#"{"v":2}"#));
    let v = s.view_page("alice").await.unwrap().unwrap();
    assert_eq!(v.published.as_deref(), Some(r#"{"v":2}"#));
    assert_eq!(v.status, "active");

    s.suspend(a.id, "legal", "court order", Some(now - Duration::seconds(1))).await.unwrap();
    assert_eq!(s.view_page("alice").await.unwrap().unwrap().suspension_kind.as_deref(), Some("legal"));
    assert_eq!(s.lift_expired_suspensions(now).await.unwrap(), vec![a.id]);
    assert_eq!(s.view_page("alice").await.unwrap().unwrap().status, "active");

    let url = "https://bad.example/x";
    s.put_screen(url, "flagged", "webrisk", "SOCIAL_ENGINEERING", now + Duration::days(1), now).await.unwrap();
    let flagged = s.view_flagged(&[sha256(url.as_bytes()), sha256(b"https://ok.example/")]).await.unwrap();
    assert_eq!(flagged.len(), 1);
    s.override_screen(url, Some("clean"), "operator", now).await.unwrap();
    s.put_screen(url, "flagged", "webrisk", "again", now + Duration::days(1), now).await.unwrap();
    assert!(s.view_flagged(&[sha256(url.as_bytes())]).await.unwrap().is_empty(), "the operator's verdict holds");

    s.add_block("evil.example", "host", "phishing kit", "operator").await.unwrap();
    s.replace_iocs(&[("malware.example".into(), "host".into(), "botnet_cc".into())]).await.unwrap();
    let hosts = |h: &str| vec![h.to_string()];
    assert_eq!(s.blocked("https://evil.example/", &hosts("evil.example")).await.unwrap().unwrap().0, "blocklist");
    assert_eq!(s.blocked("https://malware.example/", &hosts("malware.example")).await.unwrap().unwrap().0, "threatfox");
    assert!(s.blocked("https://fine.example/", &hosts("fine.example")).await.unwrap().is_none());

    assert!(s.take_from_counter("webrisk", "2026-11", 2, 3).await.unwrap());
    assert!(!s.take_from_counter("webrisk", "2026-11", 2, 3).await.unwrap(), "the cap holds");
    assert!(s.take_from_counter("webrisk", "2026-11", 1, 3).await.unwrap());
    assert_eq!(s.counter("webrisk", "2026-11").await.unwrap(), 3);
}

#[tokio::test]
async fn billing_periods_are_idempotent() {
    let Some(s) = store().await else { return };
    let now = Utc.with_ymd_and_hms(2026, 11, 16, 12, 0, 0).unwrap();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let change = |event: &'static str, kind: &'static str, months: i32| PeriodChange {
        account_id: a.id,
        provider: "chain-payments",
        provider_event: event,
        kind,
        months,
        amount_pence: 300 * i64::from(months.abs()),
        evidence: json!({"country": "GB"}),
        checkout: None,
    };
    let until = s.change_period(&change("s1", "purchase", 3), now).await.unwrap().unwrap();
    assert_eq!(until, now + link_in_bio_store::MONTH * 3);
    assert!(s.change_period(&change("s1", "purchase", 3), now).await.unwrap().is_none(), "applied once");
    let until2 = s.change_period(&change("g1", "grant", 1), now).await.unwrap().unwrap();
    assert_eq!(until2, until + link_in_bio_store::MONTH);
    let until3 = s.change_period(&change("r1", "refund", -10), now).await.unwrap().unwrap();
    assert_eq!(until3, now, "a refund never ends the period in the past");
    assert_eq!(s.billing_events(a.id).await.unwrap().len(), 3);
    let acct = s.account(a.id).await.unwrap().unwrap();
    assert!(!acct.entitled(now + Duration::days(8), Duration::days(7)));
    assert!(acct.entitled(now + Duration::days(6), Duration::days(7)), "within the grace period");
}

#[tokio::test]
async fn open_payments_grants_are_used_once() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let c = link_in_bio_store::Checkout {
        id: uuid::Uuid::new_v4(),
        account_id: a.id,
        provider: "open-payments".into(),
        provider_ref: "https://wallet.example/rs/incoming-payments/1".into(),
        method: "open-payments:wallet".into(),
        months: 1,
        amount_pence: 300,
        status: "open".into(),
        country_declared: Some("GB".into()),
        country_request: Some("GB".into()),
        created_at: now,
        completed_at: None,
    };
    s.create_checkout(&c).await.unwrap();
    assert!(s.open_payments_grant(c.id).await.unwrap().is_none());
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 1})).await.unwrap());
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 2})).await.unwrap(), "replaced");
    assert_eq!(s.open_payments_grant(c.id).await.unwrap(), Some(("pending".into(), json!({"n": 2}))));
    assert_eq!(s.take_open_payments_grant(c.id).await.unwrap(), Some(json!({"n": 2})));
    assert!(s.take_open_payments_grant(c.id).await.unwrap().is_none(), "taken once");
    s.finish_open_payments_grant(c.id, None, now).await.unwrap();
    assert_eq!(s.open_payments_grant(c.id).await.unwrap(), Some(("failed".into(), json!({}))), "pending removed");
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 3})).await.unwrap(), "retry");
    s.take_open_payments_grant(c.id).await.unwrap();
    s.finish_open_payments_grant(c.id, Some("https://wallet.example/rs/outgoing-payments/9"), now).await.unwrap();
    assert_eq!(s.open_payments_grant(c.id).await.unwrap().unwrap().0, "sent");
    assert!(!s.put_open_payments_grant(c.id, "https://wallet.example/eve", &json!({})).await.unwrap(), "sent is final");
}

#[tokio::test]
async fn bank_feed_cursors() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    assert!(s.bank_feed("bunq").await.unwrap().is_none());
    s.bank_feed_failed("bunq", "bunq answered HTTP 503", now).await.unwrap();
    let r = s.bank_feed("bunq").await.unwrap().unwrap();
    assert_eq!((r.cursor, r.last_error.as_deref(), r.credits_seen), (None, Some("bunq answered HTTP 503"), 0));
    s.save_bank_feed("bunq", Some(r#"{"7":103}"#), &json!({"device": true}), 2, now).await.unwrap();
    s.save_bank_feed("bunq", Some(r#"{"7":104}"#), &json!({"device": true}), 1, now).await.unwrap();
    s.bank_feed_failed("bunq", &"x".repeat(900), now).await.unwrap();
    let r = s.bank_feed("bunq").await.unwrap().unwrap();
    assert_eq!(r.cursor.as_deref(), Some(r#"{"7":104}"#), "a failure keeps the cursor");
    assert_eq!((r.credits_seen, r.state, r.last_error.map(|e| e.len())), (3, json!({"device": true}), Some(500)));
    s.save_bank_feed("wise", Some("2026-11-17T00:00:00.000Z"), &json!({}), 0, now).await.unwrap();
    assert_eq!(s.bank_feeds().await.unwrap().iter().map(|r| r.feed.as_str()).collect::<Vec<_>>(), vec!["bunq", "wise"]);
}

#[tokio::test]
async fn selections_reports_appeals_and_housekeeping() {
    let Some(s) = store().await else { return };
    let now = Utc::now();
    let a =
        s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now - Duration::days(40)).await.unwrap();
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", None), now).await.unwrap();
    s.publish(a.id, "{}", now).await.unwrap();
    s.set_flags(b.id, false, false, true, &["beta".into()]).await.unwrap();
    let old_published = Criteria { min_age_days: Some(30), published: Some(true), ..Default::default() };
    assert_eq!(
        s.match_selection(&old_published, now).await.unwrap().iter().map(|x| x.id).collect::<Vec<_>>(),
        vec![a.id]
    );
    let tagged = Criteria { tag: Some("beta".into()), ..Default::default() };
    assert_eq!(s.match_selection(&tagged, now).await.unwrap()[0].id, b.id);
    let sel = s.create_selection("Old publishers", &old_published, "operator").await.unwrap();
    assert_eq!(s.selections().await.unwrap()[0].id, sel);

    let r = s
        .create_report("alice", Some("https://x.example/"), "fraud", "fake shop", None, now - Duration::hours(25))
        .await
        .unwrap();
    s.create_report("nobody", None, "other", "", Some("me@example.org"), now).await.unwrap();
    let st = s.stats(now).await.unwrap();
    assert_eq!((st.reports_open, st.reports_open_over_24h, st.accounts_active, st.pages_published), (2, 1, 2, 1));
    assert!(
        s.decide_report(r, "actioned", "operator", "link removed", Some("The link led to a fake shop."), now)
            .await
            .unwrap()
    );
    assert!(!s.decide_report(r, "dismissed", "operator", "x", None, now).await.unwrap(), "decided once");
    assert_eq!(s.statements_for(a.id).await.unwrap().len(), 1);
    let ap = s.create_appeal(a.id, Some(r), "The shop is real.").await.unwrap();
    assert_eq!(s.decide_appeal(ap, "rejected", "operator", "Checked again.", now).await.unwrap(), Some(a.id));

    s.audit("operator", "suspend", &a.id.to_string(), &json!({"kind": "policy"})).await.unwrap();
    assert_eq!(s.audit_log(Some(&a.id.to_string()), 10).await.unwrap().len(), 1);
    s.create_session(&sha256(b"old"), b.id, now - Duration::seconds(1)).await.unwrap();
    assert!(s.prune(now, Duration::days(730), Duration::days(730)).await.unwrap() >= 1);

    assert!(s.delete_account(a.id, now).await.unwrap());
    let gone = s.account(a.id).await.unwrap().unwrap();
    assert_eq!(gone.status, "deleted");
    assert!(s.view_page("alice").await.unwrap().unwrap().published.is_none());
    assert!(!s.handle_available("alice", "allce").await.unwrap(), "a deleted handle is not reissued");
}
