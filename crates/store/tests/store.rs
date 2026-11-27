//! The store against a real PostgreSQL over TLS (`scripts/test-postgres.sh start`, then `source <dir>/env.sh`). Each
//! test makes its own database. Without TEST_DATABASE_URL the tests skip (CI sets REQUIRE_TEST_DATABASE=1, so there they
//! fail instead).

use link_in_bio_store::config::{Access, DatabaseSettings};
use link_in_bio_store::{CreateError, Criteria, NewAccount, PeriodChange, Store, sha256};
use serde_json::json;
use time::{Duration, OffsetDateTime};

/// A store on a fresh, migrated database made for this test, or `None` (a logged skip) when no test database is configured; with `REQUIRE_TEST_DATABASE=1` a missing one is a failure.
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

/// A new-account request with the usual test values (a GB account on the 2026-11 terms and an empty page).
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

/// Accounts invites and handles.
#[tokio::test]
async fn accounts_invites_and_handles() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    // A plain sign-up is neither free nor invited.
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

/// Sign in material sessions and challenges.
#[tokio::test]
async fn sign_in_material_sessions_and_challenges() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    // A first sign-in method.
    s.add_passkey(a.id, &[7u8; 16], &json!({"cred": 1}), "Laptop").await.unwrap();
    assert_eq!(s.passkey_owner(&[7u8; 16]).await.unwrap().unwrap().0, a.id);
    assert!(!s.delete_passkey(a.id, &[7u8; 16]).await.unwrap(), "the last sign-in method stays");
    // A wallet address, as the sign-in stores it.
    let addr = format!("0x{}", "ab".repeat(32));
    assert!(s.add_wallet(a.id, &addr).await.unwrap());
    // A second account, which cannot link the same wallet.
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", None), now).await.unwrap();
    assert!(!s.add_wallet(b.id, &addr).await.unwrap(), "one account per wallet");
    assert!(s.delete_passkey(a.id, &[7u8; 16]).await.unwrap());
    assert_eq!(s.wallet_owner(&addr).await.unwrap(), Some(a.id));

    // Two recovery codes, stored as hashes.
    s.set_recovery_codes(a.id, &[sha256(b"r1"), sha256(b"r2")]).await.unwrap();
    assert_eq!(s.use_recovery_code("alice", &sha256(b"r1"), now).await.unwrap(), Some(a.id));
    assert_eq!(s.use_recovery_code("alice", &sha256(b"r1"), now).await.unwrap(), None);
    assert_eq!(s.use_recovery_code("bob", &sha256(b"r2"), now).await.unwrap(), None);
    assert_eq!(s.recovery_codes_left(a.id).await.unwrap(), 1);

    // A session, stored by the hash of its cookie value.
    let t = sha256(b"token");
    s.create_session(&t, a.id, now + Duration::hours(1)).await.unwrap();
    let idle = Duration::days(7);
    let abs = Duration::days(30);
    assert_eq!(s.session_account(&t, now, idle, abs).await.unwrap(), Some(a.id));
    assert_eq!(s.session_account(&t, now + Duration::days(31), idle, abs).await.unwrap(), None, "absolute limit");
    // Suspending an account ends its sessions.
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
    // A challenge of another kind is not taken.
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "passkey-login", now).await.unwrap().is_none());
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "wallet-login", now).await.unwrap().is_some());
    assert!(s.take_challenge("0123456789abcdef0123456789abcdef", "wallet-login", now).await.unwrap().is_none(), "once");
}

/// Pages versions views and screening.
#[tokio::test]
async fn pages_versions_views_and_screening() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    // A new page is not published.
    assert!(s.view_page("alice").await.unwrap().unwrap().published.is_none());
    // Three publishes make versions 2, 3 and 4 (the page starts at 1).
    for i in 0..3 {
        assert_eq!(s.publish(a.id, &format!(r#"{{"v":{i}}}"#), now).await.unwrap(), i + 2);
    }
    assert_eq!(s.page_versions(a.id).await.unwrap().len(), 3);
    // Keeping the newest two removes the oldest.
    assert_eq!(s.prune_versions(2).await.unwrap(), 1);
    assert_eq!(s.page_version(a.id, 4).await.unwrap().as_deref(), Some(r#"{"v":2}"#));
    let v = s.view_page("alice").await.unwrap().unwrap();
    assert_eq!(v.published.as_deref(), Some(r#"{"v":2}"#));
    assert_eq!(v.status, "active");

    // A suspension that has already ended is lifted by the worker's sweep.
    s.suspend(a.id, "legal", "court order", Some(now - Duration::seconds(1))).await.unwrap();
    assert_eq!(s.view_page("alice").await.unwrap().unwrap().suspension_kind.as_deref(), Some("legal"));
    assert_eq!(s.lift_expired_suspensions(now).await.unwrap(), vec![a.id]);
    assert_eq!(s.view_page("alice").await.unwrap().unwrap().status, "active");

    // A flagged link is visible to the page process by its hash only.
    let url = "https://bad.example/x";
    s.put_screen(url, "flagged", "webrisk", "SOCIAL_ENGINEERING", now + Duration::days(1), now).await.unwrap();
    let flagged = s.view_flagged(&[sha256(url.as_bytes()), sha256(b"https://ok.example/")]).await.unwrap();
    assert_eq!(flagged.len(), 1);
    // An operator's verdict holds against a later automatic one.
    s.override_screen(url, Some("clean"), "operator", now).await.unwrap();
    s.put_screen(url, "flagged", "webrisk", "again", now + Duration::days(1), now).await.unwrap();
    assert!(s.view_flagged(&[sha256(url.as_bytes())]).await.unwrap().is_empty(), "the operator's verdict holds");

    // The blocklist and the ThreatFox indicators are searched together.
    s.add_block("evil.example", "host", "phishing kit", "operator").await.unwrap();
    s.replace_iocs(&[("malware.example".into(), "host".into(), "botnet_cc".into())]).await.unwrap();
    let hosts = |h: &str| vec![h.to_string()];
    assert_eq!(s.blocked("https://evil.example/", &hosts("evil.example")).await.unwrap().unwrap().0, "blocklist");
    assert_eq!(s.blocked("https://malware.example/", &hosts("malware.example")).await.unwrap().unwrap().0, "threatfox");
    assert!(s.blocked("https://fine.example/", &hosts("fine.example")).await.unwrap().is_none());

    // A counter with a cap of three: two fit, a second two do not, and one more does.
    assert!(s.take_from_counter("webrisk", "2026-11", 2, 3).await.unwrap());
    assert!(!s.take_from_counter("webrisk", "2026-11", 2, 3).await.unwrap(), "the cap holds");
    assert!(s.take_from_counter("webrisk", "2026-11", 1, 3).await.unwrap());
    assert_eq!(s.counter("webrisk", "2026-11").await.unwrap(), 3);
}

/// Billing periods are idempotent.
#[tokio::test]
async fn billing_periods_are_idempotent() {
    let Some(s) = store().await else { return };
    let now = time::macros::datetime!(2026-11-16 12:00 UTC);
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
        checkout_id: None,
        refund_of: None,
    };
    // A purchase extends the period from now.
    let until = s.change_period(&change("s1", "purchase", 3), now).await.unwrap().unwrap();
    assert_eq!(until, now + link_in_bio_store::MONTH * 3);
    assert!(s.change_period(&change("s1", "purchase", 3), now).await.unwrap().is_none(), "applied once");
    // A grant extends it from the current end.
    let until2 = s.change_period(&change("g1", "grant", 1), now).await.unwrap().unwrap();
    assert_eq!(until2, until + link_in_bio_store::MONTH);
    // A refund larger than what is held stops at now.
    let until3 = s.change_period(&change("r1", "refund", -10), now).await.unwrap().unwrap();
    assert_eq!(until3, now, "a refund never ends the period in the past");
    assert_eq!(s.billing_events(a.id).await.unwrap().len(), 3);
    // Entitlement allows a grace period after the end.
    let acct = s.account(a.id).await.unwrap().unwrap();
    assert!(!acct.entitled(now + Duration::days(8), Duration::days(7)));
    assert!(acct.entitled(now + Duration::days(6), Duration::days(7)), "within the grace period");
}

/// Open payments grants are used once.
#[tokio::test]
async fn open_payments_grants_are_used_once() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
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
        fee_fixed_pence: None,
        fee_percent_bps: None,
    };
    // A checkout for the grant to belong to.
    s.create_checkout(&c).await.unwrap();
    assert!(s.open_payments_grant(c.id).await.unwrap().is_none());
    // A pending grant, which a second put replaces.
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 1})).await.unwrap());
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 2})).await.unwrap(), "replaced");
    assert_eq!(s.open_payments_grant(c.id).await.unwrap(), Some(("pending".into(), json!({"n": 2}))));
    // Taking it once moves it to finishing.
    assert_eq!(s.take_open_payments_grant(c.id).await.unwrap(), Some(json!({"n": 2})));
    assert!(s.take_open_payments_grant(c.id).await.unwrap().is_none(), "taken once");
    // A failed grant loses what was pending.
    s.finish_open_payments_grant(c.id, None, now).await.unwrap();
    assert_eq!(s.open_payments_grant(c.id).await.unwrap(), Some(("failed".into(), json!({}))), "pending removed");
    assert!(s.put_open_payments_grant(c.id, "https://wallet.example/bob", &json!({"n": 3})).await.unwrap(), "retry");
    s.take_open_payments_grant(c.id).await.unwrap();
    // A sent grant is final.
    s.finish_open_payments_grant(c.id, Some("https://wallet.example/rs/outgoing-payments/9"), now).await.unwrap();
    assert_eq!(s.open_payments_grant(c.id).await.unwrap().unwrap().0, "sent");
    assert!(!s.put_open_payments_grant(c.id, "https://wallet.example/eve", &json!({})).await.unwrap(), "sent is final");
}

/// Bank feed cursors.
#[tokio::test]
async fn bank_feed_cursors() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    assert!(s.bank_feed("bunq").await.unwrap().is_none());
    // A first failure creates the feed's row with no cursor.
    s.bank_feed_failed("bunq", "bunq answered HTTP 503", now).await.unwrap();
    let r = s.bank_feed("bunq").await.unwrap().unwrap();
    assert_eq!((r.cursor, r.last_error.as_deref(), r.credits_seen), (None, Some("bunq answered HTTP 503"), 0));
    // Two successful polls add up the credits seen.
    s.save_bank_feed("bunq", Some(r#"{"7":103}"#), &json!({"device": true}), 2, now).await.unwrap();
    s.save_bank_feed("bunq", Some(r#"{"7":104}"#), &json!({"device": true}), 1, now).await.unwrap();
    // A long error is cut to 500 characters.
    s.bank_feed_failed("bunq", &"x".repeat(900), now).await.unwrap();
    let r = s.bank_feed("bunq").await.unwrap().unwrap();
    assert_eq!(r.cursor.as_deref(), Some(r#"{"7":104}"#), "a failure keeps the cursor");
    assert_eq!((r.credits_seen, r.state, r.last_error.map(|e| e.len())), (3, json!({"device": true}), Some(500)));
    s.save_bank_feed("wise", Some("2026-11-17T00:00:00.000Z"), &json!({}), 0, now).await.unwrap();
    assert_eq!(s.bank_feeds().await.unwrap().iter().map(|r| r.feed.as_str()).collect::<Vec<_>>(), vec!["bunq", "wise"]);
}

/// Refund requests take months back once.
#[tokio::test]
async fn refund_requests_take_months_back_once() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let change = |event: &'static str, unapplied: bool| PeriodChange {
        account_id: a.id,
        provider: "chain-payments",
        provider_event: event,
        kind: "purchase",
        months: 3,
        amount_pence: 900,
        evidence: json!({ "unapplied": unapplied, "digest": "D2", "payer": "0x2" }),
        checkout: None,
        checkout_id: None,
        refund_of: None,
    };
    s.change_period(&change("paid:s1", false), now).await.unwrap().unwrap();
    // A late payment is credited like any other, and marked in its evidence.
    let credited = s.change_period(&change("unapplied:w1", true), now).await.unwrap().unwrap();
    let events = s.billing_events(a.id).await.unwrap();
    let late = events.iter().find(|e| e.unapplied).unwrap().clone();
    assert_eq!(events.iter().filter(|e| e.unapplied).count(), 1);
    let detail = s.billing_event(late.id).await.unwrap().unwrap();
    assert_eq!((detail.account_id, detail.months, detail.evidence["digest"].as_str()), (a.id, 3, Some("D2")));

    // A holder asks for the late payment back; a second ask about it is refused.
    let r = s.create_refund_request(late.id, a.id, "two tabs").await.unwrap().unwrap();
    assert!(s.create_refund_request(late.id, a.id, "again").await.unwrap().is_none(), "one request per event");
    let queue = s.refund_requests("open", 10).await.unwrap();
    assert_eq!((queue.len(), queue[0].handle.as_str(), queue[0].months), (1, "alice", Some(3)));
    assert_eq!(s.refund_requests_of(a.id).await.unwrap()[0].id, r);

    // The operator sends it and records the reference; the months come back.
    let done = s.record_refund(r, "9xRefundDigest", "operator:op-1", "", now).await.unwrap().unwrap();
    assert_eq!((done.account_id, done.months), (a.id, 3));
    assert_eq!(done.paid_until, credited - link_in_bio_store::MONTH * 3, "the three months taken back");
    assert!(s.record_refund(r, "other", "operator:op-1", "", now).await.unwrap().is_none(), "recorded once");
    let rr = s.refund_request(r).await.unwrap().unwrap();
    assert_eq!(
        (rr.status.as_str(), rr.refund_reference.as_deref(), rr.refund_event),
        ("refunded", Some("9xRefundDigest"), Some(done.event_id))
    );
    assert!(s.refund_requests("open", 10).await.unwrap().is_empty());
    let refund = s.billing_event(done.event_id).await.unwrap().unwrap();
    assert_eq!((refund.kind.as_str(), refund.months, refund.amount_pence), ("refund", -3, -900));
    assert_eq!(s.account(a.id).await.unwrap().unwrap().paid_until, Some(done.paid_until));
}

/// Selections reports appeals and housekeeping.
#[tokio::test]
async fn selections_reports_appeals_and_housekeeping() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a =
        s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now - Duration::days(40)).await.unwrap();
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", None), now).await.unwrap();
    s.publish(a.id, "{}", now).await.unwrap();
    s.set_flags(b.id, false, false, true, &["beta".into()]).await.unwrap();
    // A selection of accounts at least 30 days old with a published page.
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
    // A report about a page that does not exist is kept with its handle.
    s.create_report("nobody", None, "other", "", Some("me@example.org"), now).await.unwrap();
    // Two open reports, one older than a day.
    let st = s.stats(now).await.unwrap();
    assert_eq!((st.reports_open, st.reports_open_over_24h, st.accounts_active, st.pages_published), (2, 1, 2, 1));
    assert!(
        s.decide_report(r, "actioned", "operator", "link removed", Some("The link led to a fake shop."), now)
            .await
            .unwrap()
    );
    // A decided report cannot be decided again.
    assert!(!s.decide_report(r, "dismissed", "operator", "x", None, now).await.unwrap(), "decided once");
    assert_eq!(s.statements_for(a.id).await.unwrap().len(), 1);
    // The holder appeals; the decision returns the account to tell.
    let ap = s.create_appeal(a.id, Some(r), "The shop is real.").await.unwrap();
    assert_eq!(s.decide_appeal(ap, "rejected", "operator", "Checked again.", now).await.unwrap(), Some(a.id));

    // An audit entry for the account.
    s.audit("operator", "suspend", &a.id.to_string(), &json!({"kind": "policy"})).await.unwrap();
    assert_eq!(s.audit_log(Some(&a.id.to_string()), 10).await.unwrap().len(), 1);
    s.create_session(&sha256(b"old"), b.id, now - Duration::seconds(1)).await.unwrap();
    // Pruning removes at least the expired session.
    assert!(s.prune(now, Duration::days(730), Duration::days(730)).await.unwrap() >= 1);

    // Deleting an account erases its page and sign-in material but keeps the handle taken.
    assert!(s.delete_account(a.id, now).await.unwrap());
    let gone = s.account(a.id).await.unwrap().unwrap();
    assert_eq!(gone.status, "deleted");
    assert!(s.view_page("alice").await.unwrap().unwrap().published.is_none());
    assert!(!s.handle_available("alice", "allce").await.unwrap(), "a deleted handle is not reissued");
}

/// Two accounts can each use the same picture.
#[tokio::test]
async fn two_accounts_can_each_use_the_same_picture() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let b = s.create_account(&new("bob", "bob", "ref-bob-00000000001", None), now).await.unwrap();
    let pic = link_in_bio_store::AssetRow {
        sha256: "ab".repeat(32),
        mime: "image/png".into(),
        ext: "png".into(),
        width: 400,
        height: 400,
        bytes: vec![1, 2, 3],
    };
    s.put_asset(a.id, &pic).await.unwrap();
    s.put_asset(b.id, &pic).await.unwrap();
    s.put_asset(b.id, &pic).await.unwrap();
    assert!(s.owns_asset(a.id, &pic.sha256).await.unwrap());
    assert!(s.owns_asset(b.id, &pic.sha256).await.unwrap(), "the second account owns its own copy");
    assert_eq!(s.asset_bytes(b.id).await.unwrap(), 3, "counted once for each account");
    assert_eq!(s.view_asset(&pic.sha256).await.unwrap().unwrap().bytes, vec![1, 2, 3]);
    // Deleting one account leaves the other's copy.
    s.delete_account(a.id, now).await.unwrap();
    assert!(s.owns_asset(b.id, &pic.sha256).await.unwrap());
    assert!(s.view_asset(&pic.sha256).await.unwrap().is_some());
}

/// The months a refund gives back, as the billing crate computes them (pro rata, rounded down, all of them for the whole amount), written out here so the store's test does not depend on that crate.
fn months_refunded(months: u32, paid: u64, refunded: u64) -> u32 {
    if paid == 0 || refunded >= paid {
        months
    } else {
        (u128::from(months) * u128::from(refunded) / u128::from(paid)) as u32
    }
}

/// Refunds take months back pro rata and never more than bought.
#[tokio::test]
async fn refunds_take_months_back_pro_rata_and_never_more_than_bought() {
    let Some(s) = store().await else { return };
    let now = time::macros::datetime!(2026-11-18 12:00 UTC);
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let paid_checkout = |id: uuid::Uuid, status: &str| link_in_bio_store::Checkout {
        id,
        account_id: a.id,
        provider: "square".into(),
        provider_ref: format!("ORD-{}", id.simple()),
        method: "square:card".into(),
        months: 12,
        amount_pence: 3600,
        status: status.into(),
        country_declared: None,
        country_request: None,
        created_at: now,
        completed_at: None,
        fee_fixed_pence: None,
        fee_percent_bps: None,
    };
    let c = uuid::Uuid::new_v4();
    s.create_checkout(&paid_checkout(c, "open")).await.unwrap();
    s.change_period(
        &PeriodChange {
            account_id: a.id,
            provider: "square",
            provider_event: "paid:x",
            kind: "purchase",
            months: 12,
            amount_pence: 3600,
            evidence: json!({}),
            checkout: Some(c),
            checkout_id: None,
            refund_of: None,
        },
        now,
    )
    .await
    .unwrap();
    let refund = |event: &'static str, minor: u64| link_in_bio_store::RefundChange {
        account_id: a.id,
        provider: "square",
        provider_event: event,
        checkout: c,
        months: 12,
        paid_minor: 3600,
        refunded_minor: minor,
        amount_pence: 3600,
        evidence: json!({}),
    };
    let r1 = s.refund_purchase(&refund("refund:1", 1000), months_refunded, now).await.unwrap().unwrap();
    assert_eq!(r1.months_taken, 3, "1000 of 3600 is 3.33 months: 3");
    assert!(s.refund_purchase(&refund("refund:1", 1000), months_refunded, now).await.unwrap().is_none(), "once");
    let r2 = s.refund_purchase(&refund("refund:2", 2600), months_refunded, now).await.unwrap().unwrap();
    assert_eq!(r2.months_taken, 9, "together the whole amount: the other 9");
    let r3 = s.refund_purchase(&refund("refund:3", 100), months_refunded, now).await.unwrap().unwrap();
    assert_eq!(r3.months_taken, 0, "never more than the purchase bought");
    let events = s.billing_events(a.id).await.unwrap();
    let refunds: Vec<_> = events.iter().filter(|e| e.kind == "refund").collect();
    assert_eq!(refunds.iter().map(|e| -e.months).sum::<i32>(), 12);
    assert_eq!(refunds.iter().map(|e| -e.amount_pence).sum::<i64>(), 1000 + 2600 + 100);
    assert_eq!(s.account(a.id).await.unwrap().unwrap().paid_until, Some(now), "back to now, not before");

    // A checkout that was never paid gives nothing back.
    let open = uuid::Uuid::new_v4();
    s.create_checkout(&paid_checkout(open, "open")).await.unwrap();
    let r = s
        .refund_purchase(
            &link_in_bio_store::RefundChange { checkout: open, ..refund("refund:open", 3600) },
            months_refunded,
            now,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(r.months_taken, 0);
}

/// Refund lines take back exactly their months once.
#[tokio::test]
async fn refund_lines_take_back_exactly_their_months_once() {
    let Some(s) = store().await else { return };
    let now = time::macros::datetime!(2026-11-18 12:00 UTC);
    let a = s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let c = uuid::Uuid::new_v4();
    s.create_checkout(&link_in_bio_store::Checkout {
        id: c,
        account_id: a.id,
        provider: "square".into(),
        provider_ref: "ORD-L".into(),
        method: "square:card".into(),
        months: 12,
        amount_pence: 3600,
        status: "open".into(),
        country_declared: None,
        country_request: None,
        created_at: now,
        completed_at: None,
        fee_fixed_pence: None,
        fee_percent_bps: None,
    })
    .await
    .unwrap();
    let paid = |event: &'static str| PeriodChange {
        account_id: a.id,
        provider: "square",
        provider_event: event,
        kind: "purchase",
        months: 12,
        amount_pence: 3600,
        evidence: json!({ "paid": { "amountMinor": 3600, "currency": "GBP" } }),
        checkout: Some(c),
        checkout_id: None,
        refund_of: None,
    };
    s.change_period(&paid("paid:ORD-L"), now).await.unwrap().unwrap();
    let ext = s.extensions(a.id).await.unwrap();
    assert_eq!((ext.len(), ext[0].held, ext[0].checkout_id), (1, 12, Some(c)), "the purchase names its checkout");
    let purchase = ext[0].id;
    let line = |months: i32, amount: i64| link_in_bio_store::NewRefundLine {
        purchase_id: purchase,
        checkout_id: Some(c),
        provider: "square".into(),
        months,
        amount_minor: amount,
        unit: "GBP".into(),
        scale: Some(2),
        fee_minor: 13,
        charge_minor: 0,
        used_minor: 0,
        days_used: 0,
        amount_pence: amount,
        destination: json!({ "how": "Square" }),
    };
    let r = s
        .create_refund_request_lines(a.id, "unstarted", None, "", &json!({}), &[line(2, 587)], now)
        .await
        .unwrap()
        .unwrap();
    // One open request per account.
    assert_eq!(
        s.create_refund_request_lines(a.id, "unstarted", None, "", &json!({}), &[line(1, 293)], now).await.unwrap(),
        Err(link_in_bio_store::RefundConflict::OpenRequest)
    );
    let open = s.open_refund_line_for_checkout(c).await.unwrap().unwrap();
    assert_eq!((open.request_id, open.months, open.held), (r, 2, 12));
    // Refunded: exactly its two months, once.
    let done = s.refund_line(r, purchase, "sq-1", "operator:op", None, json!({}), now).await.unwrap().unwrap();
    assert_eq!((done.months_taken, done.request_closed), (2, true));
    assert_eq!(done.paid_until, Some(now + link_in_bio_store::MONTH * 10));
    assert!(s.refund_line(r, purchase, "sq-1", "operator:op", None, json!({}), now).await.unwrap().is_none());
    assert_eq!(s.refund_request(r).await.unwrap().unwrap().status, "refunded");
    assert_eq!(s.extensions(a.id).await.unwrap()[0].held, 10);
    assert!(s.open_refund_line_for_checkout(c).await.unwrap().is_none());
    // A provider's refund no request names counts what the line refunded: 587 + 1213 = 1800 of 3600 → 6 in all.
    let pro_rata = link_in_bio_store::RefundChange {
        account_id: a.id,
        provider: "square",
        provider_event: "refund:x",
        checkout: c,
        months: 12,
        paid_minor: 3600,
        refunded_minor: 1213,
        amount_pence: 3600,
        evidence: json!({}),
    };
    let r2 = s.refund_purchase(&pro_rata, months_refunded, now).await.unwrap().unwrap();
    assert_eq!(r2.months_taken, 4, "6 in all, 2 already taken");
    // Withdrawn by the account holder, or declined by the operator: nothing taken back.
    let w = s
        .create_refund_request_lines(a.id, "unstarted", None, "", &json!({}), &[line(1, 293)], now)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !s.close_refund_request(w, Some(uuid::Uuid::new_v4()), "withdrawn", "x", "", now).await.unwrap(),
        "not theirs"
    );
    assert!(s.close_refund_request(w, Some(a.id), "withdrawn", "account", "", now).await.unwrap());
    let d = s
        .create_refund_request_lines(a.id, "unstarted", None, "", &json!({}), &[line(1, 293)], now)
        .await
        .unwrap()
        .unwrap();
    assert!(s.close_refund_request(d, None, "declined", "operator", "duplicate", now).await.unwrap());
    assert!(!s.close_refund_request(d, None, "declined", "operator", "again", now).await.unwrap());
    assert_eq!(s.extensions(a.id).await.unwrap()[0].held, 6);
}

/// Counters are taken all or none and web risk lists are kept.
#[tokio::test]
async fn counters_are_taken_all_or_none_and_web_risk_lists_are_kept() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let t = |name: &str, by: i64, cap: i64| (name.to_string(), "2026-11-18T13".to_string(), by, cap);
    assert_eq!(s.take_from_counters(&[t("p:a", 1, 3), t("n:a", 4, 4)]).await.unwrap(), None);
    assert_eq!(s.take_from_counters(&[t("p:a", 1, 3), t("n:a", 1, 4)]).await.unwrap(), Some(1), "the second is full");
    assert_eq!(s.counter("p:a", "2026-11-18T13").await.unwrap(), 1, "and the first was not taken either");

    assert!(s.web_risk_list("MALWARE").await.unwrap().is_none());
    let list = link_in_bio_store::WebRiskList {
        threat_type: "MALWARE".into(),
        version_token: "v1".into(),
        entries: 2,
        prefixes: vec![4, 1, 2, 3, 4, 4, 5, 6, 7, 8],
        checksum: "c".into(),
        next_diff_at: Some(now + Duration::minutes(30)),
        updated_at: now,
        last_error: None,
    };
    s.put_web_risk_list(&list).await.unwrap();
    assert_eq!(s.web_risk_list("MALWARE").await.unwrap().unwrap().prefixes, list.prefixes);
    // A failed update keeps the prefixes and their time (nobody reloads), and asks for a full list next time.
    s.web_risk_list_failed("MALWARE", "checksum", now + Duration::hours(1), true).await.unwrap();
    let after = s.web_risk_list("MALWARE").await.unwrap().unwrap();
    assert_eq!(
        (after.prefixes, after.version_token.as_str(), after.last_error.as_deref()),
        (list.prefixes, "", Some("checksum"))
    );
    let states = s.web_risk_lists().await.unwrap();
    assert_eq!((states.len(), states[0].entries), (1, 2));
    // A first failure of a list never stored makes an empty row with nothing to load.
    s.web_risk_list_failed("UNWANTED_SOFTWARE", "down", now, false).await.unwrap();
    assert_eq!(s.web_risk_list("UNWANTED_SOFTWARE").await.unwrap().unwrap().entries, 0);
}

// ── Roles: the grants the database tier gives each process, set up here as the provisioner does ─────────────────

/// A fresh database with the schema, the superuser's URL for it, and a pool on it as `role` (password `pw`).
struct Roles {
    admin: sqlx::PgPool,
    url: String,
    created: Vec<String>,
}

impl Roles {
    /// A fresh database with the schema, and a handle to make roles on it; `None` (a logged skip) when no test database is configured.
    async fn new() -> Option<(Store, Roles)> {
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
            eprintln!("SKIPPED: no TEST_DATABASE_URL");
            return None;
        };
        let server = DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
        let name = format!("lib_roles_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(&server).await.unwrap();
        let db_url = url.replacen("/postgres?", &format!("/{name}?"), 1);
        let admin = DatabaseSettings::parse(&db_url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
        let s = Store::new(admin.clone());
        s.migrate().await.unwrap();
        Some((s, Roles { admin, url: db_url, created: Vec::new() }))
    }

    /// A login role with `grants` (statements with `{role}` for its name); returns a pool connected as it.
    async fn role(&mut self, kind: &str, grants: &[&str], access: Access) -> sqlx::PgPool {
        let role = format!("lib_test_{kind}_{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        let db: String = sqlx::query_scalar("SELECT current_database()").fetch_one(&self.admin).await.unwrap();
        let mut statements = vec![
            format!("CREATE ROLE {role} LOGIN PASSWORD 'pw'"),
            format!("REVOKE ALL ON DATABASE {db} FROM PUBLIC"),
            format!("GRANT CONNECT ON DATABASE {db} TO {role}"),
        ];
        statements.extend(grants.iter().map(|g| g.replace("{role}", &role)));
        for q in statements {
            sqlx::query(sqlx::AssertSqlSafe(q)).execute(&self.admin).await.unwrap();
        }
        self.created.push(role.clone());
        let at = self.url.find('@').unwrap();
        let url = format!("postgres://{role}:pw{}", &self.url[at..]);
        DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, access).unwrap()
    }

    /// Drop the roles this test made, ignoring any that are already gone.
    async fn drop_all(self) {
        for r in &self.created {
            for q in [format!("DROP OWNED BY {r}"), format!("DROP ROLE {r}")] {
                let _ = sqlx::query(sqlx::AssertSqlSafe(q)).execute(&self.admin).await;
            }
        }
    }
}

/// The writer grants of `services.conf` (`writer … schema=lib`) with `insert_only_tables=audit_log`.
const WRITER: &[&str] = &[
    "GRANT USAGE ON SCHEMA lib TO {role}",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA lib TO {role}",
    "REVOKE UPDATE, DELETE ON lib.audit_log FROM {role}",
    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA lib TO {role}",
    "GRANT USAGE ON SCHEMA public TO {role}",
];

/// The page server's read-only grants: the public views only, read-only by default.
const PAGES: &[&str] = &[
    "GRANT USAGE ON SCHEMA public TO {role}",
    "GRANT SELECT ON public.page_v1, public.asset_v1, public.domain_v1, public.flagged_link_v1 TO {role}",
    "ALTER ROLE {role} SET default_transaction_read_only = on",
];

/// Whether the database refused a statement for lack of privilege (42501) or because the session is read-only (25006).
async fn refused(pool: &sqlx::PgPool, q: &str) -> bool {
    match sqlx::query(sqlx::AssertSqlSafe(q.to_string())).execute(pool).await {
        Err(sqlx::Error::Database(e)) => {
            let code = e.code().unwrap_or_default().to_string();
            // 42501 insufficient privilege; 25006 read-only transaction.
            code == "42501" || code == "25006"
        }
        _ => false,
    }
}

/// The pages role reads only the public views and writes nothing.
#[tokio::test]
async fn the_pages_role_reads_only_the_public_views_and_writes_nothing() {
    let Some((s, mut roles)) = Roles::new().await else { return };
    let now = OffsetDateTime::now_utc();
    s.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    let pages = roles.role("pages", PAGES, Access::ReadOnly).await;
    let p = Store::new(pages.clone());
    assert!(p.view_page("alice").await.unwrap().is_some(), "the views are readable");
    for q in [
        "SELECT * FROM lib.sessions",
        "SELECT * FROM lib.accounts",
        "SELECT * FROM lib.billing_events",
        "SELECT * FROM lib.refund_lines",
        "SELECT * FROM lib.web_risk_lists",
        "INSERT INTO lib.audit_log (actor, action, subject) VALUES ('x', 'y', 'z')",
        "UPDATE lib.accounts SET free = true",
        "DELETE FROM lib.pages",
        "CREATE TABLE public.x (a int)",
        "CREATE TEMPORARY TABLE x (a int)",
    ] {
        assert!(refused(&pages, q).await, "the pages role must not: {q}");
    }
    pages.close().await;
    roles.drop_all().await;
}

/// A writer cannot rewrite the audit log or change the schema.
#[tokio::test]
async fn a_writer_cannot_rewrite_the_audit_log_or_change_the_schema() {
    let Some((s, mut roles)) = Roles::new().await else { return };
    let writer = roles.role("writer", WRITER, Access::ReadWrite).await;
    let w = Store::new(writer.clone());
    let now = OffsetDateTime::now_utc();
    let a = w.create_account(&new("alice", "allce", "ref-alice-000000001", None), now).await.unwrap();
    // It writes rows, and appends to the audit log.
    w.audit("test", "act", &a.id.to_string(), &json!({})).await.unwrap();
    assert!(w.audit_once("test", "once", "s", &json!({ "event": "e1" })).await.unwrap());
    assert!(!w.audit_once("test", "once", "s", &json!({ "event": "e1" })).await.unwrap());
    for q in [
        "UPDATE lib.audit_log SET action = 'forged'",
        "DELETE FROM lib.audit_log",
        "TRUNCATE lib.audit_log",
        "CREATE TABLE lib.x (a int)",
        "CREATE TABLE public.x (a int)",
        "ALTER TABLE lib.accounts ADD COLUMN x int",
        "DROP TABLE lib.sessions",
    ] {
        assert!(refused(&writer, q).await, "a writer must not: {q}");
    }
    // Retention still runs through the owner's function, which never removes anything younger than two years.
    sqlx::query("INSERT INTO lib.audit_log (at, actor, action, subject) VALUES (now() - interval '800 days', 'a', 'old', 's'), (now() - interval '1 day', 'a', 'new', 's')")
        .execute(&s.pool().clone())
        .await
        .unwrap();
    w.prune(now, Duration::days(0), Duration::days(730)).await.unwrap();
    let left: Vec<String> =
        sqlx::query_scalar("SELECT action FROM lib.audit_log ORDER BY action").fetch_all(s.pool()).await.unwrap();
    assert!(!left.contains(&"old".to_string()), "older than two years: pruned");
    assert!(left.contains(&"new".to_string()), "asked to prune everything, it still kept the last two years");
    writer.close().await;
    roles.drop_all().await;
}

/// A sign-in in progress works once, and a stale one is refused and still consumed.
#[tokio::test]
async fn an_admin_login_attempt_is_consumed_by_its_first_use() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let v = "v".repeat(43);
    s.begin_admin_login("state-hash-0123456789", "binding-hash-012345", "nonce-0123456789abcdef", &v, now)
        .await
        .unwrap();
    let first = s.take_admin_login("state-hash-0123456789", Duration::minutes(10), now).await.unwrap().expect("fresh");
    assert_eq!((first.binding_hash.as_str(), first.nonce.as_str()), ("binding-hash-012345", "nonce-0123456789abcdef"));
    assert!(
        s.take_admin_login("state-hash-0123456789", Duration::minutes(10), now).await.unwrap().is_none(),
        "works once"
    );
    assert!(s.take_admin_login("never-made-0123456789", Duration::minutes(10), now).await.unwrap().is_none());
    // Older than the limit: refused, and the row is gone afterwards.
    s.begin_admin_login(
        "state-old-0123456789a",
        "binding-hash-012345",
        "nonce-0123456789abcdef",
        &v,
        now - Duration::minutes(11),
    )
    .await
    .unwrap();
    assert!(s.take_admin_login("state-old-0123456789a", Duration::minutes(10), now).await.unwrap().is_none());
    assert!(
        s.take_admin_login("state-old-0123456789a", Duration::minutes(60), now).await.unwrap().is_none(),
        "consumed even though stale"
    );
}

/// A session lives inside both limits; the idle limit counts from the last use, the absolute limit from sign-in.
#[tokio::test]
async fn an_admin_session_lives_inside_its_idle_and_absolute_limits() {
    let Some(s) = store().await else { return };
    let t0 = OffsetDateTime::now_utc();
    let (idle, absolute) = (Duration::hours(1), Duration::hours(12));
    s.create_admin_session("session-hash-0123456", "sub-1", "sid-1", "meddler", "id.token.value", t0).await.unwrap();
    let seen = s
        .use_admin_session("session-hash-0123456", idle, absolute, t0 + Duration::minutes(5))
        .await
        .unwrap()
        .expect("found");
    assert_eq!(
        (seen.subject.as_str(), seen.display_name.as_str(), seen.id_token.as_str()),
        ("sub-1", "meddler", "id.token.value")
    );
    // Used at +5 min: idle for 59 minutes after that is fine, 61 is not.
    assert!(
        s.use_admin_session("session-hash-0123456", idle, absolute, t0 + Duration::minutes(64))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        s.use_admin_session("session-hash-0123456", idle, absolute, t0 + Duration::minutes(64) + Duration::minutes(61))
            .await
            .unwrap()
            .is_none(),
        "idle"
    );
    // A kept-alive session still ends at the absolute limit.
    s.create_admin_session("session-hash-abcdefg", "sub-2", "", "meddler", "tok", t0).await.unwrap();
    for h in 1..=11 {
        assert!(
            s.use_admin_session("session-hash-abcdefg", idle, absolute, t0 + Duration::minutes(50 * h))
                .await
                .unwrap()
                .is_some()
                || h > 14
        );
    }
    assert!(
        s.use_admin_session("session-hash-abcdefg", idle, absolute, t0 + Duration::hours(13)).await.unwrap().is_none(),
        "absolute"
    );
    assert!(s.use_admin_session("unknown-hash-0123456", idle, absolute, t0).await.unwrap().is_none());
}

/// Sign-out and both back-channel forms end the right sessions and no others; the purge removes the expired.
#[tokio::test]
async fn admin_sign_out_back_channel_logout_and_purge() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    for (hash, sub, sid) in [
        ("hash-a-0123456789012", "sub-1", "sid-a"),
        ("hash-b-0123456789012", "sub-1", "sid-b"),
        ("hash-c-0123456789012", "sub-2", "sid-c"),
        ("hash-d-0123456789012", "sub-3", ""),
    ] {
        s.create_admin_session(hash, sub, sid, "name", "tok", now).await.unwrap();
    }
    assert_eq!(s.end_admin_sessions_by_provider_session("sid-a").await.unwrap(), 1);
    assert_eq!(s.end_admin_sessions_by_provider_session("").await.unwrap(), 0, "an empty sid names no session");
    assert_eq!(s.end_admin_sessions_by_subject("sub-1").await.unwrap(), 1, "the rest of sub-1");
    assert!(s.end_admin_session("hash-c-0123456789012").await.unwrap().is_some());
    assert!(s.end_admin_session("hash-c-0123456789012").await.unwrap().is_none());
    // Only sub-3's session is left; it is purged once past the idle limit.
    s.begin_admin_login(
        "state-old-0123456789a",
        "binding-hash-012345",
        "nonce-0123456789abcdef",
        &"v".repeat(43),
        now - Duration::hours(1),
    )
    .await
    .unwrap();
    assert_eq!(
        s.purge_admin_sessions(Duration::minutes(10), Duration::hours(1), Duration::hours(12), now).await.unwrap(),
        1,
        "the stale sign-in only"
    );
    assert_eq!(
        s.purge_admin_sessions(
            Duration::minutes(10),
            Duration::hours(1),
            Duration::hours(12),
            now + Duration::hours(2)
        )
        .await
        .unwrap(),
        1,
        "then the idle session"
    );
}
