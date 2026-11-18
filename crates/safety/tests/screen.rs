//! The screening layers against a real PostgreSQL and an in-process stand-in for Web Risk's Update API: the order of
//! the layers, the lists kept by the worker and checked locally, confirmations under their monthly cap, and what
//! happens when Web Risk is down or a diff does not match its checksum.

use axum::Router;
use axum::extract::Query;
use axum::routing::get;
use link_in_bio_safety::{Screener, UpdateOutcome, Verdict, WebRiskLookup, WebRiskUpdate, period};
use link_in_bio_store::Store;
use link_in_bio_store::config::{Access, DatabaseSettings};
use serde_json::json;
use std::collections::HashMap;
use time::OffsetDateTime;

async fn store() -> Option<Store> {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        assert!(std::env::var("REQUIRE_TEST_DATABASE").as_deref() != Ok("1"), "TEST_DATABASE_URL is required");
        eprintln!("SKIPPED: no TEST_DATABASE_URL");
        return None;
    };
    let admin = DatabaseSettings::parse(&url, false).unwrap().lazy_pool(2, Access::ReadWrite).unwrap();
    let name = format!("lib_safety_{}", uuid_like());
    sqlx_create(&admin, &name).await;
    let pool = DatabaseSettings::parse(&url.replacen("/postgres?", &format!("/{name}?"), 1), false)
        .unwrap()
        .lazy_pool(4, Access::ReadWrite)
        .unwrap();
    let s = Store::new(pool);
    s.migrate().await.unwrap();
    Some(s)
}

fn uuid_like() -> String {
    format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos())
}

async fn sqlx_create(pool: &sqlx::PgPool, name: &str) {
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}"))).execute(pool).await.unwrap();
}

fn prefix(expression: &str) -> Vec<u8> {
    sha2_256(expression.as_bytes())[..4].to_vec()
}

fn sha2_256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Web Risk Update API stand-in. MALWARE holds the prefixes of `phish.example/login`, `down.example/` and
/// `collide.example/`; the other lists are empty. `hashes:search` knows `phish.example/login` as SOCIAL_ENGINEERING,
/// answers 503 for `down.example/`'s prefix, and nothing else. A version token `v1` gets a diff with a wrong checksum.
async fn web_risk() -> String {
    let app = Router::new()
        .route(
            "/v1/threatLists:computeDiff",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                if q.get("key").map(String::as_str) != Some("test-key")
                    || q.get("constraints.supportedCompressions").map(String::as_str) != Some("RAW")
                {
                    return (axum::http::StatusCode::FORBIDDEN, axum::Json(json!({})));
                }
                let mut prefixes: Vec<Vec<u8>> = if q.get("threatType").map(String::as_str) == Some("MALWARE") {
                    vec![prefix("phish.example/login"), prefix("down.example/"), prefix("collide.example/")]
                } else {
                    Vec::new()
                };
                prefixes.sort();
                let raw: Vec<u8> = prefixes.concat();
                let body = if q.get("versionToken").map(String::as_str) == Some("v1") {
                    json!({ "responseType": "DIFF", "newVersionToken": "v2", "additions": { "rawHashes": [] },
                            "removals": { "rawIndices": { "indices": [0] } }, "checksum": { "sha256": b64(&[0u8; 32]) } })
                } else {
                    json!({
                        "responseType": "RESET", "newVersionToken": "v1",
                        "additions": { "rawHashes": [{ "prefixSize": 4, "rawHashes": b64(&raw) }] },
                        "checksum": { "sha256": b64(&sha2_256(&raw)) },
                        "recommendedNextDiff": "2000-01-01T00:00:00Z",
                    })
                };
                (axum::http::StatusCode::OK, axum::Json(body))
            }),
        )
        .route(
            "/v1/hashes:search",
            get(|Query(q): Query<HashMap<String, String>>| async move {
                use base64::Engine;
                let asked = base64::engine::general_purpose::URL_SAFE.decode(q.get("hashPrefix").cloned().unwrap_or_default()).unwrap_or_default();
                if asked == prefix("down.example/") {
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({})));
                }
                let mut threats = Vec::new();
                if asked == prefix("phish.example/login") {
                    threats.push(json!({ "threatTypes": ["SOCIAL_ENGINEERING"], "hash": b64(&sha2_256(b"phish.example/login")),
                                         "expireTime": "2099-01-01T00:00:00Z" }));
                }
                (axum::http::StatusCode::OK, axum::Json(json!({ "threats": threats, "negativeExpireTime": "2099-01-01T00:00:00Z" })))
            }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}/v1")
}

#[tokio::test]
async fn layers_lists_caps_and_outage() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    // Ten calls a month in all, two of them confirmations.
    let mut w = WebRiskUpdate::new("test-key".into(), 10, 2, 1024);
    w.api.base = web_risk().await;
    let screener = Screener { lookup: None, update: Some(w) };
    let w = screener.update.as_ref().unwrap();

    // Layer 1 and the blocklist answer without Web Risk.
    assert!(matches!(screener.screen(&s, "https://bit.ly/x", now).await, Verdict::Flagged { .. }));
    s.add_block("blocked.example", "host", "known scam", "operator").await.unwrap();
    assert!(
        matches!(screener.screen(&s, "https://www.blocked.example/", now).await, Verdict::Flagged { source, .. } if source == "blocklist")
    );
    // No list yet: unknown (shown, checked again within the hour), and nothing asked of Google.
    assert!(
        matches!(screener.screen(&s, "https://fine.example/", now).await, Verdict::Unknown { reason } if reason.contains("not loaded"))
    );
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 0);

    // The worker's update: a full list per threat type (three calls), stored and loaded.
    for t in link_in_bio_safety::webrisk::THREAT_TYPES {
        let r = link_in_bio_safety::update_list(w, &s, t, now, time::Duration::minutes(15)).await.unwrap();
        assert!(matches!(r, UpdateOutcome::Updated(_)), "{t}: {r:?}");
    }
    assert_eq!(s.web_risk_list("MALWARE").await.unwrap().unwrap().entries, 3);
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 3);
    w.refresh(&s, true).await.unwrap();
    assert_eq!(w.entries(), 3);

    // Checked locally: no call for a link that matches nothing.
    assert_eq!(screener.screen(&s, "https://fine.example/", now).await, Verdict::Clean { source: "webrisk" });
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 3);
    // A match is confirmed once (its prefix only goes to Google), then served from the cache.
    let v = screener.screen_and_record(&s, "https://phish.example/login", now).await.unwrap();
    assert!(matches!(&v, Verdict::Flagged { detail, .. } if detail == "SOCIAL_ENGINEERING"), "{v:?}");
    assert_eq!(s.view_flagged(&[link_in_bio_store::sha256(b"https://phish.example/login")]).await.unwrap().len(), 1);
    assert!(matches!(screener.screen(&s, "https://phish.example/login", now).await, Verdict::Flagged { .. }));
    assert_eq!(s.counter("webrisk-confirm", &period(now)).await.unwrap(), 1);
    // An outage while confirming is "unknown": shown, and checked again within the hour.
    let v = screener.screen_and_record(&s, "https://down.example/", now).await.unwrap();
    assert!(matches!(v, Verdict::Unknown { .. }));
    let due = s.screens_due(now + time::Duration::minutes(61), 10).await.unwrap();
    assert!(due.iter().any(|d| d.url == "https://down.example/"));
    // Two confirmations spent: a third match cannot be confirmed, so it is hidden pending review and checked daily.
    let v = screener.screen(&s, "https://collide.example/", now).await;
    assert!(matches!(&v, Verdict::Flagged { source, .. } if source == link_in_bio_safety::UNCONFIRMED), "{v:?}");
    assert_eq!(v.next_check(now), now + link_in_bio_safety::RESCAN_CLEAN);
    assert_eq!(s.counter("webrisk-confirm", &period(now)).await.unwrap(), 2, "the cap held");
    // mailto links are checked against the lists only.
    assert_eq!(screener.screen(&s, "mailto:me@fine.example", now).await, Verdict::Clean { source: "lists" });

    // A diff whose checksum does not match is discarded: the list stays, and the next update asks for all of it.
    let later = now + time::Duration::days(1);
    let r = link_in_bio_safety::update_list(w, &s, "MALWARE", later, time::Duration::minutes(15)).await.unwrap();
    assert!(matches!(&r, UpdateOutcome::Failed(e) if e.contains("checksum")), "{r:?}");
    let l = s.web_risk_list("MALWARE").await.unwrap().unwrap();
    assert_eq!((l.entries, l.version_token.as_str()), (3, ""), "kept, and a full list next time");
}

/// Lookup API stand-in that counts what each endpoint is asked: `phish.example` is SOCIAL_ENGINEERING, `down.example`
/// answers 503, anything else is clean. `computeDiff` and `hashes.search` are counted so a test can show they are never
/// called in lookup mode.
async fn lookup_stand_in() -> (String, std::sync::Arc<[std::sync::atomic::AtomicUsize; 3]>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = std::sync::Arc::new([AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)]);
    let (h0, h1, h2) = (hits.clone(), hits.clone(), hits.clone());
    let app = Router::new()
        .route(
            "/v1/uris:search",
            get(move |Query(q): Query<HashMap<String, String>>| {
                let h = h0.clone();
                async move {
                    h[0].fetch_add(1, Ordering::SeqCst);
                    let uri = q.get("uri").cloned().unwrap_or_default();
                    if uri.contains("down.example") {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({})));
                    }
                    let body = if uri.contains("phish.example") {
                        json!({ "threat": { "threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": "2099-01-01T00:00:00Z" } })
                    } else {
                        json!({})
                    };
                    (axum::http::StatusCode::OK, axum::Json(body))
                }
            }),
        )
        .route(
            "/v1/threatLists:computeDiff",
            get(move || {
                let h = h1.clone();
                async move {
                    h[1].fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({}))
                }
            }),
        )
        .route(
            "/v1/hashes:search",
            get(move || {
                let h = h2.clone();
                async move {
                    h[2].fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({}))
                }
            }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (format!("http://{addr}/v1"), hits)
}

#[tokio::test]
async fn lookup_mode_keeps_a_reserve_for_publishes_and_stops_at_the_paid_allowance() {
    use std::sync::atomic::Ordering;
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let (base, hits) = lookup_stand_in().await;
    // A free allowance of 10 and 2 paid calls: a hard stop at 12; rechecks stop at 80 % of it, 9.
    let mut l = WebRiskLookup::new("test-key".into(), 10, 2);
    l.endpoint = format!("{base}/uris:search");
    assert_eq!((l.allowance(), l.recheck_stop()), (12, 9));
    let screener = Screener { lookup: Some(l), update: None };
    assert_eq!(screener.mode(), Some("lookup"));

    // Publish time: one call per link.
    let v = screener.screen_and_record(&s, "https://phish.example/login", now).await.unwrap();
    assert!(matches!(&v, Verdict::Flagged { detail, .. } if detail == "SOCIAL_ENGINEERING"));
    assert_eq!(screener.screen(&s, "https://fine.example/", now).await, Verdict::Clean { source: "webrisk" });
    // A clean verdict holds a week in this mode (each check is a call).
    assert_eq!(screener.next_check(&Verdict::Clean { source: "webrisk" }, now), now + time::Duration::days(7));
    // An outage is unknown: shown, checked again within the hour.
    assert!(matches!(screener.screen(&s, "https://down.example/", now).await, Verdict::Unknown { .. }));
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 3);

    // The worker's rechecks run up to 9 calls, then stop without changing anything: the rest is for publishes.
    let mut rechecked = 0;
    while let Some(v) = screener.recheck(&s, "https://fine.example/", now).await.unwrap() {
        assert_eq!(v, Verdict::Clean { source: "webrisk" });
        rechecked += 1;
        assert!(rechecked < 20, "rechecks must stop");
    }
    assert_eq!((rechecked, s.counter("webrisk", &period(now)).await.unwrap()), (6, 9));
    // Publishes go on to the hard stop (the free allowance, then the paid calls), then a link is unknown and shown.
    for _ in 0..3 {
        assert_eq!(screener.screen(&s, "https://new.example/", now).await, Verdict::Clean { source: "webrisk" });
    }
    let v = screener.screen(&s, "https://later.example/", now).await;
    assert!(matches!(&v, Verdict::Unknown { reason } if reason.contains("allowance")), "{v:?}");
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 12, "never past the hard stop");
    // Lookup mode never asks for a list or a full hash (one computeDiff would reprice every lookup of the month).
    assert_eq!(hits[0].load(Ordering::SeqCst), 12);
    assert_eq!((hits[1].load(Ordering::SeqCst), hits[2].load(Ordering::SeqCst)), (0, 0));
}
