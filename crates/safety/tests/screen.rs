//! The screening layers against a real PostgreSQL and an in-process stand-in for Web Risk: the order of the layers,
//! the monthly cap, and what happens when Web Risk is down.

use axum::Router;
use axum::extract::Query;
use axum::routing::get;
use link_in_bio_safety::{Screener, Verdict, WebRisk, period};
use link_in_bio_store::Store;
use link_in_bio_store::config::{Access, DatabaseSettings};
use serde_json::{Value, json};
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

/// Web Risk stand-in: `phish.example` is SOCIAL_ENGINEERING; `down.example` answers 503; anything else is clean.
async fn web_risk() -> String {
    let app = Router::new().route(
        "/v1/uris:search",
        get(|Query(q): Query<HashMap<String, String>>| async move {
            let uri = q.get("uri").cloned().unwrap_or_default();
            if q.get("key").map(String::as_str) != Some("test-key") {
                return (axum::http::StatusCode::FORBIDDEN, axum::Json(json!({})));
            }
            if uri.contains("down.example") {
                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::Json(json!({})));
            }
            let body: Value = if uri.contains("phish.example") {
                json!({"threat": {"threatTypes": ["SOCIAL_ENGINEERING"], "expireTime": "2026-12-01T00:00:00Z"}})
            } else {
                json!({})
            };
            (axum::http::StatusCode::OK, axum::Json(body))
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}/v1/uris:search")
}

#[tokio::test]
async fn layers_cap_and_outage() {
    let Some(s) = store().await else { return };
    let now = OffsetDateTime::now_utc();
    let mut w = WebRisk::new("test-key".into(), 3);
    w.endpoint = web_risk().await;
    let screener = Screener { web_risk: Some(w) };

    // Layer 1 answers without spending a Web Risk call.
    assert!(matches!(screener.screen(&s, "https://bit.ly/x", now).await, Verdict::Flagged { .. }));
    // Layer 2: the blocklist (a parent domain matches).
    s.add_block("blocked.example", "host", "known scam", "operator").await.unwrap();
    assert!(
        matches!(screener.screen(&s, "https://www.blocked.example/", now).await, Verdict::Flagged { source, .. } if source == "blocklist")
    );
    assert_eq!(s.counter("webrisk", &period(now)).await.unwrap(), 0);

    // Layer 3.
    assert_eq!(screener.screen(&s, "https://fine.example/", now).await, Verdict::Clean { source: "webrisk" });
    let v = screener.screen_and_record(&s, "https://phish.example/login", now).await.unwrap();
    assert!(matches!(&v, Verdict::Flagged { detail, .. } if detail == "SOCIAL_ENGINEERING"));
    assert_eq!(s.view_flagged(&[link_in_bio_store::sha256(b"https://phish.example/login")]).await.unwrap().len(), 1);
    // An outage is "unknown": shown, and checked again within the hour.
    let v = screener.screen_and_record(&s, "https://down.example/", now).await.unwrap();
    assert!(matches!(v, Verdict::Unknown { .. }));
    let due = s.screens_due(now + time::Duration::minutes(61), 10).await.unwrap();
    assert!(due.iter().any(|d| d.url == "https://down.example/"));
    // Three calls spent: the cap holds and the next link is unknown, not clean.
    assert!(
        matches!(screener.screen(&s, "https://another.example/", now).await, Verdict::Unknown { reason } if reason.contains("cap"))
    );
    // mailto links are checked against the lists only.
    assert_eq!(screener.screen(&s, "mailto:me@fine.example", now).await, Verdict::Clean { source: "lists" });
}
