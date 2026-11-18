//! The worker: one process (a PostgreSQL advisory lock makes it the single writer of these duties) that, on a schedule,
//!
//! - lifts suspensions whose time is up;
//! - screens again the links that are due (unknown within the hour, clean daily, flagged weekly);
//! - asks payment providers how checkouts no notification closed have ended (and applies a payment once);
//! - polls the bank feeds (Wise, bunq, Revolut Business; when configured) and pays bank-transfer checkouts from their
//!   credits by the same rules as an imported statement;
//! - checks custom domains' TXT records (when custom domains are on);
//! - syncs ThreatFox indicators (when its key is configured);
//! - prunes: page versions beyond 20, unused pictures and screens, expired sessions, challenges and invites, audit
//!   entries older than two years, decided cases older than two years.

use std::time::{Duration as StdDuration, Instant};

use serde_json::Value;
use time::Duration;

use link_in_bio_billing::bank_feed::{BankFeed, FeedState, bunq, revolut, wise};
use link_in_bio_billing::keys::RsaKey;
use link_in_bio_billing::{Outcome, ProviderEvent};

use super::app::DOMAIN_TXT_LABEL;
use super::config::{BankFeedEnv, HostedConfig};
use super::internal::{Matched, apply_event, match_credits};
use super::metrics::Metrics;
use super::{Shared, now};

pub const KEEP_VERSIONS: i64 = 20;
pub const AUDIT_KEEP: Duration = Duration::days(730);
pub const CASES_KEEP: Duration = Duration::days(730);
/// The longest DNS-over-HTTPS answer read (a TXT lookup is well under a kilobyte).
const DOH_MAX_BYTES: usize = 64 * 1024;
/// A checkout open this long is asked about.
pub const RECONCILE_AFTER: Duration = Duration::minutes(30);
/// And given up after this long.
pub const CHECKOUT_LIFETIME: Duration = Duration::days(2);

/// When each slower duty last ran (in this process).
#[derive(Default)]
pub struct Schedule {
    feeds: Option<Instant>,
    hourly: Option<Instant>,
    six_hourly: Option<Instant>,
    daily: Option<Instant>,
}

fn due(last: &mut Option<Instant>, every: StdDuration) -> bool {
    if last.is_none_or(|t| t.elapsed() >= every) {
        *last = Some(Instant::now());
        true
    } else {
        false
    }
}

fn failed(app: &Shared, duty: &str, e: impl std::fmt::Display) {
    Metrics::inc(&app.metrics.job_failures);
    tracing::error!(duty, error = %e, "worker duty failed");
}

pub async fn lift_suspensions(app: &Shared) {
    match app.store.lift_expired_suspensions(now()).await {
        Ok(ids) => {
            for id in ids {
                let _ = app.store.audit("worker", "suspension-ended", &id.to_string(), &serde_json::json!({})).await;
            }
        }
        Err(e) => failed(app, "suspensions", e),
    }
}

pub async fn rescreen(app: &Shared, limit: i64) {
    let n = now();
    match app.store.screens_due(n, limit).await {
        Ok(due) => {
            for s in due {
                if let Err(e) = app.screener.screen_and_record(&app.store, &s.url, n).await {
                    failed(app, "screening", e);
                    return;
                }
                Metrics::inc(&app.metrics.screenings);
            }
        }
        Err(e) => failed(app, "screening", e),
    }
}

pub async fn reconcile(app: &Shared) {
    let n = now();
    let stale = match app.store.stale_checkouts(n - RECONCILE_AFTER, 50).await {
        Ok(s) => s,
        Err(e) => return failed(app, "reconcile", e),
    };
    for c in stale {
        let Some(p) = app.billing.provider(&c.provider) else { continue };
        match p.checkout_outcome(&c.provider_ref).await {
            Ok(Outcome::Paid) => {
                let e = ProviderEvent {
                    event_id: p.paid_event_id(&c.provider_ref),
                    provider_ref: c.provider_ref.clone(),
                    outcome: Outcome::Paid,
                    months: None,
                    evidence: serde_json::json!({ "source": "reconciliation" }),
                };
                if let Err(e) = apply_event(app, p.id(), &e).await {
                    failed(app, "reconcile", e);
                }
            }
            Ok(Outcome::Expired | Outcome::Failed) => {
                let _ = app.store.close_checkout(c.id, "expired", n).await;
            }
            Ok(_) if c.created_at < n - CHECKOUT_LIFETIME => {
                let _ = app.store.close_checkout(c.id, "expired", n).await;
            }
            Ok(_) => {}
            Err(e) => failed(app, "reconcile", e),
        }
    }
}

/// The bank feeds the configuration names, with their keys and tokens read from their files. Only the worker builds
/// them, so the other roles need none of these secrets.
pub fn bank_feeds(config: &HostedConfig) -> Result<Vec<Box<dyn BankFeed>>, String> {
    let read = |f: &str| std::fs::read_to_string(f).map(|s| s.trim().to_string()).map_err(|e| format!("{f}: {e}"));
    let key = |f: &str| RsaKey::from_pem(&read(f)?).map_err(|e| format!("{f}: {e}"));
    let mut out: Vec<Box<dyn BankFeed>> = Vec::new();
    for f in &config.bank_feeds {
        let http = link_in_bio_billing::http_client();
        out.push(match f {
            BankFeedEnv::Wise { api_base, api_version, token_file, profile_id, sca_key_file } => {
                Box::new(wise::Wise::new(
                    wise::Config {
                        api_base: api_base.clone(),
                        api_version: api_version.clone(),
                        token: read(token_file)?,
                        profile_id: *profile_id,
                        sca_key: sca_key_file.as_deref().map(key).transpose()?,
                    },
                    http,
                ))
            }
            BankFeedEnv::Bunq { api_base, api_key_file, key_file, permitted_ips } => Box::new(bunq::Bunq::new(
                bunq::Config {
                    api_base: api_base.clone(),
                    api_key: read(api_key_file)?,
                    key: key(key_file)?,
                    permitted_ips: permitted_ips.clone(),
                    description: format!("{} worker", config.product_name),
                },
                http,
            )),
            BankFeedEnv::Revolut { api_base, client_id, issuer, key_file, refresh_token_file } => {
                Box::new(revolut::Revolut::new(
                    revolut::Config {
                        api_base: api_base.clone(),
                        client_id: client_id.clone(),
                        issuer: issuer.clone(),
                        key: key(key_file)?,
                        refresh_token: read(refresh_token_file)?,
                    },
                    http,
                ))
            }
        });
    }
    Ok(out)
}

/// One poll of every bank feed: credits matched against bank-transfer checkouts, the cursor kept per feed. A feed
/// that fails keeps its cursor (and says why in the console's overview).
pub async fn poll_bank_feeds(app: &Shared, feeds: &[Box<dyn BankFeed>]) {
    for f in feeds {
        let n = now();
        let from = match app.store.bank_feed(f.id()).await {
            Ok(r) => r.map(|r| FeedState { cursor: r.cursor, state: r.state }).unwrap_or_default(),
            Err(e) => return failed(app, "bank-feeds", e),
        };
        let batch = match f.fetch(&from, n).await {
            Ok(b) => b,
            Err(e) => {
                failed(app, "bank-feeds", format!("{}: {e}", f.id()));
                let _ = app.store.bank_feed_failed(f.id(), &e.to_string(), n).await;
                continue;
            }
        };
        let Matched { paid, short, unknown } = match match_credits(app, &batch.credits).await {
            Ok(m) => m,
            Err(e) => {
                failed(app, "bank-feeds", e);
                continue;
            }
        };
        if !paid.is_empty() || !short.is_empty() {
            let _ = app
                .store
                .audit(
                    &format!("worker:bank-feed:{}", f.id()),
                    "bank-feed-credits",
                    "bank-transfer",
                    &serde_json::json!({ "credits": batch.credits.len(), "paid": paid, "short": short, "unknown": unknown.len() }),
                )
                .await;
        }
        if let Err(e) =
            app.store.save_bank_feed(f.id(), batch.cursor.as_deref(), &batch.state, batch.credits.len() as i64, n).await
        {
            failed(app, "bank-feeds", e);
        }
    }
}

/// Whether a DNS-over-HTTPS answer (`application/dns-json`) holds the TXT value.
pub fn txt_holds(answer: &Value, token: &str) -> bool {
    answer["Answer"].as_array().is_some_and(|a| {
        a.iter()
            .filter(|r| r["type"].as_u64() == Some(16))
            .any(|r| r["data"].as_str().is_some_and(|d| d.trim_matches('"') == token))
    })
}

pub async fn check_domains(app: &Shared, http: &reqwest::Client) {
    if app.config.custom_hostname_cap == 0 {
        return;
    }
    let n = now();
    let due = match app.store.domains_due(n - Duration::hours(24), 50).await {
        Ok(d) => d,
        Err(e) => return failed(app, "domains", e),
    };
    for d in due {
        let name = format!("{DOMAIN_TXT_LABEL}.{}", d.hostname);
        let Ok(mut url) = url::Url::parse("https://cloudflare-dns.com/dns-query") else { return };
        url.query_pairs_mut().append_pair("name", &name).append_pair("type", "TXT");
        let answer = match http.get(url).header("accept", "application/dns-json").send().await {
            Ok(r) => link_in_bio_billing::read_limited(r, DOH_MAX_BYTES)
                .await
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
            Err(_) => None,
        };
        let Some(answer) = answer else { continue };
        let status = if txt_holds(&answer, &d.token) {
            "verified"
        } else if d.status == "verified" {
            "failed"
        } else {
            "pending"
        };
        if let Err(e) = app.store.set_domain_status(&d.hostname, status, n).await {
            failed(app, "domains", e);
        }
        if status != d.status {
            app.pages.forget(&d.hostname).await;
        }
    }
}

pub async fn sync_threatfox(app: &Shared, http: &reqwest::Client) {
    let Some(file) = &app.config.threatfox_key_file else { return };
    let Ok(key) = std::fs::read_to_string(file) else { return failed(app, "threatfox", "cannot read the key file") };
    match link_in_bio_safety::fetch_threatfox(http, "https://threatfox-api.abuse.ch/api/v1/", key.trim(), 7).await {
        Ok(rows) if !rows.is_empty() => {
            if let Err(e) = app.store.replace_iocs(&rows).await {
                failed(app, "threatfox", e);
            }
        }
        Ok(_) => {}
        Err(e) => failed(app, "threatfox", e),
    }
}

pub async fn prune(app: &Shared) {
    let n = now();
    for r in [
        app.store.prune_versions(KEEP_VERSIONS).await,
        app.store.prune_assets().await,
        app.store.prune_screens().await,
        app.store.prune(n, AUDIT_KEEP, CASES_KEEP).await,
    ] {
        if let Err(e) = r {
            failed(app, "prune", e);
        }
    }
}

/// One pass of every duty that is due.
pub async fn tick(app: &Shared, http: &reqwest::Client, s: &mut Schedule, feeds: &[Box<dyn BankFeed>]) {
    lift_suspensions(app).await;
    rescreen(app, 100).await;
    reconcile(app).await;
    if !feeds.is_empty() && due(&mut s.feeds, StdDuration::from_secs(app.config.bank_feed_poll_secs)) {
        poll_bank_feeds(app, feeds).await;
    }
    if due(&mut s.hourly, StdDuration::from_secs(3600)) {
        check_domains(app, http).await;
    }
    if due(&mut s.six_hourly, StdDuration::from_secs(6 * 3600)) {
        sync_threatfox(app, http).await;
    }
    if due(&mut s.daily, StdDuration::from_secs(24 * 3600)) {
        prune(app).await;
    }
}

/// Runs until `stop` resolves, holding the single-writer lock. `feeds` are the bank feeds ([`bank_feeds`]).
pub async fn run(app: Shared, feeds: Vec<Box<dyn BankFeed>>, stop: impl std::future::Future<Output = ()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(StdDuration::from_secs(10))
        .build()
        .unwrap_or_default();
    tokio::pin!(stop);
    let _lock = loop {
        match app.store.try_worker_lock().await {
            Ok(Some(c)) => break c,
            Ok(None) => tracing::info!("another worker holds the lock; waiting"),
            Err(e) => tracing::warn!(error = %e, "cannot take the lock yet"),
        }
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep(StdDuration::from_secs(15)) => {}
        }
    };
    tracing::info!("worker running");
    let mut schedule = Schedule::default();
    loop {
        tick(&app, &http, &mut schedule, &feeds).await;
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep(StdDuration::from_secs(60)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn txt_records() {
        let a = json!({"Status": 0, "Answer": [{"name": "_link-in-bio.example.org", "type": 16, "data": "\"abc\""}]});
        assert!(super::txt_holds(&a, "abc"));
        assert!(!super::txt_holds(&a, "abd"));
        assert!(!super::txt_holds(&json!({"Status": 3}), "abc"));
    }
}
