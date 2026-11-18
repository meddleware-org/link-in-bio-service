//! `link-in-bio-safety`: link screening, in layers, cheapest first.
//!
//! 1. Built-in checks (no network): an IP address instead of a name, a port other than 443, a URL shortener (it hides
//!    the destination; link to the destination instead).
//! 2. The operator's blocklist and the ThreatFox indicators (CC0, synced into the database by the worker).
//! 3. Google Web Risk, in one of two modes (`WEB_RISK_MODE`), never both:
//!    - **lookup** ([`WebRiskLookup`], the default): `uris.search` for each new link at publish time and weekly for
//!      links on published pages, within the free monthly allowance (and any paid calls), with the last 20 % of it
//!      kept for publishes;
//!    - **update** ([`WebRiskUpdate`], [`webrisk`]): the threat lists as local hash prefixes, kept current by the
//!      worker; a link is checked locally (daily, at no cost), and only a match sends its hash prefix (never the URL)
//!      to Google to confirm, under a cap of its own.
//!
//!    Every call is counted in the database across every process, against hard monthly caps.
//!
//! A flagged link is hidden from the page until an operator reviews it; a link that could not be checked (Web Risk
//! down, the allowance spent, the lists not loaded yet) is shown and checked again within the hour.

pub mod webrisk;

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration as StdDuration;

use base64::Engine;
use link_in_bio_store::Store;
use serde_json::Value;
use time::{Duration, OffsetDateTime, UtcOffset};

pub const RESCAN_CLEAN: Duration = Duration::hours(24);
pub const RESCAN_UNKNOWN: Duration = Duration::hours(1);
pub const RESCAN_FLAGGED: Duration = Duration::days(7);

/// The longest ThreatFox answer read (seven days of indicators are a few megabytes).
const MAX_THREATFOX_BYTES: usize = 64 * 1024 * 1024;

/// Reads a response body of at most `max` bytes (checked on the declared length, then while reading); `None` when it is
/// longer or the connection broke off.
pub(crate) async fn read_limited(mut resp: reqwest::Response, max: usize) -> Option<Vec<u8>> {
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return None;
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        if out.len() + chunk.len() > max {
            return None;
        }
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// Hosts whose only job is to redirect somewhere else.
pub const SHORTENERS: &[&str] = &[
    "bit.ly",
    "bitly.com",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "t.ly",
    "s.id",
    "v.gd",
    "lnkd.in",
    "bl.ink",
    "short.io",
    "tr.im",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean { source: &'static str },
    Flagged { source: String, detail: String },
    Unknown { reason: String },
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean { .. } => "clean",
            Verdict::Flagged { .. } => "flagged",
            Verdict::Unknown { .. } => "unknown",
        }
    }

    pub fn next_check(&self, now: OffsetDateTime) -> OffsetDateTime {
        now + match self {
            Verdict::Clean { .. } => RESCAN_CLEAN,
            // A prefix match nobody confirmed: checked again daily (locally), so a list update clears it.
            Verdict::Flagged { source, .. } if source == UNCONFIRMED => RESCAN_CLEAN,
            Verdict::Flagged { .. } => RESCAN_FLAGGED,
            Verdict::Unknown { .. } => RESCAN_UNKNOWN,
        }
    }
}

/// The host of an `https:` link and its parent domains (`a.b.example.org` → itself, `b.example.org`, `example.org`),
/// lower-case, never the bare top-level domain. `mailto:` links give the address's domain.
pub fn hosts_of(link: &str) -> Vec<String> {
    let host = if let Some(addr) = link.strip_prefix("mailto:") {
        addr.split('?').next().and_then(|a| a.rsplit_once('@')).map(|(_, d)| d.to_ascii_lowercase())
    } else {
        url::Url::parse(link).ok().and_then(|u| u.host_str().map(|h| h.trim_end_matches('.').to_ascii_lowercase()))
    };
    let Some(host) = host else { return Vec::new() };
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return vec![host];
    }
    (0..labels.len() - 1).map(|i| labels[i..].join(".")).collect()
}

/// Layer 1: what can be said without asking anyone.
pub fn builtin(link: &str) -> Option<(String, String)> {
    if link.starts_with("mailto:") {
        return None;
    }
    let u = url::Url::parse(link).ok()?;
    match u.host() {
        Some(url::Host::Ipv4(_)) | Some(url::Host::Ipv6(_)) => {
            return Some(("builtin".into(), "the link goes to an IP address instead of a name".into()));
        }
        None => return Some(("builtin".into(), "the link has no host".into())),
        _ => {}
    }
    if u.port().is_some_and(|p| p != 443) {
        return Some(("builtin".into(), "the link uses an unusual port".into()));
    }
    let hosts = hosts_of(link);
    if hosts.iter().any(|h| SHORTENERS.contains(&h.as_str())) {
        return Some((
            "builtin".into(),
            "a link shortener hides where it goes: link to the destination instead".into(),
        ));
    }
    None
}

/// Google Web Risk through its Update API ([`webrisk`]): the lists of hash prefixes are kept in the database by the
/// worker and held in memory here; a link is checked locally, and only a local match sends its hash prefix (never the
/// URL) to `hashes.search`. Every call counts against `monthly_cap` (`computeDiff` and `hashes.search` together), and
/// `hashes.search`, the only billed call, against `confirm_monthly_cap` as well.
pub struct WebRiskUpdate {
    pub api: webrisk::UpdateApi,
    pub monthly_cap: i64,
    pub confirm_monthly_cap: i64,
    /// `constraints.maxDatabaseEntries` per list (a power of two from 2^10 to 2^20).
    pub max_entries: u32,
    lists: RwLock<Arc<Loaded>>,
    checked: Mutex<Option<std::time::Instant>>,
    cache: Mutex<webrisk::HashCache>,
}

/// The lists in memory and what they were loaded from (`threat:updated_at` per list).
#[derive(Default)]
struct Loaded {
    stamp: String,
    lists: Vec<(String, webrisk::Lookup)>,
}

/// How often a process compares its lists with the database's.
const RELOAD_EVERY: StdDuration = StdDuration::from_secs(60);

impl WebRiskUpdate {
    pub fn new(key: String, monthly_cap: i64, confirm_monthly_cap: i64, max_entries: u32) -> Self {
        Self {
            api: webrisk::UpdateApi::new(key),
            monthly_cap,
            confirm_monthly_cap,
            max_entries,
            lists: RwLock::new(Arc::new(Loaded::default())),
            checked: Mutex::new(None),
            cache: Mutex::new(webrisk::HashCache::default()),
        }
    }

    fn loaded(&self) -> Arc<Loaded> {
        self.lists.read().map(|l| l.clone()).unwrap_or_default()
    }

    /// Prefixes held in memory, over every list.
    pub fn entries(&self) -> usize {
        self.loaded().lists.iter().map(|(_, l)| l.len()).sum()
    }

    /// Loads the lists again when the worker has changed them (compared at most once a minute, or now with `force`).
    pub async fn refresh(&self, store: &Store, force: bool) -> Result<(), link_in_bio_store::DbError> {
        {
            let Ok(mut last) = self.checked.lock() else { return Ok(()) };
            if !force && last.is_some_and(|t| t.elapsed() < RELOAD_EVERY) {
                return Ok(());
            }
            *last = Some(std::time::Instant::now());
        }
        let states = store.web_risk_lists().await?;
        let stamp: String = states
            .iter()
            .filter(|s| s.entries > 0)
            .map(|s| format!("{}:{}:{};", s.threat_type, s.updated_at.unix_timestamp_nanos(), s.entries))
            .collect();
        if stamp == self.loaded().stamp {
            return Ok(());
        }
        let mut lists = Vec::new();
        for s in states.iter().filter(|s| s.entries > 0) {
            if let Some(l) = store.web_risk_list(&s.threat_type).await?
                && let Some(prefixes) = webrisk::decode(&l.prefixes)
            {
                lists.push((l.threat_type, webrisk::Lookup::new(&prefixes)));
            }
        }
        if let Ok(mut w) = self.lists.write() {
            *w = Arc::new(Loaded { stamp, lists });
        }
        Ok(())
    }

    /// One billed `hashes.search` call, if both monthly caps allow it.
    async fn confirm(&self, store: &Store, prefix: &[u8], now: OffsetDateTime) -> Result<webrisk::Found, Confirm> {
        let month = period(now);
        let takes = [
            ("webrisk".to_string(), month.clone(), 1, self.monthly_cap),
            ("webrisk-confirm".to_string(), month, 1, self.confirm_monthly_cap),
        ];
        match store.take_from_counters(&takes).await {
            Ok(None) => {}
            Ok(Some(_)) => return Err(Confirm::Budget),
            Err(_) => return Err(Confirm::Down("the Web Risk counter could not be read".into())),
        }
        let found = self.api.search_hashes(prefix, now).await.map_err(Confirm::Down)?;
        if let Ok(mut c) = self.cache.lock() {
            c.record(prefix, &found, now);
        }
        Ok(found)
    }

    /// Layer 3 for one link.
    async fn check(&self, store: &Store, link: &str, now: OffsetDateTime) -> Verdict {
        if self.refresh(store, false).await.is_err() {
            return Verdict::Unknown { reason: "the Web Risk lists could not be read".into() };
        }
        let loaded = self.loaded();
        if loaded.lists.is_empty() {
            return Verdict::Unknown { reason: "the Web Risk lists are not loaded yet".into() };
        }
        // Each of the link's full hashes that starts with a local prefix, by prefix.
        let mut by_prefix: Vec<(Vec<u8>, Vec<[u8; 32]>)> = Vec::new();
        for h in webrisk::full_hashes(link) {
            for (_, l) in &loaded.lists {
                if let Some(p) = l.matching(&h) {
                    match by_prefix.iter_mut().find(|(q, _)| *q == p) {
                        Some((_, hs)) => hs.push(h),
                        None => by_prefix.push((p, vec![h])),
                    }
                }
            }
        }
        if by_prefix.is_empty() {
            return Verdict::Clean { source: "webrisk" };
        }
        let mut threats: Vec<String> = Vec::new();
        let mut unconfirmed = false;
        for (prefix, hashes) in by_prefix {
            let cached: Option<Vec<String>> = self.cache.lock().ok().and_then(|c| {
                let types: Vec<String> =
                    hashes.iter().filter_map(|h| c.unsafe_types(h, now)).flatten().cloned().collect();
                if !types.is_empty() {
                    Some(types)
                } else if c.safe(&prefix, now) {
                    Some(Vec::new())
                } else {
                    None
                }
            });
            let types = match cached {
                Some(t) => t,
                None => match self.confirm(store, &prefix, now).await {
                    Ok(found) => found
                        .threats
                        .iter()
                        .filter(|(h, _, until)| hashes.contains(h) && *until > now)
                        .flat_map(|(_, t, _)| t.clone())
                        .collect(),
                    Err(Confirm::Budget) => {
                        unconfirmed = true;
                        Vec::new()
                    }
                    Err(Confirm::Down(reason)) => return Verdict::Unknown { reason },
                },
            };
            for t in types {
                if !threats.contains(&t) {
                    threats.push(t);
                }
            }
        }
        if !threats.is_empty() {
            Verdict::Flagged { source: "webrisk".into(), detail: threats.join(", ") }
        } else if unconfirmed {
            Verdict::Flagged {
                source: UNCONFIRMED.into(),
                detail: "the link matches a Web Risk list prefix; confirming it with Google is not allowed this month \
                         (WEB_RISK_CONFIRM_MONTHLY_CAP), so it is hidden until an operator reviews it"
                    .into(),
            }
        } else {
            Verdict::Clean { source: "webrisk" }
        }
    }
}

enum Confirm {
    /// A monthly cap is reached.
    Budget,
    Down(String),
}

/// The source of a verdict that rests on a local prefix match alone (no confirmation was allowed).
pub const UNCONFIRMED: &str = "webrisk-prefix";

/// The month a Web Risk call is counted in.
pub fn period(now: OffsetDateTime) -> String {
    let now = now.to_offset(UtcOffset::UTC);
    format!("{:04}-{:02}", now.year(), now.month() as u8)
}

/// Web Risk's Lookup API (`uris.search`, the default mode): one call per link screened. `free_monthly` is the free
/// allowance (`WEB_RISK_MONTHLY_CAP`, at most 100 000) and `paid_monthly` the calls bought on top of it
/// (`WEB_RISK_PAID_MONTHLY_CALLS`, $0.50 per 1 000), together a hard stop. The worker's rechecks stop at 80 % of that, so
/// the rest is kept for links being published. This mode never calls `computeDiff` or `hashes.search`: one `computeDiff`
/// would price every `uris.search` of the month at $50 per 1 000.
#[derive(Clone)]
pub struct WebRiskLookup {
    pub key: String,
    pub endpoint: String,
    pub http: reqwest::Client,
    pub free_monthly: i64,
    pub paid_monthly: i64,
}

/// The longest `uris.search` answer read (a few hundred bytes).
const MAX_LOOKUP_BYTES: usize = 64 * 1024;

/// The share of the month's allowance the worker's rechecks may use (the rest is kept for publishes).
pub const RECHECK_SHARE_PERCENT: i64 = 80;

impl WebRiskLookup {
    pub const ENDPOINT: &'static str = "https://webrisk.googleapis.com/v1/uris:search";

    pub fn new(key: String, free_monthly: i64, paid_monthly: i64) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(StdDuration::from_secs(3))
            .timeout(StdDuration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { key, endpoint: Self::ENDPOINT.into(), http, free_monthly, paid_monthly }
    }

    /// The month's hard stop: the free allowance and the paid calls.
    pub fn allowance(&self) -> i64 {
        self.free_monthly.saturating_add(self.paid_monthly)
    }

    /// Where the worker's rechecks stop: 80 % of the allowance.
    pub fn recheck_stop(&self) -> i64 {
        self.allowance() * RECHECK_SHARE_PERCENT / 100
    }

    /// The threat types Web Risk reports for a URL (empty: none known), or an error to retry later.
    pub async fn lookup(&self, link: &str) -> Result<Vec<String>, String> {
        let mut u = url::Url::parse(&self.endpoint).map_err(|_| "the Web Risk endpoint is not a URL".to_string())?;
        u.query_pairs_mut()
            .append_pair("threatTypes", "MALWARE")
            .append_pair("threatTypes", "SOCIAL_ENGINEERING")
            .append_pair("threatTypes", "UNWANTED_SOFTWARE")
            .append_pair("uri", link)
            .append_pair("key", &self.key);
        let r = self.http.get(u).send().await.map_err(|e| {
            if e.is_timeout() { "Web Risk timed out".to_string() } else { "Web Risk unreachable".to_string() }
        })?;
        if !r.status().is_success() {
            return Err(format!("Web Risk answered HTTP {}", r.status().as_u16()));
        }
        let body = read_limited(r, MAX_LOOKUP_BYTES).await.ok_or("Web Risk answered too much or broke off")?;
        let v: Value =
            serde_json::from_slice(&body).map_err(|_| "Web Risk answered something unreadable".to_string())?;
        Ok(v["threat"]["threatTypes"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
            .unwrap_or_default())
    }

    /// Layer 3 for one link: `None` when a recheck must wait (the recheck share of the month is spent).
    async fn check(&self, store: &Store, link: &str, now: OffsetDateTime, recheck: bool) -> Option<Verdict> {
        let cap = if recheck { self.recheck_stop() } else { self.allowance() };
        match store.take_from_counter("webrisk", &period(now), 1, cap).await {
            Ok(true) => {}
            Ok(false) if recheck => return None,
            Ok(false) => return Some(Verdict::Unknown { reason: "the Web Risk monthly allowance is reached".into() }),
            Err(_) => return Some(Verdict::Unknown { reason: "the Web Risk counter could not be read".into() }),
        }
        Some(match self.lookup(link).await {
            Ok(t) if t.is_empty() => Verdict::Clean { source: "webrisk" },
            Ok(t) => Verdict::Flagged { source: "webrisk".into(), detail: t.join(", ") },
            Err(reason) => Verdict::Unknown { reason },
        })
    }
}

/// How often a clean link on a published page is looked up again in lookup mode.
pub const RESCAN_CLEAN_LOOKUP: Duration = Duration::days(7);

/// The layers, with at most one Web Risk mode (both `None`: the built-in checks and the lists only).
#[derive(Default)]
pub struct Screener {
    pub lookup: Option<WebRiskLookup>,
    pub update: Option<WebRiskUpdate>,
}

impl Screener {
    /// `lookup`, `update`, or `None` without Web Risk.
    pub fn mode(&self) -> Option<&'static str> {
        match (&self.lookup, &self.update) {
            (Some(_), _) => Some("lookup"),
            (None, Some(_)) => Some("update"),
            (None, None) => None,
        }
    }

    /// How long a clean verdict holds before the link is checked again: a week in lookup mode (each check is a call),
    /// a day otherwise (local).
    pub fn clean_for(&self) -> Duration {
        if self.lookup.is_some() { RESCAN_CLEAN_LOOKUP } else { RESCAN_CLEAN }
    }

    /// When a verdict is checked again: unknown within the hour, flagged weekly (an unconfirmed prefix match daily),
    /// clean after [`Screener::clean_for`].
    pub fn next_check(&self, v: &Verdict, now: OffsetDateTime) -> OffsetDateTime {
        match v {
            Verdict::Clean { .. } => now + self.clean_for(),
            other => other.next_check(now),
        }
    }

    async fn layers(&self, store: &Store, link: &str, now: OffsetDateTime, recheck: bool) -> Option<Verdict> {
        if let Some((source, detail)) = builtin(link) {
            return Some(Verdict::Flagged { source, detail });
        }
        match store.blocked(link, &hosts_of(link)).await {
            Ok(Some((source, detail))) => return Some(Verdict::Flagged { source, detail }),
            Ok(None) => {}
            Err(_) => return Some(Verdict::Unknown { reason: "the blocklist could not be read".into() }),
        }
        if link.starts_with("mailto:") {
            return Some(Verdict::Clean { source: "lists" });
        }
        match (&self.lookup, &self.update) {
            (Some(l), _) => l.check(store, link, now, recheck).await,
            (None, Some(u)) => Some(u.check(store, link, now).await),
            (None, None) => Some(Verdict::Clean { source: "lists" }),
        }
    }

    /// Screens one link being published (layers 1–3), without recording anything.
    pub async fn screen(&self, store: &Store, link: &str, now: OffsetDateTime) -> Verdict {
        self.layers(store, link, now, false)
            .await
            .unwrap_or_else(|| Verdict::Unknown { reason: "Web Risk is not available".into() })
    }

    async fn record(
        &self,
        store: &Store,
        link: &str,
        v: &Verdict,
        now: OffsetDateTime,
    ) -> Result<(), link_in_bio_store::DbError> {
        let (source, detail) = match v {
            Verdict::Clean { source } => (source.to_string(), String::new()),
            Verdict::Flagged { source, detail } => (source.clone(), detail.clone()),
            Verdict::Unknown { reason } => ("none".to_string(), reason.clone()),
        };
        store.put_screen(link, v.as_str(), &source, &detail, self.next_check(v, now), now).await
    }

    /// Screens a link being published and records the verdict (unless an operator has overridden the link).
    pub async fn screen_and_record(
        &self,
        store: &Store,
        link: &str,
        now: OffsetDateTime,
    ) -> Result<Verdict, link_in_bio_store::DbError> {
        let v = self.screen(store, link, now).await;
        self.record(store, link, &v, now).await?;
        Ok(v)
    }

    /// The worker's recheck of a due link: screened and recorded, or `None` when rechecks must stop for now (lookup
    /// mode, the month's recheck share spent), leaving the link as it was.
    pub async fn recheck(
        &self,
        store: &Store,
        link: &str,
        now: OffsetDateTime,
    ) -> Result<Option<Verdict>, link_in_bio_store::DbError> {
        let Some(v) = self.layers(store, link, now, true).await else { return Ok(None) };
        self.record(store, link, &v, now).await?;
        Ok(Some(v))
    }
}

/// Keeps one Web Risk list current (the worker's duty): when its next update is due, asks `computeDiff` from the stored
/// version, applies the answer and stores it only if the checksum matches. A mismatch keeps the list as it was and asks
/// for the whole list at the next allowed time; a failure keeps it and tries again after `retry`.
pub async fn update_list(
    w: &WebRiskUpdate,
    store: &Store,
    threat: &str,
    now: OffsetDateTime,
    retry: Duration,
) -> Result<UpdateOutcome, link_in_bio_store::DbError> {
    let current = store.web_risk_list(threat).await?;
    if current.as_ref().and_then(|c| c.next_diff_at).is_some_and(|t| t > now) {
        return Ok(UpdateOutcome::NotDue);
    }
    if !store.take_from_counter("webrisk", &period(now), 1, w.monthly_cap).await? {
        return Ok(UpdateOutcome::CapReached);
    }
    let version = current.as_ref().map(|c| c.version_token.clone()).unwrap_or_default();
    let diff = match w.api.compute_diff(threat, &version, w.max_entries).await {
        Ok(d) => d,
        Err(e) => {
            store.web_risk_list_failed(threat, &e, now + retry, false).await?;
            return Ok(UpdateOutcome::Failed(e));
        }
    };
    let next = diff.recommended_next.filter(|t| *t > now).unwrap_or(now + DEFAULT_NEXT_DIFF);
    let held = current.as_ref().and_then(|c| webrisk::decode(&c.prefixes)).unwrap_or_default();
    match webrisk::apply(&held, &diff) {
        Ok(list) => {
            store
                .put_web_risk_list(&link_in_bio_store::WebRiskList {
                    threat_type: threat.to_string(),
                    version_token: diff.new_version,
                    entries: i32::try_from(list.len()).unwrap_or(i32::MAX),
                    prefixes: webrisk::encode(&list),
                    checksum: base64::engine::general_purpose::STANDARD.encode(&diff.checksum),
                    next_diff_at: Some(next),
                    updated_at: now,
                    last_error: None,
                })
                .await?;
            Ok(UpdateOutcome::Updated(list.len()))
        }
        Err(e) => {
            store.web_risk_list_failed(threat, &e, next, true).await?;
            Ok(UpdateOutcome::Failed(e))
        }
    }
}

/// When to ask again if Web Risk recommends no time.
pub const DEFAULT_NEXT_DIFF: Duration = Duration::minutes(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    NotDue,
    CapReached,
    Updated(usize),
    Failed(String),
}

/// Reads a ThreatFox `get_iocs` answer into (indicator, `host`|`url`, threat) rows; other indicator types (IP:port,
/// hashes) do not appear in links and are skipped.
pub fn parse_threatfox(v: &Value) -> Vec<(String, String, String)> {
    let Some(rows) = v["data"].as_array() else { return Vec::new() };
    rows.iter()
        .filter_map(|r| {
            let ioc = r["ioc"].as_str()?.trim();
            let threat = r["threat_type"].as_str().unwrap_or("").to_string();
            match r["ioc_type"].as_str()? {
                "domain" => Some((ioc.trim_end_matches('.').to_ascii_lowercase(), "host".to_string(), threat)),
                "url" => url::Url::parse(ioc).ok().map(|u| (u.to_string(), "url".to_string(), threat)),
                _ => None,
            }
        })
        .filter(|(i, _, _)| !i.is_empty() && i.len() <= 2048)
        .collect()
}

/// Fetches the last `days` (at most 7) of ThreatFox indicators. `auth_key` is the abuse.ch Auth-Key.
pub async fn fetch_threatfox(
    http: &reqwest::Client,
    endpoint: &str,
    auth_key: &str,
    days: u8,
) -> Result<Vec<(String, String, String)>, String> {
    let r = http
        .post(endpoint)
        .header("Auth-Key", auth_key)
        .json(&serde_json::json!({ "query": "get_iocs", "days": days.clamp(1, 7) }))
        .send()
        .await
        .map_err(|_| "ThreatFox unreachable".to_string())?;
    if !r.status().is_success() {
        return Err(format!("ThreatFox answered HTTP {}", r.status().as_u16()));
    }
    let body = read_limited(r, MAX_THREATFOX_BYTES).await.ok_or("ThreatFox answered too much or broke off")?;
    let v: Value = serde_json::from_slice(&body).map_err(|_| "ThreatFox answered something unreadable".to_string())?;
    if v["query_status"].as_str() != Some("ok") {
        return Err(format!("ThreatFox: {}", v["query_status"].as_str().unwrap_or("error")));
    }
    Ok(parse_threatfox(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hosts_and_parents() {
        assert_eq!(hosts_of("https://a.b.example.org/x"), vec!["a.b.example.org", "b.example.org", "example.org"]);
        assert_eq!(hosts_of("mailto:me@Mail.Example.org?subject=x"), vec!["mail.example.org", "example.org"]);
        assert!(hosts_of("not a url").is_empty());
    }

    #[test]
    fn builtin_checks() {
        assert!(builtin("https://192.0.2.1/").is_some());
        assert!(builtin("https://[2001:db8::1]/").is_some());
        assert!(builtin("https://example.org:8443/").is_some());
        assert!(builtin("https://bit.ly/abc").is_some());
        assert!(builtin("https://www.tinyurl.com/abc").is_some());
        assert!(builtin("https://example.org/").is_none());
        assert!(builtin("mailto:me@example.org").is_none());
    }

    #[test]
    fn verdict_schedule() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(Verdict::Unknown { reason: "x".into() }.next_check(now), now + RESCAN_UNKNOWN);
        assert_eq!(Verdict::Clean { source: "webrisk" }.next_check(now), now + RESCAN_CLEAN);
        assert_eq!(period(time::macros::datetime!(2026-03-09 00:00 UTC)), "2026-03");
        assert_eq!(period(time::macros::datetime!(2026-04-01 00:30 +01:00)), "2026-03", "counted in UTC");
    }

    #[test]
    fn threatfox_rows() {
        let v = json!({"query_status": "ok", "data": [
            {"ioc": "Evil.Example.", "ioc_type": "domain", "threat_type": "botnet_cc"},
            {"ioc": "https://bad.example/p", "ioc_type": "url", "threat_type": "payload_delivery"},
            {"ioc": "192.0.2.1:443", "ioc_type": "ip:port", "threat_type": "botnet_cc"},
            {"ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash"}
        ]});
        let rows = parse_threatfox(&v);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("evil.example".into(), "host".into(), "botnet_cc".into()));
        assert_eq!(rows[1].1, "url");
    }
}
