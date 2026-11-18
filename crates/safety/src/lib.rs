//! `link-in-bio-safety`: link screening, in layers, cheapest first.
//!
//! 1. Built-in checks (no network): an IP address instead of a name, a port other than 443, a URL shortener (it hides
//!    the destination; link to the destination instead).
//! 2. The operator's blocklist and the ThreatFox indicators (CC0, synced into the database by the worker).
//! 3. Google Web Risk Lookup (commercial use allowed; free up to 100 000 calls a month), behind a hard monthly cap
//!    counted in the database across every process.
//!
//! A flagged link is hidden from the page until an operator reviews it; a link that could not be checked (Web Risk
//! down, the cap reached) is shown and checked again within the hour. Clean links are checked again daily.

use std::time::Duration as StdDuration;

use link_in_bio_store::Store;
use serde_json::Value;
use time::{Duration, OffsetDateTime, UtcOffset};

pub const RESCAN_CLEAN: Duration = Duration::hours(24);
pub const RESCAN_UNKNOWN: Duration = Duration::hours(1);
pub const RESCAN_FLAGGED: Duration = Duration::days(7);

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

/// Web Risk Lookup (`uris.search`).
#[derive(Clone)]
pub struct WebRisk {
    pub key: String,
    pub monthly_cap: i64,
    pub endpoint: String,
    pub http: reqwest::Client,
}

impl WebRisk {
    pub const ENDPOINT: &'static str = "https://webrisk.googleapis.com/v1/uris:search";

    pub fn new(key: String, monthly_cap: i64) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(StdDuration::from_secs(3))
            .timeout(StdDuration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { key, monthly_cap, endpoint: Self::ENDPOINT.into(), http }
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
        let v: Value = r.json().await.map_err(|_| "Web Risk answered something unreadable".to_string())?;
        Ok(v["threat"]["threatTypes"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str().map(String::from)).collect())
            .unwrap_or_default())
    }
}

/// The month a Web Risk call is counted in.
pub fn period(now: OffsetDateTime) -> String {
    let now = now.to_offset(UtcOffset::UTC);
    format!("{:04}-{:02}", now.year(), now.month() as u8)
}

pub struct Screener {
    pub web_risk: Option<WebRisk>,
}

impl Screener {
    /// Screens one link (layers 1–3), without recording anything.
    pub async fn screen(&self, store: &Store, link: &str, now: OffsetDateTime) -> Verdict {
        if let Some((source, detail)) = builtin(link) {
            return Verdict::Flagged { source, detail };
        }
        match store.blocked(link, &hosts_of(link)).await {
            Ok(Some((source, detail))) => return Verdict::Flagged { source, detail },
            Ok(None) => {}
            Err(_) => return Verdict::Unknown { reason: "the blocklist could not be read".into() },
        }
        if link.starts_with("mailto:") {
            return Verdict::Clean { source: "lists" };
        }
        let Some(w) = &self.web_risk else { return Verdict::Clean { source: "lists" } };
        match store.take_from_counter("webrisk", &period(now), 1, w.monthly_cap).await {
            Ok(true) => {}
            Ok(false) => return Verdict::Unknown { reason: "the Web Risk monthly cap is reached".into() },
            Err(_) => return Verdict::Unknown { reason: "the Web Risk counter could not be read".into() },
        }
        match w.lookup(link).await {
            Ok(t) if t.is_empty() => Verdict::Clean { source: "webrisk" },
            Ok(t) => Verdict::Flagged { source: "webrisk".into(), detail: t.join(", ") },
            Err(reason) => Verdict::Unknown { reason },
        }
    }

    /// Screens and records the verdict (unless an operator has overridden the link).
    pub async fn screen_and_record(
        &self,
        store: &Store,
        link: &str,
        now: OffsetDateTime,
    ) -> Result<Verdict, link_in_bio_store::DbError> {
        let v = self.screen(store, link, now).await;
        let (source, detail) = match &v {
            Verdict::Clean { source } => (source.to_string(), String::new()),
            Verdict::Flagged { source, detail } => (source.clone(), detail.clone()),
            Verdict::Unknown { reason } => ("none".to_string(), reason.clone()),
        };
        store.put_screen(link, v.as_str(), &source, &detail, v.next_check(now), now).await?;
        Ok(v)
    }
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
    let v: Value = r.json().await.map_err(|_| "ThreatFox answered something unreadable".to_string())?;
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
