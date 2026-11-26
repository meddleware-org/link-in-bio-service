//! Google Web Risk's Update API: local lists of hash prefixes, checked without sending a URL anywhere.
//!
//! - [`canonicalize`] and [`expressions`] follow "URLs and hashing"
//!   (<https://cloud.google.com/web-risk/docs/urls-hashing>, test vectors below); each expression's SHA-256 is looked
//!   up in the local prefixes ([`Lookup`]).
//! - The worker keeps the lists current with `threatLists.computeDiff` ([`UpdateApi::compute_diff`], uncompressed
//!   `RAW` answers only): a `RESET` replaces a list, a `DIFF` removes by index then adds, and the SHA-256 of the sorted
//!   result must equal the answer's checksum or the update is discarded ([`apply`]).
//! - Only when a link's hash matches a local prefix is that prefix (4 bytes, typically) sent to `hashes.search`
//!   ([`UpdateApi::search_hashes`]); full hashes are cached until their `expireTime` and a prefix's absence until its
//!   `negativeExpireTime` ([`HashCache`]).
//!
//! Pricing (<https://cloud.google.com/web-risk/pricing>, read 2026-11-18): `threatLists.computeDiff` is free without
//! limit; `hashes.search` costs $50 per 1 000 calls with no free tier, and once a project calls `computeDiff`, its
//! `uris.search` calls are priced as `hashes.search`. So the confirmations have a monthly cap of their own (default 0).

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The three lists screened against.
pub const THREAT_TYPES: [&str; 3] = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"];
/// The longest `computeDiff` answer read (2^20 four-byte prefixes in base64 are under 6 MiB).
const MAX_DIFF_BYTES: usize = 32 * 1024 * 1024;
/// The longest `hashes.search` answer read (a few full hashes).
const MAX_SEARCH_BYTES: usize = 256 * 1024;

// ── canonicalisation and expressions ──────────────────────────────────────────────────────────────────────────────

/// The value of one hex digit, in either case.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// One pass of percent-unescaping (`%` not followed by two hex digits stays).
fn unescape_once(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%'
            && i + 2 < s.len()
            && let (Some(h), Some(l)) = (hex_val(s[i + 1]), hex_val(s[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

/// Percent-unescape until nothing changes, as the specification asks.
fn unescape_fully(mut s: Vec<u8>) -> Vec<u8> {
    // Each pass shortens the string or leaves it as it is, so this ends.
    loop {
        let next = unescape_once(&s);
        if next == s {
            return s;
        }
        s = next;
    }
}

/// Escapes what the spec escapes: bytes ≤ 32, ≥ 127, `#` and `%`, in upper-case hex.
fn escape(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s {
        if b <= 32 || b >= 127 || b == b'#' || b == b'%' {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// A number in C's `inet_aton` notation: `0x` hexadecimal, a leading `0` octal, otherwise decimal.
fn ip_part(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 32 {
        return None;
    }
    let (digits, radix) = if s.len() > 2 && (s.starts_with(b"0x") || s.starts_with(b"0X")) {
        (&s[2..], 16)
    } else if s.len() > 1 && s[0] == b'0' {
        (&s[1..], 8)
    } else {
        (s, 10)
    };
    u64::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()
}

/// A host that is a legal IPv4 address in any notation, as four decimal numbers.
fn ipv4(host: &[u8]) -> Option<String> {
    let parts: Vec<&[u8]> = host.split(|&b| b == b'.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let nums: Vec<u64> = parts.iter().map(|p| ip_part(p)).collect::<Option<_>>()?;
    // All but the last part are single bytes; the last part fills the rest, as inet_aton does.
    let (head, last) = nums.split_at(nums.len() - 1);
    if head.iter().any(|&n| n > 255) {
        return None;
    }
    // How many bits the last part may use.
    let last_bits = 8 * (4 - head.len() as u32);
    if last[0] >= 1u64 << last_bits {
        return None;
    }
    let mut v: u64 = 0;
    for (i, &n) in head.iter().enumerate() {
        v |= n << (24 - 8 * i as u32);
    }
    v |= last[0];
    Some(format!("{}.{}.{}.{}", (v >> 24) & 255, (v >> 16) & 255, (v >> 8) & 255, v & 255))
}

/// The host as the specification canonicalises it: leading and trailing dots removed, repeated dots collapsed, an IP address in any notation written as four decimals, and the rest lower-cased.
fn canonical_host(host: &[u8]) -> Vec<u8> {
    let trimmed: &[u8] = {
        let mut h = host;
        while let [b'.', rest @ ..] = h {
            h = rest;
        }
        while let [rest @ .., b'.'] = h {
            h = rest;
        }
        h
    };
    let mut collapsed = Vec::with_capacity(trimmed.len());
    for &b in trimmed {
        if !(b == b'.' && collapsed.last() == Some(&b'.')) {
            collapsed.push(b);
        }
    }
    if let Some(ip) = ipv4(&collapsed) {
        return ip.into_bytes();
    }
    collapsed.to_ascii_lowercase()
}

/// The path with `.`, `..` and empty segments resolved, keeping a trailing slash that was there or that a dot segment implies.
fn canonical_path(path: &[u8]) -> Vec<u8> {
    let segments: Vec<&[u8]> = path.split(|&b| b == b'/').collect();
    let mut out: Vec<&[u8]> = Vec::new();
    let mut trailing = path.ends_with(b"/");
    for (i, seg) in segments.iter().enumerate() {
        let last = i + 1 == segments.len();
        match *seg {
            b"" => {}
            b"." => trailing |= last,
            b".." => {
                out.pop();
                trailing |= last;
            }
            s => out.push(s),
        }
    }
    let mut p = vec![b'/'];
    for (i, s) in out.iter().enumerate() {
        if i > 0 {
            p.push(b'/');
        }
        p.extend_from_slice(s);
    }
    if trailing && !out.is_empty() {
        p.push(b'/');
    }
    p
}

/// A canonical URL's parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    /// The scheme, lower-case.
    pub scheme: String,
    /// The host, tidied and lower-case, with an address in dotted decimal.
    pub host: String,
    /// The path, with dot segments and repeated slashes resolved.
    pub path: String,
    /// The query, if there is one (even an empty one).
    pub query: Option<String>,
}

impl Canonical {
    /// The canonical URL as text.
    pub fn as_url(&self) -> String {
        match &self.query {
            Some(q) => format!("{}://{}{}?{}", self.scheme, self.host, self.path, q),
            None => format!("{}://{}{}", self.scheme, self.host, self.path),
        }
    }
}

/// Canonicalises a URL as "URLs and hashing" describes: whitespace trimmed, tab, CR and LF removed, the fragment
/// removed, percent-escapes undone until none are left, the host's dots tidied, an IP address in any notation written
/// as four decimals, the host lower-cased, `/./`, `/../` and repeated slashes resolved in the path (not the query),
/// and bytes ≤ 32, ≥ 127, `#` and `%` escaped again. A URL without a scheme is taken as `http://`; the port and any
/// user name are dropped.
pub fn canonicalize(url: &str) -> Option<Canonical> {
    canonicalize_bytes(url.as_bytes())
}

/// [`canonicalize`] of a URL given as bytes (a percent-escape may stand for any byte, UTF-8 or not).
pub fn canonicalize_bytes(url: &[u8]) -> Option<Canonical> {
    // Leading and trailing spaces are removed first.
    let start = url.iter().position(|&c| c != b' ').unwrap_or(url.len());
    let end = url.iter().rposition(|&c| c != b' ').map_or(start, |i| i + 1);
    let mut b: Vec<u8> = url[start..end].iter().copied().filter(|c| !matches!(c, b'\t' | b'\r' | b'\n')).collect();
    // The fragment is dropped.
    if let Some(i) = b.iter().position(|&c| c == b'#') {
        b.truncate(i);
    }
    let (scheme, rest): (String, Vec<u8>) = match b.windows(3).position(|w| w == b"://") {
        Some(i) if i > 0 && b[..i].iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.')) => {
            (String::from_utf8_lossy(&b[..i]).to_ascii_lowercase(), b[i + 3..].to_vec())
        }
        _ => ("http".to_string(), b),
    };
    // Escapes are undone before anything else is looked at, so an escaped dot or slash cannot hide.
    let rest = unescape_fully(rest);
    let split = rest.iter().position(|&c| c == b'/' || c == b'?').unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    // A user name and password are dropped.
    let authority = match authority.iter().rposition(|&c| c == b'@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    let host = if authority.starts_with(b"[") {
        authority
    } else {
        match authority.iter().rposition(|&c| c == b':') {
            Some(i) if authority[i + 1..].iter().all(u8::is_ascii_digit) => &authority[..i],
            _ => authority,
        }
    };
    // A host that is empty after tidying is not a URL.
    let host = canonical_host(host);
    if host.is_empty() {
        return None;
    }
    let (path, query) = match tail.iter().position(|&c| c == b'?') {
        Some(i) => (&tail[..i], Some(&tail[i + 1..])),
        None => (tail, None),
    };
    // An empty path is the root.
    let path = canonical_path(if path.is_empty() { b"/" } else { path });
    Some(Canonical { scheme, host: escape(&host), path: escape(&path), query: query.map(escape) })
}

/// The host-suffix and path-prefix expressions to look up (at most 5 hosts × 6 paths): the exact host and up to four
/// suffixes from its last five labels (never the bare top-level domain, none for an IP address); the exact path with
/// and without its query, and up to four prefixes from `/` adding one segment at a time.
pub fn expressions(c: &Canonical) -> Vec<String> {
    // The exact host first, then up to four suffixes from the last five labels.
    let mut hosts = vec![c.host.clone()];
    let is_ip = ipv4(c.host.as_bytes()).is_some_and(|ip| ip == c.host) || c.host.starts_with('[');
    if !is_ip {
        let labels: Vec<&str> = c.host.split('.').collect();
        // The suffixes start at the last five labels, and never include the bare top-level domain.
        let start = labels.len().saturating_sub(5).max(1);
        for i in start..labels.len().saturating_sub(1) {
            let h = labels[i..].join(".");
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    // The exact path with its query, without it, and the prefixes from the root.
    let mut paths = Vec::new();
    if let Some(q) = &c.query {
        paths.push(format!("{}?{}", c.path, q));
    }
    paths.push(c.path.clone());
    let segments: Vec<&str> = c.path.trim_start_matches('/').split('/').collect();
    let mut prefix = String::from("/");
    if !paths.contains(&prefix) {
        paths.push(prefix.clone());
    }
    for seg in &segments[..segments.len().saturating_sub(1)] {
        // At most six paths and four prefixes.
        if paths.len() >= 6 || prefix.matches('/').count() >= 4 {
            break;
        }
        prefix.push_str(seg);
        prefix.push('/');
        if !paths.contains(&prefix) {
            paths.push(prefix.clone());
        }
    }
    let mut out = Vec::new();
    // Every host expression with every path expression.
    for h in &hosts {
        for p in &paths {
            out.push(format!("{h}{p}"));
        }
    }
    out
}

/// The full SHA-256 hashes of a link's expressions (none for a link that cannot be canonicalised).
pub fn full_hashes(link: &str) -> Vec<[u8; 32]> {
    // The parser's links are valid URLs: their WHATWG serialisation has the host in ASCII (Punycode), as the spec asks.
    // The parsed link has its host in ASCII (Punycode), as the specification asks.
    let ascii = url::Url::parse(link).map(|u| u.to_string()).unwrap_or_else(|_| link.to_string());
    let Some(c) = canonicalize(&ascii) else { return Vec::new() };
    expressions(&c).iter().map(|e| Sha256::digest(e.as_bytes()).into()).collect()
}

// ── prefix lists ───────────────────────────────────────────────────────────────────────────────────────────────────

/// One hash prefix (4 to 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix {
    /// The number of bytes of the prefix that are used.
    len: u8,
    /// The prefix's bytes, padded with zeros.
    bytes: [u8; 32],
}

impl Prefix {
    /// A prefix from 4 to 32 bytes; any other length is refused.
    pub fn new(b: &[u8]) -> Option<Self> {
        if !(4..=32).contains(&b.len()) {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes[..b.len()].copy_from_slice(b);
        Some(Self { len: b.len() as u8, bytes })
    }

    /// The prefix's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl Ord for Prefix {
    /// Prefixes sort by their bytes, the shorter of two with the same start first.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

impl PartialOrd for Prefix {
    /// The same order as `cmp`.
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The stored form: each prefix as one length byte and its bytes, in order.
pub fn encode(list: &[Prefix]) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 5);
    for p in list {
        out.push(p.len);
        out.extend_from_slice(p.as_bytes());
    }
    out
}

/// The prefixes from their stored form; `None` if the bytes do not parse.
pub fn decode(b: &[u8]) -> Option<Vec<Prefix>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let n = b[i] as usize;
        out.push(Prefix::new(b.get(i + 1..i + 1 + n)?)?);
        i += 1 + n;
    }
    Some(out)
}

/// The SHA-256 of the sorted prefixes concatenated (what `checksum.sha256` is).
pub fn checksum(list: &[Prefix]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in list {
        h.update(p.as_bytes());
    }
    h.finalize().into()
}

/// One `computeDiff` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    /// Whether the answer replaces the whole list.
    pub reset: bool,
    /// The prefixes to add.
    pub additions: Vec<Prefix>,
    /// The indices of the prefixes to remove from the list before the additions.
    pub removals: Vec<u32>,
    /// The version token to store and send next time.
    pub new_version: String,
    /// The SHA-256 the list must have after the update.
    pub checksum: Vec<u8>,
    /// When Web Risk asks to be called again.
    pub recommended_next: Option<OffsetDateTime>,
}

/// Applies a diff to a sorted list (a reset starts from nothing; removals are indices into the list before the
/// additions) and checks the result against the answer's checksum. `Err` leaves nothing changed: the diff is discarded.
pub fn apply(list: &[Prefix], d: &Diff) -> Result<Vec<Prefix>, String> {
    // A reset starts from nothing; a diff removes the listed indices first.
    let mut next: Vec<Prefix> = if d.reset {
        Vec::new()
    } else {
        // Removal indices refer to the list as it was before the diff.
        let mut remove = d.removals.clone();
        remove.sort_unstable();
        remove.dedup();
        if remove.last().is_some_and(|&i| i as usize >= list.len()) {
            return Err("a removal index is past the end of the list".into());
        }
        // The sorted indices are walked along with the list.
        let mut r = remove.iter().peekable();
        list.iter()
            .enumerate()
            .filter(|(i, _)| {
                if r.peek().is_some_and(|&&x| x as usize == *i) {
                    r.next();
                    false
                } else {
                    true
                }
            })
            .map(|(_, p)| *p)
            .collect()
    };
    // The list is kept sorted and without duplicates, as the checksum requires.
    next.extend_from_slice(&d.additions);
    next.sort_unstable();
    next.dedup();
    // A list that does not match the answer's checksum is discarded whole.
    if checksum(&next).as_slice() != d.checksum.as_slice() {
        return Err("the list's checksum does not match after the update".into());
    }
    Ok(next)
}

/// A list ready for lookups: the prefixes grouped by length, each group one sorted flat array.
#[derive(Debug, Clone, Default)]
pub struct Lookup {
    /// Each prefix length with the prefixes of that length as one sorted flat array.
    groups: Vec<(usize, Vec<u8>)>,
    /// How many prefixes in all.
    entries: usize,
}

impl Lookup {
    /// A lookup over a list of prefixes.
    pub fn new(list: &[Prefix]) -> Self {
        let mut by_len: std::collections::BTreeMap<usize, Vec<&Prefix>> = Default::default();
        for p in list {
            by_len.entry(p.len as usize).or_default().push(p);
        }
        let groups = by_len
            .into_iter()
            .map(|(n, mut ps)| {
                ps.sort_unstable();
                (n, ps.iter().flat_map(|p| p.as_bytes().iter().copied()).collect())
            })
            .collect();
        Self { groups, entries: list.len() }
    }

    /// How many prefixes the list holds.
    pub fn len(&self) -> usize {
        self.entries
    }

    /// Whether the list holds none.
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// The local prefix a full hash starts with, if any (the shortest).
    pub fn matching(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        // Each prefix length is searched by bisection over its flat array.
        for (n, flat) in &self.groups {
            let want = &hash[..*n];
            let count = flat.len() / n;
            let (mut lo, mut hi) = (0usize, count);
            while lo < hi {
                let mid = (lo + hi) / 2;
                match flat[mid * n..(mid + 1) * n].cmp(want) {
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => hi = mid,
                    std::cmp::Ordering::Equal => return Some(want.to_vec()),
                }
            }
        }
        None
    }
}

// ── the API ────────────────────────────────────────────────────────────────────────────────────────────────────────

/// What `hashes.search` said about one prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Found {
    /// Full hashes on a list, their threat types and until when they may be taken as unsafe.
    pub threats: Vec<([u8; 32], Vec<String>, OffsetDateTime)>,
    /// Until when the prefix's other hashes may be taken as safe.
    pub negative_expire: Option<OffsetDateTime>,
}

/// The Web Risk Update API client.
#[derive(Clone)]
pub struct UpdateApi {
    /// The API key, sent as a query parameter as Web Risk asks.
    pub key: String,
    /// `https://webrisk.googleapis.com/v1` (a test points it at a stand-in).
    pub base: String,
    /// The HTTP client: no redirects, short timeouts.
    pub http: reqwest::Client,
}

/// Decode base64 in either alphabet, as Web Risk uses both.
fn b64(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok().or_else(|| URL_SAFE.decode(s).ok())
}

/// An RFC 3339 time from a JSON string.
fn time_of(v: &Value) -> Option<OffsetDateTime> {
    v.as_str().and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
}

/// Reads a `computeDiff` answer (uncompressed only).
pub fn parse_diff(v: &Value) -> Result<Diff, String> {
    // Only a reset and a diff are understood.
    let reset = match v["responseType"].as_str() {
        Some("RESET") => true,
        Some("DIFF") => false,
        other => return Err(format!("unexpected responseType {other:?}")),
    };
    // Compressed answers are refused, because only uncompressed ones were asked for.
    if !v["additions"]["riceHashes"].is_null() || !v["removals"]["riceIndices"].is_null() {
        return Err("a compressed answer, though only RAW was asked for".into());
    }
    let mut additions = Vec::new();
    for set in v["additions"]["rawHashes"].as_array().into_iter().flatten() {
        let size =
            set["prefixSize"].as_u64().filter(|n| (4..=32).contains(n)).ok_or("a prefixSize out of range")? as usize;
        // Each set is one prefix size and a run of prefixes of it.
        let raw = b64(set["rawHashes"].as_str().unwrap_or("")).ok_or("rawHashes is not base64")?;
        // A run that is not a whole number of prefixes is refused.
        if raw.len() % size != 0 {
            return Err("rawHashes is not a whole number of prefixes".into());
        }
        additions.extend(raw.chunks(size).filter_map(Prefix::new));
    }
    // The indices to remove from the list as it was.
    let removals = v["removals"]["rawIndices"]["indices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|i| i.as_u64().and_then(|i| u32::try_from(i).ok()).ok_or("a removal index is not a number"))
        .collect::<Result<Vec<u32>, _>>()?;
    let checksum =
        b64(v["checksum"]["sha256"].as_str().unwrap_or("")).filter(|c| c.len() == 32).ok_or("no checksum")?;
    // The answer as a value, with the next time Web Risk asked for.
    Ok(Diff {
        reset,
        additions,
        removals,
        new_version: v["newVersionToken"].as_str().unwrap_or("").to_string(),
        checksum,
        recommended_next: time_of(&v["recommendedNextDiff"]),
    })
}

/// Reads a `hashes.search` answer.
pub fn parse_found(v: &Value, now: OffsetDateTime) -> Result<Found, String> {
    let mut threats = Vec::new();
    for t in v["threats"].as_array().into_iter().flatten() {
        // A threat's hash must be 32 bytes of base64.
        let hash: [u8; 32] = b64(t["hash"].as_str().unwrap_or(""))
            .and_then(|h| h.try_into().ok())
            .ok_or("a threat hash is not 32 bytes of base64")?;
        let types: Vec<String> =
            t["threatTypes"].as_array().into_iter().flatten().filter_map(|x| x.as_str().map(String::from)).collect();
        // A threat with no expiry is taken as expiring now, so it is not cached.
        threats.push((hash, types, time_of(&t["expireTime"]).unwrap_or(now)));
    }
    Ok(Found { threats, negative_expire: time_of(&v["negativeExpireTime"]) })
}

impl UpdateApi {
    /// The address of Web Risk's API.
    pub const BASE: &'static str = "https://webrisk.googleapis.com/v1";

    /// A client for the Update API with the usual limits.
    pub fn new(key: String) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .user_agent(concat!("link-in-bio/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();
        Self { key, base: Self::BASE.into(), http }
    }

    /// A GET with the query and the key; failures give a fixed message that names the failure, never the address (which holds the key).
    async fn get(&self, path: &str, query: &[(&str, String)], max: usize) -> Result<Value, String> {
        // The base is configurable so a test can point it at a stand-in.
        let mut u = url::Url::parse(&format!("{}{path}", self.base)).map_err(|_| "the Web Risk base is not a URL")?;
        {
            let mut q = u.query_pairs_mut();
            for (k, v) in query {
                q.append_pair(k, v);
            }
            q.append_pair("key", &self.key);
        }
        let r = self.http.get(u).send().await.map_err(|e| {
            if e.is_timeout() { "Web Risk timed out".to_string() } else { "Web Risk unreachable".to_string() }
        })?;
        if !r.status().is_success() {
            return Err(format!("Web Risk answered HTTP {}", r.status().as_u16()));
        }
        let body = crate::read_limited(r, max).await.ok_or("Web Risk answered too much or broke off")?;
        serde_json::from_slice(&body).map_err(|_| "Web Risk answered something unreadable".to_string())
    }

    /// `threatLists.computeDiff` for one list from `version` (empty: the whole list), at most `max_entries` entries.
    pub async fn compute_diff(&self, threat: &str, version: &str, max_entries: u32) -> Result<Diff, String> {
        let mut q = vec![
            ("threatType", threat.to_string()),
            ("constraints.maxDiffEntries", max_entries.to_string()),
            ("constraints.maxDatabaseEntries", max_entries.to_string()),
            // Only uncompressed answers are asked for.
            ("constraints.supportedCompressions", "RAW".to_string()),
        ];
        // An empty version asks for the whole list.
        if !version.is_empty() {
            q.push(("versionToken", version.to_string()));
        }
        parse_diff(&self.get("/threatLists:computeDiff", &q, MAX_DIFF_BYTES).await?)
    }

    /// `hashes.search` for one local prefix, in every list screened against.
    pub async fn search_hashes(&self, prefix: &[u8], now: OffsetDateTime) -> Result<Found, String> {
        // The prefix in URL-safe base64, for every list screened against.
        let mut q = vec![("hashPrefix", URL_SAFE.encode(prefix))];
        q.extend(THREAT_TYPES.iter().map(|t| ("threatTypes", t.to_string())));
        parse_found(&self.get("/hashes:search", &q, MAX_SEARCH_BYTES).await?, now)
    }
}

/// The positive and negative caches of `hashes.search` answers, bounded.
#[derive(Debug, Default)]
pub struct HashCache {
    /// Full hashes on a list, with their types and until when.
    positive: HashMap<[u8; 32], (Vec<String>, OffsetDateTime)>,
    /// Prefixes whose other hashes are known safe, until when.
    negative: HashMap<Vec<u8>, OffsetDateTime>,
}

impl HashCache {
    /// The most entries in either cache.
    const MAX: usize = 20_000;

    /// An unexpired positive entry: the hash is on a list.
    pub fn unsafe_types(&self, hash: &[u8; 32], now: OffsetDateTime) -> Option<&[String]> {
        // Only an unexpired entry counts.
        self.positive.get(hash).filter(|(_, until)| *until > now).map(|(t, _)| t.as_slice())
    }

    /// An unexpired negative entry: no other hash with this prefix is on a list.
    pub fn safe(&self, prefix: &[u8], now: OffsetDateTime) -> bool {
        // Only an unexpired entry counts.
        self.negative.get(prefix).is_some_and(|until| *until > now)
    }

    /// Keep what an answer said. Expired entries are dropped when a cache is full, and the cache is emptied if that is not enough.
    pub fn record(&mut self, prefix: &[u8], f: &Found, now: OffsetDateTime) {
        // When a cache is full, expired entries go first; if that is not enough it is emptied.
        if self.positive.len() + f.threats.len() > Self::MAX {
            self.positive.retain(|_, (_, until)| *until > now);
            if self.positive.len() + f.threats.len() > Self::MAX {
                self.positive.clear();
            }
        }
        if self.negative.len() >= Self::MAX {
            self.negative.retain(|_, until| *until > now);
            if self.negative.len() >= Self::MAX {
                self.negative.clear();
            }
        }
        // What the answer said is a threat is remembered until its expiry.
        for (h, types, until) in &f.threats {
            self.positive.insert(*h, (types.clone(), *until));
        }
        // What it said is safe for the prefix is remembered until its expiry.
        if let Some(until) = f.negative_expire {
            self.negative.insert(prefix.to_vec(), until);
        }
    }
}

/// Unit tests against the published vectors of Google's specification.
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The canonical form of a URL as text.
    fn canon(s: &str) -> String {
        canonicalize(s).map(|c| c.as_url()).unwrap_or_default()
    }

    /// Every test vector of "URLs and hashing" (<https://cloud.google.com/web-risk/docs/urls-hashing>).
    #[test]
    fn canonicalisation_test_vectors() {
        let vectors: &[(&str, &str)] = &[
            // Repeated percent-unescaping, then the percent sign is escaped once.
            ("http://host/%25%32%35", "http://host/%25"),
            ("http://host/%25%32%35%25%32%35", "http://host/%25%25"),
            ("http://host/%2525252525252525", "http://host/%25"),
            ("http://host/asdf%25%32%35asd", "http://host/asdf%25asd"),
            ("http://host/%%%25%32%35asd%%", "http://host/%25%25%25asd%25%25"),
            // A URL that is already canonical is unchanged.
            ("http://www.google.com/", "http://www.google.com/"),
            (
                "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/",
                "http://168.188.99.26/.secure/www.ebay.com/",
            ),
            (
                "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
                "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
            ),
            (
                "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B",
                "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+",
            ),
            // A whole-number IP address is written as four decimals.
            ("http://3279880203/blah", "http://195.127.0.11/blah"),
            // Dot segments are resolved.
            ("http://www.google.com/blah/..", "http://www.google.com/"),
            // A missing scheme is taken as http.
            ("www.google.com/", "http://www.google.com/"),
            ("www.google.com", "http://www.google.com/"),
            // The fragment is removed.
            ("http://www.evil.com/blah#frag", "http://www.evil.com/blah"),
            // The host is lower-cased.
            ("http://www.GOOgle.com/", "http://www.google.com/"),
            // Trailing dots are removed.
            ("http://www.google.com.../", "http://www.google.com/"),
            // Tabs and line breaks are removed.
            ("http://www.google.com/foo\tbar\rbaz\n2", "http://www.google.com/foobarbaz2"),
            // An empty query is kept, and only the first question mark starts it.
            ("http://www.google.com/q?", "http://www.google.com/q?"),
            ("http://www.google.com/q?r?", "http://www.google.com/q?r?"),
            ("http://www.google.com/q?r?s", "http://www.google.com/q?r?s"),
            ("http://evil.com/foo#bar#baz", "http://evil.com/foo"),
            ("http://evil.com/foo;", "http://evil.com/foo;"),
            ("http://evil.com/foo?bar;", "http://evil.com/foo?bar;"),
            // An empty path becomes the root.
            ("http://notrailingslash.com", "http://notrailingslash.com/"),
            // The port is dropped.
            ("http://www.gotaport.com:1234/", "http://www.gotaport.com/"),
            // Surrounding spaces are removed.
            ("  http://www.google.com/  ", "http://www.google.com/"),
            // A space inside is escaped.
            ("http:// leadingspace.com/", "http://%20leadingspace.com/"),
            ("http://%20leadingspace.com/", "http://%20leadingspace.com/"),
            ("%20leadingspace.com/", "http://%20leadingspace.com/"),
            ("https://www.securesite.com/", "https://www.securesite.com/"),
            ("http://host.com/ab%23cd", "http://host.com/ab%23cd"),
            // Repeated slashes collapse in the path but not in the query.
            ("http://host.com//twoslashes?more//slashes", "http://host.com/twoslashes?more//slashes"),
        ];
        // Each vector is checked on its own, with the input named in any failure.
        for (input, want) in vectors {
            assert_eq!(&canon(input), want, "Canonicalize({input:?})");
        }
        // The spec's `\x01\x80` is two bytes, not UTF-8.
        // The specification's own byte example, which is not UTF-8.
        assert_eq!(canonicalize_bytes(b"http://\x01\x80.com/").unwrap().as_url(), "http://%01%80.com/");
    }

    /// The expressions of a URL, sorted.
    fn exprs(url: &str) -> Vec<String> {
        let mut e = expressions(&canonicalize(url).unwrap());
        e.sort();
        e
    }

    /// Strings sorted, to compare lists without caring about order.
    fn sorted(v: &[&str]) -> Vec<String> {
        let mut v: Vec<String> = v.iter().map(|s| s.to_string()).collect();
        v.sort();
        v
    }

    /// The specification's examples of host and path expressions, the limits on suffixes and prefixes, and the case of an IP address.
    #[test]
    fn the_spec_examples_of_expressions() {
        assert_eq!(
            // The specification's first example.
            exprs("http://a.b.c/1/2.html?param=1"),
            sorted(&[
                "a.b.c/1/2.html?param=1",
                "a.b.c/1/2.html",
                "a.b.c/",
                "a.b.c/1/",
                "b.c/1/2.html?param=1",
                "b.c/1/2.html",
                "b.c/",
                "b.c/1/",
            ])
        );
        assert_eq!(
            // Only the last five labels give suffixes.
            exprs("http://a.b.c.d.e.f.g/1.html"),
            sorted(&[
                "a.b.c.d.e.f.g/1.html",
                "a.b.c.d.e.f.g/",
                "c.d.e.f.g/1.html",
                "c.d.e.f.g/",
                "d.e.f.g/1.html",
                "d.e.f.g/",
                "e.f.g/1.html",
                "e.f.g/",
                "f.g/1.html",
                "f.g/",
            ])
        );
        // An IP address has no host suffixes.
        assert_eq!(exprs("http://1.2.3.4/1/"), sorted(&["1.2.3.4/1/", "1.2.3.4/"]));
        // At most four path prefixes and six paths.
        // A deep path still gives at most six paths.
        let deep = exprs("http://w.x.y/a/b/c/d/e/f.html?q=1");
        assert_eq!(deep.len(), 2 * 6, "two hosts, six paths");
        assert!(deep.contains(&"x.y/a/b/c/".to_string()) && !deep.contains(&"x.y/a/b/c/d/".to_string()));
    }

    /// SHA-256 gives the published values, so the hashing is the standard one.
    #[test]
    fn the_spec_hash_prefixes() {
        // The FIPS 180 examples: "abc", the two-block message and a million letters.
        let h: [u8; 32] = Sha256::digest(b"abc").into();
        assert_eq!(h[..4], [0xba, 0x78, 0x16, 0xbf]);
        let h: [u8; 32] = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").into();
        assert_eq!(h[..6], [0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06]);
        let h: [u8; 32] = Sha256::digest(vec![b'a'; 1_000_000]).into();
        assert_eq!(h[..12], [0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2]);
    }

    /// A prefix from bytes.
    fn p(b: &[u8]) -> Prefix {
        Prefix::new(b).unwrap()
    }

    /// A diff that adds, removes and expects the given list afterwards.
    fn diff(reset: bool, add: &[&[u8]], remove: &[u32], after: &[Prefix]) -> Diff {
        Diff {
            reset,
            additions: add.iter().map(|b| p(b)).collect(),
            removals: remove.to_vec(),
            new_version: "v".into(),
            checksum: checksum(after).to_vec(),
            recommended_next: None,
        }
    }

    /// A reset builds a sorted list, a diff removes by index and adds, a wrong checksum or an index past the end discards the diff, and the stored form round-trips.
    #[test]
    fn a_reset_then_a_diff_with_the_checksum_checked() {
        // The list expected after the reset.
        let after = vec![p(b"aaaa"), p(b"bbbb"), p(b"bbbbc"), p(b"cccc")];
        let list = apply(&[], &diff(true, &[b"cccc", b"aaaa", b"bbbbc", b"bbbb"], &[], &after)).unwrap();
        assert_eq!(list, after, "sorted, the shorter of two first");
        // Remove indices 0 and 2 (aaaa, bbbbc), add dddd.
        // The list expected after the diff.
        let want = vec![p(b"bbbb"), p(b"cccc"), p(b"dddd")];
        let next = apply(&list, &diff(false, &[b"dddd"], &[2, 0], &want)).unwrap();
        assert_eq!(next, want);
        // A wrong checksum discards the diff.
        // The same diff with a checksum that cannot match.
        let mut bad = diff(false, &[b"eeee"], &[], &want);
        bad.checksum = vec![0; 32];
        assert!(apply(&next, &bad).is_err());
        assert!(apply(&next, &diff(false, &[], &[3], &want)).is_err(), "an index past the end");
        assert_eq!(decode(&encode(&next)).unwrap(), next);
        assert!(decode(&[3, 1, 2, 3]).is_none(), "a prefix shorter than 4 bytes");
    }

    /// A lookup finds a prefix of any length that a hash starts with, and nothing for another hash.
    #[test]
    fn lookups_find_prefixes_of_any_length() {
        // A full hash whose five-byte prefix is on the list.
        let hash: [u8; 32] = Sha256::digest(b"evil.example/").into();
        let list = vec![p(&hash[..5]), p(b"zzzz"), p(b"\0\0\0\0")];
        // A lookup over prefixes of different lengths.
        let l = Lookup::new(&list);
        assert_eq!(l.matching(&hash), Some(hash[..5].to_vec()));
        // A hash no prefix starts.
        let other: [u8; 32] = Sha256::digest(b"fine.example/").into();
        assert_eq!(l.matching(&other), None);
        assert_eq!(l.len(), 3);
    }

    /// A computeDiff answer is read and applied, a compressed one is refused, and a hashes.search answer fills the cache both ways.
    #[test]
    fn answers_are_read() {
        // Two four-byte prefixes in one raw set.
        let raw = STANDARD.encode([b"aaaa".as_slice(), b"bbbb"].concat());
        let after = vec![p(b"aaaa"), p(b"bbbb")];
        let v = json!({
            "responseType": "RESET", "newVersionToken": "tok",
            "additions": { "rawHashes": [{ "prefixSize": 4, "rawHashes": raw }] },
            "checksum": { "sha256": STANDARD.encode(checksum(&after)) },
            "recommendedNextDiff": "2026-11-18T13:00:00.123456789Z",
        });
        // The answer reads as a reset with two additions.
        let d = parse_diff(&v).unwrap();
        assert!(d.reset && d.additions.len() == 2 && d.new_version == "tok");
        assert_eq!(apply(&[], &d).unwrap(), after);
        assert!(d.recommended_next.is_some());
        assert!(
            parse_diff(&json!({ "responseType": "DIFF", "additions": { "riceHashes": {} }, "checksum": {} })).is_err()
        );
        // A full hash for the search answer.
        let full: [u8; 32] = Sha256::digest(b"evil.example/").into();
        let now = OffsetDateTime::now_utc();
        let f = parse_found(
            &json!({ "threats": [{ "threatTypes": ["MALWARE"], "hash": URL_SAFE.encode(full), "expireTime": "2099-01-01T00:00:00Z" }],
                     "negativeExpireTime": "2099-01-01T00:00:00Z" }),
            now,
        )
        .unwrap();
        // Recording the answer fills both caches.
        let mut cache = HashCache::default();
        cache.record(&full[..4], &f, now);
        assert_eq!(cache.unsafe_types(&full, now), Some(["MALWARE".to_string()].as_slice()));
        assert!(cache.safe(&full[..4], now));
    }
}
