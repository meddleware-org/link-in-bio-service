//! How much one account may change its page ([`AccountLimits`], `ACCOUNT_LIMITS`): changes (publishes and picture
//! uploads, one shared count) an hour, and links a published page did not have before, a day, counted in `lib.counters` by UTC hour and day.
//!
//! Removing or hiding links and unpublishing are never limited: a publish whose only differences from the published
//! page are links removed or hidden ([`only_removes`]) is always accepted, past every budget, so nobody is ever stuck
//! showing a link. Over a limit the answer is 429 with the limit, when it resets and `Retry-After`; the draft is kept.

use std::collections::BTreeSet;

use time::{Duration, OffsetDateTime, Time, UtcOffset};
use uuid::Uuid;

use link_in_bio_core::Manifest;
use link_in_bio_core::manifest::Item;

use super::Shared;
use super::config::AccountLimits;
use super::error::{ApiError, ApiResult};

/// Everything but links that are hidden.
fn shown(m: &Manifest) -> Manifest {
    let mut m = m.clone();
    m.items = m
        .items
        .into_iter()
        .filter_map(|i| match i {
            Item::Link(l) if l.hidden => None,
            Item::Group(mut g) => {
                g.items.retain(|l| !l.hidden);
                Some(Item::Group(g))
            }
            other => Some(other),
        })
        .collect();
    m
}

/// Whether `new` keeps `old`'s order and only leaves things out.
fn subsequence<T>(new: &[T], old: &[T], same: impl Fn(&T, &T) -> bool) -> bool {
    let mut rest = old.iter();
    new.iter().all(|n| rest.by_ref().any(|o| same(n, o)))
}

/// Whether `new` differs from the published `old` only by links removed or hidden (and contact entries removed).
pub fn only_removes(old: &Manifest, new: &Manifest) -> bool {
    let (o, n) = (shown(old), shown(new));
    let rest = |m: &Manifest| {
        let mut m = m.clone();
        m.items.clear();
        m.contact.clear();
        m
    };
    if rest(&o) != rest(&n) {
        return false;
    }
    let same_item = |a: &Item, b: &Item| match (a, b) {
        (Item::Link(x), Item::Link(y)) => x == y,
        (Item::Group(x), Item::Group(y)) => {
            x.id == y.id && x.title == y.title && x.open == y.open && subsequence(&x.items, &y.items, |p, q| p == q)
        }
        _ => false,
    };
    subsequence(&n.contact, &o.contact, |a, b| a == b) && subsequence(&n.items, &o.items, same_item)
}

/// The shown links' URLs in `new` that `old` (the published page, if any) did not show.
pub fn new_urls(old: Option<&Manifest>, new: &Manifest) -> BTreeSet<String> {
    let before: BTreeSet<&str> = old.map(|o| o.visible_links().map(|l| l.url.as_str()).collect()).unwrap_or_default();
    new.visible_links().map(|l| l.url.as_str()).filter(|u| !before.contains(u)).map(String::from).collect()
}

/// The UTC hour a publish is counted in (`2026-11-18T13`).
pub fn hour(now: OffsetDateTime) -> String {
    let t = now.to_offset(UtcOffset::UTC);
    format!("{}T{:02}", link_in_bio_store::day(t), t.hour())
}

/// When the current UTC hour or day ends.
pub fn next_hour(now: OffsetDateTime) -> OffsetDateTime {
    let t = now.to_offset(UtcOffset::UTC);
    t.replace_time(Time::from_hms(t.hour(), 0, 0).unwrap_or(Time::MIDNIGHT)) + Duration::HOUR
}

pub fn next_day(now: OffsetDateTime) -> OffsetDateTime {
    let t = now.to_offset(UtcOffset::UTC);
    t.replace_time(Time::MIDNIGHT) + Duration::DAY
}

fn wait(now: OffsetDateTime, until: OffsetDateTime) -> (u64, String) {
    let secs = (until - now).whole_seconds().max(1) as u64;
    let words = if secs < 3600 {
        format!("in {} minute(s)", secs.div_ceil(60))
    } else {
        format!("in about {} hour(s)", secs.div_ceil(3600))
    };
    (secs, format!("{:02}:00 UTC ({words})", until.hour()))
}

/// What is taken for one publish: `(name, period, by, cap)`, the publish itself and its new links, leaving out a
/// limit of 0 (none).
pub fn takes(
    limits: &AccountLimits,
    account: Uuid,
    new_links: usize,
    now: OffsetDateTime,
) -> Vec<(String, String, i64, i64)> {
    let mut t = Vec::new();
    if limits.changes_per_hour > 0 {
        t.push((format!("changes:{account}"), hour(now), 1, limits.changes_per_hour));
    }
    if limits.new_links_per_day > 0 && new_links > 0 {
        t.push((
            format!("new-links:{account}"),
            link_in_bio_store::day(now),
            new_links as i64,
            limits.new_links_per_day,
        ));
    }
    t
}

/// The refusal for the take at `index` of [`takes`].
pub fn refusal(take: &(String, String, i64, i64), used: i64, now: OffsetDateTime, upload: bool) -> ApiError {
    let (name, _, by, cap) = take;
    if name.starts_with("changes:") {
        let (secs, when) = wait(now, next_hour(now));
        let what = if upload { "This picture upload is refused: you" } else { "You" };
        ApiError::TooMany {
            message: format!(
                "{what} have made {used} changes (publishes and picture uploads) this hour, the most an account may \
                 (CHANGES_PER_ACCOUNT_HOUR = {cap}). You can make more from {when}. Your draft is kept; removing or \
                 hiding links, and unpublishing, are always possible."
            ),
            retry_after: secs,
        }
    } else {
        let (secs, when) = wait(now, next_day(now));
        let left = (cap - used).max(0);
        ApiError::TooMany {
            message: format!(
                "This publish adds {by} link(s) your page did not have; an account may add {cap} a day \
                 (NEW_LINKS_PER_ACCOUNT_DAY) and you have {left} left today. You can add more from {when}. Your \
                 draft is kept; removing or hiding links, and unpublishing, are always possible."
            ),
            retry_after: secs,
        }
    }
}

/// Takes a publish (or, with `upload`, a picture upload) and its new links from the account's budgets, all or none.
pub async fn take(app: &Shared, account: Uuid, new_links: usize, upload: bool, now: OffsetDateTime) -> ApiResult<()> {
    let t = takes(&app.config.account_limits, account, new_links, now);
    if t.is_empty() {
        return Ok(());
    }
    match app.store.take_from_counters(&t).await? {
        None => Ok(()),
        Some(i) => {
            let used = app.store.counter(&t[i].0, &t[i].1).await?;
            Err(refusal(&t[i], used, now, upload))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn page(links: &str) -> Manifest {
        let doc = format!(r#"{{"schema":1,"identity":{{"displayName":"Alice","handle":"alice"}},"items":[{links}]}}"#);
        link_in_bio_core::parse(doc.as_bytes(), super::super::account_page_options()).unwrap().manifest
    }

    const A: &str = r#"{"kind":"link","id":"a","title":"A","url":"https://a.example/"}"#;
    const B: &str = r#"{"kind":"link","id":"b","title":"B","url":"https://b.example/"}"#;
    const C: &str = r#"{"kind":"link","id":"c","title":"C","url":"https://c.example/"}"#;
    const B_HIDDEN: &str = r#"{"kind":"link","id":"b","title":"B","url":"https://b.example/","hidden":true}"#;

    #[test]
    fn removing_or_hiding_links_is_only_removing() {
        let old = page(&[A, B, C].join(","));
        assert!(only_removes(&old, &page(&[A, C].join(","))), "one removed");
        assert!(only_removes(&old, &page(&[A, B_HIDDEN, C].join(","))), "one hidden");
        assert!(only_removes(&old, &page("")), "all removed");
        assert!(only_removes(&old, &old), "nothing changed");
        assert!(!only_removes(&old, &page(&[C, A].join(","))), "reordered");
        let d = r#"{"kind":"link","id":"d","title":"D","url":"https://d.example/"}"#;
        assert!(!only_removes(&old, &page(&[A, B, C, d].join(","))), "added");
        let retitled = r#"{"kind":"link","id":"a","title":"A2","url":"https://a.example/"}"#;
        assert!(!only_removes(&old, &page(&[retitled, B, C].join(","))), "changed");
        // Showing a hidden link again is adding it.
        let hidden = page(&[A, B_HIDDEN].join(","));
        assert!(!only_removes(&hidden, &page(&[A, B].join(","))));
        let grouped = |items: &str| page(&format!(r#"{{"kind":"group","id":"g","title":"G","items":[{items}]}}"#));
        assert!(only_removes(&grouped(&[A, B].join(",")), &grouped(B)), "removed from a group");
        assert!(!only_removes(&grouped(B), &grouped(&[A, B].join(","))));
    }

    #[test]
    fn new_links_are_those_the_published_page_did_not_show() {
        let old = page(&[A, B_HIDDEN].join(","));
        let new = page(&[A, B, C].join(","));
        let n = new_urls(Some(&old), &new);
        assert_eq!(n.into_iter().collect::<Vec<_>>(), vec!["https://b.example/", "https://c.example/"]);
        assert_eq!(new_urls(None, &new).len(), 3, "a first publish: every link is new");
    }

    #[test]
    fn budgets_and_their_resets() {
        let now = datetime!(2026-11-18 13:37:10 UTC);
        assert_eq!(hour(now), "2026-11-18T13");
        assert_eq!(next_hour(now), datetime!(2026-11-18 14:00 UTC));
        assert_eq!(next_day(now), datetime!(2026-11-19 00:00 UTC));
        let limits = AccountLimits {
            preset: super::super::LimitsPreset::Standard,
            changes_per_hour: 30,
            new_links_per_day: 120,
        };
        let id = Uuid::nil();
        let t = takes(&limits, id, 7, now);
        assert_eq!(t.len(), 2);
        assert_eq!(t[1], (format!("new-links:{id}"), "2026-11-18".to_string(), 7, 120));
        assert_eq!(takes(&limits, id, 0, now).len(), 1, "no new link, nothing to take for them");
        let off = AccountLimits { changes_per_hour: 0, new_links_per_day: 0, ..limits };
        assert!(takes(&off, id, 7, now).is_empty(), "0 means no limit");
        match refusal(&t[0], 30, now, false) {
            ApiError::TooMany { message, retry_after } => {
                assert_eq!(retry_after, 22 * 60 + 50);
                assert!(
                    message.contains("CHANGES_PER_ACCOUNT_HOUR = 30")
                        && message.contains("changes (publishes and picture uploads)")
                        && message.contains("14:00 UTC")
                );
            }
            e => panic!("{e:?}"),
        }
        match refusal(&t[1], 118, now, false) {
            ApiError::TooMany { message, retry_after } => {
                assert_eq!(retry_after, (datetime!(2026-11-19 00:00 UTC) - now).whole_seconds() as u64);
                assert!(message.contains("you have 2 left today") && message.contains("00:00 UTC"));
            }
            e => panic!("{e:?}"),
        }
    }
}
