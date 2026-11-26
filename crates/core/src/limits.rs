//! Every bound the parser enforces, in one place. The editor reads them from `GET /api/v1/limits` (`limits_json`), so
//! the hints a person sees and the rules the server applies cannot disagree.

/// The most bytes a page document may be (64 KiB), checked before anything is parsed.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// The most characters in the display name.
pub const MAX_DISPLAY_NAME: usize = 64;
/// The most characters in a handle.
pub const MAX_HANDLE: usize = 30;
/// The most characters in the short bio.
pub const MAX_BIO: usize = 160;
/// The most characters in the pronouns field.
pub const MAX_PRONOUNS: usize = 24;
/// The most characters in a link's title.
pub const MAX_LINK_TITLE: usize = 80;
/// The most characters in a group's title.
pub const MAX_GROUP_TITLE: usize = 80;
/// The most characters in a link's description.
pub const MAX_LINK_DESCRIPTION: usize = 120;
/// The most links on one page.
pub const MAX_LINKS: usize = 60;
/// The most groups on one page.
pub const MAX_GROUPS: usize = 10;
/// The most characters in a link or group id.
pub const MAX_ID: usize = 36;
/// The most contact addresses on one page.
pub const MAX_CONTACTS: usize = 4;
/// The most support links on one page.
pub const MAX_SUPPORT: usize = 3;
/// The most characters in a label, such as a contact's or a support link's name.
pub const MAX_LABEL: usize = 40;
// The most bytes in a link target, owned by the URL rules and re-exported here so every limit is listed in one place.
pub use crate::safe_url::MAX_URL_BYTES;

/// Handles a tenant cannot take: hosts the service uses, roles people expect to be official, words that invite
/// impersonation, and the labels that mail clients, mail servers, DNS and browsers look up by name under a domain
/// (`autoconfig`, `autodiscover`, `mta-sts`, `wpad`, `smtp`, `ns1`, …), since every handle is a host name under the pages
/// domain. The operator's own page is exempt (its handle is set in its own configuration).
pub const RESERVED_HANDLES: &[&str] = &[
    "about",
    "abuse",
    "account",
    "accounts",
    "admin",
    "administrator",
    "api",
    "app",
    "apps",
    "assets",
    "auth",
    "autoconfig",
    "autodiscover",
    "billing",
    "blog",
    "cdn",
    "console",
    "contact",
    "dashboard",
    "dev",
    "docs",
    "edit",
    "editor",
    "email",
    "ftp",
    "help",
    "home",
    "hostmaster",
    "imap",
    "info",
    "invite",
    "invites",
    "isatap",
    "legal",
    "localhost",
    "login",
    "logout",
    "mail",
    "meddleware",
    "moderator",
    "mta-sts",
    "mx",
    "news",
    "noc",
    "ns",
    "ns1",
    "ns2",
    "official",
    "pay",
    "payments",
    "pop",
    "pop3",
    "postmaster",
    "privacy",
    "report",
    "root",
    "security",
    "settings",
    "shop",
    "signin",
    "signup",
    "smtp",
    "spec",
    "static",
    "status",
    "support",
    "system",
    "terms",
    "webmail",
    "webmaster",
    "well-known",
    "wpad",
    "www",
];

/// The confusable skeleton of a handle: what a reader may take it for. Handles are ASCII, so the confusions are the
/// lookalike digits and letter pairs (`rn` for `m`, `vv` for `w`, `0` for `o`, `1`/`i` for `l`, `5` for `s`) and the
/// hyphens a reader skims over. Two handles with one skeleton cannot both exist, and a tenant handle whose skeleton is
/// a reserved handle's is refused, so `rneddleware` cannot pass for `meddleware`.
pub fn handle_skeleton(handle: &str) -> String {
    // Hyphens are skimmed over, so they are dropped first; then the multi-letter lookalikes are folded, then the single characters.
    let mut s = handle.to_ascii_lowercase().replace('-', "");
    // Pairs of letters that look like one: `rn` as `m`, `vv` as `w`, `cl` as `d`.
    for (from, to) in [("rn", "m"), ("vv", "w"), ("cl", "d")] {
        s = s.replace(from, to);
    }
    s.chars()
        .map(|c| match c {
            // Single characters that look like another letter.
            '0' => 'o',
            '1' | 'i' | 'j' => 'l',
            '5' => 's',
            '8' => 'b',
            '9' => 'g',
            _ => c,
        })
        .collect()
}

/// Whether a tenant handle looks like a reserved one.
pub fn looks_reserved(handle: &str) -> bool {
    // The handle's skeleton is compared with each reserved name's skeleton.
    let k = handle_skeleton(handle);
    // A handle is reserved when its skeleton equals the skeleton of any reserved name, so a lookalike of a reserved name is refused too.
    RESERVED_HANDLES.iter().any(|r| handle_skeleton(r) == k)
}

/// Every limit, the reserved handles and the icon names as one JSON object, for `GET /api/v1/limits`.
pub fn limits_json() -> serde_json::Value {
    serde_json::json!({
        "manifestBytes": MAX_MANIFEST_BYTES,
        "displayName": MAX_DISPLAY_NAME,
        "handle": MAX_HANDLE,
        "bio": MAX_BIO,
        "pronouns": MAX_PRONOUNS,
        "linkTitle": MAX_LINK_TITLE,
        "groupTitle": MAX_GROUP_TITLE,
        "linkDescription": MAX_LINK_DESCRIPTION,
        "links": MAX_LINKS,
        "groups": MAX_GROUPS,
        "id": MAX_ID,
        "contacts": MAX_CONTACTS,
        "support": MAX_SUPPORT,
        "label": MAX_LABEL,
        "urlBytes": MAX_URL_BYTES,
        // The reserved list and the icon names are sent as they are, so the editor can warn before the server refuses.
        "reservedHandles": RESERVED_HANDLES,
        "icons": crate::icons::Icon::names(),
    })
}

/// Unit tests for the handle skeleton and the reserved list.
#[cfg(test)]
mod skeleton_tests {
    use super::*;

    /// Lookalike handles share a skeleton, the reserved names (including the ones other software looks up under a domain) are refused, and the list stays sorted without duplicates.
    #[test]
    fn skeletons() {
        // Lookalikes collapse to the same skeleton.
        assert_eq!(handle_skeleton("rneddleware"), handle_skeleton("meddleware"));
        assert_eq!(handle_skeleton("b0b-1"), handle_skeleton("bobl"));
        assert_ne!(handle_skeleton("alice"), handle_skeleton("bob"));
        assert!(looks_reserved("adrnin"));
        assert!(looks_reserved("supp0rt"));
        assert!(!looks_reserved("alice"));
        // The names other software looks up under the pages domain are not handles anyone can take.
        for h in ["autoconfig", "autodiscover", "mta-sts", "wpad", "smtp", "imap", "ns1", "webmail", "localhost"] {
            assert!(looks_reserved(h), "{h}");
            assert!(crate::manifest::check_handle(h, true).is_err(), "{h}");
        }
        // Sorted, so the list is easy to review, and free of duplicates.
        assert!(RESERVED_HANDLES.windows(2).all(|w| w[0] < w[1]), "sorted, no duplicates");
    }
}
