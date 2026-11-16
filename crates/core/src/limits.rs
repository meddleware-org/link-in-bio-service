//! Every bound the parser enforces, in one place. The editor reads them from `GET /api/v1/limits` (`limits_json`), so
//! the hints a person sees and the rules the server applies cannot disagree.

pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
pub const MAX_DISPLAY_NAME: usize = 64;
pub const MAX_HANDLE: usize = 30;
pub const MAX_BIO: usize = 160;
pub const MAX_PRONOUNS: usize = 24;
pub const MAX_LINK_TITLE: usize = 80;
pub const MAX_GROUP_TITLE: usize = 80;
pub const MAX_LINK_DESCRIPTION: usize = 120;
pub const MAX_LINKS: usize = 60;
pub const MAX_GROUPS: usize = 10;
pub const MAX_ID: usize = 36;
pub const MAX_CONTACTS: usize = 4;
pub const MAX_SUPPORT: usize = 3;
pub const MAX_LABEL: usize = 40;
pub use crate::safe_url::MAX_URL_BYTES;

/// Handles a tenant cannot take: hosts the service uses, roles people expect to be official, and words that invite
/// impersonation. The operator's own page is exempt (its handle is set in its own configuration).
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
    "help",
    "home",
    "hostmaster",
    "info",
    "invite",
    "invites",
    "legal",
    "login",
    "logout",
    "mail",
    "meddleware",
    "moderator",
    "news",
    "noc",
    "official",
    "pay",
    "payments",
    "postmaster",
    "privacy",
    "report",
    "root",
    "security",
    "settings",
    "shop",
    "signin",
    "signup",
    "spec",
    "static",
    "status",
    "support",
    "system",
    "terms",
    "webmaster",
    "well-known",
    "www",
];

/// The confusable skeleton of a handle: what a reader may take it for. Handles are ASCII, so the confusions are the
/// lookalike digits and letter pairs (`rn` for `m`, `vv` for `w`, `0` for `o`, `1`/`i` for `l`, `5` for `s`) and the
/// hyphens a reader skims over. Two handles with one skeleton cannot both exist, and a tenant handle whose skeleton is
/// a reserved handle's is refused, so `rneddleware` cannot pass for `meddleware`.
pub fn handle_skeleton(handle: &str) -> String {
    let mut s = handle.to_ascii_lowercase().replace('-', "");
    for (from, to) in [("rn", "m"), ("vv", "w"), ("cl", "d")] {
        s = s.replace(from, to);
    }
    s.chars()
        .map(|c| match c {
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
    let k = handle_skeleton(handle);
    RESERVED_HANDLES.iter().any(|r| handle_skeleton(r) == k)
}

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
        "reservedHandles": RESERVED_HANDLES,
        "icons": crate::icons::Icon::names(),
    })
}

#[cfg(test)]
mod skeleton_tests {
    use super::*;

    #[test]
    fn skeletons() {
        assert_eq!(handle_skeleton("rneddleware"), handle_skeleton("meddleware"));
        assert_eq!(handle_skeleton("b0b-1"), handle_skeleton("bobl"));
        assert_ne!(handle_skeleton("alice"), handle_skeleton("bob"));
        assert!(looks_reserved("adrnin"));
        assert!(looks_reserved("supp0rt"));
        assert!(!looks_reserved("alice"));
    }
}
