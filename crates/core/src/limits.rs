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
