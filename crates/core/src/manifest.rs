//! The manifest (schema 1): the document a page is made from, and its hand-written parser, the trust boundary.
//!
//! Rules: unknown fields are dropped (and reported as warnings); every string is normalised and bounded
//! (`crate::text`); links are `https:` or `mailto:` only (`crate::safe_url`); a theme that fails the contrast checks
//! is refused; nothing else gets through. The parser never panics on any input (property-tested).

use serde::Serialize;
use serde_json::{Map, Value};

use crate::issue::{Issue, Issues, join};
use crate::limits::*;
use crate::safe_url::{self, UrlKind};
use crate::text::clean_line;
use crate::theme::{self, Accent, Buttons, ColorMode, Density, Font, Layout, Radius, Season, Theme};

pub const SCHEMA: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Person,
    Organization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub kind: Kind,
    pub display_name: String,
    pub handle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    /// A file name in the page's asset directory (static and local modes) or `sha256:<hex>` (hosted mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atproto_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<crate::icons::Icon>,
    /// One of the person's own profiles: rendered with `rel="me"`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub identity: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    pub items: Vec<Link>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Item {
    Link(Link),
    Group(Group),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub label: String,
    pub url: String,
}

/// A way for visitors to support the person. Display only: no widget, no script, no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SupportMethod {
    SuiAddress {
        address: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

/// The operator's own call to action (for example "make your own page"). Refused on tenant pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cta {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The button's words (default "Find out more").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub lang: String,
    pub indexable: bool,
}

impl Default for Meta {
    fn default() -> Self {
        Self { lang: "en".into(), indexable: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub schema: u64,
    pub identity: Identity,
    pub items: Vec<Item>,
    pub theme: Theme,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<Contact>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub support: Vec<SupportMethod>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cta: Option<Cta>,
    pub meta: Meta,
}

impl Manifest {
    /// Every visible link, groups flattened, in page order.
    pub fn visible_links(&self) -> impl Iterator<Item = &Link> {
        self.items
            .iter()
            .flat_map(|i| match i {
                Item::Link(l) => std::slice::from_ref(l).iter(),
                Item::Group(g) => g.items.iter(),
            })
            .filter(|l| !l.hidden)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Who the page belongs to: the operator's own page may carry a call to action and an SVG avatar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Owner {
    #[default]
    Tenant,
    Operator,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    pub owner: Owner,
    /// Tenant handles may not be on the reserved list; the operator chooses theirs freely.
    pub check_reserved: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Parsed {
    pub manifest: Manifest,
    pub warnings: Vec<Issue>,
}

/// Parses manifest bytes. On success returns the manifest and any warnings; on failure every error found.
pub fn parse(bytes: &[u8], opts: ParseOptions) -> Result<Parsed, Vec<Issue>> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(vec![Issue::new(
            "",
            "too_large",
            format!("The page document is too large: at most {} KiB.", MAX_MANIFEST_BYTES / 1024),
        )]);
    }
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return Err(vec![Issue::new("", "not_json", "This is not a valid page document (JSON).")]),
    };
    parse_value(&value, opts)
}

pub fn parse_value(value: &Value, opts: ParseOptions) -> Result<Parsed, Vec<Issue>> {
    let mut is = Issues::default();
    let Some(root) = value.as_object() else {
        return Err(vec![Issue::new("", "not_object", "The page document must be a JSON object.")]);
    };
    let known = ["schema", "identity", "items", "theme", "contact", "support", "cta", "meta"];
    unknown_fields(root, "", &known, &mut is);

    match root.get("schema").and_then(Value::as_u64) {
        Some(SCHEMA) => {}
        Some(n) => is.error(
            "schema",
            "unsupported_schema",
            format!("Schema {n} is not supported; this version reads schema {SCHEMA}."),
        ),
        None => is.error("schema", "missing", format!("The document must say \"schema\": {SCHEMA}.")),
    }

    let identity = parse_identity(root.get("identity"), opts, &mut is);
    let items = parse_items(root.get("items"), &mut is);
    let theme = parse_theme(root.get("theme"), &mut is);
    let contact = parse_contact(root.get("contact"), &mut is);
    let support = parse_support(root.get("support"), &mut is);
    let cta = match root.get("cta") {
        None | Some(Value::Null) => None,
        Some(v) if opts.owner == Owner::Operator => parse_cta(v, &mut is),
        Some(_) => {
            is.warn("cta", "dropped", "A call to action is only available on the operator's page; it was removed.");
            None
        }
    };
    let meta = parse_meta(root.get("meta"), &mut is);

    if !is.errors.is_empty() {
        return Err(is.errors);
    }
    let (Some(identity), Some(theme)) = (identity, theme) else {
        return Err(vec![Issue::new("", "invalid", "The page document is not valid.")]);
    };
    Ok(Parsed {
        manifest: Manifest { schema: SCHEMA, identity, items, theme, contact, support, cta, meta },
        warnings: is.warnings,
    })
}

fn unknown_fields(obj: &Map<String, Value>, path: &str, known: &[&str], is: &mut Issues) {
    for k in obj.keys() {
        if !known.contains(&k.as_str()) {
            let key: String = k.chars().take(40).collect();
            is.warn(&join(path, &key), "unknown_field", "This field is not part of the page document; it was removed.");
        }
    }
}

fn object<'a>(v: Option<&'a Value>, path: &str, required: bool, is: &mut Issues) -> Option<&'a Map<String, Value>> {
    match v {
        Some(Value::Object(m)) => Some(m),
        None | Some(Value::Null) if !required => None,
        None | Some(Value::Null) => {
            is.error(path, "missing", "This is required.");
            None
        }
        Some(_) => {
            is.error(path, "wrong_type", "This must be an object.");
            None
        }
    }
}

/// A required or optional single-line string field.
fn line(
    obj: &Map<String, Value>,
    key: &str,
    path: &str,
    max: usize,
    required: bool,
    is: &mut Issues,
) -> Option<String> {
    let p = join(path, key);
    match obj.get(key) {
        None | Some(Value::Null) => {
            if required {
                is.error(&p, "missing", "This is required.");
            }
            None
        }
        Some(Value::String(s)) => match clean_line(s, max, !required) {
            Ok(s) if s.is_empty() => None,
            Ok(s) => Some(s),
            Err(e) => {
                is.error(&p, e.code(), e.message());
                None
            }
        },
        Some(_) => {
            is.error(&p, "wrong_type", "This must be text.");
            None
        }
    }
}

fn boolean(obj: &Map<String, Value>, key: &str, path: &str, default: bool, is: &mut Issues) -> bool {
    match obj.get(key) {
        None | Some(Value::Null) => default,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            is.error(&join(path, key), "wrong_type", "This must be true or false.");
            default
        }
    }
}

fn parse_identity(v: Option<&Value>, opts: ParseOptions, is: &mut Issues) -> Option<Identity> {
    let o = object(v, "identity", true, is)?;
    unknown_fields(
        o,
        "identity",
        &["kind", "displayName", "handle", "bio", "pronouns", "avatar", "atprotoDid", "nostrPubkey"],
        is,
    );
    let kind = match o.get("kind").and_then(Value::as_str) {
        None => Kind::Person,
        Some("person") => Kind::Person,
        Some("organization") => Kind::Organization,
        Some(_) => {
            is.error("identity/kind", "invalid_option", "Choose \"person\" or \"organization\".");
            Kind::Person
        }
    };
    let display_name = line(o, "displayName", "identity", MAX_DISPLAY_NAME, true, is);
    let handle = match o.get("handle").and_then(Value::as_str) {
        Some(h) => match check_handle(h, opts.check_reserved) {
            Ok(h) => Some(h),
            Err((code, msg)) => {
                is.error("identity/handle", code, msg);
                None
            }
        },
        None => {
            is.error("identity/handle", "missing", "This is required.");
            None
        }
    };
    let bio = line(o, "bio", "identity", MAX_BIO, false, is);
    let pronouns = line(o, "pronouns", "identity", MAX_PRONOUNS, false, is);
    let avatar = match o.get("avatar") {
        None | Some(Value::Null) => None,
        Some(Value::String(a)) if is_asset_ref(a, opts.owner) => Some(a.clone()),
        Some(_) => {
            is.error("identity/avatar", "avatar_invalid", "The picture must be an uploaded image.");
            None
        }
    };
    let atproto_did = match o.get("atprotoDid").and_then(Value::as_str) {
        None => None,
        Some(d) if is_did(d) => Some(d.to_string()),
        Some(_) => {
            is.error("identity/atprotoDid", "did_invalid", "This must be a Bluesky DID (did:plc:… or did:web:…).");
            None
        }
    };
    let nostr_pubkey = match o.get("nostrPubkey").and_then(Value::as_str) {
        None => None,
        Some(k) if k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()) => Some(k.to_ascii_lowercase()),
        Some(_) => {
            is.error(
                "identity/nostrPubkey",
                "nostr_key_invalid",
                "This must be a Nostr public key in hex (64 characters).",
            );
            None
        }
    };
    Some(Identity {
        kind,
        display_name: display_name?,
        handle: handle?,
        bio,
        pronouns,
        avatar,
        atproto_did,
        nostr_pubkey,
    })
}

/// Handles: 1–30 of `a-z 0-9 -`, starting and ending with a letter or digit, no `--` in third and fourth place
/// (which would look like a punycode label), and, for tenants, not on the reserved list.
pub fn check_handle(h: &str, check_reserved: bool) -> Result<String, (&'static str, String)> {
    let h = h.trim().to_ascii_lowercase();
    let valid = (1..=MAX_HANDLE).contains(&h.len())
        && h.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !h.starts_with('-')
        && !h.ends_with('-');
    if !valid {
        return Err((
            "handle_invalid",
            format!(
                "A handle is 1 to {MAX_HANDLE} lowercase letters, digits or hyphens, and cannot start or end with a hyphen."
            ),
        ));
    }
    if h.len() >= 4 && &h[2..4] == "--" {
        return Err(("handle_invalid", "A handle cannot have two hyphens in the third and fourth place.".into()));
    }
    if check_reserved && RESERVED_HANDLES.contains(&h.as_str()) {
        return Err(("handle_reserved", "This handle is reserved. Choose another.".into()));
    }
    Ok(h)
}

fn is_asset_ref(a: &str, owner: Owner) -> bool {
    if let Some(hex) = a.strip_prefix("sha256:") {
        return hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    }
    let name_ok = (1..=64).contains(&a.len())
        && a.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && a.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !a.contains("..");
    let ext_ok = [".png", ".jpg", ".jpeg", ".webp", ".gif"].iter().any(|e| a.ends_with(e))
        || (owner == Owner::Operator && a.ends_with(".svg"));
    name_ok && ext_ok
}

fn is_did(d: &str) -> bool {
    if let Some(id) = d.strip_prefix("did:plc:") {
        return id.len() == 24 && id.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    }
    if let Some(host) = d.strip_prefix("did:web:") {
        return (3..=253).contains(&host.len())
            && host.contains('.')
            && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    }
    false
}

fn check_id(v: Option<&Value>, path: &str, seen: &mut Vec<String>, is: &mut Issues) -> Option<String> {
    let p = join(path, "id");
    let Some(id) = v.and_then(Value::as_str) else {
        is.error(&p, "missing", "Every link and group needs an id.");
        return None;
    };
    if !(1..=MAX_ID).contains(&id.len()) || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        is.error(&p, "id_invalid", format!("An id is 1 to {MAX_ID} letters, digits, hyphens or underscores."));
        return None;
    }
    if seen.iter().any(|s| s == id) {
        is.error(&p, "id_duplicate", "Two items have the same id.");
        return None;
    }
    seen.push(id.to_string());
    Some(id.to_string())
}

fn parse_link(v: &Value, path: &str, seen: &mut Vec<String>, is: &mut Issues) -> Option<Link> {
    let Some(o) = v.as_object() else {
        is.error(path, "wrong_type", "A link must be an object.");
        return None;
    };
    unknown_fields(o, path, &["kind", "id", "title", "url", "description", "icon", "identity", "hidden"], is);
    let id = check_id(o.get("id"), path, seen, is);
    let title = line(o, "title", path, MAX_LINK_TITLE, true, is);
    let url = match o.get("url").and_then(Value::as_str) {
        Some(u) => match safe_url::check_link(u) {
            Ok((u, _)) => Some(u),
            Err(e) => {
                is.error(&join(path, "url"), e.code(), e.message());
                None
            }
        },
        None => {
            is.error(&join(path, "url"), "missing", "Every link needs a web address.");
            None
        }
    };
    let description = line(o, "description", path, MAX_LINK_DESCRIPTION, false, is);
    let icon = match o.get("icon").and_then(Value::as_str) {
        None => None,
        Some(name) => match crate::icons::Icon::parse(name) {
            Some(i) => Some(i),
            None => {
                is.warn(&join(path, "icon"), "icon_unknown", "This icon is not available; the link shows without one.");
                None
            }
        },
    };
    let identity = boolean(o, "identity", path, false, is);
    let hidden = boolean(o, "hidden", path, false, is);
    if identity && url.as_deref().is_some_and(|u| u.starts_with("mailto:")) {
        is.error(
            &join(path, "identity"),
            "identity_mailto",
            "Only web profiles can be marked as yours, not email links.",
        );
    }
    Some(Link { id: id?, title: title?, url: url?, description, icon, identity, hidden })
}

fn parse_items(v: Option<&Value>, is: &mut Issues) -> Vec<Item> {
    let arr = match v {
        None | Some(Value::Null) => return Vec::new(),
        Some(Value::Array(a)) => a,
        Some(_) => {
            is.error("items", "wrong_type", "This must be a list.");
            return Vec::new();
        }
    };
    let mut seen = Vec::new();
    let mut out = Vec::new();
    let (mut links, mut groups) = (0usize, 0usize);
    for (i, item) in arr.iter().enumerate() {
        let path = join("items", i);
        let kind = item.get("kind").and_then(Value::as_str).unwrap_or("link");
        match kind {
            "link" => {
                links += 1;
                if let Some(l) = parse_link(item, &path, &mut seen, is) {
                    out.push(Item::Link(l));
                }
            }
            "group" => {
                groups += 1;
                let Some(o) = item.as_object() else { continue };
                unknown_fields(o, &path, &["kind", "id", "title", "open", "items"], is);
                let id = check_id(o.get("id"), &path, &mut seen, is);
                let title = line(o, "title", &path, MAX_GROUP_TITLE, true, is);
                let open = boolean(o, "open", &path, false, is);
                let mut inner = Vec::new();
                match o.get("items") {
                    Some(Value::Array(a)) => {
                        for (j, l) in a.iter().enumerate() {
                            let lp = join(&join(&path, "items"), j);
                            if l.get("kind").and_then(Value::as_str).is_some_and(|k| k != "link") {
                                is.error(&lp, "nested_group", "Groups can hold links only, not other groups.");
                                continue;
                            }
                            links += 1;
                            if let Some(l) = parse_link(l, &lp, &mut seen, is) {
                                inner.push(l);
                            }
                        }
                    }
                    _ => is.error(&join(&path, "items"), "missing", "A group needs a list of links."),
                }
                if let (Some(id), Some(title)) = (id, title) {
                    out.push(Item::Group(Group { id, title, open, items: inner }));
                }
            }
            _ => is.error(&join(&path, "kind"), "invalid_option", "An item is either a \"link\" or a \"group\"."),
        }
    }
    if links > MAX_LINKS {
        is.error("items", "too_many_links", format!("A page can have at most {MAX_LINKS} links."));
    }
    if groups > MAX_GROUPS {
        is.error("items", "too_many_groups", format!("A page can have at most {MAX_GROUPS} groups."));
    }
    out
}

fn parse_theme(v: Option<&Value>, is: &mut Issues) -> Option<Theme> {
    let mut t = Theme::default();
    let Some(o) = object(v, "theme", false, is) else { return Some(t) };
    unknown_fields(
        o,
        "theme",
        &["colorMode", "season", "accent", "buttons", "radius", "density", "layout", "font"],
        is,
    );
    fn opt<T: Copy>(
        o: &Map<String, Value>,
        key: &str,
        parse: fn(&str) -> Option<T>,
        names: Vec<&'static str>,
        slot: &mut T,
        is: &mut Issues,
    ) {
        match o.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::String(s)) => match parse(s) {
                Some(v) => *slot = v,
                None => {
                    is.error(&join("theme", key), "invalid_option", format!("Choose one of: {}.", names.join(", ")))
                }
            },
            Some(_) => is.error(&join("theme", key), "wrong_type", "This must be text."),
        }
    }
    opt(o, "colorMode", ColorMode::parse, ColorMode::names(), &mut t.color_mode, is);
    opt(o, "season", Season::parse, Season::names(), &mut t.season, is);
    opt(o, "accent", Accent::parse, Accent::names(), &mut t.accent, is);
    opt(o, "buttons", Buttons::parse, Buttons::names(), &mut t.buttons, is);
    opt(o, "radius", Radius::parse, Radius::names(), &mut t.radius, is);
    opt(o, "density", Density::parse, Density::names(), &mut t.density, is);
    opt(o, "layout", Layout::parse, Layout::names(), &mut t.layout, is);
    opt(o, "font", Font::parse, Font::names(), &mut t.font, is);
    if let Err(failures) = theme::check(&t) {
        for f in failures {
            is.error("theme", "contrast", f.message);
        }
        return None;
    }
    Some(t)
}

fn list<'a>(v: Option<&'a Value>, path: &str, max: usize, is: &mut Issues) -> &'a [Value] {
    match v {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) if a.len() <= max => a,
        Some(Value::Array(_)) => {
            is.error(path, "too_many", format!("At most {max} entries."));
            &[]
        }
        Some(_) => {
            is.error(path, "wrong_type", "This must be a list.");
            &[]
        }
    }
}

fn parse_contact(v: Option<&Value>, is: &mut Issues) -> Vec<Contact> {
    let mut out = Vec::new();
    for (i, c) in list(v, "contact", MAX_CONTACTS, is).iter().enumerate() {
        let path = join("contact", i);
        let Some(o) = c.as_object() else {
            is.error(&path, "wrong_type", "This must be an object.");
            continue;
        };
        unknown_fields(o, &path, &["label", "url"], is);
        let label = line(o, "label", &path, MAX_LABEL, true, is);
        let url = match o.get("url").and_then(Value::as_str).map(safe_url::check_link) {
            Some(Ok((u, UrlKind::Mailto))) => Some(u),
            Some(Ok(_)) => {
                is.error(&join(&path, "url"), "mailto_required", "A contact is an email link (mailto:).");
                None
            }
            Some(Err(e)) => {
                is.error(&join(&path, "url"), e.code(), e.message());
                None
            }
            None => {
                is.error(&join(&path, "url"), "missing", "This is required.");
                None
            }
        };
        if let (Some(label), Some(url)) = (label, url) {
            out.push(Contact { label, url });
        }
    }
    out
}

fn parse_support(v: Option<&Value>, is: &mut Issues) -> Vec<SupportMethod> {
    let mut out = Vec::new();
    for (i, s) in list(v, "support", MAX_SUPPORT, is).iter().enumerate() {
        let path = join("support", i);
        let Some(o) = s.as_object() else {
            is.error(&path, "wrong_type", "This must be an object.");
            continue;
        };
        match o.get("kind").and_then(Value::as_str) {
            Some("sui-address") => {
                unknown_fields(o, &path, &["kind", "address", "label"], is);
                let label = line(o, "label", &path, MAX_LABEL, false, is);
                match o.get("address").and_then(Value::as_str).and_then(normalise_sui_address) {
                    Some(address) => out.push(SupportMethod::SuiAddress { address, label }),
                    None => is.error(
                        &join(&path, "address"),
                        "address_invalid",
                        "A Sui address is 0x followed by 64 hexadecimal characters.",
                    ),
                }
            }
            _ => is.error(&join(&path, "kind"), "invalid_option", "Supported kinds: sui-address."),
        }
    }
    out
}

/// `0x` + 64 hex digits, lower-cased.
pub fn normalise_sui_address(a: &str) -> Option<String> {
    let hex = a.trim().strip_prefix("0x")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("0x{}", hex.to_ascii_lowercase()))
}

fn parse_cta(v: &Value, is: &mut Issues) -> Option<Cta> {
    let o = object(Some(v), "cta", true, is)?;
    unknown_fields(o, "cta", &["title", "description", "action", "url"], is);
    let title = line(o, "title", "cta", MAX_LINK_TITLE, true, is);
    let description = line(o, "description", "cta", MAX_BIO, false, is);
    let action = line(o, "action", "cta", MAX_LABEL, false, is);
    let url = match o.get("url").and_then(Value::as_str).map(safe_url::check_https) {
        Some(Ok(u)) => Some(u),
        Some(Err(e)) => {
            is.error("cta/url", e.code(), e.message());
            None
        }
        None => {
            is.error("cta/url", "missing", "This is required.");
            None
        }
    };
    Some(Cta { title: title?, description, action, url: url? })
}

fn parse_meta(v: Option<&Value>, is: &mut Issues) -> Meta {
    let mut m = Meta::default();
    let Some(o) = object(v, "meta", false, is) else { return m };
    unknown_fields(o, "meta", &["lang", "indexable"], is);
    if let Some(l) = o.get("lang").and_then(Value::as_str) {
        if is_lang(l) {
            m.lang = l.to_string();
        } else {
            is.error("meta/lang", "lang_invalid", "This must be a language tag such as en or en-GB.");
        }
    }
    m.indexable = boolean(o, "indexable", "meta", true, is);
    m
}

fn is_lang(l: &str) -> bool {
    let mut parts = l.split('-');
    let first = parts.next().unwrap_or("");
    l.len() <= 35
        && (2..=3).contains(&first.len())
        && first.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op() -> ParseOptions {
        ParseOptions { owner: Owner::Operator, check_reserved: false }
    }

    #[test]
    fn minimal_document_parses_with_defaults() {
        let p =
            parse(br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada"}}"#, ParseOptions::default()).unwrap();
        assert_eq!(p.manifest.theme, Theme::default());
        assert!(p.manifest.items.is_empty());
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn unknown_fields_are_dropped_with_a_warning() {
        let p = parse(
            br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada","x":1},"payments":{"sdkUrl":"https://evil.example/x.js"}}"#,
            ParseOptions::default(),
        )
        .unwrap();
        let paths: Vec<&str> = p.warnings.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(paths, ["payments", "identity/x"]);
        assert!(!p.manifest.to_json().contains("evil"));
    }

    #[test]
    fn cta_is_operator_only_and_reserved_handles_are_tenant_only() {
        let doc = br#"{"schema":1,"identity":{"displayName":"A","handle":"app"},"cta":{"title":"Go","url":"https://example.org"}}"#;
        let tenant = parse(doc, ParseOptions { owner: Owner::Tenant, check_reserved: true }).unwrap_err();
        assert_eq!(tenant[0].code, "handle_reserved");
        let p = parse(doc, op()).unwrap();
        assert!(p.manifest.cta.is_some());
    }

    #[test]
    fn handles() {
        assert!(check_handle("ada-lovelace", true).is_ok());
        assert_eq!(check_handle("Ada", true).unwrap(), "ada");
        for bad in ["", "-a", "a-", "xn--abc", "a_b", "a.b", &"a".repeat(31)] {
            assert!(check_handle(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn did_and_nostr() {
        assert!(is_did("did:plc:abcdefghijklmnopqrstuvwx"));
        assert!(is_did("did:web:example.org"));
        assert!(!is_did("did:plc:short"));
        assert!(!is_did("did:key:z6Mk"));
    }
}
