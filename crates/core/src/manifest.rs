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

/// The only schema version this parser reads; a document must say so.
pub const SCHEMA: u64 = 1;

/// Whether the page is about a person or an organisation (the interop documents use different types for each).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A person; the default.
    #[default]
    Person,
    /// An organisation.
    Organization,
}

/// Who the page is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    /// A person or an organisation.
    pub kind: Kind,
    /// The name shown at the top of the page.
    pub display_name: String,
    /// The handle, which is also the page's host name under the pages domain.
    pub handle: String,
    /// A short line about the person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bio: Option<String>,
    /// The person's pronouns, if they chose to show them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
    /// A file name in the page's asset directory (static and local modes) or `sha256:<hex>` (hosted mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// The Bluesky identifier (a DID) that the handle file `/.well-known/atproto-did` answers with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atproto_did: Option<String>,
    /// The Nostr public key (64 hex digits, lower case) that the NIP-05 file answers with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nostr_pubkey: Option<String>,
}

/// One link on the page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    /// A stable identifier for the link, unique on the page, so the editor and the interop documents can refer to it.
    pub id: String,
    /// The words on the link.
    pub title: String,
    /// The normalised target: an `https:` or `mailto:` address.
    pub url: String,
    /// A line of explanation under the title.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The icon drawn beside the title, from the fixed set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<crate::icons::Icon>,
    /// One of the person's own profiles: rendered with `rel="me"`.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub identity: bool,
    /// A hidden link is kept in the document but not shown or listed anywhere.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

/// A titled, collapsible group of links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    /// A stable identifier, unique among the page's ids.
    pub id: String,
    /// The group's heading.
    pub title: String,
    /// Whether the group starts expanded.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub open: bool,
    /// The links in the group, in order.
    pub items: Vec<Link>,
}

/// One entry of the page's list: a link or a group of links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Item {
    /// A single link.
    Link(Link),
    /// A group of links.
    Group(Group),
}

/// A way to contact the person (for example an email address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    /// What the contact is, in a few words.
    pub label: String,
    /// The contact's address, a `mailto:` link.
    pub url: String,
}

/// A way for visitors to support the person. Display only: no widget, no script, no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SupportMethod {
    /// A Sui address visitors can send support to.
    SuiAddress {
        /// The address, as given.
        address: String,
        /// What the address is for.
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
}

/// The operator's own call to action (for example "make your own page"). Refused on tenant pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cta {
    /// The call to action's headline.
    pub title: String,
    /// A line of explanation under it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The button's words (default "Find out more").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Where the button goes, an `https:` address.
    pub url: String,
}

/// Page-level settings that are not part of the design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    /// The page's language, as a language tag.
    pub lang: String,
    /// Whether search engines may index the page.
    pub indexable: bool,
}

impl Default for Meta {
    /// The default language and indexing.
    fn default() -> Self {
        // English and indexable unless the document says otherwise.
        Self { lang: "en".into(), indexable: true }
    }
}

/// A page document that has passed the parser; nothing renders anything that has not.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// Always [`SCHEMA`].
    pub schema: u64,
    /// Who the page is about.
    pub identity: Identity,
    /// The links and groups, in page order.
    pub items: Vec<Item>,
    /// The constrained theme choices.
    pub theme: Theme,
    /// Contact addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contact: Vec<Contact>,
    /// Ways to support the person.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub support: Vec<SupportMethod>,
    /// The call to action, only ever present on the operator's own page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cta: Option<Cta>,
    /// Language and indexing.
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
            // Hidden links are left out of every listing.
            .filter(|l| !l.hidden)
    }

    /// The document as pretty-printed JSON (the shape the parser reads back).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Who the page belongs to: the operator's own page may carry a call to action and an SVG avatar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Owner {
    /// A tenant's page; the default.
    #[default]
    Tenant,
    /// The operator's own page.
    Operator,
}

/// How to treat a document: whose page it is and whether handles are checked against the reserved list.
#[derive(Debug, Clone, Copy, Default)]
pub struct ParseOptions {
    /// Whose page the document is for.
    pub owner: Owner,
    /// Tenant handles may not be on the reserved list; the operator chooses theirs freely.
    pub check_reserved: bool,
}

/// A document that was accepted, with what was dropped.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Parsed {
    /// The checked document.
    pub manifest: Manifest,
    /// What was removed or changed on the way in (unknown fields, a call to action on a tenant page).
    pub warnings: Vec<Issue>,
}

/// Parses manifest bytes. On success returns the manifest and any warnings; on failure every error found.
pub fn parse(bytes: &[u8], opts: ParseOptions) -> Result<Parsed, Vec<Issue>> {
    // The size limit is checked before parsing, so an oversized upload costs almost nothing.
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(vec![Issue::new(
            "",
            "too_large",
            format!("The page document is too large: at most {} KiB.", MAX_MANIFEST_BYTES / 1024),
        )]);
    }
    // Invalid JSON is one plain error; the parser's own message is not shown, because it can quote the input.
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(v) => v,
        Err(_) => return Err(vec![Issue::new("", "not_json", "This is not a valid page document (JSON).")]),
    };
    parse_value(&value, opts)
}

/// Parse an already-decoded JSON value, collecting every error rather than stopping at the first.
pub fn parse_value(value: &Value, opts: ParseOptions) -> Result<Parsed, Vec<Issue>> {
    // The collector for this document.
    let mut is = Issues::default();
    let Some(root) = value.as_object() else {
        return Err(vec![Issue::new("", "not_object", "The page document must be a JSON object.")]);
    };
    // The fields the root may hold; anything else is dropped with a warning.
    let known = ["schema", "identity", "items", "theme", "contact", "support", "cta", "meta"];
    // Report every key the document should not have.
    unknown_fields(root, "", &known, &mut is);

    // The schema number must be present and equal to the one this parser reads.
    match root.get("schema").and_then(Value::as_u64) {
        Some(SCHEMA) => {}
        Some(n) => is.error(
            "schema",
            "unsupported_schema",
            format!("Schema {n} is not supported; this version reads schema {SCHEMA}."),
        ),
        None => is.error("schema", "missing", format!("The document must say \"schema\": {SCHEMA}.")),
    }

    // Every part is parsed even when an earlier one failed, so the person sees all their problems at once.
    let identity = parse_identity(root.get("identity"), opts, &mut is);
    // The list of links and groups.
    let items = parse_items(root.get("items"), &mut is);
    // The theme, checked for contrast.
    let theme = parse_theme(root.get("theme"), &mut is);
    // The contact addresses.
    let contact = parse_contact(root.get("contact"), &mut is);
    let support = parse_support(root.get("support"), &mut is);
    // A call to action is parsed only for the operator's page; on a tenant's page it is dropped with a warning, not an error.
    let cta = match root.get("cta") {
        None | Some(Value::Null) => None,
        Some(v) if opts.owner == Owner::Operator => parse_cta(v, &mut is),
        Some(_) => {
            is.warn("cta", "dropped", "A call to action is only available on the operator's page; it was removed.");
            None
        }
    };
    // Language and indexing.
    let meta = parse_meta(root.get("meta"), &mut is);

    // Any error refuses the whole document.
    if !is.errors.is_empty() {
        return Err(is.errors);
    }
    // Unreachable in practice (a missing identity or theme is already an error), but the parser never panics, so it refuses.
    let (Some(identity), Some(theme)) = (identity, theme) else {
        return Err(vec![Issue::new("", "invalid", "The page document is not valid.")]);
    };
    // Accepted: the checked document, and everything that was dropped.
    Ok(Parsed {
        manifest: Manifest { schema: SCHEMA, identity, items, theme, contact, support, cta, meta },
        warnings: is.warnings,
    })
}

/// Warn about each key of an object that is not in the known list; the key is shortened in the warning so a huge key cannot make a huge message.
fn unknown_fields(obj: &Map<String, Value>, path: &str, known: &[&str], is: &mut Issues) {
    for k in obj.keys() {
        if !known.contains(&k.as_str()) {
            let key: String = k.chars().take(40).collect();
            is.warn(&join(path, &key), "unknown_field", "This field is not part of the page document; it was removed.");
        }
    }
}

/// The value as an object, or an error that says it is missing (when required) or has the wrong type.
fn object<'a>(v: Option<&'a Value>, path: &str, required: bool, is: &mut Issues) -> Option<&'a Map<String, Value>> {
    match v {
        // An object is what is wanted.
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
    // The full path of the field, for any message about it.
    let p = join(path, key);
    // A missing or null value is fine unless the field is required.
    match obj.get(key) {
        None | Some(Value::Null) => {
            if required {
                is.error(&p, "missing", "This is required.");
            }
            None
        }
        // A string goes through the text rules, which normalise it and refuse hidden characters.
        Some(Value::String(s)) => match clean_line(s, max, !required) {
            // An optional field left empty is the same as absent.
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

/// A true-or-false field, with a default for a missing value and an error for any other type.
fn boolean(obj: &Map<String, Value>, key: &str, path: &str, default: bool, is: &mut Issues) -> bool {
    match obj.get(key) {
        None | Some(Value::Null) => default,
        // A boolean is used as given.
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            is.error(&join(path, key), "wrong_type", "This must be true or false.");
            default
        }
    }
}

/// Parse the identity block, with its handle, optional picture and the identifiers other software looks up.
fn parse_identity(v: Option<&Value>, opts: ParseOptions, is: &mut Issues) -> Option<Identity> {
    // The identity block is required, and nothing else can be parsed without it.
    let o = object(v, "identity", true, is)?;
    unknown_fields(
        o,
        "identity",
        &["kind", "displayName", "handle", "bio", "pronouns", "avatar", "atprotoDid", "nostrPubkey"],
        is,
    );
    // The kind defaults to a person.
    let kind = match o.get("kind").and_then(Value::as_str) {
        None => Kind::Person,
        // Both spellings that name a kind are accepted; any other value is refused below.
        Some("person") => Kind::Person,
        Some("organization") => Kind::Organization,
        Some(_) => {
            is.error("identity/kind", "invalid_option", "Choose \"person\" or \"organization\".");
            Kind::Person
        }
    };
    // The name is required and is one line of text.
    let display_name = line(o, "displayName", "identity", MAX_DISPLAY_NAME, true, is);
    // The handle is required and has its own rules.
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
    // The optional short lines.
    let bio = line(o, "bio", "identity", MAX_BIO, false, is);
    let pronouns = line(o, "pronouns", "identity", MAX_PRONOUNS, false, is);
    let avatar = match o.get("avatar") {
        None | Some(Value::Null) => None,
        // A picture is an uploaded image, never a URL, so a page cannot load an image from elsewhere.
        Some(Value::String(a)) if is_asset_ref(a, opts.owner) => Some(a.clone()),
        Some(_) => {
            is.error("identity/avatar", "avatar_invalid", "The picture must be an uploaded image.");
            None
        }
    };
    // The Bluesky identifier is optional, and checked for its shape.
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
        // A Nostr key is exactly 64 hex digits; it is stored lower case.
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
    // The identity exists only if the name and the handle both parsed.
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
    // Handles are case-insensitive, so they are stored lower case.
    let h = h.trim().to_ascii_lowercase();
    // A handle is 1 to the maximum length of lower-case letters, digits and hyphens, not starting or ending with a hyphen.
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
    // `--` in the third and fourth place is how internationalised labels start, and a handle is a host name.
    if h.len() >= 4 && &h[2..4] == "--" {
        return Err(("handle_invalid", "A handle cannot have two hyphens in the third and fourth place.".into()));
    }
    // Only tenants are held to the reserved list.
    if check_reserved && RESERVED_HANDLES.contains(&h.as_str()) {
        return Err(("handle_reserved", "This handle is reserved. Choose another.".into()));
    }
    Ok(h)
}

/// Whether a picture reference is acceptable: `sha256:` and 64 lower-case hex digits (hosted mode), or a plain lower-case file name with a raster extension (static and local modes). An SVG is allowed only on the operator's page.
fn is_asset_ref(a: &str, owner: Owner) -> bool {
    // A stored picture is named by its content hash: 64 lower-case hex digits.
    if let Some(hex) = a.strip_prefix("sha256:") {
        return hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    }
    // A file name stays inside the asset directory: short, starting with a letter or digit, lower-case, and with no `..`.
    let name_ok = (1..=64).contains(&a.len())
        && a.bytes().next().is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && a.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        && !a.contains("..");
    // Raster formats only; the operator's own page may use an SVG.
    let ext_ok = [".png", ".jpg", ".jpeg", ".webp", ".gif"].iter().any(|e| a.ends_with(e))
        || (owner == Owner::Operator && a.ends_with(".svg"));
    name_ok && ext_ok
}

/// Whether an identifier is a Bluesky DID: `did:plc:` with 24 base32 characters, or `did:web:` with a host name.
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

/// Check a link or group id (1 to the maximum length of letters, digits, hyphens and underscores) and that no other item on the page has it; remembers the ids seen.
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

/// Parse one link: its id, title and target, an optional description and icon, and the two flags.
fn parse_link(v: &Value, path: &str, seen: &mut Vec<String>, is: &mut Issues) -> Option<Link> {
    let Some(o) = v.as_object() else {
        is.error(path, "wrong_type", "A link must be an object.");
        return None;
    };
    // The fields a link may hold; `kind` is read by the caller.
    unknown_fields(o, path, &["kind", "id", "title", "url", "description", "icon", "identity", "hidden"], is);
    // The id comes first so a duplicate is reported at the id, not at some later field.
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
    // The description is optional.
    let description = line(o, "description", path, MAX_LINK_DESCRIPTION, false, is);
    let icon = match o.get("icon").and_then(Value::as_str) {
        None => None,
        Some(name) => match crate::icons::Icon::parse(name) {
            Some(i) => Some(i),
            None => {
                // An unknown icon is a warning, not an error: the link is still shown, without an icon.
                is.warn(&join(path, "icon"), "icon_unknown", "This icon is not available; the link shows without one.");
                None
            }
        },
    };
    // Both flags default to false.
    let identity = boolean(o, "identity", path, false, is);
    let hidden = boolean(o, "hidden", path, false, is);
    // A profile marked as the person's own (`rel="me"`) must be a web address, so an email link cannot be one.
    if identity && url.as_deref().is_some_and(|u| u.starts_with("mailto:")) {
        is.error(
            &join(path, "identity"),
            "identity_mailto",
            "Only web profiles can be marked as yours, not email links.",
        );
    }
    // A link needs an id, a title and a target; without all three it is dropped (the errors are recorded).
    Some(Link { id: id?, title: title?, url: url?, description, icon, identity, hidden })
}

/// Parse the page's list of links and groups, with every id unique across the whole page and the totals bounded.
fn parse_items(v: Option<&Value>, is: &mut Issues) -> Vec<Item> {
    // No items is a valid, empty page.
    let arr = match v {
        None | Some(Value::Null) => return Vec::new(),
        Some(Value::Array(a)) => a,
        Some(_) => {
            is.error("items", "wrong_type", "This must be a list.");
            return Vec::new();
        }
    };
    // The ids seen so far across links and groups.
    let mut seen = Vec::new();
    let mut out = Vec::new();
    // Counted across the whole page, groups' links included.
    let (mut links, mut groups) = (0usize, 0usize);
    for (i, item) in arr.iter().enumerate() {
        let path = join("items", i);
        // An item without a kind is a link.
        let kind = item.get("kind").and_then(Value::as_str).unwrap_or("link");
        match kind {
            "link" => {
                links += 1;
                if let Some(l) = parse_link(item, &path, &mut seen, is) {
                    out.push(Item::Link(l));
                }
            }
            // A group is parsed inline, because it owns the nested links and the shared id list.
            "group" => {
                groups += 1;
                // A group that is not an object is skipped: the caller counted it, and its own position is already in the path.
                let Some(o) = item.as_object() else { continue };
                unknown_fields(o, &path, &["kind", "id", "title", "open", "items"], is);
                // A group's id comes from the same list as the links' ids.
                let id = check_id(o.get("id"), &path, &mut seen, is);
                let title = line(o, "title", &path, MAX_GROUP_TITLE, true, is);
                // Groups start collapsed unless they say otherwise.
                let open = boolean(o, "open", &path, false, is);
                let mut inner = Vec::new();
                match o.get("items") {
                    Some(Value::Array(a)) => {
                        for (j, l) in a.iter().enumerate() {
                            let lp = join(&join(&path, "items"), j);
                            // A group holds links only, so the nesting depth is bounded at one.
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
                // A group with an invalid id or title is dropped; the errors are already recorded.
                if let (Some(id), Some(title)) = (id, title) {
                    out.push(Item::Group(Group { id, title, open, items: inner }));
                }
            }
            // Anything but a link or a group is an error.
            _ => is.error(&join(&path, "kind"), "invalid_option", "An item is either a \"link\" or a \"group\"."),
        }
    }
    // The totals are checked after the loop, so the person sees every other problem as well.
    if links > MAX_LINKS {
        is.error("items", "too_many_links", format!("A page can have at most {MAX_LINKS} links."));
    }
    if groups > MAX_GROUPS {
        is.error("items", "too_many_groups", format!("A page can have at most {MAX_GROUPS} groups."));
    }
    out
}

/// Parse the theme choices over the defaults, then require the result to pass the contrast checks.
fn parse_theme(v: Option<&Value>, is: &mut Issues) -> Option<Theme> {
    // Start from the defaults, so a document may say nothing about the theme.
    let mut t = Theme::default();
    // A missing theme is the default theme.
    let Some(o) = object(v, "theme", false, is) else { return Some(t) };
    unknown_fields(
        o,
        "theme",
        &["colorMode", "season", "accent", "buttons", "radius", "density", "layout", "font"],
        is,
    );
    /// Read one named choice into its slot: a missing value keeps the default, an unknown name lists the valid ones.
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
    // Each choice is read in the same way, from its own set of names.
    opt(o, "colorMode", ColorMode::parse, ColorMode::names(), &mut t.color_mode, is);
    opt(o, "season", Season::parse, Season::names(), &mut t.season, is);
    opt(o, "accent", Accent::parse, Accent::names(), &mut t.accent, is);
    opt(o, "buttons", Buttons::parse, Buttons::names(), &mut t.buttons, is);
    opt(o, "radius", Radius::parse, Radius::names(), &mut t.radius, is);
    opt(o, "density", Density::parse, Density::names(), &mut t.density, is);
    opt(o, "layout", Layout::parse, Layout::names(), &mut t.layout, is);
    opt(o, "font", Font::parse, Font::names(), &mut t.font, is);
    // The combination must meet the contrast rules in every colour mode the page can show; if not, the theme is refused with the reason.
    if let Err(failures) = theme::check(&t) {
        for f in failures {
            is.error("theme", "contrast", f.message);
        }
        return None;
    }
    Some(t)
}

/// The value as a list of at most `max` entries; a longer list or another type is an error and reads as empty.
fn list<'a>(v: Option<&'a Value>, path: &str, max: usize, is: &mut Issues) -> &'a [Value] {
    match v {
        None | Some(Value::Null) => &[],
        // A list within its limit is used as it is.
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

/// Parse the contact list: each entry has a label and an email link.
fn parse_contact(v: Option<&Value>, is: &mut Issues) -> Vec<Contact> {
    let mut out = Vec::new();
    for (i, c) in list(v, "contact", MAX_CONTACTS, is).iter().enumerate() {
        // The position of the entry, for messages.
        let path = join("contact", i);
        let Some(o) = c.as_object() else {
            is.error(&path, "wrong_type", "This must be an object.");
            continue;
        };
        unknown_fields(o, &path, &["label", "url"], is);
        // Every contact has a label and an address.
        let label = line(o, "label", &path, MAX_LABEL, true, is);
        // A contact is an email link, so a web address is refused here.
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

/// Parse the support list. Only a Sui address is supported, and it is display-only.
fn parse_support(v: Option<&Value>, is: &mut Issues) -> Vec<SupportMethod> {
    let mut out = Vec::new();
    for (i, s) in list(v, "support", MAX_SUPPORT, is).iter().enumerate() {
        let path = join("support", i);
        let Some(o) = s.as_object() else {
            is.error(&path, "wrong_type", "This must be an object.");
            continue;
        };
        // The kind selects the shape of the entry; an unknown kind is refused.
        match o.get("kind").and_then(Value::as_str) {
            // The only kind of support entry so far.
            Some("sui-address") => {
                unknown_fields(o, &path, &["kind", "address", "label"], is);
                let label = line(o, "label", &path, MAX_LABEL, false, is);
                match o.get("address").and_then(Value::as_str).and_then(normalise_sui_address) {
                    // The address is stored in its normalised form.
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
    // A Sui address is `0x` and 64 hex digits; the digits are lower-cased.
    let hex = a.trim().strip_prefix("0x")?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("0x{}", hex.to_ascii_lowercase()))
}

/// Parse the operator's call to action: a title, optional text and button words, and a web address.
fn parse_cta(v: &Value, is: &mut Issues) -> Option<Cta> {
    let o = object(Some(v), "cta", true, is)?;
    // The fields a call to action may hold.
    unknown_fields(o, "cta", &["title", "description", "action", "url"], is);
    // The title is required; the text and the button words are optional.
    let title = line(o, "title", "cta", MAX_LINK_TITLE, true, is);
    let description = line(o, "description", "cta", MAX_BIO, false, is);
    let action = line(o, "action", "cta", MAX_LABEL, false, is);
    // The call to action goes to a web address, never an email link.
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
    // Without a title and a target there is no call to action.
    Some(Cta { title: title?, description, action, url: url? })
}

/// Parse the language and indexing settings over their defaults.
fn parse_meta(v: Option<&Value>, is: &mut Issues) -> Meta {
    // English and indexable unless the document says otherwise.
    let mut m = Meta::default();
    let Some(o) = object(v, "meta", false, is) else { return m };
    // Only two settings are known.
    unknown_fields(o, "meta", &["lang", "indexable"], is);
    if let Some(l) = o.get("lang").and_then(Value::as_str) {
        if is_lang(l) {
            m.lang = l.to_string();
        } else {
            is.error("meta/lang", "lang_invalid", "This must be a language tag such as en or en-GB.");
        }
    }
    // Indexable is the default.
    m.indexable = boolean(o, "indexable", "meta", true, is);
    m
}

/// A simple check for a language tag: a two or three letter primary part, then sub-tags of letters and digits.
fn is_lang(l: &str) -> bool {
    let mut parts = l.split('-');
    let first = parts.next().unwrap_or("");
    // A language tag is at most 35 characters.
    l.len() <= 35
        && (2..=3).contains(&first.len())
        && first.bytes().all(|b| b.is_ascii_alphabetic())
        && parts.all(|p| (1..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Unit tests for the parser.
#[cfg(test)]
mod tests {
    use super::*;

    /// Parse options for the operator's page, with the reserved list not applied.
    fn op() -> ParseOptions {
        ParseOptions { owner: Owner::Operator, check_reserved: false }
    }

    /// A document with only an identity parses, with the default theme, no items and no warnings.
    #[test]
    fn minimal_document_parses_with_defaults() {
        let p =
            parse(br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada"}}"#, ParseOptions::default()).unwrap();
        // No theme in the document means the default theme.
        assert_eq!(p.manifest.theme, Theme::default());
        assert!(p.manifest.items.is_empty());
        assert!(p.warnings.is_empty());
    }

    /// Unknown fields (a payment widget URL, for example) are dropped with a warning and never reach the output.
    #[test]
    fn unknown_fields_are_dropped_with_a_warning() {
        let p = parse(
            br#"{"schema":1,"identity":{"displayName":"Ada","handle":"ada","x":1},"payments":{"sdkUrl":"https://evil.example/x.js"}}"#,
            ParseOptions::default(),
        )
        .unwrap();
        // The warnings name where each dropped field was, in the order they were found.
        let paths: Vec<&str> = p.warnings.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(paths, ["payments", "identity/x"]);
        // What was dropped is not in the output.
        assert!(!p.manifest.to_json().contains("evil"));
    }

    /// A reserved handle is refused for a tenant and accepted for the operator, who alone may have a call to action.
    #[test]
    fn cta_is_operator_only_and_reserved_handles_are_tenant_only() {
        let doc = br#"{"schema":1,"identity":{"displayName":"A","handle":"app"},"cta":{"title":"Go","url":"https://example.org"}}"#;
        // For a tenant the reserved handle is the first error.
        let tenant = parse(doc, ParseOptions { owner: Owner::Tenant, check_reserved: true }).unwrap_err();
        assert_eq!(tenant[0].code, "handle_reserved");
        let p = parse(doc, op()).unwrap();
        assert!(p.manifest.cta.is_some());
    }

    /// Handles are lower-cased, and the empty, hyphen-edged, punycode-looking, punctuated and over-long ones are refused.
    #[test]
    fn handles() {
        assert!(check_handle("ada-lovelace", true).is_ok());
        assert_eq!(check_handle("Ada", true).unwrap(), "ada");
        // Each of these is refused for its own reason.
        for bad in ["", "-a", "a-", "xn--abc", "a_b", "a.b", &"a".repeat(31)] {
            assert!(check_handle(bad, true).is_err(), "{bad}");
        }
    }

    /// A DID is `did:plc:` with 24 characters or `did:web:` with a host; short and other methods are refused.
    #[test]
    fn did_and_nostr() {
        // Exactly 24 base32 characters.
        assert!(is_did("did:plc:abcdefghijklmnopqrstuvwx"));
        assert!(is_did("did:web:example.org"));
        assert!(!is_did("did:plc:short"));
        assert!(!is_did("did:key:z6Mk"));
    }
}
