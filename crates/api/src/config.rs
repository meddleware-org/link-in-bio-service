//! The site configuration for `serve --mode static` (and the defaults of `--mode local`): one JSON file, mounted
//! from the deployment. It carries the operator's choices (host, footer, contact addresses); it never carries a
//! secret.

use serde::Deserialize;

use link_in_bio_core::Owner;
use link_in_bio_core::render::{Footer, FooterLink, RightsNotice, RightsSymbol};
use link_in_bio_core::safe_url;

/// The site configuration file as written: one JSON document, with unknown keys refused so a misspelt setting is an error and not silently ignored.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SiteConfigFile {
    /// The site's origin, `https://host/`.
    pub base_url: String,
    /// Whose page it is: a tenant's (the default) or the operator's own.
    #[serde(default)]
    pub owner: OwnerName,
    /// The product's name, used in the footer's attribution.
    #[serde(default = "default_product")]
    pub product_name: String,
    /// The Sui explorer origin that support addresses link to.
    #[serde(default = "default_explorer")]
    pub explorer: String,
    /// The address of the Profile Links specification, defaulting to this site's own copy.
    pub profile_uri: Option<String>,
    /// Whether to serve the specification at the profile address.
    #[serde(default)]
    pub serve_spec: bool,
    /// Whether to serve the ActivityPub actor (on by default).
    #[serde(default = "yes")]
    pub federation: bool,
    /// The footer's settings.
    #[serde(default)]
    pub footer: FooterFile,
    /// A web or mail address for the security.txt contact.
    pub security_contact: Option<String>,
    /// A web address for the security.txt policy.
    pub security_policy: Option<String>,
    /// Whether to use the brand icons, which the operator's page does.
    #[serde(default)]
    pub brand_icons: bool,
    /// Whether to send strict transport security (on by default).
    #[serde(default = "yes")]
    pub hsts: bool,
}

/// The owner as written in the file.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OwnerName {
    /// A tenant's page; the default.
    #[default]
    Tenant,
    /// The operator's own page.
    Operator,
}

/// The footer's settings as written.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FooterFile {
    /// The operator's footer links (legal notice, licence).
    #[serde(default)]
    pub links: Vec<FooterLinkFile>,
    /// A short line of text.
    pub note: Option<String>,
    /// The "Made with" link.
    pub attribution: Option<FooterLinkFile>,
    /// The account-free report form's address.
    pub report_url: Option<String>,
    /// The rights notice, drawn like the Vue sites' `CopyrightLine` (workspace docs/legal L-IP-1).
    pub rights: Option<RightsFile>,
}

/// `footer.rights`: `{ "symbol": "kopimi", "href": "https://…/powr.broccoli-kopimi.pdf", "organisation": "Meddleware",
/// "statement": "All jams preserved." }`. `year` defaults to the current year when the configuration is loaded.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RightsFile {
    /// Which symbol leads the notice.
    pub symbol: RightsSymbolName,
    /// The document the symbol links to.
    pub href: String,
    /// The organisation the notice names.
    pub organisation: String,
    /// For example "All jams preserved."
    pub statement: Option<String>,
    /// The year, defaulting to the current one.
    pub year: Option<i32>,
}

/// The rights symbol as written.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RightsSymbolName {
    /// The Kopimi triangle.
    Kopimi,
    /// The reversed C.
    Copyleft,
    /// The copyright sign.
    Copyright,
}

/// A footer link as written.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FooterLinkFile {
    /// The words of the link.
    pub text: String,
    /// Where it goes.
    pub url: String,
}

/// The default product name.
fn default_product() -> String {
    "Link in Bio".into()
}
/// The default explorer origin.
fn default_explorer() -> String {
    "https://suivision.xyz".into()
}
/// A `true` default for the settings that are on unless turned off.
fn yes() -> bool {
    true
}

/// Checked configuration.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// `https://<host>/` with a trailing slash (or `http://127.0.0.1:<port>/` in local mode).
    pub base_url: String,
    /// The host name.
    pub host: String,
    /// Whose page it is.
    pub owner: Owner,
    /// The product's name.
    pub product_name: String,
    /// The explorer origin, without a trailing slash.
    pub explorer: String,
    /// The Profile Links specification's address.
    pub profile_uri: String,
    /// Whether the specification is served.
    pub serve_spec: bool,
    /// Whether the actor is served.
    pub federation: bool,
    /// The checked footer.
    pub footer: Footer,
    /// The security.txt contact, checked.
    pub security_contact: Option<String>,
    /// The security.txt policy address, checked.
    pub security_policy: Option<String>,
    /// Whether the brand icons are used.
    pub brand_icons: bool,
    /// Whether strict transport security is sent.
    pub hsts: bool,
    /// Loopback-only editor mode: plain HTTP, no HSTS, no `upgrade-insecure-requests`.
    pub local: bool,
}

/// Why the configuration was refused. A message names the field and what is wrong with it.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration is invalid; the message says which field.
    #[error("site config: {0}")]
    Invalid(String),
}

/// A web address that must be `https`, with the field named in the error and never the address itself.
fn https(field: &str, v: &str) -> Result<String, ConfigError> {
    safe_url::check_https(v).map_err(|e| ConfigError::Invalid(format!("{field}: {}", e.message())))
}

/// A footer link, checked: short text and an https address.
fn link(field: &str, l: &FooterLinkFile) -> Result<FooterLink, ConfigError> {
    let text = link_in_bio_core::text::clean_line(&l.text, 60, false)
        .map_err(|e| ConfigError::Invalid(format!("{field}: {}", e.message())))?;
    Ok(FooterLink { text, url: https(field, &l.url)? })
}

impl SiteConfig {
    /// The configuration from the file's bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let f: SiteConfigFile = serde_json::from_slice(bytes).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        Self::from_file(f)
    }

    /// Check every field: the base address must be an origin, every address must be https, text is cleaned and bounded, and the year must be four digits.
    pub fn from_file(f: SiteConfigFile) -> Result<Self, ConfigError> {
        // The base address must be exactly an origin, so every address derived from it is predictable.
        let base = https("baseUrl", &f.base_url)?;
        // The base address is parsed to read its host and to check that it is only an origin.
        let parsed = url::Url::parse(&base).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ConfigError::Invalid("baseUrl: must be the site's origin, like https://example.org/".into()));
        }
        let host = parsed.host_str().unwrap_or_default().to_string();
        // Without a configured address, the specification is served from this site's own copy.
        let profile_uri = match &f.profile_uri {
            Some(p) => https("profileUri", p)?,
            None => format!("{base}spec/profile-links/v1"),
        };
        // The footer is built from the checked parts, each field named in any error.
        let mut footer = Footer::default();
        for l in &f.footer.links {
            footer.links.push(link("footer.links", l)?);
        }
        footer.note = match &f.footer.note {
            Some(n) => Some(
                link_in_bio_core::text::clean_line(n, 120, false)
                    .map_err(|e| ConfigError::Invalid(format!("footer.note: {}", e.message())))?,
            ),
            None => None,
        };
        footer.rights = match &f.footer.rights {
            Some(r) => {
                let line = |field: &str, v: &str| {
                    link_in_bio_core::text::clean_line(v, 120, false)
                        .map_err(|e| ConfigError::Invalid(format!("footer.rights.{field}: {}", e.message())))
                };
                // The year defaults to the current one when the configuration is loaded.
                let year = r.year.unwrap_or_else(|| time::OffsetDateTime::now_utc().year());
                if !(1970..=9999).contains(&year) {
                    return Err(ConfigError::Invalid("footer.rights.year: must be a four-digit year".into()));
                }
                Some(RightsNotice {
                    symbol: match r.symbol {
                        RightsSymbolName::Kopimi => RightsSymbol::Kopimi,
                        RightsSymbolName::Copyleft => RightsSymbol::Copyleft,
                        RightsSymbolName::Copyright => RightsSymbol::Copyright,
                    },
                    href: https("footer.rights.href", &r.href)?,
                    year,
                    organisation: line("organisation", &r.organisation)?,
                    statement: match &r.statement {
                        Some(t) => line("statement", t)?,
                        None => String::new(),
                    },
                })
            }
            None => None,
        };
        footer.attribution = f.footer.attribution.as_ref().map(|a| link("footer.attribution", a)).transpose()?;
        footer.report_url = f.footer.report_url.as_deref().map(|u| https("footer.reportUrl", u)).transpose()?;
        // The contact may be a web or a mail address.
        let security_contact = match &f.security_contact {
            Some(c) => match safe_url::check_link(c) {
                Ok((u, _)) => Some(u),
                Err(e) => return Err(ConfigError::Invalid(format!("securityContact: {}", e.message()))),
            },
            None => None,
        };
        Ok(Self {
            base_url: base,
            host,
            owner: if f.owner == OwnerName::Operator { Owner::Operator } else { Owner::Tenant },
            product_name: f.product_name,
            explorer: https("explorer", &f.explorer)?.trim_end_matches('/').to_string(),
            profile_uri,
            serve_spec: f.serve_spec,
            federation: f.federation,
            footer,
            security_contact,
            security_policy: f.security_policy.as_deref().map(|p| https("securityPolicy", p)).transpose()?,
            brand_icons: f.brand_icons,
            hsts: f.hsts,
            local: false,
        })
    }

    /// The configuration of the loopback editor.
    pub fn local(port: u16, owner: Owner) -> Self {
        // The loopback editor: plain HTTP on 127.0.0.1, no HSTS, the specification served, no federation.
        let base_url = format!("http://127.0.0.1:{port}/");
        Self {
            host: "127.0.0.1".into(),
            profile_uri: "https://meddleware.link/spec/profile-links/v1".into(),
            base_url,
            owner,
            product_name: default_product(),
            explorer: default_explorer(),
            serve_spec: true,
            federation: false,
            footer: Footer::default(),
            security_contact: None,
            security_policy: None,
            brand_icons: owner == Owner::Operator,
            hsts: false,
            local: true,
        }
    }
}

/// Unit tests for the site configuration.
#[cfg(test)]
mod tests {
    use super::*;

    /// The rights notice is read with its symbol and year, and a notice with a non-https address, an unknown symbol or a two-digit year is refused.
    #[test]
    fn reads_the_rights_notice() {
        let c = SiteConfig::from_json(
            br#"{"baseUrl":"https://meddleware.link/","footer":{"rights":{"symbol":"kopimi","href":"https://meddleware.co.uk/legal/powr.broccoli-kopimi.pdf","organisation":"Meddleware","statement":"All jams preserved.","year":2026}}}"#,
        )
        .unwrap();
        let r = c.footer.rights.unwrap();
        assert_eq!(
            (r.symbol, r.year, r.organisation.as_str(), r.statement.as_str()),
            (RightsSymbol::Kopimi, 2026, "Meddleware", "All jams preserved.")
        );
        for bad in [
            r#"{"baseUrl":"https://meddleware.link/","footer":{"rights":{"symbol":"kopimi","href":"http://x.example/","organisation":"M"}}}"#,
            r#"{"baseUrl":"https://meddleware.link/","footer":{"rights":{"symbol":"other","href":"https://x.example/","organisation":"M"}}}"#,
            r#"{"baseUrl":"https://meddleware.link/","footer":{"rights":{"symbol":"kopimi","href":"https://x.example/","organisation":"M","year":20}}}"#,
        ] {
            assert!(SiteConfig::from_json(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    /// A valid configuration reads, and a plain-http base, a base with a path, a script link and an unknown key are each refused.
    #[test]
    fn parses_and_checks() {
        let c = SiteConfig::from_json(
            br#"{"baseUrl":"https://meddleware.link/","owner":"operator","footer":{"links":[{"text":"Legal","url":"https://example.org/legal/"}]},"securityContact":"mailto:security@example.org"}"#,
        )
        .unwrap();
        assert_eq!(c.host, "meddleware.link");
        assert_eq!(c.profile_uri, "https://meddleware.link/spec/profile-links/v1");
        assert_eq!(c.owner, Owner::Operator);
        for bad in [
            r#"{"baseUrl":"http://meddleware.link/"}"#,
            r#"{"baseUrl":"https://meddleware.link/page"}"#,
            r#"{"baseUrl":"https://meddleware.link/","footer":{"links":[{"text":"x","url":"javascript:alert(1)"}]}}"#,
            r#"{"baseUrl":"https://meddleware.link/","secret":"x"}"#,
        ] {
            assert!(SiteConfig::from_json(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
