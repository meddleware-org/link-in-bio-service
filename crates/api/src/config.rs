//! The site configuration for `serve --mode static` (and the defaults of `--mode local`): one JSON file, mounted
//! from the deployment. It carries the operator's choices (host, footer, contact addresses); it never carries a
//! secret.

use serde::Deserialize;

use link_in_bio_core::Owner;
use link_in_bio_core::render::{Footer, FooterLink};
use link_in_bio_core::safe_url;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SiteConfigFile {
    pub base_url: String,
    #[serde(default)]
    pub owner: OwnerName,
    #[serde(default = "default_product")]
    pub product_name: String,
    #[serde(default = "default_explorer")]
    pub explorer: String,
    pub profile_uri: Option<String>,
    #[serde(default)]
    pub serve_spec: bool,
    #[serde(default = "yes")]
    pub federation: bool,
    #[serde(default)]
    pub footer: FooterFile,
    pub security_contact: Option<String>,
    pub security_policy: Option<String>,
    #[serde(default)]
    pub brand_icons: bool,
    #[serde(default = "yes")]
    pub hsts: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OwnerName {
    #[default]
    Tenant,
    Operator,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FooterFile {
    #[serde(default)]
    pub links: Vec<FooterLinkFile>,
    pub note: Option<String>,
    pub attribution: Option<FooterLinkFile>,
    pub report_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FooterLinkFile {
    pub text: String,
    pub url: String,
}

fn default_product() -> String {
    "Link in Bio".into()
}
fn default_explorer() -> String {
    "https://suivision.xyz".into()
}
fn yes() -> bool {
    true
}

/// Checked configuration.
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// `https://<host>/` with a trailing slash (or `http://127.0.0.1:<port>/` in local mode).
    pub base_url: String,
    pub host: String,
    pub owner: Owner,
    pub product_name: String,
    pub explorer: String,
    pub profile_uri: String,
    pub serve_spec: bool,
    pub federation: bool,
    pub footer: Footer,
    pub security_contact: Option<String>,
    pub security_policy: Option<String>,
    pub brand_icons: bool,
    pub hsts: bool,
    /// Loopback-only editor mode: plain HTTP, no HSTS, no `upgrade-insecure-requests`.
    pub local: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("site config: {0}")]
    Invalid(String),
}

fn https(field: &str, v: &str) -> Result<String, ConfigError> {
    safe_url::check_https(v).map_err(|e| ConfigError::Invalid(format!("{field}: {}", e.message())))
}

fn link(field: &str, l: &FooterLinkFile) -> Result<FooterLink, ConfigError> {
    let text = link_in_bio_core::text::clean_line(&l.text, 60, false)
        .map_err(|e| ConfigError::Invalid(format!("{field}: {}", e.message())))?;
    Ok(FooterLink { text, url: https(field, &l.url)? })
}

impl SiteConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfigError> {
        let f: SiteConfigFile = serde_json::from_slice(bytes).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        Self::from_file(f)
    }

    pub fn from_file(f: SiteConfigFile) -> Result<Self, ConfigError> {
        let base = https("baseUrl", &f.base_url)?;
        let parsed = url::Url::parse(&base).map_err(|e| ConfigError::Invalid(e.to_string()))?;
        if parsed.path() != "/" || parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(ConfigError::Invalid("baseUrl: must be the site's origin, like https://example.org/".into()));
        }
        let host = parsed.host_str().unwrap_or_default().to_string();
        let profile_uri = match &f.profile_uri {
            Some(p) => https("profileUri", p)?,
            None => format!("{base}spec/profile-links/v1"),
        };
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
        footer.attribution = f.footer.attribution.as_ref().map(|a| link("footer.attribution", a)).transpose()?;
        footer.report_url = f.footer.report_url.as_deref().map(|u| https("footer.reportUrl", u)).transpose()?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
