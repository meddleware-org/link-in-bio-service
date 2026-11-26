//! A built site: every document of one page, rendered once from the manifest and the configuration, held in memory.

use std::path::Path;

use link_in_bio_assets::{Avatar as Picture, AvatarError};
use link_in_bio_core::assets::Bundle;
use link_in_bio_core::render::{Avatar, PageContext};
use link_in_bio_core::{Issue, Manifest, Owner, ParseOptions, interop, render};

use crate::config::SiteConfig;

/// Everything a page serves.
#[derive(Debug)]
pub struct Site {
    /// The configuration the site was built from.
    pub config: SiteConfig,
    /// The checked page document.
    pub manifest: Manifest,
    /// What the parser dropped.
    pub warnings: Vec<Issue>,
    /// The page's HTML.
    pub html: String,
    /// The Profile Links document, as JSON text.
    pub linkset: String,
    /// The `Link` header that advertises it.
    pub linkset_header: String,
    /// The picture and the path it is served at, if there is one.
    pub avatar: Option<(String, Picture)>,
    /// The ActivityPub actor, as JSON text, when federation is on.
    pub actor: Option<String>,
    /// The WebFinger answer, as JSON text.
    pub webfinger: String,
    /// The security.txt, when a contact is configured.
    pub security_txt: Option<String>,
}

/// Why a site could not be built.
#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    /// The page document is not valid; every problem found.
    #[error("the page document is not valid")]
    Manifest(Vec<Issue>),
    /// The picture could not be used: its file name and why.
    #[error("the picture {0}: {1}")]
    Avatar(String, AvatarError),
    /// A file could not be read: its path and the operating system's error.
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
}

/// The parse options for a page of this owner: only a tenant's handle is held to the reserved list.
pub fn parse_options(owner: Owner) -> ParseOptions {
    ParseOptions { owner, check_reserved: owner == Owner::Tenant }
}

/// Reads the picture a manifest names from `assets_dir` and normalises it.
pub fn load_avatar(manifest: &Manifest, assets_dir: &Path, owner: Owner) -> Result<Option<Picture>, SiteError> {
    // A hosted picture is named by its hash and lives in the store, so a file directory cannot resolve it.
    let Some(name) = &manifest.identity.avatar else { return Ok(None) };
    if name.starts_with("sha256:") {
        // Hosted pages keep pictures in the asset store; a file directory cannot resolve them.
        return Ok(None);
    }
    let path = assets_dir.join(name);
    let bytes = std::fs::read(&path).map_err(|e| SiteError::Io(path.display().to_string(), e))?;
    let pic = if name.ends_with(".svg") && owner == Owner::Operator {
        link_in_bio_assets::normalise_operator_svg(&bytes)
    } else {
        link_in_bio_assets::normalise_raster(&bytes)
    };
    pic.map(Some).map_err(|e| SiteError::Avatar(name.clone(), e))
}

/// The path a normalised picture is served at.
pub fn avatar_path(p: &Picture) -> String {
    format!("/_/avatar.{}.{}", &p.sha256[..12], p.ext)
}

/// Builds the page context for a configuration and picture.
pub fn context(config: &SiteConfig, avatar: Option<&Picture>, inline_sprite: bool) -> PageContext {
    // The addresses of the interop documents are built from the configured base address.
    let base = config.base_url.trim_end_matches('/');
    PageContext {
        canonical: config.base_url.clone(),
        assets: Bundle::get().urls(),
        avatar: avatar.map(|p| Avatar {
            url: format!("{base}{}", avatar_path(p)),
            path: avatar_path(p),
            width: p.width,
            height: p.height,
            mime: p.mime,
        }),
        owner: config.owner,
        footer: config.footer.clone(),
        brand_icons: config.brand_icons,
        explorer: config.explorer.clone(),
        linkset_url: Some(format!("{base}/links.json")),
        actor_url: config.federation.then(|| format!("{base}/actor")),
        inline_sprite,
    }
}

impl Site {
    /// Build a site from a manifest's bytes, reading its picture from `assets_dir`.
    pub fn build(
        config: SiteConfig,
        manifest_bytes: &[u8],
        assets_dir: &Path,
        actor_public_key_pem: Option<String>,
        now_unix: u64,
    ) -> Result<Site, SiteError> {
        let parsed =
            link_in_bio_core::parse(manifest_bytes, parse_options(config.owner)).map_err(SiteError::Manifest)?;
        let picture = load_avatar(&parsed.manifest, assets_dir, config.owner)?;
        Ok(Self::from_parts(config, parsed.manifest, parsed.warnings, picture, actor_public_key_pem, now_unix))
    }

    /// Build a site from an already-checked manifest and picture: render the page and every document derived from it, once.
    pub fn from_parts(
        config: SiteConfig,
        manifest: Manifest,
        warnings: Vec<Issue>,
        picture: Option<Picture>,
        actor_public_key_pem: Option<String>,
        now_unix: u64,
    ) -> Site {
        // The page, the link set, the actor and the WebFinger answer are rendered once here and served from memory afterwards.
        let cx = context(&config, picture.as_ref(), false);
        let html = render::render_page(&manifest, &cx);
        let linkset = interop::linkset(&manifest, &cx, &config.profile_uri).to_string();
        let linkset_header =
            interop::linkset_header(cx.linkset_url.as_deref().unwrap_or("/links.json"), &config.profile_uri);
        let actor =
            config.federation.then(|| interop::actor(&manifest, &cx, actor_public_key_pem.as_deref()).to_string());
        // The WebFinger answer is always built; it names the account on this host.
        let webfinger = interop::webfinger(&manifest, &cx, &config.host).to_string();
        let security_txt = config.security_contact.as_deref().map(|c| {
            let expires = crate::time::rfc3339(now_unix + 365 * 24 * 3600);
            interop::security_txt(
                c,
                &format!("{}.well-known/security.txt", config.base_url),
                &expires,
                config.security_policy.as_deref(),
            )
        });
        // The picture is kept with the path it is served at.
        let avatar = picture.map(|p| (avatar_path(&p), p));
        Site { config, manifest, warnings, html, linkset, linkset_header, avatar, actor, webfinger, security_txt }
    }

    /// The `acct:` resources this site answers WebFinger for.
    pub fn answers_webfinger(&self, resource: &str) -> bool {
        // The account address, or the page's own address with or without its slash.
        let acct = format!("acct:{}@{}", self.manifest.identity.handle, self.config.host);
        resource.eq_ignore_ascii_case(&acct)
            || resource == self.config.base_url
            || resource == self.config.base_url.trim_end_matches('/')
    }
}
