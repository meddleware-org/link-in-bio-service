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
    pub config: SiteConfig,
    pub manifest: Manifest,
    pub warnings: Vec<Issue>,
    pub html: String,
    pub linkset: String,
    pub linkset_header: String,
    pub avatar: Option<(String, Picture)>,
    pub actor: Option<String>,
    pub webfinger: String,
    pub security_txt: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SiteError {
    #[error("the page document is not valid")]
    Manifest(Vec<Issue>),
    #[error("the picture {0}: {1}")]
    Avatar(String, AvatarError),
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
}

pub fn parse_options(owner: Owner) -> ParseOptions {
    ParseOptions { owner, check_reserved: owner == Owner::Tenant }
}

/// Reads the picture a manifest names from `assets_dir` and normalises it.
pub fn load_avatar(manifest: &Manifest, assets_dir: &Path, owner: Owner) -> Result<Option<Picture>, SiteError> {
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

    pub fn from_parts(
        config: SiteConfig,
        manifest: Manifest,
        warnings: Vec<Issue>,
        picture: Option<Picture>,
        actor_public_key_pem: Option<String>,
        now_unix: u64,
    ) -> Site {
        let cx = context(&config, picture.as_ref(), false);
        let html = render::render_page(&manifest, &cx);
        let linkset = interop::linkset(&manifest, &cx, &config.profile_uri).to_string();
        let linkset_header =
            interop::linkset_header(cx.linkset_url.as_deref().unwrap_or("/links.json"), &config.profile_uri);
        let actor =
            config.federation.then(|| interop::actor(&manifest, &cx, actor_public_key_pem.as_deref()).to_string());
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
        let avatar = picture.map(|p| (avatar_path(&p), p));
        Site { config, manifest, warnings, html, linkset, linkset_header, avatar, actor, webfinger, security_txt }
    }

    /// The `acct:` resources this site answers WebFinger for.
    pub fn answers_webfinger(&self, resource: &str) -> bool {
        let acct = format!("acct:{}@{}", self.manifest.identity.handle, self.config.host);
        resource.eq_ignore_ascii_case(&acct)
            || resource == self.config.base_url
            || resource == self.config.base_url.trim_end_matches('/')
    }
}
