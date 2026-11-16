//! `link-in-bio`: one binary for every role.
//!
//! - `serve --mode static`: one page from a manifest file and a site config (the operator's own page);
//! - `serve --mode local`: the editor's backend, loopback only, files in one directory;
//! - `check`: validates a manifest (and its picture) exactly as the page server will;
//! - `render`: writes the page and its documents to a directory;
//! - `schema`, `theme-table`: the limits and the contrast table as JSON.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use link_in_bio_api::config::SiteConfig;
use link_in_bio_api::site::{Site, SiteError, load_avatar, parse_options};
use link_in_bio_api::{local_mode, static_mode};
use link_in_bio_core::Owner;

#[derive(Parser)]
#[command(name = "link-in-bio", version, about = "Link in Bio: pages, documents and the editor's backend")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    /// One page from files (no database).
    Static,
    /// The editor's loopback backend.
    Local,
}

#[derive(Clone, Copy, ValueEnum)]
enum OwnerArg {
    Operator,
    Tenant,
}

impl From<OwnerArg> for Owner {
    fn from(o: OwnerArg) -> Self {
        match o {
            OwnerArg::Operator => Owner::Operator,
            OwnerArg::Tenant => Owner::Tenant,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Serve pages.
    Serve {
        #[arg(long, value_enum)]
        mode: Mode,
        /// static: the site config (JSON).
        #[arg(long, env = "SITE_CONFIG")]
        config: Option<PathBuf>,
        /// static: the manifest.
        #[arg(long, env = "MANIFEST")]
        manifest: Option<PathBuf>,
        /// static: the directory the manifest's picture is in.
        #[arg(long, env = "ASSETS_DIR")]
        assets: Option<PathBuf>,
        /// static: the actor's public key (PEM), published for fediverse servers that expect one.
        #[arg(long, env = "ACTOR_PUBLIC_KEY")]
        actor_key: Option<PathBuf>,
        /// static: the address to listen on.
        #[arg(long, env = "LISTEN_ADDR", default_value = "0.0.0.0:8080")]
        listen: SocketAddr,
        /// local: the page's directory (manifest.json and pictures).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// local: the loopback port.
        #[arg(long, default_value_t = 4298)]
        port: u16,
        /// local: whose page this is (the operator's page may use an SVG picture and a call to action).
        #[arg(long, value_enum, default_value = "tenant")]
        owner: OwnerArg,
    },
    /// Check a manifest (and its picture) exactly as the page server will.
    Check {
        manifest: PathBuf,
        #[arg(long)]
        assets: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "tenant")]
        owner: OwnerArg,
        /// Also fail on warnings and on any remaining TODO placeholder.
        #[arg(long)]
        strict: bool,
    },
    /// Write the page and its documents to a directory.
    Render {
        manifest: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        assets: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the limits the parser enforces (JSON).
    Schema,
    /// Print the contrast table: every accent × button style × season in both modes (JSON).
    ThemeTable,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn print_site_error(e: &SiteError) {
    match e {
        SiteError::Manifest(issues) => {
            eprintln!("The page document is not valid:");
            for i in issues {
                eprintln!("  {i}");
            }
        }
        other => eprintln!("{other}"),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}

async fn serve(app: axum::Router, addr: SocketAddr) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await.map_err(|e| e.to_string())
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Serve { mode: Mode::Static, config, manifest, assets, actor_key, listen, .. } => {
            let config = config.ok_or("--config (or SITE_CONFIG) is required")?;
            let manifest = manifest.ok_or("--manifest (or MANIFEST) is required")?;
            let assets = assets.unwrap_or_else(|| manifest.parent().map(Path::to_path_buf).unwrap_or_default());
            let config = SiteConfig::from_json(&read(&config)?).map_err(|e| e.to_string())?;
            let key = actor_key.map(|k| read(&k)).transpose()?.map(|b| String::from_utf8_lossy(&b).trim().to_string());
            let site = Site::build(config, &read(&manifest)?, &assets, key, now()).map_err(|e| {
                print_site_error(&e);
                "cannot build the page".to_string()
            })?;
            for w in &site.warnings {
                tracing::warn!(path = %w.path, code = w.code, "{}", w.message);
            }
            let app = static_mode::router(Arc::new(site));
            runtime()?.block_on(serve(app, listen))
        }
        Command::Serve { mode: Mode::Local, dir, port, owner, .. } => {
            let dir = dir.ok_or("--dir is required")?;
            std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            let local = local_mode::Local::open(dir, port, owner.into(), now())?;
            // Loopback only, always: the editor is never reachable from another machine.
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            eprintln!("Editor backend on http://127.0.0.1:{port}/ (loopback only)");
            runtime()?.block_on(serve(local_mode::router(local), addr))
        }
        Command::Check { manifest, assets, owner, strict } => {
            let owner: Owner = owner.into();
            let bytes = read(&manifest)?;
            let parsed = match link_in_bio_core::parse(&bytes, parse_options(owner)) {
                Ok(p) => p,
                Err(issues) => {
                    print_site_error(&SiteError::Manifest(issues));
                    return Err("not valid".into());
                }
            };
            let assets = assets.unwrap_or_else(|| manifest.parent().map(Path::to_path_buf).unwrap_or_default());
            if let Err(e) = load_avatar(&parsed.manifest, &assets, owner) {
                print_site_error(&e);
                return Err("the picture cannot be used".into());
            }
            for w in &parsed.warnings {
                eprintln!("warning: {w}");
            }
            let todos = String::from_utf8_lossy(&bytes).matches("TODO").count();
            if todos > 0 {
                eprintln!("{todos} TODO placeholder(s) remain");
            }
            if strict && (!parsed.warnings.is_empty() || todos > 0) {
                return Err("--strict: warnings or placeholders remain".into());
            }
            println!("ok: {} link(s)", parsed.manifest.visible_links().count());
            Ok(())
        }
        Command::Render { manifest, config, assets, out } => {
            let config = SiteConfig::from_json(&read(&config)?).map_err(|e| e.to_string())?;
            let site = Site::build(config, &read(&manifest)?, &assets, None, now()).map_err(|e| {
                print_site_error(&e);
                "cannot build the page".to_string()
            })?;
            let write = |p: &str, b: &[u8]| {
                let path = out.join(p.trim_start_matches('/'));
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                std::fs::write(&path, b).map_err(|e| format!("{}: {e}", path.display()))
            };
            write("index.html", site.html.as_bytes())?;
            write("links.json", site.linkset.as_bytes())?;
            let b = link_in_bio_core::assets::Bundle::get();
            for a in [&b.css, &b.js, &b.icons] {
                write(&a.path, &a.body)?;
            }
            if let Some((p, pic)) = &site.avatar {
                write(p, &pic.bytes)?;
            }
            println!("wrote {}", out.display());
            Ok(())
        }
        Command::Schema => {
            println!("{}", serde_json::to_string_pretty(&link_in_bio_core::limits::limits_json()).unwrap_or_default());
            Ok(())
        }
        Command::ThemeTable => {
            println!("{}", serde_json::to_string_pretty(&link_in_bio_core::theme::option_table()).unwrap_or_default());
            Ok(())
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_writer(std::io::stderr)
        .json()
        .init();
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
