//! `link-in-bio`: one binary for every role.
//!
//! - `serve --mode static`: one page from a manifest file and a site config (the operator's own page);
//! - `serve --mode local`: the editor's backend, loopback only, files in one directory;
//! - `check`: validates a manifest (and its picture) exactly as the page server will;
//! - `render`: writes the page and its documents to a directory;
//! - `schema`, `theme-table`: the limits and the contrast table as JSON;
//! - `serve --mode pages|app|admin`, `worker`, `migrate`: the hosted service (configuration from the environment);
//! - `account create`: the operator's own accounts while sign-up is closed (signed in with a Sui wallet).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use link_in_bio_api::config::SiteConfig;
use link_in_bio_api::site::{Site, SiteError, load_avatar, parse_options};
use link_in_bio_api::{hosted, local_mode, static_mode};
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
    /// Hosted: tenant pages by host (read-only database role).
    Pages,
    /// Hosted: the account API on the app host, and the internal port (provider notifications, metrics).
    App,
    /// Hosted: the operator console's API (behind Cloudflare Access).
    Admin,
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
    /// Hosted: settle checkouts, screen links, check domains, sync ThreatFox, prune (one process holds the lock).
    Worker {
        #[arg(long, env = "WORKER_LISTEN_ADDR", default_value = "0.0.0.0:8081")]
        listen: SocketAddr,
    },
    /// Hosted: apply the database schema (as the owner role).
    Migrate,
    /// Hosted: operator account administration.
    Account {
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Print the limits the parser enforces (JSON).
    Schema,
    /// Print the contrast table: every accent × button style × season in both modes (JSON).
    ThemeTable,
}

#[derive(Subcommand)]
enum AccountAction {
    /// Create one of the operator's own accounts (free, served while third-party pages are off). It signs in with
    /// the given Sui wallet; add a passkey in the app afterwards.
    Create {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        wallet: String,
        /// The terms version recorded (the operator accepts their own terms).
        #[arg(long, env = "TERMS_VERSION")]
        terms_version: String,
    },
    /// Let another Sui wallet sign in to one of the operator's own accounts (for example a browser wallet next to the
    /// CLI key the account was created with). Tenants link wallets in the app, by signing with them.
    AddWallet {
        #[arg(long)]
        handle: String,
        #[arg(long)]
        wallet: String,
    },
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
        Command::Serve { mode: m @ (Mode::Pages | Mode::App | Mode::Admin), listen, .. } => {
            let rt = runtime()?;
            rt.block_on(async move {
                let pool = match m {
                    Mode::Pages => 8,
                    _ => 4,
                };
                let app = hosted_app(pool, matches!(m, Mode::Pages))?;
                match m {
                    Mode::Pages => serve(hosted::pages::router(app), listen).await,
                    Mode::Admin => serve(hosted::admin::router(app), listen).await,
                    _ => {
                        let internal: SocketAddr = std::env::var("INTERNAL_LISTEN_ADDR")
                            .unwrap_or_else(|_| "0.0.0.0:8081".into())
                            .parse()
                            .map_err(|_| "INTERNAL_LISTEN_ADDR is not an address")?;
                        let (a, b) = tokio::join!(
                            serve(hosted::app::router(app.clone()), listen),
                            serve(hosted::internal::router(app), internal)
                        );
                        a.and(b)
                    }
                }
            })
        }
        Command::Worker { listen } => runtime()?.block_on(async move {
            let app = hosted_app(4, false)?;
            let (_, s) = tokio::join!(
                hosted::jobs::run(app.clone(), shutdown_signal()),
                serve(hosted::internal::worker_router(app), listen)
            );
            s
        }),
        Command::Migrate => runtime()?.block_on(async {
            store(1, false)?.migrate().await.map_err(|e| e.to_string())?;
            println!("schema up to date");
            Ok(())
        }),
        Command::Account { action: AccountAction::AddWallet { handle, wallet } } => runtime()?.block_on(async move {
            let store = store(1, false)?;
            let wallet = link_in_bio_auth::wallet::canonical_address(&wallet).ok_or("--wallet is not a Sui address")?;
            let account = store
                .account_by_handle(&handle.trim().to_ascii_lowercase())
                .await
                .map_err(|e| e.to_string())?
                .ok_or("no account has that handle")?;
            if !account.operator {
                return Err("only the operator's own accounts take a wallet here; tenants link wallets in the app".into());
            }
            match store.wallet_owner(&wallet).await.map_err(|e| e.to_string())? {
                Some(owner) if owner == account.id => {
                    println!("{wallet} already signs in to {}", account.handle);
                    return Ok(());
                }
                Some(_) => return Err("that wallet already signs in to another account".into()),
                None => {}
            }
            store.add_wallet(account.id, &wallet).await.map_err(|e| e.to_string())?;
            store
                .audit("operator:cli", "wallet-added", &account.id.to_string(), &serde_json::json!({ "wallet": wallet }))
                .await
                .map_err(|e| e.to_string())?;
            println!("{wallet} now signs in to {}", account.handle);
            Ok(())
        }),
        Command::Account { action: AccountAction::Create { handle, wallet, terms_version } } => runtime()?.block_on(async move {
            let store = store(1, false)?;
            let handle = link_in_bio_core::manifest::check_handle(&handle, false).map_err(|(_, m)| m)?;
            let wallet = link_in_bio_auth::wallet::canonical_address(&wallet).ok_or("--wallet is not a Sui address")?;
            if store.wallet_owner(&wallet).await.map_err(|e| e.to_string())?.is_some() {
                return Err("that wallet already signs in to an account".into());
            }
            let draft = serde_json::json!({ "schema": 1, "identity": { "displayName": handle, "handle": handle }, "items": [] }).to_string();
            let billing_ref = link_in_bio_auth::random_hex(16);
            let skeleton = link_in_bio_core::limits::handle_skeleton(&handle);
            let a = store
                .create_account(
                    &link_in_bio_store::NewAccount {
                        id: uuid::Uuid::new_v4(),
                        handle: &handle,
                        handle_skeleton: &skeleton,
                        terms_version: &terms_version,
                        country_declared: None,
                        billing_ref: &billing_ref,
                        operator: true,
                        draft: &draft,
                        invite_hash: None,
                    },
                    chrono::Utc::now(),
                )
                .await
                .map_err(|e| e.to_string())?;
            store.set_flags(a.id, true, true, true, &[]).await.map_err(|e| e.to_string())?;
            store.add_wallet(a.id, &wallet).await.map_err(|e| e.to_string())?;
            store
                .audit("cli", "operator-account-created", &a.id.to_string(), &serde_json::json!({ "handle": handle }))
                .await
                .map_err(|e| e.to_string())?;
            println!("account {} ({handle}) created; sign in with the wallet {wallet}", a.id);
            Ok(())
        }),
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

fn store(pool: u32, read_only: bool) -> Result<link_in_bio_store::Store, String> {
    use link_in_bio_store::config::{Access, DatabaseSettings};
    let settings = DatabaseSettings::from_env(|k| std::env::var(k).ok()).map_err(|e| e.to_string())?;
    let access = if read_only { Access::ReadOnly } else { Access::ReadWrite };
    Ok(link_in_bio_store::Store::new(settings.lazy_pool(pool, access).map_err(|e| e.to_string())?))
}

/// The hosted settings a process reads. The page server (read-only) never takes payments and holds no provider key,
/// so for it `BILLING_PROVIDERS` is always `manual`, whatever the shared configuration says.
fn hosted_env(read_only: bool, get: impl Fn(&str) -> Option<String>) -> impl Fn(&str) -> Option<String> {
    move |k: &str| if read_only && k == "BILLING_PROVIDERS" { Some("manual".into()) } else { get(k) }
}

fn hosted_app(pool: u32, read_only: bool) -> Result<hosted::Shared, String> {
    let config =
        hosted::HostedConfig::from_env(hosted_env(read_only, |k| std::env::var(k).ok())).map_err(|e| e.to_string())?;
    let cache = std::env::var("PAGE_CACHE_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(30).clamp(1, 600);
    let app = hosted::App::new(store(pool, read_only)?, config, std::time::Duration::from_secs(cache))?;
    Ok(Arc::new(app))
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

#[cfg(test)]
mod hosted_env_tests {
    #[test]
    fn the_page_server_never_reads_payment_providers() {
        let shared = |k: &str| (k == "BILLING_PROVIDERS").then(|| "chain-payments,square".to_string());
        assert_eq!(super::hosted_env(true, shared)("BILLING_PROVIDERS").as_deref(), Some("manual"));
        assert_eq!(super::hosted_env(false, shared)("BILLING_PROVIDERS").as_deref(), Some("chain-payments,square"));
        assert_eq!(super::hosted_env(true, shared)("PAGES_DOMAIN"), None);
    }
}
