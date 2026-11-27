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

// The command line is declared with `clap`'s derive macros.
use clap::{Parser, Subcommand, ValueEnum};

use link_in_bio_api::config::SiteConfig;
use link_in_bio_api::site::{Site, SiteError, load_avatar, parse_options};
use link_in_bio_api::{hosted, local_mode, static_mode};
use link_in_bio_core::Owner;

/// The command line: one binary, one subcommand per role or task.
#[derive(Parser)]
#[command(name = "link-in-bio", version, about = "Link in Bio: pages, documents and the editor's backend")]
struct Cli {
    /// What to run.
    #[command(subcommand)]
    command: Command,
}

/// Which kind of server `serve` runs.
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

/// Whose page a command works on.
#[derive(Clone, Copy, ValueEnum)]
enum OwnerArg {
    /// The operator's own page.
    Operator,
    /// A tenant's page.
    Tenant,
}

impl From<OwnerArg> for Owner {
    /// A command-line owner as the library's owner type.
    fn from(o: OwnerArg) -> Self {
        match o {
            OwnerArg::Operator => Owner::Operator,
            OwnerArg::Tenant => Owner::Tenant,
        }
    }
}

/// The subcommands.
#[derive(Subcommand)]
enum Command {
    /// Serve pages.
    Serve {
        /// Which role to run: the static page, the local editor, or a hosted role (pages, app, console).
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
        /// The manifest to check.
        manifest: PathBuf,
        /// The directory the manifest's picture is in.
        #[arg(long)]
        assets: Option<PathBuf>,
        /// Whose page this is; the operator's page may use an SVG picture and a call to action.
        #[arg(long, value_enum, default_value = "tenant")]
        owner: OwnerArg,
        /// Also fail on warnings and on any remaining TODO placeholder.
        #[arg(long)]
        strict: bool,
    },
    /// Write the page and its documents to a directory.
    Render {
        /// The manifest to render.
        manifest: PathBuf,
        /// The site config (JSON).
        #[arg(long)]
        config: PathBuf,
        /// The directory the manifest's picture is in.
        #[arg(long)]
        assets: PathBuf,
        /// The directory the page and its documents are written to.
        #[arg(long)]
        out: PathBuf,
    },
    /// Hosted: settle checkouts, screen links, check domains, sync ThreatFox, prune (one process holds the lock).
    Worker {
        /// The address the worker's health and metrics endpoint listens on.
        #[arg(long, env = "WORKER_LISTEN_ADDR", default_value = "0.0.0.0:8081")]
        listen: SocketAddr,
    },
    /// Hosted: apply the database schema (as the owner role).
    Migrate,
    /// Hosted: bank feed set-up.
    BankFeed {
        /// The set-up step to run.
        #[command(subcommand)]
        action: BankFeedAction,
    },
    /// Hosted: operator account administration.
    Account {
        /// The administration step to run.
        #[command(subcommand)]
        action: AccountAction,
    },
    /// Print the limits the parser enforces (JSON).
    Schema,
    /// Print the contrast table: every accent × button style × season in both modes (JSON).
    ThemeTable,
}

/// Operator account administration.
#[derive(Subcommand)]
enum AccountAction {
    /// Create one of the operator's own accounts (free, served while third-party pages are off). It signs in with
    /// the given Sui wallet; add a passkey in the app afterwards.
    Create {
        /// The new account's handle (its page address).
        #[arg(long)]
        handle: String,
        /// The Sui address that signs in to the account.
        #[arg(long)]
        wallet: String,
        /// The terms version recorded (the operator accepts their own terms).
        #[arg(long, env = "TERMS_VERSION")]
        terms_version: String,
    },
    /// Let another Sui wallet sign in to one of the operator's own accounts (for example a browser wallet next to the
    /// CLI key the account was created with). Tenants link wallets in the app, by signing with them.
    AddWallet {
        /// The handle of the operator's account.
        #[arg(long)]
        handle: String,
        /// The additional Sui address that may sign in.
        #[arg(long)]
        wallet: String,
    },
}

/// Bank feed set-up.
#[derive(Subcommand)]
enum BankFeedAction {
    /// Exchange the code from Revolut Business's consent page for a refresh token, written to a new file (mode 0600)
    /// for REVOLUT_REFRESH_TOKEN_FILE. Reads REVOLUT_API_BASE, REVOLUT_CLIENT_ID, REVOLUT_ISSUER and REVOLUT_KEY_FILE.
    /// The token is never printed.
    RevolutToken {
        /// The authorisation code from the consent page.
        #[arg(long)]
        code: String,
        /// The new file the refresh token is written to.
        #[arg(long)]
        out: PathBuf,
    },
}

/// The current time in Unix seconds (zero if the clock is before the epoch).
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Print a site error for a person: a list of the document's problems, or the one error.
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

/// Read a file; the error names the file.
fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Resolve when the process is asked to stop (Ctrl-C or SIGTERM).
async fn shutdown_signal() {
    // Ctrl-C for a terminal, SIGTERM for a Pod being stopped.
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

/// Serve a router until the process is asked to stop, finishing the requests in flight.
async fn serve(app: axum::Router, addr: SocketAddr) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("cannot listen on {addr}: {e}"))?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await.map_err(|e| e.to_string())
}

/// Run the chosen subcommand.
fn run(cli: Cli) -> Result<(), String> {
    // Each subcommand is one arm; the hosted ones build their own runtime and read their settings from the environment.
    match cli.command {
        Command::Serve { mode: Mode::Static, config, manifest, assets, actor_key, listen, .. } => {
            // Static mode needs the site configuration and the manifest.
            let config = config.ok_or("--config (or SITE_CONFIG) is required")?;
            let manifest = manifest.ok_or("--manifest (or MANIFEST) is required")?;
            // The picture is looked for beside the manifest unless a directory is given.
            let assets = assets.unwrap_or_else(|| manifest.parent().map(Path::to_path_buf).unwrap_or_default());
            let config = SiteConfig::from_json(&read(&config)?).map_err(|e| e.to_string())?;
            let key = actor_key.map(|k| read(&k)).transpose()?.map(|b| String::from_utf8_lossy(&b).trim().to_string());
            let site = Site::build(config, &read(&manifest)?, &assets, key, now()).map_err(|e| {
                print_site_error(&e);
                "cannot build the page".to_string()
            })?;
            // What the parser dropped is logged, so the operator sees it.
            for w in &site.warnings {
                tracing::warn!(path = %w.path, code = w.code, "{}", w.message);
            }
            // The same time and concurrency bound as the hosted routers.
            let app = hosted::bounded(static_mode::router(Arc::new(site)), hosted::REQUEST_TIMEOUT, 128);
            runtime()?.block_on(serve(app, listen))
        }
        Command::Serve { mode: m @ (Mode::Pages | Mode::App | Mode::Admin), listen, .. } => {
            let rt = runtime()?;
            rt.block_on(async move {
                // The page server takes more connections than the others.
                let pool = match m {
                    Mode::Pages => 8,
                    _ => 4,
                };
                // The role decides which settings and secrets the process reads.
                let role = match m {
                    Mode::Pages => Role::Pages,
                    Mode::Admin => Role::Console,
                    _ => Role::App,
                };
                let app = hosted_app(pool, role)?;
                match m {
                    Mode::Pages => serve(hosted::pages::router(app), listen).await,
                    Mode::Admin => {
                        // Expired sign-ins and sessions are removed every ten minutes (they are never accepted after they expire; this only keeps the tables small).
                        if let Some(o) = app.oidc.clone() {
                            let store = app.store.clone();
                            tokio::spawn(async move {
                                loop {
                                    tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                                    if let Err(e) = o.purge(&store).await {
                                        tracing::warn!(error = %e, "purging expired console sessions failed");
                                    }
                                }
                            });
                        }
                        serve(hosted::admin::router(app), listen).await
                    }
                    _ => {
                        // The app also serves the internal port (provider notifications, metrics).
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
            let app = hosted_app(4, Role::Worker)?;
            // The worker builds the bank feeds, so only it reads the bank credentials.
            let feeds = hosted::jobs::bank_feeds(&app.config)?;
            // The duties and the metrics server run together and stop together.
            let (_, s) = tokio::join!(
                hosted::jobs::run(app.clone(), feeds, shutdown_signal()),
                serve(hosted::internal::worker_router(app), listen)
            );
            s
        }),
        Command::BankFeed { action: BankFeedAction::RevolutToken { code, out } } => runtime()?.block_on(async move {
            use link_in_bio_billing::bank_feed::revolut;
            let env = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
            let need = |k: &'static str| env(k).ok_or(format!("{k} is not set"));
            let base = env("REVOLUT_API_BASE").unwrap_or_else(|| revolut::SANDBOX.into());
            // The settings come from the environment, like the worker's.
            let key_file = need("REVOLUT_KEY_FILE")?;
            let key = link_in_bio_billing::keys::RsaKey::from_pem(&String::from_utf8_lossy(&read(Path::new(&key_file))?))
                .map_err(|e| format!("{key_file}: {e}"))?;
            let token = revolut::exchange_code(
                &link_in_bio_billing::http_client(),
                &base,
                &need("REVOLUT_CLIENT_ID")?,
                &need("REVOLUT_ISSUER")?,
                &key,
                code.trim(),
            )
            .await
            .map_err(|e| e.to_string())?;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // The token goes into a new file readable only by its owner, and is never printed.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&out)
                .map_err(|e| format!("{}: {e}", out.display()))?;
            f.write_all(token.as_bytes()).map_err(|e| e.to_string())?;
            println!("refresh token written to {}", out.display());
            Ok(())
        }),
        // Migrating uses the owner role, which the environment's `DATABASE_URL` names.
        Command::Migrate => runtime()?.block_on(async {
            store(1, false)?.migrate().await.map_err(|e| e.to_string())?;
            println!("schema up to date");
            Ok(())
        }),
        Command::Account { action: AccountAction::AddWallet { handle, wallet } } => runtime()?.block_on(async move {
            let store = store(1, false)?;
            // The address in its canonical form.
            let wallet = link_in_bio_auth::wallet::canonical_address(&wallet).ok_or("--wallet is not a Sui address")?;
            let account = store
                .account_by_handle(&handle.trim().to_ascii_lowercase())
                .await
                .map_err(|e| e.to_string())?
                .ok_or("no account has that handle")?;
            // Only the operator's own accounts take a wallet here.
            if !account.operator {
                return Err("only the operator's own accounts take a wallet here; tenants link wallets in the app".into());
            }
            // A wallet already on this account is a no-op; on another account it is refused.
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
            // The operator's handles are not held to the reserved list.
            let handle = link_in_bio_core::manifest::check_handle(&handle, false).map_err(|(_, m)| m)?;
            let wallet = link_in_bio_auth::wallet::canonical_address(&wallet).ok_or("--wallet is not a Sui address")?;
            if store.wallet_owner(&wallet).await.map_err(|e| e.to_string())?.is_some() {
                return Err("that wallet already signs in to an account".into());
            }
            // The first draft is a page with only a name.
            let draft = serde_json::json!({ "schema": 1, "identity": { "displayName": handle, "handle": handle }, "items": [] }).to_string();
            // An opaque reference for payment providers.
            let billing_ref = link_in_bio_auth::random_hex(16);
            // The skeleton keeps look-alike handles unique.
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
                    time::OffsetDateTime::now_utc(),
                )
                .await
                .map_err(|e| e.to_string())?;
            // The account is the operator's own, free, and may share invites.
            store.set_flags(a.id, true, true, true, &[]).await.map_err(|e| e.to_string())?;
            store.add_wallet(a.id, &wallet).await.map_err(|e| e.to_string())?;
            store
                .audit("cli", "operator-account-created", &a.id.to_string(), &serde_json::json!({ "handle": handle }))
                .await
                .map_err(|e| e.to_string())?;
            // Only public values are printed.
            println!("account {} ({handle}) created; sign in with the wallet {wallet}", a.id);
            Ok(())
        }),
        Command::Serve { mode: Mode::Local, dir, port, owner, .. } => {
            let dir = dir.ok_or("--dir is required")?;
            // The directory is made if it does not exist.
            std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
            // The editor's state over the directory.
            let local = local_mode::Local::open(dir, port, owner.into(), now())?;
            // Loopback only, always: the editor is never reachable from another machine.
            // The address is fixed to loopback and cannot be set.
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            eprintln!("Editor backend on http://127.0.0.1:{port}/ (loopback only)");
            runtime()?.block_on(serve(local_mode::router(local), addr))
        }
        Command::Check { manifest, assets, owner, strict } => {
            // The command-line owner as the library's.
            let owner: Owner = owner.into();
            // The document as the file holds it.
            let bytes = read(&manifest)?;
            // The same parser and rules as the page server.
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
            // Warnings are printed but do not fail unless `--strict`.
            for w in &parsed.warnings {
                eprintln!("warning: {w}");
            }
            // A leftover placeholder in the document is reported, and an error with --strict.
            let todos = String::from_utf8_lossy(&bytes).matches("TODO").count();
            if todos > 0 {
                eprintln!("{todos} TODO placeholder(s) remain");
            }
            if strict && (!parsed.warnings.is_empty() || todos > 0) {
                return Err("--strict: warnings or placeholders remain".into());
            }
            // The count of links a visitor would see.
            println!("ok: {} link(s)", parsed.manifest.visible_links().count());
            Ok(())
        }
        Command::Render { manifest, config, assets, out } => {
            let config = SiteConfig::from_json(&read(&config)?).map_err(|e| e.to_string())?;
            let site = Site::build(config, &read(&manifest)?, &assets, None, now()).map_err(|e| {
                print_site_error(&e);
                "cannot build the page".to_string()
            })?;
            // Write a file under the output directory, making its folders.
            let write = |p: &str, b: &[u8]| {
                let path = out.join(p.trim_start_matches('/'));
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                }
                std::fs::write(&path, b).map_err(|e| format!("{}: {e}", path.display()))
            };
            // The page and its link set.
            write("index.html", site.html.as_bytes())?;
            write("links.json", site.linkset.as_bytes())?;
            let b = link_in_bio_core::assets::Bundle::get();
            // The three embedded files go to their hashed paths.
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

/// A store over the database named by `DATABASE_URL`, with a pool of this size, read-only or read-write.
fn store(pool: u32, read_only: bool) -> Result<link_in_bio_store::Store, String> {
    // The connection is lazy: nothing connects until first use.
    use link_in_bio_store::config::{Access, DatabaseSettings};
    // The settings are read from the environment, and the error redacts the URL.
    let settings = DatabaseSettings::from_env(|k| std::env::var(k).ok()).map_err(|e| e.to_string())?;
    // Only the page server uses a read-only pool.
    let access = if read_only { Access::ReadOnly } else { Access::ReadWrite };
    Ok(link_in_bio_store::Store::new(settings.lazy_pool(pool, access).map_err(|e| e.to_string())?))
}

/// The hosted process roles, for what each may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// `serve --mode pages`: tenant pages; no payment, no screening, no key.
    Pages,
    /// `serve --mode app`: the account API and provider notifications; the providers' and Web Risk keys.
    App,
    /// `serve --mode admin`: the console; switches for display only, no key.
    Console,
    /// `worker`: reconciliation, screening, bank feeds; every key it is configured with.
    Worker,
}

impl Role {
    /// Whether the role holds key files.
    fn keys(self) -> hosted::Keys {
        match self {
            Role::App | Role::Worker => hosted::Keys::Read,
            Role::Pages | Role::Console => hosted::Keys::DisplayOnly,
        }
    }
}

/// The hosted settings a process reads. The page server never takes payments, screens no link and mounts no secret,
/// so for it `BILLING_PROVIDERS` is always `manual`, `BANK_FEEDS` empty and every `*_FILE` setting (provider and bank
/// keys, the Web Risk and ThreatFox keys) unset, whatever the shared configuration says. The console sees every switch
/// (it shows them) but, like the page server, holds no key: its configuration is parsed with `Keys::DisplayOnly`
/// ([`Role::keys`]), so no `*_FILE` setting is required or read. A key path in the shared ConfigMap can never make either
/// read, or fail on, a file it does not have.
fn hosted_env(role: Role, get: impl Fn(&str) -> Option<String>) -> impl Fn(&str) -> Option<String> {
    // Only the page server is filtered: it sees no payment provider, no bank feed and no `*_FILE` setting, so nothing it does can read a secret.
    // Only the page server is restricted.
    let pages = role == Role::Pages;
    move |k: &str| match k {
        "BILLING_PROVIDERS" if pages => Some("manual".into()),
        "BANK_FEEDS" if pages => None,
        // Only the console signs operators in: every other role sees the default (Access only), so a shared ConfigMap that switches the console to OpenID Connect never makes the
        // page server, the app or the worker require settings and secret files that only the console has.
        "ADMIN_AUTH" if role != Role::Console => None,
        // No secret file path reaches the page server.
        _ if pages && k.ends_with("_FILE") => None,
        _ => get(k),
    }
}

/// The hosted configuration for a role, through its filter.
fn hosted_config(role: Role, get: impl Fn(&str) -> Option<String>) -> Result<hosted::HostedConfig, String> {
    hosted::HostedConfig::from_env_with(hosted_env(role, get), role.keys()).map_err(|e| e.to_string())
}

/// Build the hosted application for a role. The page cache time is `PAGE_CACHE_SECS` (30 by default, between 1 and 600), and only the page server opens a read-only pool.
fn hosted_app(pool: u32, role: Role) -> Result<hosted::Shared, String> {
    let config = hosted_config(role, |k| std::env::var(k).ok())?;
    // Between a second and ten minutes.
    let cache = std::env::var("PAGE_CACHE_SECS").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(30).clamp(1, 600);
    let app = hosted::App::new(store(pool, role == Role::Pages)?, config, std::time::Duration::from_secs(cache))?;
    Ok(Arc::new(app))
}

/// A multi-threaded runtime.
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())
}

/// The entry point: JSON logs on standard error, then the subcommand; a failure prints one line and exits non-zero.
fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        // Logs go to standard error as JSON, so standard output stays for the commands' own output.
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

/// Unit tests for what each hosted role may read.
#[cfg(test)]
mod hosted_env_tests {
    use super::Role;

    /// Only the console sees `ADMIN_AUTH`; every other role keeps the default (Access only), whatever the shared configuration says.
    #[test]
    fn only_the_console_sees_the_admin_auth_switch() {
        // A shared configuration that switches the console to OpenID Connect.
        let shared = |k: &str| (k == "ADMIN_AUTH").then(|| "oidc".to_string());
        assert_eq!(super::hosted_env(Role::Console, shared)("ADMIN_AUTH").as_deref(), Some("oidc"));
        for role in [Role::Pages, Role::App] {
            assert_eq!(super::hosted_env(role, shared)("ADMIN_AUTH"), None);
        }
    }

    /// The page server's environment names only the manual provider and no bank feed, and every other role sees the shared one.
    #[test]
    fn the_page_server_never_reads_payment_providers() {
        // The shared configuration names two providers.
        let shared = |k: &str| (k == "BILLING_PROVIDERS").then(|| "chain-payments,square".to_string());
        assert_eq!(super::hosted_env(Role::Pages, shared)("BILLING_PROVIDERS").as_deref(), Some("manual"));
        for role in [Role::App, Role::Console, Role::Worker] {
            assert_eq!(super::hosted_env(role, shared)("BILLING_PROVIDERS").as_deref(), Some("chain-payments,square"));
        }
        let feeds = |k: &str| (k == "BANK_FEEDS").then(|| "wise".to_string());
        assert_eq!(super::hosted_env(Role::Pages, feeds)("BANK_FEEDS"), None);
        assert_eq!(super::hosted_env(Role::Worker, feeds)("BANK_FEEDS").as_deref(), Some("wise"));
        assert_eq!(super::hosted_env(Role::Pages, shared)("PAGES_DOMAIN"), None);
    }

    /// The shared ConfigMap names every switch and the Web Risk key path; the provider keys' paths are set only in the
    /// processes that mount them (absent here, as in the console's and the page server's Deployments).
    fn shared(k: &str) -> Option<String> {
        match k {
            "PAGES_DOMAIN" => Some("example.link".to_string()),
            "APP_HOST" => Some("app.example.link".to_string()),
            "BILLING_PROVIDERS" => Some("chain-payments,square,bank-transfer".to_string()),
            "CHAIN_PAYMENTS_METHODS" => Some("sui-testnet:SUI=SUI".to_string()),
            "CHAIN_PAYMENTS_ORIGIN" => Some("https://cp.example.org".to_string()),
            "CHAIN_PAYMENTS_MERCHANT_API" | "CHAIN_PAYMENTS_PUBLIC_API" => Some("http://cp.svc".to_string()),
            "SQUARE_LOCATION_ID" => Some("L1".to_string()),
            "BANK_TRANSFER_SCHEME" => Some("faster-payments".to_string()),
            "BANK_TRANSFER_PAYEE" => Some("Example Ltd".to_string()),
            "BANK_TRANSFER_SORT_CODE" => Some("12-34-56".to_string()),
            "BANK_TRANSFER_ACCOUNT_NUMBER" => Some("12345678".to_string()),
            "WEB_RISK_KEY_FILE" | "THREATFOX_KEY_FILE" => Some(format!("/nonexistent/{k}")),
            _ => None,
        }
    }

    /// The shared environment plus a path for every `*_FILE` setting, as a process that mounts the secrets would see.
    fn with_keys(k: &str) -> Option<String> {
        shared(k).or_else(|| k.ends_with("_FILE").then(|| format!("/nonexistent/{k}")))
    }

    /// The page server sees no key file and parses with none, while the app sees them all.
    #[test]
    fn the_page_server_never_reads_a_secret_file() {
        for k in ["WEB_RISK_KEY_FILE", "THREATFOX_KEY_FILE", "CHAIN_PAYMENTS_KEY_FILE", "SQUARE_ACCESS_TOKEN_FILE"] {
            assert_eq!(super::hosted_env(Role::Pages, with_keys)(k), None, "{k}");
            assert_eq!(super::hosted_env(Role::App, with_keys)(k), Some(format!("/nonexistent/{k}")), "{k}");
        }
        assert_eq!(super::hosted_env(Role::Pages, with_keys)("PAGES_DOMAIN").as_deref(), Some("example.link"));
        let pages = super::hosted_config(Role::Pages, with_keys).unwrap();
        assert!(pages.web_risk_key_file.is_none() && pages.threatfox_key_file.is_none() && !pages.web_risk_on);
        assert!(pages.chain_payments.is_none() && pages.bank_feeds.is_empty());
        let app = super::hosted_config(Role::App, with_keys).unwrap();
        assert_eq!(app.web_risk_key_file.as_deref(), Some("/nonexistent/WEB_RISK_KEY_FILE"));
    }

    /// The console starts without any key path, shows every switch, and holds none of the keys; the app, which needs them, refuses to start without.
    #[test]
    fn the_console_shows_the_switches_and_holds_no_key() {
        // The app and the worker need their key paths; the console starts without any.
        assert!(super::hosted_config(Role::App, shared).is_err(), "the app needs CHAIN_PAYMENTS_KEY_FILE");
        let c = super::hosted_config(Role::Console, shared).unwrap();
        assert_eq!(c.keys, link_in_bio_api::hosted::Keys::DisplayOnly);
        assert!(c.billing_providers.contains("chain-payments") && c.billing_providers.contains("square"));
        assert!(c.web_risk_on, "the switch is shown");
        assert!(c.web_risk_key_file.is_none() && c.threatfox_key_file.is_none());
        assert_eq!(c.chain_payments.as_ref().unwrap().api_key_file, "");
        assert_eq!(c.square.as_ref().unwrap().access_token_file, "");
        assert!(c.bank_transfer.is_some(), "statement imports need the scheme, which is not a secret");
    }
}
