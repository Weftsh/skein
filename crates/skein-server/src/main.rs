//! `skein` — a self-hosted package registry for npm, Maven, PyPI, Cargo
//! and container images.
//!
//! ```text
//! skein                       serve (the default)
//! skein admin bootstrap       create the organization and its first admin
//! skein admin create-user     add a person or a CI service account
//! skein admin reset-password  get back into an account
//! skein admin mint-token      mint an API token for somebody
//! skein admin set-role        change what somebody may do
//! skein admin gc              collect unreferenced package bytes now
//! skein admin license …       the commercial licence: status, install, check, keys
//! ```
//!
//! Configuration is the environment — see `docs/operations.md`.

// Handlers use `Result<T, Response>` so an authorization failure short-
// circuits with the exact HTTP response the client needs; the "large Err
// variant" lint is noise for that idiom.
#![allow(clippy::result_large_err)]

mod api;
mod app;
mod authx;
mod gc;
mod license;
mod registry;
mod throttle;
mod ui;

use clap::{Parser, Subcommand};
use skein_control::auth::Scope;
use skein_control::users::Role;
use skein_control::ControlDb;
use std::io::Read;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "skein",
    version,
    about = "A self-hosted package registry for npm, Maven, PyPI, Cargo and container images"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the registry, the API and the UI (the default).
    Serve,
    /// Set up and repair an install from the server's own shell.
    #[command(subcommand)]
    Admin(Admin),
}

#[derive(Subcommand)]
enum Admin {
    /// Create the organization this install serves and its first admin.
    ///
    /// Prints the admin's password and an API token, once. Refuses to run
    /// twice: an install serves one organization.
    Bootstrap {
        /// The organization's name: lowercase letters, digits and dashes.
        #[arg(long)]
        org: String,
        /// The first admin's username.
        #[arg(long, default_value = "admin")]
        username: String,
        /// Read the admin's password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
        /// Ecosystems to switch on, comma-separated, or `none`. Defaults
        /// to every ecosystem this build serves, in private mode.
        #[arg(long)]
        ecosystems: Option<String>,
        /// Print JSON instead of prose.
        #[arg(long)]
        json: bool,
    },
    /// Add a person, or a service account for CI (`--no-password`).
    CreateUser {
        username: String,
        #[arg(long, default_value = "reader")]
        role: String,
        /// A service account: it holds tokens and cannot sign in.
        #[arg(long)]
        no_password: bool,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        json: bool,
    },
    /// Set a new password for somebody, and sign them out everywhere.
    /// Prints the new password unless `--password-stdin`.
    ResetPassword {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Mint an API token for somebody. Prints it once.
    MintToken {
        username: String,
        #[arg(long, default_value = "cli")]
        label: String,
        /// Repeatable: package:read, package:write, org:read, org:admin.
        #[arg(long = "scope", default_value = "package:read")]
        scopes: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Change somebody's role: admin, publisher or reader.
    SetRole { username: String, role: String },
    /// Collect package bytes nothing references any more, now.
    Gc {
        /// Only what has been unreferenced for at least this long.
        #[arg(long, default_value_t = 3600)]
        grace_secs: u64,
    },
    /// The commercial licence. It never stops Skein; these say what it says.
    #[command(subcommand)]
    License(LicenseCmd),
}

#[derive(Subcommand)]
enum LicenseCmd {
    /// What the licence says: its terms, seats, warnings and the last check.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Install a licence key, read from stdin so it stays out of the
    /// process list and the shell history.
    Install,
    /// Run the daily check now.
    Check {
        #[arg(long)]
        json: bool,
    },
    /// The signing keys this build trusts. Needs no database: the release
    /// workflow runs it on the binary it is about to publish.
    Keys {
        #[arg(long)]
        json: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    let out = match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(),
        Command::Admin(a) => admin(a),
    };
    if let Err(e) = out {
        eprintln!("skein: {e}");
        std::process::exit(1);
    }
}

fn env_required(var: &str, example: &str) -> Result<String, String> {
    std::env::var(var)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| format!("{var} must be set (e.g. {example})"))
}

fn open_db() -> Result<ControlDb, String> {
    let url = env_required(
        "SKEIN_DB_URL",
        "postgres://skein:skein@127.0.0.1:5432/skein",
    )?;
    ControlDb::open(&url)
}

fn state() -> Result<app::SharedState, String> {
    let db = open_db()?;
    let store_url = env_required("SKEIN_STORE_URL", "http://127.0.0.1:9000/skein")?;
    let public_url = std::env::var("SKEIN_PUBLIC_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "http://localhost:8080".to_string());
    let license = license::Licensing::from_env()?;
    license.init(&db)?;
    let sign_ins = throttle::Throttle::new(throttle::Policy::from_env()?);
    Ok(Arc::new(app::AppState::new(
        db,
        store_url.trim_end_matches('/').to_string(),
        public_url.trim_end_matches('/').to_string(),
        license,
        sign_ins,
    )))
}

fn serve() -> Result<(), String> {
    let state = state()?;
    // MinIO and the other self-hosted stores: create the bucket rather
    // than make everybody reach for a separate tool first.
    if matches!(
        std::env::var("SKEIN_STORE_CREATE_BUCKET").as_deref(),
        Ok("1" | "true" | "yes")
    ) && skein_store::ObjectStore::new(&state.store_url).ensure_bucket()?
    {
        eprintln!("skein: created the bucket at {}", state.store_url);
    }
    let bind = std::env::var("SKEIN_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?
        .block_on(app::serve(state, &bind))
}

/// A password nobody chose: 24 characters of base32 from the OS CSPRNG,
/// 120 bits.
fn generated_password() -> String {
    skein_control::ids::token_secret()[..24].to_string()
}

fn read_stdin_password() -> Result<String, String> {
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| format!("read password from stdin: {e}"))?;
    Ok(s.trim_end_matches(['\n', '\r']).to_string())
}

fn parse_role(s: &str) -> Result<Role, String> {
    Role::parse(s).ok_or_else(|| format!("unknown role {s:?} (admin | publisher | reader)"))
}

fn user(db: &ControlDb, username: &str) -> Result<skein_control::users::User, String> {
    skein_control::users::by_username(db, username)?
        .ok_or_else(|| format!("no user called {username:?}"))
}

fn admin(cmd: Admin) -> Result<(), String> {
    if let Admin::License(LicenseCmd::Keys { json }) = cmd {
        let ids = license::Licensing::from_env()?.trusted_key_ids();
        if json {
            println!("{}", serde_json::json!({ "trusted_key_ids": ids }));
        } else if ids.is_empty() {
            println!("this build trusts no licence signing keys");
        } else {
            println!("{}", ids.join("\n"));
        }
        return Ok(());
    }
    let db = open_db()?;
    match cmd {
        Admin::Bootstrap {
            org,
            username,
            password_stdin,
            ecosystems,
            json,
        } => {
            let ecos = match ecosystems.as_deref() {
                None => skein_control::packages::Ecosystem::ALL
                    .into_iter()
                    .filter(|e| app::served(*e))
                    .collect(),
                Some("none") => Vec::new(),
                Some(list) => list
                    .split(',')
                    .map(|s| {
                        let s = s.trim();
                        skein_control::packages::Ecosystem::parse(s)
                            .filter(|e| app::served(*e))
                            .ok_or_else(|| format!("{s:?} is not an ecosystem this build serves"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            let (password, generated) = if password_stdin {
                (read_stdin_password()?, false)
            } else {
                (generated_password(), true)
            };
            let o = skein_control::registry::create_org(&db, &org)?;
            let u = skein_control::users::create(&db, &username, Role::Admin, Some(&password))?;
            let now = skein_control::ids::now_ms();
            for e in &ecos {
                skein_control::packages::set_ecosystem_policy(
                    &db,
                    &o.id,
                    *e,
                    skein_control::packages::MODE_PRIVATE,
                    "block",
                    now,
                )?;
            }
            let (_, token) =
                skein_control::auth::mint(&db, &u, "bootstrap", &[Scope::OrgAdmin], None)?;
            let ctx = skein_control::audit::AuditCtx::system(&o.id, "bootstrap");
            skein_control::audit::record(
                &db,
                &ctx,
                "org.bootstrap",
                Some(&serde_json::json!({ "org": o.name, "admin": u.username })),
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "org": o.name,
                        "username": u.username,
                        "password": if generated { Some(&password) } else { None },
                        "token": token,
                        "ecosystems": ecos.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                    })
                );
            } else {
                println!("Skein is set up for {}.\n", o.name);
                println!("  admin username  {}", u.username);
                if generated {
                    println!("  admin password  {password}");
                }
                println!("  admin API token {token}\n");
                println!(
                    "Both are shown once. Sign in to the UI with the password; use the token \
                     for scripts, or revoke it from the UI."
                );
            }
            Ok(())
        }
        Admin::CreateUser {
            username,
            role,
            no_password,
            password_stdin,
            json,
        } => {
            let role = parse_role(&role)?;
            let password = match (no_password, password_stdin) {
                (true, _) => None,
                (false, true) => Some(read_stdin_password()?),
                (false, false) => Some(generated_password()),
            };
            let u = skein_control::users::create(&db, &username, role, password.as_deref())?;
            let shown = password.filter(|_| !password_stdin);
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "id": u.id, "username": u.username, "role": role.as_str(), "password": shown })
                );
            } else {
                println!("created {} ({})", u.username, role.as_str());
                if let Some(p) = shown {
                    println!("password: {p}");
                }
            }
            Ok(())
        }
        Admin::ResetPassword {
            username,
            password_stdin,
        } => {
            let u = user(&db, &username)?;
            let password = if password_stdin {
                read_stdin_password()?
            } else {
                generated_password()
            };
            skein_control::users::set_password(&db, &u.id, &password)?;
            skein_control::sessions::revoke_all_for_user(&db, &u.id)?;
            if !password_stdin {
                println!("{password}");
            }
            Ok(())
        }
        Admin::MintToken {
            username,
            label,
            scopes,
            json,
        } => {
            let u = user(&db, &username)?;
            let scopes = scopes
                .iter()
                .map(|s| Scope::parse(s).ok_or_else(|| format!("unknown scope {s:?}")))
                .collect::<Result<Vec<_>, _>>()?;
            let (info, token) = skein_control::auth::mint(&db, &u, &label, &scopes, None)?;
            if json {
                println!("{}", serde_json::json!({ "id": info.id, "token": token }));
            } else {
                println!("{token}");
            }
            Ok(())
        }
        Admin::SetRole { username, role } => {
            let u = user(&db, &username)?;
            skein_control::users::set_role(&db, &u.id, parse_role(&role)?)
                .map_err(|e| e.to_string())
        }
        Admin::Gc { grace_secs } => {
            let state = state()?;
            if !state.ready()? {
                return Err("this install has not been set up yet".into());
            }
            let swept = gc::sweep(&state, grace_secs)?;
            println!("{}", serde_json::to_string(&swept).unwrap_or_default());
            Ok(())
        }
        Admin::License(cmd) => {
            let lic = license::Licensing::from_env()?;
            lic.init(&db)?;
            let print = |r: &license::Report, json: bool| {
                if json {
                    println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
                } else {
                    print_license(r);
                }
            };
            match cmd {
                LicenseCmd::Status { json } => {
                    print(&lic.report(&db, skein_control::ids::now_ms())?, json);
                    Ok(())
                }
                LicenseCmd::Install => {
                    let mut key = String::new();
                    std::io::stdin()
                        .read_to_string(&mut key)
                        .map_err(|e| format!("read the key from stdin: {e}"))?;
                    let lic_terms = lic
                        .install(&db, &key)?
                        .map_err(|r| format!("that licence key was not installed: {r}"))?;
                    if let Some(org) = skein_control::registry::the_org(&db)? {
                        let ctx = skein_control::audit::AuditCtx::system(&org.id, "cli");
                        skein_control::audit::record(
                            &db,
                            &ctx,
                            "license.install",
                            Some(&serde_json::json!({
                                "license_id": lic_terms.lid,
                                "tier": lic_terms.tier.as_str(),
                                "entity": lic_terms.entity,
                            })),
                        )?;
                    }
                    print(&lic.report(&db, skein_control::ids::now_ms())?, false);
                    Ok(())
                }
                LicenseCmd::Check { json } => {
                    match lic.run_check(&db, std::time::Duration::ZERO)? {
                        license::CheckRun::NoValidKey => {
                            return Err("there is no valid licence key to check".into())
                        }
                        license::CheckRun::Offline => {
                            return Err(
                                "this is an offline licence: Skein makes no calls for it".into()
                            )
                        }
                        _ => {}
                    }
                    print(&lic.report(&db, skein_control::ids::now_ms())?, json);
                    Ok(())
                }
                LicenseCmd::Keys { .. } => unreachable!("answered before the database"),
            }
        }
    }
}

fn print_license(r: &license::Report) {
    let s = &r.status;
    let state = serde_json::to_value(s.state).unwrap_or_default();
    println!("state      {}", state.as_str().unwrap_or("?"));
    if let (Some(lid), Some(entity), Some(tier)) = (&s.license_id, &s.entity, s.tier) {
        println!(
            "licence    {lid}, {} tier, issued to {entity}",
            tier.as_str()
        );
        if let Some(exp) = &s.expires_at {
            println!("expires    {exp}");
        }
    }
    match s.max_seats {
        Some(cap) => println!("seats      {} of {cap}", s.seats),
        None => println!("seats      {}", s.seats),
    }
    println!("this month {} at most", r.peak_seats_this_month);
    if let Some(at) = &r.last_check_at {
        println!(
            "checked    {at} ({})",
            r.last_check_status.as_deref().unwrap_or("?")
        );
    }
    if let Some(e) = &r.last_check_error {
        println!("last error {e}");
    }
    if let Some(n) = &r.notice {
        println!("from Weft  {n}");
    }
    for w in &s.warnings {
        println!("warning    {w}");
    }
}
