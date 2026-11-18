//! Entry point: `hangar-server [serve|healthcheck|login-link <email>|create-team <email> <name>|
//! invite <team> <email> [member|admin]|teams|license <file>]`.
//!
//! The commands other than `serve` and `healthcheck` are for self-hosting on the host, e.g.
//! `docker compose run --rm server invite Development anna@example.org`. Whatever a script
//! consumes further (link, team ID) is printed as the last line on stdout.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use hangar_server::config::{Config, IdentityMode};
use tracing_subscriber::EnvFilter;

fn init_logging(json: bool) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    if json {
        builder
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .init();
    } else {
        builder.init();
    }
}

fn main() -> ExitCode {
    let _ = dotenvy::dotenv();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().cloned().unwrap_or_else(|| "serve".into());
    if command.as_str() == "healthcheck" {
        return healthcheck();
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("configuration: {error}");
            return ExitCode::from(2);
        }
    };
    init_logging(config.log_json);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        match command.as_str() {
            "serve" => serve(config).await,
            "login-link" => login_link(config, args.get(1).cloned()).await,
            "create-team" => create_team(config, &args[1..]).await,
            "invite" => invite(config, &args[1..]).await,
            "teams" => teams(config).await,
            "license" => install_license(config, args.get(1).cloned()).await,
            other => Err(format!(
                "unknown command {other:?} (serve, healthcheck, login-link, create-team, invite, teams, license)"
            )),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "aborted");
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let bind = config.bind;
    if let Some(warning) = hangar_server::config::memory_warning(
        config.max_connections,
        hangar_server::config::memory_limit(),
    ) {
        tracing::warn!("{warning}");
    }
    let server = hangar_server::build(config)
        .await
        .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("{bind}: {e}"))?;
    tracing::info!(%bind, "server ready");
    let shutdown = server.shutdown;
    let app = server
        .router
        .into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_signal().await;
            tracing::info!("shutting down: closing connections");
            // Live connections close with 1012; the clients reconnect.
            let _ = shutdown.send(true);
        })
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("stopped");
    Ok(())
}

async fn wait_for_signal() {
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
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
}

/// Self-hosting without mail: print a one-time magic link on the console.
async fn login_link(config: Config, email: Option<String>) -> Result<(), String> {
    if config.identity != IdentityMode::Local {
        return Err("login-link is only available with IDENTITY=local".into());
    }
    let email = email.ok_or("usage: login-link <email>")?;
    let db = hangar_server::db::connect(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let link = hangar_server::identity::auth::admin_login_link(&db, &config, &email).await?;
    println!("{link}");
    Ok(())
}

/// Database for the self-hosting commands; with IDENTITY=official they are not available.
async fn local_db(config: &Config, command: &str) -> Result<hangar_server::db::Db, String> {
    if config.identity != IdentityMode::Local {
        return Err(format!("{command} is only available with IDENTITY=local"));
    }
    hangar_server::db::connect(&config.database_url)
        .await
        .map_err(|e| e.to_string())
}

/// `create-team <owner-email> <name>`: create a team, and the owner's account if needed.
async fn create_team(config: Config, args: &[String]) -> Result<(), String> {
    let (Some(email), Some(first)) = (args.first(), args.get(1)) else {
        return Err("usage: create-team <owner-email> <name>".into());
    };
    // A name containing spaces may be given without quotes.
    let name = std::iter::once(first.as_str())
        .chain(args[2..].iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let db = local_db(&config, "create-team").await?;
    let id =
        hangar_server::identity::teams::cli_create_team(&db, &config.default_lang, email, &name)
            .await?;
    eprintln!("team {name:?} created, owner {email}. To invite: invite {id} <email>");
    println!("{id}");
    Ok(())
}

/// `invite <team> <email> [member|admin]`: print an invitation link (team by ID or name).
async fn invite(config: Config, args: &[String]) -> Result<(), String> {
    let (Some(team), Some(email)) = (args.first(), args.get(1)) else {
        return Err("usage: invite <team-id or name> <email> [member|admin]".into());
    };
    if args.len() > 3 {
        return Err("usage: invite <team-id or name> <email> [member|admin]; quote team names containing spaces".into());
    }
    let role = args.get(2).map_or("member", String::as_str);
    let db = local_db(&config, "invite").await?;
    let link = hangar_server::identity::teams::cli_invite(
        &db,
        &config.public_url,
        &config.default_lang,
        team,
        email,
        role,
    )
    .await?;
    eprintln!("invitation for {email} as {role}: single use, 7 days, only for this address.");
    println!("{link}");
    Ok(())
}

/// `teams`: teams with ID, name, owner, members and open invitations (tab-separated).
async fn teams(config: Config) -> Result<(), String> {
    let db = local_db(&config, "teams").await?;
    let lines = hangar_server::identity::teams::cli_teams(&db).await?;
    if lines.is_empty() {
        eprintln!("no team yet. To create one: create-team <owner-email> <name>");
    }
    for line in lines {
        println!(
            "{}	{}	{}	{} members	{} open invitations",
            line.id, line.name, line.owner, line.members, line.open_invitations
        );
    }
    Ok(())
}

/// `license <file>`: store a license file from the website for the account it names. In the
/// container the file must be readable there, e.g. in the data volume or piped in with `-`.
async fn install_license(config: Config, path: Option<String>) -> Result<(), String> {
    let path = path.ok_or("usage: license <file> (or - for stdin)")?;
    let document = if path == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(|e| format!("stdin: {e}"))?;
        text
    } else {
        std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?
    };
    let db = local_db(&config, "license").await?;
    let installed =
        hangar_server::identity::teams::cli_install_license(&db, &config, &document).await?;
    let days = (installed.exp - hangar_server::util::now_s()).max(0) / 86_400;
    eprintln!(
        "license stored for {}: {} seats, valid for {days} more days.",
        installed.email, installed.seats
    );
    println!("{}", installed.email);
    Ok(())
}

/// For the distroless image (no curl): `GET /health` on our own port.
fn healthcheck() -> ExitCode {
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let check = || -> std::io::Result<bool> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut head = [0u8; 16];
        let n = stream.read(&mut head)?;
        Ok(head[..n].starts_with(b"HTTP/1.1 200"))
    };
    match check() {
        Ok(true) => ExitCode::SUCCESS,
        _ => ExitCode::FAILURE,
    }
}
