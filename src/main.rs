//! Einstieg: `hangar-team-server [serve|healthcheck|login-link <email>]`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

use hangar_team_server::config::{Config, IdentityMode};
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
            eprintln!("Konfiguration: {error}");
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
            eprintln!("Laufzeit: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        match command.as_str() {
            "serve" => serve(config).await,
            "login-link" => login_link(config, args.get(1).cloned()).await,
            other => Err(format!(
                "unbekannter Befehl {other:?} (serve, healthcheck, login-link)"
            )),
        }
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "Abbruch");
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn serve(config: Config) -> Result<(), String> {
    let bind = config.bind;
    let server = hangar_team_server::build(config)
        .await
        .map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("{bind}: {e}"))?;
    tracing::info!(%bind, "Teamserver bereit");
    let shutdown = server.shutdown;
    let app = server
        .router
        .into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            wait_for_signal().await;
            tracing::info!("Beenden: Verbindungen werden geschlossen");
            // Live-Verbindungen schließen sich mit 1012; die Clients verbinden sich neu.
            let _ = shutdown.send(true);
        })
        .await
        .map_err(|e| e.to_string())?;
    tracing::info!("beendet");
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

/// Selbstbetrieb ohne Mail: einen einmaligen Anmeldelink auf der Konsole ausgeben.
async fn login_link(config: Config, email: Option<String>) -> Result<(), String> {
    if config.identity != IdentityMode::Local {
        return Err("login-link gibt es nur mit IDENTITY=local".into());
    }
    let email = email.ok_or("Aufruf: login-link <email>")?;
    let db = hangar_team_server::db::connect(&config.database_url)
        .await
        .map_err(|e| e.to_string())?;
    let link = hangar_team_server::identity::auth::admin_login_link(&db, &config, &email).await?;
    println!("{link}");
    Ok(())
}

/// Für das distroless-Image (kein curl): `GET /health` auf dem eigenen Port.
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
