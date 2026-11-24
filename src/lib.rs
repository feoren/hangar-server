//! Hangar server: relay for live collaboration (official mode and
//! self-hosting) and a lean built-in identity for self-hosting.
//!
//! Architecture: `docs/development.md`, operations: `docs/operations.md`; protocol: `docs/protocol.md`;
//! security: `docs/security.md`.

#![forbid(unsafe_code)]

pub mod config;
pub mod db;
pub mod http;
pub mod identity;
pub mod license;
pub mod mail;
pub mod relay;
pub mod signed;
pub mod ticket;
pub mod tls;
pub mod util;
pub mod wire;

use std::sync::Arc;

use axum::Router;
use tokio::sync::{mpsc, watch};

use config::{Config, IdentityMode};
use http::AppState;
use identity::Identity;
use relay::Relay;

/// Everything a running server needs; the tests build it the same way.
pub struct Server {
    pub router: Router,
    pub state: AppState,
    pub shutdown: watch::Sender<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("data directory: {0}")]
    DataDir(std::io::Error),
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error("identity: {0}")]
    Identity(String),
}

pub async fn build(config: Config) -> Result<Server, StartError> {
    std::fs::create_dir_all(&config.data_dir).map_err(StartError::DataDir)?;
    let db = db::connect(&config.database_url).await?;
    let config = Arc::new(config);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let mut keys = config.ticket_keys.clone();
    let (identity, attention) = if config.identity == IdentityMode::Local {
        let (tx, rx) = mpsc::channel(256);
        let identity = Identity::start(db.clone(), config.clone(), rx, shutdown_rx.clone())
            .await
            .map_err(StartError::Identity)?;
        keys.insert(identity.ticket_kid(), identity.ticket_public_key());
        (Some(identity), Some(tx))
    } else {
        (None, None)
    };
    let relay = Arc::new(Relay::new(db, &config, keys, attention));
    if let Some(identity) = &identity {
        identity.attach_relay(relay.clone());
    }
    relay.spawn_timers(shutdown_rx.clone());
    if config.identity == IdentityMode::Official {
        match &config.revocation {
            Some(source) => {
                let poller = relay::revocation::Poller::new(
                    relay.clone(),
                    source.clone(),
                    relay.ticket_keys().clone(),
                    relay.audience().to_owned(),
                )
                .map_err(StartError::Identity)?;
                tokio::spawn(poller.run(shutdown_rx.clone()));
            }
            None => tracing::warn!(
                "REVOCATION_URL missing: revoked rights only take effect with the next ticket"
            ),
        }
    }
    let state = AppState {
        config,
        relay,
        identity,
        shutdown: shutdown_rx,
    };
    Ok(Server {
        router: http::router(state.clone()),
        state,
        shutdown,
    })
}

/// How long a shutdown waits for the live connections to close (below the 20 s that Compose
/// and systemd give before they kill the process).
pub const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a client may take to send the headers of a request.
pub const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Serves `server` on `listener` until `signal` completes, then closes the live connections
/// with 1012 (the clients reconnect) and waits up to `SHUTDOWN_DRAIN` for them: the graceful
/// shutdown of the HTTP server does not wait for upgraded WebSockets, and ending the runtime
/// would cut them off without a close frame (1006) and before they leave their teams.
pub async fn serve_until(
    server: Server,
    listener: tokio::net::TcpListener,
    signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use hyper_util::service::TowerToHyperService;

    let relay = server.state.relay.clone();
    let shutdown = server.shutdown;
    let router = server.router;
    // Not `axum::serve`: it builds hyper without a timer, so a client could hold a socket open
    // forever by sending its request headers byte by byte (slowloris).
    let (stop, stopped) = watch::channel(false);
    // Every connection task holds a sender; once all are gone, `open.recv()` returns `None`.
    let (alive, mut open) = mpsc::channel::<()>(1);
    tokio::pin!(signal);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut signal => break,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                // Out of file descriptors and the like: wait a moment instead of spinning.
                tracing::warn!(%error, "accepting a connection failed");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        // One layer around the whole router, not `Router::layer`, which would wrap every
        // route again for each connection.
        let service = TowerToHyperService::new(tower::Layer::layer(
            &axum::Extension(axum::extract::ConnectInfo(peer)),
            router.clone(),
        ));
        let connection = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades();
        let mut stopped = stopped.clone();
        let alive = alive.clone();
        tokio::spawn(async move {
            let mut connection = std::pin::pin!(connection);
            tokio::select! {
                _ = connection.as_mut() => {}
                _ = async { stopped.wait_for(|stop| *stop).await.map(|_| ()) } => {
                    // Finishes the request in progress, then closes; idle ones close at once.
                    connection.as_mut().graceful_shutdown();
                    let _ = connection.await;
                }
            }
            drop(alive);
        });
    }
    drop(listener);
    tracing::info!("shutting down: closing connections");
    let _ = shutdown.send(true);
    let _ = stop.send(true);
    drop(alive);
    // Open HTTP requests finish; upgraded WebSockets are not counted here, see below.
    if tokio::time::timeout(SHUTDOWN_DRAIN, open.recv())
        .await
        .is_err()
    {
        tracing::warn!("HTTP requests still open after the shutdown deadline");
    }
    if !relay.wait_for_connections(SHUTDOWN_DRAIN).await {
        tracing::warn!(
            open = relay.connection_count(),
            "connections still open after the shutdown deadline"
        );
    }
    Ok(())
}
