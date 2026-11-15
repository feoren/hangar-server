//! Hangar team server: relay for live collaboration (official mode and
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
