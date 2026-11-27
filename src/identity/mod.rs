//! Built-in identity for self-hosting (`IDENTITY=local`): sign-in via magic link and
//! OAuth device flow, teams, roles, invitations, seats checked against the website's license document.
//! Issues tickets in the same format as the website, so the relay knows only one path.
//!
//! Layout: `auth.rs` (sessions, tokens, magic link, device flow), `teams.rs` (teams,
//! invitations, license, tickets), `pages.rs` (browser pages), `api.rs` (the app's account API
//! under `/api/v1`, same as the website), `account.rs` (browser page `/account/devices`). Handlers
//! only read the request and call the service functions; the rules live in the service functions.

pub mod account;
pub mod api;
pub mod auth;
pub mod pages;
pub mod teams;

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::json;
use tokio::sync::{mpsc, watch};

use crate::config::Config;
use crate::db::Db;
use crate::http::ratelimit::RateLimiter;
use crate::http::AppState;
use crate::mail::Mailer;
use crate::relay::team::Attention;
use crate::relay::Relay;
use crate::util::{hex, random_bytes, sha256};

pub struct Identity {
    pub db: Db,
    pub config: Arc<Config>,
    pub mailer: Mailer,
    pub limiter: RateLimiter,
    key: SigningKey,
    kid: String,
    relay: OnceLock<Arc<Relay>>,
}

/// Error of the identity API: status and a fixed code, never internal details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
}

impl ApiError {
    pub const fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
    pub const UNAUTHORIZED: ApiError = ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized");
    pub const NOT_FOUND: ApiError = ApiError::new(StatusCode::NOT_FOUND, "not_found");
    pub const FORBIDDEN: ApiError = ApiError::new(StatusCode::FORBIDDEN, "forbidden");
    pub const INVALID: ApiError = ApiError::new(StatusCode::BAD_REQUEST, "invalid_request");
    pub const RATE_LIMITED: ApiError = ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    pub const INTERNAL: ApiError = ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal");
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(%error, "database error");
        ApiError::INTERNAL
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

/// The self-hosting ticket signing key is stored as a hex seed in the data directory and
/// is generated on first start (file mode 0600 on Unix). It never leaves the server.
fn load_or_create_key(dir: &Path) -> Result<SigningKey, String> {
    let path = dir.join("ticket-signing.key");
    if let Ok(text) = std::fs::read_to_string(&path) {
        // A file restored from a backup may have come back readable for others.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let open = std::fs::metadata(&path).is_ok_and(|m| m.permissions().mode() & 0o077 != 0);
            if open {
                match std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => tracing::warn!(
                        "{} was readable for other users; its mode is now 0600",
                        path.display()
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        "{} is readable for other users; restrict it to its owner (chmod 600)",
                        path.display()
                    ),
                }
            }
        }
        let text = text.trim();
        let bytes: Vec<u8> = (0..text.len() / 2)
            .filter_map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok())
            .collect();
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| format!("{} is corrupted", path.display()))?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    let seed = random_bytes::<32>();
    let tmp = dir.join("ticket-signing.key.tmp");
    // Created with 0600 from the start, never readable for others in between; a leftover from
    // an interrupted start is replaced.
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        let mut file = options
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        file.write_all(hex(&seed).as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

impl Identity {
    pub async fn start(
        db: Db,
        config: Arc<Config>,
        attention: mpsc::Receiver<Attention>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Arc<Identity>, String> {
        let key = load_or_create_key(&config.data_dir)?;
        let kid = format!(
            "local-{}",
            &hex(&sha256(key.verifying_key().as_bytes()))[..12]
        );
        let mailer = Mailer::start(&config, shutdown.clone())?;
        let identity = Arc::new(Identity {
            limiter: RateLimiter::new(&config.server_secret),
            db,
            config,
            mailer,
            key,
            kid,
            relay: OnceLock::new(),
        });
        tokio::spawn(teams::attention_worker(
            identity.clone(),
            attention,
            shutdown.clone(),
        ));
        let housekeeping = identity.clone();
        let mut stop = shutdown;
        tokio::spawn(async move {
            let mut hourly = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = hourly.tick() => {
                        if let Err(error) = auth::housekeeping(&housekeeping.db).await {
                            tracing::error!(%error, "cleanup of sign-in data failed");
                        }
                    }
                    _ = stop.changed() => break,
                }
            }
        });
        Ok(identity)
    }

    pub fn ticket_kid(&self) -> &str {
        &self.kid
    }

    pub fn ticket_public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn attach_relay(&self, relay: Arc<Relay>) {
        let _ = self.relay.set(relay);
    }

    pub(crate) fn relay(&self) -> Option<&Arc<Relay>> {
        self.relay.get()
    }

    /// Invitation links and magic links are returned to the admin when the server sends no
    /// mails (self-hosting without SMTP).
    pub fn links_to_admin(&self) -> bool {
        !self.mailer.enabled()
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.public_url)
    }
}

/// Reads `Authorization: Bearer <token>`.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.len() <= 128)
}

pub fn routes(_identity: Arc<Identity>) -> Router<AppState> {
    Router::new()
        .route("/assets/style.css", get(pages::stylesheet))
        .route(
            "/oauth/device_authorization",
            post(auth::device_authorization),
        )
        .route("/oauth/token", post(auth::token))
        .route("/device", get(auth::device_page).post(auth::device_decide))
        .route("/auth/email", post(auth::email_submit))
        .route(
            "/auth/magic/{token}",
            get(auth::magic_page).post(auth::magic_consume),
        )
        .route("/auth/logout", post(auth::browser_logout))
        .route(
            "/invite/{token}",
            get(teams::invite_page).post(teams::invite_accept_page),
        )
        .route("/v1/me", get(teams::me))
        .route("/v1/sessions", get(auth::sessions))
        .route("/v1/sessions/{id}", delete(auth::revoke_session))
        .route("/v1/auth/logout", post(auth::app_logout))
        .route("/v1/teams", post(teams::create_team))
        .route(
            "/v1/teams/{team}",
            get(teams::team_detail).delete(teams::delete_team),
        )
        .route(
            "/v1/teams/{team}/members/{user}",
            patch(teams::set_role).delete(teams::remove_member),
        )
        .route("/v1/teams/{team}/invitations", post(teams::invite))
        .route(
            "/v1/teams/{team}/invitations/{invitation}/resend",
            post(teams::resend),
        )
        .route(
            "/v1/teams/{team}/invitations/{invitation}",
            delete(teams::revoke),
        )
        .route("/v1/invitations/accept", post(teams::accept_api))
        .route(
            "/v1/license",
            get(teams::license_get)
                .put(teams::license_put)
                .delete(teams::license_delete),
        )
        .route("/v1/tickets", post(teams::issue_ticket))
        .route(
            auth::DEVICES_PAGE,
            get(account::devices_page).post(account::devices_revoke),
        )
        .merge(api::routes())
}
