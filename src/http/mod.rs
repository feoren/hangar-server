//! HTTP-Oberfläche: Router, Sicherheitsheader, Gesundheitsprüfung, Client-Adresse.

pub mod ratelimit;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::watch;

use crate::config::Config;
use crate::identity::Identity;
use crate::relay::Relay;

/// Größter Anfragekörper außerhalb des WebSockets.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub relay: Arc<Relay>,
    pub identity: Option<Arc<Identity>>,
    pub shutdown: watch::Receiver<bool>,
}

pub fn router(state: AppState) -> Router {
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/v1/live", get(crate::relay::conn::upgrade));
    if let Some(identity) = &state.identity {
        app = app.merge(crate::identity::routes(identity.clone()));
    }
    app.fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

/// `GET /health`: Prozess lebt und die Datenbank antwortet. Verrät keine Zahlen.
async fn health(State(state): State<AppState>) -> Response {
    match sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.relay.db)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "Gesundheitsprüfung: Datenbank antwortet nicht");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "error" })),
            )
                .into_response()
        }
    }
}

/// Vor jeder Anfrage: Origin-Prüfung schreibender Anfragen; nach jeder: Sicherheitsheader und
/// ein Protokolleintrag mit dem Routenmuster (nie dem Pfad: der kann Tokens tragen).
async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let writes = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
    if writes {
        if let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
        {
            if !state.config.origin_allowed(origin) {
                tracing::info!(route, "fremder Origin abgewiesen");
                // Unter /api/v1 gilt das Fehlerformat der Konto-API (RFC 9457).
                let refused = if crate::identity::api::is_api_path(request.uri().path()) {
                    crate::identity::api::Problem::new(
                        StatusCode::FORBIDDEN,
                        "origin",
                        "Requests from this origin are not allowed.",
                    )
                    .into_response()
                } else {
                    (StatusCode::FORBIDDEN, Json(json!({ "error": "origin" }))).into_response()
                };
                return with_headers(&state.config, refused);
            }
        }
    }
    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status().as_u16();
    if route != "/health" {
        tracing::info!(method = %method, route, status, ms = started.elapsed().as_millis() as u64, "Anfrage");
    }
    with_headers(&state.config, response)
}

fn with_headers(config: &Config, mut response: Response) -> Response {
    let headers = response.headers_mut();
    let set = |headers: &mut HeaderMap, name: &'static str, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, "x-content-type-options", "nosniff");
    set(headers, "x-frame-options", "DENY");
    set(headers, "referrer-policy", "no-referrer");
    set(headers, "cross-origin-opener-policy", "same-origin");
    set(headers, "cross-origin-resource-policy", "same-origin");
    set(
        headers,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    );
    set(
        headers,
        "content-security-policy",
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    );
    if !headers.contains_key(header::CACHE_CONTROL) {
        set(headers, "cache-control", "no-store");
    }
    if config.is_https() {
        set(
            headers,
            "strict-transport-security",
            "max-age=31536000; includeSubDomains",
        );
    }
    response
}

/// Extraktor für die Client-Adresse (für Ratenbegrenzung), nie für Entscheidungen über Rechte.
pub struct ClientIp(pub Option<IpAddr>);

impl axum::extract::FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts.extensions.get::<ConnectInfo<SocketAddr>>();
        Ok(ClientIp(client_ip(
            &parts.headers,
            peer,
            state.config.trust_proxy,
        )))
    }
}

impl ClientIp {
    /// Schlüssel für die Ratenbegrenzung. IPv6 zählt je /64: ein Anschluss bekommt meist ein
    /// ganzes /64, einzelne Adressen daraus kosten nichts.
    pub fn key(&self) -> String {
        match self.0 {
            Some(IpAddr::V4(ip)) => ip.to_string(),
            Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => {
                    let s = ip.segments();
                    format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
                }
            },
            None => "unknown".into(),
        }
    }
}

/// Adresse des Clients: direkt, oder hinter dem eigenen Proxy (Caddy) der letzte Eintrag von
/// `X-Forwarded-For`, den der Proxy selbst angehängt hat.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<&ConnectInfo<SocketAddr>>,
    trust_proxy: bool,
) -> Option<IpAddr> {
    if trust_proxy {
        if let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse().ok())
        {
            return Some(ip);
        }
    }
    peer.map(|p| p.0.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratenschlüssel_fasst_ipv6_je_64_zusammen() {
        let key = |ip: &str| ClientIp(Some(ip.parse().unwrap())).key();
        assert_eq!(key("203.0.113.7"), "203.0.113.7");
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(ClientIp(None).key(), "unknown");
    }
}
