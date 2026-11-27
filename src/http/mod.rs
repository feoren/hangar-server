//! HTTP surface: router, security headers, health check, client address.

pub mod ratelimit;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, DefaultBodyLimit, MatchedPath, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tokio::sync::watch;

use crate::config::Config;
use crate::identity::Identity;
use crate::relay::Relay;

/// Largest request body outside the WebSocket.
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
        .route("/v1/live", get(crate::relay::conn::upgrade))
        .route("/", get(start_page))
        .route("/assets/style.css", get(crate::identity::pages::stylesheet));
    if let Some(identity) = &state.identity {
        app = app.merge(crate::identity::routes(identity.clone()));
    }
    app.fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(middleware::from_fn_with_state(state.clone(), guard))
        .with_state(state)
}

/// `GET /`: with `ROOT_REDIRECT` on to the product page, otherwise a short page that says the
/// server runs and, in self-hosting, which address goes into the app.
async fn start_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match &state.config.root_redirect {
        Some(target) => Redirect::permanent(target).into_response(),
        None => crate::identity::pages::home(&headers, &state.config),
    }
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response()
}

/// `GET /health`: the process is alive and the database responds. Reveals no numbers.
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
            tracing::error!(%error, "health check: database not responding");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "error" })),
            )
                .into_response()
        }
    }
}

/// Before each request: origin check for writing requests; after each: security headers and
/// a log entry with the route pattern (never the path: it may carry tokens).
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
                tracing::info!(route, "foreign origin rejected");
                // Under /api/v1 the error format of the account API applies (RFC 9457).
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
        tracing::info!(method = %method, route, status, ms = started.elapsed().as_millis() as u64, "request");
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

/// Extractor for the client address (for rate limiting), never for authorization decisions.
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
    /// Key for rate limiting. IPv6 counts per /64: a connection usually gets a whole /64,
    /// so individual addresses from it cost nothing.
    /// Coarser key for the connections waiting for `hello`: IPv6 per /48, since a single
    /// customer often gets a whole /48 and with it 65536 networks of /64.
    pub fn wide_key(&self) -> String {
        match self.0 {
            Some(IpAddr::V6(ip)) if ip.to_ipv4_mapped().is_none() => {
                let s = ip.segments();
                format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
            }
            _ => self.key(),
        }
    }

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

/// Client address: direct, or behind our own proxy (Caddy) the last entry of
/// `X-Forwarded-For`, which the proxy itself appended. With several header lines the last line
/// counts: a proxy that appends a line instead of extending the header must not let the line the
/// client sent win.
pub fn client_ip(
    headers: &HeaderMap,
    peer: Option<&ConnectInfo<SocketAddr>>,
    trust_proxy: bool,
) -> Option<IpAddr> {
    if trust_proxy {
        if let Some(ip) = headers
            .get_all("x-forwarded-for")
            .iter()
            .next_back()
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
    fn forwarded_for_uses_the_last_entry_of_the_last_header_line() {
        let mut headers = HeaderMap::new();
        // The client sends its own line; the proxy appends a second line with the real address.
        headers.append("x-forwarded-for", "10.0.0.1".parse().unwrap());
        headers.append("x-forwarded-for", "198.51.100.7".parse().unwrap());
        assert_eq!(
            client_ip(&headers, None, true),
            Some("198.51.100.7".parse().unwrap())
        );
        let mut joined = HeaderMap::new();
        joined.insert("x-forwarded-for", "10.0.0.1, 198.51.100.8".parse().unwrap());
        assert_eq!(
            client_ip(&joined, None, true),
            Some("198.51.100.8".parse().unwrap())
        );
    }

    #[test]
    fn rate_key_groups_ipv6_per_64() {
        let key = |ip: &str| ClientIp(Some(ip.parse().unwrap())).key();
        assert_eq!(key("203.0.113.7"), "203.0.113.7");
        assert_eq!(key("2001:db8:1:2:aaaa::1"), key("2001:db8:1:2:bbbb::9"));
        assert_ne!(key("2001:db8:1:2::1"), key("2001:db8:1:3::1"));
        assert_eq!(key("::ffff:203.0.113.7"), "203.0.113.7");
        assert_eq!(ClientIp(None).key(), "unknown");
    }
}
