//! The app's account API under `/api/v1`, self-hosting only (`IDENTITY=local`). Same paths,
//! inputs and responses as on hangar.feoren.com (`wiki/Team-Schnittstelle.md` of the website),
//! so the app works with a single base URL (`<PUBLIC_URL>/api/v1`). In official mode these
//! routes do not exist (404); there the app talks to the website.
//!
//! - Input: `application/x-www-form-urlencoded` or `application/json` (flat object),
//!   otherwise 415; bodies above [`MAX_INPUT_BYTES`] 413. Values come out as strings
//!   (integers become text, nested values count as missing).
//! - Errors: RFC 9457 `application/problem+json` with `type`, `title`, `status`, `detail`,
//!   `code`; the OAuth endpoints additionally `error` and `error_description` (RFC 6749 5.2).
//!   401 carries `WWW-Authenticate: Bearer` (RFC 6750). Never internal details, never tokens.
//! - No cookies, no CSRF (bearer or no authentication at all), no CORS allowance.
//!
//! The handlers only read the request and call the services in `auth.rs` and `teams.rs`.

use std::borrow::Cow;
use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get, post, MethodRouter};
use axum::{Json, Router};
use serde::Serialize;
use serde_json::{json, Value};

use super::auth::{self, identity};
use super::teams;
use super::{ApiError, Identity};
use crate::http::{AppState, ClientIp};
use crate::util::{b64, is_id};

/// Largest request body of the account API (same as the website).
pub const MAX_INPUT_BYTES: usize = 16 * 1024;
/// Maximum number of fields read and length of a field name (same as the website).
const MAX_FIELDS: usize = 32;
const MAX_KEY_LEN: usize = 64;
/// Prefix of the problem types (URN, not resolvable; RFC 9457 3.1.1), same as the website.
const PROBLEM_TYPE: &str = "urn:hangar:api:problem:";
const BEARER_CHALLENGE: &str = r#"Bearer realm="hangar", error="invalid_token""#;

// ---------------------------------------------------------------------------------------------
// Errors (RFC 9457)

#[derive(Debug)]
pub struct Problem {
    status: StatusCode,
    code: &'static str,
    detail: Cow<'static, str>,
    /// OAuth endpoint: additionally `error` and `error_description`.
    oauth: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Problem {
    pub fn new(status: StatusCode, code: &'static str, detail: &'static str) -> Self {
        Self {
            status,
            code,
            detail: Cow::Borrowed(detail),
            oauth: false,
            headers: Vec::new(),
        }
    }

    fn header(mut self, name: HeaderName, value: &'static str) -> Self {
        self.headers.push((name, HeaderValue::from_static(value)));
        self
    }

    /// Error of an OAuth endpoint from the code of the services in `auth.rs`.
    pub fn oauth(code: &'static str) -> Self {
        let (status, code, detail) = match code {
            "authorization_pending" => (
                StatusCode::BAD_REQUEST,
                code,
                "The user has not confirmed the device yet.",
            ),
            "slow_down" => (
                StatusCode::BAD_REQUEST,
                code,
                "Polling too fast. Wait 5 seconds longer between requests.",
            ),
            "access_denied" => (StatusCode::BAD_REQUEST, code, "The request was denied."),
            "expired_token" => (
                StatusCode::BAD_REQUEST,
                code,
                "The device code has expired. Start again.",
            ),
            "invalid_grant" => (
                StatusCode::BAD_REQUEST,
                code,
                "The grant is invalid, expired or revoked.",
            ),
            "invalid_client" => (StatusCode::BAD_REQUEST, code, "Unknown client."),
            "invalid_scope" => (StatusCode::BAD_REQUEST, code, "Unknown scope."),
            "unsupported_grant_type" => (StatusCode::BAD_REQUEST, code, "Unsupported grant_type."),
            "invalid_request" => (
                StatusCode::BAD_REQUEST,
                code,
                "A required parameter is missing or invalid.",
            ),
            // Like the website: 429 with the OAuth code slow_down (the app increases the interval).
            "rate_limited" => {
                let mut problem = Self::new(
                    StatusCode::TOO_MANY_REQUESTS,
                    "slow_down",
                    "Too many requests.",
                )
                .header(header::RETRY_AFTER, "60");
                problem.oauth = true;
                return problem;
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error.",
            ),
        };
        let mut problem = Self::new(status, code, detail);
        problem.oauth = true;
        problem
    }

    fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "The access token is missing, invalid or expired.",
        )
        .header(header::WWW_AUTHENTICATE, BEARER_CHALLENGE)
    }

    fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "Not found.")
    }
}

fn title(status: StatusCode) -> &'static str {
    match status.as_u16() {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let mut body = json!({
            "type": format!("{PROBLEM_TYPE}{}", self.code),
            "title": title(self.status),
            "status": self.status.as_u16(),
            "detail": self.detail,
            "code": self.code,
        });
        if self.oauth {
            body["error"] = Value::from(self.code);
            body["error_description"] = Value::from(self.detail.as_ref());
        }
        let mut response = (self.status, body.to_string()).into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        no_store(headers);
        for (name, value) in self.headers {
            headers.insert(name, value);
        }
        response
    }
}

impl From<ApiError> for Problem {
    fn from(error: ApiError) -> Self {
        match error.status {
            StatusCode::UNAUTHORIZED => Self::unauthorized(),
            StatusCode::NOT_FOUND => Self::not_found(),
            StatusCode::FORBIDDEN => Self::new(StatusCode::FORBIDDEN, "forbidden", "Forbidden."),
            StatusCode::BAD_REQUEST => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The request is invalid.",
            ),
            StatusCode::TOO_MANY_REQUESTS => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Too many requests.",
            )
            .header(header::RETRY_AFTER, "60"),
            _ => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Internal error.",
            ),
        }
    }
}

fn no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// Successful response: JSON, never cached.
fn ok<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    no_store(response.headers_mut());
    response
}

type ApiOut = Result<Response, Problem>;

fn local(state: &AppState) -> Result<&Identity, Problem> {
    identity(state)
        .map(AsRef::as_ref)
        .map_err(|_| Problem::not_found())
}

// ---------------------------------------------------------------------------------------------
// Input

/// Body fields as strings. Repeated fields: the last value wins.
pub type Input = HashMap<String, String>;

async fn read_input(headers: &HeaderMap, body: Body) -> Result<Input, Problem> {
    let kind = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let form = match kind.as_str() {
        "application/x-www-form-urlencoded" => true,
        "application/json" => false,
        _ => {
            return Err(Problem::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Use application/json or application/x-www-form-urlencoded.",
            ))
        }
    };
    let too_large = || {
        Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "The request body is too large.",
        )
    };
    let bytes = axum::body::to_bytes(body, MAX_INPUT_BYTES)
        .await
        .map_err(|_| too_large())?;
    if form {
        parse_form(&bytes).ok_or_else(|| {
            Problem::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The form body is not valid UTF-8.",
            )
        })
    } else {
        parse_json(&bytes).ok_or_else(|| {
            Problem::new(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "The body must be a JSON object.",
            )
        })
    }
}

fn keep(input: &mut Input, key: String, value: String) {
    if key.len() <= MAX_KEY_LEN && (input.len() < MAX_FIELDS || input.contains_key(&key)) {
        input.insert(key, value);
    }
}

/// `application/x-www-form-urlencoded` (WHATWG): `+` is a space, `%XX` a byte,
/// a `%` without two hex digits is kept as is. `None`: not valid UTF-8.
pub fn parse_form(body: &[u8]) -> Option<Input> {
    fn decode(raw: &[u8]) -> Option<String> {
        let hex = |b: u8| char::from(b).to_digit(16);
        let mut out = Vec::with_capacity(raw.len());
        let mut i = 0;
        while i < raw.len() {
            match raw[i] {
                b'+' => out.push(b' '),
                b'%' => match (raw.get(i + 1).copied(), raw.get(i + 2).copied()) {
                    (Some(h), Some(l)) if hex(h).is_some() && hex(l).is_some() => {
                        let (h, l) = (hex(h).unwrap_or(0), hex(l).unwrap_or(0));
                        out.push(u8::try_from(h * 16 + l).unwrap_or(0));
                        i += 2;
                    }
                    _ => out.push(b'%'),
                },
                b => out.push(b),
            }
            i += 1;
        }
        String::from_utf8(out).ok()
    }
    let mut input = Input::new();
    for pair in body.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        let (key, value) = match pair.iter().position(|b| *b == b'=') {
            Some(at) => (&pair[..at], &pair[at + 1..]),
            None => (pair, &[][..]),
        };
        keep(&mut input, decode(key)?, decode(value)?);
    }
    Some(input)
}

/// Flat JSON object; an empty array counts as an empty object (same as the website).
pub fn parse_json(body: &[u8]) -> Option<Input> {
    let mut input = Input::new();
    match serde_json::from_slice::<Value>(body).ok()? {
        Value::Object(map) => {
            for (key, value) in map {
                let text = match value {
                    Value::String(text) => text,
                    Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
                    _ => continue,
                };
                keep(&mut input, key, text);
            }
            Some(input)
        }
        Value::Array(items) if items.is_empty() => Some(input),
        _ => None,
    }
}

fn field<'a>(input: &'a Input, key: &str) -> Option<&'a str> {
    input.get(key).map(String::as_str)
}

// ---------------------------------------------------------------------------------------------
// OAuth

/// `POST /api/v1/oauth/device` (RFC 8628 3.1): `client_id`, optional `scope`, `device_name`
/// (100 characters), `platform` (40 characters).
async fn device(State(state): State<AppState>, ip: ClientIp, request: Request) -> ApiOut {
    let identity = local(&state)?;
    let (parts, body) = request.into_parts();
    let input = read_input(&parts.headers, body).await?;
    let label = auth::clean_label(field(&input, "device_name"), 100);
    let platform = auth::clean_platform(field(&input, "platform"));
    let started = auth::start_device(
        identity,
        &ip.key(),
        field(&input, "client_id"),
        field(&input, "scope"),
        &label,
        platform.as_deref(),
    )
    .await
    .map_err(Problem::oauth)?;
    Ok(ok(started))
}

/// `POST /api/v1/oauth/token`: redeem a device code (RFC 8628 3.4) or rotate a refresh token
/// (RFC 6749 6, with reuse detection).
async fn token(State(state): State<AppState>, ip: ClientIp, request: Request) -> ApiOut {
    let identity = local(&state)?;
    let (parts, body) = request.into_parts();
    let input = read_input(&parts.headers, body).await?;
    let tokens = auth::exchange(
        identity,
        &ip.key(),
        field(&input, "client_id"),
        field(&input, "grant_type"),
        field(&input, "device_code"),
        field(&input, "refresh_token"),
    )
    .await
    .map_err(Problem::oauth)?;
    Ok(ok(tokens))
}

/// `POST /api/v1/oauth/revoke` (RFC 7009): always 200 without body, even for unknown tokens.
async fn revoke(State(state): State<AppState>, ip: ClientIp, request: Request) -> ApiOut {
    let identity = local(&state)?;
    let (parts, body) = request.into_parts();
    let input = read_input(&parts.headers, body).await?;
    auth::revoke_token(
        identity,
        &ip.key(),
        field(&input, "client_id"),
        field(&input, "token"),
        field(&input, "token_type_hint"),
    )
    .await
    .map_err(Problem::oauth)?;
    let mut response = StatusCode::OK.into_response();
    no_store(response.headers_mut());
    Ok(response)
}

// ---------------------------------------------------------------------------------------------
// Account, projects, tickets (bearer)

async fn signed_in(identity: &Identity, headers: &HeaderMap) -> Result<auth::User, Problem> {
    auth::authenticate(identity, headers)
        .await
        .map_err(Problem::from)
}

/// `GET /api/v1/me`: own account and the own account's seats. Self-hosting knows no
/// names, so `name` is absent.
async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiOut {
    let identity = local(&state)?;
    let user = signed_in(identity, &headers).await?;
    let seats = teams::account_seats(identity, &user).await?;
    Ok(ok(json!({
        "id": user.id,
        "email": user.email,
        "locale": user.lang,
        "seats_account_total": seats.limit,
        "seats_account_used": seats.used,
    })))
}

/// `GET /api/v1/projects`: the person's teams. `invite_url` is absent: self-hosting has no
/// browser page for inviting (invitations go through `POST /v1/teams/{team}/invitations`).
async fn projects(State(state): State<AppState>, headers: HeaderMap) -> ApiOut {
    let identity = local(&state)?;
    let user = signed_in(identity, &headers).await?;
    let list: Vec<Value> = teams::projects_of(identity, &user)
        .await?
        .into_iter()
        .map(|p| {
            let mut item = json!({
                "id": p.id,
                "name": p.name,
                "role": p.role,
                "owner_id": p.owner_id,
                "plan": p.plan,
                "seats_account_total": p.seats.limit,
                "seats_account_used": p.seats.used,
            });
            if let Some(pending) = p.pending_invitations {
                item["pending_invitations"] = Value::from(pending);
            }
            item
        })
        .collect();
    Ok(ok(json!({ "projects": list })))
}

/// `POST /api/v1/relay-ticket` `{"project_id"}`: ticket (60 s) for `hello`; members only,
/// otherwise 404 (also for unknown teams).
async fn relay_ticket(State(state): State<AppState>, request: Request) -> ApiOut {
    let identity = local(&state)?;
    let (parts, body) = request.into_parts();
    let user = signed_in(identity, &parts.headers).await?;
    let input = read_input(&parts.headers, body).await?;
    let Some(team) = field(&input, "project_id").filter(|id| is_id(id, 64)) else {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "project_id must be a project id string.",
        ));
    };
    let (ticket, expires_at) =
        teams::issue(identity, &user, team)
            .await
            .map_err(|error| match error.status {
                StatusCode::NOT_FOUND => {
                    Problem::new(StatusCode::NOT_FOUND, "not_found", "Project not found.")
                }
                _ => Problem::from(error),
            })?;
    Ok(ok(json!({
        "ticket": ticket,
        "expires_at": expires_at,
        "relay_url": teams::live_url(&identity.config.public_url),
    })))
}

/// `GET /api/v1/keys`: this server's public ticket key, JWKS-like (RFC 8037).
/// License keys are not listed here: the website signs those, not this server.
async fn keys(State(state): State<AppState>) -> ApiOut {
    let identity = local(&state)?;
    let mut response = Json(json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": b64(identity.ticket_public_key().as_bytes()),
            "kid": identity.ticket_kid(),
            "use": "sig",
            "alg": "EdDSA",
        }]
    }))
    .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    Ok(response)
}

/// Path of the account API (`/api/v1` or below); there, upstream checks also respond
/// as problem+json.
pub fn is_api_path(path: &str) -> bool {
    path == "/api/v1" || path.starts_with("/api/v1/")
}

async fn not_found() -> Problem {
    Problem::not_found()
}

/// Other methods (including `OPTIONS`): 405 problem+json with `Allow`.
fn only(router: MethodRouter<AppState>, allow: &'static str) -> MethodRouter<AppState> {
    router.fallback(move || async move {
        Problem::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "Method not allowed.",
        )
        .header(header::ALLOW, allow)
    })
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/oauth/device", only(post(device), "POST"))
        .route("/api/v1/oauth/token", only(post(token), "POST"))
        .route("/api/v1/oauth/revoke", only(post(revoke), "POST"))
        .route("/api/v1/me", only(get(me), "GET, HEAD"))
        .route("/api/v1/projects", only(get(projects), "GET, HEAD"))
        .route("/api/v1/relay-ticket", only(post(relay_ticket), "POST"))
        .route("/api/v1/keys", only(get(keys), "GET, HEAD"))
        .route("/api/v1", any(not_found))
        .route("/api/v1/{*rest}", any(not_found))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_is_decoded() {
        let input = parse_form(b"a=1&b=x+y%20z&c=%C3%A4&d&e=%zz&a=2").unwrap();
        assert_eq!(input["a"], "2");
        assert_eq!(input["b"], "x y z");
        assert_eq!(input["c"], "\u{e4}");
        assert_eq!(input["d"], "");
        assert_eq!(input["e"], "%zz");
        assert!(parse_form(b"a=%FF").is_none(), "not UTF-8");
    }

    #[test]
    fn json_only_as_flat_object() {
        let input = parse_json(br#"{"a":"x","n":7,"f":1.5,"o":{"x":1},"l":[1]}"#).unwrap();
        assert_eq!(input["a"], "x");
        assert_eq!(input["n"], "7");
        assert!(!input.contains_key("f") && !input.contains_key("o") && !input.contains_key("l"));
        assert!(parse_json(b"[]").unwrap().is_empty());
        assert!(parse_json(b"[1]").is_none());
        assert!(parse_json(b"\"x\"").is_none());
        assert!(parse_json(b"{").is_none());
    }

    #[test]
    fn at_most_32_fields_with_short_names() {
        let body: String = (0..40).map(|i| format!("k{i}=v&")).collect();
        assert_eq!(parse_form(body.as_bytes()).unwrap().len(), MAX_FIELDS);
        let long = format!("{}=v", "k".repeat(MAX_KEY_LEN + 1));
        assert!(parse_form(long.as_bytes()).unwrap().is_empty());
    }
}
