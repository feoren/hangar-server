//! Sign-in for self-hosting: opaque, hashed, rotating tokens; magic link by mail;
//! OAuth 2.0 Device Authorization Grant (RFC 8628) for the app; revocable sessions.
//!
//! Tokens are stored only as SHA-256 in the database. A refresh token is valid exactly once;
//! if an already exchanged one is presented again, the whole session ends (stolen token).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

use super::pages::{self, csrf_ok, csrf_token, hidden, message, page, same_origin, t};
use super::{bearer, ApiError, ApiResult, Identity};
use crate::config::{Config, Signup};
use crate::db::{begin_write, Db, Tx};
use crate::http::ratelimit::Rule;
use crate::http::{AppState, ClientIp};
use crate::mail::i18n::{fill, pick};
use crate::mail::templates::{escape, MailKind};
use crate::util::{normalize_email, now_s, random_bytes, random_id, random_token, token_hash};

/// Allowed `client_id`: the app sends `hangar-desktop` (as with the website); `hangar` stays
/// valid for existing scripts and older versions of the self-hosting docs. Both names
/// denote the same public client without a secret; they make no difference in
/// permissions.
pub const CLIENT_IDS: [&str; 2] = ["hangar-desktop", "hangar"];
/// The only scope (same as the website); empty also means `team`.
pub const SCOPE: &str = "team";
pub const ACCESS_TTL_S: i64 = 3600;
pub const REFRESH_TTL_S: i64 = 30 * 86_400;
pub const BROWSER_TTL_S: i64 = 12 * 3600;
pub const MAGIC_TTL_S: i64 = 15 * 60;
pub const ADMIN_LINK_TTL_S: i64 = 60 * 60;
pub const DEVICE_TTL_S: i64 = 600;
pub const DEVICE_INTERVAL_S: i64 = 5;
pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Device requests per address (old and new route share the counter).
const DEVICE_RULE: Rule = Rule {
    limit: 30,
    window_s: 3600,
};
/// Token requests per address and 15 minutes (same as the website).
const TOKEN_RULE: Rule = Rule {
    limit: 600,
    window_s: 900,
};
/// RFC 7009 revocations per address and 15 minutes (same as the website).
const REVOKE_RULE: Rule = Rule {
    limit: 60,
    window_s: 900,
};
/// Longest accepted tokens and device codes (issued ones are 43 to 47 characters).
const MAX_TOKEN_LEN: usize = 128;
/// Letters without vowels and look-alikes (RFC 8628, section 6.1): 20^8 combinations.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub email: String,
    pub lang: String,
    pub session_id: String,
}

pub(crate) fn identity(state: &AppState) -> ApiResult<&Arc<Identity>> {
    state.identity.as_ref().ok_or(ApiError::NOT_FOUND)
}

async fn user_by_token(db: &Db, token: &str, kind: &str) -> ApiResult<Option<User>> {
    let now = now_s();
    let row = sqlx::query(
        "SELECT u.id, u.email, u.lang, s.id AS session_id FROM auth_tokens t \
         JOIN auth_sessions s ON s.id = t.session_id JOIN users u ON u.id = s.user_id \
         WHERE t.hash = ? AND t.kind = ? AND t.expires_at > ? AND s.revoked_at IS NULL AND s.expires_at > ?",
    )
    .bind(token_hash(token))
    .bind(kind)
    .bind(now)
    .bind(now)
    .fetch_optional(db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let user = User {
        id: row.get("id"),
        email: row.get("email"),
        lang: row.get("lang"),
        session_id: row.get("session_id"),
    };
    sqlx::query("UPDATE auth_sessions SET last_used_at = ? WHERE id = ? AND last_used_at < ?")
        .bind(now)
        .bind(&user.session_id)
        .bind(now - 60)
        .execute(db)
        .await?;
    Ok(Some(user))
}

/// Signed-in app (bearer access token).
pub async fn authenticate(identity: &Identity, headers: &HeaderMap) -> ApiResult<User> {
    let token = bearer(headers).ok_or(ApiError::UNAUTHORIZED)?;
    user_by_token(&identity.db, token, "access")
        .await?
        .ok_or(ApiError::UNAUTHORIZED)
}

/// Signed-in browser (session cookie).
pub async fn browser_user(identity: &Identity, headers: &HeaderMap) -> ApiResult<Option<User>> {
    match pages::read_cookie(headers, pages::cookie_name(&identity.config)) {
        Some(token) if token.len() <= 128 => user_by_token(&identity.db, token, "browser").await,
        _ => Ok(None),
    }
}

pub async fn find_or_create_user(
    tx: &mut Tx,
    email: &str,
    lang: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    sqlx::query("INSERT INTO users (id, email, lang, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (email) DO NOTHING")
        .bind(format!("u_{}", random_id()))
        .bind(email)
        .bind(lang)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .fetch_one(&mut **tx)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn new_session(
    tx: &mut Tx,
    user_id: &str,
    kind: &str,
    label: &str,
    platform: Option<&str>,
    ttl_s: i64,
    now: i64,
) -> Result<String, sqlx::Error> {
    let id = format!("s_{}", random_id());
    sqlx::query("INSERT INTO auth_sessions (id, user_id, kind, label, platform, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(user_id)
        .bind(kind)
        .bind(label)
        .bind(platform)
        .bind(now)
        .bind(now)
        .bind(now + ttl_s)
        .execute(&mut **tx)
        .await?;
    Ok(id)
}

async fn store_token(
    tx: &mut Tx,
    session_id: &str,
    kind: &str,
    prefix: &str,
    ttl_s: i64,
    now: i64,
) -> Result<String, sqlx::Error> {
    let token = format!("{prefix}{}", random_token());
    sqlx::query("INSERT INTO auth_tokens (hash, session_id, kind, expires_at) VALUES (?, ?, ?, ?)")
        .bind(token_hash(&token))
        .bind(session_id)
        .bind(kind)
        .bind(now + ttl_s)
        .execute(&mut **tx)
        .await?;
    Ok(token)
}

#[derive(Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
    scope: &'static str,
}

/// Without the tokens: debug output must never carry secrets.
impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

async fn issue_app_tokens(
    tx: &mut Tx,
    session_id: &str,
    now: i64,
) -> Result<TokenResponse, sqlx::Error> {
    let access = store_token(tx, session_id, "access", "hta_", ACCESS_TTL_S, now).await?;
    let refresh = store_token(tx, session_id, "refresh", "htr_", REFRESH_TTL_S, now).await?;
    sqlx::query("UPDATE auth_sessions SET expires_at = ?, last_used_at = ? WHERE id = ?")
        .bind(now + REFRESH_TTL_S)
        .bind(now)
        .bind(session_id)
        .execute(&mut **tx)
        .await?;
    Ok(TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in: ACCESS_TTL_S,
        refresh_token: refresh,
        scope: SCOPE,
    })
}

/// Starts a browser session and returns the cookie token.
pub async fn start_browser_session(
    tx: &mut Tx,
    user_id: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    let session = new_session(tx, user_id, "browser", "Browser", None, BROWSER_TTL_S, now).await?;
    store_token(tx, &session, "browser", "htb_", BROWSER_TTL_S, now).await
}

pub async fn housekeeping(db: &Db) -> Result<(), sqlx::Error> {
    let now = now_s();
    sqlx::query("DELETE FROM auth_tokens WHERE expires_at < ?")
        .bind(now)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM auth_sessions WHERE expires_at < ? OR revoked_at < ?")
        .bind(now)
        .bind(now - 30 * 86_400)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM magic_links WHERE expires_at < ?")
        .bind(now - 86_400)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM device_codes WHERE expires_at < ?")
        .bind(now - 86_400)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM mail_throttle WHERE sent_at < ?")
        .bind(now - 7 * 86_400)
        .execute(db)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Magic link

/// Allowed return targets after the magic link (no open redirects).
fn safe_return(raw: Option<&str>) -> String {
    match raw {
        Some(path) if path == "/device" || path == DEVICES_PAGE => path.to_owned(),
        Some(path)
            if path.strip_prefix("/device?code=").is_some_and(|c| {
                c.len() == 9 && c.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
            }) =>
        {
            path.to_owned()
        }
        _ => "/device".into(),
    }
}

/// Browser page of the connected devices; the path is hard-coded in the app (`BaseUrl::devices_page`).
pub const DEVICES_PAGE: &str = "/account/devices";

/// Return after the magic link. A device code in the target is only honored in the browser that
/// requested the link: otherwise someone could have a link with their own code sent to another
/// person's address, and that person would approve the attacker's device with one click.
fn return_after_magic(stored: &str, bound: Option<&str>, browser: Option<&str>) -> String {
    let same_browser = match (bound, browser) {
        (Some(bound), Some(browser)) => {
            crate::util::ct_eq(bound.as_bytes(), token_hash(browser).as_bytes())
        }
        _ => false,
    };
    // The device list carries no code: it may be the target in any browser.
    if same_browser || stored == DEVICES_PAGE {
        safe_return(Some(stored))
    } else {
        "/device".into()
    }
}

async fn may_sign_in(db: &Db, config: &Config, email: &str) -> Result<bool, sqlx::Error> {
    if config.signup == Signup::Open {
        return Ok(true);
    }
    let known: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM users WHERE email = ? UNION ALL \
         SELECT 1 FROM invitations WHERE email = ? AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > ? LIMIT 1",
    )
    .bind(email)
    .bind(email)
    .bind(now_s())
    .fetch_optional(db)
    .await?;
    Ok(known.is_some())
}

async fn create_magic_link(
    db: &Db,
    email: &str,
    return_to: &str,
    ttl_s: i64,
    browser: Option<&str>,
) -> Result<String, sqlx::Error> {
    let token = random_token();
    let now = now_s();
    sqlx::query("INSERT INTO magic_links (hash, email, return_to, created_at, expires_at, browser_hash) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(token_hash(&token))
        .bind(email)
        .bind(return_to)
        .bind(now)
        .bind(now + ttl_s)
        .bind(browser.map(token_hash))
        .execute(db)
        .await?;
    Ok(token)
}

/// Service: request a magic link. The answer never differs depending on whether the address
/// is known. `browser`: random value from the requesting browser's cookie; only there does
/// the link lead back to the device code.
pub async fn request_magic_link(
    identity: &Identity,
    raw_email: &str,
    return_to: Option<&str>,
    lang: &str,
    ip: &str,
    browser: Option<&str>,
) -> ApiResult<()> {
    let now = now_s();
    if !identity.limiter.hit(
        "magic-ip",
        ip,
        Rule {
            limit: 20,
            window_s: 900,
        },
        now,
    ) {
        return Err(ApiError::RATE_LIMITED);
    }
    let Some(email) = normalize_email(raw_email) else {
        return Err(ApiError::INVALID);
    };
    if !identity.limiter.hit(
        "magic-email",
        &email,
        Rule {
            limit: 5,
            window_s: 3600,
        },
        now,
    ) {
        return Ok(());
    }
    if !identity.mailer.enabled() || !may_sign_in(&identity.db, &identity.config, &email).await? {
        return Ok(());
    }
    let token = create_magic_link(
        &identity.db,
        &email,
        &safe_return(return_to),
        MAGIC_TTL_S,
        browser,
    )
    .await?;
    let link = identity.url(&format!("/auth/magic/{token}"));
    identity.mailer.send(
        &email,
        lang,
        MailKind::LoginLink {
            link,
            minutes: (MAGIC_TTL_S / 60) as u32,
        },
    );
    Ok(())
}

/// For `hangar-server login-link <email>`: link without mail for the person at the server.
pub async fn admin_login_link(db: &Db, config: &Config, raw_email: &str) -> Result<String, String> {
    let email = normalize_email(raw_email).ok_or("invalid email address")?;
    let token = create_magic_link(db, &email, "/device", ADMIN_LINK_TTL_S, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(format!("{}/auth/magic/{token}", config.public_url))
}

#[derive(Debug, Deserialize)]
pub struct EmailForm {
    email: String,
    return_to: Option<String>,
}

pub async fn email_submit(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<EmailForm>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    if !same_origin(&headers, &identity.config) {
        return message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::FORBIDDEN,
        );
    }
    if !identity.mailer.enabled() {
        return message(
            lang,
            s.page_sign_in,
            s.page_no_mail,
            "muted",
            StatusCode::OK,
        );
    }
    let browser = random_token();
    let mut response = match request_magic_link(
        identity,
        &form.email,
        form.return_to.as_deref(),
        lang,
        &ip.key(),
        Some(&browser),
    )
    .await
    {
        Ok(())
        | Err(ApiError {
            code: "invalid_request",
            ..
        }) => message(
            lang,
            s.page_sign_in,
            s.page_email_sent,
            "ok",
            StatusCode::OK,
        ),
        Err(ApiError {
            code: "rate_limited",
            ..
        }) => message(
            lang,
            s.page_sign_in,
            s.page_too_many,
            "error",
            StatusCode::TOO_MANY_REQUESTS,
        ),
        Err(_) => message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    };
    // Always set, whether a mail was produced or not (reveals nothing about addresses).
    response.headers_mut().insert(
        header::SET_COOKIE,
        pages::cookie(
            &identity.config,
            pages::login_cookie_name(&identity.config),
            &browser,
            MAGIC_TTL_S,
        ),
    );
    response
}

/// GET: only shows a confirmation, so link scanners in mail clients trigger nothing.
pub async fn magic_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM magic_links WHERE hash = ? AND used_at IS NULL AND expires_at > ?",
    )
    .bind(token_hash(&token))
    .bind(now_s())
    .fetch_optional(&identity.db)
    .await
    .ok()
    .flatten();
    let Some(email) = email else {
        return message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        );
    };
    let body = format!(
        r#"<h1>{title}</h1><p>{prompt}</p><form method="post" action="/auth/magic/{token}"><button type="submit">{button}</button></form>"#,
        title = escape(s.page_sign_in),
        prompt = escape(&fill(s.page_magic_prompt, &[("email", &email)])),
        token = escape(&token),
        button = escape(s.page_sign_in),
    );
    page(lang, s.page_sign_in, &body, StatusCode::OK)
}

/// POST: redeems the link once and starts the browser session.
pub async fn magic_consume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    if !same_origin(&headers, &identity.config) {
        return message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::FORBIDDEN,
        );
    }
    let browser = pages::read_cookie(&headers, pages::login_cookie_name(&identity.config));
    match consume_magic(identity, &token, lang, browser).await {
        Ok(Some((cookie, return_to))) => {
            let mut response = Redirect::to(&return_to).into_response();
            response.headers_mut().insert(
                header::SET_COOKIE,
                pages::session_cookie(&identity.config, &cookie, BROWSER_TTL_S),
            );
            response.headers_mut().append(
                header::SET_COOKIE,
                pages::cookie(
                    &identity.config,
                    pages::login_cookie_name(&identity.config),
                    "",
                    0,
                ),
            );
            response
        }
        Ok(None) => message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        ),
        Err(_) => message(
            lang,
            s.page_sign_in,
            s.page_link_invalid,
            "error",
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    }
}

async fn consume_magic(
    identity: &Identity,
    token: &str,
    lang: &str,
    browser: Option<&str>,
) -> ApiResult<Option<(String, String)>> {
    let now = now_s();
    let mut tx = begin_write(&identity.db).await?;
    let row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "UPDATE magic_links SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ? RETURNING email, return_to, browser_hash",
    )
    .bind(now)
    .bind(token_hash(token))
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, return_to, bound)) = row else {
        return Ok(None);
    };
    let user = find_or_create_user(&mut tx, &email, lang, now).await?;
    let cookie = start_browser_session(&mut tx, &user, now).await?;
    tx.commit().await?;
    tracing::info!("sign-in via link");
    Ok(Some((
        cookie,
        return_after_magic(&return_to, bound.as_deref(), browser),
    )))
}

pub async fn browser_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    if same_origin(&headers, &identity.config) {
        if let Ok(Some(user)) = browser_user(identity, &headers).await {
            let _ = revoke(&identity.db, &user.id, &user.session_id).await;
        }
    }
    let mut response = Redirect::to("/device").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        pages::session_cookie(&identity.config, "", 0),
    );
    response
}

// ---------------------------------------------------------------------------------------------
// Device flow (RFC 8628)

fn user_code() -> String {
    let bytes = random_bytes::<8>();
    let letters: String = bytes
        .iter()
        .map(|b| char::from(USER_CODE_ALPHABET[usize::from(*b) % 20]))
        .collect();
    format!("{}-{}", &letters[..4], &letters[4..])
}

/// Normalizes input such as `bcdf ghjk` or `BCDFGHJK` to the form `BCDF-GHJK`.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (letters.len() == 8 && letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then(|| format!("{}-{}", &letters[..4], &letters[4..]))
}

/// Device name for the session list and confirmation page: control characters become spaces,
/// trimmed, shortened; empty becomes `Hangar`.
pub fn clean_label(raw: Option<&str>, max_chars: usize) -> String {
    let spaced: String = raw
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let label: String = spaced.trim().chars().take(max_chars).collect();
    let label = label.trim_end();
    if label.is_empty() {
        "Hangar".into()
    } else {
        label.to_owned()
    }
}

/// The app's platform (`windows`, `macos`, `linux`, ...): `[A-Za-z0-9 ._-]`, 1 to 40 characters,
/// otherwise none (same as the website).
pub fn clean_platform(raw: Option<&str>) -> Option<String> {
    let value = raw?.trim();
    let fine = !value.is_empty()
        && value.len() <= 40
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'));
    fine.then(|| value.to_owned())
}

/// Token or device code of usable length.
fn usable_token(value: Option<&str>) -> Option<&str> {
    value.filter(|v| !v.is_empty() && v.len() <= MAX_TOKEN_LEN)
}

pub fn client_ok(client_id: Option<&str>) -> bool {
    client_id.is_some_and(|id| CLIENT_IDS.contains(&id))
}

/// Scope of the request: empty or missing means `team`, otherwise only `team` (also repeated).
pub fn scope_ok(scope: Option<&str>) -> bool {
    scope.is_none_or(|s| s.split(' ').filter(|p| !p.is_empty()).all(|p| p == SCOPE))
}

/// Response to the start of the device flow (RFC 8628, section 3.2).
#[derive(Serialize)]
pub struct DeviceStart {
    device_code: String,
    pub user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i64,
}

/// Service: start the device flow. Errors as OAuth code (`rate_limited` becomes 429).
pub async fn start_device(
    identity: &Identity,
    ip: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    label: &str,
    platform: Option<&str>,
) -> Result<DeviceStart, &'static str> {
    if !identity.limiter.hit("device-ip", ip, DEVICE_RULE, now_s()) {
        return Err("rate_limited");
    }
    if !client_ok(client_id) {
        return Err("invalid_client");
    }
    if !scope_ok(scope) {
        return Err("invalid_scope");
    }
    let device_code = random_token();
    let code = user_code();
    let now = now_s();
    sqlx::query("INSERT INTO device_codes (hash, user_code, label, platform, created_at, expires_at, interval_s, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')")
        .bind(token_hash(&device_code))
        .bind(&code)
        .bind(label)
        .bind(platform)
        .bind(now)
        .bind(now + DEVICE_TTL_S)
        .bind(DEVICE_INTERVAL_S)
        .execute(&identity.db)
        .await
        .map_err(|error| {
            tracing::error!(%error, "device flow: start");
            "server_error"
        })?;
    Ok(DeviceStart {
        device_code,
        verification_uri: identity.url("/device"),
        verification_uri_complete: identity.url(&format!("/device?code={code}")),
        user_code: code,
        expires_in: DEVICE_TTL_S,
        interval: DEVICE_INTERVAL_S,
    })
}

/// Service: token endpoint (redeem a device code or rotate a refresh token). Errors as
/// OAuth code per RFC 6749 5.2 and RFC 8628 3.5; `rate_limited` becomes 429.
pub async fn exchange(
    identity: &Identity,
    ip: &str,
    client_id: Option<&str>,
    grant_type: Option<&str>,
    device_code: Option<&str>,
    refresh_token: Option<&str>,
) -> Result<TokenResponse, &'static str> {
    if !identity.limiter.hit("token-ip", ip, TOKEN_RULE, now_s()) {
        return Err("rate_limited");
    }
    if !client_ok(client_id) {
        return Err("invalid_client");
    }
    match grant_type {
        Some(DEVICE_GRANT) => match usable_token(device_code) {
            Some(code) => poll_device(&identity.db, code).await,
            None => Err("invalid_request"),
        },
        Some("refresh_token") => match usable_token(refresh_token) {
            Some(token) => refresh(&identity.db, token).await,
            None => Err("invalid_request"),
        },
        Some(_) => Err("unsupported_grant_type"),
        None => Err("invalid_request"),
    }
}

/// Service: revocation by the app (RFC 7009). A refresh token ends the whole device session
/// (all tokens of the family), an access token only itself. Unknown, foreign or already
/// revoked tokens change nothing and look the same (reveals nothing).
/// Browser tokens are excluded. `token_type_hint` is only a hint (RFC 7009 2.1).
pub async fn revoke_token(
    identity: &Identity,
    ip: &str,
    client_id: Option<&str>,
    token: Option<&str>,
    hint: Option<&str>,
) -> Result<(), &'static str> {
    if !identity.limiter.hit("revoke-ip", ip, REVOKE_RULE, now_s()) {
        return Err("rate_limited");
    }
    if !client_ok(client_id) {
        return Err("invalid_client");
    }
    let Some(token) = usable_token(token) else {
        return Err("invalid_request");
    };
    if !matches!(hint, None | Some("" | "refresh_token" | "access_token")) {
        return Err("invalid_request");
    }
    let internal = |error: sqlx::Error| {
        tracing::error!(%error, "revocation (RFC 7009)");
        "server_error"
    };
    let now = now_s();
    let hash = token_hash(token);
    let mut tx = begin_write(&identity.db).await.map_err(internal)?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT t.kind, t.session_id FROM auth_tokens t JOIN auth_sessions s ON s.id = t.session_id \
         WHERE t.hash = ? AND t.kind IN ('access', 'refresh') AND s.kind = 'app'",
    )
    .bind(&hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    match row {
        Some((kind, session)) if kind == "refresh" => {
            sqlx::query(
                "UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(&session)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            sqlx::query("DELETE FROM auth_tokens WHERE session_id = ?")
                .bind(&session)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            tracing::info!("app signed out: device session revoked (RFC 7009)");
        }
        Some(_) => {
            sqlx::query("DELETE FROM auth_tokens WHERE hash = ?")
                .bind(&hash)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
        }
        None => {}
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthForm {
    client_id: Option<String>,
    scope: Option<String>,
    /// Display name of the device for the session list (e.g. "Hangar on Laptop").
    device_name: Option<String>,
    platform: Option<String>,
}

/// Errors of the old OAuth routes: `{"error": code}` (format kept for existing clients).
fn oauth_error(code: &'static str) -> Response {
    let status = match code {
        "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
        "server_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    (status, Json(json!({ "error": code }))).into_response()
}

/// `POST /oauth/device_authorization` (form only). The app uses `/api/v1/oauth/device`.
pub async fn device_authorization(
    State(state): State<AppState>,
    ip: ClientIp,
    Form(form): Form<DeviceAuthForm>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let label = clean_label(form.device_name.as_deref(), 64);
    let platform = clean_platform(form.platform.as_deref());
    match start_device(
        identity,
        &ip.key(),
        form.client_id.as_deref(),
        form.scope.as_deref(),
        &label,
        platform.as_deref(),
    )
    .await
    {
        Ok(started) => Json(started).into_response(),
        Err(code) => oauth_error(code),
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: Option<String>,
    client_id: Option<String>,
    device_code: Option<String>,
    refresh_token: Option<String>,
}

/// `POST /oauth/token` (form only). The app uses `/api/v1/oauth/token`.
pub async fn token(
    State(state): State<AppState>,
    ip: ClientIp,
    Form(form): Form<TokenForm>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    match exchange(
        identity,
        &ip.key(),
        form.client_id.as_deref(),
        form.grant_type.as_deref(),
        form.device_code.as_deref(),
        form.refresh_token.as_deref(),
    )
    .await
    {
        Ok(tokens) => Json(tokens).into_response(),
        Err(code) => oauth_error(code),
    }
}

/// status, expires_at, interval_s, last_poll_at, user_id, label, platform
type DeviceRow = (
    String,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    String,
    Option<String>,
);

async fn poll_device(db: &Db, device_code: &str) -> Result<TokenResponse, &'static str> {
    let now = now_s();
    let internal = |error: sqlx::Error| {
        tracing::error!(%error, "device flow");
        "server_error"
    };
    let mut tx = begin_write(db).await.map_err(internal)?;
    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT status, expires_at, interval_s, last_poll_at, user_id, label, platform FROM device_codes WHERE hash = ?",
    )
    .bind(token_hash(device_code))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some((status, expires_at, interval, last_poll, user_id, label, platform)) = row else {
        return Err("invalid_grant");
    };
    if expires_at <= now {
        return Err("expired_token");
    }
    let hash = token_hash(device_code);
    match status.as_str() {
        "pending" => {
            let too_fast = last_poll.is_some_and(|last| now - last < interval);
            let next_interval = if too_fast { interval + 5 } else { interval };
            sqlx::query("UPDATE device_codes SET last_poll_at = ?, interval_s = ? WHERE hash = ?")
                .bind(now)
                .bind(next_interval)
                .bind(&hash)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            Err(if too_fast {
                "slow_down"
            } else {
                "authorization_pending"
            })
        }
        "denied" => Err("access_denied"),
        "approved" => {
            let user_id = user_id.ok_or("server_error")?;
            sqlx::query(
                "UPDATE device_codes SET status = 'used' WHERE hash = ? AND status = 'approved'",
            )
            .bind(&hash)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
            let session = new_session(
                &mut tx,
                &user_id,
                "app",
                &label,
                platform.as_deref(),
                REFRESH_TTL_S,
                now,
            )
            .await
            .map_err(internal)?;
            let tokens = issue_app_tokens(&mut tx, &session, now)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            tracing::info!("app signed in (device flow)");
            Ok(tokens)
        }
        _ => Err("invalid_grant"),
    }
}

/// session_id, expires_at, used_at, revoked_at, session expires_at
type RefreshRow = (String, i64, Option<i64>, Option<i64>, i64);

/// Exchanges a refresh token for a new pair (rotation with reuse detection).
pub async fn refresh(db: &Db, token: &str) -> Result<TokenResponse, &'static str> {
    let now = now_s();
    let internal = |error: sqlx::Error| {
        tracing::error!(%error, "refresh");
        "server_error"
    };
    let mut tx = begin_write(db).await.map_err(internal)?;
    let row: Option<RefreshRow> = sqlx::query_as(
        "SELECT t.session_id, t.expires_at, t.used_at, s.revoked_at, s.expires_at FROM auth_tokens t \
         JOIN auth_sessions s ON s.id = t.session_id WHERE t.hash = ? AND t.kind = 'refresh'",
    )
    .bind(token_hash(token))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some((session, expires_at, used_at, revoked_at, session_expires)) = row else {
        return Err("invalid_grant");
    };
    if used_at.is_some() {
        sqlx::query("UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
            .bind(now)
            .bind(&session)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        sqlx::query("DELETE FROM auth_tokens WHERE session_id = ?")
            .bind(&session)
            .execute(&mut *tx)
            .await
            .map_err(internal)?;
        tx.commit().await.map_err(internal)?;
        tracing::warn!("refresh token reused: session revoked");
        return Err("invalid_grant");
    }
    if expires_at <= now || revoked_at.is_some() || session_expires <= now {
        return Err("invalid_grant");
    }
    sqlx::query("UPDATE auth_tokens SET used_at = ? WHERE hash = ?")
        .bind(now)
        .bind(token_hash(token))
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    // The session's old access tokens end with the rotation.
    sqlx::query("DELETE FROM auth_tokens WHERE session_id = ? AND kind = 'access'")
        .bind(&session)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let tokens = issue_app_tokens(&mut tx, &session, now)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(tokens)
}

/// Sign-in form (magic link by mail) returning to `return_to` (only paths from
/// [`safe_return`]); without mail delivery, a note to ask the admin for a link.
pub(crate) fn sign_in_page(
    identity: &Identity,
    lang: &str,
    title: &str,
    return_to: &str,
) -> Response {
    let s = crate::mail::i18n::strings(lang);
    let body = if identity.mailer.enabled() {
        format!(
            r#"<h1>{title}</h1><p>{prompt}</p><form method="post" action="/auth/email">{ret}<label for="email">{label}</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254"><button type="submit">{send}</button></form>"#,
            title = escape(title),
            prompt = escape(s.page_email_prompt),
            ret = hidden("return_to", return_to),
            label = escape(s.page_email_label),
            send = escape(s.page_email_send),
        )
    } else {
        format!(
            r#"<h1>{}</h1><p class="muted">{}</p>"#,
            escape(title),
            escape(s.page_no_mail)
        )
    };
    page(lang, title, &body, StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct DeviceQuery {
    code: Option<String>,
}

pub async fn device_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<DeviceQuery>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let code = query.code.as_deref().and_then(normalize_user_code);
    let user = browser_user(identity, &headers).await.ok().flatten();
    let Some(user) = user else {
        // Sign in first; afterwards the link leads back here.
        let return_to = code
            .as_ref()
            .map_or("/device".to_owned(), |c| format!("/device?code={c}"));
        return sign_in_page(identity, lang, s.page_device_title, &return_to);
    };
    let csrf = csrf_token(&identity.config, &user.session_id);
    let signed_in = escape(&fill(s.page_signed_in, &[("email", &user.email)]));
    let label = match &code {
        Some(code) => {
            let label: Option<(String, Option<String>)> = sqlx::query_as(
                "SELECT label, platform FROM device_codes WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
            )
            .bind(code)
            .bind(now_s())
            .fetch_optional(&identity.db)
            .await
            .ok()
            .flatten();
            match label {
                Some((label, Some(platform))) => format!("{label} ({platform})"),
                Some((label, None)) => label,
                None => {
                    return message(
                        lang,
                        s.page_device_title,
                        s.page_code_invalid,
                        "error",
                        StatusCode::NOT_FOUND,
                    )
                }
            }
        }
        None => String::new(),
    };
    let body = match code {
        Some(code) => format!(
            r#"<h1>{title}</h1><p>{prompt}</p><p class="code">{code}</p><p class="muted">{device}</p><form method="post" action="/device">{csrf}{codefield}<div class="row"><button type="submit" name="decision" value="approve">{approve}</button><button class="secondary" type="submit" name="decision" value="deny">{deny}</button></div></form><p class="muted">{signed_in}</p>"#,
            title = escape(s.page_device_title),
            prompt = escape(s.page_device_prompt),
            code = escape(&code),
            device = escape(&fill(s.page_device_label, &[("label", &label)])),
            csrf = hidden("csrf", &csrf),
            codefield = hidden("user_code", &code),
            approve = escape(s.page_approve),
            deny = escape(s.page_deny),
        ),
        None => format!(
            r#"<h1>{title}</h1><form method="get" action="/device"><label for="code">{label}</label><input id="code" name="code" autocomplete="one-time-code" required maxlength="12" autocapitalize="characters"><button type="submit">{cont}</button></form><p class="muted">{signed_in}</p>"#,
            title = escape(s.page_device_title),
            label = escape(s.page_code_label),
            cont = escape(s.page_continue),
        ),
    };
    page(lang, s.page_device_title, &body, StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct DeviceDecision {
    csrf: Option<String>,
    user_code: String,
    decision: String,
}

pub async fn device_decide(
    State(state): State<AppState>,
    ip: ClientIp,
    headers: HeaderMap,
    Form(form): Form<DeviceDecision>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let user = browser_user(identity, &headers).await.ok().flatten();
    let Some(user) = user.filter(|u| {
        same_origin(&headers, &identity.config)
            && csrf_ok(&identity.config, &u.session_id, form.csrf.as_deref())
    }) else {
        return message(
            lang,
            s.page_device_title,
            s.page_code_invalid,
            "error",
            StatusCode::FORBIDDEN,
        );
    };
    let now = now_s();
    if !identity.limiter.hit(
        "device-decide",
        &user.id,
        Rule {
            limit: 10,
            window_s: 900,
        },
        now,
    ) || !identity.limiter.hit(
        "device-decide-ip",
        &ip.key(),
        Rule {
            limit: 30,
            window_s: 900,
        },
        now,
    ) {
        return message(
            lang,
            s.page_device_title,
            s.page_too_many,
            "error",
            StatusCode::TOO_MANY_REQUESTS,
        );
    }
    let Some(code) = normalize_user_code(&form.user_code) else {
        return message(
            lang,
            s.page_device_title,
            s.page_code_invalid,
            "error",
            StatusCode::BAD_REQUEST,
        );
    };
    let status = if form.decision == "approve" {
        "approved"
    } else {
        "denied"
    };
    let done = sqlx::query("UPDATE device_codes SET status = ?, user_id = ? WHERE user_code = ? AND status = 'pending' AND expires_at > ?")
        .bind(status)
        .bind(&user.id)
        .bind(&code)
        .bind(now)
        .execute(&identity.db)
        .await;
    match done {
        Ok(r) if r.rows_affected() == 1 && status == "approved" => message(
            lang,
            s.page_device_title,
            s.page_device_done,
            "ok",
            StatusCode::OK,
        ),
        Ok(r) if r.rows_affected() == 1 => message(
            lang,
            s.page_device_title,
            s.page_device_denied,
            "muted",
            StatusCode::OK,
        ),
        _ => message(
            lang,
            s.page_device_title,
            s.page_code_invalid,
            "error",
            StatusCode::NOT_FOUND,
        ),
    }
}

// ---------------------------------------------------------------------------------------------
// Sessions

pub(crate) async fn revoke(db: &Db, user_id: &str, session_id: &str) -> Result<bool, sqlx::Error> {
    let mut tx = begin_write(db).await?;
    let done = sqlx::query("UPDATE auth_sessions SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL")
        .bind(now_s())
        .bind(session_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM auth_tokens WHERE session_id = ? AND session_id IN (SELECT id FROM auth_sessions WHERE user_id = ?)")
        .bind(session_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(done.rows_affected() == 1)
}

pub async fn sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    let rows: Vec<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT id, kind, label, created_at, last_used_at FROM auth_sessions \
         WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_used_at DESC LIMIT 100",
    )
    .bind(&user.id)
    .bind(now_s())
    .fetch_all(&identity.db)
    .await?;
    let list: Vec<_> = rows
        .into_iter()
        .map(|(id, kind, label, created, used)| json!({ "id": id, "kind": kind, "label": label, "createdAt": created, "lastUsedAt": used, "current": id == user.session_id }))
        .collect();
    Ok(Json(json!({ "sessions": list })))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    if revoke(&identity.db, &user.id, &id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NOT_FOUND)
    }
}

pub async fn app_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let identity = identity(&state)?;
    let user = authenticate(identity, &headers).await?;
    revoke(&identity.db, &user.id, &user.session_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Language for mails to a person: their stored one, otherwise the default.
pub fn mail_lang(stored: Option<&str>, config: &Config) -> &'static str {
    pick(stored, None, &config.default_lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_code_format() {
        let code = user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(
            normalize_user_code(&code.to_lowercase().replace('-', " ")),
            Some(code)
        );
        assert_eq!(
            normalize_user_code("ABCD-EFGH"),
            None,
            "vowels are not part of the alphabet"
        );
        assert_eq!(normalize_user_code("BCDF"), None);
    }

    #[test]
    fn device_code_in_return_only_in_requesting_browser() {
        let stored = "/device?code=BCDF-GHJK";
        let bound = token_hash("nonce-a");
        assert_eq!(
            return_after_magic(stored, Some(&bound), Some("nonce-a")),
            stored
        );
        assert_eq!(
            return_after_magic(stored, Some(&bound), Some("nonce-b")),
            "/device"
        );
        assert_eq!(return_after_magic(stored, Some(&bound), None), "/device");
        assert_eq!(return_after_magic(stored, None, Some("nonce-a")), "/device");
    }

    #[test]
    fn return_only_to_allowed_paths() {
        assert_eq!(
            safe_return(Some("/device?code=BCDF-GHJK")),
            "/device?code=BCDF-GHJK"
        );
        assert_eq!(safe_return(Some("https://evil.example")), "/device");
        assert_eq!(safe_return(Some("//evil.example")), "/device");
        assert_eq!(safe_return(Some("/device?code=x&next=//evil")), "/device");
    }
}
