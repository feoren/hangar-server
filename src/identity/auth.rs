//! Anmeldung im Selbstbetrieb: opake, gehashte, rotierende Tokens; Magic Link per Mail;
//! OAuth 2.0 Device Authorization Grant (RFC 8628) für die App; widerrufbare Sitzungen.
//!
//! Tokens liegen nur als SHA-256 in der Datenbank. Ein Erneuerungstoken gilt genau einmal;
//! wird ein schon getauschtes erneut vorgelegt, endet die ganze Sitzung (gestohlenes Token).

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

pub const CLIENT_ID: &str = "hangar";
pub const ACCESS_TTL_S: i64 = 3600;
pub const REFRESH_TTL_S: i64 = 30 * 86_400;
pub const BROWSER_TTL_S: i64 = 12 * 3600;
pub const MAGIC_TTL_S: i64 = 15 * 60;
pub const ADMIN_LINK_TTL_S: i64 = 60 * 60;
pub const DEVICE_TTL_S: i64 = 600;
pub const DEVICE_INTERVAL_S: i64 = 5;
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Buchstaben ohne Vokale und Verwechselbares (RFC 8628, Abschnitt 6.1): 20^8 Möglichkeiten.
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

/// Angemeldete App (Bearer-Zugriffstoken).
pub async fn authenticate(identity: &Identity, headers: &HeaderMap) -> ApiResult<User> {
    let token = bearer(headers).ok_or(ApiError::UNAUTHORIZED)?;
    user_by_token(&identity.db, token, "access")
        .await?
        .ok_or(ApiError::UNAUTHORIZED)
}

/// Angemeldeter Browser (Sitzungscookie).
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

async fn new_session(
    tx: &mut Tx,
    user_id: &str,
    kind: &str,
    label: &str,
    ttl_s: i64,
    now: i64,
) -> Result<String, sqlx::Error> {
    let id = format!("s_{}", random_id());
    sqlx::query("INSERT INTO auth_sessions (id, user_id, kind, label, created_at, last_used_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(user_id)
        .bind(kind)
        .bind(label)
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

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
    refresh_token: String,
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
    })
}

/// Startet eine Browsersitzung und gibt das Cookie-Token zurück.
pub async fn start_browser_session(
    tx: &mut Tx,
    user_id: &str,
    now: i64,
) -> Result<String, sqlx::Error> {
    let session = new_session(tx, user_id, "browser", "Browser", BROWSER_TTL_S, now).await?;
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
// Magic Link

/// Erlaubte Rücksprungziele nach dem Anmeldelink (keine offenen Weiterleitungen).
fn safe_return(raw: Option<&str>) -> String {
    match raw {
        Some(path) if path == "/device" => path.to_owned(),
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

/// Rücksprung nach dem Anmeldelink. Ein Gerätecode im Ziel gilt nur in dem Browser, der den
/// Link angefordert hat: sonst könnte jemand einen Link mit seinem eigenen Code an eine fremde
/// Adresse schicken lassen, und die Person ließe mit einem Klick sein Gerät zu.
fn return_after_magic(stored: &str, bound: Option<&str>, browser: Option<&str>) -> String {
    let same_browser = match (bound, browser) {
        (Some(bound), Some(browser)) => {
            crate::util::ct_eq(bound.as_bytes(), token_hash(browser).as_bytes())
        }
        _ => false,
    };
    if same_browser {
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

/// Dienst: Anmeldelink anfordern. Antwortet nie anders, ob die Adresse bekannt ist.
/// `browser`: Zufallswert aus dem Cookie des anfragenden Browsers; nur dort führt der Link
/// zurück auf den Gerätecode.
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

/// Für `hangar-team-server login-link <email>`: Link ohne Mail für die Person am Server.
pub async fn admin_login_link(db: &Db, config: &Config, raw_email: &str) -> Result<String, String> {
    let email = normalize_email(raw_email).ok_or("ungültige E-Mail-Adresse")?;
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
    // Immer setzen, ob eine Mail entstand oder nicht (keine Auskunft über Adressen).
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

/// GET: zeigt nur eine Bestätigung. Linkprüfer in Mailprogrammen lösen so nichts aus.
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

/// POST: löst den Link einmalig ein und startet die Browsersitzung.
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
    tracing::info!("Anmeldung per Link");
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
// Device Flow (RFC 8628)

fn user_code() -> String {
    let bytes = random_bytes::<8>();
    let letters: String = bytes
        .iter()
        .map(|b| char::from(USER_CODE_ALPHABET[usize::from(*b) % 20]))
        .collect();
    format!("{}-{}", &letters[..4], &letters[4..])
}

/// Eingaben wie `bcdf ghjk` oder `BCDFGHJK` auf die Form `BCDF-GHJK` bringen.
pub fn normalize_user_code(raw: &str) -> Option<String> {
    let letters: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (letters.len() == 8 && letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then(|| format!("{}-{}", &letters[..4], &letters[4..]))
}

#[derive(Debug, Deserialize)]
pub struct DeviceAuthForm {
    client_id: Option<String>,
    /// Anzeigename des Geräts für die Sitzungsliste (z. B. "Hangar auf Laptop").
    device_name: Option<String>,
}

fn oauth_error(code: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": code }))).into_response()
}

pub async fn device_authorization(
    State(state): State<AppState>,
    ip: ClientIp,
    Form(form): Form<DeviceAuthForm>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    if form.client_id.as_deref() != Some(CLIENT_ID) {
        return oauth_error("invalid_client");
    }
    if !identity.limiter.hit(
        "device-ip",
        &ip.key(),
        Rule {
            limit: 30,
            window_s: 3600,
        },
        now_s(),
    ) {
        return ApiError::RATE_LIMITED.into_response();
    }
    let label: String = form
        .device_name
        .unwrap_or_else(|| "Hangar".into())
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let device_code = random_token();
    let code = user_code();
    let now = now_s();
    let stored = sqlx::query("INSERT INTO device_codes (hash, user_code, label, created_at, expires_at, interval_s, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')")
        .bind(token_hash(&device_code))
        .bind(&code)
        .bind(&label)
        .bind(now)
        .bind(now + DEVICE_TTL_S)
        .bind(DEVICE_INTERVAL_S)
        .execute(&identity.db)
        .await;
    if let Err(error) = stored {
        return ApiError::from(error).into_response();
    }
    Json(json!({
        "device_code": device_code,
        "user_code": code,
        "verification_uri": identity.url("/device"),
        "verification_uri_complete": identity.url(&format!("/device?code={code}")),
        "expires_in": DEVICE_TTL_S,
        "interval": DEVICE_INTERVAL_S,
    }))
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    client_id: Option<String>,
    device_code: Option<String>,
    refresh_token: Option<String>,
}

pub async fn token(State(state): State<AppState>, Form(form): Form<TokenForm>) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    if form.client_id.as_deref() != Some(CLIENT_ID) {
        return oauth_error("invalid_client");
    }
    let result = match form.grant_type.as_str() {
        DEVICE_GRANT => match form.device_code.as_deref() {
            Some(code) => poll_device(&identity.db, code).await,
            None => Err("invalid_request"),
        },
        "refresh_token" => match form.refresh_token.as_deref() {
            Some(token) => refresh(&identity.db, token).await,
            None => Err("invalid_request"),
        },
        _ => Err("unsupported_grant_type"),
    };
    match result {
        Ok(tokens) => Json(tokens).into_response(),
        Err(code) => oauth_error(code),
    }
}

/// status, expires_at, interval_s, last_poll_at, user_id, label
type DeviceRow = (String, i64, i64, Option<i64>, Option<String>, String);

async fn poll_device(db: &Db, device_code: &str) -> Result<TokenResponse, &'static str> {
    let now = now_s();
    let internal = |error: sqlx::Error| {
        tracing::error!(%error, "Device Flow");
        "server_error"
    };
    let mut tx = begin_write(db).await.map_err(internal)?;
    let row: Option<DeviceRow> = sqlx::query_as(
        "SELECT status, expires_at, interval_s, last_poll_at, user_id, label FROM device_codes WHERE hash = ?",
    )
    .bind(token_hash(device_code))
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    let Some((status, expires_at, interval, last_poll, user_id, label)) = row else {
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
            let session = new_session(&mut tx, &user_id, "app", &label, REFRESH_TTL_S, now)
                .await
                .map_err(internal)?;
            let tokens = issue_app_tokens(&mut tx, &session, now)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            tracing::info!("App angemeldet (Device Flow)");
            Ok(tokens)
        }
        _ => Err("invalid_grant"),
    }
}

/// session_id, expires_at, used_at, revoked_at, session expires_at
type RefreshRow = (String, i64, Option<i64>, Option<i64>, i64);

/// Tauscht ein Erneuerungstoken gegen ein neues Paar (Rotation mit Erkennung der Wiederverwendung).
pub async fn refresh(db: &Db, token: &str) -> Result<TokenResponse, &'static str> {
    let now = now_s();
    let internal = |error: sqlx::Error| {
        tracing::error!(%error, "Erneuerung");
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
        tracing::warn!("Erneuerungstoken erneut verwendet: Sitzung widerrufen");
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
    // Alte Zugriffstokens der Sitzung enden mit der Rotation.
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
        // Erst anmelden; danach führt der Link hierher zurück.
        let return_to = code
            .as_ref()
            .map_or("/device".to_owned(), |c| format!("/device?code={c}"));
        let body = if identity.mailer.enabled() {
            format!(
                r#"<h1>{title}</h1><p>{prompt}</p><form method="post" action="/auth/email">{ret}<label for="email">{label}</label><input id="email" name="email" type="email" autocomplete="email" required maxlength="254"><button type="submit">{send}</button></form>"#,
                title = escape(s.page_device_title),
                prompt = escape(s.page_email_prompt),
                ret = hidden("return_to", &return_to),
                label = escape(s.page_email_label),
                send = escape(s.page_email_send),
            )
        } else {
            format!(
                r#"<h1>{}</h1><p class="muted">{}</p>"#,
                escape(s.page_device_title),
                escape(s.page_no_mail)
            )
        };
        return page(lang, s.page_device_title, &body, StatusCode::OK);
    };
    let csrf = csrf_token(&identity.config, &user.session_id);
    let signed_in = escape(&fill(s.page_signed_in, &[("email", &user.email)]));
    let label = match &code {
        Some(code) => {
            let label: Option<String> = sqlx::query_scalar(
                "SELECT label FROM device_codes WHERE user_code = ? AND status = 'pending' AND expires_at > ?",
            )
            .bind(code)
            .bind(now_s())
            .fetch_optional(&identity.db)
            .await
            .ok()
            .flatten();
            match label {
                Some(label) => label,
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
// Sitzungen

async fn revoke(db: &Db, user_id: &str, session_id: &str) -> Result<bool, sqlx::Error> {
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

/// Sprache für Mails an eine Person: ihre gespeicherte, sonst die Vorgabe.
pub fn mail_lang(stored: Option<&str>, config: &Config) -> &'static str {
    pick(stored, None, &config.default_lang)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benutzercode() {
        let code = user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(
            normalize_user_code(&code.to_lowercase().replace('-', " ")),
            Some(code)
        );
        assert_eq!(
            normalize_user_code("ABCD-EFGH"),
            None,
            "Vokale gehören nicht zum Alphabet"
        );
        assert_eq!(normalize_user_code("BCDF"), None);
    }

    #[test]
    fn gerätecode_im_rücksprung_nur_im_anfragenden_browser() {
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
    fn rücksprung_nur_auf_erlaubte_pfade() {
        assert_eq!(
            safe_return(Some("/device?code=BCDF-GHJK")),
            "/device?code=BCDF-GHJK"
        );
        assert_eq!(safe_return(Some("https://evil.example")), "/device");
        assert_eq!(safe_return(Some("//evil.example")), "/device");
        assert_eq!(safe_return(Some("/device?code=x&next=//evil")), "/device");
    }
}
