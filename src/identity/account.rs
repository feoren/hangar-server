//! Browserseite `/account/devices` (die App verlinkt sie unter `<Ursprung>/account/devices`):
//! verbundene Geräte des angemeldeten Kontos ansehen und trennen. Trennen beendet die ganze
//! Gerätesitzung sofort (alle Tokens); die App dort muss sich neu anmelden. Laufende
//! Live-Verbindungen enden spätestens mit dem nächsten Ticket (höchstens 60 s gültig).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use super::auth::{self, browser_user, identity, sign_in_page, DEVICES_PAGE};
use super::pages::{csrf_ok, csrf_token, hidden, message, page, same_origin, t};
use super::ApiError;
use crate::http::AppState;
use crate::mail::i18n::fill;
use crate::mail::templates::escape;
use crate::util::{is_id, now_s};

/// `JJJJ-MM-TT hh:mm UTC` aus Unix-Sekunden (proleptischer Gregorianischer Kalender, ohne
/// Zeitzonen-Datenbank; Algorithmus "civil_from_days" von Howard Hinnant).
pub fn utc_minute(unix_s: i64) -> String {
    let days = unix_s.div_euclid(86_400);
    let secs = unix_s.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

#[derive(Debug, Deserialize)]
pub struct DevicesQuery {
    revoked: Option<String>,
}

/// id, label, platform, created_at, last_used_at
type DeviceRow = (String, String, Option<String>, i64, i64);

pub async fn devices_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DevicesQuery>,
) -> Response {
    let Ok(identity) = identity(&state) else {
        return ApiError::NOT_FOUND.into_response();
    };
    let (lang, s) = t(&headers, &identity.config);
    let Ok(Some(user)) = browser_user(identity, &headers).await else {
        return sign_in_page(identity, lang, s.page_devices_title, DEVICES_PAGE);
    };
    let rows: Result<Vec<DeviceRow>, sqlx::Error> = sqlx::query_as(
        "SELECT id, label, platform, created_at, last_used_at FROM auth_sessions \
         WHERE user_id = ? AND kind = 'app' AND revoked_at IS NULL AND expires_at > ? \
         ORDER BY last_used_at DESC LIMIT 100",
    )
    .bind(&user.id)
    .bind(now_s())
    .fetch_all(&identity.db)
    .await;
    let rows = match rows {
        Ok(rows) => rows,
        Err(error) => return ApiError::from(error).into_response(),
    };
    let csrf = hidden("csrf", &csrf_token(&identity.config, &user.session_id));
    let mut body = format!("<h1>{}</h1>", escape(s.page_devices_title));
    if query.revoked.is_some() {
        body.push_str(&format!(
            r#"<p class="ok" role="status">{}</p>"#,
            escape(s.page_devices_revoked)
        ));
    }
    if rows.is_empty() {
        body.push_str(&format!(
            r#"<p class="muted">{}</p>"#,
            escape(s.page_devices_empty)
        ));
    } else {
        body.push_str(r#"<ul class="devices">"#);
        for (id, label, platform, created, used) in rows {
            let name = match platform {
                Some(platform) => format!("{label} ({platform})"),
                None => label,
            };
            let meta = fill(
                s.page_devices_meta,
                &[
                    ("created", &utc_minute(created)),
                    ("used", &utc_minute(used)),
                ],
            );
            body.push_str(&format!(
                r#"<li><div><p><strong>{name}</strong></p><p class="muted">{meta}</p></div><form method="post" action="{DEVICES_PAGE}">{csrf}{session}<button class="secondary" type="submit" aria-label="{button}: {name}">{button}</button></form></li>"#,
                name = escape(&name),
                meta = escape(&meta),
                session = hidden("session", &id),
                button = escape(s.page_devices_revoke),
            ));
        }
        body.push_str("</ul>");
    }
    body.push_str(&format!(
        r#"<p class="muted">{}</p>"#,
        escape(&fill(s.page_signed_in, &[("email", &user.email)]))
    ));
    page(lang, s.page_devices_title, &body, StatusCode::OK)
}

/// Eine eigene, noch offene App-Sitzung widerrufen; `false` für fremde, unbekannte,
/// schon widerrufene Sitzungen und Browsersitzungen.
async fn revoke_app_session(
    identity: &super::Identity,
    user_id: &str,
    session: &str,
) -> Result<bool, sqlx::Error> {
    let app: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM auth_sessions WHERE id = ? AND user_id = ? AND kind = 'app' AND revoked_at IS NULL",
    )
    .bind(session)
    .bind(user_id)
    .fetch_optional(&identity.db)
    .await?;
    match app {
        Some(_) => auth::revoke(&identity.db, user_id, session).await,
        None => Ok(false),
    }
}

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    csrf: Option<String>,
    /// Fehlt oder unbrauchbar: wie eine unbekannte Sitzung (404), keine Rohantwort von axum.
    session: Option<String>,
}

/// POST: ein eigenes Gerät trennen (nur Sitzungen der App, nie die Browsersitzung), danach
/// zurück zur Liste (Post/Redirect/Get).
pub async fn devices_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
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
            s.page_devices_title,
            s.page_link_invalid,
            "error",
            StatusCode::FORBIDDEN,
        );
    };
    let done = match form.session.as_deref().filter(|id| is_id(id, 64)) {
        Some(session) => revoke_app_session(identity, &user.id, session).await,
        None => Ok(false),
    };
    match done {
        Ok(true) => {
            tracing::info!("Gerät im Browser getrennt");
            Redirect::to(&format!("{DEVICES_PAGE}?revoked=1")).into_response()
        }
        Ok(false) => message(
            lang,
            s.page_devices_title,
            s.page_link_invalid,
            "error",
            StatusCode::NOT_FOUND,
        ),
        Err(error) => ApiError::from(error).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_zeit() {
        assert_eq!(utc_minute(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_minute(951_782_400), "2000-02-29 00:00 UTC");
        assert_eq!(utc_minute(1_794_225_600), "2026-11-09 12:00 UTC");
        assert_eq!(utc_minute(-60), "1969-12-31 23:59 UTC");
    }
}
