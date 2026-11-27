//! Plain browser pages (approve device, magic link, invitation) without JavaScript. All
//! inserted values are escaped; the stylesheet comes from our own origin (CSP
//! `style-src 'self'`). Light and dark follow `prefers-color-scheme`.

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use crate::config::Config;
use crate::mail::i18n::{fill, pick, strings, Strings};
use crate::mail::templates::escape;
use crate::util::{ct_eq, hmac_hex};

const CSS: &str = r#":root{--canvas:#eef1f5;--panel:#fff;--border:#dde3ea;--text:#0e1116;--muted:#59636e;--primary:#0969da;--primary-hover:#0860ca;--on-primary:#fff;--error:#cf222e;--ok:#1a7f37;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--canvas:#0a0d11;--panel:#0e1116;--border:#262e39;--text:#e6edf3;--muted:#8592a3;--primary:#5aa9ff;--primary-hover:#7dbbff;--on-primary:#06121f;--error:#f47067;--ok:#57ab5a}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--canvas);color:var(--text);font:16px/1.5 'Inter Variable','Segoe UI Variable','Segoe UI',system-ui,-apple-system,sans-serif;display:flex;align-items:flex-start;justify-content:center;padding:48px 16px}
main{width:100%;max-width:480px}.brand{display:flex;gap:10px;align-items:center;font-weight:700;font-size:18px;margin:0 0 16px}.mark{width:28px;height:28px;flex:none;display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px}h1{font-size:20px;margin:0 0 12px}p{margin:0 0 16px}.muted{color:var(--muted);font-size:14px}.error{color:var(--error)}.ok{color:var(--ok)}
.code{font:600 28px/1.2 'Cascadia Mono',ui-monospace,Consolas,monospace;letter-spacing:.08em;margin:0 0 20px}label{display:block;font-size:14px;margin:0 0 6px}
input{width:100%;min-height:44px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:var(--canvas);color:var(--text);font:inherit;margin:0 0 16px}
.row{display:flex;gap:12px;flex-wrap:wrap}button{min-height:44px;padding:10px 20px;border-radius:10px;border:1px solid var(--primary);background:var(--primary);color:var(--on-primary);font-family:inherit;font-size:16px;font-weight:600;line-height:1;cursor:pointer}
button.secondary{background:transparent;color:var(--text);border-color:var(--border)}button:hover{background:var(--primary-hover)}button.secondary:hover{background:var(--canvas)}
button:focus-visible,input:focus-visible{outline:3px solid var(--primary);outline-offset:2px}
.devices{list-style:none;padding:0;margin:0 0 16px}.devices li{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;border-top:1px solid var(--border);padding:12px 0}.devices li:first-child{border-top:0}.devices p{margin:0;overflow-wrap:anywhere}.devices form{margin:0}
.running{display:flex;gap:10px;align-items:center}.running::before{content:"";width:10px;height:10px;flex:none;border-radius:50%;background:var(--ok);box-shadow:0 0 0 4px color-mix(in srgb,var(--ok) 22%,transparent)}
.label{font-size:14px;font-weight:600;margin:24px 0 6px}.address{font:600 15px/1.4 'Cascadia Mono',ui-monospace,Consolas,monospace;background:var(--canvas);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin:0 0 12px;overflow-wrap:anywhere;user-select:all}
.version{margin:20px 0 0}"#;

/// The Hangar Server logo (`docs/images/logo.svg`) inline: CSP allows no external images
/// beyond our own origin, and inline SVG needs no request.
const LOGO: &str = r##"<svg class="mark" viewBox="0 0 256 256" width="28" height="28" aria-hidden="true" focusable="false"><rect width="256" height="256" rx="56" fill="#141a24"/><path d="M216 58H80L40 98V124L176 160H40V200H176L216 160V134L80 98H216Z" fill="#b59aff" fill-rule="evenodd"/><path d="M168 102H200V118H168Z" fill="#f2e3c6"/></svg>"##;

pub async fn stylesheet() -> Response {
    let mut response = (StatusCode::OK, CSS).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    response
}

/// Page language from `Accept-Language`.
pub fn lang(headers: &HeaderMap, config: &Config) -> &'static str {
    pick(
        None,
        headers.get("accept-language").and_then(|v| v.to_str().ok()),
        &config.default_lang,
    )
}

pub fn t(headers: &HeaderMap, config: &Config) -> (&'static str, &'static Strings) {
    let lang = lang(headers, config);
    (lang, strings(lang))
}

/// A complete page. `body` is finished, already escaped HTML.
pub fn page(lang: &str, title: &str, body: &str, status: StatusCode) -> Response {
    let dir = if strings(lang).rtl { "rtl" } else { "ltr" };
    let html = format!(
        r#"<!DOCTYPE html><html lang="{lang}" dir="{dir}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light dark"><meta name="robots" content="noindex"><title>{title} · Hangar</title><link rel="stylesheet" href="/assets/style.css"></head><body><main><div class="brand">{logo}<span>Hangar Server</span></div><section class="card">{body}</section></main></body></html>"#,
        lang = escape(lang),
        title = escape(title),
        logo = LOGO,
    );
    (status, Html(html)).into_response()
}

/// The start page `/`: the server runs, and in self-hosting the address the app needs. Shows
/// nothing about the server's state beyond what `/health` already tells everyone.
pub fn home(headers: &HeaderMap, config: &Config) -> Response {
    let (lang, s) = t(headers, config);
    let mut body = format!(
        r#"<h1 class="running">{}</h1><p>{}</p>"#,
        escape(s.page_home_title),
        escape(s.page_home_intro)
    );
    if config.identity == crate::config::IdentityMode::Local {
        body.push_str(&format!(
            r#"<p class="label">{}</p><p class="address" dir="ltr">{}/api/v1</p><p class="muted">{}</p>"#,
            escape(s.page_home_address),
            escape(&config.public_url),
            escape(s.page_home_steps)
        ));
    }
    body.push_str(&format!(
        r#"<p class="muted version">{}</p>"#,
        escape(&fill(
            s.page_home_version,
            &[("version", env!("CARGO_PKG_VERSION"))]
        ))
    ));
    page(lang, s.page_home_title, &body, StatusCode::OK)
}

/// Page with a single message.
pub fn message(lang: &str, title: &str, text: &str, class: &str, status: StatusCode) -> Response {
    page(
        lang,
        title,
        &format!(
            r#"<h1>{}</h1><p class="{class}">{}</p>"#,
            escape(title),
            escape(text)
        ),
        status,
    )
}

/// Writing browser requests only from our own origin: `Origin` must match, alternatively
/// `Sec-Fetch-Site: same-origin`. Without either the request is refused (protection against login CSRF).
pub fn same_origin(headers: &HeaderMap, config: &Config) -> bool {
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        return config.origin_allowed(origin)
            && origin
                .trim_end_matches('/')
                .eq_ignore_ascii_case(&config.public_url);
    }
    headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("same-origin")
}

pub fn cookie_name(config: &Config) -> &'static str {
    if config.is_https() {
        "__Host-hangar_team"
    } else {
        "hangar_team"
    }
}

pub fn session_cookie(config: &Config, token: &str, max_age_s: i64) -> HeaderValue {
    cookie(config, cookie_name(config), token, max_age_s)
}

/// Cookie of the browser that requested a magic link (binds the return with the
/// device code to this browser).
pub fn login_cookie_name(config: &Config) -> &'static str {
    if config.is_https() {
        "__Host-hangar_login"
    } else {
        "hangar_login"
    }
}

pub fn cookie(config: &Config, name: &str, value: &str, max_age_s: i64) -> HeaderValue {
    let secure = if config.is_https() { "; Secure" } else { "" };
    let value =
        format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_s}{secure}");
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

pub fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// CSRF token of a browser session (synchronizer token, derived from the session).
pub fn csrf_token(config: &Config, session_id: &str) -> String {
    hmac_hex(&config.server_secret, &[b"csrf", session_id.as_bytes()])
}

pub fn csrf_ok(config: &Config, session_id: &str, sent: Option<&str>) -> bool {
    sent.is_some_and(|s| ct_eq(s.as_bytes(), csrf_token(config, session_id).as_bytes()))
}

pub fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{}" value="{}">"#,
        escape(name),
        escape(value)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IdentityMode;
    use crate::signed::KeySet;

    #[test]
    fn origin_check() {
        let config = Config::for_tests(IdentityMode::Local, KeySet::default());
        let mut h = HeaderMap::new();
        assert!(!same_origin(&h, &config));
        h.insert("origin", HeaderValue::from_static("http://localhost:8080"));
        assert!(same_origin(&h, &config));
        h.insert("origin", HeaderValue::from_static("https://evil.example"));
        assert!(!same_origin(&h, &config));
        let mut f = HeaderMap::new();
        f.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        assert!(same_origin(&f, &config));
    }

    #[test]
    fn cookies() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            HeaderValue::from_static("a=1; hangar_team=xyz; b=2"),
        );
        assert_eq!(read_cookie(&h, "hangar_team"), Some("xyz"));
        assert_eq!(read_cookie(&h, "c"), None);
    }
}
