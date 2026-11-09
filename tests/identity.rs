//! Selbstbetrieb: Magic Link, Device Flow mit Token-Rotation, Teams, Einladungen mit
//! Platzgrenze (auch nebenläufig), Lizenzprüfung, Tickets bis zur Live-Verbindung.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use ed25519_dalek::SigningKey;
use hangar_team_server::config::{Config, IdentityMode};
use hangar_team_server::license::LicenseClaims;
use hangar_team_server::signed::{self, KeySet, LICENSE_CONTEXT};
use hangar_team_server::util::{b64, now_s};
use hangar_team_server::wire::{
    ClientMessage, Epoch, ErrorCode, KeyRotate, ServerMessage, WrappedKey,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";

fn license_key() -> SigningKey {
    SigningKey::from_bytes(&[77; 32])
}

fn local_config() -> Config {
    let mut config = Config::for_tests(IdentityMode::Local, KeySet::default());
    config.license_keys = KeySet::parse(&format!(
        "web-1:{}",
        b64(license_key().verifying_key().as_bytes())
    ))
    .unwrap();
    config
}

struct Resp {
    status: StatusCode,
    cookie: Option<String>,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<(&str, String)>,
) -> Resp {
    let mut builder = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        Some((kind, text)) => builder
            .header("content-type", kind)
            .body(Body::from(text))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::to_owned);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        cookie,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn form(pairs: &[(&str, &str)]) -> (&'static str, String) {
    let encoded: Vec<String> = pairs
        .iter()
        .map(|(k, v)| {
            let enc: String = v
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            format!("{k}={enc}")
        })
        .collect();
    ("application/x-www-form-urlencoded", encoded.join("&"))
}

fn json_body(value: Value) -> Option<(&'static str, String)> {
    Some(("application/json", value.to_string()))
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).expect(start) + start.len();
    let rest = &text[from..];
    &rest[..rest.find(end).unwrap()]
}

/// Ganzer Anmeldeweg: Admin-Link, Browsersitzung, Device Flow. Gibt das Zugriffstoken zurück
/// und dazu das Erneuerungstoken.
async fn login(s: &TestServer, email: &str) -> (String, String) {
    let app = &s.server.router;
    let config = &s.server.state.config;
    let device = call(
        app,
        "POST",
        "/oauth/device_authorization",
        &[],
        Some(form(&[("client_id", "hangar"), ("device_name", "Test")])),
    )
    .await
    .json();
    let device_code = device["device_code"].as_str().unwrap().to_owned();
    let user_code = device["user_code"].as_str().unwrap().to_owned();
    let pending = call(
        app,
        "POST",
        "/oauth/token",
        &[],
        Some(form(&[
            ("client_id", "hangar"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
        ])),
    )
    .await;
    assert_eq!(pending.json()["error"], "authorization_pending");

    let link = hangar_team_server::identity::auth::admin_login_link(
        &s.server.state.relay.db,
        config,
        email,
    )
    .await
    .unwrap();
    let path = link.trim_start_matches(ORIGIN);
    assert_eq!(
        call(app, "GET", path, &[], None).await.status,
        StatusCode::OK
    );
    // Ohne Origin: kein Login (Schutz vor Login-CSRF), der Link bleibt gültig.
    assert_eq!(
        call(app, "POST", path, &[], None).await.status,
        StatusCode::FORBIDDEN
    );
    let signed_in = call(app, "POST", path, &[("origin", ORIGIN)], None).await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    let cookie = signed_in.cookie.expect("Sitzungscookie");
    // Ein zweites Mal geht der Link nicht.
    assert_eq!(
        call(app, "POST", path, &[("origin", ORIGIN)], None)
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let page = call(
        app,
        "GET",
        &format!("/device?code={user_code}"),
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert!(page.body.contains("Test"), "Gerätename steht auf der Seite");
    let unknown = call(
        app,
        "GET",
        "/device?code=BCDF-BCDF",
        &[("cookie", &cookie)],
        None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert!(
        !unknown.body.contains("csrf"),
        "kein Zulassen für fremde Codes"
    );
    let csrf = between(&page.body, r#"name="csrf" value=""#, "\"").to_owned();
    let wrong = call(
        app,
        "POST",
        "/device",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        Some(form(&[
            ("csrf", "falsch"),
            ("user_code", &user_code),
            ("decision", "approve"),
        ])),
    )
    .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN);
    let approved = call(
        app,
        "POST",
        "/device",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        Some(form(&[
            ("csrf", &csrf),
            ("user_code", &user_code),
            ("decision", "approve"),
        ])),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);

    let tokens = call(
        app,
        "POST",
        "/oauth/token",
        &[],
        Some(form(&[
            ("client_id", "hangar"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
        ])),
    )
    .await
    .json();
    let access = tokens["access_token"]
        .as_str()
        .expect("Zugriffstoken")
        .to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    // Der Gerätecode gilt nur einmal.
    let again = call(
        app,
        "POST",
        "/oauth/token",
        &[],
        Some(form(&[
            ("client_id", "hangar"),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("device_code", &device_code),
        ])),
    )
    .await;
    assert_eq!(again.json()["error"], "invalid_grant");
    (access, refresh)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn anmeldung_rotation_und_widerruf() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (access, refresh) = login(&s, "owner@example.org").await;
    let me = call(
        app,
        "GET",
        "/v1/me",
        &[("authorization", &bearer(&access))],
        None,
    )
    .await;
    assert_eq!(me.json()["email"], "owner@example.org");

    // Zu schnelles Abfragen: slow_down.
    let device = call(
        app,
        "POST",
        "/oauth/device_authorization",
        &[],
        Some(form(&[("client_id", "hangar")])),
    )
    .await
    .json();
    let code = device["device_code"].as_str().unwrap();
    let grant = [
        ("client_id", "hangar"),
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", code),
    ];
    call(app, "POST", "/oauth/token", &[], Some(form(&grant))).await;
    assert_eq!(
        call(app, "POST", "/oauth/token", &[], Some(form(&grant)))
            .await
            .json()["error"],
        "slow_down"
    );
    assert_eq!(
        call(
            app,
            "POST",
            "/oauth/device_authorization",
            &[],
            Some(form(&[("client_id", "fremd")]))
        )
        .await
        .json()["error"],
        "invalid_client"
    );

    // Rotation: neues Paar, altes Zugriffstoken endet.
    let rotated = call(
        app,
        "POST",
        "/oauth/token",
        &[],
        Some(form(&[
            ("client_id", "hangar"),
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
        ])),
    )
    .await
    .json();
    let access2 = rotated["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            app,
            "GET",
            "/v1/me",
            &[("authorization", &bearer(&access))],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            app,
            "GET",
            "/v1/me",
            &[("authorization", &bearer(&access2))],
            None
        )
        .await
        .status,
        StatusCode::OK
    );
    // Wiederverwendung des alten Erneuerungstokens: die ganze Sitzung endet.
    let reuse = call(
        app,
        "POST",
        "/oauth/token",
        &[],
        Some(form(&[
            ("client_id", "hangar"),
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
        ])),
    )
    .await;
    assert_eq!(reuse.json()["error"], "invalid_grant");
    assert_eq!(
        call(
            app,
            "GET",
            "/v1/me",
            &[("authorization", &bearer(&access2))],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );

    // Sitzungen auflisten und widerrufen.
    let (access3, _) = login(&s, "owner@example.org").await;
    let list = call(
        app,
        "GET",
        "/v1/sessions",
        &[("authorization", &bearer(&access3))],
        None,
    )
    .await
    .json();
    let current = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["current"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(
            app,
            "DELETE",
            &format!("/v1/sessions/{current}"),
            &[("authorization", &bearer(&access3))],
            None
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            app,
            "GET",
            "/v1/me",
            &[("authorization", &bearer(&access3))],
            None
        )
        .await
        .status,
        StatusCode::UNAUTHORIZED
    );
}

async fn create_team(app: &Router, token: &str, name: &str) -> String {
    let r = call(
        app,
        "POST",
        "/v1/teams",
        &[("authorization", &bearer(token))],
        json_body(json!({ "name": name })),
    )
    .await;
    assert_eq!(r.status, StatusCode::CREATED, "{}", r.body);
    r.json()["id"].as_str().unwrap().to_owned()
}

async fn invite_links(
    app: &Router,
    token: &str,
    team: &str,
    emails: &[&str],
    role: &str,
) -> Vec<String> {
    let r = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[("authorization", &bearer(token))],
        json_body(json!({ "emails": emails, "role": role })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.json()["invitations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            i["link"]
                .as_str()
                .expect("Link für den Admin")
                .trim_start_matches(ORIGIN)
                .trim_start_matches("/invite/")
                .to_owned()
        })
        .collect()
}

async fn accept(app: &Router, token: &str, invitation: &str) -> Resp {
    call(
        app,
        "POST",
        "/v1/invitations/accept",
        &[("authorization", &bearer(token))],
        json_body(json!({ "token": invitation })),
    )
    .await
}

fn license(seats: u32, email: &str, exp: i64, key: &SigningKey) -> String {
    let claims = LicenseClaims {
        v: 1,
        kid: "web-1".into(),
        lid: format!("lic_{seats}_{exp}"),
        sub: "42".into(),
        email: email.into(),
        plan: "team".into(),
        seats,
        features: vec![],
        iat: now_s() - 10,
        exp,
    };
    signed::sign(&serde_json::to_vec(&claims).unwrap(), LICENSE_CONTEXT, key)
}

#[tokio::test]
async fn einladungen_plätze_und_lizenz() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Kern").await;
    let links = invite_links(
        app,
        &owner,
        &team,
        &[
            "a@example.org",
            "b@example.org",
            "c@example.org",
            "d@example.org",
        ],
        "member",
    )
    .await;
    let (a, _) = login(&s, "a@example.org").await;
    let (b, _) = login(&s, "b@example.org").await;
    let (c, _) = login(&s, "c@example.org").await;

    // Falsches Konto: d's Einladung gilt nicht für a.
    assert_eq!(
        accept(app, &a, &links[3]).await.json()["error"],
        "wrong_account"
    );
    assert_eq!(accept(app, &a, &links[0]).await.status, StatusCode::OK);
    assert_eq!(accept(app, &b, &links[1]).await.status, StatusCode::OK);
    // Eigentümer + 2 = Free voll.
    let full = accept(app, &c, &links[2]).await;
    assert_eq!(full.status, StatusCode::CONFLICT);
    assert_eq!(full.json()["error"], "seats_full");
    // Einladung gilt nur einmal.
    assert_eq!(
        accept(app, &a, &links[0]).await.status,
        StatusCode::NOT_FOUND
    );

    // Rollen: ein Mitglied darf nicht einladen.
    let member_invite = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[("authorization", &bearer(&a))],
        json_body(json!({ "emails": ["x@example.org"], "role": "member" })),
    )
    .await;
    assert_eq!(member_invite.status, StatusCode::FORBIDDEN);

    // Lizenz: fremde Signatur, abgelaufen, andere Adresse, dann gültig mit 5 Plätzen.
    let put = |doc: String| json_body(json!({ "document": doc }));
    let foreign = call(
        app,
        "PUT",
        "/v1/license",
        &[("authorization", &bearer(&owner))],
        put(license(
            5,
            "owner@example.org",
            now_s() + 86_400,
            &SigningKey::from_bytes(&[1; 32]),
        )),
    )
    .await;
    assert_eq!(foreign.json()["error"], "invalid_license");
    let expired = call(
        app,
        "PUT",
        "/v1/license",
        &[("authorization", &bearer(&owner))],
        put(license(5, "owner@example.org", now_s() - 1, &license_key())),
    )
    .await;
    assert_eq!(expired.json()["error"], "license_expired");
    let other = call(
        app,
        "PUT",
        "/v1/license",
        &[("authorization", &bearer(&owner))],
        put(license(
            5,
            "x@example.org",
            now_s() + 86_400,
            &license_key(),
        )),
    )
    .await;
    assert_eq!(other.json()["error"], "license_email_mismatch");
    let ok = call(
        app,
        "PUT",
        "/v1/license",
        &[("authorization", &bearer(&owner))],
        put(license(
            5,
            "owner@example.org",
            now_s() + 86_400,
            &license_key(),
        )),
    )
    .await;
    assert_eq!(ok.json()["effectiveSeats"], 5, "{}", ok.body);

    // Jetzt ist Platz: c tritt bei. Eine erneute Einladung erneuert den Link.
    let fresh = invite_links(app, &owner, &team, &["c@example.org"], "member").await;
    assert_eq!(accept(app, &c, &fresh[0]).await.status, StatusCode::OK);
    let detail = call(
        app,
        "GET",
        &format!("/v1/teams/{team}"),
        &[("authorization", &bearer(&owner))],
        None,
    )
    .await
    .json();
    assert_eq!(detail["seats"]["used"], 4);
    assert_eq!(detail["seats"]["limit"], 5);
    assert_eq!(detail["seats"]["plan"], "team");

    // Fremde Teams sind nicht sichtbar.
    let (stranger, _) = login(&s, "x@example.org").await;
    assert_eq!(
        call(
            app,
            "GET",
            &format!("/v1/teams/{team}"),
            &[("authorization", &bearer(&stranger))],
            None
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn letzter_platz_geht_genau_einmal_weg() {
    let s = start(local_config()).await;
    let app = s.server.router.clone();
    let (owner, _) = login(&s, "boss@example.org").await;
    let team = create_team(&app, &owner, "Rennen").await;
    let emails: Vec<String> = (0..6).map(|i| format!("p{i}@example.org")).collect();
    let refs: Vec<&str> = emails.iter().map(String::as_str).collect();
    let links = invite_links(&app, &owner, &team, &refs, "member").await;
    let mut tokens = Vec::new();
    for email in &emails {
        tokens.push(login(&s, email).await.0);
    }
    let mut tasks = Vec::new();
    for (token, link) in tokens.into_iter().zip(links) {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            accept(&app, &token, &link).await.status
        }));
    }
    let mut joined = 0;
    let mut full = 0;
    for task in tasks {
        match task.await.unwrap() {
            StatusCode::OK => joined += 1,
            StatusCode::CONFLICT => full += 1,
            other => panic!("{other}"),
        }
    }
    assert_eq!(
        (joined, full),
        (2, 4),
        "Free: Eigentümer und genau zwei weitere"
    );
}

#[tokio::test]
async fn einladung_im_browser_und_ticket_bis_zur_live_verbindung() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Live <b>").await;
    let link = invite_links(app, &owner, &team, &["neu@example.org"], "member")
        .await
        .remove(0);
    let page = call(app, "GET", &format!("/invite/{link}"), &[], None).await;
    assert!(page.body.contains("Live &lt;b&gt;"), "Teamname maskiert");
    assert!(page.body.contains("neu@example.org"));
    // Ohne Origin nichts; mit Origin: Link belegt das Postfach, Konto entsteht, Beitritt.
    assert_eq!(
        call(
            app,
            "POST",
            &format!("/invite/{link}"),
            &[],
            Some(form(&[]))
        )
        .await
        .status,
        StatusCode::FORBIDDEN
    );
    let joined = call(
        app,
        "POST",
        &format!("/invite/{link}"),
        &[("origin", ORIGIN)],
        Some(form(&[])),
    )
    .await;
    assert_eq!(joined.status, StatusCode::OK, "{}", joined.body);
    assert!(joined.cookie.is_some());

    // Ticket des Selbstbetriebs öffnet die Live-Verbindung (gleicher Relay-Weg wie offiziell).
    let ticket = call(
        app,
        "POST",
        "/v1/tickets",
        &[("authorization", &bearer(&owner))],
        json_body(json!({ "team": team })),
    )
    .await
    .json();
    let ticket = ticket["ticket"].as_str().unwrap().to_owned();
    let mut ws = Client::connect(s.addr).await;
    let welcome = ws.hello(&team, ticket.clone(), "owner-laptop", None).await;
    assert!(
        matches!(welcome.message, ServerMessage::Welcome(_)),
        "{welcome:?}"
    );
    // Dasselbe Ticket ein zweites Mal: abgelehnt.
    let mut ws2 = Client::connect(s.addr).await;
    assert!(matches!(
        ws2.hello(&team, ticket, "owner-laptop", None).await.message,
        ServerMessage::Err(_)
    ));
    // Kein Ticket für fremde Teams.
    let (stranger, _) = login(&s, "fremd@example.org").await;
    assert_eq!(
        call(
            app,
            "POST",
            "/v1/tickets",
            &[("authorization", &bearer(&stranger))],
            json_body(json!({ "team": team }))
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn anmeldelink_ohne_mail_nicht_anforderbar_und_ohne_auskunft() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let r = call(
        app,
        "POST",
        "/auth/email",
        &[("origin", ORIGIN)],
        Some(form(&[("email", "jemand@example.org")])),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("sends no mail") || r.body.contains("keine Mails"));
    let cross = call(
        app,
        "POST",
        "/auth/email",
        &[("origin", "https://evil.example")],
        Some(form(&[("email", "jemand@example.org")])),
    )
    .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn einladungsmail_über_log_transport() {
    let mut config = local_config();
    config.mail_transport = hangar_team_server::config::MailTransport::Log;
    let dir = config.data_dir.join("mail");
    let s = start(config).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Post").await;
    let r = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[
            ("authorization", &bearer(&owner)),
            ("accept-language", "de-DE"),
        ],
        json_body(json!({ "emails": ["gast@example.org"], "role": "member" })),
    )
    .await;
    assert!(
        r.json()["invitations"][0].get("link").is_none(),
        "mit Mailversand kein Link an den Admin"
    );
    let mut mail = None;
    for _ in 0..50 {
        if let Some(entry) = std::fs::read_dir(&dir).ok().and_then(|mut d| d.next()) {
            mail = Some(std::fs::read_to_string(entry.unwrap().path()).unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mail = mail.expect("Mail geschrieben");
    assert!(mail.contains("multipart/alternative"));
    assert!(mail.contains("text/plain") && mail.contains("text/html"));
    assert!(mail.contains("To: gast@example.org"));
}

/// Wartet auf die nächste neue Mail im Log-Ordner und gibt ihren Text zurück (Quoted-Printable
/// mit weichen Umbrüchen zusammengefügt).
async fn next_mail(dir: &std::path::Path, seen: usize) -> String {
    for _ in 0..100 {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .map(|d| d.filter_map(Result::ok).map(|e| e.path()).collect())
            .unwrap_or_default();
        entries.sort();
        if entries.len() > seen {
            let text = std::fs::read_to_string(&entries[entries.len() - 1]).unwrap();
            return text.replace("=\r\n", "").replace("=3D", "=");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("keine Mail geschrieben");
}

#[tokio::test]
async fn gerätecode_im_anmeldelink_gilt_nur_im_anfragenden_browser() {
    let mut config = local_config();
    config.mail_transport = hangar_team_server::config::MailTransport::Log;
    let dir = config.data_dir.join("mail");
    let s = start(config).await;
    let app = &s.server.router;
    login(&s, "opfer@example.org").await;
    let request = |cookie_jar: bool| {
        let app = app.clone();
        async move {
            let r = call(
                &app,
                "POST",
                "/auth/email",
                &[("origin", ORIGIN), ("accept-language", "en")],
                Some(form(&[
                    ("email", "opfer@example.org"),
                    ("return_to", "/device?code=BCDF-GHJK"),
                ])),
            )
            .await;
            assert_eq!(r.status, StatusCode::OK);
            let cookie = r.cookie.expect("Browser-Cookie gesetzt");
            assert!(cookie.starts_with("hangar_login="));
            cookie_jar.then_some(cookie)
        }
    };
    let token_of = |mail: &str| {
        let from = mail.find("/auth/magic/").expect("Link in der Mail") + "/auth/magic/".len();
        mail[from..from + 43].to_owned()
    };

    // Ein anderer Browser (oder eine Person, die eine fremd angeforderte Mail öffnet): der
    // Code fällt weg, die Person landet auf /device und müsste ihn selbst eingeben.
    request(false).await;
    let token = token_of(&next_mail(&dir, 0).await);
    let post = |token: String, cookie: Option<String>| {
        let app = app.clone();
        async move {
            let mut builder = Request::builder()
                .method("POST")
                .uri(format!("/auth/magic/{token}"))
                .header("origin", ORIGIN);
            if let Some(cookie) = cookie {
                builder = builder.header("cookie", cookie);
            }
            app.oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap()
        }
    };
    let foreign = post(token.clone(), None).await;
    assert_eq!(foreign.status(), StatusCode::SEE_OTHER);
    assert_eq!(foreign.headers()["location"].to_str().unwrap(), "/device");
    // Einmalig.
    assert_eq!(post(token, None).await.status(), StatusCode::NOT_FOUND);

    // Derselbe Browser: der Rücksprung behält den Code.
    let cookie = request(true).await.unwrap();
    let token = token_of(&next_mail(&dir, 1).await);
    let same = post(token, Some(cookie)).await;
    assert_eq!(same.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        same.headers()["location"].to_str().unwrap(),
        "/device?code=BCDF-GHJK"
    );

    // Fremder Browser mit frischem Link: nur /device.
    request(false).await;
    let token = token_of(&next_mail(&dir, 2).await);
    let other = post(token, Some("hangar_login=fremd".into())).await;
    assert_eq!(other.headers()["location"].to_str().unwrap(), "/device");
}

async fn ticket_for(app: &Router, token: &str, team: &str) -> String {
    let r = call(
        app,
        "POST",
        "/v1/tickets",
        &[("authorization", &bearer(token))],
        json_body(json!({ "team": team })),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    r.json()["ticket"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn rollenwechsel_und_entfernen_wirken_sofort_im_relay() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Sofort").await;
    let links = invite_links(app, &owner, &team, &["admin@example.org"], "admin").await;
    let (admin, _) = login(&s, "admin@example.org").await;
    assert_eq!(accept(app, &admin, &links[0]).await.status, StatusCode::OK);
    let links = invite_links(app, &owner, &team, &["neu@example.org"], "member").await;
    let (member, _) = login(&s, "neu@example.org").await;
    assert_eq!(accept(app, &member, &links[0]).await.status, StatusCode::OK);
    let id_of = |token: String| {
        let app = app.clone();
        async move {
            call(
                &app,
                "GET",
                "/v1/me",
                &[("authorization", &bearer(&token))],
                None,
            )
            .await
            .json()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    let admin_id = id_of(admin.clone()).await;
    let member_id = id_of(member.clone()).await;

    // Herabstufung: still auf der offenen Verbindung angewendet, keine Trennung; die nächste
    // Admin-Absicht (key.rotate) wird abgelehnt.
    let mut ws = Client::connect(s.addr).await;
    let welcome = ws
        .hello(
            &team,
            ticket_for(app, &admin, &team).await,
            "admin-pc",
            None,
        )
        .await;
    assert!(matches!(welcome.message, ServerMessage::Welcome(_)));
    let r = call(
        app,
        "PATCH",
        &format!("/v1/teams/{team}/members/{admin_id}"),
        &[("authorization", &bearer(&owner))],
        json_body(json!({ "role": "member" })),
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    ws.until(|f| matches!(f.message, ServerMessage::MemberRoleChanged(_)))
        .await;
    let rotate = ClientMessage::KeyRotate(KeyRotate {
        log: dummy_log(),
        epoch: Epoch(1),
        wrapped: vec![WrappedKey {
            holder: holder(&admin_id, "admin-pc"),
            data: cipher("YQ"),
        }],
    });
    let refused = ws.request(&team, rotate).await;
    assert!(
        matches!(&refused.message, ServerMessage::Err(e) if e.code == ErrorCode::Forbidden),
        "{refused:?}"
    );
    ws.send_raw(&format!(
        r#"{{"v":1,"id":"noch-da","team":"{team}","type":"ping"}}"#
    ))
    .await;
    assert!(matches!(
        ws.answer("noch-da").await.message,
        ServerMessage::Ack(_)
    ));

    // Entfernen, bevor das Mitglied je verbunden war: ein vorher ausgestelltes Ticket hilft
    // nicht mehr.
    let early = ticket_for(app, &member, &team).await;
    let r = call(
        app,
        "DELETE",
        &format!("/v1/teams/{team}/members/{member_id}"),
        &[("authorization", &bearer(&owner))],
        None,
    )
    .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let mut late = Client::connect(s.addr).await;
    assert!(matches!(
        late.hello(&team, early, "neu-pc", None).await.message,
        ServerMessage::Err(_)
    ));
}

#[tokio::test]
async fn einladungen_zählen_je_adresse_für_die_ratenbegrenzung() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Viele").await;
    let batch = |n: usize| {
        (0..20)
            .map(|i| format!("gast{n}-{i}@example.org"))
            .collect::<Vec<_>>()
    };
    let send = |emails: Vec<String>| {
        let (app, owner, team) = (app.clone(), owner.clone(), team.clone());
        async move {
            call(
                &app,
                "POST",
                &format!("/v1/teams/{team}/invitations"),
                &[("authorization", &bearer(&owner))],
                json_body(json!({ "emails": emails, "role": "member" })),
            )
            .await
            .status
        }
    };
    assert_eq!(send(batch(1)).await, StatusCode::OK);
    assert_eq!(send(batch(2)).await, StatusCode::OK);
    // 40 Adressen verbraucht; 20 weitere überschreiten die 50 je Stunde.
    assert_eq!(send(batch(3)).await, StatusCode::TOO_MANY_REQUESTS);
}
