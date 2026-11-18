//! Self-hosting: magic link, device flow with token rotation, teams, invitations with seat
//! limit (also concurrent), license check, tickets through to the live connection.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use common::*;
use ed25519_dalek::SigningKey;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::license::LicenseClaims;
use hangar_server::signed::{self, KeySet, LICENSE_CONTEXT};
use hangar_server::util::{b64, now_s};
use hangar_server::wire::{ClientMessage, Epoch, ErrorCode, KeyRotate, ServerMessage, WrappedKey};
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

/// Full sign-in path: admin link, browser session, device flow. Returns the access token
/// together with the refresh token.
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

    let link =
        hangar_server::identity::auth::admin_login_link(&s.server.state.relay.db, config, email)
            .await
            .unwrap();
    let path = link.trim_start_matches(ORIGIN);
    assert_eq!(
        call(app, "GET", path, &[], None).await.status,
        StatusCode::OK
    );
    // Without Origin: no sign-in (login CSRF protection), the link stays valid.
    assert_eq!(
        call(app, "POST", path, &[], None).await.status,
        StatusCode::FORBIDDEN
    );
    let signed_in = call(app, "POST", path, &[("origin", ORIGIN)], None).await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    let cookie = signed_in.cookie.expect("session cookie");
    // The link does not work a second time.
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
    assert!(page.body.contains("Test"), "device name shown on the page");
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
        "no approval for unknown codes"
    );
    let csrf = between(&page.body, r#"name="csrf" value=""#, "\"").to_owned();
    let wrong = call(
        app,
        "POST",
        "/device",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        Some(form(&[
            ("csrf", "wrong"),
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
        .expect("access token")
        .to_owned();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
    // The device code is valid only once.
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
async fn sign_in_rotation_and_revocation() {
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

    // Polling too fast: slow_down.
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
            Some(form(&[("client_id", "foreign")]))
        )
        .await
        .json()["error"],
        "invalid_client"
    );

    // Rotation: new pair, the old access token ends.
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
    // Reusing the old refresh token ends the whole session.
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

    // List and revoke sessions.
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
                .expect("link for the admin")
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
async fn invitations_seats_and_license() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Core").await;
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

    // Wrong account: d's invitation is not valid for a.
    assert_eq!(
        accept(app, &a, &links[3]).await.json()["error"],
        "wrong_account"
    );
    assert_eq!(accept(app, &a, &links[0]).await.status, StatusCode::OK);
    assert_eq!(accept(app, &b, &links[1]).await.status, StatusCode::OK);
    // Owner + 2 = Free plan full.
    let full = accept(app, &c, &links[2]).await;
    assert_eq!(full.status, StatusCode::CONFLICT);
    assert_eq!(full.json()["error"], "seats_full");
    // An invitation is valid only once.
    assert_eq!(
        accept(app, &a, &links[0]).await.status,
        StatusCode::NOT_FOUND
    );

    // Roles: a member may not invite.
    let member_invite = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[("authorization", &bearer(&a))],
        json_body(json!({ "emails": ["x@example.org"], "role": "member" })),
    )
    .await;
    assert_eq!(member_invite.status, StatusCode::FORBIDDEN);

    // License: foreign signature, expired, other address, then valid with 5 seats.
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

    // Now there is a seat: c joins. Inviting again renews the link.
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

    // Other teams are not visible.
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
async fn last_seat_is_taken_exactly_once() {
    let s = start(local_config()).await;
    let app = s.server.router.clone();
    let (owner, _) = login(&s, "boss@example.org").await;
    let team = create_team(&app, &owner, "Race").await;
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
    assert_eq!((joined, full), (2, 4), "Free: owner and exactly two more");
}

#[tokio::test]
async fn browser_invitation_and_ticket_through_to_live_connection() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Live <b>").await;
    let link = invite_links(app, &owner, &team, &["new@example.org"], "member")
        .await
        .remove(0);
    let page = call(app, "GET", &format!("/invite/{link}"), &[], None).await;
    assert!(page.body.contains("Live &lt;b&gt;"), "team name escaped");
    assert!(page.body.contains("new@example.org"));
    // Without Origin nothing; with Origin: the link proves the mailbox, account created, joined.
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

    // A self-hosting ticket opens the live connection (same relay path as official).
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
    // The same ticket a second time: rejected.
    let mut ws2 = Client::connect(s.addr).await;
    assert!(matches!(
        ws2.hello(&team, ticket, "owner-laptop", None).await.message,
        ServerMessage::Err(_)
    ));
    // No ticket for other teams.
    let (stranger, _) = login(&s, "stranger@example.org").await;
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
async fn magic_link_cannot_be_requested_without_mail_and_reveals_nothing() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let r = call(
        app,
        "POST",
        "/auth/email",
        &[("origin", ORIGIN)],
        Some(form(&[("email", "someone@example.org")])),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("sends no mail"));
    let cross = call(
        app,
        "POST",
        "/auth/email",
        &[("origin", "https://evil.example")],
        Some(form(&[("email", "someone@example.org")])),
    )
    .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invitation_mail_via_log_transport() {
    let mut config = local_config();
    config.mail_transport = hangar_server::config::MailTransport::Log;
    let dir = config.data_dir.join("mail");
    let s = start(config).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Mailroom").await;
    let r = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[
            ("authorization", &bearer(&owner)),
            ("accept-language", "de-DE"),
        ],
        json_body(json!({ "emails": ["guest@example.org"], "role": "member" })),
    )
    .await;
    assert!(
        r.json()["invitations"][0].get("link").is_none(),
        "with mail delivery no link for the admin"
    );
    let mut mail = None;
    for _ in 0..50 {
        if let Some(entry) = std::fs::read_dir(&dir).ok().and_then(|mut d| d.next()) {
            mail = Some(std::fs::read_to_string(entry.unwrap().path()).unwrap());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let mail = mail.expect("mail written");
    assert!(mail.contains("multipart/alternative"));
    assert!(mail.contains("text/plain") && mail.contains("text/html"));
    assert!(mail.contains("To: guest@example.org"));
}

/// Waits for the next new mail in the log folder and returns its text (quoted-printable soft
/// line breaks joined).
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
    panic!("no mail written");
}

#[tokio::test]
async fn device_code_in_magic_link_only_applies_in_requesting_browser() {
    let mut config = local_config();
    config.mail_transport = hangar_server::config::MailTransport::Log;
    let dir = config.data_dir.join("mail");
    let s = start(config).await;
    let app = &s.server.router;
    login(&s, "victim@example.org").await;
    let request = |cookie_jar: bool| {
        let app = app.clone();
        async move {
            let r = call(
                &app,
                "POST",
                "/auth/email",
                &[("origin", ORIGIN), ("accept-language", "en")],
                Some(form(&[
                    ("email", "victim@example.org"),
                    ("return_to", "/device?code=BCDF-GHJK"),
                ])),
            )
            .await;
            assert_eq!(r.status, StatusCode::OK);
            let cookie = r.cookie.expect("browser cookie set");
            assert!(cookie.starts_with("hangar_login="));
            cookie_jar.then_some(cookie)
        }
    };
    let token_of = |mail: &str| {
        let from = mail.find("/auth/magic/").expect("link in the mail") + "/auth/magic/".len();
        mail[from..from + 43].to_owned()
    };

    // A different browser (or someone opening a mail requested by somebody else): the code is
    // dropped, the person lands on /device and would have to enter it themselves.
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
    // Single use.
    assert_eq!(post(token, None).await.status(), StatusCode::NOT_FOUND);

    // Same browser: the return path keeps the code.
    let cookie = request(true).await.unwrap();
    let token = token_of(&next_mail(&dir, 1).await);
    let same = post(token, Some(cookie)).await;
    assert_eq!(same.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        same.headers()["location"].to_str().unwrap(),
        "/device?code=BCDF-GHJK"
    );

    // Foreign browser with a fresh link: only /device.
    request(false).await;
    let token = token_of(&next_mail(&dir, 2).await);
    let other = post(token, Some("hangar_login=foreign".into())).await;
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
async fn role_change_and_removal_take_effect_in_relay_immediately() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Instant").await;
    let links = invite_links(app, &owner, &team, &["admin@example.org"], "admin").await;
    let (admin, _) = login(&s, "admin@example.org").await;
    assert_eq!(accept(app, &admin, &links[0]).await.status, StatusCode::OK);
    let links = invite_links(app, &owner, &team, &["new@example.org"], "member").await;
    let (member, _) = login(&s, "new@example.org").await;
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

    // Demotion: applied silently on the open connection, no disconnect; the next admin
    // intent (key.rotate) is rejected.
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
        r#"{{"v":1,"id":"still-there","team":"{team}","type":"ping"}}"#
    ))
    .await;
    assert!(matches!(
        ws.answer("still-there").await.message,
        ServerMessage::Ack(_)
    ));

    // Removal before the member ever connected: a ticket issued earlier no longer helps.
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
        late.hello(&team, early, "new-pc", None).await.message,
        ServerMessage::Err(_)
    ));
}

#[tokio::test]
async fn invitations_count_per_address_for_rate_limit() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "owner@example.org").await;
    let team = create_team(app, &owner, "Many").await;
    let batch = |n: usize| {
        (0..20)
            .map(|i| format!("guest{n}-{i}@example.org"))
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
    // 40 addresses used; 20 more exceed the 50 per hour.
    assert_eq!(send(batch(3)).await, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn host_commands_create_team_invite_and_teams() {
    use hangar_server::identity::teams::{cli_create_team, cli_invite, cli_teams};
    let s = start(local_config()).await;
    let app = &s.server.router;
    let db = &s.server.state.relay.db;
    let public = &s.server.state.config.public_url;

    assert!(cli_teams(db).await.unwrap().is_empty());
    // Owner without an account: the account is created with the team.
    let team = cli_create_team(db, "de", " Chef@Example.org ", "Engineering")
        .await
        .unwrap();
    assert!(team.starts_with("t_"));
    assert!(cli_create_team(db, "de", "not-an-address", "X")
        .await
        .is_err());
    assert!(cli_create_team(db, "de", "chef@example.org", "  ")
        .await
        .is_err());
    assert!(
        cli_create_team(db, "de", "chef@example.org", &"x".repeat(81))
            .await
            .is_err()
    );

    // Role owner and nonsense rejected, unknown team with a hint.
    for role in ["owner", "root", ""] {
        assert!(
            cli_invite(db, public, "de", &team, "new@example.org", role)
                .await
                .is_err(),
            "{role}"
        );
    }
    let unknown = cli_invite(
        db,
        public,
        "de",
        "DoesNotExist",
        "new@example.org",
        "member",
    )
    .await
    .unwrap_err();
    assert!(unknown.contains("teams"), "{unknown}");

    // Team by name; a second call renews the invitation, the old link is no longer valid.
    let first = cli_invite(db, public, "de", "Engineering", "new@example.org", "member")
        .await
        .unwrap();
    let link = cli_invite(db, public, "de", &team, "New@example.org", "admin")
        .await
        .unwrap();
    assert!(link.starts_with(&format!("{public}/invite/")), "{link}");
    let old_path = first.trim_start_matches(public.as_str()).to_owned();
    assert_eq!(
        call(app, "GET", &old_path, &[], None).await.status,
        StatusCode::NOT_FOUND
    );
    let lines = cli_teams(db).await.unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].owner, "chef@example.org");
    assert_eq!((lines[0].members, lines[0].open_invitations), (1, 1));

    // The link signs the person in and lets them join, like an invitation from the API.
    let path = link.trim_start_matches(public.as_str()).to_owned();
    let page = call(app, "GET", &path, &[], None).await;
    assert!(page.body.contains("Engineering") && page.body.contains("new@example.org"));
    let joined = call(app, "POST", &path, &[("origin", ORIGIN)], Some(form(&[]))).await;
    assert_eq!(joined.status, StatusCode::OK, "{}", joined.body);
    assert!(joined.cookie.is_some(), "browser session for /device");
    let lines = cli_teams(db).await.unwrap();
    assert_eq!((lines[0].members, lines[0].open_invitations), (2, 0));
    let again = cli_invite(db, public, "de", &team, "new@example.org", "member")
        .await
        .unwrap_err();
    assert!(again.contains("is already a member"), "{again}");

    // The invited person sees the team as admin in the app's account API.
    let (token, _) = login(&s, "new@example.org").await;
    let me = call(
        app,
        "GET",
        "/v1/me",
        &[("authorization", &bearer(&token))],
        None,
    )
    .await
    .json();
    assert_eq!(me["teams"][0]["id"], team.as_str(), "{me}");
    assert_eq!(me["teams"][0]["role"], "admin", "{me}");

    // Two teams with the same name: the name no longer suffices, the ID does.
    let second = cli_create_team(db, "de", "chef@example.org", "Engineering")
        .await
        .unwrap();
    let ambiguous = cli_invite(db, public, "de", "Engineering", "b@example.org", "member")
        .await
        .unwrap_err();
    assert!(
        ambiguous.contains(&team) && ambiguous.contains(&second),
        "{ambiguous}"
    );
    assert!(
        cli_invite(db, public, "de", &second, "b@example.org", "member")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn host_command_license_stores_for_the_named_account() {
    use hangar_server::identity::teams::cli_install_license;
    let s = start(local_config()).await;
    let app = &s.server.router;
    let db = &s.server.state.relay.db;
    let config = &s.server.state.config;
    let valid_until = now_s() + 30 * 86_400;

    let foreign = license(
        5,
        "chef@example.org",
        valid_until,
        &SigningKey::from_bytes(&[1; 32]),
    );
    let error = cli_install_license(db, config, &foreign).await.unwrap_err();
    assert!(error.starts_with("invalid license"), "{error}");
    let expired = license(5, "chef@example.org", now_s() - 1, &license_key());
    let error = cli_install_license(db, config, &expired).await.unwrap_err();
    assert!(error.contains("expired"), "{error}");

    // No account yet: the command creates it; surrounding whitespace from the file is ignored.
    let doc = license(5, "chef@example.org", valid_until, &license_key());
    let installed = cli_install_license(db, config, &format!("\n{doc}\r\n"))
        .await
        .unwrap();
    assert_eq!(
        (installed.email.as_str(), installed.seats, installed.exp),
        ("chef@example.org", 5, valid_until)
    );
    // Running it again with the same file is harmless.
    assert!(cli_install_license(db, config, &doc).await.is_ok());

    let (token, _) = login(&s, "chef@example.org").await;
    let stored = call(
        app,
        "GET",
        "/v1/license",
        &[("authorization", &bearer(&token))],
        None,
    )
    .await;
    assert_eq!(stored.json()["effectiveSeats"], 5, "{}", stored.body);

    // The same license ID cannot move to a second account through the API.
    let (other, _) = login(&s, "other@example.org").await;
    let taken = call(
        app,
        "PUT",
        "/v1/license",
        &[("authorization", &bearer(&other))],
        json_body(
            json!({ "document": license(5, "other@example.org", valid_until, &license_key()) }),
        ),
    )
    .await;
    assert_eq!(taken.json()["error"], "license_in_use", "{}", taken.body);
}

/// Security: an invitation link must not sign in an account that already exists. Without mail
/// the inviter receives the link, so it proves nothing about the invited mailbox; otherwise any
/// account could create a team, invite someone else's address and take that account over.
#[tokio::test]
async fn invitation_link_never_signs_in_an_existing_account() {
    let s = start(local_config()).await;
    let app = &s.server.router;
    let (victim, _) = login(&s, "victim@example.org").await;
    let secret = create_team(app, &victim, "Secret").await;
    let (attacker, _) = login(&s, "attacker@example.org").await;
    let bait = create_team(app, &attacker, "Bait").await;
    let link = invite_links(app, &attacker, &bait, &["victim@example.org"], "member")
        .await
        .remove(0);

    let response = call(
        app,
        "POST",
        &format!("/invite/{link}"),
        &[("origin", ORIGIN)],
        Some(form(&[])),
    )
    .await;
    assert!(
        response.cookie.is_none(),
        "no browser session for the existing account: {}",
        response.body
    );
    assert_ne!(response.status, StatusCode::OK);

    // The victim was not added to the attacker's team, and still owns their own team alone.
    let detail = call(
        app,
        "GET",
        &format!("/v1/teams/{secret}"),
        &[("authorization", &bearer(&victim))],
        None,
    )
    .await
    .json();
    assert_eq!(detail["seats"]["used"], 1);
}

/// A new address still joins with one click, but the session starts only after joining.
#[tokio::test]
async fn invitation_link_session_only_after_joining() {
    let mut config = local_config();
    config.license_keys = KeySet::default();
    let s = start(config).await;
    let app = &s.server.router;
    let (owner, _) = login(&s, "full@example.org").await;
    let team = create_team(app, &owner, "Full").await;
    let emails = ["a1@example.org", "a2@example.org", "a3@example.org"];
    let links = invite_links(app, &owner, &team, &emails, "member").await;
    for link in &links[..2] {
        let joined = call(
            app,
            "POST",
            &format!("/invite/{link}"),
            &[("origin", ORIGIN)],
            Some(form(&[])),
        )
        .await;
        assert_eq!(joined.status, StatusCode::OK, "{}", joined.body);
    }
    // Free has three seats: the third person cannot join and gets no session either.
    let full = call(
        app,
        "POST",
        &format!("/invite/{}", links[2]),
        &[("origin", ORIGIN)],
        Some(form(&[])),
    )
    .await;
    assert_eq!(full.status, StatusCode::CONFLICT, "{}", full.body);
    assert!(full.cookie.is_none(), "no session without joining");
}
