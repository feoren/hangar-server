//! The app's account API under `/api/v1` when self-hosting: the same paths, inputs (JSON and
//! form) and responses as on the website. Device flow, rotation, RFC 7009 revocation, account,
//! projects, tickets up to the live connection, errors as problem+json, the devices page in the
//! browser and the absence of these routes in official mode.

mod common;

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use common::*;
use ed25519_dalek::SigningKey;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::license::LicenseClaims;
use hangar_server::signed::{self, KeySet, LICENSE_CONTEXT};
use hangar_server::util::{b64, now_s};
use hangar_server::wire::ServerMessage;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

const ORIGIN: &str = "http://localhost:8080";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

struct Resp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
    fn cookie(&self) -> Option<String> {
        self.headers
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .map(str::to_owned)
    }
    /// RFC 9457 with the expected code; for OAuth errors also `error`.
    fn problem(&self, status: StatusCode, code: &str) -> Value {
        assert_eq!(self.status, status, "{}", self.body);
        assert!(
            self.header("content-type")
                .starts_with("application/problem+json"),
            "{:?}",
            self.headers
        );
        let body = self.json();
        assert_eq!(body["code"], code, "{}", self.body);
        assert_eq!(body["status"], status.as_u16());
        assert_eq!(body["type"], format!("urn:hangar:api:problem:{code}"));
        assert!(body["title"].is_string() && body["detail"].is_string());
        assert_eq!(self.header("cache-control"), "no-store");
        body
    }
    fn oauth(&self, code: &str) {
        let body = self.problem(StatusCode::BAD_REQUEST, code);
        assert_eq!(body["error"], code);
        assert!(body["error_description"].is_string());
    }
}

enum In {
    None,
    Json(Value),
    Form(Vec<(&'static str, String)>),
    Raw(&'static str, String),
}

async fn call(app: &Router, method: &str, path: &str, headers: &[(&str, &str)], body: In) -> Resp {
    let mut builder = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let request = match body {
        In::None => builder.body(Body::empty()).unwrap(),
        In::Json(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        In::Form(pairs) => builder
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(encode(&pairs)))
            .unwrap(),
        In::Raw(kind, text) => builder
            .header("content-type", kind)
            .body(Body::from(text))
            .unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Resp {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn encode(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            let value: String = v
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
                        char::from(b).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            format!("{k}={value}")
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn pairs(list: &[(&'static str, &str)]) -> In {
    In::Form(list.iter().map(|(k, v)| (*k, (*v).to_owned())).collect())
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn between<'a>(text: &'a str, start: &str, end: &str) -> &'a str {
    let from = text.find(start).expect(start) + start.len();
    let rest = &text[from..];
    &rest[..rest.find(end).unwrap()]
}

fn local() -> Config {
    let mut config = Config::for_tests(IdentityMode::Local, KeySet::default());
    config.license_keys = KeySet::parse(&format!(
        "web-1:{}",
        b64(license_key().verifying_key().as_bytes())
    ))
    .unwrap();
    config
}

fn license_key() -> SigningKey {
    SigningKey::from_bytes(&[77; 32])
}

/// A valid license document with `seats` seats for `email`.
fn license(seats: u32, email: &str) -> String {
    let claims = LicenseClaims {
        v: 1,
        kid: "web-1".into(),
        lid: format!("lic_{seats}"),
        sub: "42".into(),
        email: email.into(),
        plan: "team".into(),
        seats,
        features: vec![],
        iat: now_s() - 10,
        exp: now_s() + 86_400,
    };
    signed::sign(
        &serde_json::to_vec(&claims).unwrap(),
        LICENSE_CONTEXT,
        &license_key(),
    )
}

/// Browser session via an admin magic link; returns the cookie.
async fn browser(s: &TestServer, email: &str) -> String {
    let app = &s.server.router;
    let link = hangar_server::identity::auth::admin_login_link(
        &s.server.state.relay.db,
        &s.server.state.config,
        email,
    )
    .await
    .unwrap();
    let signed_in = call(
        app,
        "POST",
        link.trim_start_matches(ORIGIN),
        &[("origin", ORIGIN)],
        In::None,
    )
    .await;
    assert_eq!(signed_in.status, StatusCode::SEE_OTHER);
    signed_in.cookie().expect("session cookie")
}

/// Approves `user_code` on `/device` and checks that name and platform are shown there.
async fn approve(app: &Router, cookie: &str, user_code: &str, shown: &str) {
    let page = call(
        app,
        "GET",
        &format!("/device?code={user_code}"),
        &[("cookie", cookie)],
        In::None,
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(shown), "{}", page.body);
    let csrf = between(&page.body, r#"name="csrf" value=""#, "\"").to_owned();
    let approved = call(
        app,
        "POST",
        "/device",
        &[("cookie", cookie), ("origin", ORIGIN)],
        pairs(&[
            ("csrf", &csrf),
            ("user_code", user_code),
            ("decision", "approve"),
        ]),
    )
    .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
}

/// The app's device flow via `/api/v1` with JSON, as `AccountApi` sends it. Returns the access
/// token, the refresh token and the browser cookie.
async fn app_login(s: &TestServer, email: &str, device: &str) -> (String, String, String) {
    let app = &s.server.router;
    let started = call(
        app,
        "POST",
        "/api/v1/oauth/device",
        &[("accept", "application/json")],
        In::Json(json!({
            "client_id": "hangar-desktop",
            "scope": "team",
            "device_name": device,
            "platform": "windows",
        })),
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.body);
    let started = started.json();
    let device_code = started["device_code"].as_str().unwrap().to_owned();
    let user_code = started["user_code"].as_str().unwrap().to_owned();
    assert_eq!(started["verification_uri"], format!("{ORIGIN}/device"));
    assert_eq!(
        started["verification_uri_complete"],
        format!("{ORIGIN}/device?code={user_code}")
    );
    assert_eq!(started["expires_in"], 600);
    assert_eq!(started["interval"], 5);

    let poll = || async {
        call(
            app,
            "POST",
            "/api/v1/oauth/token",
            &[],
            In::Json(json!({
                "grant_type": DEVICE_GRANT,
                "device_code": device_code,
                "client_id": "hangar-desktop",
            })),
        )
        .await
    };
    poll().await.oauth("authorization_pending");
    let cookie = browser(s, email).await;
    approve(app, &cookie, &user_code, &format!("{device} (windows)")).await;
    let tokens = poll().await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    let tokens = tokens.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["scope"], "team");
    assert!(tokens["expires_in"].as_i64().unwrap() > 0);
    // The device code is not valid a second time.
    poll().await.oauth("invalid_grant");
    (
        tokens["access_token"].as_str().unwrap().to_owned(),
        tokens["refresh_token"].as_str().unwrap().to_owned(),
        cookie,
    )
}

async fn create_team(app: &Router, access: &str, name: &str) -> String {
    let created = call(
        app,
        "POST",
        "/v1/teams",
        &[("authorization", &bearer(access))],
        In::Json(json!({ "name": name })),
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    created.json()["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn device_start_accepts_json_and_form_and_validates_input() {
    let s = start(local()).await;
    let app = &s.server.router;
    let path = "/api/v1/oauth/device";
    let form = call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("client_id", "hangar-desktop"),
            ("device_name", "Laptop"),
            ("platform", "linux"),
        ]),
    )
    .await;
    assert_eq!(form.status, StatusCode::OK, "{}", form.body);
    assert!(form.json()["device_code"].is_string());
    // `hangar` stays allowed (old clients and scripts), as does omitting scope.
    let old = call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "client_id": "hangar" })),
    )
    .await;
    assert_eq!(old.status, StatusCode::OK, "{}", old.body);

    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "client_id": "foreign" })),
    )
    .await
    .oauth("invalid_client");
    call(app, "POST", path, &[], In::Json(json!({})))
        .await
        .oauth("invalid_client");
    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "client_id": "hangar-desktop", "scope": "team admin" })),
    )
    .await
    .oauth("invalid_scope");
    call(
        app,
        "POST",
        path,
        &[],
        In::Raw("text/plain", "client_id=hangar-desktop".into()),
    )
    .await
    .problem(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type");
    call(
        app,
        "POST",
        path,
        &[],
        In::Raw("application/json", "[1]".into()),
    )
    .await
    .problem(StatusCode::BAD_REQUEST, "invalid_request");
    call(
        app,
        "POST",
        path,
        &[],
        In::Raw(
            "application/json",
            format!("{{\"x\":\"{}\"}}", "a".repeat(17 * 1024)),
        ),
    )
    .await
    .problem(StatusCode::PAYLOAD_TOO_LARGE, "too_large");

    // Other methods: 405 with Allow; unknown paths: 404, both as problem+json.
    let wrong = call(app, "GET", path, &[], In::None).await;
    wrong.problem(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    assert_eq!(wrong.header("allow"), "POST");
    call(app, "GET", "/api/v1/does-not-exist", &[], In::None)
        .await
        .problem(StatusCode::NOT_FOUND, "not_found");
    // Foreign origin (browser on another site): 403, again as problem+json.
    call(
        app,
        "POST",
        path,
        &[("origin", "https://evil.example")],
        In::Json(json!({ "client_id": "hangar-desktop" })),
    )
    .await
    .problem(StatusCode::FORBIDDEN, "origin");
}

#[tokio::test]
async fn token_endpoint_with_json_and_form_and_oauth_errors() {
    let s = start(local()).await;
    let app = &s.server.router;
    let path = "/api/v1/oauth/token";
    call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("grant_type", DEVICE_GRANT),
            ("device_code", "unknown"),
            ("client_id", "hangar-desktop"),
        ]),
    )
    .await
    .oauth("invalid_grant");
    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "grant_type": "password", "client_id": "hangar-desktop" })),
    )
    .await
    .oauth("unsupported_grant_type");
    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "grant_type": DEVICE_GRANT, "client_id": "hangar-desktop" })),
    )
    .await
    .oauth("invalid_request");
    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({ "grant_type": DEVICE_GRANT, "device_code": "x", "client_id": "x" })),
    )
    .await
    .oauth("invalid_client");

    // Rotation via the form; reusing the old token ends the session.
    let (access, refresh, _) = app_login(&s, "a@example.org", "Laptop").await;
    let rotated = call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", "hangar-desktop"),
        ]),
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let new_access = rotated.json()["access_token"].as_str().unwrap().to_owned();
    assert_ne!(new_access, access);
    let me = |token: String| async move {
        call(
            app,
            "GET",
            "/api/v1/me",
            &[("authorization", &bearer(&token))],
            In::None,
        )
        .await
    };
    assert_eq!(me(new_access.clone()).await.status, StatusCode::OK);
    me(access)
        .await
        .problem(StatusCode::UNAUTHORIZED, "invalid_token");
    call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "hangar-desktop",
        })),
    )
    .await
    .oauth("invalid_grant");
    me(new_access)
        .await
        .problem(StatusCode::UNAUTHORIZED, "invalid_token");
}

#[tokio::test]
async fn revocation_ends_the_whole_device_session() {
    let s = start(local()).await;
    let app = &s.server.router;
    let path = "/api/v1/oauth/revoke";
    let (access, refresh, _) = app_login(&s, "a@example.org", "Laptop").await;

    // Malformed requests: wrong client, missing token, unknown hint.
    call(
        app,
        "POST",
        path,
        &[],
        pairs(&[("token", &refresh), ("client_id", "foreign")]),
    )
    .await
    .oauth("invalid_client");
    call(
        app,
        "POST",
        path,
        &[],
        pairs(&[("client_id", "hangar-desktop")]),
    )
    .await
    .oauth("invalid_request");
    call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("token", &refresh),
            ("token_type_hint", "id_token"),
            ("client_id", "hangar-desktop"),
        ]),
    )
    .await
    .oauth("invalid_request");

    // Unknown token: 200 without a body, no information disclosed.
    let unknown = call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("token", "hgrt_unknown"),
            ("token_type_hint", "refresh_token"),
            ("client_id", "hangar-desktop"),
        ]),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::OK);
    assert!(unknown.body.is_empty());

    // Like the app: form with the refresh token.
    let revoked = call(
        app,
        "POST",
        path,
        &[],
        pairs(&[
            ("token", &refresh),
            ("token_type_hint", "refresh_token"),
            ("client_id", "hangar-desktop"),
        ]),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert!(revoked.body.is_empty());
    call(
        app,
        "GET",
        "/api/v1/me",
        &[("authorization", &bearer(&access))],
        In::None,
    )
    .await
    .problem(StatusCode::UNAUTHORIZED, "invalid_token");
    call(
        app,
        "POST",
        "/api/v1/oauth/token",
        &[],
        In::Json(json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "hangar-desktop",
        })),
    )
    .await
    .oauth("invalid_grant");
    // A second time: still 200.
    assert_eq!(
        call(
            app,
            "POST",
            path,
            &[],
            In::Json(json!({ "token": refresh, "client_id": "hangar-desktop" })),
        )
        .await
        .status,
        StatusCode::OK
    );

    // An access token (JSON) only ends itself; the refresh token stays valid.
    let (access, refresh, _) = app_login(&s, "a@example.org", "Desktop").await;
    let only_access = call(
        app,
        "POST",
        path,
        &[],
        In::Json(json!({
            "token": access,
            "token_type_hint": "access_token",
            "client_id": "hangar-desktop",
        })),
    )
    .await;
    assert_eq!(only_access.status, StatusCode::OK);
    call(
        app,
        "GET",
        "/api/v1/me",
        &[("authorization", &bearer(&access))],
        In::None,
    )
    .await
    .problem(StatusCode::UNAUTHORIZED, "invalid_token");
    let renewed = call(
        app,
        "POST",
        "/api/v1/oauth/token",
        &[],
        In::Json(json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": "hangar-desktop",
        })),
    )
    .await;
    assert_eq!(renewed.status, StatusCode::OK, "{}", renewed.body);
}

#[tokio::test]
async fn account_projects_and_ticket_up_to_the_live_connection() {
    let s = start(local()).await;
    let app = &s.server.router;

    // Without or with a wrong bearer: 401 with WWW-Authenticate.
    for headers in [vec![], vec![("authorization", "Bearer wrong")]] {
        for (method, path) in [
            ("GET", "/api/v1/me"),
            ("GET", "/api/v1/projects"),
            ("POST", "/api/v1/relay-ticket"),
        ] {
            let r = call(
                app,
                method,
                path,
                &headers,
                In::Json(json!({ "project_id": "t_x" })),
            )
            .await;
            r.problem(StatusCode::UNAUTHORIZED, "invalid_token");
            assert!(
                r.header("www-authenticate").starts_with("Bearer "),
                "{:?}",
                r.headers
            );
        }
    }

    let (owner, _, _) = app_login(&s, "owner@example.org", "Laptop").await;
    let auth = bearer(&owner);
    let me = call(
        app,
        "GET",
        "/api/v1/me",
        &[("authorization", &auth)],
        In::None,
    )
    .await;
    assert_eq!(me.status, StatusCode::OK, "{}", me.body);
    let me = me.json();
    assert!(me["id"].is_string(), "IDs as strings");
    assert_eq!(me["email"], "owner@example.org");
    assert_eq!(me["locale"], "en");
    // Without a license, Free: the owner alone.
    assert_eq!(me["seats_account_total"], 1);
    assert_eq!(me["seats_account_used"], 0);

    let empty = call(
        app,
        "GET",
        "/api/v1/projects",
        &[("authorization", &auth)],
        In::None,
    )
    .await;
    assert_eq!(empty.json(), json!({ "projects": [] }));

    let team = create_team(app, &owner, "Shop").await;
    let projects = call(
        app,
        "GET",
        "/api/v1/projects",
        &[("authorization", &auth)],
        In::None,
    )
    .await;
    assert_eq!(projects.status, StatusCode::OK, "{}", projects.body);
    assert_eq!(
        projects.json(),
        json!({ "projects": [{
            "id": team,
            "name": "Shop",
            "role": "owner",
            "owner_id": me["id"],
            "plan": "free",
            "seats_account_total": 1,
            "seats_account_used": 1,
            "pending_invitations": 0,
        }]})
    );

    // Teams need a license.
    hangar_server::identity::teams::cli_install_license(
        &s.server.state.relay.db,
        &s.server.state.config,
        &license(3, "owner@example.org"),
    )
    .await
    .unwrap();

    // Invite and accept: the member sees no pending invitations.
    let (member, _, _) = app_login(&s, "member@example.org", "Desktop").await;
    let invited = call(
        app,
        "POST",
        &format!("/v1/teams/{team}/invitations"),
        &[("authorization", &auth)],
        In::Json(
            json!({ "emails": ["member@example.org", "pending@example.org"], "role": "member" }),
        ),
    )
    .await;
    assert_eq!(invited.status, StatusCode::OK, "{}", invited.body);
    let link = invited.json()["invitations"][0]["link"]
        .as_str()
        .unwrap()
        .to_owned();
    let accepted = call(
        app,
        "POST",
        "/v1/invitations/accept",
        &[("authorization", &bearer(&member))],
        In::Json(json!({ "token": link.rsplit('/').next().unwrap() })),
    )
    .await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.body);
    let seen = call(
        app,
        "GET",
        "/api/v1/projects",
        &[("authorization", &bearer(&member))],
        In::None,
    )
    .await
    .json();
    let project = &seen["projects"][0];
    assert_eq!(project["role"], "member");
    assert_eq!(project["seats_account_used"], 2);
    assert!(project.get("pending_invitations").is_none(), "{project}");
    assert!(project.get("invite_url").is_none(), "no invitation page");
    let owner_view = call(
        app,
        "GET",
        "/api/v1/projects",
        &[("authorization", &auth)],
        In::None,
    )
    .await
    .json();
    assert_eq!(owner_view["projects"][0]["pending_invitations"], 1);

    // The member list every member's Hangar compares its team log with.
    let members = call(
        app,
        "GET",
        &format!("/api/v1/projects/{team}/members"),
        &[("authorization", &bearer(&member))],
        In::None,
    )
    .await;
    assert_eq!(members.status, StatusCode::OK, "{}", members.body);
    let listed = members.json()["members"].as_array().unwrap().clone();
    assert_eq!(listed.len(), 2, "{listed:?}");
    assert_eq!(listed[0], json!({ "id": me["id"], "role": "owner" }));
    assert_eq!(listed[1]["role"], "member");
    let (outsider, _, _) = app_login(&s, "outsider@example.org", "Phone").await;
    let foreign = call(
        app,
        "GET",
        &format!("/api/v1/projects/{team}/members"),
        &[("authorization", &bearer(&outsider))],
        In::None,
    )
    .await;
    assert_eq!(foreign.status, StatusCode::NOT_FOUND, "{}", foreign.body);
    let unknown = call(
        app,
        "GET",
        "/api/v1/projects/no-such-team/members",
        &[("authorization", &auth)],
        In::None,
    )
    .await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND, "{}", unknown.body);

    // Ticket as JSON and as form.
    let ticket = call(
        app,
        "POST",
        "/api/v1/relay-ticket",
        &[("authorization", &auth)],
        In::Json(json!({ "project_id": team })),
    )
    .await;
    assert_eq!(ticket.status, StatusCode::OK, "{}", ticket.body);
    let ticket = ticket.json();
    assert_eq!(ticket["relay_url"], "ws://localhost:8080/v1/live");
    let expires = ticket["expires_at"].as_i64().unwrap();
    assert!(
        (now_s() + 55..=now_s() + 61).contains(&expires),
        "{expires}"
    );
    let by_form = call(
        app,
        "POST",
        "/api/v1/relay-ticket",
        &[("authorization", &bearer(&member))],
        pairs(&[("project_id", &team)]),
    )
    .await;
    assert_eq!(by_form.status, StatusCode::OK, "{}", by_form.body);

    let mut ws = Client::connect(s.addr).await;
    let welcome = ws
        .hello(
            &team,
            ticket["ticket"].as_str().unwrap().to_owned(),
            "owner-laptop",
            None,
        )
        .await;
    assert!(
        matches!(welcome.message, ServerMessage::Welcome(_)),
        "{welcome:?}"
    );

    // Foreign and unknown teams: 404; without project_id: 400.
    let (stranger, _, _) = app_login(&s, "stranger@example.org", "Tablet").await;
    for (token, project) in [(&stranger, team.as_str()), (&owner, "t_doesnotexist")] {
        call(
            app,
            "POST",
            "/api/v1/relay-ticket",
            &[("authorization", &bearer(token))],
            In::Json(json!({ "project_id": project })),
        )
        .await
        .problem(StatusCode::NOT_FOUND, "not_found");
    }
    call(
        app,
        "POST",
        "/api/v1/relay-ticket",
        &[("authorization", &auth)],
        In::Json(json!({})),
    )
    .await
    .problem(StatusCode::BAD_REQUEST, "invalid_request");

    // Public ticket key, cacheable.
    let keys = call(app, "GET", "/api/v1/keys", &[], In::None).await;
    assert_eq!(keys.status, StatusCode::OK);
    assert_eq!(keys.header("cache-control"), "public, max-age=3600");
    let key = &keys.json()["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(
        key["kid"],
        s.server.state.identity.as_ref().unwrap().ticket_kid()
    );
}

#[tokio::test]
async fn devices_page_lists_and_disconnects_devices() {
    let s = start(local()).await;
    let app = &s.server.router;
    let anonymous = call(app, "GET", "/account/devices", &[], In::None).await;
    assert_eq!(anonymous.status, StatusCode::OK);
    assert!(
        !anonymous.body.contains("csrf"),
        "no list without signing in"
    );

    let (access, _, cookie) = app_login(&s, "a@example.org", "Laptop").await;
    let page = call(
        app,
        "GET",
        "/account/devices",
        &[("cookie", &cookie)],
        In::None,
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Laptop (windows)"), "{}", page.body);
    assert!(
        !page.body.contains(">Browser<"),
        "browser sessions are not listed"
    );
    let csrf = between(&page.body, r#"name="csrf" value=""#, "\"").to_owned();
    let session = between(&page.body, r#"name="session" value=""#, "\"").to_owned();

    let forged = call(
        app,
        "POST",
        "/account/devices",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        pairs(&[("csrf", "wrong"), ("session", &session)]),
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let foreign = call(
        app,
        "POST",
        "/account/devices",
        &[("cookie", &cookie), ("origin", "https://evil.example")],
        pairs(&[("csrf", &csrf), ("session", &session)]),
    )
    .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN);

    let done = call(
        app,
        "POST",
        "/account/devices",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        pairs(&[("csrf", &csrf), ("session", &session)]),
    )
    .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert_eq!(done.header("location"), "/account/devices?revoked=1");
    call(
        app,
        "GET",
        "/api/v1/me",
        &[("authorization", &bearer(&access))],
        In::None,
    )
    .await
    .problem(StatusCode::UNAUTHORIZED, "invalid_token");
    let after = call(
        app,
        "GET",
        "/account/devices?revoked=1",
        &[("cookie", &cookie)],
        In::None,
    )
    .await;
    assert!(!after.body.contains("Laptop (windows)"));
    let again = call(
        app,
        "POST",
        "/account/devices",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        pairs(&[("csrf", &csrf), ("session", &session)]),
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    // Without the session field: the same "not found" page, no raw extractor response.
    let missing = call(
        app,
        "POST",
        "/account/devices",
        &[("cookie", &cookie), ("origin", ORIGIN)],
        pairs(&[("csrf", &csrf)]),
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.header("content-type").starts_with("text/html"));
}

#[tokio::test]
async fn rate_limit_applies_to_device_start_and_revocation() {
    let s = start(local()).await;
    let app = &s.server.router;
    let mut last = None;
    for _ in 0..31 {
        last = Some(
            call(
                app,
                "POST",
                "/api/v1/oauth/device",
                &[],
                In::Json(json!({ "client_id": "hangar-desktop" })),
            )
            .await,
        );
    }
    let last = last.unwrap();
    let body = last.problem(StatusCode::TOO_MANY_REQUESTS, "slow_down");
    assert_eq!(body["error"], "slow_down");
    assert_eq!(last.header("retry-after"), "60");

    let mut last = None;
    for _ in 0..61 {
        last = Some(
            call(
                app,
                "POST",
                "/api/v1/oauth/revoke",
                &[],
                pairs(&[("token", "x"), ("client_id", "hangar-desktop")]),
            )
            .await,
        );
    }
    last.unwrap()
        .problem(StatusCode::TOO_MANY_REQUESTS, "slow_down");
}

#[tokio::test]
async fn official_mode_does_not_offer_the_account_api() {
    let s = start_official().await;
    let app = &s.server.router;
    for (method, path) in [
        ("POST", "/api/v1/oauth/device"),
        ("POST", "/api/v1/oauth/token"),
        ("POST", "/api/v1/oauth/revoke"),
        ("GET", "/api/v1/me"),
        ("GET", "/api/v1/projects"),
        ("POST", "/api/v1/relay-ticket"),
        ("GET", "/api/v1/keys"),
        ("GET", "/account/devices"),
    ] {
        let r = call(
            app,
            method,
            path,
            &[],
            In::Json(json!({ "client_id": "hangar-desktop" })),
        )
        .await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{method} {path}");
    }
}

#[tokio::test]
async fn root_page_redirects_with_root_redirect() {
    // Without ROOT_REDIRECT, `/` is the start page; the official service names no address
    // (the app knows its server) and serves the stylesheet the page needs.
    let s = start_official().await;
    let r = call(&s.server.router, "GET", "/", &[], In::None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body.contains("Hangar Server is running"), "{}", r.body);
    assert!(!r.body.contains("/api/v1"), "{}", r.body);
    let css = call(&s.server.router, "GET", "/assets/style.css", &[], In::None).await;
    assert_eq!(css.status, StatusCode::OK);

    let mut config = Config::for_tests(IdentityMode::Official, common::website_keys());
    config.root_redirect = Some("https://hangar.feoren.com/".into());
    let s = common::start(config).await;
    let app = &s.server.router;
    let r = call(app, "GET", "/", &[], In::None).await;
    assert_eq!(r.status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        r.headers.get("location").and_then(|v| v.to_str().ok()),
        Some("https://hangar.feoren.com/")
    );
    // Only the root page: other paths and the state stay as they are.
    assert_eq!(
        call(app, "GET", "/health", &[], In::None).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(app, "GET", "/anything", &[], In::None).await.status,
        StatusCode::NOT_FOUND
    );
}
