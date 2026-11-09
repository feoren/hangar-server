//! Widerrufsliste der Webseite gegen einen lokalen Nachbau der Webseite: Signatur, Cursor,
//! Seiten mit `more`, Idempotenz je `rid`, Wirkung auf laufende Verbindungen, Wiederzulassung.

mod common;

use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use common::*;
use ed25519_dalek::SigningKey;
use hangar_team_server::config::{Config, IdentityMode, RevocationSource};
use hangar_team_server::relay::revocation::{PollError, Poller};
use hangar_team_server::relay::team::close;
use hangar_team_server::signed::{self, REVOKE_CONTEXT};
use hangar_team_server::ticket::Role;
use hangar_team_server::util::now_s;
use hangar_team_server::wire::{
    ClientMessage, Epoch, ErrorCode, KeyRotate, ServerMessage, WrappedKey,
};
use serde_json::{json, Value};

const TOKEN: &str = "relay-token-relay-token-relay-token-1234";

#[derive(Default)]
struct Mock {
    /// Antworten nach `after`.
    pages: Vec<(String, String)>,
    seen_after: Vec<String>,
}

type Shared = Arc<Mutex<Mock>>;

async fn serve(
    State(mock): State<Shared>,
    headers: HeaderMap,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> (StatusCode, String) {
    if headers.get("authorization").and_then(|v| v.to_str().ok())
        != Some(&format!("Bearer {TOKEN}"))
    {
        return (StatusCode::UNAUTHORIZED, String::new());
    }
    let after = q.get("after").cloned().unwrap_or_default();
    let mut mock = mock.lock().unwrap();
    mock.seen_after.push(after.clone());
    match mock.pages.iter().find(|(a, _)| *a == after) {
        Some((_, doc)) => (StatusCode::OK, doc.clone()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

fn list(after: u64, last: u64, more: bool, items: Value, key: &SigningKey) -> String {
    let now = now_s();
    let payload = json!({
        "v": 1, "kid": KID, "aud": "hangar-relay", "iat": now, "exp": now + 120,
        "after": after, "last": last, "more": more, "items": items,
    });
    signed::sign(payload.to_string().as_bytes(), REVOKE_CONTEXT, key)
}

async fn website(mock: Shared) -> String {
    let app = Router::new()
        .route("/api/v1/team/revocations", get(serve))
        .with_state(mock);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://127.0.0.1:{}/api/v1/team/revocations", addr.port())
}

fn poller(s: &TestServer, url: &str, token: &str) -> Poller {
    let source = RevocationSource {
        url: url.to_owned(),
        token: token.to_owned(),
        interval_s: 15,
    };
    let relay = s.server.state.relay.clone();
    let keys = relay.ticket_keys().clone();
    Poller::new(relay, source, keys, "hangar-relay".into()).unwrap()
}

#[tokio::test]
async fn widerrufe_wirken_auf_laufende_verbindungen() {
    let mock: Shared = Arc::default();
    let url = website(mock.clone()).await;
    let s = start(Config::for_tests(IdentityMode::Official, website_keys())).await;
    let (mut alice, _) = Client::join(s.addr, "317", "1042", Role::Owner).await;
    let (mut bob, _) = Client::join(s.addr, "317", "1043", Role::Member).await;
    let (mut carol, _) = Client::join(s.addr, "317", "1044", Role::Member).await;
    let at = now_s() - 20;
    {
        let mut m = mock.lock().unwrap();
        m.pages.push((
            "0".into(),
            list(0, 2, true, json!([
                {"rid": 1, "prj": 317, "sub": 1043, "kind": "member_removed", "at": at},
                {"rid": 2, "prj": 317, "sub": 1042, "kind": "role_changed", "role": "member", "at": at}
            ]), &website_key()),
        ));
        m.pages.push((
            "2".into(),
            list(
                2,
                3,
                false,
                json!([
                    {"rid": 3, "prj": "317", "sub": "1044", "kind": "seat_lost", "at": at}
                ]),
                &website_key(),
            ),
        ));
    }
    let p = poller(&s, &url, TOKEN);
    assert_eq!(
        p.poll_once().await.unwrap(),
        3,
        "beide Seiten in einer Runde (more)"
    );
    assert_eq!(mock.lock().unwrap().seen_after, vec!["0", "2"]);

    // Entfernt und Platz verloren: Close 4403.
    assert_eq!(bob.close_code().await, Some(close::CLOSE_REMOVED));
    assert_eq!(carol.close_code().await, Some(close::CLOSE_REMOVED));
    // Rolle mit bekanntem Wert: still angewendet, keine Trennung, Admin-Absicht scheitert.
    alice
        .until(|f| matches!(f.message, ServerMessage::MemberRoleChanged(_)))
        .await;
    let rotate = ClientMessage::KeyRotate(KeyRotate {
        log: dummy_log(),
        epoch: Epoch(1),
        wrapped: vec![WrappedKey {
            holder: holder("1042", "1042-device"),
            data: cipher("YQ"),
        }],
    });
    let refused = alice.request("317", rotate).await;
    assert!(matches!(&refused.message, ServerMessage::Err(e) if e.code == ErrorCode::Forbidden));

    // Ein Ticket von vor dem Widerruf öffnet das Team nicht mehr, ein späteres schon.
    let mut before = claims("1043", "317", Role::Member);
    before.iat = at - 30;
    before.exp = now_s() + 20;
    let mut old = Client::connect(s.addr).await;
    let refused = old
        .hello(
            "317",
            sign_ticket(&before, &website_key()),
            "1043-device",
            None,
        )
        .await;
    assert!(matches!(refused.message, ServerMessage::Err(_)));
    let mut again = Client::connect(s.addr).await;
    let welcome = again
        .hello(
            "317",
            ticket("1043", "317", Role::Member),
            "1043-device",
            None,
        )
        .await;
    assert!(
        matches!(welcome.message, ServerMessage::Welcome(_)),
        "{welcome:?}"
    );

    // Nächste Seite: rid 3 noch einmal (übersprungen) und das Projekt gelöscht.
    mock.lock().unwrap().pages.push((
        "3".into(),
        list(
            3,
            4,
            false,
            json!([
                {"rid": 3, "prj": "317", "sub": "1044", "kind": "seat_lost", "at": at},
                {"rid": 4, "prj": 317, "sub": null, "kind": "project_deleted", "at": at}
            ]),
            &website_key(),
        ),
    ));
    assert_eq!(p.poll_once().await.unwrap(), 1, "rid 3 wirkt nur einmal");
    assert_eq!(alice.close_code().await, Some(close::CLOSE_TEAM_DELETED));
}

#[tokio::test]
async fn ungültige_listen_ändern_nichts() {
    let mock: Shared = Arc::default();
    let url = website(mock.clone()).await;
    let s = start(Config::for_tests(IdentityMode::Official, website_keys())).await;
    let (mut bob, _) = Client::join(s.addr, "317", "1043", Role::Member).await;
    let items =
        json!([{"rid": 1, "prj": 317, "sub": 1043, "kind": "member_removed", "at": now_s()}]);
    mock.lock().unwrap().pages.push((
        "0".into(),
        list(
            0,
            1,
            false,
            items.clone(),
            &SigningKey::from_bytes(&[9; 32]),
        ),
    ));
    let p = poller(&s, &url, TOKEN);
    assert!(matches!(p.poll_once().await, Err(PollError::Invalid(_))));
    // Falsches Token: die Webseite antwortet 401.
    assert!(matches!(
        poller(&s, &url, "falsch-falsch-falsch-falsch-falsch-1")
            .poll_once()
            .await,
        Err(PollError::Status(401))
    ));
    // Die Verbindung blieb, der Cursor auch (nächster Abruf wieder mit after=0).
    bob.send_raw(r#"{"v":1,"id":"da","type":"ping"}"#).await;
    assert!(matches!(
        bob.answer("da").await.message,
        ServerMessage::Ack(_)
    ));
    mock.lock().unwrap().pages.clear();
    mock.lock()
        .unwrap()
        .pages
        .push(("0".into(), list(0, 1, false, items, &website_key())));
    assert_eq!(p.poll_once().await.unwrap(), 1);
    assert_eq!(bob.close_code().await, Some(close::CLOSE_REMOVED));
}

#[tokio::test]
async fn rollenwechsel_ohne_rolle_verlangt_neues_ticket() {
    let mock: Shared = Arc::default();
    let url = website(mock.clone()).await;
    let s = start(Config::for_tests(IdentityMode::Official, website_keys())).await;
    let (mut alice, _) = Client::join(s.addr, "317", "1042", Role::Admin).await;
    mock.lock().unwrap().pages.push((
        "0".into(),
        list(
            0,
            9,
            false,
            json!([
                {"rid": 9, "prj": 317, "sub": 1042, "kind": "role_changed", "at": now_s()}
            ]),
            &website_key(),
        ),
    ));
    assert_eq!(poller(&s, &url, TOKEN).poll_once().await.unwrap(), 1);
    assert_eq!(alice.close_code().await, Some(close::CLOSE_ROLE_CHANGED));
}

/// Sicherheitsprüfung 2026-11-09: ein herabgestuftes Mitglied hortet vor der Herabstufung
/// gültige Admin-Tickets. Weder `ticket.renew` noch ein neues `hello` mit so einem Ticket darf
/// ihm die alte Rolle zurückgeben (vorher: bis zu `CONNECTION_MAX_AGE_SECS` lang Admin).
#[tokio::test]
async fn gehortetes_ticket_bringt_die_alte_rolle_nicht_zurück() {
    use hangar_team_server::wire::{Ticket, TicketRenew};

    let mock: Shared = Arc::default();
    let url = website(mock.clone()).await;
    let s = start(Config::for_tests(IdentityMode::Official, website_keys())).await;
    let (mut alice, _) = Client::join(s.addr, "317", "1042", Role::Admin).await;
    let at = now_s() - 5;
    let hoarded = |role| {
        let mut c = claims("1042", "317", role);
        c.iat = at - 10;
        c.exp = now_s() + 50;
        sign_ticket(&c, &website_key())
    };
    mock.lock().unwrap().pages.push((
        "0".into(),
        list(
            0,
            1,
            false,
            json!([
                {"rid": 1, "prj": 317, "sub": 1042, "kind": "role_changed", "role": "member", "at": at}
            ]),
            &website_key(),
        ),
    ));
    assert_eq!(poller(&s, &url, TOKEN).poll_once().await.unwrap(), 1);
    alice
        .until(|f| matches!(f.message, ServerMessage::MemberRoleChanged(_)))
        .await;

    // ticket.renew mit dem alten Admin-Ticket: abgewiesen, Close 4401 (neues Ticket holen).
    let op = alice.op();
    alice
        .send(
            &op,
            Some("317"),
            ClientMessage::TicketRenew(TicketRenew {
                ticket: Ticket::new(hoarded(Role::Admin)).unwrap(),
            }),
        )
        .await;
    assert_eq!(alice.close_code().await, Some(close::CLOSE_ROLE_CHANGED));

    // hello mit einem zweiten gehorteten Admin-Ticket: abgewiesen.
    let mut again = Client::connect(s.addr).await;
    let refused = again
        .hello("317", hoarded(Role::Admin), "1042-device", None)
        .await;
    assert!(
        matches!(&refused.message, ServerMessage::Err(e) if e.code == ErrorCode::Forbidden),
        "{refused:?}"
    );

    // Ein Ticket nach der Änderung (neue Rolle) öffnet das Team.
    let mut fresh = Client::connect(s.addr).await;
    let welcome = fresh
        .hello(
            "317",
            ticket("1042", "317", Role::Member),
            "1042-device",
            None,
        )
        .await;
    assert!(
        matches!(welcome.message, ServerMessage::Welcome(_)),
        "{welcome:?}"
    );
}
