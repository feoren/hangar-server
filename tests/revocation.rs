//! The website's revocation list against a local mock of the website: signature, cursor,
//! pages with `more`, idempotency per `rid`, effect on live connections, readmission.

mod common;

use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use axum::Router;
use common::*;
use ed25519_dalek::SigningKey;
use hangar_server::config::{Config, IdentityMode, RevocationSource};
use hangar_server::relay::revocation::{PollError, Poller};
use hangar_server::relay::team::close;
use hangar_server::signed::{self, REVOKE_CONTEXT};
use hangar_server::ticket::Role;
use hangar_server::util::now_s;
use hangar_server::wire::{ClientMessage, Epoch, ErrorCode, KeyRotate, ServerMessage, WrappedKey};
use serde_json::{json, Value};

const TOKEN: &str = "relay-token-relay-token-relay-token-1234";

#[derive(Default)]
struct Mock {
    /// Responses keyed by `after`.
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
async fn revocations_affect_live_connections() {
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
        "both pages in one round (more)"
    );
    assert_eq!(mock.lock().unwrap().seen_after, vec!["0", "2"]);

    // Removed and seat lost: close 4403.
    assert_eq!(bob.close_code().await, Some(close::CLOSE_REMOVED));
    assert_eq!(carol.close_code().await, Some(close::CLOSE_REMOVED));
    // Role with a known value: applied silently, no disconnect, admin intent fails.
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

    // A ticket issued before the revocation no longer opens the team, a later one does.
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

    // Next page: rid 3 again (skipped) and the project deleted.
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
    assert_eq!(
        p.poll_once().await.unwrap(),
        1,
        "rid 3 takes effect only once"
    );
    assert_eq!(alice.close_code().await, Some(close::CLOSE_TEAM_DELETED));
}

#[tokio::test]
async fn invalid_lists_change_nothing() {
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
    // Wrong token: the website answers 401.
    assert!(matches!(
        poller(&s, &url, "wrong-token-wrong-token-wrong-token1")
            .poll_once()
            .await,
        Err(PollError::Status(401))
    ));
    // The connection stayed, and so did the cursor (next poll again with after=0).
    bob.send_raw(r#"{"v":1,"id":"p1","type":"ping"}"#).await;
    assert!(matches!(
        bob.answer("p1").await.message,
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
async fn role_change_without_role_requires_new_ticket() {
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

/// Security review 2026-11-09: a demoted member hoards valid admin tickets before the demotion.
/// Neither `ticket.renew` nor a new `hello` with such a ticket may restore the old role
/// (previously: admin for up to `CONNECTION_MAX_AGE_SECS`).
#[tokio::test]
async fn hoarded_ticket_does_not_restore_the_old_role() {
    use hangar_server::wire::{Ticket, TicketRenew};

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

    // ticket.renew with the old admin ticket: rejected, close 4401 (fetch a new ticket).
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

    // hello with a second hoarded admin ticket: rejected.
    let mut again = Client::connect(s.addr).await;
    let refused = again
        .hello("317", hoarded(Role::Admin), "1042-device", None)
        .await;
    assert!(
        matches!(&refused.message, ServerMessage::Err(e) if e.code == ErrorCode::Forbidden),
        "{refused:?}"
    );

    // A ticket issued after the change (new role) opens the team.
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

/// A revocation for a project this relay has never seen is stored durably: after a restart a
/// ticket issued before it still does not open the team.
#[tokio::test]
async fn revocation_for_unknown_project_survives_a_restart() {
    let mock: Shared = Arc::default();
    let url = website(mock.clone()).await;
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let at = now_s() - 5;
    mock.lock().unwrap().pages.push((
        "0".into(),
        list(
            0,
            3,
            false,
            json!([
                {"rid": 1, "prj": 999, "sub": 2001, "kind": "member_removed", "at": at},
                {"rid": 2, "prj": 998, "sub": 2002, "kind": "role_changed", "role": "member", "at": at},
                {"rid": 3, "prj": 997, "sub": 2003, "kind": "role_changed", "at": at}
            ]),
            &website_key(),
        ),
    ));
    assert_eq!(poller(&s, &url, TOKEN).poll_once().await.unwrap(), 3);

    // Restart on the same data (as in tests/persistence.rs).
    let _ = s.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let s = start(config).await;

    let before = |member: &str, team: &str, role| {
        let mut c = claims(member, team, role);
        c.iat = at - 10;
        c.exp = now_s() + 30;
        sign_ticket(&c, &website_key())
    };
    for (member, team, role) in [
        ("2001", "999", Role::Member),
        ("2002", "998", Role::Admin),
        ("2003", "997", Role::Admin),
    ] {
        let mut old = Client::connect(s.addr).await;
        let refused = old
            .hello(team, before(member, team, role), "old-device", None)
            .await;
        assert!(
            matches!(&refused.message, ServerMessage::Err(e) if e.code == ErrorCode::Forbidden),
            "{team}: {refused:?}"
        );
        let mut fresh = Client::connect(s.addr).await;
        let welcome = fresh
            .hello(team, ticket(member, team, Role::Member), "new-device", None)
            .await;
        assert!(
            matches!(welcome.message, ServerMessage::Welcome(_)),
            "{team}: {welcome:?}"
        );
    }
}
