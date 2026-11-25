//! Protocol version 2: the team's notes key ring (`notes.keys.get`, `notes.keys.set`,
//! `notes.keys`, `notes.keys.updated`) and the version negotiated per `hello`. A connection of
//! version 1 behaves exactly as before: the new kinds are refused and never sent to it.

mod common;

use std::net::SocketAddr;

use common::*;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::ticket::Role;
use hangar_server::wire::{Role as LogRole, *};

fn code(frame: &ServerFrame) -> Option<ErrorCode> {
    match &frame.message {
        ServerMessage::Err(e) => Some(e.code),
        _ => None,
    }
}

fn is_ack(frame: &ServerFrame) -> bool {
    matches!(frame.message, ServerMessage::Ack(_))
}

fn v1() -> ProtoRange {
    ProtoRange::new(1, 1).unwrap()
}

/// An app of version 2: no proof of possession (version 3) in these tests.
fn v2() -> ProtoRange {
    ProtoRange::new(1, 2).unwrap()
}

fn sealed(epoch: u32, data: &str) -> Sealed {
    Sealed {
        epoch: Epoch(epoch),
        data: cipher(data),
    }
}

fn set(base: u64, content: Sealed) -> ClientMessage {
    ClientMessage::NotesKeysSet(NotesKeysSet { base, content })
}

/// Connects `dev` with the given protocol range and registers its keys; returns the client and
/// the version the relay chose.
async fn join_with(
    addr: SocketAddr,
    team: &str,
    dev: &Dev,
    role: Role,
    proto: ProtoRange,
) -> (Client, u16) {
    let mut client = Client::connect(addr).await;
    let frame = client
        .hello_with(
            team,
            ticket(dev.holder.member.as_str(), team, role),
            dev.holder.device.as_str(),
            proto,
            None,
        )
        .await;
    let ServerMessage::Welcome(welcome) = frame.message else {
        panic!("no welcome: {frame:?}")
    };
    let keys = client
        .request(team, ClientMessage::DeviceKeys(dev.keys(team)))
        .await;
    assert!(is_ack(&keys), "{keys:?}");
    (client, welcome.proto)
}

/// The answer to `notes.keys.get`.
async fn get(c: &mut Client, team: &str) -> Option<NotesKeysRecord> {
    let frame = c.request(team, ClientMessage::NotesKeysGet).await;
    match frame.message {
        ServerMessage::NotesKeys(keys) => keys.record,
        other => panic!("no notes.keys: {other:?}"),
    }
}

async fn updated(c: &mut Client) -> NotesKeysUpdated {
    let frame = c
        .until(|f| matches!(f.message, ServerMessage::NotesKeysUpdated(_)))
        .await;
    assert_eq!(frame.seq, None, "a live hint, never logged");
    let ServerMessage::NotesKeysUpdated(hint) = frame.message else {
        unreachable!()
    };
    hint
}

/// Team `t` with alice (owner), bob (member) and carol (admin), all with keys and in the log,
/// rotated to epoch 1. Every connection speaks version 2.
struct Team {
    alice: Dev,
    a: Client,
    bob: Dev,
    b: Client,
    carol: Dev,
    c: Client,
}

async fn team(addr: SocketAddr) -> Team {
    let mut log = Log::new("t");
    let alice = Dev::new("alice", "alice-laptop");
    let (mut a, proto) = join_with(addr, "t", &alice, Role::Owner, v2()).await;
    assert_eq!(proto, 2);
    let create = log.create(&alice);
    assert!(is_ack(
        &a.request("t", ClientMessage::MemberLogAppend(create.clone()))
            .await
    ));
    log.accept(&create, &alice.holder);
    let bob = Dev::new("bob", "bob-laptop");
    let (b, _) = join_with(addr, "t", &bob, Role::Member, v2()).await;
    let carol = Dev::new("carol", "carol-pc");
    let (c, _) = join_with(addr, "t", &carol, Role::Admin, v2()).await;
    for (dev, role) in [(&bob, LogRole::Member), (&carol, LogRole::Admin)] {
        let add = log.add_member(&alice, dev, role);
        assert!(is_ack(
            &a.request("t", ClientMessage::MemberLogAppend(add.clone()))
                .await
        ));
        log.accept(&add, &alice.holder);
    }
    let (rotate, _) = log.rotate(&alice);
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyRotate(rotate.clone()))
            .await
    ));
    log.accept_rotation(&rotate, &alice.holder);
    Team {
        alice,
        a,
        bob,
        b,
        carol,
        c,
    }
}

#[tokio::test]
async fn hello_negotiates_the_highest_common_version() {
    let s = start_official().await;
    let (_a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    assert_eq!(welcome.proto, 3);
    let mut two = Client::connect(s.addr).await;
    let frame = two
        .hello_with(
            "t",
            ticket("dave", "t", Role::Member),
            "dave-pc",
            v2(),
            None,
        )
        .await;
    let ServerMessage::Welcome(welcome) = frame.message else {
        panic!("{frame:?}")
    };
    assert_eq!(welcome.proto, 2);
    let mut old = Client::connect(s.addr).await;
    let frame = old
        .hello_with("t", ticket("bob", "t", Role::Member), "bob-pc", v1(), None)
        .await;
    let ServerMessage::Welcome(welcome) = frame.message else {
        panic!("{frame:?}")
    };
    assert_eq!(welcome.proto, 1);
    let mut newer = Client::connect(s.addr).await;
    let frame = newer
        .hello_with(
            "t",
            ticket("carol", "t", Role::Member),
            "carol-pc",
            ProtoRange::new(2, 3).unwrap(),
            None,
        )
        .await;
    let ServerMessage::Welcome(welcome) = frame.message else {
        panic!("{frame:?}")
    };
    assert_eq!(welcome.proto, 3);
}

#[tokio::test]
async fn owner_stores_the_ring_and_every_version_two_connection_hears_of_it() {
    let s = start_official().await;
    let mut t = team(s.addr).await;
    assert_eq!(get(&mut t.a, "t").await, None);
    assert_eq!(get(&mut t.b, "t").await, None, "any member may fetch");

    let op = t.a.op();
    t.a.send(&op, Some("t"), set(0, sealed(1, "cmluZzE"))).await;
    // The answer first, then the hint, also on the writing connection.
    let first =
        t.a.until(|f| {
            f.id.as_ref().map(|i| i.as_str()) == Some(op.as_str())
                || matches!(f.message, ServerMessage::NotesKeysUpdated(_))
        })
        .await;
    assert!(is_ack(&first), "{first:?}");
    let own = updated(&mut t.a).await;
    assert_eq!(own.version, 1);
    let hint = updated(&mut t.b).await;
    assert_eq!(hint.version, 1);
    assert_eq!(hint.by, t.alice.holder);
    assert_eq!(updated(&mut t.c).await.version, 1);

    let record = get(&mut t.b, "t").await.expect("stored");
    assert_eq!(record.version, 1);
    assert_eq!(record.by, t.alice.holder);
    assert_eq!(record.content, sealed(1, "cmluZzE"));

    // An admin builds on version 1.
    assert!(is_ack(
        &t.c.request("t", set(1, sealed(1, "cmluZzI"))).await
    ));
    let hint = updated(&mut t.b).await;
    assert_eq!((hint.version, hint.by), (2, t.carol.holder.clone()));
    let record = get(&mut t.a, "t").await.expect("stored");
    assert_eq!(record.version, 2);
    assert_eq!(record.content, sealed(1, "cmluZzI"));
}

#[tokio::test]
async fn writes_are_checked_for_role_version_and_epoch() {
    let s = start_official().await;
    let mut t = team(s.addr).await;
    // A member never writes the ring.
    let r = t.b.request("t", set(0, sealed(1, "Ym9i"))).await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
    // The lower of log role and ticket role: carol is admin in the log, her ticket says member.
    let mut demoted = Client::connect(s.addr).await;
    let w = demoted
        .hello_with(
            "t",
            ticket("carol", "t", Role::Member),
            "carol-pc",
            v2(),
            None,
        )
        .await;
    assert!(matches!(w.message, ServerMessage::Welcome(_)), "{w:?}");
    let r = demoted.request("t", set(0, sealed(1, "Y2Fyb2w"))).await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
    // An owner's device the log does not list.
    let mut spare = Client::connect(s.addr).await;
    let w = spare
        .hello_with(
            "t",
            ticket("alice", "t", Role::Owner),
            "alice-spare",
            v2(),
            None,
        )
        .await;
    assert!(matches!(w.message, ServerMessage::Welcome(_)), "{w:?}");
    let r = spare.request("t", set(0, sealed(1, "c3BhcmU"))).await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
    // Sealed under an older epoch.
    let r = t.a.request("t", set(0, sealed(0, "b2xk"))).await;
    assert_eq!(code(&r), Some(ErrorCode::StaleEpoch));
    assert_eq!(get(&mut t.a, "t").await, None, "nothing stored so far");

    assert!(is_ack(&t.a.request("t", set(0, sealed(1, "djE"))).await));
    // `base` must be the stored version.
    for base in [0, 2, 7] {
        let r = t.c.request("t", set(base, sealed(1, "c3RhbGU"))).await;
        assert_eq!(code(&r), Some(ErrorCode::Conflict), "base {base}");
    }
    let record = get(&mut t.a, "t").await.expect("stored");
    assert_eq!(record.version, 1);
    assert_eq!(record.content, sealed(1, "djE"));
}

#[tokio::test]
async fn retry_gets_the_first_answer() {
    let s = start_official().await;
    let mut t = team(s.addr).await;
    let op = t.a.op();
    t.a.send(&op, Some("t"), set(0, sealed(1, "Zmlyc3Q"))).await;
    assert!(is_ack(&t.a.answer(&op).await));
    // The same intent again: the remembered `ack`, not a `conflict`, and no second write.
    t.a.send(&op, Some("t"), set(0, sealed(1, "Zmlyc3Q"))).await;
    assert!(is_ack(&t.a.answer(&op).await));
    // Another intent under the same op id.
    t.a.send(&op, Some("t"), set(1, sealed(1, "b3RoZXI"))).await;
    assert_eq!(code(&t.a.answer(&op).await), Some(ErrorCode::BadRequest));
    let record = get(&mut t.b, "t").await.expect("stored");
    assert_eq!(record.version, 1);
    assert_eq!(record.content, sealed(1, "Zmlyc3Q"));
}

#[tokio::test]
async fn a_team_without_a_log_has_no_one_to_write_the_ring() {
    let s = start_official().await;
    let (mut a, welcome) = Client::join(s.addr, "solo", "alice", Role::Owner).await;
    assert_eq!(welcome.proto, 3);
    let r = a.request("solo", set(0, sealed(0, "cmluZw"))).await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
    assert_eq!(get(&mut a, "solo").await, None);
}

#[tokio::test]
async fn version_one_connections_neither_send_nor_see_the_new_kinds() {
    let s = start_official().await;
    let mut t = team(s.addr).await;
    // A second connection of alice's device that only speaks version 1.
    let (mut old, proto) = join_with(s.addr, "t", &t.alice, Role::Owner, v1()).await;
    assert_eq!(proto, 1);
    let r = old.request("t", ClientMessage::NotesKeysGet).await;
    assert_eq!(code(&r), Some(ErrorCode::BadRequest));
    // Refused before anything is applied or remembered: the same op id goes through on a
    // connection of version 2.
    let op = old.op();
    old.send(&op, Some("t"), set(0, sealed(1, "djE"))).await;
    assert_eq!(code(&old.answer(&op).await), Some(ErrorCode::BadRequest));
    t.a.send(&op, Some("t"), set(0, sealed(1, "djE"))).await;
    assert!(is_ack(&t.a.answer(&op).await));
    assert_eq!(updated(&mut t.b).await.version, 1);
    // Everything queued for the old connection before this ping's answer: no hint among it.
    let ping = old.op();
    old.send(&ping, Some("t"), ClientMessage::Ping).await;
    loop {
        let frame = old.recv().await.expect("answer to ping");
        assert!(
            !matches!(
                frame.message,
                ServerMessage::NotesKeysUpdated(_) | ServerMessage::NotesKeys(_)
            ),
            "{frame:?}"
        );
        if frame.id.as_ref().map(|i| i.as_str()) == Some(ping.as_str()) {
            assert!(is_ack(&frame));
            break;
        }
    }
    // Everything of version 1 keeps working on it.
    let r = old
        .request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
        .await;
    assert!(
        matches!(r.message, ServerMessage::MemberLogEntries(_)),
        "{r:?}"
    );
}

#[tokio::test]
async fn the_ring_survives_a_restart() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let mut t = team(s.addr).await;
    assert!(is_ack(&t.a.request("t", set(0, sealed(1, "a2VwdA"))).await));
    t.a.close().await;
    t.b.close().await;
    t.c.close().await;
    let _ = s.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let s2 = start(config).await;
    let mut b = Client::join_device(s2.addr, "t", &t.bob, Role::Member).await;
    let record = get(&mut b, "t").await.expect("stored durably");
    assert_eq!(record.version, 1);
    assert_eq!(record.by, t.alice.holder);
    assert_eq!(record.content, sealed(1, "a2VwdA"));
    // The version counts on from the stored one.
    let mut c = Client::join_device(s2.addr, "t", &t.carol, Role::Admin).await;
    assert!(is_ack(&c.request("t", set(1, sealed(1, "bmV4dA"))).await));
    assert_eq!(get(&mut b, "t").await.map(|r| r.version), Some(2));
}

#[tokio::test]
async fn the_ring_goes_with_the_team() {
    let s = start_official().await;
    let mut t = team(s.addr).await;
    assert!(is_ack(&t.a.request("t", set(0, sealed(1, "Z29uZQ"))).await));
    let relay = s.server.state.relay.clone();
    let rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relay_notes_keys WHERE team_id = 't'")
            .fetch_one(&relay.db)
            .await
            .unwrap()
    };
    assert_eq!(rows().await, 1);
    relay.close_team("t").await.unwrap();
    assert_eq!(rows().await, 0);
}
