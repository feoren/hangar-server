//! Protocol version 3: the proof of possession at `hello` (`welcome.challenge`, `device.prove`),
//! the rule for devices that do not count as devices of the membership log, the downgrade
//! protection (`relay_device_proofs`, `REQUIRE_DEVICE_PROOF`) and `blob.delete`.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::relay::team::close;
use hangar_server::ticket::Role;
use hangar_server::wire::{self, Role as LogRole, *};

fn code(frame: &ServerFrame) -> Option<ErrorCode> {
    match &frame.message {
        ServerMessage::Err(e) => Some(e.code),
        _ => None,
    }
}

fn is_ack(frame: &ServerFrame) -> bool {
    matches!(frame.message, ServerMessage::Ack(_))
}

fn v2() -> ProtoRange {
    ProtoRange::new(1, 2).unwrap()
}

fn welcome_of(frame: ServerFrame) -> Welcome {
    match frame.message {
        ServerMessage::Welcome(w) => w,
        other => panic!("no welcome: {other:?}"),
    }
}

async fn append(c: &mut Client, team: &str, entry: &MemberLogAppend) -> ServerFrame {
    c.request(team, ClientMessage::MemberLogAppend(entry.clone()))
        .await
}

/// Connects as `dev` on version 3 and registers its keys, but does not prove.
async fn unproven(addr: SocketAddr, team: &str, dev: &Dev, role: Role) -> (Client, Welcome) {
    let mut c = Client::connect(addr).await;
    let welcome = welcome_of(
        c.hello(
            team,
            ticket(dev.holder.member.as_str(), team, role),
            dev.holder.device.as_str(),
            None,
        )
        .await,
    );
    assert_eq!(welcome.proto, 3);
    let keys = c
        .request(team, ClientMessage::DeviceKeys(dev.keys(team)))
        .await;
    assert!(is_ack(&keys), "{keys:?}");
    (c, welcome)
}

/// Everything the relay queued for `c` before the answer to a fresh `ping`.
async fn drain(c: &mut Client) -> Vec<ServerFrame> {
    let op = c.op();
    c.send(&op, None, ClientMessage::Ping).await;
    let mut frames = Vec::new();
    loop {
        let frame = c.recv().await.expect("answer to ping");
        if frame.id.as_ref().map(|i| i.as_str()) == Some(op.as_str()) {
            return frames;
        }
        frames.push(frame);
    }
}

fn presence() -> ClientMessage {
    ClientMessage::PresenceSet(PresenceSet {
        state: PresenceState::Active,
        status: None,
    })
}

fn reserve(byte: u8) -> ClientMessage {
    ClientMessage::TaskReserve(TaskReserve {
        task: KeyedHash::from_bytes([byte; 32]),
        epoch: Epoch(0),
        prev: Vec::new(),
        note: None,
    })
}

fn claim(key: &str, file: u8) -> ClientMessage {
    ClientMessage::ClaimSet(ClaimSet {
        session: session(key),
        repo: KeyedHash::from_bytes([200; 32]),
        epoch: Epoch(0),
        files: vec![PathHashes {
            area: Some(KeyedHash::from_bytes([10; 32])),
            file: KeyedHash::from_bytes([file; 32]),
        }],
        truncated: false,
        detail: Some(Sealed {
            epoch: Epoch(0),
            data: cipher("ZGV0YWls"),
        }),
    })
}

fn blob_put(len: usize) -> ClientMessage {
    ClientMessage::BlobPut(BlobPut {
        kind: BlobKind::Decision,
        content: Sealed {
            epoch: Epoch(0),
            data: Ciphertext::new("D".repeat(len)).unwrap(),
        },
    })
}

fn blob_delete(blob: &BlobId) -> ClientMessage {
    ClientMessage::BlobDelete(BlobDelete { blob: blob.clone() })
}

async fn put(c: &mut Client, team: &str, len: usize) -> BlobId {
    let r = c.request(team, blob_put(len)).await;
    match r.message {
        ServerMessage::Ack(Ack { blob: Some(id), .. }) => id,
        other => panic!("not stored: {other:?}"),
    }
}

async fn proof_rows(s: &TestServer, holder: &Holder) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM relay_device_proofs WHERE team_id = 't' AND member = ? AND device = ?",
    )
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .fetch_one(&s.server.state.relay.db)
    .await
    .unwrap()
}

/// Team `t` with alice (owner) and bob (member), both on version 3, proven and in the log.
async fn team(s: &TestServer) -> (Log, Dev, Client, Dev, Client) {
    let mut log = Log::new("t");
    let alice = Dev::new("alice", "alice-laptop");
    let mut a = Client::join_device(s.addr, "t", &alice, Role::Owner).await;
    let create = log.create(&alice);
    assert!(is_ack(&append(&mut a, "t", &create).await));
    log.accept(&create, &alice.holder);
    let bob = Dev::new("bob", "bob-laptop");
    let b = Client::join_device(s.addr, "t", &bob, Role::Member).await;
    let add = log.add_member(&alice, &bob, LogRole::Member);
    assert!(is_ack(&append(&mut a, "t", &add).await));
    log.accept(&add, &alice.holder);
    (log, alice, a, bob, b)
}

#[tokio::test]
async fn welcome_carries_a_challenge_exactly_from_version_three() {
    let s = start_official().await;
    // Version 2: the welcome of before, byte for byte without the field.
    let mut old = Client::connect(s.addr).await;
    let op = old.op();
    old.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("alice", "t", Role::Owner)).unwrap(),
            device: device("alice-old"),
            proto: v2(),
            last_seq: None,
        }),
    )
    .await;
    let text = loop {
        let text = old.recv_text().await.expect("welcome");
        if text.contains("\"welcome\"") {
            break text;
        }
    };
    assert!(!text.contains("challenge"), "{text}");
    let frame = wire::decode_server(&text).unwrap();
    assert_eq!(wire::encode_server(&frame).unwrap(), text);
    let ServerMessage::Welcome(w) = frame.message else {
        panic!("{text}")
    };
    assert_eq!((w.proto, w.challenge), (2, None));

    // Version 3: 32 random bytes, 43 characters, new for every welcome.
    let mut challenges = Vec::new();
    for (member, team) in [("bob", "t"), ("carol", "t"), ("bob", "u")] {
        let mut c = Client::connect(s.addr).await;
        let w = welcome_of(
            c.hello(team, ticket(member, team, Role::Member), "pc", None)
                .await,
        );
        assert_eq!(w.proto, 3);
        let challenge = w.challenge.expect("challenge on version 3");
        assert_eq!(challenge.to_base64url().len(), 43);
        challenges.push(challenge);
    }
    // A second team on the same connection gets its own.
    let mut both = Client::connect(s.addr).await;
    for team in ["v", "w"] {
        let w = welcome_of(
            both.hello(team, ticket("dave", team, Role::Member), "pc", None)
                .await,
        );
        challenges.push(w.challenge.unwrap());
    }
    for (i, a) in challenges.iter().enumerate() {
        for b in &challenges[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[tokio::test]
async fn a_proof_passes_only_for_its_own_connection_team_holder_version_and_key() {
    let s = start_official().await;
    let (_log, _alice, _a, bob, _b) = team(&s).await;
    let (mut c, welcome) = unproven(s.addr, "t", &bob, Role::Member).await;
    let challenge = welcome.challenge.unwrap();
    // A second connection of the same device has another challenge.
    let (_other, other_welcome) = unproven(s.addr, "t", &bob, Role::Member).await;
    let wrong_member = holder("mallory", "bob-laptop");
    let wrong_device = holder("bob", "bob-phone");
    let mut wrong_key = bob
        .identity
        .prove_connection(&team_id("t"), &bob.holder, 3, &challenge);
    wrong_key.sign = Dev::new("bob", "bob-laptop").identity.public_keys().sign;
    let refused = [
        bob.identity.prove_connection(
            &team_id("t"),
            &bob.holder,
            3,
            &other_welcome.challenge.unwrap(),
        ),
        bob.identity
            .prove_connection(&team_id("u"), &bob.holder, 3, &challenge),
        bob.identity
            .prove_connection(&team_id("t"), &wrong_member, 3, &challenge),
        bob.identity
            .prove_connection(&team_id("t"), &wrong_device, 3, &challenge),
        bob.identity
            .prove_connection(&team_id("t"), &bob.holder, 2, &challenge),
        wrong_key,
    ];
    for prove in refused.iter().cloned() {
        let r = c.request("t", ClientMessage::DeviceProve(prove)).await;
        assert_eq!(code(&r), Some(ErrorCode::Forbidden), "{r:?}");
    }
    assert_eq!(
        code(&c.request("t", presence()).await),
        Some(ErrorCode::Forbidden),
        "still unproven"
    );
    assert!(is_ack(&c.request("t", bob.prove("t", &welcome)).await));
    assert!(is_ack(&c.request("t", presence()).await));
    // A refused proof afterwards keeps the proven key.
    let r = c
        .request("t", ClientMessage::DeviceProve(refused[1].clone()))
        .await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
    assert!(is_ack(&c.request("t", presence()).await));
    // The same proof again verifies to the same result (not deduplicated).
    assert!(is_ack(&c.request("t", bob.prove("t", &welcome)).await));
}

#[tokio::test]
async fn refused_proofs_count_as_bad_frames() {
    let s = start_official().await;
    let (_log, _alice, _a, bob, _b) = team(&s).await;
    let (mut c, welcome) = unproven(s.addr, "t", &bob, Role::Member).await;
    let bad =
        bob.identity
            .prove_connection(&team_id("u"), &bob.holder, 3, &welcome.challenge.unwrap());
    for _ in 0..25 {
        let op = c.op();
        c.send(&op, Some("t"), ClientMessage::DeviceProve(bad.clone()))
            .await;
    }
    assert_eq!(c.close_code().await, Some(close::CLOSE_HELLO_TIMEOUT));
}

#[tokio::test]
async fn a_listed_device_without_proof_may_only_register_and_read() {
    let s = start_official().await;
    let (_log, _alice, _a, bob, _b) = team(&s).await;
    let (mut c, welcome) = unproven(s.addr, "t", &bob, Role::Member).await;
    let unknown = BlobId::new("bm90LWEtYmxvYg").unwrap();
    let restricted = [
        presence(),
        ClientMessage::KeyGet(KeyGet { epoch: Epoch(0) }),
        ClientMessage::BlobGet(BlobGet {
            blob: unknown.clone(),
        }),
        ClientMessage::NotesKeysGet,
        claim("kb", 50),
        reserve(1),
        blob_delete(&unknown),
    ];
    for message in restricted.iter().cloned() {
        let kind = message.kind();
        let r = c.request("t", message).await;
        assert_eq!(code(&r), Some(ErrorCode::Forbidden), "{kind}: {r:?}");
    }
    // Registering and reading pass.
    assert!(is_ack(
        &c.request("t", ClientMessage::DeviceKeys(bob.keys("t")))
            .await
    ));
    let r = c.request("t", ClientMessage::DevicesGet).await;
    assert!(matches!(r.message, ServerMessage::Devices(_)), "{r:?}");
    let r = c
        .request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
        .await;
    assert!(
        matches!(r.message, ServerMessage::MemberLogEntries(_)),
        "{r:?}"
    );
    let renew = ClientMessage::TicketRenew(TicketRenew {
        ticket: Ticket::new(ticket("bob", "t", Role::Member)).unwrap(),
    });
    assert!(is_ack(&c.request("t", renew).await));

    // A refused intent is not remembered: its op ID goes through after the proof.
    let op = c.op();
    c.send(&op, Some("t"), reserve(2)).await;
    assert_eq!(code(&c.answer(&op).await), Some(ErrorCode::Forbidden));
    assert!(is_ack(&c.request("t", bob.prove("t", &welcome)).await));
    c.send(&op, Some("t"), reserve(2)).await;
    assert!(is_ack(&c.answer(&op).await), "applied after the proof");
    // After the proof everything passes the rule (and meets its own checks).
    for message in restricted {
        let kind = message.kind();
        let r = c.request("t", message).await;
        assert_ne!(code(&r), Some(ErrorCode::Forbidden), "{kind}: {r:?}");
    }
}

#[tokio::test]
async fn frames_sent_without_waiting_meet_the_proven_state() {
    let s = start_official().await;
    let (_log, _alice, _a, bob, _b) = team(&s).await;
    let mut c = Client::connect(s.addr).await;
    let welcome = welcome_of(
        c.hello("t", ticket("bob", "t", Role::Member), "bob-laptop", None)
            .await,
    );
    let ops: Vec<String> = (0..3).map(|_| c.op()).collect();
    c.send(&ops[0], Some("t"), ClientMessage::DeviceKeys(bob.keys("t")))
        .await;
    c.send(&ops[1], Some("t"), bob.prove("t", &welcome)).await;
    c.send(&ops[2], Some("t"), presence()).await;
    for op in &ops {
        let r = c.answer(op).await;
        assert!(is_ack(&r), "{r:?}");
    }
}

#[tokio::test]
async fn a_pending_device_counts_from_its_admission_and_gets_its_proof_row_then() {
    let s = start_official().await;
    let (mut log, _alice, _a, bob, mut b) = team(&s).await;
    // Rows for the two proven devices of the log.
    assert_eq!(proof_rows(&s, &bob.holder).await, 1);
    let phone = Dev::new("bob", "bob-phone");
    // A version 2 connection of the phone, opened before its row exists.
    let mut legacy = Client::connect(s.addr).await;
    let w = welcome_of(
        legacy
            .hello_with(
                "t",
                ticket("bob", "t", Role::Member),
                "bob-phone",
                v2(),
                None,
            )
            .await,
    );
    assert_eq!((w.proto, w.challenge), (2, None));
    // Proven before its admission: the key is not in the log yet, no row, no intents.
    let mut p = Client::join_device(s.addr, "t", &phone, Role::Member).await;
    assert_eq!(proof_rows(&s, &phone.holder).await, 0);
    assert_eq!(
        code(&p.request("t", reserve(3)).await),
        Some(ErrorCode::Forbidden)
    );
    assert_eq!(
        code(&legacy.request("t", reserve(3)).await),
        Some(ErrorCode::Forbidden),
        "an unlisted device is restricted on version 2 as well"
    );
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    assert!(is_ack(&p.request("t", reserve(3)).await), "counts now");
    assert_eq!(proof_rows(&s, &phone.holder).await, 1);
    // The row closed the holder's version 2 connection; its next version 2 hello is refused.
    assert_eq!(legacy.close_code().await, Some(close::CLOSE_ROLE_CHANGED));
    let mut again = Client::connect(s.addr).await;
    let r = again
        .hello_with(
            "t",
            ticket("bob", "t", Role::Member),
            "bob-phone",
            v2(),
            None,
        )
        .await;
    assert_eq!(code(&r), Some(ErrorCode::OutdatedClient));
    // A proof with a key the log does not list writes no row.
    let stranger = Dev::new("bob", "bob-tablet");
    let _t = Client::join_device(s.addr, "t", &stranger, Role::Member).await;
    assert_eq!(proof_rows(&s, &stranger.holder).await, 0);
    // Removing the device drops its row: admitted again under the same IDs it starts fresh.
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    assert_eq!(proof_rows(&s, &phone.holder).await, 0);
    assert_eq!(
        code(&p.request("t", reserve(4)).await),
        Some(ErrorCode::Forbidden),
        "a removed device stops counting on its live connection"
    );
}

#[tokio::test]
async fn version_two_connections_follow_the_transition_rule() {
    let s = start_official().await;
    let mut log = Log::new("t");
    let alice = Dev::new("alice", "alice-laptop");
    let mut a = Client::join_device_with(s.addr, "t", &alice, Role::Owner, v2()).await;
    let create = log.create(&alice);
    assert!(is_ack(&append(&mut a, "t", &create).await));
    log.accept(&create, &alice.holder);
    // The listed device acts as today.
    assert!(is_ack(&a.request("t", presence()).await));
    assert!(is_ack(&a.request("t", reserve(1)).await));
    // An unlisted one may only register and read.
    let bob = Dev::new("bob", "bob-laptop");
    let mut b = Client::join_device_with(s.addr, "t", &bob, Role::Member, v2()).await;
    assert_eq!(
        code(&b.request("t", presence()).await),
        Some(ErrorCode::Forbidden)
    );
    let r = b.request("t", ClientMessage::DevicesGet).await;
    assert!(matches!(r.message, ServerMessage::Devices(_)), "{r:?}");
    let add = log.add_member(&alice, &bob, LogRole::Member);
    assert!(is_ack(&append(&mut a, "t", &add).await));
    log.accept(&add, &alice.holder);
    assert!(is_ack(&b.request("t", presence()).await), "listed now");
    // No version 3 connection proved anything: no rows.
    assert_eq!(proof_rows(&s, &alice.holder).await, 0);
}

#[tokio::test]
async fn required_proof_refuses_and_closes_older_versions() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.require_device_proof = true;
    let s = start(config).await;
    let mut c = Client::connect(s.addr).await;
    let r = c
        .hello_with("t", ticket("alice", "t", Role::Owner), "pc", v2(), None)
        .await;
    assert_eq!(code(&r), Some(ErrorCode::OutdatedClient));
    let w = welcome_of(
        c.hello("t", ticket("alice", "t", Role::Owner), "pc", None)
            .await,
    );
    assert_eq!(w.proto, 3);

    // Switched on at runtime: open version 2 connections close with 4401.
    let s = start_official().await;
    let mut old = Client::connect(s.addr).await;
    welcome_of(
        old.hello_with("t", ticket("bob", "t", Role::Member), "pc", v2(), None)
            .await,
    );
    let (mut new, _) = Client::join(s.addr, "t", "carol", Role::Member).await;
    s.server
        .state
        .relay
        .set_require_device_proof(true)
        .await
        .unwrap();
    assert_eq!(old.close_code().await, Some(close::CLOSE_ROLE_CHANGED));
    // A connection of version 3 stays open (drain needs its answer).
    drain(&mut new).await;
    let mut again = Client::connect(s.addr).await;
    let r = again
        .hello_with("t", ticket("bob", "t", Role::Member), "pc", v2(), None)
        .await;
    assert_eq!(code(&r), Some(ErrorCode::OutdatedClient));
}

#[tokio::test]
async fn a_twin_connection_without_proof_inherits_nothing() {
    let s = start_official().await;
    let (_log, _alice, mut a, bob, mut b) = team(&s).await;
    // The twin: same ticket subject and device ID as bob's proven connection.
    let (mut twin, _) = unproven(s.addr, "t", &bob, Role::Member).await;
    assert_eq!(
        code(&twin.request("t", presence()).await),
        Some(ErrorCode::Forbidden)
    );
    // No claim.overlap meant for the holder.
    assert!(is_ack(&b.request("t", claim("kb", 50)).await));
    assert!(is_ack(&a.request("t", claim("ka", 50)).await));
    b.until(|f| matches!(f.message, ServerMessage::ClaimOverlap(_)))
        .await;
    let seen = drain(&mut twin).await;
    assert!(
        seen.iter()
            .all(|f| !matches!(f.message, ServerMessage::ClaimOverlap(_))),
        "{seen:?}"
    );
    // The proven connection keeps its state.
    assert!(is_ack(&b.request("t", presence()).await));
    twin.close().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = drain(&mut a).await;
    assert!(
        seen.iter().all(|f| !matches!(
            &f.message,
            ServerMessage::PresenceUpdate(u) if u.state == PresenceState::Offline
        )),
        "the twin's close reports nothing: {seen:?}"
    );
    assert!(is_ack(&b.request("t", presence()).await));
}

#[tokio::test]
async fn a_twin_changes_no_deadline_and_gets_no_notify() {
    let s = start_official().await;
    let (_log, _alice, mut a, bob, mut b) = team(&s).await;
    assert!(is_ack(&b.request("t", reserve(7)).await));
    b.close().await;
    // Bob is offline: his hold runs out, the release request is kept as a notify.
    a.until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.expires_at.is_some()))
        .await;
    let request = ClientMessage::TaskReleaseRequest(TaskReleaseRequest {
        task: KeyedHash::from_bytes([7; 32]),
        note: None,
    });
    assert!(is_ack(&a.request("t", request).await));
    drain(&mut a).await;
    // The twin's hello and close neither stop the deadline nor report presence.
    let (mut twin, _) = unproven(s.addr, "t", &bob, Role::Member).await;
    let seen = drain(&mut twin).await;
    assert!(
        seen.iter()
            .all(|f| !matches!(f.message, ServerMessage::Notify(_))),
        "{seen:?}"
    );
    let seen = drain(&mut a).await;
    assert!(
        seen.iter().all(|f| !matches!(
            &f.message,
            ServerMessage::TaskReserved(_) | ServerMessage::PresenceUpdate(_)
        )),
        "the twin's hello changed something: {seen:?}"
    );
    twin.close().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = drain(&mut a).await;
    assert!(
        seen.iter()
            .all(|f| !matches!(f.message, ServerMessage::PresenceUpdate(_))),
        "the twin's close changed something: {seen:?}"
    );
    // The real device gets the notify once its proof passes, and stops the deadline.
    let mut back = Client::join_device(s.addr, "t", &bob, Role::Member).await;
    back.until(|f| matches!(f.message, ServerMessage::Notify(_)))
        .await;
    a.until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.expires_at.is_none()))
        .await;
}

#[tokio::test]
async fn key_wrapped_goes_only_to_connections_that_count() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let (rotate, secret) = log.rotate(&alice);
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyRotate(rotate.clone()))
            .await
    ));
    log.accept_rotation(&rotate, &alice.holder);
    let phone = Dev::new("bob", "bob-phone");
    let mut p = Client::join_device(s.addr, "t", &phone, Role::Member).await;
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    let (mut twin, _) = unproven(s.addr, "t", &phone, Role::Member).await;
    let wrap = log.wrap(&secret, &phone.holder);
    assert!(is_ack(&a.request("t", ClientMessage::KeyWrap(wrap)).await));
    p.until(|f| matches!(f.message, ServerMessage::KeyWrapped(_)))
        .await;
    let seen = drain(&mut twin).await;
    assert!(
        seen.iter()
            .all(|f| !matches!(f.message, ServerMessage::KeyWrapped(_))),
        "{seen:?}"
    );
}

#[tokio::test]
async fn blobs_are_deleted_by_their_author_an_owner_or_an_admin() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let carol = Dev::new("carol", "carol-pc");
    let mut c = Client::join_device(s.addr, "t", &carol, Role::Admin).await;
    let add = log.add_member(&alice, &carol, LogRole::Admin);
    assert!(is_ack(&append(&mut a, "t", &add).await));
    log.accept(&add, &alice.holder);
    let phone = Dev::new("bob", "bob-phone");
    let mut p = Client::join_device(s.addr, "t", &phone, Role::Member).await;
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    let db = s.server.state.relay.db.clone();
    let team_bytes = || async {
        sqlx::query_scalar::<_, i64>("SELECT blob_bytes FROM relay_teams WHERE id = 't'")
            .fetch_one(&db)
            .await
            .unwrap()
    };
    let member_bytes = |member: &'static str| {
        let db = db.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT COALESCE(SUM(size), 0) FROM relay_blobs WHERE member = ?",
            )
            .bind(member)
            .fetch_one(&db)
            .await
            .unwrap()
        }
    };

    // The author from another of its listed devices; the quota drops by the size.
    let first = put(&mut b, "t", 100).await;
    assert_eq!((team_bytes().await, member_bytes("bob").await), (100, 100));
    assert!(is_ack(&p.request("t", blob_delete(&first)).await));
    assert_eq!((team_bytes().await, member_bytes("bob").await), (0, 0));
    // Deleted before, unknown, or of another team: notFound.
    assert_eq!(
        code(&p.request("t", blob_delete(&first)).await),
        Some(ErrorCode::NotFound)
    );
    let unknown = BlobId::new("bm90LWEtYmxvYg").unwrap();
    assert_eq!(
        code(&a.request("t", blob_delete(&unknown)).await),
        Some(ErrorCode::NotFound)
    );
    let (mut elsewhere, _) = Client::join(s.addr, "u", "alice", Role::Owner).await;
    let foreign = put(&mut elsewhere, "u", 10).await;
    assert_eq!(
        code(&a.request("t", blob_delete(&foreign)).await),
        Some(ErrorCode::NotFound)
    );
    // An owner and an admin delete anyone's blob.
    for deleter in [&mut a, &mut c] {
        let blob = put(&mut b, "t", 10).await;
        assert!(is_ack(&deleter.request("t", blob_delete(&blob)).await));
    }
    // A member who is not the author may not.
    let alices = put(&mut a, "t", 20).await;
    assert_eq!(
        code(&b.request("t", blob_delete(&alices)).await),
        Some(ErrorCode::Forbidden)
    );
    // The author on a device the log does not list may not.
    let tablet = Dev::new("bob", "bob-tablet");
    let mut t = Client::join_device(s.addr, "t", &tablet, Role::Member).await;
    let bobs = put(&mut b, "t", 30).await;
    assert_eq!(
        code(&t.request("t", blob_delete(&bobs)).await),
        Some(ErrorCode::Forbidden)
    );
    // The lower of log and ticket role: an admin with a member ticket, a member with an admin
    // ticket, and a member the log does not name with an admin ticket.
    let mut demoted = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    let mut promoted = Client::join_device(s.addr, "t", &bob, Role::Admin).await;
    let dave = Dev::new("dave", "dave-pc");
    let mut stranger = Client::join_device(s.addr, "t", &dave, Role::Admin).await;
    for (who, client) in [
        ("demoted admin", &mut demoted),
        ("member with an admin ticket", &mut promoted),
        ("unlisted member", &mut stranger),
    ] {
        let r = client.request("t", blob_delete(&alices)).await;
        assert_eq!(code(&r), Some(ErrorCode::Forbidden), "{who}: {r:?}");
    }
    assert_eq!(
        team_bytes().await,
        50,
        "nothing deleted by the refused ones"
    );

    // A retry with the same op ID gets the first ack.
    let op = b.op();
    b.send(&op, Some("t"), blob_delete(&bobs)).await;
    assert!(is_ack(&b.answer(&op).await));
    b.send(&op, Some("t"), blob_delete(&bobs)).await;
    assert!(is_ack(&b.answer(&op).await), "the remembered answer");
    assert_eq!(team_bytes().await, 20);

    // Two deletes at once: one wins, the quota stays right.
    let raced = put(&mut b, "t", 40).await;
    let (op_a, op_c) = (a.op(), c.op());
    a.send(&op_a, Some("t"), blob_delete(&raced)).await;
    c.send(&op_c, Some("t"), blob_delete(&raced)).await;
    let answers = [a.answer(&op_a).await, c.answer(&op_c).await];
    assert_eq!(
        answers.iter().filter(|f| is_ack(f)).count(),
        1,
        "{answers:?}"
    );
    assert_eq!(
        answers
            .iter()
            .filter(|f| code(f) == Some(ErrorCode::NotFound))
            .count(),
        1
    );
    assert_eq!(team_bytes().await, 20);
    assert_eq!(member_bytes("alice").await, 30, "20 in t, 10 in u");
}

#[tokio::test]
async fn blob_delete_needs_version_three() {
    let s = start_official().await;
    let (mut c, _) = Client::join(s.addr, "solo", "alice", Role::Owner).await;
    let blob = put(&mut c, "solo", 5).await;
    let mut old = Client::connect(s.addr).await;
    welcome_of(
        old.hello_with(
            "solo",
            ticket("alice", "solo", Role::Owner),
            "old",
            v2(),
            None,
        )
        .await,
    );
    assert_eq!(
        code(&old.request("solo", blob_delete(&blob)).await),
        Some(ErrorCode::BadRequest)
    );
    let r = old
        .request(
            "solo",
            ClientMessage::DeviceProve(Dev::new("alice", "old").identity.prove_connection(
                &team_id("solo"),
                &holder("alice", "old"),
                2,
                &Challenge::from_bytes([0; 32]),
            )),
        )
        .await;
    assert_eq!(code(&r), Some(ErrorCode::BadRequest));
    // A team without a log restricts nothing: the author deletes on version 3.
    assert!(is_ack(&c.request("solo", blob_delete(&blob)).await));
}
