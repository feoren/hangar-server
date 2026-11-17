//! E2E foundation with hangar-team-crypto (b30b9d5): the relay checks every log entry with the
//! `LogVerifier`, rotation and device removal only with a signed entry and atomically, key
//! packages per `relay::check_wrap`, proof of possession and device limits.

mod common;

use common::*;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::relay::team::close;
use hangar_server::ticket::Role;
use hangar_server::wire::{Role as LogRole, *};
use hangar_team_crypto::memberlog::LogVerifier;

fn code(frame: &ServerFrame) -> Option<ErrorCode> {
    match &frame.message {
        ServerMessage::Err(e) => Some(e.code),
        _ => None,
    }
}

fn is_ack(frame: &ServerFrame) -> bool {
    matches!(frame.message, ServerMessage::Ack(_))
}

async fn append(c: &mut Client, team: &str, entry: &MemberLogAppend) -> ServerFrame {
    c.request(team, ClientMessage::MemberLogAppend(entry.clone()))
        .await
}

async fn log_len(c: &mut Client, team: &str) -> usize {
    let ServerMessage::MemberLogEntries(page) = c
        .request(team, ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
        .await
        .message
    else {
        panic!("no entries")
    };
    page.entries.len()
}

/// Team `t` with alice (owner) and bob (member), both with keys and in the log.
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
async fn invalid_entries_are_rejected_and_block_nothing() {
    let s = start_official().await;
    // Entry 1 only with an owner ticket.
    let mut early = Log::new("t2");
    let eve = Dev::new("eve", "eve-pc");
    let mut e = Client::join_device(s.addr, "t2", &eve, Role::Admin).await;
    assert_eq!(
        code(&append(&mut e, "t2", &early.create(&eve)).await),
        Some(ErrorCode::Forbidden)
    );
    let _ = &mut early;

    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let carol = Dev::new("carol", "carol-pc");
    // Keys never registered over the sender's own connection: forbidden.
    let unregistered = log.add_member(&alice, &carol, LogRole::Member);
    assert_eq!(
        code(&append(&mut a, "t", &unregistered).await),
        Some(ErrorCode::Forbidden)
    );
    // A member may not add members.
    let mut c = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    let by_member = log.add_member(&bob, &carol, LogRole::Member);
    assert_eq!(
        code(&append(&mut b, "t", &by_member).await),
        Some(ErrorCode::Forbidden)
    );
    // Signed by alice but sent by bob: not the sender.
    let foreign = log.add_member(&alice, &carol, LogRole::Member);
    assert!(code(&append(&mut b, "t", &foreign).await).is_some());
    // Rotation and device removal never via memberlog.append.
    let (rotate, _) = log.rotate(&alice);
    assert_eq!(
        code(&append(&mut a, "t", &rotate.log).await),
        Some(ErrorCode::BadRequest)
    );
    let removal = log.remove_device(&alice, &bob.holder);
    assert_eq!(
        code(&append(&mut a, "t", &removal.log).await),
        Some(ErrorCode::BadRequest)
    );
    // None of it was stored, and the next valid entry goes through.
    assert_eq!(log_len(&mut a, "t").await, 2);
    let ok = log.add_member(&alice, &carol, LogRole::Member);
    assert!(is_ack(&append(&mut a, "t", &ok).await));
    log.accept(&ok, &alice.holder);
    let appended = c
        .until(|f| matches!(f.message, ServerMessage::MemberLogAppended(_)))
        .await;
    assert!(appended.seq.is_some());
    assert_eq!(log_len(&mut a, "t").await, 3);
}

#[tokio::test]
async fn effective_role_is_the_lower_one() {
    let s = start_official().await;
    let (log, alice, a, _bob, _b) = team(&s).await;
    a.close().await;
    // alice is owner in the log, but her ticket says member (the website downgraded her).
    let mut a = Client::connect(s.addr).await;
    let w = a
        .hello(
            "t",
            ticket("alice", "t", Role::Member),
            "alice-laptop",
            None,
        )
        .await;
    assert!(matches!(w.message, ServerMessage::Welcome(_)));
    let carol = Dev::new("carol", "carol-pc");
    let _c = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    let add = log.add_member(&alice, &carol, LogRole::Member);
    assert_eq!(
        code(&append(&mut a, "t", &add).await),
        Some(ErrorCode::Forbidden)
    );
    let (rotate, _) = log.rotate(&alice);
    let r = a.request("t", ClientMessage::KeyRotate(rotate)).await;
    assert_eq!(code(&r), Some(ErrorCode::Forbidden));
}

#[tokio::test]
async fn rotation_is_atomic() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let (rotate, _) = log.rotate(&alice);
    // A package for a device unknown to the log: rejected, neither entry nor epoch.
    let mut bad = rotate.clone();
    let mut stranger = bad.wrapped[0].clone();
    stranger.holder = holder("nobody", "nowhere");
    bad.wrapped.push(stranger);
    assert!(code(&a.request("t", ClientMessage::KeyRotate(bad)).await).is_some());
    assert_eq!(log_len(&mut a, "t").await, 2);
    let none = b
        .request("t", ClientMessage::KeyGet(KeyGet { epoch: Epoch(1) }))
        .await;
    assert_eq!(code(&none), Some(ErrorCode::NotFound));
    // Wrong epoch in the envelope.
    let mut wrong = rotate.clone();
    wrong.epoch = Epoch(2);
    assert_eq!(
        code(&a.request("t", ClientMessage::KeyRotate(wrong)).await),
        Some(ErrorCode::StaleEpoch)
    );
    // The correct rotation: entry and packages together.
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyRotate(rotate.clone()))
            .await
    ));
    log.accept_rotation(&rotate, &alice.holder);
    b.until(|f| matches!(f.message, ServerMessage::MemberLogAppended(_)))
        .await;
    let rotated = b
        .until(|f| matches!(f.message, ServerMessage::KeyRotated(_)))
        .await;
    let ServerMessage::KeyRotated(r) = rotated.message else {
        unreachable!()
    };
    let mine = rotate
        .wrapped
        .iter()
        .find(|w| w.holder == bob.holder)
        .unwrap();
    assert_eq!(r.wrapped.as_ref(), Some(&mine.data), "only its own package");
    let got = b
        .request("t", ClientMessage::KeyGet(KeyGet { epoch: Epoch(1) }))
        .await;
    let ServerMessage::Ack(ack) = got.message else {
        panic!("{got:?}")
    };
    assert_eq!(ack.keys.map(|k| k.len()), Some(1));
    assert_eq!(log_len(&mut a, "t").await, 3);
}

#[tokio::test]
async fn key_packages_follow_the_log_rules() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let (rotate, secret) = log.rotate(&alice);
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyRotate(rotate.clone()))
            .await
    ));
    log.accept_rotation(&rotate, &alice.holder);
    // More devices: bob-phone (target), alice-phone, alice-tablet, bob-tablet (senders).
    let mut devs = Vec::new();
    for (owner_dev, name, role) in [
        (&bob, "bob-phone", Role::Member),
        (&alice, "alice-phone", Role::Owner),
        (&alice, "alice-tablet", Role::Owner),
        (&bob, "bob-tablet", Role::Member),
    ] {
        let member = owner_dev.holder.member.as_str().to_owned();
        let dev = Dev::new(&member, name);
        let client = Client::join_device(s.addr, "t", &dev, role).await;
        let add = log.add_device(owner_dev, &dev);
        let sender = if member == "alice" { &mut a } else { &mut b };
        assert!(is_ack(&append(sender, "t", &add).await));
        log.accept(&add, &owner_dev.holder);
        devs.push((dev, client));
    }
    let (phone, mut phone_c) = devs.remove(0);
    let wrap = log.wrap(&secret, &phone.holder);
    // Never for itself.
    assert_eq!(
        code(
            &phone_c
                .request("t", ClientMessage::KeyWrap(wrap.clone()))
                .await
        ),
        Some(ErrorCode::Forbidden)
    );
    // Owner for any device, the member for another device of its own; one per sender.
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyWrap(wrap.clone())).await
    ));
    let wrapped = phone_c
        .until(|f| matches!(f.message, ServerMessage::KeyWrapped(_)))
        .await;
    assert!(
        wrapped.seq.is_none(),
        "key.wrapped does not go into the log"
    );
    assert_eq!(
        code(&a.request("t", ClientMessage::KeyWrap(wrap.clone())).await),
        Some(ErrorCode::Conflict)
    );
    assert!(is_ack(
        &b.request(
            "t",
            ClientMessage::KeyWrap(log.wrap(&secret, &phone.holder))
        )
        .await
    ));
    let (_alice_phone, mut ap) = devs.remove(0);
    let (_alice_tablet, mut at) = devs.remove(0);
    let (_bob_tablet, mut bt) = devs.remove(0);
    assert!(is_ack(
        &ap.request(
            "t",
            ClientMessage::KeyWrap(log.wrap(&secret, &phone.holder))
        )
        .await
    ));
    assert!(is_ack(
        &at.request(
            "t",
            ClientMessage::KeyWrap(log.wrap(&secret, &phone.holder))
        )
        .await
    ));
    // At most four packages per target and epoch.
    assert_eq!(
        code(
            &bt.request(
                "t",
                ClientMessage::KeyWrap(log.wrap(&secret, &phone.holder))
            )
            .await
        ),
        Some(ErrorCode::Limit)
    );
    // Unknown target.
    let mut unknown = wrap.clone();
    unknown.wrapped.holder = holder("bob", "does-not-exist");
    assert_eq!(
        code(&a.request("t", ClientMessage::KeyWrap(unknown)).await),
        Some(ErrorCode::NotFound)
    );
    // key.get returns all packages.
    let got = phone_c
        .request("t", ClientMessage::KeyGet(KeyGet { epoch: Epoch(1) }))
        .await;
    let ServerMessage::Ack(ack) = got.message else {
        panic!("{got:?}")
    };
    assert_eq!(ack.keys.map(|k| k.len()), Some(4));
}

#[tokio::test]
async fn removing_a_device_requires_a_signed_entry() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let phone = Dev::new("bob", "bob-phone");
    let mut p = Client::join_device(s.addr, "t", &phone, Role::Member).await;
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    let reserve = ClientMessage::TaskReserve(TaskReserve {
        task: KeyedHash::from_bytes([4; 32]),
        epoch: Epoch(0),
        prev: Vec::new(),
        note: None,
    });
    assert!(is_ack(&p.request("t", reserve).await));
    // Without a valid entry: badRequest.
    let bare = DeviceRemove {
        holder: phone.holder.clone(),
        log: dummy_log(),
    };
    assert!(code(&b.request("t", ClientMessage::DeviceRemove(bare)).await).is_some());
    // A device unknown to the log: badRequest.
    let ghost = log.remove_device(&alice, &holder("bob", "does-not-exist"));
    assert!(code(&a.request("t", ClientMessage::DeviceRemove(ghost)).await).is_some());
    // bob-laptop removes bob-phone with a signed entry.
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    log.accept_removal(&removal, &bob.holder);
    a.until(|f| matches!(f.message, ServerMessage::MemberLogAppended(_)))
        .await;
    let released = a
        .until(|f| matches!(&f.message, ServerMessage::TaskReleased(r) if r.task == KeyedHash::from_bytes([4; 32])))
        .await;
    assert!(released.seq.is_some());
    let removed = a
        .until(|f| matches!(f.message, ServerMessage::DeviceRemoved(_)))
        .await;
    assert!(removed.seq.is_some());
    assert_eq!(p.close_code().await, Some(close::CLOSE_REMOVED));
    // After that only the grace period remains (separate tests below), and devices omits it.
    let mut again = Client::connect(s.addr).await;
    let welcome = again
        .hello("t", ticket("bob", "t", Role::Member), "bob-phone", None)
        .await;
    assert!(matches!(welcome.message, ServerMessage::Welcome(_)));
    assert_eq!(again.close_code().await, Some(close::CLOSE_REMOVED));
    let ServerMessage::Devices(list) = a.request("t", ClientMessage::DevicesGet).await.message
    else {
        panic!()
    };
    assert!(list.devices.iter().all(|d| d.holder != phone.holder));
    assert!(
        list.devices
            .iter()
            .all(|d| d.proof.to_base64url().len() == 86),
        "proof of possession listed"
    );
}

/// Team `t` with alice, bob (bob-laptop) and bob-phone in the log; bob-phone holds a
/// reservation. Also returns the connection of bob-phone.
async fn team_with_phone(s: &TestServer) -> (Log, Dev, Client, Dev, Client, Dev, Client) {
    let (mut log, alice, a, bob, mut b) = team(s).await;
    let phone = Dev::new("bob", "bob-phone");
    let mut p = Client::join_device(s.addr, "t", &phone, Role::Member).await;
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    let reserve = ClientMessage::TaskReserve(TaskReserve {
        task: KeyedHash::from_bytes([4; 32]),
        epoch: Epoch(0),
        prev: Vec::new(),
        note: None,
    });
    assert!(is_ack(&p.request("t", reserve).await));
    (log, alice, a, bob, b, phone, p)
}

fn reserve_task(byte: u8) -> ClientMessage {
    ClientMessage::TaskReserve(TaskReserve {
        task: KeyedHash::from_bytes([byte; 32]),
        epoch: Epoch(0),
        prev: Vec::new(),
        note: None,
    })
}

fn grace_config(ms: u64) -> Config {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.removed_grace_ms = ms;
    config
}

/// A page of the log, as the app checks it with a fresh `LogVerifier`.
fn entries_of(frame: ServerFrame) -> MemberLogEntries {
    match frame.message {
        ServerMessage::MemberLogEntries(page) => page,
        other => panic!("no entries: {other:?}"),
    }
}

#[tokio::test]
async fn removed_device_reads_log_up_to_removal_then_4403() {
    let s = start(grace_config(5_000)).await;
    let (mut log, _alice, _a, bob, mut b, phone, mut p) = team_with_phone(&s).await;
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    log.accept_removal(&removal, &bob.holder);
    let removed_at = log.state().head().index;
    // The device only gets memberlog.appended and its device.removed, no team data (the
    // release of its reservation goes to the others), and both without seq: with seq the app
    // would see a gap at the skipped release and abort before checking the log.
    loop {
        let frame = p.recv().await.expect("frame before the grace period ends");
        assert!(
            frame.seq.is_none(),
            "frame with seq during the grace period: {frame:?}"
        );
        match &frame.message {
            ServerMessage::MemberLogAppended(m) => assert_eq!(m.index, removed_at),
            ServerMessage::DeviceRemoved(r) => {
                assert_eq!(r.holder, phone.holder);
                break;
            }
            other => panic!("removed device got {other:?}"),
        }
    }
    // During the grace period everything except memberlog.get is rejected and writes nothing.
    assert_eq!(
        code(&p.request("t", reserve_task(9)).await),
        Some(ErrorCode::Forbidden)
    );
    assert_eq!(
        code(&p.request("t", ClientMessage::DevicesGet).await),
        Some(ErrorCode::Forbidden)
    );
    assert_eq!(
        code(
            &p.request("t", ClientMessage::DeviceKeys(phone.keys("t")))
                .await
        ),
        Some(ErrorCode::Forbidden)
    );
    assert!(
        is_ack(&b.request("t", reserve_task(9)).await),
        "nothing reserved"
    );
    // memberlog.get: the log up to the removal, verifiable as in the app; then 4403.
    let page = entries_of(
        p.request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
            .await,
    );
    assert!(!page.more);
    assert_eq!(page.entries.last().map(|e| e.index), Some(removed_at));
    let mut check = LogVerifier::new(team_id("t"));
    check.apply_all(&page.entries).expect("log verifiable");
    assert!(check.state().unwrap().device(&phone.holder).is_none());
    let started = std::time::Instant::now();
    assert_eq!(p.close_code().await, Some(close::CLOSE_REMOVED));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "4403 right after the reply, not only after the grace period"
    );
}

#[tokio::test]
async fn grace_period_without_memberlog_get_ends_with_4403() {
    let s = start(grace_config(300)).await;
    let (log, _alice, _a, bob, mut b, phone, mut p) = team_with_phone(&s).await;
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    p.until(|f| matches!(f.message, ServerMessage::DeviceRemoved(_)))
        .await;
    let started = std::time::Instant::now();
    assert_eq!(p.close_code().await, Some(close::CLOSE_REMOVED));
    let waited = started.elapsed();
    assert!(
        waited >= std::time::Duration::from_millis(150),
        "closed too early: {waited:?}"
    );
}

#[tokio::test]
async fn hello_from_removed_device_only_gets_log_up_to_removal() {
    let s = start(grace_config(5_000)).await;
    let (mut log, _alice, mut a, bob, mut b, phone, p) = team_with_phone(&s).await;
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    log.accept_removal(&removal, &bob.holder);
    let removed_at = log.state().head().index;
    // The connection was already gone (app closed) before it could read the log.
    p.close().await;
    // A later entry (new device) stays hidden from the removed device.
    let tablet = Dev::new("bob", "bob-tablet");
    let _t = Client::join_device(s.addr, "t", &tablet, Role::Member).await;
    let add = log.add_device(&bob, &tablet);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    // Drain everything sent to alice so far (including the earlier presence of bob-phone).
    a.request("t", ClientMessage::DevicesGet).await;
    let mut again = Client::connect(s.addr).await;
    let op = again.op();
    again
        .send(
            &op,
            Some("t"),
            ClientMessage::Hello(Hello {
                ticket: Ticket::new(ticket("bob", "t", Role::Member)).unwrap(),
                device: device("bob-phone"),
                proto: ProtoRange::CURRENT,
                last_seq: None,
            }),
        )
        .await;
    // Only welcome: no snapshot, no reservations, no presence.
    let first = again.recv().await.expect("reply to hello");
    assert!(
        matches!(first.message, ServerMessage::Welcome(_)),
        "{:?}",
        first.message
    );
    for message in [
        ClientMessage::DeviceKeys(phone.keys("t")),
        reserve_task(10),
        ClientMessage::DevicesGet,
        ClientMessage::PresenceSet(PresenceSet {
            state: PresenceState::Active,
            status: None,
        }),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("bob", "t", Role::Member)).unwrap(),
            device: device("bob-phone"),
            proto: ProtoRange::CURRENT,
            last_seq: None,
        }),
    ] {
        let op = again.op();
        again.send(&op, Some("t"), message).await;
        let answer = again.recv().await.expect("reply during the grace period");
        assert_eq!(answer.id.as_ref().map(|i| i.as_str()), Some(op.as_str()));
        assert_eq!(code(&answer), Some(ErrorCode::Forbidden));
    }
    let page = entries_of(
        again
            .request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
            .await,
    );
    assert!(!page.more);
    assert_eq!(page.entries.last().map(|e| e.index), Some(removed_at));
    let mut check = LogVerifier::new(team_id("t"));
    check.apply_all(&page.entries).expect("log verifiable");
    assert!(check.state().unwrap().device(&phone.holder).is_none());
    assert_eq!(again.close_code().await, Some(close::CLOSE_REMOVED));
    // Nothing written: no keys, no reservation, not among the devices.
    assert!(is_ack(&b.request("t", reserve_task(10)).await));
    // Up to the reply to devices.get alice received nothing about the removed device
    // (no presence, no join): everything before that arrived before the hello.
    let op = a.op();
    a.send(&op, Some("t"), ClientMessage::DevicesGet).await;
    let list = loop {
        let frame = a.recv().await.expect("reply to devices.get");
        match frame.message {
            ServerMessage::Devices(list) if frame.id.as_ref().map(|i| i.as_str()) == Some(&op) => {
                break list
            }
            ServerMessage::PresenceUpdate(u) => assert_ne!(u.holder, phone.holder),
            ServerMessage::MemberJoined(_) => panic!("join reported"),
            _ => {}
        }
    };
    assert!(list.devices.iter().all(|d| d.holder != phone.holder));

    // Blocks from before migration 0010 (without log_index): the last entry up to the block.
    sqlx::query("UPDATE relay_removed_devices SET log_index = NULL")
        .execute(&s.server.state.relay.db)
        .await
        .unwrap();
    let mut old = Client::connect(s.addr).await;
    let welcome = old
        .hello("t", ticket("bob", "t", Role::Member), "bob-phone", None)
        .await;
    assert!(matches!(welcome.message, ServerMessage::Welcome(_)));
    let page = entries_of(
        old.request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
            .await,
    );
    assert_eq!(page.entries.last().map(|e| e.index), Some(removed_at));
    assert_eq!(old.close_code().await, Some(close::CLOSE_REMOVED));
}

#[tokio::test]
async fn removing_a_member_closes_its_devices() {
    let s = start_official().await;
    let (mut log, alice, mut a, _bob, mut b) = team(&s).await;
    let remove = log.remove_member(&alice, "bob");
    let op = a.op();
    a.send(
        &op,
        Some("t"),
        ClientMessage::MemberLogAppend(remove.clone()),
    )
    .await;
    // The events go to everyone, including the triggering connection, before the ack.
    let removed = a
        .until(|f| matches!(f.message, ServerMessage::DeviceRemoved(_)))
        .await;
    assert!(removed.seq.is_some());
    let ServerMessage::DeviceRemoved(r) = removed.message else {
        unreachable!()
    };
    assert_eq!(r.holder, holder("bob", "bob-laptop"));
    assert!(is_ack(&a.answer(&op).await));
    log.accept(&remove, &alice.holder);
    assert_eq!(b.close_code().await, Some(close::CLOSE_REMOVED));
}

#[tokio::test]
async fn restart_rebuilds_the_verified_log() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut log, alice, a, _bob, b) = team(&s).await;
    a.close().await;
    b.close().await;
    let _ = s.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let s2 = start(config).await;
    // The next entry only fits if the relay rebuilt the log with apply_all.
    let mut a = Client::join_device(s2.addr, "t", &alice, Role::Owner).await;
    let carol = Dev::new("carol", "carol-pc");
    let _c = Client::join_device(s2.addr, "t", &carol, Role::Member).await;
    let add = log.add_member(&alice, &carol, LogRole::Admin);
    assert!(is_ack(&append(&mut a, "t", &add).await));
    log.accept(&add, &alice.holder);
    assert_eq!(log_len(&mut a, "t").await, 3);
}

#[tokio::test]
async fn at_most_sixteen_devices_per_member() {
    let s = start_official().await;
    for i in 0..16 {
        let dev = Dev::new("many", &format!("device-{i}"));
        let _c = Client::join_device(s.addr, "t", &dev, Role::Member).await;
    }
    let extra = Dev::new("many", "device-16");
    let mut c = Client::connect(s.addr).await;
    assert!(matches!(
        c.hello("t", ticket("many", "t", Role::Member), "device-16", None)
            .await
            .message,
        ServerMessage::Welcome(_)
    ));
    let r = c
        .request("t", ClientMessage::DeviceKeys(extra.keys("t")))
        .await;
    assert_eq!(code(&r), Some(ErrorCode::Limit));
}

#[tokio::test]
async fn storing_encrypted_content() {
    let s = start_official().await;
    let (_log, _alice, mut a, _bob, mut b) = team(&s).await;
    let put = a
        .request(
            "t",
            ClientMessage::BlobPut(BlobPut {
                kind: BlobKind::Decision,
                content: Sealed {
                    epoch: Epoch(0),
                    data: cipher("YWJj"),
                },
            }),
        )
        .await;
    let ServerMessage::Ack(Ack { blob: Some(id), .. }) = put.message else {
        panic!("{put:?}")
    };
    let got = b
        .request("t", ClientMessage::BlobGet(BlobGet { blob: id }))
        .await;
    let ServerMessage::Ack(Ack {
        content: Some(content),
        ..
    }) = got.message
    else {
        panic!()
    };
    assert_eq!(content.data.as_str(), "YWJj");
}
