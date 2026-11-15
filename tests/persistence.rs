//! Restart, durability rule, `notify` and `device.remove` against protocol crate 525a8c7.

mod common;

use common::*;
use hangar_team_server::config::{Config, IdentityMode};
use hangar_team_server::ticket::Role;
use hangar_team_server::util::now_ms;
use hangar_team_server::wire::*;

fn h(b: u8) -> KeyedHash {
    KeyedHash::from_bytes([b; 32])
}

fn reserve(task: KeyedHash) -> ClientMessage {
    ClientMessage::TaskReserve(TaskReserve {
        task,
        epoch: Epoch(0),
        prev: Vec::new(),
        note: None,
    })
}

fn code(frame: &ServerFrame) -> Option<ErrorCode> {
    match &frame.message {
        ServerMessage::Err(e) => Some(e.code),
        _ => None,
    }
}

fn is_ack(frame: &ServerFrame) -> bool {
    matches!(frame.message, ServerMessage::Ack(_))
}

/// Stored log position of a team, read directly from the database.
async fn stored_head(s: &TestServer, team: &str) -> u64 {
    let position: String =
        sqlx::query_scalar("SELECT position FROM relay_team_state WHERE team_id = ?")
            .bind(team)
            .fetch_one(&s.server.state.relay.db)
            .await
            .unwrap();
    let cursor: Cursor = serde_json::from_str(&position).unwrap();
    cursor.seq.0
}

/// Stops the first process (timers and connections closed) and starts a second one on the same data.
async fn restart(first: TestServer, config: Config) -> TestServer {
    let _ = first.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    start(config).await
}

#[tokio::test]
async fn restart_preserves_stream_reservations_and_deadlines() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    assert!(is_ack(&a.request("t", reserve(h(3))).await));
    assert!(is_ack(
        &b.request(
            "t",
            ClientMessage::TaskReleaseRequest(TaskReleaseRequest {
                task: h(3),
                note: None
            })
        )
        .await
    ));
    let seen = a
        .until(|f| matches!(f.message, ServerMessage::TaskReleaseRequested(_)))
        .await;
    let cursor = Cursor {
        stream: welcome.stream.clone(),
        seq: seen.seq.expect("logged"),
    };
    a.close().await;
    b.close().await;

    let before = now_ms();
    let s2 = restart(s, config).await;
    // Alice returns with her cursor. The stream continues (no `otherStream`); since her
    // disconnect and the restart itself produced events after her cursor that only lived in the
    // first process's window, she gets `tooOld` and a snapshot. In it she still holds the task
    // and the grace period is running (everyone counts as disconnected after the restart).
    let mut a = Client::connect(s2.addr).await;
    let op = a.op();
    a.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("alice", "t", Role::Owner)).unwrap(),
            device: device("alice-device"),
            proto: ProtoRange::CURRENT,
            last_seq: Some(cursor.clone()),
        }),
    )
    .await;
    let mut expires = None;
    let welcome = loop {
        let f = a.recv().await.expect("reply to hello");
        match &f.message {
            ServerMessage::ResyncRequired(r) => {
                assert_eq!(r.stream, cursor.stream, "the stream continues");
                assert_eq!(r.reason, ResyncReason::TooOld);
            }
            ServerMessage::TaskReserved(r) if r.task == h(3) => {
                assert_eq!(r.holder.member, member("alice"));
                expires = r.expires_at;
            }
            ServerMessage::Welcome(w) => break w.clone(),
            _ => {}
        }
    };
    assert_eq!(welcome.stream, cursor.stream);
    assert!(welcome.head > cursor.seq);
    let expires = expires.expect("grace period runs after the restart").0;
    assert!(
        expires >= before + 5 * 60 * 1000,
        "at least the warning time"
    );

    // The open release request survived the restart (snapshot of a new device).
    let mut c = Client::connect(s2.addr).await;
    let op = c.op();
    c.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("carol", "t", Role::Member)).unwrap(),
            device: device("carol-device"),
            proto: ProtoRange::CURRENT,
            last_seq: None,
        }),
    )
    .await;
    let mut saw_request = false;
    loop {
        let f = c.recv().await.expect("Snapshot");
        saw_request |=
            matches!(&f.message, ServerMessage::TaskReleaseRequested(r) if r.task == h(3));
        if matches!(f.message, ServerMessage::Welcome(_)) {
            break;
        }
    }
    assert!(saw_request);
    // And "first wins" still holds.
    let (mut b, _) = Client::join(s2.addr, "t", "bob", Role::Member).await;
    assert_eq!(
        code(&b.request("t", reserve(h(3))).await),
        Some(ErrorCode::Conflict)
    );
}

#[tokio::test]
async fn no_seq_ahead_of_the_stored_head() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    for round in 0..10u8 {
        let op = a.op();
        a.send(&op, Some("t"), reserve(h(round))).await;
        // Every frame with a seq that Bob sees is already persisted.
        let seen = b.until(|f| f.seq.is_some()).await;
        let seq = seen.seq.unwrap().0;
        assert!(
            stored_head(&s, "t").await >= seq,
            "round {round}: seq {seq} ahead of the stored head"
        );
        a.answer(&op).await;
    }
}

#[tokio::test]
async fn notify_after_the_next_welcome() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut bob, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    assert!(is_ack(&bob.request("t", reserve(h(9))).await));
    bob.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let (mut alice, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let note = Sealed {
        epoch: Epoch(0),
        data: cipher("Yml0dGU"),
    };
    let req = alice
        .request(
            "t",
            ClientMessage::TaskReleaseRequest(TaskReleaseRequest {
                task: h(9),
                note: Some(note.clone()),
            }),
        )
        .await;
    assert!(is_ack(&req));
    alice.close().await;

    // Persisted: it is delivered even after a restart.
    let s2 = restart(s, config).await;
    let (mut bob, _) = Client::join(s2.addr, "t", "bob", Role::Member).await;
    let notify = bob
        .until(|f| matches!(f.message, ServerMessage::Notify(_)))
        .await;
    assert!(notify.seq.is_none(), "notify is never logged");
    let ServerMessage::Notify(n) = notify.message else {
        unreachable!()
    };
    assert_eq!(n.member, member("bob"));
    assert_eq!(n.topic, NotifyTopic::Attention);
    assert_eq!(n.content, Some(note), "carries the request's note");
    // Delivered means deleted.
    let mut left = 1i64;
    for _ in 0..20 {
        left = sqlx::query_scalar("SELECT COUNT(*) FROM relay_pending_notify")
            .fetch_one(&s2.server.state.relay.db)
            .await
            .unwrap();
        if left == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(left, 0);
}

#[tokio::test]
async fn client_at_the_stored_head_needs_no_snapshot() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    // member.joined is the only logged event; disconnecting without a reservation logs nothing.
    let joined = a
        .until(|f| matches!(f.message, ServerMessage::MemberJoined(_)))
        .await;
    let head = joined.seq.expect("logged").0;
    assert_eq!(stored_head(&s, "t").await, head);
    a.close().await;
    let s2 = restart(s, config).await;
    let mut a = Client::connect(s2.addr).await;
    let cursor = Cursor {
        stream: welcome.stream.clone(),
        seq: Seq(head),
    };
    let op = a.op();
    a.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("alice", "t", Role::Owner)).unwrap(),
            device: device("alice-device"),
            proto: ProtoRange::CURRENT,
            last_seq: Some(cursor),
        }),
    )
    .await;
    let first = a.recv().await.unwrap();
    let ServerMessage::Welcome(w) = first.message else {
        panic!("expected welcome without snapshot: {first:?}")
    };
    assert_eq!(w.stream, welcome.stream);
    assert_eq!(w.head, Seq(head));
}

/// A removed device reads the log only up to the removing entry, also when paged, with any
/// `after`, and for removals predating migration 0010 (`log_index` NULL).
#[tokio::test]
async fn removed_device_log_ends_at_the_removing_entry() {
    use hangar_team_server::relay::store;
    let s = start_official().await;
    let db = &s.server.state.relay.db;
    sqlx::query("INSERT INTO relay_teams (id, stream, created_at) VALUES ('z', 's', 0)")
        .execute(db)
        .await
        .unwrap();
    for idx in 1..=7i64 {
        sqlx::query(
            "INSERT INTO relay_member_log (team_id, idx, hash, entry, member, device, created_at) \
             VALUES ('z', ?, ?, 'AAAA', 'm', 'd', ?)",
        )
        .bind(idx)
        .bind("ab".repeat(32))
        .bind(idx * 10)
        .execute(db)
        .await
        .unwrap();
    }
    for (device, removed_at, index) in [
        ("recent", 40i64, Some(4i64)),
        ("legacy", 55, None),
        ("early", 5, None),
    ] {
        sqlx::query(
            "INSERT INTO relay_removed_devices (team_id, member, device, removed_at, by_member, log_index) \
             VALUES ('z', 'm', ?, ?, 'm', ?)",
        )
        .bind(device)
        .bind(removed_at)
        .bind(index)
        .execute(db)
        .await
        .unwrap();
    }
    assert_eq!(
        store::device_removed(db, "z", "m", "recent").await.unwrap(),
        Some(4)
    );
    // Without log_index: the last entry up to the removal, or 0 if there is none (empty log).
    assert_eq!(
        store::device_removed(db, "z", "m", "legacy").await.unwrap(),
        Some(5)
    );
    assert_eq!(
        store::device_removed(db, "z", "m", "early").await.unwrap(),
        Some(0)
    );
    assert_eq!(
        store::device_removed(db, "z", "m", "present")
            .await
            .unwrap(),
        None
    );
    let indices =
        |entries: Vec<MemberLogEntry>| entries.iter().map(|e| e.index).collect::<Vec<_>>();
    // Paged (limit 3) up to and including 4, never beyond.
    let first = store::log_get_until(db, "z", 0, 4, 3).await.unwrap();
    assert_eq!(indices(first), vec![1, 2, 3]);
    let second = store::log_get_until(db, "z", 3, 4, 3).await.unwrap();
    assert_eq!(indices(second), vec![4]);
    assert!(store::log_get_until(db, "z", 4, 4, 3)
        .await
        .unwrap()
        .is_empty());
    assert!(store::log_get_until(db, "z", 9, 4, 3)
        .await
        .unwrap()
        .is_empty());
    assert!(store::log_get_until(db, "z", 0, 0, 3)
        .await
        .unwrap()
        .is_empty());
}
