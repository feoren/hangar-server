//! Neustart, Haltbarkeitsregel, `notify` und `device.remove` mit dem Protokoll-Crate 525a8c7.

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

/// Gespeicherte Log-Position eines Teams, direkt aus der Datenbank.
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

/// Erster Prozess beendet (Zeitgeber und Verbindungen zu), zweiter auf denselben Daten.
async fn restart(first: TestServer, config: Config) -> TestServer {
    let _ = first.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    start(config).await
}

#[tokio::test]
async fn neustart_setzt_stream_reservierungen_und_fristen_fort() {
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
        seq: seen.seq.expect("geloggt"),
    };
    a.close().await;
    b.close().await;

    let before = now_ms();
    let s2 = restart(s, config).await;
    // Alice kommt mit ihrem Cursor zurück. Der Stream läuft weiter (kein `otherStream`); da
    // ihr Abmelden und der Neustart selbst Ereignisse nach ihrem Cursor erzeugt haben, die nur
    // im Fenster des ersten Prozesses lagen, bekommt sie `tooOld` und einen Snapshot. Darin hält
    // sie die Aufgabe weiter, und die Frist läuft (alle gelten nach dem Neustart als getrennt).
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
        let f = a.recv().await.expect("Antwort auf hello");
        match &f.message {
            ServerMessage::ResyncRequired(r) => {
                assert_eq!(r.stream, cursor.stream, "der Stream läuft weiter");
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
    let expires = expires.expect("Frist läuft nach dem Neustart").0;
    assert!(expires >= before + 5 * 60 * 1000, "mindestens die Warnzeit");

    // Der offene Freigabewunsch hat den Neustart überstanden (Snapshot eines neuen Geräts).
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
    // Und "first wins" gilt weiter.
    let (mut b, _) = Client::join(s2.addr, "t", "bob", Role::Member).await;
    assert_eq!(
        code(&b.request("t", reserve(h(3))).await),
        Some(ErrorCode::Conflict)
    );
}

#[tokio::test]
async fn kein_seq_vor_dem_gespeicherten_head() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    for round in 0..10u8 {
        let op = a.op();
        a.send(&op, Some("t"), reserve(h(round))).await;
        // Jeder Rahmen mit seq, den Bob sieht, ist schon gespeichert.
        let seen = b.until(|f| f.seq.is_some()).await;
        let seq = seen.seq.unwrap().0;
        assert!(
            stored_head(&s, "t").await >= seq,
            "Runde {round}: seq {seq} vor dem gespeicherten head"
        );
        a.answer(&op).await;
    }
}

#[tokio::test]
async fn notify_nach_dem_nächsten_welcome() {
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

    // Gespeichert: auch nach einem Neustart wird sie zugestellt.
    let s2 = restart(s, config).await;
    let (mut bob, _) = Client::join(s2.addr, "t", "bob", Role::Member).await;
    let notify = bob
        .until(|f| matches!(f.message, ServerMessage::Notify(_)))
        .await;
    assert!(notify.seq.is_none(), "notify wird nie geloggt");
    let ServerMessage::Notify(n) = notify.message else {
        unreachable!()
    };
    assert_eq!(n.member, member("bob"));
    assert_eq!(n.topic, NotifyTopic::Attention);
    assert_eq!(n.content, Some(note), "trägt die Notiz des Wunsches");
    // Zugestellt heißt gelöscht.
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
async fn client_am_gespeicherten_head_braucht_keinen_snapshot() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    // member.joined ist das einzige geloggte Ereignis; Abmelden ohne Reservierung loggt nichts.
    let joined = a
        .until(|f| matches!(f.message, ServerMessage::MemberJoined(_)))
        .await;
    let head = joined.seq.expect("geloggt").0;
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
        panic!("erwartet welcome ohne Snapshot: {first:?}")
    };
    assert_eq!(w.stream, welcome.stream);
    assert_eq!(w.head, Seq(head));
}

/// Ein entferntes Gerät liest das Log nur bis zum entfernenden Eintrag, auch seitenweise, mit
/// beliebigem `after` und für Sperren von vor Migration 0010 (`log_index` NULL).
#[tokio::test]
async fn log_eines_entfernten_geräts_endet_am_entfernenden_eintrag() {
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
        ("neu", 40i64, Some(4i64)),
        ("alt", 55, None),
        ("früh", 5, None),
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
        store::device_removed(db, "z", "m", "neu").await.unwrap(),
        Some(4)
    );
    // Ohne log_index: der letzte Eintrag bis zur Sperre, ohne einen solchen 0 (leeres Log).
    assert_eq!(
        store::device_removed(db, "z", "m", "alt").await.unwrap(),
        Some(5)
    );
    assert_eq!(
        store::device_removed(db, "z", "m", "früh").await.unwrap(),
        Some(0)
    );
    assert_eq!(
        store::device_removed(db, "z", "m", "da").await.unwrap(),
        None
    );
    let indices =
        |entries: Vec<MemberLogEntry>| entries.iter().map(|e| e.index).collect::<Vec<_>>();
    // Seitenweise (limit 3) bis einschließlich 4, nie darüber.
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
