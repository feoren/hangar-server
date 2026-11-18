//! Relay over real WebSockets with the app's protocol crate: tickets, "first wins" reservation
//! under concurrency, idempotent retry with digest, replay and snapshot, claims, storage, E2E
//! groundwork, `ticket.renew`, limits.

mod common;

use common::*;
use ed25519_dalek::SigningKey;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::ticket::Role;
use hangar_server::wire::*;

fn h(b: u8) -> KeyedHash {
    KeyedHash::from_bytes([b; 32])
}

fn reserve_at(task: KeyedHash, epoch: u32) -> ClientMessage {
    ClientMessage::TaskReserve(TaskReserve {
        task,
        epoch: Epoch(epoch),
        prev: Vec::new(),
        note: None,
    })
}

fn reserve(task: KeyedHash) -> ClientMessage {
    reserve_at(task, 0)
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

#[tokio::test]
async fn ticket_validation() {
    let s = start_official().await;
    // Valid, without cursor: snapshot (resync_required) and welcome.
    let mut c = Client::connect(s.addr).await;
    let t = ticket("u1", "p1", Role::Owner);
    let op = c.op();
    c.send(
        &op,
        Some("p1"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(t.clone()).unwrap(),
            device: device("d1"),
            proto: ProtoRange::CURRENT,
            last_seq: None,
        }),
    )
    .await;
    let first = c.recv().await.unwrap();
    assert!(matches!(
        first.message,
        ServerMessage::ResyncRequired(ResyncRequired {
            reason: ResyncReason::NoCursor,
            ..
        })
    ));
    assert!(matches!(
        c.answer(&op).await.message,
        ServerMessage::Welcome(_)
    ));

    let mut c2 = Client::connect(s.addr).await;
    // The same ticket a second time: rejected (jti).
    assert_eq!(
        code(&c2.hello("p1", t, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Ticket for a different project.
    let other_team = ticket("u1", "p1", Role::Owner);
    assert_eq!(
        code(&c2.hello("p2", other_team, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Expired.
    let mut old = claims("u1", "p1", Role::Owner);
    old.iat -= 600;
    old.exp -= 600;
    let old = sign_ticket(&old, &website_key());
    assert_eq!(
        code(&c2.hello("p1", old, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Foreign signature.
    let foreign = sign_ticket(
        &claims("u1", "p1", Role::Owner),
        &SigningKey::from_bytes(&[7; 32]),
    );
    assert_eq!(
        code(&c2.hello("p1", foreign, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Audience is mandatory: rejected without `aud` or with a foreign one.
    for aud in [None, Some("https://other-relay.example".to_owned())] {
        let mut other = claims("u1", "p1", Role::Owner);
        other.aud = aud;
        let other = sign_ticket(&other, &website_key());
        assert_eq!(
            code(&c2.hello("p1", other, "d1", None).await),
            Some(ErrorCode::Forbidden)
        );
    }
    // No seat according to the website.
    let mut full = claims("u9", "p1", Role::Member);
    full.seat_ok = false;
    let full = sign_ticket(&full, &website_key());
    assert_eq!(
        code(&c2.hello("p1", full, "d9", None).await),
        Some(ErrorCode::Limit)
    );
    // Outdated protocol version.
    let old_proto = ProtoRange::new(0, 0).unwrap();
    let frame = c2
        .hello_with(
            "p1",
            ticket("u2", "p1", Role::Member),
            "d2",
            old_proto,
            None,
        )
        .await;
    assert_eq!(code(&frame), Some(ErrorCode::OutdatedClient));
    // No team message without hello.
    assert_eq!(
        code(&c2.request("p1", reserve(h(1))).await),
        Some(ErrorCode::Forbidden)
    );
}

#[tokio::test]
async fn device_ids_are_scoped_per_member() {
    let s = start_official().await;
    // Two members with the same device ID are two devices.
    let mut a = Client::connect(s.addr).await;
    assert!(matches!(
        a.hello("t", ticket("alice", "t", Role::Owner), "laptop", None)
            .await
            .message,
        ServerMessage::Welcome(_)
    ));
    let mut b = Client::connect(s.addr).await;
    assert!(matches!(
        b.hello("t", ticket("bob", "t", Role::Member), "laptop", None)
            .await
            .message,
        ServerMessage::Welcome(_)
    ));
    assert!(is_ack(&a.request("t", reserve(h(1))).await));
    let refused = b.request("t", reserve(h(1))).await;
    match refused.message {
        ServerMessage::Err(e) => assert_eq!(e.holder, Some(holder("alice", "laptop"))),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn first_wins_under_concurrency() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "team", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "team", "bob", Role::Member).await;
    for round in 0..25u8 {
        let task = h(round);
        let (oa, ob) = (a.op(), b.op());
        // Both send before either reads.
        a.send(&oa, Some("team"), reserve(task)).await;
        b.send(&ob, Some("team"), reserve(task)).await;
        let (ra, rb) = tokio::join!(a.answer(&oa), b.answer(&ob));
        let wins = [&ra, &rb].iter().filter(|f| is_ack(f)).count();
        assert_eq!(wins, 1, "round {round}: exactly one wins");
        let loser = if is_ack(&ra) { &rb } else { &ra };
        match &loser.message {
            ServerMessage::Err(e) => {
                assert_eq!(e.code, ErrorCode::Conflict);
                assert!(e.holder.is_some(), "the conflict names the holder");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn idempotent_retry_and_replay() {
    let s = start_official().await;
    let (mut a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let stream = welcome.stream.clone();
    // Same operation ID twice: one event, two identical replies.
    let op = a.op();
    a.send(&op, Some("t"), reserve(h(1))).await;
    let reserved = a
        .until(|f| matches!(f.message, ServerMessage::TaskReserved(_)))
        .await;
    let first = a.answer(&op).await;
    a.send(&op, Some("t"), reserve(h(1))).await;
    let again = a.recv().await.unwrap();
    assert_eq!(
        again.id.as_ref().map(|i| i.as_str()),
        Some(op.as_str()),
        "retry: only the remembered reply, no new event"
    );
    assert_eq!(first.message, again.message);
    // Same operation ID with different content: badRequest, nothing applied.
    a.send(&op, Some("t"), reserve(h(2))).await;
    assert_eq!(code(&a.answer(&op).await), Some(ErrorCode::BadRequest));
    let cursor = Cursor {
        stream: stream.clone(),
        seq: reserved.seq.expect("logged"),
    };
    a.close().await;

    // Meanwhile Bob changes something.
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    assert!(is_ack(&b.request("t", reserve(h(2))).await));
    assert!(is_ack(
        &b.request("t", ClientMessage::TaskRelease(TaskRef { task: h(2) }))
            .await
    ));

    // Alice returns with a cursor: welcome, then the missed events in order.
    let mut a = Client::connect(s.addr).await;
    let w = a
        .hello(
            "t",
            ticket("alice", "t", Role::Owner),
            "alice-device",
            Some(cursor.clone()),
        )
        .await;
    let ServerMessage::Welcome(w) = w.message else {
        panic!("no welcome")
    };
    assert!(w.head > cursor.seq);
    let mut seqs = Vec::new();
    while seqs.last().copied() != Some(w.head) {
        let f = a.recv().await.expect("replay");
        if let Some(seq) = f.seq {
            seqs.push(seq);
        }
    }
    let expected: Vec<Seq> = (cursor.seq.0 + 1..=w.head.0).map(Seq).collect();
    assert_eq!(seqs, expected, "gapless and ordered");

    // Foreign stream: snapshot instead of replay; the snapshot contains the held task.
    let mut c = Client::connect(s.addr).await;
    let op = c.op();
    c.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("carol", "t", Role::Member)).unwrap(),
            device: device("carol-device"),
            proto: ProtoRange::CURRENT,
            last_seq: Some(Cursor {
                stream: StreamId::new("other").unwrap(),
                seq: Seq(1),
            }),
        }),
    )
    .await;
    let first = c.recv().await.unwrap();
    assert!(matches!(
        first.message,
        ServerMessage::ResyncRequired(ResyncRequired {
            reason: ResyncReason::OtherStream,
            ..
        })
    ));
    let mut saw_task = false;
    loop {
        let f = c.recv().await.unwrap();
        if let ServerMessage::TaskReserved(r) = &f.message {
            assert!(f.seq.is_none(), "snapshot without seq");
            saw_task |= r.task == h(1);
        }
        if matches!(f.message, ServerMessage::Welcome(_)) {
            break;
        }
    }
    assert!(saw_task);
}

#[tokio::test]
async fn release_request_handover_and_force() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    let note = Sealed {
        epoch: Epoch(0),
        data: cipher("bm90aXo"),
    };
    let reserved = a
        .request(
            "t",
            ClientMessage::TaskReserve(TaskReserve {
                task: h(5),
                epoch: Epoch(0),
                prev: Vec::new(),
                note: Some(note.clone()),
            }),
        )
        .await;
    assert!(is_ack(&reserved));
    let seen = b
        .until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.task == h(5)))
        .await;
    let ServerMessage::TaskReserved(r) = seen.message else {
        unreachable!()
    };
    assert_eq!(r.note, Some(note), "the note travels along");
    let req = b
        .request(
            "t",
            ClientMessage::TaskReleaseRequest(TaskReleaseRequest {
                task: h(5),
                note: None,
            }),
        )
        .await;
    assert!(is_ack(&req));
    a.until(|f| matches!(f.message, ServerMessage::TaskReleaseRequested(_)))
        .await;
    let ans = a
        .request(
            "t",
            ClientMessage::TaskReleaseAnswer(TaskReleaseAnswer {
                task: h(5),
                requester: member("bob"),
                accept: true,
            }),
        )
        .await;
    assert!(is_ack(&ans));
    let held = b
        .until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.holder.member == member("bob")))
        .await;
    assert!(held.seq.is_some());
    let ServerMessage::TaskReserved(r) = held.message else {
        unreachable!()
    };
    assert_eq!(
        r.note, None,
        "the previous holder's note does not carry over"
    );

    // A member may not end other people's reservations, the owner may.
    assert!(is_ack(&b.request("t", reserve(h(6))).await));
    assert!(is_ack(&a.request("t", reserve(h(7))).await));
    let refused = b
        .request("t", ClientMessage::TaskForceRelease(TaskRef { task: h(7) }))
        .await;
    assert_eq!(code(&refused), Some(ErrorCode::Forbidden));
    assert!(is_ack(
        &a.request("t", ClientMessage::TaskForceRelease(TaskRef { task: h(6) }))
            .await
    ));
    let ended = b
        .until(|f| matches!(&f.message, ServerMessage::TaskReleased(r) if r.task == h(6)))
        .await;
    let ServerMessage::TaskReleased(r) = ended.message else {
        unreachable!()
    };
    assert_eq!(r.reason, ReleaseReason::ForceReleased);
}

#[tokio::test]
async fn claims_are_compared_for_equality_only() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    let claim = |key: &str, file: u8, detail: &str| {
        ClientMessage::ClaimSet(ClaimSet {
            session: session(key),
            repo: h(200),
            epoch: Epoch(0),
            files: vec![PathHashes {
                area: Some(h(10)),
                file: h(file),
            }],
            truncated: false,
            detail: Some(Sealed {
                epoch: Epoch(0),
                data: cipher(detail),
            }),
        })
    };
    assert!(is_ack(&a.request("t", claim("ka", 50, "ZGV0YWlsYQ")).await));
    b.send("o1", Some("t"), claim("kb", 50, "ZGV0YWlsYg")).await;
    let overlap = b
        .until(|f| matches!(f.message, ServerMessage::ClaimOverlap(_)))
        .await;
    let ServerMessage::ClaimOverlap(o) = overlap.message else {
        unreachable!()
    };
    assert_eq!(o.level, MatchLevel::SameFile);
    assert_eq!(o.other.holder.member, member("alice"));
    assert_eq!(
        o.detail.map(|d| d.data.as_str().to_owned()).as_deref(),
        Some("ZGV0YWlsYQ"),
        "same file: the other side's encrypted detail"
    );
    let mine = a
        .until(|f| matches!(f.message, ServerMessage::ClaimOverlap(_)))
        .await;
    assert!(mine.seq.is_none());
    // Different file hash in the same area: sameArea.
    b.send("o2", Some("t"), claim("kb", 51, "ZGV0YWlsYg")).await;
    let area = b
        .until(|f| matches!(&f.message, ServerMessage::ClaimOverlap(o) if o.level == MatchLevel::SameArea))
        .await;
    assert!(area.seq.is_none());
}

#[tokio::test]
async fn ticket_renew_silent_role_change_and_revocation() {
    let s = start_official().await;
    let renew = |t: String| {
        ClientMessage::TicketRenew(TicketRenew {
            ticket: Ticket::new(t).unwrap(),
        })
    };
    // Before hello: badRequest.
    let mut early = Client::connect(s.addr).await;
    let r = early
        .request("t", renew(ticket("alice", "t", Role::Owner)))
        .await;
    assert_eq!(code(&r), Some(ErrorCode::BadRequest));

    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    // Demotion via ticket.renew: applied silently, no disconnect.
    assert!(is_ack(
        &a.request("t", renew(ticket("alice", "t", Role::Member)))
            .await
    ));
    let changed = b
        .until(|f| matches!(f.message, ServerMessage::MemberRoleChanged(_)))
        .await;
    assert!(changed.seq.is_some());
    let rotate = ClientMessage::KeyRotate(KeyRotate {
        log: dummy_log(),
        epoch: Epoch(1),
        wrapped: vec![WrappedKey {
            holder: holder("bob", "bob-device"),
            data: cipher("Yg"),
        }],
    });
    assert_eq!(
        code(&a.request("t", rotate).await),
        Some(ErrorCode::Forbidden)
    );
    a.send_raw(r#"{"v":1,"id":"still-here","type":"ping"}"#)
        .await;
    assert!(
        is_ack(&a.answer("still-here").await),
        "the connection stays"
    );

    // Ticket for a different team: err forbidden, then close 4403.
    let op = a.op();
    a.send(&op, Some("t"), renew(ticket("alice", "other", Role::Owner)))
        .await;
    assert_eq!(code(&a.answer(&op).await), Some(ErrorCode::Forbidden));
    assert_eq!(a.close_code().await, Some(close::CLOSE_REMOVED));

    // Without a seat: close 4403.
    let mut lost = claims("bob", "t", Role::Member);
    lost.seat_ok = false;
    let op = b.op();
    b.send(&op, Some("t"), renew(sign_ticket(&lost, &website_key())))
        .await;
    assert_eq!(b.close_code().await, Some(close::CLOSE_REMOVED));
}

#[tokio::test]
async fn frames_and_limits() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    a.send_raw(r#"{"v":1,"id":"x","type":"ping","extra":1}"#)
        .await;
    let bad = a
        .until(|f| matches!(f.message, ServerMessage::Err(_)))
        .await;
    assert_eq!(code(&bad), Some(ErrorCode::BadRequest));
    a.send_raw(r#"{"v":0,"id":"y","type":"ping"}"#).await;
    let old = a
        .until(|f| matches!(f.message, ServerMessage::Err(_)))
        .await;
    assert_eq!(code(&old), Some(ErrorCode::OutdatedClient));
    a.send_raw(r#"{"v":1,"id":"p","type":"ping"}"#).await;
    assert!(is_ack(&a.answer("p").await));
}

#[tokio::test]
async fn connection_without_hello_ends_after_the_deadline() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.hello_timeout_ms = 300;
    let s = start(config).await;
    // Pings alone do not keep the connection alive.
    let mut idle = Client::connect(s.addr).await;
    idle.send_raw(r#"{"v":1,"id":"p","type":"ping"}"#).await;
    assert!(is_ack(&idle.answer("p").await));
    let started = std::time::Instant::now();
    assert_eq!(idle.close_code().await, Some(close::CLOSE_HELLO_TIMEOUT));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    // After a valid hello the deadline no longer applies.
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    a.send_raw(r#"{"v":1,"id":"q","type":"ping"}"#).await;
    assert!(is_ack(&a.answer("q").await));
}

#[tokio::test]
async fn limit_per_address() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.max_connections_per_ip = 3;
    let s = start(config).await;
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(Client::connect(s.addr).await);
    }
    // Limit + 1: 503 before the upgrade.
    let refused = tokio_tungstenite::connect_async(format!("ws://{}/v1/live", s.addr)).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 503)
        }
        other => panic!("expected 503: {other:?}"),
    }
    // Once one is freed, it works again.
    open.pop().unwrap().close().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Client::connect(s.addr).await;
}

#[tokio::test]
async fn origin_is_checked_and_health_has_headers() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let s = start_official().await;
    let mut request = format!("ws://{}/v1/live", s.addr)
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("origin", "https://evil.example".parse().unwrap());
    assert!(tokio_tungstenite::connect_async(request).await.is_err());

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut tcp = tokio::net::TcpStream::connect(s.addr).await.unwrap();
    tcp.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    tcp.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"));
    let lower = out.to_lowercase();
    assert!(lower.contains("x-content-type-options: nosniff"));
    assert!(lower.contains("content-security-policy:"));
    assert!(lower.contains("cache-control: no-store"));
}

/// On a handover the new reservation carries no note: the request's note is a
/// `ReleaseRequestNote` from the requester, but the app opens `task.reserved.note` as a
/// `ReservationNote` with the holder as sender. The snapshot then carries none either.
#[tokio::test]
async fn handover_without_note_also_in_snapshot() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    let sealed = |data: &str| Sealed {
        epoch: Epoch(0),
        data: cipher(data),
    };
    let reserved = a
        .request(
            "t",
            ClientMessage::TaskReserve(TaskReserve {
                task: h(8),
                epoch: Epoch(0),
                prev: Vec::new(),
                note: Some(sealed("aGFsdGVy")),
            }),
        )
        .await;
    assert!(is_ack(&reserved));
    let asked = b
        .request(
            "t",
            ClientMessage::TaskReleaseRequest(TaskReleaseRequest {
                task: h(8),
                note: Some(sealed("YW5mcmFnZQ")),
            }),
        )
        .await;
    assert!(is_ack(&asked));
    a.until(|f| matches!(f.message, ServerMessage::TaskReleaseRequested(_)))
        .await;
    let answered = a
        .request(
            "t",
            ClientMessage::TaskReleaseAnswer(TaskReleaseAnswer {
                task: h(8),
                requester: member("bob"),
                accept: true,
            }),
        )
        .await;
    assert!(is_ack(&answered));
    let handed = b
        .until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.task == h(8) && r.holder.member == member("bob")))
        .await;
    let ServerMessage::TaskReserved(r) = handed.message else {
        unreachable!()
    };
    assert_eq!(r.note, None);

    // Snapshot for a new connection without cursor: bob's reservation, without note.
    let mut c = Client::connect(s.addr).await;
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
    let mut seen = false;
    loop {
        let f = c.recv().await.expect("snapshot and welcome");
        if let ServerMessage::TaskReserved(r) = &f.message {
            if r.task == h(8) {
                assert_eq!(r.holder.member, member("bob"));
                assert_eq!(r.note, None, "snapshot without note");
                seen = true;
            }
        }
        if matches!(f.message, ServerMessage::Welcome(_)) {
            break;
        }
    }
    assert!(seen, "reservation in the snapshot");

    // The new holder sends their own note via task.reserve.
    let own = sealed("bmV1ZXIgaGFsdGVy");
    let again = b
        .request(
            "t",
            ClientMessage::TaskReserve(TaskReserve {
                task: h(8),
                epoch: Epoch(0),
                prev: Vec::new(),
                note: Some(own.clone()),
            }),
        )
        .await;
    assert!(is_ack(&again), "{:?}", again.message);
    let renewed = a
        .until(|f| matches!(&f.message, ServerMessage::TaskReserved(r) if r.task == h(8) && r.note.is_some()))
        .await;
    let ServerMessage::TaskReserved(r) = renewed.message else {
        unreachable!()
    };
    assert_eq!(r.holder.member, member("bob"));
    assert_eq!(r.note, Some(own));
}

/// A distinct task hash per number (more than 256 tasks).
fn task_no(n: u16) -> KeyedHash {
    let mut bytes = [0u8; 32];
    bytes[..2].copy_from_slice(&n.to_be_bytes());
    bytes[31] = 0xAA;
    KeyedHash::from_bytes(bytes)
}

/// Sends `message` and reads up to its reply; `last` follows the highest `seq` seen.
async fn request_tracking(
    c: &mut Client,
    team: &str,
    message: ClientMessage,
    last: &mut Option<Cursor>,
) -> ServerFrame {
    let op = c.op();
    c.send(&op, Some(team), message).await;
    loop {
        let f = c.recv().await.expect("reply");
        if let (Some(seq), Some(cursor)) = (f.seq, last.as_mut()) {
            if seq > cursor.seq {
                cursor.seq = seq;
            }
        }
        if f.id.as_ref().map(|i| i.as_str()) == Some(op.as_str())
            && !matches!(f.message, ServerMessage::ResyncRequired(_))
        {
            return f;
        }
    }
}

/// Joins with a cursor (replay instead of snapshot) and keeps it up to date.
async fn join_tracking(
    s: &TestServer,
    team: &str,
    member: &str,
    last: &mut Option<Cursor>,
) -> Client {
    let mut c = Client::connect(s.addr).await;
    let op = c.op();
    c.send(
        &op,
        Some(team),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket(member, team, Role::Member)).unwrap(),
            device: device(&format!("{member}-device")),
            proto: ProtoRange::CURRENT,
            last_seq: last.clone(),
        }),
    )
    .await;
    loop {
        let f = c.recv().await.expect("welcome");
        if let (Some(seq), Some(cursor)) = (f.seq, last.as_mut()) {
            if seq > cursor.seq {
                cursor.seq = seq;
            }
        }
        if let ServerMessage::Welcome(w) = &f.message {
            if f.id.as_ref().map(|i| i.as_str()) == Some(op.as_str()) {
                if last.is_none() {
                    *last = Some(Cursor {
                        stream: w.stream.clone(),
                        seq: w.head,
                    });
                }
                return c;
            }
        }
    }
}

/// The reply to a `ping` arrives and the connection is still open.
async fn still_open(c: &mut Client) {
    let op = c.op();
    c.send(&op, None, ClientMessage::Ping).await;
    let pong = c.answer(&op).await;
    assert!(is_ack(&pong), "{:?}", pong.message);
    assert_eq!(c.closed, None);
}

#[tokio::test]
async fn replay_longer_than_the_outgoing_queue_arrives_complete() {
    let s = start_official().await;
    // 600 logged events: reserve and release, a few connections in a row (rate limit per
    // connection), each joining with its cursor.
    let mut last = None;
    for batch in 0..6u16 {
        let mut c = join_tracking(&s, "t", "alice", &mut last).await;
        for n in batch * 50..(batch + 1) * 50 {
            let r = request_tracking(&mut c, "t", reserve(task_no(n)), &mut last).await;
            assert!(is_ack(&r), "{:?}", r.message);
            let release = ClientMessage::TaskRelease(TaskRef { task: task_no(n) });
            let r = request_tracking(&mut c, "t", release, &mut last).await;
            assert!(is_ack(&r), "{:?}", r.message);
        }
        c.close().await;
    }
    let stream = last.expect("cursor").stream;

    // Cursor 0 of the stream: welcome, then every event in order, without 1013.
    let mut c = Client::connect(s.addr).await;
    let w = c
        .hello(
            "t",
            ticket("bob", "t", Role::Member),
            "bob-device",
            Some(Cursor {
                stream,
                seq: Seq(0),
            }),
        )
        .await;
    let ServerMessage::Welcome(w) = w.message else {
        panic!("no welcome: {:?}", w.message)
    };
    assert!(w.head.0 >= 600, "head {:?}", w.head);
    let mut expected = 1;
    while expected <= w.head.0 {
        let f = c.recv().await.unwrap_or_else(|| {
            panic!(
                "replay ended at {expected} of {:?}, close {:?}",
                w.head, c.closed
            )
        });
        if let Some(seq) = f.seq {
            assert_eq!(seq.0, expected, "in order, without gaps");
            expected += 1;
        }
    }
    still_open(&mut c).await;
}

#[tokio::test]
async fn snapshot_larger_than_the_outgoing_queue_ends_with_welcome() {
    let s = start_official().await;
    // 20 members with 32 holds each (the crate's limit per member): 640 `task.reserved` in
    // the snapshot. Holds stay while their holders are offline.
    let mut last = None;
    for m in 0..20u16 {
        let name = format!("member{m}");
        let mut c = join_tracking(&s, "t", &name, &mut last).await;
        for n in m * 32..(m + 1) * 32 {
            let r = request_tracking(&mut c, "t", reserve(task_no(n)), &mut last).await;
            assert!(is_ack(&r), "{:?}", r.message);
        }
        c.close().await;
    }

    // Without a cursor: resync_required, the snapshot, finally welcome; no 1013.
    let mut c = Client::connect(s.addr).await;
    let op = c.op();
    c.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("observer", "t", Role::Member)).unwrap(),
            device: device("observer-device"),
            proto: ProtoRange::CURRENT,
            last_seq: None,
        }),
    )
    .await;
    let first = c.recv().await.expect("resync_required");
    assert!(
        matches!(first.message, ServerMessage::ResyncRequired(_)),
        "{:?}",
        first.message
    );
    let mut held = 0;
    loop {
        let f = c
            .recv()
            .await
            .unwrap_or_else(|| panic!("snapshot ended after {held} holds, close {:?}", c.closed));
        match &f.message {
            ServerMessage::TaskReserved(_) => held += 1,
            ServerMessage::Welcome(_) => break,
            _ => {}
        }
    }
    assert_eq!(held, 640);
    still_open(&mut c).await;
}

/// The largest `claim.set`: 1000 files (distinct per `n`, without area, so no overlaps) and a
/// detail of the longest ciphertext.
fn largest_claim(n: u16) -> ClientMessage {
    let files = (0..limits::MAX_CLAIM_FILES as u16)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&n.to_be_bytes());
            bytes[2..4].copy_from_slice(&i.to_be_bytes());
            bytes[31] = 0xCC;
            PathHashes {
                area: None,
                file: KeyedHash::from_bytes(bytes),
            }
        })
        .collect();
    ClientMessage::ClaimSet(ClaimSet {
        session: session(&format!("s{n}")),
        repo: h(1),
        epoch: Epoch(0),
        files,
        truncated: true,
        detail: Some(Sealed {
            epoch: Epoch(0),
            data: Ciphertext::new("A".repeat(limits::MAX_CIPHERTEXT_LEN)).unwrap(),
        }),
    })
}

#[tokio::test]
async fn claims_have_a_byte_budget_per_member() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Member).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    // Far below the 64 sessions per device, the member budget ends with `limit`.
    let mut accepted = 0;
    let refused = loop {
        let r = a.request("t", largest_claim(accepted)).await;
        if !is_ack(&r) {
            break r;
        }
        accepted += 1;
        assert!(accepted < 64, "no byte budget per member");
    };
    assert_eq!(code(&refused), Some(ErrorCode::Limit));
    assert!(accepted >= 16, "only {accepted} of the largest claims fit");
    // Replacing a session with one of the same size still works at the limit.
    assert!(is_ack(&a.request("t", largest_claim(0)).await));
    // Another member still has room in the team.
    assert!(is_ack(&b.request("t", largest_claim(100)).await));
}

#[tokio::test]
async fn claims_have_a_byte_budget_per_team() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.claim_bytes_per_team = 1024 * 1024;
    let s = start(config).await;
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Member).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    let mut accepted = 0;
    while is_ack(&a.request("t", largest_claim(accepted)).await) {
        accepted += 1;
        assert!(accepted < 64, "no byte budget per team");
    }
    assert!(accepted >= 3, "{accepted}");
    // The team is full for everyone, also for bob.
    assert_eq!(
        code(&b.request("t", largest_claim(100)).await),
        Some(ErrorCode::Limit)
    );
    // A cleared session frees its bytes.
    let clear = ClientMessage::ClaimClear(ClaimClear {
        session: session("s0"),
    });
    assert!(is_ack(&a.request("t", clear).await));
    assert!(is_ack(&b.request("t", largest_claim(100)).await));
}

#[tokio::test]
async fn replay_window_is_bounded_in_bytes() {
    let s = start_official().await;
    let note = Sealed {
        epoch: Epoch(0),
        data: Ciphertext::new("B".repeat(16_000)).unwrap(),
    };
    // 300 reservations with a 16 KB note each: about 4.8 MB of events.
    let mut last = None;
    for batch in 0..6u16 {
        let mut c = join_tracking(&s, "t", "alice", &mut last).await;
        for n in batch * 50..(batch + 1) * 50 {
            let reserve = ClientMessage::TaskReserve(TaskReserve {
                task: task_no(n),
                epoch: Epoch(0),
                prev: Vec::new(),
                note: Some(note.clone()),
            });
            let r = request_tracking(&mut c, "t", reserve, &mut last).await;
            assert!(is_ack(&r), "{:?}", r.message);
            let release = ClientMessage::TaskRelease(TaskRef { task: task_no(n) });
            let r = request_tracking(&mut c, "t", release, &mut last).await;
            assert!(is_ack(&r), "{:?}", r.message);
        }
        c.close().await;
    }
    let cursor = last.expect("cursor");
    assert!(cursor.seq.0 >= 600);

    // The oldest events left the window: a cursor at the start gets a snapshot.
    let mut old = Client::connect(s.addr).await;
    let op = old.op();
    old.send(
        &op,
        Some("t"),
        ClientMessage::Hello(Hello {
            ticket: Ticket::new(ticket("bob", "t", Role::Member)).unwrap(),
            device: device("bob-device"),
            proto: ProtoRange::CURRENT,
            last_seq: Some(Cursor {
                stream: cursor.stream.clone(),
                seq: Seq(0),
            }),
        }),
    )
    .await;
    let first = old.recv().await.expect("reply to hello");
    assert!(
        matches!(&first.message, ServerMessage::ResyncRequired(r) if r.reason == ResyncReason::TooOld),
        "{:?}",
        first.message
    );

    // A recent cursor still gets the replay, in order.
    let mut recent = Client::connect(s.addr).await;
    let from = cursor.seq.0 - 20;
    let w = recent
        .hello(
            "t",
            ticket("carol", "t", Role::Member),
            "carol-device",
            Some(Cursor {
                stream: cursor.stream.clone(),
                seq: Seq(from),
            }),
        )
        .await;
    assert!(matches!(w.message, ServerMessage::Welcome(_)), "{w:?}");
    let next = recent.until(|f| f.seq.is_some()).await.seq.expect("logged");
    assert_eq!(next.0, from + 1);
}

#[tokio::test]
async fn connections_before_hello_have_their_own_quota() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    // A quarter of 8: two connections may wait for their hello at once.
    config.max_connections = 8;
    let s = start(config).await;
    let mut first = Client::connect(s.addr).await;
    let _second = Client::connect(s.addr).await;
    let refused = tokio_tungstenite::connect_async(format!("ws://{}/v1/live", s.addr)).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 503)
        }
        other => panic!("expected 503: {other:?}"),
    }
    // After its hello the first one counts as a normal connection and frees the slot.
    let w = first
        .hello("t", ticket("alice", "t", Role::Owner), "alice-device", None)
        .await;
    assert!(matches!(w.message, ServerMessage::Welcome(_)), "{w:?}");
    let _third = Client::connect(s.addr).await;
}

#[tokio::test]
async fn housekeeping_forgets_devices_not_seen_for_long() {
    let s = start_official().await;
    let (_a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let db = &s.server.state.relay.db;
    sqlx::query(
        "INSERT INTO relay_devices (member, device, created_at, last_seen) \
         VALUES ('gone', 'gone-device', 1, 1)",
    )
    .execute(db)
    .await
    .unwrap();
    s.server.state.relay.housekeeping().await;
    let left: Vec<String> = sqlx::query_scalar("SELECT member FROM relay_devices ORDER BY member")
        .fetch_all(db)
        .await
        .unwrap();
    assert_eq!(left, vec!["alice".to_owned()]);
}
