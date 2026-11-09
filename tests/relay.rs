//! Relay über echte WebSockets mit dem Protokoll-Crate der App: Tickets, Reservierung "first
//! wins" unter Nebenläufigkeit, idempotente Wiederholung mit Digest, Nachspielen und Snapshot,
//! Claims, Ablage, E2E-Unterbau, `ticket.renew`, Grenzen.

mod common;

use common::*;
use ed25519_dalek::SigningKey;
use hangar_team_server::config::{Config, IdentityMode};
use hangar_team_server::ticket::Role;
use hangar_team_server::wire::*;

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
async fn ticketprüfung() {
    let s = start_official().await;
    // Gültig, ohne Cursor: Snapshot (resync_required) und welcome.
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
    // Dasselbe Ticket ein zweites Mal: abgelehnt (jti).
    assert_eq!(
        code(&c2.hello("p1", t, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Ticket für ein anderes Projekt.
    let other_team = ticket("u1", "p1", Role::Owner);
    assert_eq!(
        code(&c2.hello("p2", other_team, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Abgelaufen.
    let mut old = claims("u1", "p1", Role::Owner);
    old.iat -= 600;
    old.exp -= 600;
    let old = sign_ticket(&old, &website_key());
    assert_eq!(
        code(&c2.hello("p1", old, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Fremde Signatur.
    let foreign = sign_ticket(
        &claims("u1", "p1", Role::Owner),
        &SigningKey::from_bytes(&[7; 32]),
    );
    assert_eq!(
        code(&c2.hello("p1", foreign, "d1", None).await),
        Some(ErrorCode::Forbidden)
    );
    // Zielgruppe ist Pflicht: ohne `aud` oder mit fremder abgelehnt.
    for aud in [None, Some("https://anderes-relay.example".to_owned())] {
        let mut other = claims("u1", "p1", Role::Owner);
        other.aud = aud;
        let other = sign_ticket(&other, &website_key());
        assert_eq!(
            code(&c2.hello("p1", other, "d1", None).await),
            Some(ErrorCode::Forbidden)
        );
    }
    // Kein Platz laut Webseite.
    let mut full = claims("u9", "p1", Role::Member);
    full.seat_ok = false;
    let full = sign_ticket(&full, &website_key());
    assert_eq!(
        code(&c2.hello("p1", full, "d9", None).await),
        Some(ErrorCode::Limit)
    );
    // Veraltete Protokollversion.
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
    // Ohne hello keine Teamnachricht.
    assert_eq!(
        code(&c2.request("p1", reserve(h(1))).await),
        Some(ErrorCode::Forbidden)
    );
}

#[tokio::test]
async fn geräte_ids_gelten_je_mitglied() {
    let s = start_official().await;
    // Zwei Mitglieder mit derselben Geräte-ID sind zwei Geräte.
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
async fn erster_gewinnt_unter_nebenläufigkeit() {
    let s = start_official().await;
    let (mut a, _) = Client::join(s.addr, "team", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "team", "bob", Role::Member).await;
    for round in 0..25u8 {
        let task = h(round);
        let (oa, ob) = (a.op(), b.op());
        // Beide senden, bevor einer liest.
        a.send(&oa, Some("team"), reserve(task)).await;
        b.send(&ob, Some("team"), reserve(task)).await;
        let (ra, rb) = tokio::join!(a.answer(&oa), b.answer(&ob));
        let wins = [&ra, &rb].iter().filter(|f| is_ack(f)).count();
        assert_eq!(wins, 1, "Runde {round}: genau einer gewinnt");
        let loser = if is_ack(&ra) { &rb } else { &ra };
        match &loser.message {
            ServerMessage::Err(e) => {
                assert_eq!(e.code, ErrorCode::Conflict);
                assert!(e.holder.is_some(), "der Konflikt nennt den Halter");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn idempotente_wiederholung_und_nachspielen() {
    let s = start_official().await;
    let (mut a, welcome) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let stream = welcome.stream.clone();
    // Gleiche Operations-ID zweimal: ein Ereignis, zwei gleiche Antworten.
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
        "Wiederholung: nur die gemerkte Antwort, kein neues Ereignis"
    );
    assert_eq!(first.message, again.message);
    // Dieselbe Operations-ID mit anderem Inhalt: badRequest, nichts angewendet.
    a.send(&op, Some("t"), reserve(h(2))).await;
    assert_eq!(code(&a.answer(&op).await), Some(ErrorCode::BadRequest));
    let cursor = Cursor {
        stream: stream.clone(),
        seq: reserved.seq.expect("geloggt"),
    };
    a.close().await;

    // Währenddessen ändert Bob etwas.
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    assert!(is_ack(&b.request("t", reserve(h(2))).await));
    assert!(is_ack(
        &b.request("t", ClientMessage::TaskRelease(TaskRef { task: h(2) }))
            .await
    ));

    // Alice kommt mit Cursor zurück: welcome, dann die verpassten Ereignisse in Folge.
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
        panic!("kein welcome")
    };
    assert!(w.head > cursor.seq);
    let mut seqs = Vec::new();
    while seqs.last().copied() != Some(w.head) {
        let f = a.recv().await.expect("Nachspiel");
        if let Some(seq) = f.seq {
            seqs.push(seq);
        }
    }
    let expected: Vec<Seq> = (cursor.seq.0 + 1..=w.head.0).map(Seq).collect();
    assert_eq!(seqs, expected, "lückenlos und geordnet");

    // Fremder Stream: Snapshot statt Nachspiel; der Snapshot enthält die gehaltene Aufgabe.
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
                stream: StreamId::new("anderer").unwrap(),
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
            assert!(f.seq.is_none(), "Snapshot ohne seq");
            saw_task |= r.task == h(1);
        }
        if matches!(f.message, ServerMessage::Welcome(_)) {
            break;
        }
    }
    assert!(saw_task);
}

#[tokio::test]
async fn freigabe_anfragen_übergeben_und_erzwingen() {
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
    assert_eq!(r.note, Some(note), "die Notiz reist mit");
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

    // Ein Mitglied darf fremde Reservierungen nicht beenden, der Eigentümer schon.
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
async fn claims_werden_nur_auf_gleichheit_verglichen() {
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
        "bei gleicher Datei das verschlüsselte Detail der Gegenseite"
    );
    let mine = a
        .until(|f| matches!(f.message, ServerMessage::ClaimOverlap(_)))
        .await;
    assert!(mine.seq.is_none());
    // Anderer Datei-Hash im selben Bereich: sameArea.
    b.send("o2", Some("t"), claim("kb", 51, "ZGV0YWlsYg")).await;
    let area = b
        .until(|f| matches!(&f.message, ServerMessage::ClaimOverlap(o) if o.level == MatchLevel::SameArea))
        .await;
    assert!(area.seq.is_none());
}

#[tokio::test]
async fn ticket_renew_rolle_still_und_entzug() {
    let s = start_official().await;
    let renew = |t: String| {
        ClientMessage::TicketRenew(TicketRenew {
            ticket: Ticket::new(t).unwrap(),
        })
    };
    // Vor dem hello: badRequest.
    let mut early = Client::connect(s.addr).await;
    let r = early
        .request("t", renew(ticket("alice", "t", Role::Owner)))
        .await;
    assert_eq!(code(&r), Some(ErrorCode::BadRequest));

    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let (mut b, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    // Herabstufung über ticket.renew: still angewendet, keine Trennung.
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
    a.send_raw(r#"{"v":1,"id":"still-da","type":"ping"}"#).await;
    assert!(is_ack(&a.answer("still-da").await), "die Verbindung bleibt");

    // Ticket für ein anderes Team: err forbidden, dann Close 4403.
    let op = a.op();
    a.send(
        &op,
        Some("t"),
        renew(ticket("alice", "anderes", Role::Owner)),
    )
    .await;
    assert_eq!(code(&a.answer(&op).await), Some(ErrorCode::Forbidden));
    assert_eq!(a.close_code().await, Some(close::CLOSE_REMOVED));

    // Ohne Platz: Close 4403.
    let mut lost = claims("bob", "t", Role::Member);
    lost.seat_ok = false;
    let op = b.op();
    b.send(&op, Some("t"), renew(sign_ticket(&lost, &website_key())))
        .await;
    assert_eq!(b.close_code().await, Some(close::CLOSE_REMOVED));
}

#[tokio::test]
async fn rahmen_und_grenzen() {
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
async fn ohne_hello_endet_die_verbindung_nach_der_frist() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.hello_timeout_ms = 300;
    let s = start(config).await;
    // Pings allein halten die Verbindung nicht.
    let mut idle = Client::connect(s.addr).await;
    idle.send_raw(r#"{"v":1,"id":"p","type":"ping"}"#).await;
    assert!(is_ack(&idle.answer("p").await));
    let started = std::time::Instant::now();
    assert_eq!(idle.close_code().await, Some(close::CLOSE_HELLO_TIMEOUT));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    // Mit gültigem hello gilt die Frist nicht mehr.
    let (mut a, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    a.send_raw(r#"{"v":1,"id":"q","type":"ping"}"#).await;
    assert!(is_ack(&a.answer("q").await));
}

#[tokio::test]
async fn grenze_je_adresse() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.max_connections_per_ip = 3;
    let s = start(config).await;
    let mut open = Vec::new();
    for _ in 0..3 {
        open.push(Client::connect(s.addr).await);
    }
    // Grenze + 1: 503 vor dem Upgrade.
    let refused = tokio_tungstenite::connect_async(format!("ws://{}/v1/live", s.addr)).await;
    match refused {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status().as_u16(), 503)
        }
        other => panic!("erwartet 503: {other:?}"),
    }
    // Wird eine frei, geht es wieder.
    open.pop().unwrap().close().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    Client::connect(s.addr).await;
}

#[tokio::test]
async fn origin_wird_geprüft_und_health_hat_header() {
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
