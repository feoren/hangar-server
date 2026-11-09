//! E2E-Unterbau mit hangar-team-crypto (b30b9d5): das Relay prüft jeden Log-Eintrag mit dem
//! `LogVerifier`, Rotation und Geräteentfernung nur mit signiertem Eintrag und atomar,
//! Schlüsselpakete nach `relay::check_wrap`, Besitznachweis und Gerätegrenzen.

mod common;

use common::*;
use hangar_team_crypto::memberlog::LogVerifier;
use hangar_team_server::config::{Config, IdentityMode};
use hangar_team_server::relay::team::close;
use hangar_team_server::ticket::Role;
use hangar_team_server::wire::{Role as LogRole, *};

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
        panic!("keine Einträge")
    };
    page.entries.len()
}

/// Team `t` mit alice (owner) und bob (member), beide mit Schlüsseln und im Log.
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
async fn regelwidrige_einträge_werden_abgelehnt_und_blockieren_nichts() {
    let s = start_official().await;
    // Eintrag 1 nur mit owner-Ticket.
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
    // Schlüssel nie über die eigene Verbindung registriert: forbidden.
    let unregistered = log.add_member(&alice, &carol, LogRole::Member);
    assert_eq!(
        code(&append(&mut a, "t", &unregistered).await),
        Some(ErrorCode::Forbidden)
    );
    // Ein Mitglied darf keine Mitglieder aufnehmen.
    let mut c = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    let by_member = log.add_member(&bob, &carol, LogRole::Member);
    assert_eq!(
        code(&append(&mut b, "t", &by_member).await),
        Some(ErrorCode::Forbidden)
    );
    // Von alice signiert, aber von bob gesendet: nicht der Absender.
    let foreign = log.add_member(&alice, &carol, LogRole::Member);
    assert!(code(&append(&mut b, "t", &foreign).await).is_some());
    // Rotation und Geräteentfernung nie über memberlog.append.
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
    // Nichts davon wurde gespeichert, und der nächste gültige Eintrag geht durch.
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
async fn wirksame_rolle_ist_die_niedrigere() {
    let s = start_official().await;
    let (log, alice, a, _bob, _b) = team(&s).await;
    a.close().await;
    // alice ist im Log owner, ihr Ticket sagt aber member (die Webseite hat herabgestuft).
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
async fn rotation_ist_atomar() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let (rotate, _) = log.rotate(&alice);
    // Ein Paket an ein Gerät, das das Log nicht kennt: abgelehnt, weder Eintrag noch Epoche.
    let mut bad = rotate.clone();
    let mut stranger = bad.wrapped[0].clone();
    stranger.holder = holder("niemand", "nirgends");
    bad.wrapped.push(stranger);
    assert!(code(&a.request("t", ClientMessage::KeyRotate(bad)).await).is_some());
    assert_eq!(log_len(&mut a, "t").await, 2);
    let none = b
        .request("t", ClientMessage::KeyGet(KeyGet { epoch: Epoch(1) }))
        .await;
    assert_eq!(code(&none), Some(ErrorCode::NotFound));
    // Falsche Epoche im Umschlag.
    let mut wrong = rotate.clone();
    wrong.epoch = Epoch(2);
    assert_eq!(
        code(&a.request("t", ClientMessage::KeyRotate(wrong)).await),
        Some(ErrorCode::StaleEpoch)
    );
    // Die richtige Rotation: Eintrag und Pakete zusammen.
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
    assert_eq!(r.wrapped.as_ref(), Some(&mine.data), "nur das eigene Paket");
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
async fn schlüsselpakete_nach_den_regeln_des_logs() {
    let s = start_official().await;
    let (mut log, alice, mut a, bob, mut b) = team(&s).await;
    let (rotate, secret) = log.rotate(&alice);
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyRotate(rotate.clone()))
            .await
    ));
    log.accept_rotation(&rotate, &alice.holder);
    // Weitere Geräte: bob-phone (Ziel), alice-phone, alice-tablet, bob-tablet (Absender).
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
    // Nie für sich selbst.
    assert_eq!(
        code(
            &phone_c
                .request("t", ClientMessage::KeyWrap(wrap.clone()))
                .await
        ),
        Some(ErrorCode::Forbidden)
    );
    // owner für jedes Gerät, das Mitglied für ein eigenes anderes; je Absender eins.
    assert!(is_ack(
        &a.request("t", ClientMessage::KeyWrap(wrap.clone())).await
    ));
    let wrapped = phone_c
        .until(|f| matches!(f.message, ServerMessage::KeyWrapped(_)))
        .await;
    assert!(wrapped.seq.is_none(), "key.wrapped geht nicht ins Log");
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
    // Höchstens vier Pakete je Ziel und Epoche.
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
    // Unbekanntes Ziel.
    let mut unknown = wrap.clone();
    unknown.wrapped.holder = holder("bob", "gibt-es-nicht");
    assert_eq!(
        code(&a.request("t", ClientMessage::KeyWrap(unknown)).await),
        Some(ErrorCode::NotFound)
    );
    // key.get liefert alle Pakete.
    let got = phone_c
        .request("t", ClientMessage::KeyGet(KeyGet { epoch: Epoch(1) }))
        .await;
    let ServerMessage::Ack(ack) = got.message else {
        panic!("{got:?}")
    };
    assert_eq!(ack.keys.map(|k| k.len()), Some(4));
}

#[tokio::test]
async fn gerät_entfernen_nur_mit_signiertem_eintrag() {
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
    // Ohne gültigen Eintrag: badRequest.
    let bare = DeviceRemove {
        holder: phone.holder.clone(),
        log: dummy_log(),
    };
    assert!(code(&b.request("t", ClientMessage::DeviceRemove(bare)).await).is_some());
    // Ein Gerät, das das Log nicht kennt: badRequest.
    let ghost = log.remove_device(&alice, &holder("bob", "gibt-es-nicht"));
    assert!(code(&a.request("t", ClientMessage::DeviceRemove(ghost)).await).is_some());
    // bob-laptop entfernt bob-phone mit signiertem Eintrag.
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
    // Danach nur noch die Frist (eigene Tests unten), und devices nennt es nicht.
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
        "Besitznachweis gelistet"
    );
}

/// Team `t` mit alice, bob (bob-laptop) und bob-phone im Log; bob-phone hält eine
/// Reservierung. Gibt auch die Verbindung von bob-phone zurück.
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

/// Eine Seite des Logs, wie die App sie mit einem frischen `LogVerifier` prüft.
fn entries_of(frame: ServerFrame) -> MemberLogEntries {
    match frame.message {
        ServerMessage::MemberLogEntries(page) => page,
        other => panic!("keine Einträge: {other:?}"),
    }
}

#[tokio::test]
async fn entferntes_gerät_liest_das_log_bis_zur_entfernung_dann_4403() {
    let s = start(grace_config(5_000)).await;
    let (mut log, _alice, _a, bob, mut b, phone, mut p) = team_with_phone(&s).await;
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    log.accept_removal(&removal, &bob.holder);
    let removed_at = log.state().head().index;
    // Das Gerät bekommt nur memberlog.appended und sein device.removed, keine Teamdaten (die
    // Freigabe seiner Reservierung geht an die anderen), und beide ohne seq: mit seq sähe die
    // App in der ausgelassenen Freigabe eine Lücke und bräche ab, bevor sie das Log prüft.
    loop {
        let frame = p.recv().await.expect("Rahmen vor der Frist");
        assert!(
            frame.seq.is_none(),
            "Rahmen in der Frist mit seq: {frame:?}"
        );
        match &frame.message {
            ServerMessage::MemberLogAppended(m) => assert_eq!(m.index, removed_at),
            ServerMessage::DeviceRemoved(r) => {
                assert_eq!(r.holder, phone.holder);
                break;
            }
            other => panic!("entferntes Gerät bekam {other:?}"),
        }
    }
    // In der Frist wird alles außer memberlog.get abgelehnt und schreibt nichts.
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
        "nichts reserviert"
    );
    // memberlog.get: das Log bis zur Entfernung, prüfbar wie in der App; dann 4403.
    let page = entries_of(
        p.request("t", ClientMessage::MemberLogGet(MemberLogGet { after: 0 }))
            .await,
    );
    assert!(!page.more);
    assert_eq!(page.entries.last().map(|e| e.index), Some(removed_at));
    let mut check = LogVerifier::new(team_id("t"));
    check.apply_all(&page.entries).expect("Log prüfbar");
    assert!(check.state().unwrap().device(&phone.holder).is_none());
    let started = std::time::Instant::now();
    assert_eq!(p.close_code().await, Some(close::CLOSE_REMOVED));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(2),
        "4403 direkt nach der Antwort, nicht erst nach der Frist"
    );
}

#[tokio::test]
async fn frist_ohne_memberlog_get_endet_mit_4403() {
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
        "zu früh geschlossen: {waited:?}"
    );
}

#[tokio::test]
async fn hello_eines_entfernten_geräts_bekommt_nur_das_log_bis_zur_entfernung() {
    let s = start(grace_config(5_000)).await;
    let (mut log, _alice, mut a, bob, mut b, phone, p) = team_with_phone(&s).await;
    let removal = log.remove_device(&bob, &phone.holder);
    assert!(is_ack(
        &b.request("t", ClientMessage::DeviceRemove(removal.clone()))
            .await
    ));
    log.accept_removal(&removal, &bob.holder);
    let removed_at = log.state().head().index;
    // Die Verbindung war schon weg (App beendet), bevor sie das Log lesen konnte.
    p.close().await;
    // Ein späterer Eintrag (neues Gerät) bleibt dem entfernten Gerät verborgen.
    let tablet = Dev::new("bob", "bob-tablet");
    let _t = Client::join_device(s.addr, "t", &tablet, Role::Member).await;
    let add = log.add_device(&bob, &tablet);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    // Alles bisher Gesendete bei alice abholen (darunter die frühere Präsenz von bob-phone).
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
    // Nur welcome: kein Snapshot, keine Reservierungen, keine Präsenz.
    let first = again.recv().await.expect("Antwort auf hello");
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
        let answer = again.recv().await.expect("Antwort in der Frist");
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
    check.apply_all(&page.entries).expect("Log prüfbar");
    assert!(check.state().unwrap().device(&phone.holder).is_none());
    assert_eq!(again.close_code().await, Some(close::CLOSE_REMOVED));
    // Nichts geschrieben: keine Schlüssel, keine Reservierung, nicht unter den Geräten.
    assert!(is_ack(&b.request("t", reserve_task(10)).await));
    // Bis zur Antwort auf devices.get kam bei alice nichts über das entfernte Gerät an
    // (keine Präsenz, kein Beitritt): alles davor ging vor dem hello ein.
    let op = a.op();
    a.send(&op, Some("t"), ClientMessage::DevicesGet).await;
    let list = loop {
        let frame = a.recv().await.expect("Antwort auf devices.get");
        match frame.message {
            ServerMessage::Devices(list) if frame.id.as_ref().map(|i| i.as_str()) == Some(&op) => {
                break list
            }
            ServerMessage::PresenceUpdate(u) => assert_ne!(u.holder, phone.holder),
            ServerMessage::MemberJoined(_) => panic!("Beitritt gemeldet"),
            _ => {}
        }
    };
    assert!(list.devices.iter().all(|d| d.holder != phone.holder));

    // Sperren von vor Migration 0010 (ohne log_index): der letzte Eintrag bis zur Sperre.
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
async fn mitglied_entfernen_schließt_seine_geräte() {
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
    // Die Ereignisse gehen an alle, auch an die auslösende Verbindung, vor der Bestätigung.
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
async fn neustart_baut_das_geprüfte_log_wieder_auf() {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let s = start(config.clone()).await;
    let (mut log, alice, a, _bob, b) = team(&s).await;
    a.close().await;
    b.close().await;
    let _ = s.server.shutdown.send(true);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let s2 = start(config).await;
    // Der nächste Eintrag passt nur, wenn das Relay das Log mit apply_all neu aufgebaut hat.
    let mut a = Client::join_device(s2.addr, "t", &alice, Role::Owner).await;
    let carol = Dev::new("carol", "carol-pc");
    let _c = Client::join_device(s2.addr, "t", &carol, Role::Member).await;
    let add = log.add_member(&alice, &carol, LogRole::Admin);
    assert!(is_ack(&append(&mut a, "t", &add).await));
    log.accept(&add, &alice.holder);
    assert_eq!(log_len(&mut a, "t").await, 3);
}

#[tokio::test]
async fn höchstens_sechzehn_geräte_je_mitglied() {
    let s = start_official().await;
    for i in 0..16 {
        let dev = Dev::new("viel", &format!("gerät-{i}"));
        let _c = Client::join_device(s.addr, "t", &dev, Role::Member).await;
    }
    let extra = Dev::new("viel", "gerät-16");
    let mut c = Client::connect(s.addr).await;
    assert!(matches!(
        c.hello("t", ticket("viel", "t", Role::Member), "gerät-16", None)
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
async fn ablage_verschlüsselter_inhalte() {
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
