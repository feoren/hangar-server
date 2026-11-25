//! Protocol version 4: the listing of a team's decisions (`blob.list`, `blobs`), the live hints
//! `blob.stored` and `blob.deleted`, the pace of listings and the count and size limits of
//! decision blobs.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use hangar_server::config::{Config, IdentityMode};
use hangar_server::ticket::Role;
use hangar_server::util::now_ms;
use hangar_server::wire::limits::{
    BLOB_LIST_EVERY_MS, MAX_BLOB_LIST, MAX_DECISIONS, MAX_DECISIONS_PER_MEMBER,
    MAX_DECISION_CIPHERTEXT_LEN,
};
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

fn v3() -> ProtoRange {
    ProtoRange::new(1, 3).unwrap()
}

fn welcome_of(frame: ServerFrame) -> Welcome {
    match frame.message {
        ServerMessage::Welcome(w) => w,
        other => panic!("no welcome: {other:?}"),
    }
}

fn blob_put(kind: BlobKind, len: usize) -> ClientMessage {
    ClientMessage::BlobPut(BlobPut {
        kind,
        content: Sealed {
            epoch: Epoch(0),
            data: Ciphertext::new("D".repeat(len)).unwrap(),
        },
    })
}

fn decision(len: usize) -> ClientMessage {
    blob_put(BlobKind::Decision, len)
}

fn blob_delete(blob: &BlobId) -> ClientMessage {
    ClientMessage::BlobDelete(BlobDelete { blob: blob.clone() })
}

fn blob_list(kind: BlobKind, after: Option<&BlobId>) -> ClientMessage {
    ClientMessage::BlobList(BlobList {
        kind,
        after: after.cloned(),
    })
}

async fn put(c: &mut Client, team: &str, message: ClientMessage) -> BlobId {
    let r = c.request(team, message).await;
    match r.message {
        ServerMessage::Ack(Ack { blob: Some(id), .. }) => id,
        other => panic!("not stored: {other:?}"),
    }
}

fn listing(frame: &ServerFrame) -> &BlobListing {
    match &frame.message {
        ServerMessage::Blobs(listing) => listing,
        other => panic!("no listing: {other:?}"),
    }
}

/// Every page of one listing from the first, the ids in order.
async fn list_all(c: &mut Client, team: &str) -> (Vec<BlobId>, Vec<usize>) {
    let mut ids = Vec::new();
    let mut pages = Vec::new();
    let mut after: Option<BlobId> = None;
    loop {
        let r = c
            .request(team, blob_list(BlobKind::Decision, after.as_ref()))
            .await;
        let page = listing(&r);
        assert_eq!(page.kind, BlobKind::Decision);
        assert!(page.blobs.len() <= MAX_BLOB_LIST);
        pages.push(page.blobs.len());
        ids.extend(page.blobs.iter().map(|b| b.blob.clone()));
        if !page.more {
            return (ids, pages);
        }
        after = page.blobs.last().map(|b| b.blob.clone());
    }
}

/// Stores `n` blobs of `kind` straight in the database (faster than `blob.put`, and past the
/// count limit), returns their ids in storage order.
async fn seed(s: &TestServer, team: &str, kind: &str, prefix: &str, n: usize) -> Vec<BlobId> {
    let db = &s.server.state.relay.db;
    let mut ids = Vec::new();
    for i in 0..n {
        let id = format!("{team}-{prefix}{i:04}");
        sqlx::query(
            "INSERT INTO relay_blobs (id, team_id, kind, epoch, data, size, member, device, created_at) \
             VALUES (?, ?, ?, 0, 'ZGF0YQ', 6, 'seeder', 'seeder-pc', ?)",
        )
        .bind(&id)
        .bind(team)
        .bind(kind)
        .bind(now_ms() as i64)
        .execute(db)
        .await
        .unwrap();
        ids.push(BlobId::new(id).unwrap());
    }
    ids
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

fn hints(frames: &[ServerFrame]) -> Vec<&ServerFrame> {
    frames
        .iter()
        .filter(|f| {
            matches!(
                f.message,
                ServerMessage::BlobStored(_) | ServerMessage::BlobDeleted(_)
            )
        })
        .collect()
}

async fn append(c: &mut Client, team: &str, entry: &MemberLogAppend) -> ServerFrame {
    c.request(team, ClientMessage::MemberLogAppend(entry.clone()))
        .await
}

/// Connects as `dev` on the newest version and registers its keys, but does not prove.
async fn unproven(addr: SocketAddr, team: &str, dev: &Dev, role: Role) -> Client {
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
    assert_eq!(welcome.proto, PROTOCOL_VERSION);
    let keys = c
        .request(team, ClientMessage::DeviceKeys(dev.keys(team)))
        .await;
    assert!(is_ack(&keys), "{keys:?}");
    c
}

/// Team `t` with alice (owner) and bob (member), both on the newest version, proven and in the
/// log.
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
async fn version_three_sees_no_listing_and_stores_no_decision() {
    let s = start_official().await;
    let (mut new, welcome) = Client::join(s.addr, "solo", "alice", Role::Owner).await;
    assert_eq!(welcome.proto, 4);
    let mut old = Client::connect(s.addr).await;
    let w = welcome_of(
        old.hello_with(
            "solo",
            ticket("alice", "solo", Role::Owner),
            "old",
            v3(),
            None,
        )
        .await,
    );
    assert_eq!(w.proto, 3);
    assert_eq!(
        code(
            &old.request("solo", blob_list(BlobKind::Decision, None))
                .await
        ),
        Some(ErrorCode::BadRequest)
    );
    assert_eq!(
        code(&old.request("solo", decision(10)).await),
        Some(ErrorCode::BadRequest)
    );
    // A task blob stays as on version 3.
    put(&mut old, "solo", blob_put(BlobKind::Task, 10)).await;
    // A decision stored on version 4: no hint for the version 3 connection.
    let id = put(&mut new, "solo", decision(10)).await;
    assert!(is_ack(&new.request("solo", blob_delete(&id)).await));
    let seen = drain(&mut old).await;
    assert!(hints(&seen).is_empty(), "{seen:?}");
}

#[tokio::test]
async fn listings_page_through_decisions_in_storage_order() {
    let s = start_official().await;
    for n in [0usize, 1, 100, 101, 250] {
        let team = format!("p{n}");
        let (mut c, _) = Client::join(s.addr, &team, "alice", Role::Owner).await;
        // Other kinds interleaved: never listed under `decision`.
        seed(&s, &team, "task", "task", 3).await;
        let ids = seed(&s, &team, "decision", "dec", n).await;
        seed(&s, &team, "transcript", "tr", 2).await;
        let (listed, pages) = list_all(&mut c, &team).await;
        assert_eq!(listed, ids, "{n} decisions in storage order");
        let expected: Vec<usize> = match n {
            0 => vec![0],
            1 => vec![1],
            100 => vec![100],
            101 => vec![100, 1],
            _ => vec![100, 100, 50],
        };
        assert_eq!(pages, expected, "{n} decisions");
    }
}

#[tokio::test]
async fn a_listing_carries_metadata_only() {
    let s = start_official().await;
    let (mut c, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let before = now_ms();
    let id = put(&mut c, "t", decision(40)).await;
    // The hint to the own connection comes first; then the page, read as the relay sent it.
    c.until(|f| matches!(f.message, ServerMessage::BlobStored(_)))
        .await;
    let op = c.op();
    c.send(&op, Some("t"), blob_list(BlobKind::Decision, None))
        .await;
    let text = loop {
        let text = c.recv_text().await.expect("the page");
        if text.contains(&format!("\"{op}\"")) {
            break text;
        }
    };
    assert!(!text.contains("DDDD"), "no content in a listing: {text}");
    assert!(!text.contains("\"data\""), "{text}");
    let frame = decode_server(&text).unwrap();
    assert_eq!(frame.seq, None);
    let page = listing(&frame);
    assert!(!page.more);
    assert_eq!(page.blobs.len(), 1);
    let entry = &page.blobs[0];
    assert_eq!(entry.blob, id);
    assert_eq!(entry.by, holder("alice", "alice-device"));
    assert!(entry.created_at.0 >= before && entry.created_at.0 <= now_ms());
}

#[tokio::test]
async fn an_unknown_after_is_not_found() {
    let s = start_official().await;
    let (mut other, _) = Client::join(s.addr, "u", "alice", Role::Owner).await;
    let foreign = put(&mut other, "u", decision(5)).await;
    let (mut c, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    let gone = put(&mut c, "t", decision(5)).await;
    assert!(is_ack(&c.request("t", blob_delete(&gone)).await));
    let task = put(&mut c, "t", blob_put(BlobKind::Task, 5)).await;
    // Each `after` starts a listing of its own: one connection per check.
    for after in [&gone, &foreign, &task] {
        let (mut fresh, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
        assert_eq!(
            code(
                &fresh
                    .request("t", blob_list(BlobKind::Decision, Some(after)))
                    .await
            ),
            Some(ErrorCode::NotFound),
            "{after:?}"
        );
    }
    // Other kinds are not listed at all.
    let (mut fresh, _) = Client::join(s.addr, "t", "carol", Role::Member).await;
    for kind in [BlobKind::Task, BlobKind::Transcript] {
        assert_eq!(
            code(&fresh.request("t", blob_list(kind, None)).await),
            Some(ErrorCode::BadRequest)
        );
    }
    // A refused kind started no listing.
    let r = fresh
        .request("t", blob_list(BlobKind::Decision, None))
        .await;
    listing(&r);
}

#[tokio::test]
async fn a_connection_starts_one_listing_per_five_seconds() {
    let s = start_official().await;
    let (mut c, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    seed(&s, "t", "decision", "dec", 250).await;
    // The pages of one listing pass back to back.
    let (listed, pages) = list_all(&mut c, "t").await;
    assert_eq!((listed.len(), pages.len()), (250, 3));
    // A new listing within 5 s is refused, with the rest of the 5 s.
    let r = c.request("t", blob_list(BlobKind::Decision, None)).await;
    let ServerMessage::Err(refused) = &r.message else {
        panic!("{r:?}")
    };
    assert_eq!(refused.code, ErrorCode::RateLimited);
    let wait = refused.retry_after_ms.expect("retryAfterMs");
    assert!(wait > 0 && wait <= BLOB_LIST_EVERY_MS, "{wait}");
    // `after` of the last page (which said no `more`) starts a new listing too.
    let last = listed.last().unwrap();
    assert_eq!(
        code(
            &c.request("t", blob_list(BlobKind::Decision, Some(last)))
                .await
        ),
        Some(ErrorCode::RateLimited)
    );
    // Another connection has its own pace.
    let (mut other, _) = Client::join(s.addr, "t", "bob", Role::Member).await;
    listing(
        &other
            .request("t", blob_list(BlobKind::Decision, None))
            .await,
    );
    // After the 5 s the next listing passes.
    tokio::time::sleep(Duration::from_millis(wait + 50)).await;
    let r = c.request("t", blob_list(BlobKind::Decision, None)).await;
    assert_eq!(listing(&r).blobs.len(), MAX_BLOB_LIST);
}

#[tokio::test]
async fn only_devices_of_the_log_list() {
    let s = start_official().await;
    let (_log, _alice, mut a, bob, mut b) = team(&s).await;
    put(&mut b, "t", decision(5)).await;
    // An unproven twin of a listed device.
    let mut twin = unproven(s.addr, "t", &bob, Role::Member).await;
    assert_eq!(
        code(&twin.request("t", blob_list(BlobKind::Decision, None)).await),
        Some(ErrorCode::Forbidden)
    );
    // A proven device the log does not list, on the newest version and on version 3.
    let carol = Dev::new("carol", "carol-pc");
    let mut c = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    assert_eq!(
        code(&c.request("t", blob_list(BlobKind::Decision, None)).await),
        Some(ErrorCode::Forbidden)
    );
    let dave = Dev::new("dave", "dave-pc");
    let mut d = Client::join_device_with(s.addr, "t", &dave, Role::Member, v3()).await;
    assert_eq!(
        code(&d.request("t", blob_list(BlobKind::Decision, None)).await),
        Some(ErrorCode::BadRequest)
    );
    // The listed devices do.
    assert_eq!(
        listing(&a.request("t", blob_list(BlobKind::Decision, None)).await)
            .blobs
            .len(),
        1
    );
}

#[tokio::test]
async fn decisions_are_limited_per_team_and_per_member() {
    let s = start_official().await;
    assert_eq!((MAX_DECISIONS, MAX_DECISIONS_PER_MEMBER), (200, 50));
    let mut members = Vec::new();
    for m in 0..4 {
        let (mut c, _) = Client::join(s.addr, "t", &format!("m{m}"), Role::Member).await;
        let mut own = Vec::new();
        for _ in 0..MAX_DECISIONS_PER_MEMBER {
            own.push(put(&mut c, "t", decision(8)).await);
        }
        // The 51st of one member, while the team still has room (for the first three).
        if m < 3 {
            assert_eq!(
                code(&c.request("t", decision(8)).await),
                Some(ErrorCode::Limit),
                "m{m}"
            );
        }
        members.push((c, own));
    }
    let (first, own) = &mut members[0];
    // The 201st of the team, from a member with none yet.
    let (mut late, _) = Client::join(s.addr, "t", "late", Role::Member).await;
    assert_eq!(
        code(&late.request("t", decision(8)).await),
        Some(ErrorCode::Limit)
    );
    // A task blob is not counted.
    put(&mut late, "t", blob_put(BlobKind::Task, 8)).await;
    // After a delete there is room again, for the team and for the member.
    let freed = own.remove(0);
    assert!(is_ack(&first.request("t", blob_delete(&freed)).await));
    put(&mut late, "t", decision(8)).await;
    assert_eq!(
        code(&first.request("t", decision(8)).await),
        Some(ErrorCode::Limit),
        "the team is full again"
    );
    let gone = members[1].1.remove(0);
    assert!(is_ack(&members[1].0.request("t", blob_delete(&gone)).await));
    put(&mut late, "t", decision(8)).await;
    // The team is full. A delete and a put sent at once on one connection: the delete is
    // applied first, so the put has room.
    let (first, own) = &mut members[0];
    let room = own.remove(0);
    let del = first.op();
    first.send(&del, Some("t"), blob_delete(&room)).await;
    let r = first.request("t", decision(8)).await;
    assert!(
        matches!(r.message, ServerMessage::Ack(Ack { blob: Some(_), .. })),
        "{r:?}"
    );
}

#[tokio::test]
async fn decision_size_and_quota_answer_limit() {
    let mut config = Config::for_tests(IdentityMode::Official, website_keys());
    config.blob_quota_bytes = 2 * MAX_DECISION_CIPHERTEXT_LEN as u64;
    let s = start(config).await;
    let (mut c, _) = Client::join(s.addr, "t", "alice", Role::Owner).await;
    assert_eq!(
        code(
            &c.request("t", decision(MAX_DECISION_CIPHERTEXT_LEN + 1))
                .await
        ),
        Some(ErrorCode::Limit)
    );
    // A task blob of that size is not a decision.
    put(
        &mut c,
        "t",
        blob_put(BlobKind::Task, MAX_DECISION_CIPHERTEXT_LEN + 1),
    )
    .await;
    put(&mut c, "t", decision(MAX_DECISION_CIPHERTEXT_LEN - 2)).await;
    // Over the team's byte quota: the same code.
    assert_eq!(
        code(&c.request("t", decision(MAX_DECISION_CIPHERTEXT_LEN)).await),
        Some(ErrorCode::Limit)
    );
}

#[tokio::test]
async fn hints_reach_the_counting_version_four_connections_only() {
    let s = start_official().await;
    let (mut log, _alice, mut a, bob, mut b) = team(&s).await;
    // Bob's phone (newest version) and his old computer (version 3), both in the log.
    let phone = Dev::new("bob", "bob-phone");
    let mut p = Client::connect(s.addr).await;
    let first = welcome_of(
        p.hello("t", ticket("bob", "t", Role::Member), "bob-phone", None)
            .await,
    );
    p.register("t", &phone, &first).await;
    let add = log.add_device(&bob, &phone);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    let old = Dev::new("bob", "bob-old");
    let mut o = Client::join_device_with(s.addr, "t", &old, Role::Member, v3()).await;
    let add = log.add_device(&bob, &old);
    assert!(is_ack(&append(&mut b, "t", &add).await));
    log.accept(&add, &bob.holder);
    // An unproven twin of the laptop, and a proven device the log does not list.
    let mut twin = unproven(s.addr, "t", &bob, Role::Member).await;
    let carol = Dev::new("carol", "carol-pc");
    let mut c = Client::join_device(s.addr, "t", &carol, Role::Member).await;
    for conn in [&mut a, &mut b, &mut p, &mut o, &mut twin, &mut c] {
        drain(conn).await;
    }

    // A task blob gets no hint (stored first: `request` skips what comes before its answer).
    put(&mut b, "t", blob_put(BlobKind::Task, 12)).await;
    let id = put(&mut b, "t", decision(12)).await;
    let stored = |f: &ServerFrame| {
        matches!(&f.message, ServerMessage::BlobStored(m)
            if m.blob == id && m.kind == BlobKind::Decision && m.by == bob.holder)
    };
    for conn in [&mut a, &mut b, &mut p] {
        let seen = drain(conn).await;
        let got = hints(&seen);
        assert_eq!(got.len(), 1, "{seen:?}");
        assert!(stored(got[0]), "{seen:?}");
        assert_eq!(got[0].seq, None);
    }
    for conn in [&mut o, &mut twin, &mut c] {
        let seen = drain(conn).await;
        assert!(hints(&seen).is_empty(), "{seen:?}");
    }

    // Deleted by the owner: `blob.deleted` to the same connections.
    assert!(is_ack(&a.request("t", blob_delete(&id)).await));
    for conn in [&mut a, &mut b, &mut p] {
        let seen = drain(conn).await;
        let got = hints(&seen);
        assert_eq!(got.len(), 1, "{seen:?}");
        assert!(
            matches!(&got[0].message, ServerMessage::BlobDeleted(m)
                if m.blob == id && m.kind == BlobKind::Decision),
            "{seen:?}"
        );
        assert_eq!(got[0].seq, None);
    }
    for conn in [&mut o, &mut twin, &mut c] {
        let seen = drain(conn).await;
        assert!(hints(&seen).is_empty(), "{seen:?}");
    }
    // A delete that finds nothing announces nothing.
    assert_eq!(
        code(&a.request("t", blob_delete(&id)).await),
        Some(ErrorCode::NotFound)
    );
    for conn in [&mut a, &mut b, &mut p] {
        let seen = drain(conn).await;
        assert!(hints(&seen).is_empty(), "after notFound: {seen:?}");
    }

    // Not replayed: the phone comes back with the cursor of its first `welcome` and gets the
    // logged events since (the log entries), but no hint.
    p.close().await;
    put(&mut a, "t", decision(3)).await;
    let mut back = Client::connect(s.addr).await;
    let cursor = Cursor {
        stream: first.stream.clone(),
        seq: first.head,
    };
    let frame = back
        .hello(
            "t",
            ticket("bob", "t", Role::Member),
            "bob-phone",
            Some(cursor),
        )
        .await;
    welcome_of(frame);
    // Straight after the `welcome`, before `device.keys`: the replay follows it.
    let seen = drain(&mut back).await;
    assert!(
        seen.iter()
            .any(|f| matches!(f.message, ServerMessage::MemberLogAppended(_))),
        "the replay ran: {seen:?}"
    );
    assert!(hints(&seen).is_empty(), "{seen:?}");
}
