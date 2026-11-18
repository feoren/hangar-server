//! Runtime state of a team. The rules come from the app's protocol crate: `ReservationBook`
//! ("first wins", expiry, release, rekey), `ClaimBoard` (comparison of the keyed hashes),
//! `EventLog` (sequence, replay, resync), `RecentOps` (retries per sender, team and operation ID
//! with a digest of the content), `check_epoch`, `check_rotate`, `check_append`. Only
//! distribution, storage and the permissions the relay knows from the ticket live here.
//!
//! The caller holds the team lock; thus the order of arrival counts as the truth, and events go
//! to all receivers in sequence order.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use axum::extract::ws::Utf8Bytes;
use hangar_team_crypto::identity::DevicePublicKeys;
use hangar_team_crypto::memberlog::{Admitted, EntryBody, LogError, LogVerifier};
use hangar_team_crypto::relay::{check_registered_keys, check_wrap};
use hangar_team_protocol::log::{EventLog, OpKey, RecentOps, Replay, Retry};
use hangar_team_protocol::overlap::{ClaimBoard, OverlapNotice, SessionClaims};
use hangar_team_protocol::reservation::{
    BookEvent, BookSnapshot, Hold, Intent, Policy, Rejection, Reservation, ReservationBook,
    ReservationEvent, ReservationState,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::store::{self, BlobPut, EpochChange, MemberSeen};
use crate::db::Db;
use crate::ticket::Role;
use crate::wire::{
    self, ack, check_rotate, error, limits::MAX_DEVICES_PER_MEMBER, limits::MAX_LOG_ENTRIES,
    limits::MAX_WRAPPED_KEYS, Ack, BlobKind, Ciphertext, ClientMessage, Cursor, DeviceList,
    DeviceRemoved, Epoch, ErrorBody, ErrorCode, Holder, KeyRotated, KeyWrapped, KeyedHash,
    MemberId, MemberJoined, MemberLogAppended, MemberLogEntries, MemberRemoved, MemberRoleChanged,
    Notify as NotifyMessage, OpId, PresenceState, PresenceUpdate, ReservationExpired,
    ReservationExpiring, ResyncRequired, Sealed, Seq, ServerFrame, ServerMessage, SessionKey,
    SessionRef, StreamId, TaskReleaseAnswered, TaskReleaseRequestEnded, TaskReleaseRequested,
    TaskReleased, TaskReserved, TeamId, UnixMillis, Welcome,
};

/// Events kept in memory for replay; older ones require a snapshot.
pub const REPLAY_WINDOW: usize = 2048;
/// Remembered operation IDs per team for idempotent retries.
pub const RECENT_OPS: usize = 4096;
/// Claims per device.
pub const MAX_SESSIONS_PER_DEVICE: usize = 64;
/// Claims per team (protects memory).
pub const MAX_SESSIONS_PER_TEAM: usize = 2000;
/// Claims of a device that has been offline this long expire (in milliseconds).
pub const OFFLINE_CLAIMS_MS: u64 = 24 * 60 * 60 * 1000;

/// Close codes and `hello` deadline of the protocol crate.
pub mod close {
    pub use hangar_team_protocol::close::{
        CLOSE_HELLO_TIMEOUT, CLOSE_REMOVED, CLOSE_ROLE_CHANGED, CLOSE_TEAM_DELETED,
        HELLO_TIMEOUT_SECS,
    };
}

/// What goes to a connection.
#[derive(Debug, Clone)]
pub enum Outgoing {
    Text(Utf8Bytes),
    Close(u16, &'static str),
}

/// A connection that has joined the team.
#[derive(Debug, Clone)]
pub struct Subscriber {
    pub holder: Holder,
    pub role: Role,
    pub tx: super::outbox::Outbox,
    /// Triggered when the connection can no longer keep up (queue full).
    pub kick: Arc<Notify>,
    /// Triggered when a log entry took the device out of the team: the connection starts the
    /// grace period during which it may only send `memberlog.get`.
    pub removed: Arc<Notify>,
}

/// A connection of a removed device in its grace period: no member, no presence, no receiver of
/// events except `memberlog.appended` (up to `until`) and its own `device.removed`. Only
/// `memberlog.get` is answered, with entries up to `until` (the entry that removed the
/// device).
#[derive(Debug, Clone)]
struct Departing {
    holder: Holder,
    tx: super::outbox::Outbox,
    until: u64,
}

/// Result of a join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Joined {
    /// Joined as usual.
    Member,
    /// Blocked device: only `welcome`, then only `memberlog.get` up to the removing entry, then
    /// close 4403 (see `conn`).
    Departing,
}

/// Who a notice email could be for (self-hosting): the member is not connected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attention {
    pub team: String,
    pub member: String,
}

type Reply = Result<Ack, ErrorBody>;

/// Notes the relay keeps next to the book and stores with it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredNotes {
    holds: BTreeMap<KeyedHash, Sealed>,
    requests: BTreeMap<KeyedHash, Sealed>,
}

fn hold_of(reservation: &Reservation) -> Option<&Hold> {
    match reservation.state() {
        ReservationState::Held { hold }
        | ReservationState::Expiring { hold, .. }
        | ReservationState::ReleaseRequested { hold, .. } => Some(hold),
        _ => None,
    }
}

fn rejection(r: &Rejection, now: UnixMillis) -> ErrorBody {
    ErrorBody {
        code: r.code(),
        retry_after_ms: r.retry_after_ms(now),
        holder: r.holder().cloned(),
    }
}

fn blob_kind(kind: BlobKind) -> &'static str {
    match kind {
        BlobKind::Decision => "decision",
        BlobKind::Task => "task",
        BlobKind::Transcript => "transcript",
    }
}

pub struct Team {
    pub id: String,
    team: TeamId,
    policy: Policy,
    log: EventLog<ServerMessage>,
    book: ReservationBook,
    board: ClaimBoard,
    /// Sessions per device, for the limits (the board does not count them).
    sessions: HashMap<Holder, HashSet<SessionKey>>,
    /// Encrypted notes of held tasks and open release requests; the book does not know them,
    /// the events carry them.
    notes: HashMap<KeyedHash, Sealed>,
    request_notes: HashMap<KeyedHash, Sealed>,
    members: BTreeMap<String, Role>,
    presence: HashMap<Holder, PresenceUpdate>,
    subscribers: HashMap<u64, Subscriber>,
    /// Connections of removed devices in their grace period (see `Departing`).
    departing: HashMap<u64, Departing>,
    offline_since: HashMap<Holder, u64>,
    ops: RecentOps<Reply>,
    /// The verified membership log (hangar-team-crypto), rebuilt from the stored entries with
    /// `apply_all` after a restart.
    verifier: LogVerifier,
    /// Latest undelivered `notify` per member (also stored).
    pending: HashMap<MemberId, NotifyMessage>,
    /// The book has changed since the last save.
    dirty: bool,
    pub attention: Vec<Attention>,
    pub last_activity: u64,
}

impl Team {
    /// Loads a team: book and log position from the stored state (the crate's `restore`; all
    /// holders count as disconnected afterwards); the restart events go into the log. If the
    /// state is missing or does not fit, an empty book starts with a new stream (clients fetch a
    /// snapshot).
    pub async fn load(db: &Db, id: &str, policy: Policy, now: u64) -> Result<Team, sqlx::Error> {
        let protocol = |e: String| sqlx::Error::Protocol(e);
        let team = TeamId::new(id).map_err(|e| protocol(e.to_string()))?;
        let row = store::load_team(db, id, now).await?;
        let at = UnixMillis(now);
        let restored = row.state.as_ref().and_then(|state| {
            let position: Cursor = serde_json::from_str(&state.position).ok()?;
            let notes: StoredNotes = serde_json::from_str(&state.notes).unwrap_or_default();
            let snapshot = match BookSnapshot::from_json(&state.book) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(%error, "cannot read reservations, new stream");
                    return None;
                }
            };
            match ReservationBook::restore(snapshot, policy, at) {
                Ok(restored) => Some((position, notes, restored)),
                Err(error) => {
                    tracing::warn!(%error, "cannot restore reservations, new stream");
                    None
                }
            }
        });
        let (log, book, notes, events) = match restored {
            Some((position, notes, restored)) => (
                EventLog::resume(position.stream, position.seq, REPLAY_WINDOW),
                restored.book,
                notes,
                restored.events,
            ),
            None => {
                let stream =
                    StreamId::new(row.fresh_stream).map_err(|e| protocol(e.to_string()))?;
                (
                    EventLog::new(stream, REPLAY_WINDOW),
                    ReservationBook::new(policy, Epoch(row.epoch)),
                    StoredNotes::default(),
                    Vec::new(),
                )
            }
        };
        let members = store::members(db, id).await?.into_iter().collect();
        let mut verifier = LogVerifier::new(team.clone());
        let entries = store::log_all(db, id).await?;
        if let Err(error) = verifier.apply_all(&entries) {
            // Only what was admitted gets stored; an error here means corrupted data.
            // The log stops at the last valid entry.
            tracing::error!(%error, "stored membership log cannot be replayed");
        }
        let mut pending = HashMap::new();
        for (member, json) in store::pending_notifies(db, id).await? {
            let parsed = MemberId::new(member)
                .ok()
                .zip(serde_json::from_str(&json).ok());
            if let Some((member, notify)) = parsed {
                pending.insert(member, notify);
            }
        }
        let mut loaded = Team {
            id: id.to_owned(),
            team,
            policy,
            log,
            book,
            board: ClaimBoard::new(),
            sessions: HashMap::new(),
            notes: notes.holds.into_iter().collect(),
            request_notes: notes.requests.into_iter().collect(),
            members,
            presence: HashMap::new(),
            subscribers: HashMap::new(),
            departing: HashMap::new(),
            offline_since: HashMap::new(),
            ops: RecentOps::new(RECENT_OPS),
            verifier,
            pending,
            dirty: true,
            attention: Vec::new(),
            last_activity: now,
        };
        let mut events = loaded.book_messages(events);
        // If a crash left the epoch in the database further ahead than in the book, the
        // database's one applies (key.rotate was already confirmed there).
        if Epoch(row.epoch) > loaded.book.epoch() {
            if let Ok(rotated) = loaded.book.rotate(Epoch(row.epoch), at) {
                events.extend(loaded.book_messages(rotated));
            }
        }
        loaded.prune_notes();
        loaded.emit(db, events, None).await?;
        Ok(loaded)
    }

    pub fn head(&self) -> Seq {
        self.log.head()
    }

    pub fn epoch(&self) -> Epoch {
        self.book.epoch()
    }

    /// Nothing connected, nothing held, nothing remembered: may be unloaded from memory.
    pub fn idle(&self, now: u64) -> bool {
        self.subscribers.is_empty()
            && self.departing.is_empty()
            && self.book.iter().next().is_none()
            && self.sessions.is_empty()
            && now.saturating_sub(self.last_activity) > 10 * 60 * 1000
    }

    fn online(&self, holder: &Holder) -> bool {
        self.subscribers.values().any(|s| s.holder == *holder)
    }

    fn member_online(&self, member: &MemberId) -> bool {
        self.subscribers
            .values()
            .any(|s| s.holder.member == *member)
    }

    fn frame(
        &self,
        id: Option<&OpId>,
        seq: Option<Seq>,
        message: ServerMessage,
    ) -> Option<Utf8Bytes> {
        let kind = message.kind();
        match wire::encode_server(&ServerFrame {
            id: id.cloned(),
            seq,
            team: Some(self.team.clone()),
            message,
        }) {
            Ok(text) => Some(Utf8Bytes::from(text)),
            Err(error) => {
                tracing::error!(%error, kind, "cannot encode frame");
                None
            }
        }
    }

    fn send(&mut self, conn: u64, text: Option<Utf8Bytes>) {
        let Some(text) = text else { return };
        if let Some(sub) = self.subscribers.get(&conn) {
            // Whoever cannot keep up is kicked by the outbox and catches up via cursor.
            sub.tx.try_send(Outgoing::Text(text));
        }
    }

    fn reply(&mut self, conn: u64, op: &OpId, reply: Reply) {
        let message = match reply {
            Ok(ack) => ServerMessage::Ack(ack),
            Err(body) => ServerMessage::Err(body),
        };
        let text = self.frame(Some(op), None, message);
        self.send(conn, text);
    }

    /// A book event as a server message, with the notes the relay holds.
    fn book_message(&self, (task, event): BookEvent) -> ServerMessage {
        match event {
            ReservationEvent::Reserved {
                holder,
                epoch,
                since,
                expires_at,
            } => ServerMessage::TaskReserved(TaskReserved {
                task,
                holder,
                epoch,
                since,
                expires_at,
                note: self.notes.get(&task).cloned(),
            }),
            ReservationEvent::Released { holder, reason } => {
                ServerMessage::TaskReleased(TaskReleased {
                    task,
                    holder,
                    reason,
                })
            }
            ReservationEvent::Expiring { holder, expires_at } => {
                ServerMessage::ReservationExpiring(ReservationExpiring {
                    task,
                    holder,
                    expires_at,
                })
            }
            ReservationEvent::Expired { holder } => {
                ServerMessage::ReservationExpired(ReservationExpired { task, holder })
            }
            ReservationEvent::ReleaseRequested { holder, requester } => {
                ServerMessage::TaskReleaseRequested(TaskReleaseRequested {
                    task,
                    holder,
                    requester: requester.member,
                    note: self.request_notes.get(&task).cloned(),
                })
            }
            ReservationEvent::ReleaseAnswered {
                holder,
                requester,
                accepted,
            } => ServerMessage::TaskReleaseAnswered(TaskReleaseAnswered {
                task,
                holder,
                requester: requester.member,
                accepted,
            }),
            ReservationEvent::ReleaseRequestEnded {
                holder,
                requester,
                reason,
            } => ServerMessage::TaskReleaseRequestEnded(TaskReleaseRequestEnded {
                task,
                holder,
                requester: requester.member,
                reason,
            }),
        }
    }

    fn book_messages(&self, events: Vec<BookEvent>) -> Vec<ServerMessage> {
        events.into_iter().map(|e| self.book_message(e)).collect()
    }

    /// Keeps notes only for tasks that are still held or requested.
    fn prune_notes(&mut self) {
        let book = &self.book;
        self.notes.retain(|task, _| book.get(task).is_some());
        self.request_notes.retain(|task, _| {
            matches!(
                book.get(task).map(Reservation::state),
                Some(ReservationState::ReleaseRequested { .. })
            )
        });
    }

    /// Distributes events: logged ones get the next sequence number, all go to every connection
    /// of the team. `wrapped` fills `key.rotated` per device.
    async fn emit(
        &mut self,
        db: &Db,
        messages: Vec<ServerMessage>,
        wrapped: Option<&HashMap<Holder, Ciphertext>>,
    ) -> Result<(), sqlx::Error> {
        if messages.is_empty() {
            if self.dirty {
                self.persist(db).await?;
            }
            return Ok(());
        }
        // Durability rule: store book and log position first, then send. No frame with `seq`
        // leaves the relay before a stored head covers it; otherwise a restart would assign the
        // same `seq` to a new event.
        let mut numbered = Vec::with_capacity(messages.len());
        let mut notifies = Vec::new();
        let mut logged = false;
        for message in messages {
            self.note_attention(&message);
            if let Some(notify) = NotifyMessage::attention(&message, |m| self.member_online(m)) {
                notifies.push(notify);
            }
            let seq = message.loggable().then(|| self.log.push(message.clone()));
            logged |= seq.is_some();
            numbered.push((seq, message));
        }
        if logged || self.dirty {
            self.persist(db).await?;
        }
        for notify in notifies {
            if let Ok(json) = serde_json::to_string(&notify) {
                store::set_pending_notify(
                    db,
                    &self.id,
                    notify.member.as_str(),
                    &json,
                    crate::util::now_ms(),
                )
                .await?;
            }
            self.pending.insert(notify.member.clone(), notify);
        }
        for (seq, message) in numbered {
            let conns: Vec<(u64, Holder)> = self
                .subscribers
                .iter()
                .map(|(c, s)| (*c, s.holder.clone()))
                .collect();
            match &message {
                ServerMessage::KeyRotated(rotated) => {
                    for (conn, holder) in conns {
                        let personal = ServerMessage::KeyRotated(KeyRotated {
                            epoch: rotated.epoch,
                            wrapped: wrapped.and_then(|w| w.get(&holder).cloned()),
                        });
                        let text = self.frame(None, seq, personal);
                        self.send(conn, text);
                    }
                }
                _ => {
                    self.send_departing(&message);
                    let text = self.frame(None, seq, message);
                    for (conn, _) in conns {
                        self.send(conn, text.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// A removed device in its grace period only gets what leads to its removal:
    /// `memberlog.appended` up to the removing entry and its own `device.removed`, both without
    /// `seq`: it does not get the events in between (such as the release of its reservations),
    /// and with `seq` the app would see a gap and abort the session before it has verified its
    /// removal in the log.
    fn send_departing(&self, message: &ServerMessage) {
        let mut text = None;
        for departing in self.departing.values() {
            let wanted = match message {
                ServerMessage::MemberLogAppended(m) => m.index <= departing.until,
                ServerMessage::DeviceRemoved(r) => r.holder == departing.holder,
                _ => false,
            };
            if !wanted {
                continue;
            }
            if text.is_none() {
                text = self.frame(None, None, message.clone());
            }
            if let Some(text) = &text {
                departing.tx.try_send(Outgoing::Text(text.clone()));
            }
        }
    }

    /// `memberlog.get` of a connection in its grace period: entries after `after` up to the
    /// removing entry. `None`: the connection is not in its grace period here. `Some(true)`: the
    /// last page has been answered, the connection closes with 4403.
    pub async fn departing_log_get(
        &mut self,
        db: &Db,
        conn: u64,
        op: &OpId,
        after: u64,
    ) -> Result<Option<bool>, sqlx::Error> {
        let Some(departing) = self.departing.get(&conn).cloned() else {
            return Ok(None);
        };
        let entries =
            store::log_get_until(db, &self.id, after, departing.until, MAX_LOG_ENTRIES + 1).await?;
        let page = MemberLogEntries::page(entries);
        let done = !page.more;
        if let Some(text) = self.frame(Some(op), None, ServerMessage::MemberLogEntries(page)) {
            departing.tx.try_send(Outgoing::Text(text));
        }
        if done {
            self.departing.remove(&conn);
        }
        Ok(Some(done))
    }

    /// Book (`export`), log position and notes in a single write.
    async fn persist(&mut self, db: &Db) -> Result<(), sqlx::Error> {
        let encode = |e: serde_json::Error| sqlx::Error::Protocol(e.to_string());
        let book = serde_json::to_string(&self.book.export()).map_err(encode)?;
        let position = serde_json::to_string(&self.log.position()).map_err(encode)?;
        let notes = serde_json::to_string(&StoredNotes {
            holds: self.notes.iter().map(|(k, v)| (*k, v.clone())).collect(),
            requests: self
                .request_notes
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        })
        .map_err(encode)?;
        store::save_state(
            db,
            &self.id,
            &book,
            &position,
            &notes,
            crate::util::now_ms(),
        )
        .await?;
        self.dirty = false;
        Ok(())
    }

    /// Sends a member's remembered `notify` to all of its connections (after `welcome`).
    async fn deliver_pending(&mut self, db: &Db, member: &MemberId) -> Result<(), sqlx::Error> {
        let Some(notify) = self.pending.remove(member) else {
            return Ok(());
        };
        let text = self.frame(None, None, ServerMessage::Notify(notify));
        let conns: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.holder.member == *member)
            .map(|(c, _)| *c)
            .collect();
        for conn in conns {
            self.send(conn, text.clone());
        }
        store::clear_pending_notify(db, &self.id, member.as_str()).await
    }

    /// Release request or upcoming expiry for a holder that is not connected. `emit` stores the
    /// `notify`; in self-hosting a notice email is sent in addition.
    fn note_attention(&mut self, message: &ServerMessage) {
        let member = match message {
            ServerMessage::TaskReleaseRequested(m) => &m.holder.member,
            ServerMessage::ReservationExpiring(m) => &m.holder.member,
            _ => return,
        };
        if !self.member_online(member) {
            self.attention.push(Attention {
                team: self.id.clone(),
                member: member.as_str().to_owned(),
            });
        }
    }

    /// Joins a connection after a verified ticket. Sends replay or snapshot and then the join
    /// events. Presence counts per connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn join(
        &mut self,
        db: &Db,
        conn: u64,
        op: &OpId,
        sub: Subscriber,
        cursor: Option<&Cursor>,
        proto: u16,
        ticket_iat_ms: u64,
        now: u64,
        allow_departing: bool,
    ) -> Result<Result<Joined, ErrorCode>, sqlx::Error> {
        // The blocked device first, without writing anything: it does not count as a member.
        if let Some(until) = store::device_removed(
            db,
            &self.id,
            sub.holder.member.as_str(),
            sub.holder.device.as_str(),
        )
        .await?
        {
            let age =
                store::ticket_age(db, &self.id, sub.holder.member.as_str(), ticket_iat_ms).await?;
            if !allow_departing || age != store::TicketAge::Current {
                tracing::info!("hello from a removed device rejected");
                return Ok(Err(ErrorCode::Forbidden));
            }
            tracing::info!("hello from a removed device: only memberlog.get up to the removal");
            let welcome = ServerMessage::Welcome(Welcome {
                proto,
                stream: self.log.stream().clone(),
                head: self.log.head(),
                member: sub.holder.member.clone(),
                epoch: self.book.epoch(),
            });
            if let Some(text) = self.frame(Some(op), None, welcome) {
                sub.tx.try_send(Outgoing::Text(text));
            }
            self.departing.insert(
                conn,
                Departing {
                    holder: sub.holder,
                    tx: sub.tx,
                    until,
                },
            );
            return Ok(Ok(Joined::Departing));
        }
        let seen = store::see_member(
            db,
            &self.id,
            sub.holder.member.as_str(),
            sub.role,
            ticket_iat_ms,
            now,
        )
        .await?;
        if matches!(seen, MemberSeen::Removed | MemberSeen::Stale) {
            return Ok(Err(ErrorCode::Forbidden));
        }
        self.last_activity = now;
        let holder = sub.holder.clone();
        let role = sub.role;
        self.subscribers.insert(conn, sub);
        let welcome = ServerMessage::Welcome(Welcome {
            proto,
            stream: self.log.stream().clone(),
            head: self.log.head(),
            member: holder.member.clone(),
            epoch: self.book.epoch(),
        });
        let replay = match self.log.replay(cursor) {
            Replay::Events(events) => Ok(events
                .into_iter()
                .map(|(seq, m)| (seq, m.clone()))
                .collect::<Vec<_>>()),
            Replay::Resync(reason) => Err(reason),
        };
        match replay {
            Ok(events) => {
                let text = self.frame(Some(op), None, welcome);
                self.send(conn, text);
                for (seq, message) in events {
                    let message = self.personalize(db, &holder, message).await?;
                    let text = self.frame(None, Some(seq), message);
                    self.send(conn, text);
                }
            }
            Err(reason) => {
                let resync = ServerMessage::ResyncRequired(ResyncRequired {
                    stream: self.log.stream().clone(),
                    head: self.log.head(),
                    reason,
                });
                let text = self.frame(Some(op), None, resync);
                self.send(conn, text);
                for message in self.snapshot() {
                    let text = self.frame(None, None, message);
                    self.send(conn, text);
                }
                let text = self.frame(Some(op), None, welcome);
                self.send(conn, text);
            }
        }
        let mut events = Vec::new();
        match seen {
            MemberSeen::New => events.push(ServerMessage::MemberJoined(MemberJoined {
                member: holder.member.clone(),
                role: wire::role(role),
            })),
            MemberSeen::RoleChanged => {
                events.push(ServerMessage::MemberRoleChanged(MemberRoleChanged {
                    member: holder.member.clone(),
                    role: wire::role(role),
                }))
            }
            _ => {}
        }
        self.members.insert(holder.member.as_str().to_owned(), role);
        self.offline_since.remove(&holder);
        let presence = self.book.presence(&holder, true, UnixMillis(now));
        self.dirty = true;
        events.extend(self.book_messages(presence));
        self.prune_notes();
        self.emit(db, events, None).await?;
        self.deliver_pending(db, &holder.member).await?;
        Ok(Ok(Joined::Member))
    }

    async fn personalize(
        &self,
        db: &Db,
        holder: &Holder,
        message: ServerMessage,
    ) -> Result<ServerMessage, sqlx::Error> {
        Ok(match message {
            ServerMessage::KeyRotated(r) => {
                let wrapped = store::key_package(db, &self.id, r.epoch, holder).await?;
                ServerMessage::KeyRotated(KeyRotated {
                    epoch: r.epoch,
                    wrapped,
                })
            }
            other => other,
        })
    }

    /// State as events without `seq` (after `resync_required`).
    fn snapshot(&self) -> Vec<ServerMessage> {
        let mut out: Vec<ServerMessage> = self
            .members
            .iter()
            .filter_map(|(member, role)| {
                Some(ServerMessage::MemberJoined(MemberJoined {
                    member: MemberId::new(member.clone()).ok()?,
                    role: wire::role(*role),
                }))
            })
            .collect();
        let policy = self.policy;
        for (task, reservation) in self.book.iter() {
            let Some(hold) = hold_of(reservation) else {
                continue;
            };
            out.push(ServerMessage::TaskReserved(TaskReserved {
                task: *task,
                holder: hold.holder.clone(),
                epoch: hold.epoch,
                since: hold.since,
                expires_at: hold.deadline(&policy),
                note: self.notes.get(task).cloned(),
            }));
            let warned = match reservation.state() {
                ReservationState::Expiring { .. } => true,
                ReservationState::ReleaseRequested { warned_at, .. } => warned_at.is_some(),
                _ => false,
            };
            if let (true, Some(expires_at)) = (warned, hold.deadline(&policy)) {
                out.push(ServerMessage::ReservationExpiring(ReservationExpiring {
                    task: *task,
                    holder: hold.holder.clone(),
                    expires_at,
                }));
            }
            if let ReservationState::ReleaseRequested { request, .. } = reservation.state() {
                out.push(ServerMessage::TaskReleaseRequested(TaskReleaseRequested {
                    task: *task,
                    holder: hold.holder.clone(),
                    requester: request.requester.member.clone(),
                    note: self.request_notes.get(task).cloned(),
                }));
            }
        }
        out.extend(
            self.presence
                .values()
                .cloned()
                .map(ServerMessage::PresenceUpdate),
        );
        out
    }

    /// A connection leaves (disconnected, too slow, ticket age reached).
    pub async fn leave(&mut self, db: &Db, conn: u64, now: u64) -> Result<(), sqlx::Error> {
        self.departing.remove(&conn);
        let Some(sub) = self.subscribers.remove(&conn) else {
            return Ok(());
        };
        self.last_activity = now;
        let presence = self.book.presence(&sub.holder, false, UnixMillis(now));
        self.dirty = true;
        let mut events = self.book_messages(presence);
        if !self.online(&sub.holder) {
            self.offline_since.insert(sub.holder.clone(), now);
            self.presence.remove(&sub.holder);
            events.push(ServerMessage::PresenceUpdate(PresenceUpdate {
                holder: sub.holder.clone(),
                state: PresenceState::Offline,
                status: None,
                at: UnixMillis(now),
            }));
        }
        self.prune_notes();
        self.emit(db, events, None).await
    }

    fn close_where(&mut self, code: u16, reason: &'static str, pred: impl Fn(&Subscriber) -> bool) {
        let gone: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| pred(s))
            .map(|(c, _)| *c)
            .collect();
        for conn in gone {
            if let Some(sub) = self.subscribers.remove(&conn) {
                sub.tx.try_send(Outgoing::Close(code, reason));
            }
        }
    }

    /// A member was removed (self-hosting or revocation list): reservations and claims end,
    /// open connections are closed with 4403.
    pub async fn remove_member(
        &mut self,
        db: &Db,
        member: &MemberId,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        let removed = self.book.remove_member(member, UnixMillis(now));
        self.dirty = true;
        let mut events = self.book_messages(removed);
        let was_member = self.members.remove(member.as_str()).is_some();
        if was_member {
            events.push(ServerMessage::MemberRemoved(MemberRemoved {
                member: member.clone(),
            }));
        }
        let notices = self.board.clear_member(member);
        self.sessions.retain(|holder, _| holder.member != *member);
        self.deliver_overlaps(notices);
        self.close_where(close::CLOSE_REMOVED, "removed", |s| {
            s.holder.member == *member
        });
        self.presence.retain(|holder, _| holder.member != *member);
        self.prune_notes();
        self.emit(db, events, None).await
    }

    /// A device leaves the team (its member stays): reservations released, claims gone. Its
    /// connections stop being receivers right away; they start their grace period (`Departing`,
    /// up to the entry `until`) during which they may only send `memberlog.get`, then `conn`
    /// closes with 4403. Returns the events (without `device.removed`).
    fn drop_device(&mut self, holder: &Holder, until: u64, now: u64) -> Vec<ServerMessage> {
        let removed = self.book.remove_device(holder, UnixMillis(now));
        self.dirty = true;
        let events = self.book_messages(removed);
        let notices = self.board.clear_device(holder);
        self.sessions.remove(holder);
        self.deliver_overlaps(notices);
        let gone: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.holder == *holder)
            .map(|(c, _)| *c)
            .collect();
        for conn in gone {
            if let Some(sub) = self.subscribers.remove(&conn) {
                sub.removed.notify_one();
                self.departing.insert(
                    conn,
                    Departing {
                        holder: sub.holder,
                        tx: sub.tx,
                        until,
                    },
                );
            }
        }
        self.presence.remove(holder);
        self.offline_since.remove(holder);
        self.prune_notes();
        events
    }

    /// Closes a member's connections (4401) because its role changed and the new one is
    /// unknown; the app comes back with a new ticket.
    pub fn renew_member(&mut self, member: &str) {
        self.close_where(close::CLOSE_ROLE_CHANGED, "role changed", |s| {
            s.holder.member.as_str() == member
        });
    }

    /// Applies a known new role silently to all connections of the member (from
    /// `ticket.renew`, the revocation list or self-hosting). Permissions are checked per
    /// message, so owner and admin intents fail by themselves afterwards; nothing is
    /// disconnected. A real change reports `member.role_changed`.
    pub async fn apply_role(
        &mut self,
        db: &Db,
        member: &MemberId,
        role: Role,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        for sub in self.subscribers.values_mut() {
            if sub.holder.member == *member {
                sub.role = role;
            }
        }
        let changed = self.members.get(member.as_str()) != Some(&role);
        if !changed {
            return Ok(());
        }
        let known = self.members.contains_key(member.as_str());
        self.members.insert(member.as_str().to_owned(), role);
        store::set_member_role(db, &self.id, member.as_str(), role, now).await?;
        if known {
            let event = ServerMessage::MemberRoleChanged(MemberRoleChanged {
                member: member.clone(),
                role: wire::role(role),
            });
            self.emit(db, vec![event], None).await?;
        }
        Ok(())
    }

    /// Closes all connections (team deleted).
    pub fn close_all(&mut self) {
        for (_, sub) in self.subscribers.drain() {
            sub.tx
                .try_send(Outgoing::Close(close::CLOSE_TEAM_DELETED, "team deleted"));
        }
        for (_, departing) in self.departing.drain() {
            departing
                .tx
                .try_send(Outgoing::Close(close::CLOSE_TEAM_DELETED, "team deleted"));
        }
    }

    fn deliver_overlaps(&mut self, notices: Vec<OverlapNotice>) {
        for notice in notices {
            let conns: Vec<u64> = self
                .subscribers
                .iter()
                .filter(|(_, s)| s.holder == notice.to.holder)
                .map(|(c, _)| *c)
                .collect();
            let text = self.frame(None, None, ServerMessage::ClaimOverlap(notice.overlap));
            for conn in conns {
                self.send(conn, text.clone());
            }
        }
    }

    pub async fn tick(&mut self, db: &Db, now: u64) -> Result<(), sqlx::Error> {
        let events = self.book.tick(UnixMillis(now));
        if !events.is_empty() {
            self.dirty = true;
        }
        let events = self.book_messages(events);
        self.prune_notes();
        self.emit(db, events, None).await?;
        let stale: Vec<Holder> = self
            .offline_since
            .iter()
            .filter(|(_, since)| now.saturating_sub(**since) > OFFLINE_CLAIMS_MS)
            .map(|(h, _)| h.clone())
            .collect();
        for holder in stale {
            self.offline_since.remove(&holder);
            self.sessions.remove(&holder);
            let notices = self.board.clear_device(&holder);
            self.deliver_overlaps(notices);
        }
        Ok(())
    }

    /// An intent of a joined connection.
    pub async fn handle(
        &mut self,
        db: &Db,
        limits: &HandleLimits,
        conn: u64,
        op: &OpId,
        message: ClientMessage,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        let Some(sub) = self.subscribers.get(&conn).cloned() else {
            // Removed while the frame was already in flight: a `memberlog.get` gets the grace
            // period answer, so the app does not wait for an answer that never comes.
            if let ClientMessage::MemberLogGet(get) = message {
                self.departing_log_get(db, conn, op, get.after).await?;
            }
            return Ok(());
        };
        self.last_activity = now;
        let who = sub.holder.clone();
        let at = UnixMillis(now);
        let dedup = message.deduplicated().then(|| {
            let key = OpKey {
                holder: who.clone(),
                team: self.team.clone(),
                op: op.clone(),
            };
            (key, message.digest())
        });
        if let Some((key, digest)) = &dedup {
            match self.ops.check(key, digest) {
                Retry::Same(reply) => {
                    let reply = reply.clone();
                    self.reply(conn, op, reply);
                    return Ok(());
                }
                Retry::Mismatch => {
                    self.reply(conn, op, Err(error(ErrorCode::BadRequest)));
                    return Ok(());
                }
                Retry::New => {}
            }
        }
        let (events, reply, wrapped) = match message.check_epoch(self.book.epoch()) {
            Err(stale) => (Vec::new(), Some(Err(error(stale.code()))), None),
            Ok(()) => self.apply(db, limits, conn, op, &sub, message, at).await?,
        };
        let Some(reply) = reply else {
            return Ok(());
        };
        self.prune_notes();
        self.emit(db, events, wrapped.as_ref()).await?;
        if let Some((key, digest)) = dedup {
            self.ops.remember(key, digest, reply.clone());
        }
        self.reply(conn, op, reply);
        Ok(())
    }

    /// Applies an intent. `None` as reply: the reply has already been sent (reads).
    #[allow(clippy::too_many_arguments)]
    async fn apply(
        &mut self,
        db: &Db,
        limits: &HandleLimits,
        conn: u64,
        op: &OpId,
        sub: &Subscriber,
        message: ClientMessage,
        at: UnixMillis,
    ) -> Result<
        (
            Vec<ServerMessage>,
            Option<Reply>,
            Option<HashMap<Holder, Ciphertext>>,
        ),
        sqlx::Error,
    > {
        let who = sub.holder.clone();
        let now = at.0;
        let book = |team: &mut Team, intent: Intent| {
            let (events, refused) = team.book.apply(&who, intent, at).into_events();
            // An intent without events changed nothing that must be saved (refused, or a
            // heartbeat without held tasks); saving would rewrite the whole state for nothing.
            if !events.is_empty() {
                team.dirty = true;
            }
            (
                team.book_messages(events),
                Some(refused.map_or(Ok(ack()), |r| Err(rejection(&r, at)))),
            )
        };
        Ok(match message {
            ClientMessage::Hello(_) | ClientMessage::Ping | ClientMessage::TicketRenew(_) => {
                (Vec::new(), Some(Err(error(ErrorCode::BadRequest))), None)
            }
            ClientMessage::PresenceSet(m) => {
                let update = PresenceUpdate {
                    holder: who.clone(),
                    state: m.state,
                    status: m.status,
                    at,
                };
                self.presence.insert(who.clone(), update.clone());
                (
                    vec![ServerMessage::PresenceUpdate(update)],
                    Some(Ok(ack())),
                    None,
                )
            }
            ClientMessage::Heartbeat(m) => {
                let (events, reply) = book(self, Intent::Heartbeat { tasks: m.tasks });
                (events, reply, None)
            }
            ClientMessage::TaskReserve(m) => {
                let before = self.notes.get(&m.task).cloned();
                let moved = m.prev.iter().find_map(|old| self.notes.get(old).cloned());
                match m.note.clone().or(moved) {
                    Some(note) => {
                        self.notes.insert(m.task, note);
                    }
                    None => {
                        self.notes.remove(&m.task);
                    }
                }
                let (events, reply) = book(
                    self,
                    Intent::Reserve {
                        task: m.task,
                        epoch: m.epoch,
                        prev: m.prev,
                    },
                );
                if matches!(reply, Some(Err(_))) {
                    match before {
                        Some(note) => self.notes.insert(m.task, note),
                        None => self.notes.remove(&m.task),
                    };
                }
                (events, reply, None)
            }
            ClientMessage::TaskRelease(m) => {
                let (events, reply) = book(self, Intent::Release { task: m.task });
                (events, reply, None)
            }
            ClientMessage::TaskReleaseRequest(m) => {
                let before = self.request_notes.get(&m.task).cloned();
                if let Some(note) = m.note.clone() {
                    self.request_notes.insert(m.task, note);
                }
                let (events, reply) = book(self, Intent::RequestRelease { task: m.task });
                if matches!(reply, Some(Err(_))) {
                    match before {
                        Some(note) => self.request_notes.insert(m.task, note),
                        None => self.request_notes.remove(&m.task),
                    };
                }
                (events, reply, None)
            }
            ClientMessage::TaskReleaseWithdraw(m) => {
                let (events, reply) = book(self, Intent::WithdrawRelease { task: m.task });
                (events, reply, None)
            }
            ClientMessage::TaskReleaseAnswer(m) => {
                // On acceptance the new reservation carries no note: the request's note is a
                // `ReleaseRequestNote` (sender is the requester), while the app opens a
                // reservation note as a `ReservationNote` with the holder as sender. The new
                // holder sends its own note afterwards via `task.reserve`.
                let before = self.notes.get(&m.task).cloned();
                if m.accept {
                    self.notes.remove(&m.task);
                }
                let (events, reply) = book(
                    self,
                    Intent::AnswerRelease {
                        task: m.task,
                        requester: m.requester,
                        accept: m.accept,
                    },
                );
                if matches!(reply, Some(Err(_))) || !m.accept {
                    match before {
                        Some(note) => self.notes.insert(m.task, note),
                        None => self.notes.remove(&m.task),
                    };
                }
                (events, reply, None)
            }
            ClientMessage::TaskForceRelease(m) => {
                let (events, refused) = self
                    .book
                    .force_release(wire::role(sub.role), m.task, at)
                    .into_events();
                self.dirty = true;
                (
                    self.book_messages(events),
                    Some(refused.map_or(Ok(ack()), |r| Err(rejection(&r, at)))),
                    None,
                )
            }
            ClientMessage::TaskRekey(m) => {
                if let Some(note) = self.notes.get(&m.from).cloned() {
                    self.notes.insert(m.to, note);
                }
                let (events, reply) = book(
                    self,
                    Intent::Rekey {
                        from: m.from,
                        to: m.to,
                        epoch: m.epoch,
                    },
                );
                (events, reply, None)
            }
            ClientMessage::ClaimSet(m) => {
                let total: usize = self.sessions.values().map(HashSet::len).sum();
                let own = self.sessions.get(&who);
                let known = own.is_some_and(|s| s.contains(&m.session));
                if !known
                    && (total >= MAX_SESSIONS_PER_TEAM
                        || own.map_or(0, HashSet::len) >= MAX_SESSIONS_PER_DEVICE)
                {
                    (Vec::new(), Some(Err(error(ErrorCode::Limit))), None)
                } else {
                    self.sessions
                        .entry(who.clone())
                        .or_default()
                        .insert(m.session.clone());
                    let session = SessionRef {
                        holder: who.clone(),
                        session: m.session,
                    };
                    let notices = self.board.set(
                        session,
                        SessionClaims {
                            repo: m.repo,
                            epoch: m.epoch,
                            files: m.files,
                            detail: m.detail,
                        },
                    );
                    self.deliver_overlaps(notices);
                    (Vec::new(), Some(Ok(ack())), None)
                }
            }
            ClientMessage::ClaimClear(m) => {
                if let Some(set) = self.sessions.get_mut(&who) {
                    set.remove(&m.session);
                    if set.is_empty() {
                        self.sessions.remove(&who);
                    }
                }
                let notices = self.board.clear(&SessionRef {
                    holder: who.clone(),
                    session: m.session,
                });
                self.deliver_overlaps(notices);
                (Vec::new(), Some(Ok(ack())), None)
            }
            ClientMessage::BlobPut(m) => {
                match store::put_blob(
                    db,
                    &self.id,
                    blob_kind(m.kind),
                    m.content.epoch,
                    &m.content.data,
                    &who,
                    limits.blob_quota_bytes,
                    now,
                )
                .await?
                {
                    BlobPut::Stored(id) => match wire::BlobId::new(id) {
                        Ok(blob) => (
                            Vec::new(),
                            Some(Ok(Ack {
                                blob: Some(blob),
                                content: None,
                                keys: None,
                            })),
                            None,
                        ),
                        Err(_) => (Vec::new(), Some(Err(error(ErrorCode::BadRequest))), None),
                    },
                    BlobPut::Quota => (Vec::new(), Some(Err(error(ErrorCode::Limit))), None),
                }
            }
            ClientMessage::BlobGet(m) => {
                match store::get_blob(db, &self.id, m.blob.as_str()).await? {
                    Some((epoch, data)) => (
                        Vec::new(),
                        Some(Ok(Ack {
                            blob: Some(m.blob),
                            content: Some(Sealed { epoch, data }),
                            keys: None,
                        })),
                        None,
                    ),
                    None => (Vec::new(), Some(Err(error(ErrorCode::NotFound))), None),
                }
            }
            ClientMessage::DeviceKeys(m) => {
                let stored = store::set_device_keys(
                    db,
                    &self.id,
                    &who,
                    &m,
                    MAX_DEVICES_PER_MEMBER,
                    MAX_WRAPPED_KEYS,
                    now,
                )
                .await?;
                let reply = match stored {
                    store::KeysStored::Stored => Ok(ack()),
                    store::KeysStored::TooManyDevices => Err(error(ErrorCode::Limit)),
                };
                (Vec::new(), Some(reply), None)
            }
            ClientMessage::DevicesGet => {
                let devices = store::team_devices(db, &self.id, MAX_WRAPPED_KEYS).await?;
                let text = self.frame(
                    Some(op),
                    None,
                    ServerMessage::Devices(DeviceList { devices }),
                );
                self.send(conn, text);
                (Vec::new(), None, None)
            }
            ClientMessage::MemberLogAppend(m) => {
                // First the keys the entry records, against those registered over the own
                // connections; then the entry itself against the verified log.
                let registered = self.registered_for(db, &m).await?;
                let checked = check_registered_keys(&m, |holder| registered.get(holder).copied())
                    .and_then(|()| {
                        let mut next = self.verifier.clone();
                        next.admit(&m, &who, wire::role(sub.role))
                            .map(|a| (next, a))
                    });
                match checked {
                    Err(refused) => (Vec::new(), Some(log_refused(&refused)), None),
                    Ok((next, admitted)) => {
                        if store::log_append(
                            db,
                            &self.id,
                            &m,
                            &admitted.head.hash,
                            &admitted.removed,
                            &who,
                            now,
                        )
                        .await?
                        {
                            self.verifier = next;
                            let mut events =
                                vec![ServerMessage::MemberLogAppended(MemberLogAppended {
                                    index: admitted.head.index,
                                    hash: admitted.head.hash,
                                    by: who.clone(),
                                })];
                            events.extend(self.drop_removed(&admitted, now));
                            (events, Some(Ok(ack())), None)
                        } else {
                            (Vec::new(), Some(Err(error(ErrorCode::Conflict))), None)
                        }
                    }
                }
            }
            ClientMessage::MemberLogGet(m) => {
                let entries = store::log_get(db, &self.id, m.after, MAX_LOG_ENTRIES + 1).await?;
                let page = MemberLogEntries::page(entries);
                let text = self.frame(Some(op), None, ServerMessage::MemberLogEntries(page));
                self.send(conn, text);
                (Vec::new(), None, None)
            }
            ClientMessage::KeyRotate(m) => {
                let role = wire::role(sub.role);
                let checked = check_rotate(role, self.book.epoch(), &m)
                    .map_err(|refused| Err(error(refused.code())))
                    .and_then(|()| {
                        let mut next = self.verifier.clone();
                        next.admit_rotation(&m, &who, role)
                            .map(|a| (next, a))
                            .map_err(|refused| log_refused(&refused))
                    });
                match checked {
                    Err(reply) => (Vec::new(), Some(reply), None),
                    Ok((next, admitted)) => {
                        // Entry, epoch and packages in one transaction, or nothing.
                        match store::rotate_epoch(
                            db,
                            &self.id,
                            m.epoch,
                            &m.log,
                            &admitted.head.hash,
                            &m.wrapped,
                            &who,
                            now,
                        )
                        .await?
                        {
                            EpochChange::Done => {
                                self.verifier = next;
                                self.dirty = true;
                                let mut events =
                                    vec![ServerMessage::MemberLogAppended(MemberLogAppended {
                                        index: admitted.head.index,
                                        hash: admitted.head.hash,
                                        by: who.clone(),
                                    })];
                                match self.book.rotate(m.epoch, at) {
                                    Ok(timing) => events.extend(self.book_messages(timing)),
                                    Err(refused) => tracing::error!(
                                        ?refused,
                                        "book and database disagree on the epoch"
                                    ),
                                }
                                let wrapped =
                                    m.wrapped.into_iter().map(|w| (w.holder, w.data)).collect();
                                events.push(ServerMessage::KeyRotated(KeyRotated {
                                    epoch: m.epoch,
                                    wrapped: None,
                                }));
                                (events, Some(Ok(ack())), Some(wrapped))
                            }
                            _ => (Vec::new(), Some(Err(error(ErrorCode::StaleEpoch))), None),
                        }
                    }
                }
            }
            ClientMessage::KeyWrap(m) => {
                // Permissions before state; one package per sender, at most MAX_KEY_PACKAGES per target.
                let stored_from =
                    store::package_senders(db, &self.id, m.epoch, &m.wrapped.holder).await?;
                let checked = match self.verifier.state() {
                    Some(state) => check_wrap(state, wire::role(sub.role), &who, &m, &stored_from)
                        .map_err(|e| e.code()),
                    None => Err(ErrorCode::Forbidden),
                };
                match checked {
                    Err(code) => (Vec::new(), Some(Err(error(code))), None),
                    Ok(()) => {
                        match store::wrap_key(db, &self.id, m.epoch, &m.wrapped, &who, now).await? {
                            EpochChange::Done => {
                                self.deliver_wrapped(m.epoch, &m.wrapped.holder);
                                (Vec::new(), Some(Ok(ack())), None)
                            }
                            EpochChange::AlreadyWrapped => {
                                (Vec::new(), Some(Err(error(ErrorCode::Conflict))), None)
                            }
                            EpochChange::WrongEpoch => {
                                (Vec::new(), Some(Err(error(ErrorCode::StaleEpoch))), None)
                            }
                        }
                    }
                }
            }
            ClientMessage::DeviceRemove(m) => {
                // Only with the signed entry; stored and removed in one step.
                let mut next = self.verifier.clone();
                match next.admit_device_remove(&m, &who, wire::role(sub.role)) {
                    Err(refused) => (Vec::new(), Some(log_refused(&refused)), None),
                    Ok(admitted) => {
                        if store::log_append(
                            db,
                            &self.id,
                            &m.log,
                            &admitted.head.hash,
                            &admitted.removed,
                            &who,
                            now,
                        )
                        .await?
                        {
                            self.verifier = next;
                            let mut events =
                                vec![ServerMessage::MemberLogAppended(MemberLogAppended {
                                    index: admitted.head.index,
                                    hash: admitted.head.hash,
                                    by: who.clone(),
                                })];
                            events.extend(self.drop_removed(&admitted, now));
                            (events, Some(Ok(ack())), None)
                        } else {
                            (Vec::new(), Some(Err(error(ErrorCode::Conflict))), None)
                        }
                    }
                }
            }
            ClientMessage::KeyGet(m) => {
                let packages = store::key_packages(db, &self.id, m.epoch, &who).await?;
                if packages.is_empty() {
                    (Vec::new(), Some(Err(error(ErrorCode::NotFound))), None)
                } else {
                    let keys = packages
                        .into_iter()
                        .map(|data| Sealed {
                            epoch: m.epoch,
                            data,
                        })
                        .collect();
                    (
                        Vec::new(),
                        Some(Ok(Ack {
                            blob: None,
                            content: None,
                            keys: Some(keys),
                        })),
                        None,
                    )
                }
            }
        })
    }

    /// The registered keys of the holders an entry records (for `check_registered_keys`, which
    /// asks synchronously).
    async fn registered_for(
        &self,
        db: &Db,
        append: &wire::MemberLogAppend,
    ) -> Result<HashMap<Holder, DevicePublicKeys>, sqlx::Error> {
        let mut out = HashMap::new();
        let Ok(body) = EntryBody::decode_unverified(&append.entry) else {
            return Ok(out);
        };
        for (holder, _) in body.listed_devices() {
            if let Some((sign, kem)) = store::registered_keys(db, &self.id, &holder).await? {
                out.insert(holder, DevicePublicKeys { sign, kem });
            }
        }
        Ok(out)
    }

    /// Devices an admitted entry took out of the team: reservations released, claims gone,
    /// connections 4403; `device.removed` per device. The entry's transaction has already
    /// blocked and forgotten them.
    fn drop_removed(&mut self, admitted: &Admitted, now: u64) -> Vec<ServerMessage> {
        let mut events = Vec::new();
        for holder in &admitted.removed {
            events.extend(self.drop_device(holder, admitted.head.index, now));
            events.push(ServerMessage::DeviceRemoved(DeviceRemoved {
                holder: holder.clone(),
            }));
        }
        events
    }

    /// `key.wrapped` only goes to the connections of the target device (member and device),
    /// never into the event log.
    fn deliver_wrapped(&mut self, epoch: Epoch, holder: &Holder) {
        let text = self.frame(
            None,
            None,
            ServerMessage::KeyWrapped(KeyWrapped {
                epoch,
                holder: holder.clone(),
            }),
        );
        let conns: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.holder == *holder)
            .map(|(c, _)| *c)
            .collect();
        for conn in conns {
            self.send(conn, text.clone());
        }
    }
}

/// Reply to a rejected log entry (`LogError::code`). Rejected entries change nothing; the log
/// stays open for the next valid entry.
fn log_refused(refused: &LogError) -> Reply {
    tracing::info!(reason = %refused, "log entry rejected");
    Err(error(refused.code()))
}

/// Limits from the configuration that `handle` needs.
#[derive(Debug, Clone, Copy)]
pub struct HandleLimits {
    pub blob_quota_bytes: u64,
}
