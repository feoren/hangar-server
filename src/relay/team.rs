//! Runtime state of a team. The rules come from the app's protocol crate: `ReservationBook`
//! ("first wins", expiry, release, rekey), `ClaimBoard` (comparison of the keyed hashes),
//! `EventLog` (sequence, replay, resync), `RecentOps` (retries per sender, team and operation ID
//! with a digest of the content), `check_epoch`, `check_rotate`, `check_append`. Only
//! distribution, storage and the permissions the relay knows from the ticket live here.
//!
//! The caller holds the team lock; thus the order of arrival counts as the truth, and events go
//! to all receivers in sequence order.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::ws::Utf8Bytes;
use hangar_team_crypto::identity::DevicePublicKeys;
use hangar_team_crypto::memberlog::{Admitted, EntryBody, LogError, LogVerifier};
use hangar_team_crypto::possession::{
    check_restricted, counts_as_listed, verify_connection_proof, Possession,
};
use hangar_team_crypto::relay::{check_blob_delete, check_registered_keys, check_wrap};
use hangar_team_protocol::log::{EventLog, OpKey, RecentOps, Replay, Retry};
use hangar_team_protocol::overlap::{ClaimBoard, OverlapNotice, SessionClaims};
use hangar_team_protocol::reservation::{
    BookEvent, BookSnapshot, Hold, Intent, Policy, Rejection, Reservation, ReservationBook,
    ReservationEvent, ReservationState,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use super::store::{self, BlobPut, DecisionCaps, EpochChange, MemberSeen};
use crate::db::Db;
use crate::ticket::Role;
use crate::wire::{
    self, ack, check_rotate, error, limits::BLOB_LIST_EVERY_MS, limits::MAX_BLOB_LIST,
    limits::MAX_DECISIONS, limits::MAX_DECISIONS_PER_MEMBER, limits::MAX_DECISION_CIPHERTEXT_LEN,
    limits::MAX_DEVICES_PER_MEMBER, limits::MAX_LOG_ENTRIES, limits::MAX_WRAPPED_KEYS, Ack,
    BlobDeleted, BlobEntry, BlobId, BlobKind, BlobListing, BlobStored, Challenge, Ciphertext,
    ClientMessage, Cursor, DeviceId, DeviceList, DeviceProve, DeviceRemoved, Epoch, ErrorBody,
    ErrorCode, Holder, KeyRotated, KeyWrapped, KeyedHash, MemberId, MemberJoined,
    MemberLogAppended, MemberLogEntries, MemberRemoved, MemberRoleChanged, NotesKeys,
    NotesKeysUpdated, Notify as NotifyMessage, OpId, PathHashes, PresenceState, PresenceUpdate,
    PublicKey, ReservationExpired, ReservationExpiring, ResyncReason, ResyncRequired, Sealed, Seq,
    ServerFrame, ServerMessage, SessionKey, SessionRef, StreamId, TaskReleaseAnswered,
    TaskReleaseRequestEnded, TaskReleaseRequested, TaskReleased, TaskReserved, TeamId, UnixMillis,
    Welcome, DECISIONS_PROTOCOL_VERSION, PROOF_PROTOCOL_VERSION,
};

/// Events kept in memory for replay; older ones require a snapshot.
pub const REPLAY_WINDOW: usize = 2048;
/// Encoded bytes of the events kept for replay. Without it, 2048 events with notes of 16 KiB
/// would hold 32 MiB per team; a usual event has a few hundred bytes, so the limit only bites
/// with large notes or log entries. Older events then leave the window early and a cursor
/// behind it gets a snapshot (`tooOld`), as the protocol already defines.
pub const REPLAY_WINDOW_BYTES: usize = 4 * 1024 * 1024;
/// Remembered operation IDs per team for idempotent retries.
pub const RECENT_OPS: usize = 4096;
/// Claims per device.
pub const MAX_SESSIONS_PER_DEVICE: usize = 64;
/// Claims per team (protects memory).
pub const MAX_SESSIONS_PER_TEAM: usize = 2000;
/// Claims of one member in a team, over all its devices: one member cannot take every slot
/// of the team (devices are only IDs from `hello`, a member can name many).
pub const MAX_SESSIONS_PER_MEMBER: usize = 256;
/// Claim bytes of all loaded teams together: every team has its own limit, but one account can
/// be in many teams (a project on the website is cheap), so the relay as a whole has one too.
pub const MAX_CLAIM_BYTES_TOTAL: usize = 64 * 1024 * 1024;
/// Claim bytes of one member over all loaded teams, as a multiple of the limit per team.
pub const CLAIM_TEAMS_PER_MEMBER: usize = 4;
/// Bytes of the replay windows of all loaded teams together. Above it, the team that writes
/// keeps only `SMALL_WINDOW_BYTES`; a cursor behind the window gets a snapshot.
pub const MAX_WINDOW_BYTES_TOTAL: usize = 32 * 1024 * 1024;
pub const SMALL_WINDOW_BYTES: usize = 128 * 1024;

/// Memory shared by all loaded teams: claim bytes per team and member, and the bytes of all
/// replay windows. A team keeps its own entries current and removes them when it is dropped
/// (unloaded or deleted).
#[derive(Default)]
pub struct Budget {
    claims: std::sync::Mutex<HashMap<String, HashMap<MemberId, usize>>>,
    window_bytes: AtomicUsize,
}

impl Budget {
    /// Claim bytes outside `team`: of `member`, and of everyone.
    fn claims_elsewhere(&self, team: &str, member: &MemberId) -> (usize, usize) {
        let Ok(claims) = self.claims.lock() else {
            return (usize::MAX / 4, usize::MAX / 4);
        };
        let others = claims.iter().filter(|(id, _)| id.as_str() != team);
        others.fold((0, 0), |(own, all), (_, members)| {
            (
                own + members.get(member).copied().unwrap_or(0),
                all + members.values().sum::<usize>(),
            )
        })
    }

    fn set_claims(&self, team: &str, totals: HashMap<MemberId, usize>) {
        if let Ok(mut claims) = self.claims.lock() {
            if totals.is_empty() {
                claims.remove(team);
            } else {
                claims.insert(team.to_owned(), totals);
            }
        }
    }

    /// Bytes of all replay windows (for tests and diagnostics).
    pub fn window_bytes(&self) -> usize {
        self.window_bytes.load(Ordering::Relaxed)
    }
}
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
    /// The catch-up of a `hello` (welcome and replay, or snapshot and welcome) as one entry of
    /// the queue, so it cannot overflow it (see `outbox`).
    Batch(Vec<Utf8Bytes>),
    Close(u16, &'static str),
}

/// An encoded server frame together with the protocol version that introduced its kind
/// (`ServerMessage::since`). The text only comes out through `for_proto`, so no path can hand a
/// kind to a connection whose team negotiated an older version: an app of that version would
/// end the connection on a kind it does not know.
#[derive(Debug, Clone)]
pub struct Framed {
    since: u16,
    text: Utf8Bytes,
}

impl Framed {
    /// The text for a connection that negotiated `proto`, `None` if the kind is newer.
    fn for_proto(&self, proto: u16) -> Option<Utf8Bytes> {
        (self.since <= proto).then(|| self.text.clone())
    }
}

/// A connection that has joined the team.
#[derive(Debug, Clone)]
pub struct Subscriber {
    pub holder: Holder,
    pub role: Role,
    /// The protocol version negotiated for this team in this connection's `hello`
    /// (`welcome.proto`). Client kinds newer than it are refused, server kinds newer than it are
    /// never sent.
    pub proto: u16,
    pub tx: super::outbox::Outbox,
    /// Triggered when the connection can no longer keep up (queue full).
    pub kick: Arc<Notify>,
    /// Gets the team's ID when a log entry took the device out of the team: the connection
    /// starts the grace period for this team, during which it may only send `memberlog.get`
    /// here; its other teams are not affected.
    pub removed: tokio::sync::mpsc::UnboundedSender<String>,
    /// What the connection has shown of its device's key in this team (protocol version 3).
    pub possession: ConnectionProof,
    /// Its `blob.list` pace in this team (protocol version 4).
    pub listing: ListingPace,
}

/// Where a connection's `blob.list` stands in one team (protocol version 4): when its last
/// listing started, and where that listing goes on. In memory only.
#[derive(Debug, Clone, Default)]
pub struct ListingPace {
    started_at: Option<u64>,
    /// Kind and last blob of the page sent last, when that page said `more`: a `blob.list` with
    /// this kind and this `after` continues the listing and starts none.
    next: Option<(BlobKind, BlobId)>,
}

/// The proof of possession of one connection in one team (protocol version 3,
/// `docs/protocol.md`). In memory only: the challenge is never stored or logged.
#[derive(Debug, Clone, Default)]
pub struct ConnectionProof {
    /// The challenge of this connection's `welcome` (version 3 and newer).
    challenge: Option<Challenge>,
    /// The signing key the last passing `device.prove` showed. A refused proof keeps it.
    proven: Option<PublicKey>,
    /// The connection counts as the log's device and its joining took effect (the book's
    /// online counting, delivered `notify`): see `Team::refresh_counting`.
    counted: bool,
    /// Its proof row is written (`relay_device_proofs`).
    recorded: bool,
    /// The snapshot this connection's `hello` asked for, held back because the log did not list
    /// its device then: sent with `resync_required` and a new `welcome` once the log lists it
    /// (`Team::deliver_withheld`).
    withheld: Option<ResyncReason>,
}

impl Subscriber {
    fn possession(&self) -> Possession<'_> {
        Possession::of_connection(self.proto, self.possession.proven.as_ref())
    }
}

/// What `Team::handle` tells the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handled {
    Done,
    /// The frame counts as a bad frame (a refused `device.prove`): a connection cannot try
    /// signatures without bound.
    BadFrame,
}

/// 32 bytes from the operating system's random number generator, new for every `welcome` of
/// version 3 or newer.
fn new_challenge(proto: u16) -> Option<Challenge> {
    (proto >= PROOF_PROTOCOL_VERSION)
        .then(|| Challenge::from_bytes(crate::util::random_bytes::<32>()))
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
    proto: u16,
}

impl Departing {
    fn send(&self, framed: Option<&Framed>) {
        if let Some(text) = framed.and_then(|f| f.for_proto(self.proto)) {
            self.tx.try_send(Outgoing::Text(text));
        }
    }
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
    budget: Arc<Budget>,
    team: TeamId,
    policy: Policy,
    log: EventLog<ServerMessage>,
    /// Sequence number and encoded size of each event in the log's replay window, oldest
    /// first (the same events as the window; see `REPLAY_WINDOW_BYTES`).
    window: VecDeque<(Seq, usize)>,
    window_bytes: usize,
    book: ReservationBook,
    board: ClaimBoard,
    /// Sessions per device with the bytes of their claims, for the limits (the board does not
    /// count them).
    sessions: HashMap<Holder, HashMap<SessionKey, usize>>,
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
    pub async fn load(
        db: &Db,
        id: &str,
        policy: Policy,
        budget: Arc<Budget>,
        now: u64,
    ) -> Result<Team, sqlx::Error> {
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
        let entries = store::log_all(db, id).await?;
        // Verifying every signature of the log is CPU work: off the async threads.
        let for_log = team.clone();
        let (verifier, replayed) = tokio::task::spawn_blocking(move || {
            let mut verifier = LogVerifier::new(for_log);
            let replayed = verifier.apply_all(&entries).map_err(|e| e.to_string());
            (verifier, replayed)
        })
        .await
        .map_err(|e| protocol(e.to_string()))?;
        if let Err(error) = replayed {
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
            budget,
            team,
            policy,
            log,
            window: VecDeque::new(),
            window_bytes: 0,
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

    /// Writes this team's claim bytes per member into the shared budget.
    fn publish_claims(&self) {
        let mut totals: HashMap<MemberId, usize> = HashMap::new();
        for (holder, sessions) in &self.sessions {
            *totals.entry(holder.member.clone()).or_insert(0) += sessions.values().sum::<usize>();
        }
        totals.retain(|_, bytes| *bytes > 0);
        self.budget.set_claims(&self.id, totals);
    }

    /// Nothing connected, nothing held, nothing remembered: may be unloaded from memory.
    pub fn idle(&self, now: u64) -> bool {
        self.subscribers.is_empty()
            && self.departing.is_empty()
            && self.book.iter().next().is_none()
            && self.sessions.is_empty()
            && now.saturating_sub(self.last_activity) > 10 * 60 * 1000
    }

    /// Whether a connection of `holder` counts (presence and the book count only those).
    fn online(&self, holder: &Holder) -> bool {
        self.subscribers
            .values()
            .any(|s| s.holder == *holder && s.possession.counted)
    }

    fn member_online(&self, member: &MemberId) -> bool {
        self.subscribers
            .values()
            .any(|s| s.holder.member == *member && s.possession.counted)
    }

    /// Whether the connection counts as the log's device now: in a team without a log every
    /// connection does, with a log `counts_as_listed` decides (a listed device on version 1 or 2,
    /// or on version 3 with the key the log lists for it). Evaluated against the current log,
    /// never cached: an admission or a removal changes it under a live connection.
    fn counts(&self, sub: &Subscriber) -> bool {
        match self.verifier.state() {
            None => true,
            Some(state) => counts_as_listed(state, &sub.holder, sub.possession()),
        }
    }

    /// Whether the team's log lists `holder`'s device; in a team without a log every device is.
    fn listed(&self, holder: &Holder) -> bool {
        self.verifier
            .state()
            .is_none_or(|state| state.device(holder).is_some())
    }

    /// Sends the held-back snapshot to every connection whose device the log lists by now:
    /// `resync_required`, the state, and a `welcome` with the connection's challenge from its
    /// `hello`, so a proof it already sent stays valid. One entry in the queue, under the team
    /// lock: no live event gets in between.
    fn deliver_withheld(&mut self) {
        let due: Vec<(u64, ResyncReason)> = self
            .subscribers
            .iter()
            .filter_map(|(conn, sub)| {
                let reason = sub.possession.withheld?;
                self.listed(&sub.holder).then_some((*conn, reason))
            })
            .collect();
        for (conn, reason) in due {
            let Some(sub) = self.subscribers.get(&conn) else {
                continue;
            };
            let proto = sub.proto;
            let welcome = ServerMessage::Welcome(Welcome {
                proto,
                stream: self.log.stream().clone(),
                head: self.log.head(),
                member: sub.holder.member.clone(),
                epoch: self.book.epoch(),
                challenge: sub.possession.challenge,
            });
            let resync = ServerMessage::ResyncRequired(ResyncRequired {
                stream: self.log.stream().clone(),
                head: self.log.head(),
                reason,
            });
            let mut batch = Vec::new();
            let mut add = |framed: Option<Framed>| {
                batch.extend(framed.and_then(|f| f.for_proto(proto)));
            };
            add(self.frame(None, None, resync));
            for message in self.snapshot() {
                add(self.frame(None, None, message));
            }
            add(self.frame(None, None, welcome));
            if let Some(sub) = self.subscribers.get_mut(&conn) {
                sub.possession.withheld = None;
                sub.tx.try_send(Outgoing::Batch(batch));
            }
        }
    }

    /// The connections `pred` selects that count; targeted unlogged messages go only to them.
    fn counting(&self, pred: impl Fn(&Subscriber) -> bool) -> Vec<u64> {
        self.subscribers
            .iter()
            .filter(|(_, s)| pred(s) && self.counts(s))
            .map(|(c, _)| *c)
            .collect()
    }

    fn frame(&self, id: Option<&OpId>, seq: Option<Seq>, message: ServerMessage) -> Option<Framed> {
        let kind = message.kind();
        let since = message.since();
        match wire::encode_server(&ServerFrame {
            id: id.cloned(),
            seq,
            team: Some(self.team.clone()),
            message,
        }) {
            Ok(text) => Some(Framed {
                since,
                text: Utf8Bytes::from(text),
            }),
            Err(error) => {
                tracing::error!(%error, kind, "cannot encode frame");
                None
            }
        }
    }

    /// Sends to one connection, only a kind its negotiated version knows.
    fn send(&mut self, conn: u64, framed: Option<Framed>) {
        let Some(framed) = framed else { return };
        if let Some(sub) = self.subscribers.get(&conn) {
            if let Some(text) = framed.for_proto(sub.proto) {
                // Whoever cannot keep up is kicked by the outbox and catches up via cursor.
                sub.tx.try_send(Outgoing::Text(text));
            }
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
            let seq = message.loggable().then(|| self.log_push(message.clone()));
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

    /// Appends a logged event and keeps the replay window within `REPLAY_WINDOW_BYTES`, or
    /// within `SMALL_WINDOW_BYTES` while all windows together exceed `MAX_WINDOW_BYTES_TOTAL`.
    fn log_push(&mut self, message: ServerMessage) -> Seq {
        let before = self.window_bytes;
        let seq = self.log_push_inner(message);
        self.account_window(before);
        seq
    }

    /// Carries the change of this team's window into the shared budget.
    fn account_window(&self, before: usize) {
        let now = self.window_bytes;
        if now >= before {
            self.budget
                .window_bytes
                .fetch_add(now - before, Ordering::Relaxed);
        } else {
            self.budget
                .window_bytes
                .fetch_sub(before - now, Ordering::Relaxed);
        }
    }

    fn log_push_inner(&mut self, message: ServerMessage) -> Seq {
        let size = serde_json::to_string(&message).map_or(0, |text| text.len());
        let seq = self.log.push(message);
        // The log drops its oldest event at `REPLAY_WINDOW` events; so does the mirror.
        if self.window.len() == REPLAY_WINDOW {
            if let Some((_, dropped)) = self.window.pop_front() {
                self.window_bytes -= dropped;
            }
        }
        self.window.push_back((seq, size));
        self.window_bytes += size;
        let crowded =
            self.budget.window_bytes.load(Ordering::Relaxed) + size > MAX_WINDOW_BYTES_TOTAL;
        if self.window_bytes > REPLAY_WINDOW_BYTES {
            self.shrink_window(REPLAY_WINDOW_BYTES / 4 * 3);
        } else if crowded && self.window_bytes > SMALL_WINDOW_BYTES {
            self.shrink_window(SMALL_WINDOW_BYTES / 4 * 3);
        }
        seq
    }

    /// Drops the oldest events until a quarter of the byte budget is free again (so this runs
    /// rarely), at least the newest event stays. The crate's log has no way to drop events, so
    /// it is rebuilt with `EventLog::resume` and the kept events: stream, head and the
    /// sequence numbers stay the same, nothing is stored differently.
    fn shrink_window(&mut self, target: usize) {
        while self.window_bytes > target && self.window.len() > 1 {
            if let Some((_, dropped)) = self.window.pop_front() {
                self.window_bytes -= dropped;
            }
        }
        let head = self.log.head();
        let stream = self.log.stream().clone();
        let from = Cursor {
            stream: stream.clone(),
            seq: Seq(head.0.saturating_sub(self.window.len() as u64)),
        };
        let kept: Vec<ServerMessage> = match self.log.replay(Some(&from)) {
            Replay::Events(events) => events.into_iter().map(|(_, m)| m.clone()).collect(),
            Replay::Resync(_) => Vec::new(),
        };
        if kept.len() != self.window.len() {
            // Never expected: start with an empty window (every cursor behind gets a snapshot).
            tracing::warn!("replay window out of step, emptied");
            self.window.clear();
            self.window_bytes = 0;
        }
        let start = Seq(head.0 - self.window.len() as u64);
        let mut log = EventLog::resume(stream, start, REPLAY_WINDOW);
        for message in kept.into_iter().take(self.window.len()) {
            log.push(message);
        }
        self.log = log;
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
            departing.send(text.as_ref());
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
        departing.send(
            self.frame(Some(op), None, ServerMessage::MemberLogEntries(page))
                .as_ref(),
        );
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
        // Kept until a connection that counts takes it.
        let conns = self.counting(|s| s.holder.member == *member);
        if conns.is_empty() {
            return Ok(());
        }
        let Some(notify) = self.pending.remove(member) else {
            return Ok(());
        };
        let text = self.frame(None, None, ServerMessage::Notify(notify));
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
        ticket_iat_ms: u64,
        now: u64,
        allow_departing: bool,
    ) -> Result<Result<Joined, ErrorCode>, sqlx::Error> {
        // Downgrade protection: a holder that proved itself on version 3 is not served on an
        // older version again (the app asks for an update).
        if sub.proto < PROOF_PROTOCOL_VERSION
            && store::device_proven(db, &self.id, &sub.holder).await?
        {
            tracing::info!("hello below version 3 from a device that proved itself refused");
            return Ok(Err(ErrorCode::OutdatedClient));
        }
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
            // A fresh challenge like every welcome of version 3; `device.keys` and
            // `device.prove` are acknowledged without effect here (`departing_ack`).
            let welcome = ServerMessage::Welcome(Welcome {
                proto: sub.proto,
                stream: self.log.stream().clone(),
                head: self.log.head(),
                member: sub.holder.member.clone(),
                epoch: self.book.epoch(),
                challenge: new_challenge(sub.proto),
            });
            let departing = Departing {
                holder: sub.holder,
                tx: sub.tx,
                until,
                proto: sub.proto,
            };
            departing.send(self.frame(Some(op), None, welcome).as_ref());
            self.departing.insert(conn, departing);
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
        let proto = sub.proto;
        let challenge = new_challenge(proto);
        let mut sub = sub;
        sub.possession = ConnectionProof {
            challenge,
            ..ConnectionProof::default()
        };
        self.subscribers.insert(conn, sub);
        let welcome = ServerMessage::Welcome(Welcome {
            proto,
            stream: self.log.stream().clone(),
            head: self.log.head(),
            member: holder.member.clone(),
            epoch: self.book.epoch(),
            challenge,
        });
        let replay = match self.log.replay(cursor) {
            Replay::Events(events) => Ok(events
                .into_iter()
                .map(|(seq, m)| (seq, m.clone()))
                .collect::<Vec<_>>()),
            Replay::Resync(reason) => Err(reason),
        };
        // Replay (up to `REPLAY_WINDOW` events) and snapshot can exceed the outgoing queue's
        // frame limit. They go in as a single entry, still under the team lock: no live event
        // gets in between or ahead, and the writer hands the frames over one by one.
        // Only kinds of the negotiated version (logged and snapshot kinds are all of version
        // 1 today; the filter keeps it that way should a newer kind ever be logged).
        let mut catch_up = Vec::new();
        let mut add = |framed: Option<Framed>| {
            catch_up.extend(framed.and_then(|f| f.for_proto(proto)));
        };
        match replay {
            Ok(events) => {
                add(self.frame(Some(op), None, welcome));
                for (seq, message) in events {
                    let message = self.personalize(db, &holder, message).await?;
                    add(self.frame(None, Some(seq), message));
                }
            }
            Err(reason) => {
                let resync = ServerMessage::ResyncRequired(ResyncRequired {
                    stream: self.log.stream().clone(),
                    head: self.log.head(),
                    reason,
                });
                add(self.frame(Some(op), None, resync));
                // A device the team's log does not list (one waiting for admission, or a
                // removed one back under a new ID) gets no state of the team: holds, sealed
                // notes and presence wait until the log lists it.
                if self.listed(&holder) {
                    for message in self.snapshot() {
                        add(self.frame(None, None, message));
                    }
                } else if let Some(sub) = self.subscribers.get_mut(&conn) {
                    sub.possession.withheld = Some(reason);
                }
                add(self.frame(Some(op), None, welcome));
            }
        }
        if let Some(sub) = self.subscribers.get(&conn) {
            sub.tx.try_send(Outgoing::Batch(catch_up));
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
        self.emit(db, events, None).await?;
        // The book's online counting and the remembered `notify` only for a connection that
        // counts as the log's device: on version 3 from its proof on.
        self.refresh_counting(db, now).await?;
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
        let Some(events) = self.disconnect(conn, now) else {
            return Ok(());
        };
        self.last_activity = now;
        self.prune_notes();
        self.emit(db, events, None).await
    }

    /// Takes a connection out of the team; the events of its leaving if it counted.
    fn disconnect(&mut self, conn: u64, now: u64) -> Option<Vec<ServerMessage>> {
        let sub = self.subscribers.remove(&conn)?;
        Some(if sub.possession.counted {
            self.stop_counting(&sub.holder, now)
        } else {
            Vec::new()
        })
    }

    /// A connection of `holder` starts to count: the book counts it online.
    fn start_counting(&mut self, holder: &Holder, now: u64) -> Vec<ServerMessage> {
        self.offline_since.remove(holder);
        let presence = self.book.presence(holder, true, UnixMillis(now));
        self.dirty = true;
        self.book_messages(presence)
    }

    /// A connection of `holder` stopped counting (left, or the log no longer lists its key);
    /// the caller has already taken it out or unmarked it. The last one reports the holder
    /// offline.
    fn stop_counting(&mut self, holder: &Holder, now: u64) -> Vec<ServerMessage> {
        let presence = self.book.presence(holder, false, UnixMillis(now));
        self.dirty = true;
        let mut events = self.book_messages(presence);
        if !self.online(holder) {
            self.offline_since.insert(holder.clone(), now);
            self.presence.remove(holder);
            events.push(ServerMessage::PresenceUpdate(PresenceUpdate {
                holder: holder.clone(),
                state: PresenceState::Offline,
                status: None,
                at: UnixMillis(now),
            }));
        }
        events
    }

    /// Brings every connection's counting in line with the current log: a connection that
    /// starts to count joins (book, remembered `notify`), one that stops leaves (book,
    /// presence). A connection that counts with a key it proved on version 3 gets its proof
    /// row, which closes the holder's connections of older versions. Runs after `hello`, after
    /// a passing `device.prove` and after every stored log entry.
    async fn refresh_counting(&mut self, db: &Db, now: u64) -> Result<(), sqlx::Error> {
        self.deliver_withheld();
        let mut events = Vec::new();
        let mut joined = Vec::new();
        let mut record = Vec::new();
        let has_log = self.verifier.state().is_some();
        let conns: Vec<u64> = self.subscribers.keys().copied().collect();
        for conn in conns {
            let Some(sub) = self.subscribers.get(&conn) else {
                continue;
            };
            let counts = self.counts(sub);
            let holder = sub.holder.clone();
            let was = sub.possession.counted;
            let row = counts
                && has_log
                && !sub.possession.recorded
                && matches!(sub.possession(), Possession::Proven(_));
            if let Some(sub) = self.subscribers.get_mut(&conn) {
                sub.possession.counted = counts;
                sub.possession.recorded |= row;
            }
            if counts && !was {
                events.extend(self.start_counting(&holder, now));
                if !joined.contains(&holder.member) {
                    joined.push(holder.member.clone());
                }
            } else if was && !counts {
                events.extend(self.stop_counting(&holder, now));
            }
            if row {
                record.push(holder);
            }
        }
        for holder in record {
            if store::record_device_proof(db, &self.id, &holder, now).await? {
                tracing::info!("device proved itself on version 3, older versions refused");
            }
            events.extend(self.close_legacy(|s| s.holder == holder, now));
        }
        if events.is_empty() && joined.is_empty() {
            return Ok(());
        }
        self.prune_notes();
        self.emit(db, events, None).await?;
        for member in joined {
            self.deliver_pending(db, &member).await?;
        }
        Ok(())
    }

    /// Closes the connections of protocol version 1 or 2 that `pred` selects with 4401: the app
    /// fetches a new ticket and reconnects, and its `hello` below version 3 then gets
    /// `outdatedClient`. Returns the events of their leaving.
    fn close_legacy(&mut self, pred: impl Fn(&Subscriber) -> bool, now: u64) -> Vec<ServerMessage> {
        let gone: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.proto < PROOF_PROTOCOL_VERSION && pred(s))
            .map(|(c, _)| *c)
            .collect();
        let mut events = Vec::new();
        for conn in gone {
            if let Some(sub) = self.subscribers.get(&conn) {
                sub.tx.try_send(Outgoing::Close(
                    close::CLOSE_ROLE_CHANGED,
                    "device proof required",
                ));
            }
            events.extend(self.disconnect(conn, now).unwrap_or_default());
        }
        events
    }

    /// `REQUIRE_DEVICE_PROOF` took effect: every connection of protocol version 1 or 2 closes
    /// with 4401.
    pub async fn require_device_proof(&mut self, db: &Db, now: u64) -> Result<(), sqlx::Error> {
        let events = self.close_legacy(|_| true, now);
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
        self.publish_claims();
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
        self.publish_claims();
        self.deliver_overlaps(notices);
        let gone: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.holder == *holder)
            .map(|(c, _)| *c)
            .collect();
        for conn in gone {
            if let Some(sub) = self.subscribers.remove(&conn) {
                let _ = sub.removed.send(self.id.clone());
                self.departing.insert(
                    conn,
                    Departing {
                        holder: sub.holder,
                        tx: sub.tx,
                        until,
                        proto: sub.proto,
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
    /// unknown; the app comes back with a new ticket. They leave the team like any closed
    /// connection: the book stops counting them and the last one reports the device offline.
    pub async fn renew_member(
        &mut self,
        db: &Db,
        member: &str,
        now: u64,
    ) -> Result<(), sqlx::Error> {
        let gone: Vec<u64> = self
            .subscribers
            .iter()
            .filter(|(_, s)| s.holder.member.as_str() == member)
            .map(|(c, _)| *c)
            .collect();
        let mut events = Vec::new();
        for conn in gone {
            if let Some(sub) = self.subscribers.get(&conn) {
                sub.tx
                    .try_send(Outgoing::Close(close::CLOSE_ROLE_CHANGED, "role changed"));
            }
            events.extend(self.disconnect(conn, now).unwrap_or_default());
        }
        if events.is_empty() {
            return Ok(());
        }
        self.last_activity = now;
        self.prune_notes();
        self.emit(db, events, None).await
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
            // Only connections that count: a twin with a stolen ticket and the holder's device
            // ID gets nothing of the other side's sealed detail.
            let conns = self.counting(|s| s.holder == notice.to.holder);
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
            self.publish_claims();
            let notices = self.board.clear_device(&holder);
            self.deliver_overlaps(notices);
        }
        Ok(())
    }

    /// `blob.stored` and `blob.deleted` (protocol version 4): live hints, never logged, no `seq`,
    /// not kept for anyone offline, sent only to the connections that count as devices of the
    /// log (the sender's own included); `send` leaves out those below version 4. They name blob
    /// ids and writers, which only a device that may list should learn.
    fn send_blob_hints(&mut self, hints: Vec<ServerMessage>) {
        if hints.is_empty() {
            return;
        }
        let conns = self.counting(|_| true);
        for hint in hints {
            let framed = self.frame(None, None, hint);
            for conn in &conns {
                self.send(*conn, framed.clone());
            }
        }
    }

    /// `blob.list` (protocol version 4): a page of the team's decisions in storage order,
    /// metadata only. A connection starts at most one listing per `BLOB_LIST_EVERY_MS`; the
    /// pages of one listing (the kind again and the last blob of a page with `more` as `after`)
    /// follow at once.
    async fn list_blobs(
        &mut self,
        db: &Db,
        conn: u64,
        op: &OpId,
        sub: &Subscriber,
        list: wire::BlobList,
        now: u64,
    ) -> Result<
        (
            Vec<ServerMessage>,
            Option<Reply>,
            Option<HashMap<Holder, Ciphertext>>,
        ),
        sqlx::Error,
    > {
        // Nothing lists tasks or transcripts, and their ids are not the team's business yet.
        if list.kind != BlobKind::Decision {
            return Ok((Vec::new(), Some(Err(error(ErrorCode::BadRequest))), None));
        }
        let pace = &sub.listing;
        let continues = list.after.is_some()
            && pace.next.as_ref().is_some_and(|(kind, last)| {
                *kind == list.kind && list.after.as_ref() == Some(last)
            });
        if !continues {
            let wait = pace
                .started_at
                .map_or(0, |at| (at + BLOB_LIST_EVERY_MS).saturating_sub(now));
            if wait > 0 {
                tracing::debug!(kind = blob_kind(list.kind), "blob listing too soon");
                let refused = ErrorBody {
                    code: ErrorCode::RateLimited,
                    retry_after_ms: Some(wait),
                    holder: None,
                };
                return Ok((Vec::new(), Some(Err(refused)), None));
            }
        }
        let page = store::list_blobs(
            db,
            &self.id,
            blob_kind(list.kind),
            list.after.as_ref().map(BlobId::as_str),
            MAX_BLOB_LIST + 1,
        )
        .await?;
        let Some(rows) = page else {
            if let Some(entry) = self.subscribers.get_mut(&conn) {
                if !continues {
                    entry.listing.started_at = Some(now);
                }
                entry.listing.next = None;
            }
            tracing::debug!(
                kind = blob_kind(list.kind),
                "blob listing after an unknown blob"
            );
            return Ok((Vec::new(), Some(Err(error(ErrorCode::NotFound))), None));
        };
        let more = rows.len() > MAX_BLOB_LIST;
        let blobs: Vec<BlobEntry> = rows
            .into_iter()
            .take(MAX_BLOB_LIST)
            .filter_map(|row| {
                Some(BlobEntry {
                    blob: BlobId::new(row.id).ok()?,
                    by: Holder {
                        member: MemberId::new(row.member).ok()?,
                        device: DeviceId::new(row.device).ok()?,
                    },
                    created_at: UnixMillis(row.created_at),
                })
            })
            .collect();
        if let Some(entry) = self.subscribers.get_mut(&conn) {
            if !continues {
                entry.listing.started_at = Some(now);
            }
            entry.listing.next = more
                .then(|| blobs.last().map(|last| (list.kind, last.blob.clone())))
                .flatten();
        }
        tracing::debug!(
            kind = blob_kind(list.kind),
            blobs = blobs.len(),
            more,
            "blob listing"
        );
        let text = self.frame(
            Some(op),
            None,
            ServerMessage::Blobs(BlobListing {
                kind: list.kind,
                blobs,
                more,
            }),
        );
        self.send(conn, text);
        Ok((Vec::new(), None, None))
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
    ) -> Result<Handled, sqlx::Error> {
        let Some(sub) = self.subscribers.get(&conn).cloned() else {
            // Removed while the frame was already in flight: a `memberlog.get` gets the grace
            // period answer, so the app does not wait for an answer that never comes.
            match message {
                ClientMessage::MemberLogGet(get) => {
                    self.departing_log_get(db, conn, op, get.after).await?;
                }
                ClientMessage::DeviceKeys(_) | ClientMessage::DeviceProve(_) => {
                    self.departing_ack(conn, op, &message);
                }
                _ => {}
            }
            return Ok(Handled::Done);
        };
        self.last_activity = now;
        // A kind newer than this connection's negotiated version is refused as a relay of that
        // version would refuse it: nothing applied, nothing remembered for retries.
        if message.since() > sub.proto {
            self.reply(conn, op, Err(error(ErrorCode::BadRequest)));
            return Ok(Handled::Done);
        }
        // First the possession rule: in a team with a log, a device that does not count as the
        // log's device may only register, prove itself and read. Before the op ID lookup, so a
        // refused intent is not remembered and its retry after the proof is applied.
        if let Err(restricted) = check_restricted(
            self.verifier.state(),
            &sub.holder,
            sub.possession(),
            &message,
        ) {
            tracing::debug!(
                kind = message.kind(),
                "intent of a device that does not count refused"
            );
            self.reply(conn, op, Err(error(restricted.code())));
            return Ok(Handled::Done);
        }
        if let ClientMessage::DeviceProve(prove) = &message {
            // Not deduplicated: the same proof verifies to the same result.
            let proved = self.prove(conn, &sub, prove);
            let passed = proved.is_ok();
            self.reply(conn, op, proved.map(|()| ack()).map_err(error));
            if !passed {
                return Ok(Handled::BadFrame);
            }
            self.refresh_counting(db, now).await?;
            return Ok(Handled::Done);
        }
        // Entries that change the log can make a connection start or stop counting.
        let changes_log = matches!(
            message,
            ClientMessage::MemberLogAppend(_)
                | ClientMessage::DeviceRemove(_)
                | ClientMessage::KeyRotate(_)
        );
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
                    return Ok(Handled::Done);
                }
                Retry::Mismatch => {
                    self.reply(conn, op, Err(error(ErrorCode::BadRequest)));
                    return Ok(Handled::Done);
                }
                Retry::New => {}
            }
        }
        let (events, reply, wrapped) = match message.check_epoch(self.book.epoch()) {
            Err(stale) => (Vec::new(), Some(Err(error(stale.code()))), None),
            Ok(()) => self.apply(db, limits, conn, op, &sub, message, at).await?,
        };
        let Some(reply) = reply else {
            return Ok(Handled::Done);
        };
        // Live hints that announce the answer's own write follow the answer (`notes.keys.updated`
        // after the `ack` of `notes.keys.set`); every other event goes out before it.
        let (hints, events): (Vec<_>, Vec<_>) = events.into_iter().partition(|m| {
            matches!(
                m,
                ServerMessage::NotesKeysUpdated(_)
                    | ServerMessage::BlobStored(_)
                    | ServerMessage::BlobDeleted(_)
            )
        });
        let (blob_hints, hints): (Vec<_>, Vec<_>) = hints.into_iter().partition(|m| {
            matches!(
                m,
                ServerMessage::BlobStored(_) | ServerMessage::BlobDeleted(_)
            )
        });
        self.prune_notes();
        self.emit(db, events, wrapped.as_ref()).await?;
        if let Some((key, digest)) = dedup {
            self.ops.remember(key, digest, reply.clone());
        }
        let applied = reply.is_ok();
        self.reply(conn, op, reply);
        // Right after the answer, before anything awaits: once the sender has its `ack`, the
        // hint is queued for every other connection too.
        self.send_blob_hints(blob_hints);
        self.emit(db, hints, None).await?;
        if changes_log && applied {
            self.refresh_counting(db, now).await?;
        }
        Ok(Handled::Done)
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
            // `device.prove` is answered in `handle`.
            ClientMessage::Hello(_)
            | ClientMessage::Ping
            | ClientMessage::TicketRenew(_)
            | ClientMessage::DeviceProve(_) => {
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
                // As everywhere else, the lower of log role and ticket role decides: a
                // promotion on the website alone does not release other people's tasks. A
                // member the log does not list acts as a plain member.
                let role = self.verifier.state().map_or(wire::role(sub.role), |state| {
                    state
                        .effective_role(&who.member, wire::role(sub.role))
                        .unwrap_or(wire::Role::Member)
                });
                let (events, refused) = self.book.force_release(role, m.task, at).into_events();
                self.dirty = true;
                (
                    self.book_messages(events),
                    Some(refused.map_or(Ok(ack()), |r| Err(rejection(&r, at)))),
                    None,
                )
            }
            ClientMessage::TaskRekey(m) => {
                // The note moves along, but only if the book accepts the rekey: otherwise a
                // member could overwrite the note of someone else's reservation.
                let before = self.notes.get(&m.to).cloned();
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
                if matches!(reply, Some(Err(_))) {
                    match before {
                        Some(note) => self.notes.insert(m.to, note),
                        None => self.notes.remove(&m.to),
                    };
                }
                (events, reply, None)
            }
            ClientMessage::ClaimSet(m) => {
                let bytes = claim_bytes(&m.files, m.detail.as_ref());
                let total: usize = self.sessions.values().map(HashMap::len).sum();
                let own = self.sessions.get(&who);
                // A session that is replaced frees its old bytes.
                let previous = own.and_then(|s| s.get(&m.session)).copied();
                let freed = previous.unwrap_or(0);
                let team_bytes: usize = self.sessions.values().flat_map(HashMap::values).sum();
                let member_bytes: usize = self
                    .sessions
                    .iter()
                    .filter(|(holder, _)| holder.member == who.member)
                    .flat_map(|(_, s)| s.values())
                    .sum();
                let member_sessions: usize = self
                    .sessions
                    .iter()
                    .filter(|(holder, _)| holder.member == who.member)
                    .map(|(_, s)| s.len())
                    .sum();
                let too_many = previous.is_none()
                    && (total >= MAX_SESSIONS_PER_TEAM
                        || own.map_or(0, HashMap::len) >= MAX_SESSIONS_PER_DEVICE
                        || member_sessions >= MAX_SESSIONS_PER_MEMBER);
                let member_here = member_bytes - freed + bytes;
                let team_here = team_bytes - freed + bytes;
                let (member_elsewhere, all_elsewhere) =
                    self.budget.claims_elsewhere(&self.id, &who.member);
                let too_large = member_here > limits.claim_bytes_per_member
                    || team_here > limits.claim_bytes_per_team
                    || member_elsewhere + member_here
                        > limits.claim_bytes_per_member * CLAIM_TEAMS_PER_MEMBER
                    || all_elsewhere + team_here > MAX_CLAIM_BYTES_TOTAL;
                if too_many || too_large {
                    (Vec::new(), Some(Err(error(ErrorCode::Limit))), None)
                } else {
                    self.sessions
                        .entry(who.clone())
                        .or_default()
                        .insert(m.session.clone(), bytes);
                    self.publish_claims();
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
                self.publish_claims();
                let notices = self.board.clear(&SessionRef {
                    holder: who.clone(),
                    session: m.session,
                });
                self.deliver_overlaps(notices);
                (Vec::new(), Some(Ok(ack())), None)
            }
            ClientMessage::BlobPut(m) => {
                let decision = m.kind == BlobKind::Decision;
                // Decisions are counted, sized and announced only from version 4 on, so none
                // can bypass that through an older connection (no released app of an older
                // version writes them).
                if decision && sub.proto < DECISIONS_PROTOCOL_VERSION {
                    return Ok((Vec::new(), Some(Err(error(ErrorCode::BadRequest))), None));
                }
                if decision && m.content.data.as_str().len() > MAX_DECISION_CIPHERTEXT_LEN {
                    return Ok((Vec::new(), Some(Err(error(ErrorCode::Limit))), None));
                }
                let caps = decision.then_some(DecisionCaps {
                    per_team: MAX_DECISIONS,
                    per_member: MAX_DECISIONS_PER_MEMBER,
                });
                match store::put_blob(
                    db,
                    &self.id,
                    blob_kind(m.kind),
                    m.content.epoch,
                    &m.content.data,
                    &who,
                    limits.blob_quota_bytes,
                    caps,
                    now,
                )
                .await?
                {
                    BlobPut::Stored(id) => match BlobId::new(id) {
                        Ok(blob) => {
                            let hints = if decision {
                                vec![ServerMessage::BlobStored(BlobStored {
                                    kind: m.kind,
                                    blob: blob.clone(),
                                    by: who.clone(),
                                })]
                            } else {
                                Vec::new()
                            };
                            (
                                hints,
                                Some(Ok(Ack {
                                    blob: Some(blob),
                                    content: None,
                                    keys: None,
                                })),
                                None,
                            )
                        }
                        Err(_) => (Vec::new(), Some(Err(error(ErrorCode::BadRequest))), None),
                    },
                    BlobPut::Quota | BlobPut::Full => {
                        (Vec::new(), Some(Err(error(ErrorCode::Limit))), None)
                    }
                }
            }
            ClientMessage::BlobDelete(m) => {
                // `notFound` before any right is checked, also for another team's ID: nothing
                // is told about other teams.
                let mut hints = Vec::new();
                let reply = match store::blob_author(db, &self.id, m.blob.as_str()).await? {
                    None => Err(error(ErrorCode::NotFound)),
                    Some((author, kind)) => {
                        let allowed = match MemberId::new(author) {
                            Ok(author) => check_blob_delete(
                                self.verifier.state(),
                                wire::role(sub.role),
                                &who,
                                &author,
                            )
                            .map_err(|refused| refused.code()),
                            Err(_) => Err(ErrorCode::Forbidden),
                        };
                        match allowed {
                            Err(code) => Err(error(code)),
                            Ok(()) if store::delete_blob(db, &self.id, m.blob.as_str()).await? => {
                                if kind == blob_kind(BlobKind::Decision) {
                                    hints.push(ServerMessage::BlobDeleted(BlobDeleted {
                                        kind: BlobKind::Decision,
                                        blob: m.blob.clone(),
                                    }));
                                }
                                Ok(ack())
                            }
                            // A concurrent delete won.
                            Ok(()) => Err(error(ErrorCode::NotFound)),
                        }
                    }
                };
                (hints, Some(reply), None)
            }
            ClientMessage::BlobList(m) => self.list_blobs(db, conn, op, sub, m, now).await?,
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
                // Once the verified log lists this device, its keys are fixed: other keys would
                // make `devices.get` disagree with the log, and with a stolen ticket of the same
                // member someone could slip their own keys in front of the next `AddDevice`.
                let listed = self
                    .verifier
                    .state()
                    .and_then(|state| state.device(&who))
                    .map(|entry| entry.keys);
                if listed.is_some_and(|keys| keys.sign != m.sign || keys.kem != m.kem) {
                    return Ok((Vec::new(), Some(Err(error(ErrorCode::Conflict))), None));
                }
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
                    store::KeysStored::Conflict => Err(error(ErrorCode::Conflict)),
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
            ClientMessage::NotesKeysGet => {
                let record = store::notes_keys(db, &self.id).await?;
                let text = self.frame(
                    Some(op),
                    None,
                    ServerMessage::NotesKeys(NotesKeys { record }),
                );
                self.send(conn, text);
                (Vec::new(), None, None)
            }
            ClientMessage::NotesKeysSet(m) => {
                // `handle` has checked the epoch; the size was checked while decoding.
                if !self.may_manage_notes_keys(&who, sub.role) {
                    (Vec::new(), Some(Err(error(ErrorCode::Forbidden))), None)
                } else {
                    match store::set_notes_keys(db, &self.id, m.base, &who, &m.content, now).await?
                    {
                        store::NotesKeysStored::Stored(version) => (
                            vec![ServerMessage::NotesKeysUpdated(NotesKeysUpdated {
                                version,
                                by: who.clone(),
                            })],
                            Some(Ok(ack())),
                            None,
                        ),
                        store::NotesKeysStored::Conflict => {
                            (Vec::new(), Some(Err(error(ErrorCode::Conflict))), None)
                        }
                    }
                }
            }
        })
    }

    /// Whether `who` may write the team's notes key ring: a device of the verified log whose
    /// effective role (the lower of log role and ticket role) is owner or admin. Without a log
    /// nobody may: there is no epoch secret to seal it under. A device the log does not list
    /// could not produce a record any member accepts, so it does not get to replace one.
    fn may_manage_notes_keys(&self, who: &Holder, ticket_role: Role) -> bool {
        let Some(state) = self.verifier.state() else {
            return false;
        };
        state.device(who).is_some()
            && matches!(
                state.effective_role(&who.member, wire::role(ticket_role)),
                Some(wire::Role::Owner | wire::Role::Admin)
            )
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
        let conns = self.counting(|s| s.holder == *holder);
        for conn in conns {
            self.send(conn, text.clone());
        }
    }

    /// `device.keys` or `device.prove` of a connection in its grace period: acknowledged
    /// without effect (no key registered, nothing verified or recorded), so the app goes on
    /// to read the log up to its removal. `false`: the connection is not in its grace period
    /// here.
    pub fn departing_ack(&self, conn: u64, op: &OpId, message: &ClientMessage) -> bool {
        let Some(departing) = self.departing.get(&conn) else {
            return false;
        };
        let reply = if message.since() > departing.proto {
            ServerMessage::Err(error(ErrorCode::BadRequest))
        } else {
            ServerMessage::Ack(ack())
        };
        departing.send(self.frame(Some(op), None, reply).as_ref());
        true
    }

    /// `device.prove`: verifies the proof against this connection's challenge and holder. A
    /// passing proof keeps its key (`Proven`); a refused one changes nothing.
    fn prove(&mut self, conn: u64, sub: &Subscriber, prove: &DeviceProve) -> Result<(), ErrorCode> {
        let Some(challenge) = sub.possession.challenge else {
            return Err(ErrorCode::BadRequest);
        };
        match verify_connection_proof(&self.team, &sub.holder, sub.proto, &challenge, prove) {
            Ok(key) => {
                if let Some(sub) = self.subscribers.get_mut(&conn) {
                    sub.possession.proven = Some(key);
                }
                tracing::info!("connection proof passed");
                Ok(())
            }
            Err(refused) => {
                tracing::info!(reason = %refused, "connection proof refused");
                Err(refused.code())
            }
        }
    }
}

/// Reply to a rejected log entry (`LogError::code`). Rejected entries change nothing; the log
/// stays open for the next valid entry.
fn log_refused(refused: &LogError) -> Reply {
    tracing::info!(reason = %refused, "log entry rejected");
    Err(error(refused.code()))
}

impl Drop for Team {
    /// An unloaded or deleted team gives its share of the shared budget back.
    fn drop(&mut self) {
        self.budget.set_claims(&self.id, HashMap::new());
        self.budget
            .window_bytes
            .fetch_sub(self.window_bytes, Ordering::Relaxed);
    }
}

/// Limits from the configuration that `handle` needs.
#[derive(Debug, Clone, Copy)]
pub struct HandleLimits {
    pub blob_quota_bytes: u64,
    /// Claim bytes per member and per team (`Config::claim_bytes_per_member`, `_per_team`).
    pub claim_bytes_per_member: usize,
    pub claim_bytes_per_team: usize,
}

/// Memory a claim holds in the board: its file hashes and the encrypted detail.
fn claim_bytes(files: &[PathHashes], detail: Option<&Sealed>) -> usize {
    std::mem::size_of_val(files) + detail.map_or(0, |d| d.data.as_str().len())
}
