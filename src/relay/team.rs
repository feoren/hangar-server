//! Laufzeitzustand eines Teams. Die Regeln kommen aus dem Protokoll-Crate der App:
//! `ReservationBook` ("first wins", Ablauf, Freigabe, Rekey), `ClaimBoard` (Vergleich der Keyed
//! Hashes), `EventLog` (Sequenz, Nachspielen, Resync), `RecentOps` (Wiederholungen je Absender,
//! Team und Operations-ID mit Digest des Inhalts), `check_epoch`, `check_rotate`,
//! `check_append`. Hier liegen nur Verteilung, Speicherung und die Rechte, die das Relay aus dem
//! Ticket kennt.
//!
//! Der Aufrufer hält die Sperre des Teams; damit gilt die Ankunftsreihenfolge als Wahrheit, und
//! Ereignisse gehen in Sequenzreihenfolge an alle Empfänger.

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
use tokio::sync::{mpsc, Notify};

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

/// Ereignisse im Speicher für das Nachspielen; ältere verlangen einen Snapshot.
pub const REPLAY_WINDOW: usize = 2048;
/// Gemerkte Operations-IDs je Team für idempotente Wiederholung.
pub const RECENT_OPS: usize = 4096;
/// Claims je Gerät.
pub const MAX_SESSIONS_PER_DEVICE: usize = 64;
/// Claims je Team (Schutz des Speichers).
pub const MAX_SESSIONS_PER_TEAM: usize = 2000;
/// Claims eines Geräts, das so lange offline ist, verfallen (in Millisekunden).
pub const OFFLINE_CLAIMS_MS: u64 = 24 * 60 * 60 * 1000;

/// Close-Codes und `hello`-Frist des Protokoll-Crates.
pub mod close {
    pub use hangar_team_protocol::close::{
        CLOSE_HELLO_TIMEOUT, CLOSE_REMOVED, CLOSE_ROLE_CHANGED, CLOSE_TEAM_DELETED,
        HELLO_TIMEOUT_SECS,
    };
}

/// Was an eine Verbindung geht.
#[derive(Debug, Clone)]
pub enum Outgoing {
    Text(Utf8Bytes),
    Close(u16, &'static str),
}

/// Eine Verbindung, die im Team angemeldet ist.
#[derive(Debug, Clone)]
pub struct Subscriber {
    pub holder: Holder,
    pub role: Role,
    pub tx: mpsc::Sender<Outgoing>,
    /// Wird ausgelöst, wenn die Verbindung nicht mehr mitkommt (Warteschlange voll).
    pub kick: Arc<Notify>,
}

/// Wem eine Hinweismail gelten könnte (Selbstbetrieb): Mitglied ist nicht verbunden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attention {
    pub team: String,
    pub member: String,
}

type Reply = Result<Ack, ErrorBody>;

/// Notizen, die das Relay neben dem Buch hält und mit ihm speichert.
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
    /// Sitzungen je Gerät, für die Grenzen (das Board zählt nicht).
    sessions: HashMap<Holder, HashSet<SessionKey>>,
    /// Verschlüsselte Notizen gehaltener Aufgaben und offener Freigabewünsche; das Buch kennt
    /// sie nicht, die Ereignisse tragen sie.
    notes: HashMap<KeyedHash, Sealed>,
    request_notes: HashMap<KeyedHash, Sealed>,
    members: BTreeMap<String, Role>,
    presence: HashMap<Holder, PresenceUpdate>,
    subscribers: HashMap<u64, Subscriber>,
    offline_since: HashMap<Holder, u64>,
    ops: RecentOps<Reply>,
    /// Das geprüfte Mitgliedschafts-Log (hangar-team-crypto), nach einem Neustart mit `apply_all`
    /// aus den gespeicherten Einträgen neu aufgebaut.
    verifier: LogVerifier,
    /// Neueste unzugestellte `notify` je Mitglied (auch gespeichert).
    pending: HashMap<MemberId, NotifyMessage>,
    /// Das Buch hat sich seit dem letzten Speichern geändert.
    dirty: bool,
    pub attention: Vec<Attention>,
    pub last_activity: u64,
}

impl Team {
    /// Lädt ein Team: Buch und Log-Position aus dem gespeicherten Zustand (`restore` des
    /// Crates, alle Halter gelten danach als getrennt); die Ereignisse des Neustarts gehen ins
    /// Log. Fehlt der Zustand oder passt er nicht, beginnt ein leeres Buch mit neuem Stream
    /// (Clients holen einen Snapshot).
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
                    tracing::warn!(%error, "Reservierungen nicht lesbar, neuer Stream");
                    return None;
                }
            };
            match ReservationBook::restore(snapshot, policy, at) {
                Ok(restored) => Some((position, notes, restored)),
                Err(error) => {
                    tracing::warn!(%error, "Reservierungen nicht wiederherstellbar, neuer Stream");
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
            // Gespeichert wird nur, was zugelassen war; ein Fehler hier heißt beschädigte Daten.
            // Das Log bleibt beim letzten gültigen Eintrag stehen.
            tracing::error!(%error, "gespeichertes Mitgliedschafts-Log nicht nachvollziehbar");
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
            offline_since: HashMap::new(),
            ops: RecentOps::new(RECENT_OPS),
            verifier,
            pending,
            dirty: true,
            attention: Vec::new(),
            last_activity: now,
        };
        let mut events = loaded.book_messages(events);
        // Hat ein Absturz die Epoche in der Datenbank weitergedreht als im Buch, gilt die der
        // Datenbank (key.rotate wurde dort schon bestätigt).
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

    /// Nichts verbunden, nichts gehalten, nichts gemerkt: darf aus dem Speicher.
    pub fn idle(&self, now: u64) -> bool {
        self.subscribers.is_empty()
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
                tracing::error!(%error, kind, "Rahmen nicht kodierbar");
                None
            }
        }
    }

    fn send(&mut self, conn: u64, text: Option<Utf8Bytes>) {
        let Some(text) = text else { return };
        if let Some(sub) = self.subscribers.get(&conn) {
            if sub.tx.try_send(Outgoing::Text(text)).is_err() {
                // Wer nicht mitkommt, wird getrennt und holt per Cursor nach.
                sub.kick.notify_one();
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

    /// Ein Ereignis des Buchs als Servernachricht, mit den Notizen, die das Relay hält.
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

    /// Notizen nur für Aufgaben behalten, die noch gehalten bzw. angefragt sind.
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

    /// Verteilt Ereignisse: geloggte bekommen die nächste Sequenznummer, alle gehen an jede
    /// Verbindung des Teams. `wrapped` füllt `key.rotated` je Gerät.
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
        // Haltbarkeitsregel: erst Buch und Log-Position speichern, dann senden. Kein Rahmen mit
        // `seq` verlässt das Relay, bevor ein gespeicherter head ihn abdeckt; sonst vergäbe ein
        // Neustart dieselbe `seq` an ein neues Ereignis.
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
                    let text = self.frame(None, seq, message);
                    for (conn, _) in conns {
                        self.send(conn, text.clone());
                    }
                }
            }
        }
        Ok(())
    }

    /// Buch (`export`), Log-Position und Notizen in einer Schreibung.
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

    /// Die gemerkte `notify` eines Mitglieds an alle seine Verbindungen (nach `welcome`).
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

    /// Freigabewunsch oder bevorstehender Ablauf bei einem nicht verbundenen Halter. `notify`
    /// legt `emit` ab; im Selbstbetrieb geht zusätzlich eine Hinweismail.
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

    /// Anmeldung einer Verbindung nach geprüftem Ticket. Schickt Nachspiel oder Snapshot und
    /// danach die Beitrittsereignisse. Präsenz zählt je Verbindung.
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
    ) -> Result<Result<(), ErrorCode>, sqlx::Error> {
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
        if store::device_removed(
            db,
            &self.id,
            sub.holder.member.as_str(),
            sub.holder.device.as_str(),
        )
        .await?
        {
            tracing::info!("hello eines entfernten Geräts abgelehnt");
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
        Ok(Ok(()))
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

    /// Zustand als Ereignisse ohne `seq` (nach `resync_required`).
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

    /// Eine Verbindung meldet sich ab (getrennt, zu langsam, Ticketalter erreicht).
    pub async fn leave(&mut self, db: &Db, conn: u64, now: u64) -> Result<(), sqlx::Error> {
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
                let _ = sub.tx.try_send(Outgoing::Close(code, reason));
            }
        }
    }

    /// Ein Mitglied wurde entfernt (Selbstbetrieb oder Widerrufsliste): Reservierungen und
    /// Claims enden, offene Verbindungen werden mit 4403 geschlossen.
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

    /// Ein Gerät verlässt das Team (sein Mitglied bleibt): Reservierungen frei, Claims weg,
    /// Verbindungen des Geräts mit 4403 zu. Gibt die Ereignisse zurück (ohne `device.removed`).
    fn drop_device(&mut self, holder: &Holder, now: u64) -> Vec<ServerMessage> {
        let removed = self.book.remove_device(holder, UnixMillis(now));
        self.dirty = true;
        let events = self.book_messages(removed);
        let notices = self.board.clear_device(holder);
        self.sessions.remove(holder);
        self.deliver_overlaps(notices);
        self.close_where(close::CLOSE_REMOVED, "device removed", |s| {
            s.holder == *holder
        });
        self.presence.remove(holder);
        self.offline_since.remove(holder);
        self.prune_notes();
        events
    }

    /// Verbindungen eines Mitglieds schließen (4401), weil seine Rolle sich änderte und die neue
    /// unbekannt ist; die App kommt mit einem neuen Ticket zurück.
    pub fn renew_member(&mut self, member: &str) {
        self.close_where(close::CLOSE_ROLE_CHANGED, "role changed", |s| {
            s.holder.member.as_str() == member
        });
    }

    /// Eine bekannte neue Rolle still auf allen Verbindungen des Mitglieds anwenden (aus
    /// `ticket.renew`, der Widerrufsliste oder dem Selbstbetrieb). Rechte werden je Nachricht
    /// geprüft, also scheitern Owner- und Admin-Absichten danach von selbst; getrennt wird
    /// nicht. Eine echte Änderung meldet `member.role_changed`.
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

    /// Alle Verbindungen schließen (Team gelöscht).
    pub fn close_all(&mut self) {
        for (_, sub) in self.subscribers.drain() {
            let _ = sub
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

    /// Eine Absicht einer angemeldeten Verbindung.
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

    /// Wendet eine Absicht an. `None` als Antwort: die Antwort ist schon gesendet (Lesen).
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
            team.dirty = true;
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
                // Bei Annahme trägt die neue Reservierung die Notiz des Wunsches.
                let before = self.notes.get(&m.task).cloned();
                if m.accept {
                    match self.request_notes.get(&m.task).cloned() {
                        Some(note) => self.notes.insert(m.task, note),
                        None => self.notes.remove(&m.task),
                    };
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
                // Erst die Schlüssel, die der Eintrag einträgt, gegen die über die eigenen
                // Verbindungen registrierten; dann der Eintrag selbst gegen das geprüfte Log.
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
                        // Eintrag, Epoche und Pakete in einer Transaktion oder nichts.
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
                                        "Buch und Datenbank sind bei der Epoche uneins"
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
                // Rechte vor Zustand; ein Paket je Absender, höchstens MAX_KEY_PACKAGES je Ziel.
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
                // Nur mit dem signierten Eintrag; gespeichert und entfernt in einem Schritt.
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

    /// Die registrierten Schlüssel der Holder, die ein Eintrag einträgt (für
    /// `check_registered_keys`, das synchron fragt).
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

    /// Geräte, die ein zugelassener Eintrag aus dem Team nahm: Reservierungen frei, Claims weg,
    /// Verbindungen 4403; `device.removed` je Gerät. Gesperrt und vergessen hat sie schon die
    /// Transaktion des Eintrags.
    fn drop_removed(&mut self, admitted: &Admitted, now: u64) -> Vec<ServerMessage> {
        let mut events = Vec::new();
        for holder in &admitted.removed {
            events.extend(self.drop_device(holder, now));
            events.push(ServerMessage::DeviceRemoved(DeviceRemoved {
                holder: holder.clone(),
            }));
        }
        events
    }

    /// `key.wrapped` geht nur an die Verbindungen des Zielgeräts (Mitglied und Gerät), nie ins
    /// Ereignislog.
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

/// Antwort auf einen abgelehnten Log-Eintrag (`LogError::code`). Abgelehnte Einträge ändern
/// nichts; das Log bleibt für den nächsten gültigen Eintrag offen.
fn log_refused(refused: &LogError) -> Reply {
    tracing::info!(reason = %refused, "Log-Eintrag abgelehnt");
    Err(error(refused.code()))
}

/// Grenzen aus der Konfiguration, die `handle` braucht.
#[derive(Debug, Clone, Copy)]
pub struct HandleLimits {
    pub blob_quota_bytes: u64,
}
