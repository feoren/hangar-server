//! Relay core: verifies tickets, holds the live state per team and distributes encrypted
//! events. Knows nothing about accounts, seats or licenses; the website or the self-hosting
//! identity decides those before issuing a ticket.

pub mod conn;
pub mod outbox;
pub mod revocation;
pub mod store;
pub mod team;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch, Mutex, Notify, OnceCell};

use crate::config::Config;
use crate::db::Db;
use crate::signed::KeySet;
use crate::ticket::{self, Role, TicketClaims};
use crate::util::{now_ms, now_s};
use crate::wire::{ErrorCode, MemberId, ProtoRange, PROOF_PROTOCOL_VERSION};
use hangar_team_protocol::reservation::Policy;

use team::{Attention, Budget, HandleLimits, Team};

/// Why a `ticket.renew` was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewRefused {
    /// `prj` is not the team of the frame: `err forbidden`, then close 4403.
    OtherTeam,
    /// Invalid, different member, no seat or already used: close 4403.
    Removed,
    /// Storage error: `err badRequest`, the connection stays open.
    Failed,
    /// Issued up to a role change (or an earlier removal): may carry the old role. Close 4401,
    /// the app comes back with a new ticket.
    Stale,
}

pub struct Relay {
    pub db: Db,
    keys: KeySet,
    audience: String,
    policy: Policy,
    pub limits: HandleLimits,
    /// Memory shared by all loaded teams (claims, replay windows).
    pub budget: Arc<Budget>,
    max_connections: usize,
    /// Connections without a valid `hello` yet: at most a quarter of `max_connections`, so
    /// connections that never sign in cannot take every slot. When the quota is full, a new
    /// connection closes the oldest waiting one instead of being refused: the app sends its
    /// `hello` right away, so connections that only wait cannot lock anyone out.
    max_before_hello: usize,
    max_per_member: usize,
    max_per_ip: usize,
    /// Connections one address may have waiting for `hello` (a quarter of `max_per_ip`, at
    /// least 4: behind the NAT of an office many apps reconnect at once after a restart).
    max_waiting_per_address: usize,
    pub connection_max_age: Duration,
    pub hello_timeout: Duration,
    /// Grace period of a removed device for its `memberlog.get` (see `conn`).
    pub removed_grace: Duration,
    /// `REQUIRE_DEVICE_PROOF`: only protocol version 3 and newer (`proto_range`).
    require_device_proof: AtomicBool,
    transcript_retention_ms: u64,
    /// Loaded teams. The map's lock is held only to find or insert an entry; the team itself
    /// loads outside it, in its entry's cell (see `team`).
    teams: Mutex<HashMap<String, Arc<TeamCell>>>,
    connections: AtomicUsize,
    /// Connections waiting for their first valid `hello`, oldest first.
    waiting: std::sync::Mutex<VecDeque<Waiting>>,
    /// Ticks skipped in a row per team because its lock was held (see `tick`).
    skipped_ticks: std::sync::Mutex<HashMap<String, u32>>,
    /// Test hook: every team load waits this long first (milliseconds, 0 in operation).
    load_delay_ms: AtomicU64,
    per_member: std::sync::Mutex<HashMap<String, usize>>,
    per_ip: std::sync::Mutex<HashMap<String, usize>>,
    next_conn: AtomicU64,
    attention: Option<mpsc::Sender<Attention>>,
}

pub const SERVER_PROTO: ProtoRange = ProtoRange::CURRENT;

impl Relay {
    pub fn new(
        db: Db,
        config: &Config,
        keys: KeySet,
        attention: Option<mpsc::Sender<Attention>>,
    ) -> Self {
        Relay {
            db,
            keys,
            audience: config.ticket_audience.clone(),
            policy: Policy::new(
                config.reservation_inactivity_s.saturating_mul(1000),
                config.reservation_warn_s.saturating_mul(1000),
                false,
            )
            .unwrap_or_else(|error| {
                tracing::warn!(%error, "invalid reservation deadlines, using defaults");
                Policy::default()
            }),
            limits: HandleLimits {
                blob_quota_bytes: config.blob_quota_bytes,
                claim_bytes_per_member: config.claim_bytes_per_member,
                claim_bytes_per_team: config.claim_bytes_per_team,
            },
            budget: Arc::new(Budget::default()),
            max_connections: config.max_connections,
            max_before_hello: (config.max_connections / 4).max(1),
            max_per_member: config.max_connections_per_member,
            max_per_ip: config.max_connections_per_ip,
            max_waiting_per_address: (config.max_connections_per_ip / 4).max(4),
            connection_max_age: Duration::from_secs(config.connection_max_age_s.max(60)),
            hello_timeout: Duration::from_millis(config.hello_timeout_ms.max(100)),
            removed_grace: Duration::from_millis(config.removed_grace_ms.clamp(100, 30_000)),
            require_device_proof: AtomicBool::new(config.require_device_proof),
            transcript_retention_ms: config.transcript_retention_days.saturating_mul(86_400_000),
            teams: Mutex::new(HashMap::new()),
            connections: AtomicUsize::new(0),
            waiting: std::sync::Mutex::new(VecDeque::new()),
            skipped_ticks: std::sync::Mutex::new(HashMap::new()),
            load_delay_ms: AtomicU64::new(0),
            per_member: std::sync::Mutex::new(HashMap::new()),
            per_ip: std::sync::Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            attention,
        }
    }

    /// Keys of the ticket issuers (for the revocation list, which uses the same ones).
    pub fn ticket_keys(&self) -> &KeySet {
        &self.keys
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Test hook: makes every following team load wait `ms` first, to check what else waits
    /// for a load.
    #[doc(hidden)]
    pub fn delay_team_loads(&self, ms: u64) {
        self.load_delay_ms.store(ms, Ordering::Relaxed);
    }

    pub fn next_conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Takes a connection slot; `false` when at full capacity.
    pub fn acquire_connection(&self) -> bool {
        let previous = self.connections.fetch_add(1, Ordering::AcqRel);
        if previous >= self.max_connections {
            self.connections.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    pub fn release_connection(&self) {
        self.connections.fetch_sub(1, Ordering::AcqRel);
    }

    /// Takes a slot among the connections still waiting for their first valid `hello`. `None`
    /// when this address (IPv6 per /48, see `ClientIp::wide_key`) already has
    /// `max_waiting_per_address` waiting. A full quota closes the oldest waiting connection: it
    /// receives the signal returned with its own slot.
    pub fn acquire_before_hello(&self, address: &str) -> Option<(u64, Arc<Notify>)> {
        let mut waiting = self.waiting.lock().ok()?;
        if waiting.iter().filter(|w| w.address == address).count() >= self.max_waiting_per_address {
            return None;
        }
        let id = self.next_conn();
        let close = Arc::new(Notify::new());
        waiting.push_back(Waiting {
            id,
            address: address.to_owned(),
            close: close.clone(),
        });
        if waiting.len() > self.max_before_hello {
            if let Some(oldest) = waiting.pop_front() {
                // `notify_one` keeps the signal if the connection is not waiting for it yet.
                oldest.close.notify_one();
            }
        }
        Some((id, close))
    }

    /// Connections one address may have waiting for their first `hello`.
    pub fn max_waiting_per_address(&self) -> usize {
        self.max_waiting_per_address
    }

    /// The connection's first valid `hello`, or its end without one.
    pub fn release_before_hello(&self, id: u64) {
        if let Ok(mut waiting) = self.waiting.lock() {
            waiting.retain(|w| w.id != id);
        }
    }

    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }

    pub fn acquire_member(&self, member: &str) -> bool {
        acquire(&self.per_member, member, self.max_per_member)
    }

    pub fn release_member(&self, member: &str) {
        release(&self.per_member, member);
    }

    /// Connections per client address (IPv6 per /64, see `ClientIp::key`).
    pub fn acquire_ip(&self, key: &str) -> bool {
        acquire(&self.per_ip, key, self.max_per_ip)
    }

    pub fn release_ip(&self, key: &str) {
        release(&self.per_ip, key);
    }

    /// The protocol versions this relay offers: `SERVER_PROTO`, or only 3 and newer with
    /// `REQUIRE_DEVICE_PROOF`.
    pub fn proto_range(&self) -> ProtoRange {
        if self.require_device_proof.load(Ordering::SeqCst) {
            ProtoRange::new(PROOF_PROTOCOL_VERSION, SERVER_PROTO.max()).unwrap_or(SERVER_PROTO)
        } else {
            SERVER_PROTO
        }
    }

    /// Switches `REQUIRE_DEVICE_PROOF` on a running relay. Switching it on closes every open
    /// connection of protocol version 1 or 2 with 4401; their next `hello` gets
    /// `outdatedClient`.
    pub async fn set_require_device_proof(&self, on: bool) -> Result<(), sqlx::Error> {
        // Set before any team lock is taken: a `hello` joining meanwhile reads it again under
        // its team's lock (`conn`).
        let was = self.require_device_proof.swap(on, Ordering::SeqCst);
        if !on || was {
            return Ok(());
        }
        let teams: Vec<Arc<Mutex<Team>>> = self
            .teams
            .lock()
            .await
            .values()
            .filter_map(|cell| cell.get().cloned())
            .collect();
        for team in teams {
            let mut guard = team.lock().await;
            guard.require_device_proof(&self.db, now_ms()).await?;
            self.forward_attention(&mut guard);
        }
        Ok(())
    }

    /// Checks `hello`: ticket, team, seat, protocol, single-use `jti`, device binding.
    pub async fn check_hello(
        &self,
        ticket_text: &str,
        team: &str,
        device: &str,
        proto: ProtoRange,
    ) -> Result<(TicketClaims, u16), ErrorCode> {
        let offered = self.proto_range();
        let Some(version) = proto.negotiate(offered) else {
            return Err(if proto.max() < offered.min() {
                ErrorCode::OutdatedClient
            } else {
                ErrorCode::BadRequest
            });
        };
        let claims = match ticket::verify(ticket_text, &self.keys, now_s(), Some(&self.audience)) {
            Ok(claims) => claims,
            Err(error) => {
                tracing::info!(reason = %error, "ticket rejected");
                return Err(ErrorCode::Forbidden);
            }
        };
        if MemberId::new(claims.sub.clone()).is_err() {
            tracing::info!("account ID in the ticket does not fit the protocol");
            return Err(ErrorCode::Forbidden);
        }
        if claims.prj != team {
            tracing::info!("ticket for a different team");
            return Err(ErrorCode::Forbidden);
        }
        if !claims.seat_ok {
            return Err(ErrorCode::Limit);
        }
        match store::use_jti(&self.db, &claims.jti, claims.exp).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("ticket was reused");
                return Err(ErrorCode::Forbidden);
            }
            Err(error) => {
                tracing::error!(%error, "cannot store jti");
                return Err(ErrorCode::BadRequest);
            }
        }
        match store::bind_device(&self.db, device, &claims.sub, now_ms()).await {
            Ok(()) => Ok((claims, version)),
            Err(error) => {
                tracing::error!(%error, "cannot store device");
                Err(ErrorCode::BadRequest)
            }
        }
    }

    /// The team in memory, loaded from the database if needed. Only finding or inserting the
    /// entry happens under the map's lock; loading (queries, verifying the log, the first
    /// write) runs in the entry's cell, so `hello` for other teams, the timer and the
    /// revocation list do not wait for it. Concurrent callers for the same team wait for the
    /// same load. A failed load leaves the cell empty but in the map: a caller already waiting
    /// on it tries again in the same cell (removing it would let a third caller start a
    /// second load in a new one); the timer drops empty cells nobody holds.
    pub async fn team(&self, id: &str) -> Result<Arc<Mutex<Team>>, sqlx::Error> {
        let cell = self
            .teams
            .lock()
            .await
            .entry(id.to_owned())
            .or_default()
            .clone();
        let loaded = cell
            .get_or_try_init(|| async {
                let delay = self.load_delay_ms.load(Ordering::Relaxed);
                if delay > 0 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
                let team =
                    Team::load(&self.db, id, self.policy, self.budget.clone(), now_ms()).await?;
                Ok::<_, sqlx::Error>(Arc::new(Mutex::new(team)))
            })
            .await
            .cloned();
        let teams = self.teams.lock().await;
        let current = teams.get(id).is_some_and(|c| Arc::ptr_eq(c, &cell));
        match loaded {
            Ok(team) if current => Ok(team),
            Ok(team) => {
                // Deleted (`close_team`) while it was loading. The load may have created the
                // team's row after the delete; it goes again, unless someone has loaded the
                // team anew since (then the row is theirs).
                let reloaded = teams.contains_key(id);
                drop(teams);
                team.lock().await.close_all();
                if !reloaded {
                    self.delete_team_rows(id).await?;
                }
                Err(sqlx::Error::RowNotFound)
            }
            Err(failure) => Err(failure),
        }
    }

    /// Passes notices on to the identity (only self-hosting has a receiver).
    pub fn forward_attention(&self, team: &mut Team) {
        let pending = std::mem::take(&mut team.attention);
        if let Some(tx) = &self.attention {
            for item in pending {
                let _ = tx.try_send(item);
            }
        }
    }

    /// Removes a member (self-hosting): event, reservations released, connections closed.
    pub async fn remove_member(&self, team_id: &str, member: &str) -> Result<(), sqlx::Error> {
        self.revoke_member(team_id, member, now_ms()).await
    }

    /// Removes a member as of `at_ms` (self-hosting or revocation list): a ticket issued up to
    /// then no longer opens the team; a later one lets the member in again.
    pub async fn revoke_member(
        &self,
        team_id: &str,
        member: &str,
        at_ms: u64,
    ) -> Result<(), sqlx::Error> {
        // Load the team first (creates the row), then record the removal: even someone who was
        // never connected cannot get in with an older ticket any more.
        let team = self.team(team_id).await?;
        store::mark_member_removed(&self.db, team_id, member, at_ms).await?;
        // Stays even after re-admission: a hoarded old ticket is never valid again.
        store::raise_ticket_floor(&self.db, team_id, member, at_ms).await?;
        let Ok(member) = MemberId::new(member) else {
            return Ok(());
        };
        let mut team = team.lock().await;
        team.remove_member(&self.db, &member, now_ms()).await
    }

    /// Role changed (as of `at_ms`), new role unknown: closes the member's connections (4401),
    /// the member comes back with a new ticket. Older tickets are no longer valid.
    pub async fn renew_member(
        &self,
        team_id: &str,
        member: &str,
        at_ms: u64,
    ) -> Result<(), sqlx::Error> {
        let team = self.team(team_id).await?;
        store::raise_ticket_floor(&self.db, team_id, member, at_ms).await?;
        let mut team = team.lock().await;
        team.renew_member(&self.db, member, now_ms()).await?;
        self.forward_attention(&mut team);
        Ok(())
    }

    /// Role changed (as of `at_ms`), new role known: applies it silently to the running
    /// connections. Tickets with `iat` up to `at_ms` may carry the old role; they no longer open
    /// the team and renew no connection (otherwise a demoted member could regain the old role
    /// with a previously hoarded ticket via `hello` or `ticket.renew`, for up to
    /// `CONNECTION_MAX_AGE_SECS`).
    pub async fn apply_role(
        &self,
        team_id: &str,
        member: &str,
        role: Role,
        at_ms: u64,
    ) -> Result<(), sqlx::Error> {
        let Ok(member) = MemberId::new(member) else {
            return Ok(());
        };
        // Create the team (foreign key), then set the floor before the new role.
        self.team(team_id).await?;
        store::raise_ticket_floor(&self.db, team_id, member.as_str(), at_ms).await?;
        let team = self
            .teams
            .lock()
            .await
            .get(team_id)
            .and_then(|cell| cell.get().cloned());
        match team {
            Some(team) => {
                team.lock()
                    .await
                    .apply_role(&self.db, &member, role, now_ms())
                    .await
            }
            None => {
                store::set_member_role(&self.db, team_id, member.as_str(), role, now_ms()).await
            }
        }
    }

    /// `ticket.renew`: checks the new ticket as for `hello` (signature, kid, time, `aud`,
    /// single-use `jti`) and that it is valid for this team and this member.
    pub async fn check_renew(
        &self,
        ticket_text: &str,
        team: &str,
        member: &str,
    ) -> Result<TicketClaims, RenewRefused> {
        let claims = match ticket::verify(ticket_text, &self.keys, now_s(), Some(&self.audience)) {
            Ok(claims) => claims,
            Err(error) => {
                tracing::info!(reason = %error, "renewed ticket rejected");
                return Err(RenewRefused::Removed);
            }
        };
        if claims.prj != team {
            return Err(RenewRefused::OtherTeam);
        }
        if claims.sub != member || !claims.seat_ok {
            return Err(RenewRefused::Removed);
        }
        let iat_ms = u64::try_from(claims.iat).unwrap_or(0).saturating_mul(1000);
        match store::ticket_age(&self.db, team, member, iat_ms).await {
            Ok(store::TicketAge::Current) => {}
            Ok(store::TicketAge::BeforeRemoval) => return Err(RenewRefused::Removed),
            Ok(store::TicketAge::Stale) => return Err(RenewRefused::Stale),
            Err(error) => {
                tracing::error!(%error, "cannot check ticket age");
                return Err(RenewRefused::Failed);
            }
        }
        match store::use_jti(&self.db, &claims.jti, claims.exp).await {
            Ok(true) => Ok(claims),
            Ok(false) => Err(RenewRefused::Removed),
            Err(error) => {
                tracing::error!(%error, "cannot store jti");
                Err(RenewRefused::Failed)
            }
        }
    }

    /// Team deleted (self-hosting): closes connections, removes relay data.
    pub async fn close_team(&self, team_id: &str) -> Result<(), sqlx::Error> {
        let cell = self.teams.lock().await.remove(team_id);
        if let Some(team) = cell.as_ref().and_then(|cell| cell.get()) {
            team.lock().await.close_all();
        }
        self.delete_team_rows(team_id).await
    }

    /// Deletes the team's row; everything else of the team goes with it (`ON DELETE CASCADE`).
    async fn delete_team_rows(&self, team_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM relay_teams WHERE id = ?")
            .bind(team_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Timer: expiries and warnings, unloading unused teams. A team whose lock is held right
    /// now (an intent, a slow write) is skipped, so it does not hold up the others. After
    /// `MAX_SKIPPED_TICKS` skips in a row the timer waits for its lock, after all other teams:
    /// expiries and warnings for others and the expiry of offline claims only run here.
    pub async fn tick(&self) {
        let now = now_ms();
        let teams: Vec<(String, Arc<Mutex<Team>>)> = self
            .teams
            .lock()
            .await
            .iter()
            .filter_map(|(id, cell)| Some((id.clone(), cell.get()?.clone())))
            .collect();
        let mut overdue = Vec::new();
        for (id, team) in teams {
            let Ok(mut guard) = team.try_lock() else {
                let skipped = self.note_skipped(&id);
                if skipped >= MAX_SKIPPED_TICKS {
                    overdue.push((id, team));
                } else {
                    tracing::debug!(skipped, "busy team skipped by the timer");
                }
                continue;
            };
            self.tick_team(&id, &mut guard, now).await;
        }
        for (id, team) in overdue {
            let mut guard = team.lock().await;
            self.tick_team(&id, &mut guard, now_ms()).await;
        }
        let mut map = self.teams.lock().await;
        map.retain(|_, cell| {
            // Only unload if nobody else is holding the team right now. An empty cell nobody
            // holds is the rest of a cancelled load.
            Arc::strong_count(cell) > 1
                || cell.get().is_some_and(|team| {
                    Arc::strong_count(team) > 1
                        || team.try_lock().map(|t| !t.idle(now)).unwrap_or(true)
                })
        });
        if let Ok(mut skipped) = self.skipped_ticks.lock() {
            skipped.retain(|id, _| map.contains_key(id));
        }
    }

    async fn tick_team(&self, id: &str, team: &mut Team, now: u64) {
        if let Ok(mut skipped) = self.skipped_ticks.lock() {
            skipped.remove(id);
        }
        if let Err(error) = team.tick(&self.db, now).await {
            tracing::error!(%error, "team timer failed");
        }
        self.forward_attention(team);
    }

    /// Counts a skipped tick of the team; returns the skips in a row.
    fn note_skipped(&self, id: &str) -> u32 {
        let Ok(mut skipped) = self.skipped_ticks.lock() else {
            return MAX_SKIPPED_TICKS;
        };
        let count = skipped.entry(id.to_owned()).or_insert(0);
        *count += 1;
        *count
    }

    /// Waits until every live connection has ended (after the shutdown signal they close with
    /// 1012 and leave their teams), at most `limit`. `false`: some were still open.
    pub async fn wait_for_connections(&self, limit: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + limit;
        while self.connection_count() > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        true
    }

    pub async fn housekeeping(&self) {
        let cutoff = now_ms().saturating_sub(self.transcript_retention_ms);
        if let Err(error) = store::purge(&self.db, now_s(), cutoff).await {
            tracing::error!(%error, "housekeeping failed");
        }
    }

    /// Starts the timer (10 s) and the hourly housekeeping; ends with `shutdown`.
    pub fn spawn_timers(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let relay = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            let mut hourly = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tokio::select! {
                    _ = tick.tick() => relay.tick().await,
                    _ = hourly.tick() => relay.housekeeping().await,
                    _ = shutdown.changed() => break,
                }
            }
        });
    }
}

/// Skipped ticks in a row after which the timer waits for a team's lock.
const MAX_SKIPPED_TICKS: u32 = 3;

/// A connection that has not sent a valid `hello` yet.
struct Waiting {
    id: u64,
    address: String,
    /// Closes the connection when newer ones push it out of the quota.
    close: Arc<Notify>,
}

/// A team's entry in the map: empty while it loads.
type TeamCell = OnceCell<Arc<Mutex<Team>>>;

fn acquire(map: &std::sync::Mutex<HashMap<String, usize>>, key: &str, max: usize) -> bool {
    let Ok(mut map) = map.lock() else {
        return false;
    };
    let count = map.entry(key.to_owned()).or_insert(0);
    if *count >= max {
        return false;
    }
    *count += 1;
    true
}

fn release(map: &std::sync::Mutex<HashMap<String, usize>>, key: &str) {
    if let Ok(mut map) = map.lock() {
        if let Some(count) = map.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(key);
            }
        }
    }
}
