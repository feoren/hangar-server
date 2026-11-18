//! Relay core: verifies tickets, holds the live state per team and distributes encrypted
//! events. Knows nothing about accounts, seats or licenses; the website or the self-hosting
//! identity decides those before issuing a ticket.

pub mod conn;
pub mod outbox;
pub mod revocation;
pub mod store;
pub mod team;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch, Mutex};

use crate::config::Config;
use crate::db::Db;
use crate::signed::KeySet;
use crate::ticket::{self, Role, TicketClaims};
use crate::util::{now_ms, now_s};
use crate::wire::{ErrorCode, MemberId, ProtoRange};
use hangar_team_protocol::reservation::Policy;

use team::{Attention, HandleLimits, Team};

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
    max_connections: usize,
    max_per_member: usize,
    max_per_ip: usize,
    pub connection_max_age: Duration,
    pub hello_timeout: Duration,
    /// Grace period of a removed device for its `memberlog.get` (see `conn`).
    pub removed_grace: Duration,
    transcript_retention_ms: u64,
    teams: Mutex<HashMap<String, Arc<Mutex<Team>>>>,
    connections: AtomicUsize,
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
            },
            max_connections: config.max_connections,
            max_per_member: config.max_connections_per_member,
            max_per_ip: config.max_connections_per_ip,
            connection_max_age: Duration::from_secs(config.connection_max_age_s.max(60)),
            hello_timeout: Duration::from_millis(config.hello_timeout_ms.max(100)),
            removed_grace: Duration::from_millis(config.removed_grace_ms.clamp(100, 30_000)),
            transcript_retention_ms: config.transcript_retention_days.saturating_mul(86_400_000),
            teams: Mutex::new(HashMap::new()),
            connections: AtomicUsize::new(0),
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

    /// Checks `hello`: ticket, team, seat, protocol, single-use `jti`, device binding.
    pub async fn check_hello(
        &self,
        ticket_text: &str,
        team: &str,
        device: &str,
        proto: ProtoRange,
    ) -> Result<(TicketClaims, u16), ErrorCode> {
        let Some(version) = proto.negotiate(SERVER_PROTO) else {
            return Err(if proto.max() < SERVER_PROTO.min() {
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

    /// The team in memory, loaded from the database if needed.
    pub async fn team(&self, id: &str) -> Result<Arc<Mutex<Team>>, sqlx::Error> {
        let mut teams = self.teams.lock().await;
        if let Some(team) = teams.get(id) {
            return Ok(team.clone());
        }
        let team = Arc::new(Mutex::new(
            Team::load(&self.db, id, self.policy, now_ms()).await?,
        ));
        teams.insert(id.to_owned(), team.clone());
        Ok(team)
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
        team.lock().await.renew_member(member);
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
        let team = self.teams.lock().await.get(team_id).cloned();
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
        let team = self.teams.lock().await.remove(team_id);
        if let Some(team) = team {
            team.lock().await.close_all();
        }
        sqlx::query("DELETE FROM relay_teams WHERE id = ?")
            .bind(team_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Timer: expiries and warnings, unloading unused teams.
    pub async fn tick(&self) {
        let now = now_ms();
        let teams: Vec<Arc<Mutex<Team>>> = self.teams.lock().await.values().cloned().collect();
        for team in teams {
            let mut team = team.lock().await;
            if let Err(error) = team.tick(&self.db, now).await {
                tracing::error!(%error, "team timer failed");
            }
            self.forward_attention(&mut team);
        }
        let mut map = self.teams.lock().await;
        map.retain(|_, team| {
            // Only unload if nobody else is holding the team right now.
            Arc::strong_count(team) > 1 || team.try_lock().map(|t| !t.idle(now)).unwrap_or(true)
        });
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
