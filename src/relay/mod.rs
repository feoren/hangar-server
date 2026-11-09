//! Relay-Kern: prüft Tickets, hält den Live-Zustand je Team und verteilt verschlüsselte
//! Ereignisse. Kennt keine Konten, Plätze oder Lizenzen; die entscheiden Webseite bzw.
//! Selbstbetrieb-Identität, bevor sie ein Ticket ausstellen.

pub mod conn;
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

/// Was das Relay vom Server wissen muss.
/// Warum ein `ticket.renew` nicht angenommen wurde.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewRefused {
    /// `prj` ist nicht das Team des Rahmens: `err forbidden`, dann Close 4403.
    OtherTeam,
    /// Ungültig, anderes Mitglied, kein Platz oder schon verwendet: Close 4403.
    Removed,
    /// Speicherfehler: `err badRequest`, die Verbindung bleibt.
    Failed,
    /// Ausgestellt bis zu einer Rollenänderung (oder früheren Entfernung): trägt womöglich die
    /// alte Rolle. Close 4401, die App kommt mit einem neuen Ticket.
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
                tracing::warn!(%error, "Reservierungsfristen ungültig, Vorgabe gilt");
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
            transcript_retention_ms: config.transcript_retention_days.saturating_mul(86_400_000),
            teams: Mutex::new(HashMap::new()),
            connections: AtomicUsize::new(0),
            per_member: std::sync::Mutex::new(HashMap::new()),
            per_ip: std::sync::Mutex::new(HashMap::new()),
            next_conn: AtomicU64::new(1),
            attention,
        }
    }

    /// Schlüssel der Ticket-Aussteller (für die Widerrufsliste, die dieselben nutzt).
    pub fn ticket_keys(&self) -> &KeySet {
        &self.keys
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn next_conn(&self) -> u64 {
        self.next_conn.fetch_add(1, Ordering::Relaxed)
    }

    /// Nimmt einen Verbindungsplatz; `false` bei voller Auslastung.
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

    /// Verbindungen je Client-Adresse (IPv6 je /64, siehe `ClientIp::key`).
    pub fn acquire_ip(&self, key: &str) -> bool {
        acquire(&self.per_ip, key, self.max_per_ip)
    }

    pub fn release_ip(&self, key: &str) {
        release(&self.per_ip, key);
    }

    /// Prüft `hello`: Ticket, Team, Platz, Protokoll, einmalige `jti`, Gerätebindung.
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
                tracing::info!(reason = %error, "Ticket abgelehnt");
                return Err(ErrorCode::Forbidden);
            }
        };
        if MemberId::new(claims.sub.clone()).is_err() {
            tracing::info!("Konto-ID im Ticket passt nicht zum Protokoll");
            return Err(ErrorCode::Forbidden);
        }
        if claims.prj != team {
            tracing::info!("Ticket für ein anderes Team");
            return Err(ErrorCode::Forbidden);
        }
        if !claims.seat_ok {
            return Err(ErrorCode::Limit);
        }
        match store::use_jti(&self.db, &claims.jti, claims.exp).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!("Ticket wurde erneut verwendet");
                return Err(ErrorCode::Forbidden);
            }
            Err(error) => {
                tracing::error!(%error, "jti nicht speicherbar");
                return Err(ErrorCode::BadRequest);
            }
        }
        match store::bind_device(&self.db, device, &claims.sub, now_ms()).await {
            Ok(()) => Ok((claims, version)),
            Err(error) => {
                tracing::error!(%error, "Gerät nicht speicherbar");
                Err(ErrorCode::BadRequest)
            }
        }
    }

    /// Das Team im Speicher, bei Bedarf aus der Datenbank geladen.
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

    /// Hinweise an die Identität weiterreichen (nur Selbstbetrieb hat einen Empfänger).
    pub fn forward_attention(&self, team: &mut Team) {
        let pending = std::mem::take(&mut team.attention);
        if let Some(tx) = &self.attention {
            for item in pending {
                let _ = tx.try_send(item);
            }
        }
    }

    /// Mitglied entfernen (Selbstbetrieb): Ereignis, Reservierungen frei, Verbindungen zu.
    pub async fn remove_member(&self, team_id: &str, member: &str) -> Result<(), sqlx::Error> {
        self.revoke_member(team_id, member, now_ms()).await
    }

    /// Mitglied ab `at_ms` entfernen (Selbstbetrieb oder Widerrufsliste): ein Ticket, das bis
    /// dahin ausgestellt wurde, öffnet das Team nicht mehr; ein späteres lässt es wieder zu.
    pub async fn revoke_member(
        &self,
        team_id: &str,
        member: &str,
        at_ms: u64,
    ) -> Result<(), sqlx::Error> {
        // Erst das Team laden (legt die Zeile an), dann vermerken: auch wer nie verbunden war,
        // kommt mit einem älteren Ticket nicht mehr herein.
        let team = self.team(team_id).await?;
        store::mark_member_removed(&self.db, team_id, member, at_ms).await?;
        // Bleibt auch nach einer Wiederaufnahme: ein gehortetes altes Ticket gilt nie wieder.
        store::raise_ticket_floor(&self.db, team_id, member, at_ms).await?;
        let Ok(member) = MemberId::new(member) else {
            return Ok(());
        };
        let mut team = team.lock().await;
        team.remove_member(&self.db, &member, now_ms()).await
    }

    /// Rolle geändert (ab `at_ms`), neue Rolle unbekannt: Verbindungen des Mitglieds schließen
    /// (4401), es kommt mit einem neuen Ticket zurück. Ältere Tickets gelten nicht mehr.
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

    /// Rolle geändert (ab `at_ms`), neue Rolle bekannt: still auf den laufenden Verbindungen
    /// anwenden. Tickets mit `iat` bis `at_ms` tragen womöglich die alte Rolle; sie öffnen das
    /// Team nicht mehr und erneuern keine Verbindung (sonst holte sich ein herabgestuftes
    /// Mitglied mit einem vorher gehorteten Ticket die alte Rolle per `hello` oder
    /// `ticket.renew` zurück, bis zu `CONNECTION_MAX_AGE_SECS` lang).
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
        // Das Team anlegen (Fremdschlüssel), dann die Untergrenze vor der neuen Rolle setzen.
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

    /// `ticket.renew`: prüft das neue Ticket wie beim `hello` (Signatur, kid, Zeit, `aud`,
    /// einmalige `jti`) und dass es für dieses Team und dieses Mitglied gilt.
    pub async fn check_renew(
        &self,
        ticket_text: &str,
        team: &str,
        member: &str,
    ) -> Result<TicketClaims, RenewRefused> {
        let claims = match ticket::verify(ticket_text, &self.keys, now_s(), Some(&self.audience)) {
            Ok(claims) => claims,
            Err(error) => {
                tracing::info!(reason = %error, "erneuertes Ticket abgelehnt");
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
                tracing::error!(%error, "Ticketalter nicht prüfbar");
                return Err(RenewRefused::Failed);
            }
        }
        match store::use_jti(&self.db, &claims.jti, claims.exp).await {
            Ok(true) => Ok(claims),
            Ok(false) => Err(RenewRefused::Removed),
            Err(error) => {
                tracing::error!(%error, "jti nicht speicherbar");
                Err(RenewRefused::Failed)
            }
        }
    }

    /// Team gelöscht (Selbstbetrieb): Verbindungen schließen, Relay-Daten entfernen.
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

    /// Zeitgeber: Abläufe und Warnungen, Aufräumen ungenutzter Teams.
    pub async fn tick(&self) {
        let now = now_ms();
        let teams: Vec<Arc<Mutex<Team>>> = self.teams.lock().await.values().cloned().collect();
        for team in teams {
            let mut team = team.lock().await;
            if let Err(error) = team.tick(&self.db, now).await {
                tracing::error!(%error, "Zeitgeber eines Teams fehlgeschlagen");
            }
            self.forward_attention(&mut team);
        }
        let mut map = self.teams.lock().await;
        map.retain(|_, team| {
            // Nur entladen, wenn niemand sonst das Team gerade hält.
            Arc::strong_count(team) > 1 || team.try_lock().map(|t| !t.idle(now)).unwrap_or(true)
        });
    }

    pub async fn housekeeping(&self) {
        let cutoff = now_ms().saturating_sub(self.transcript_retention_ms);
        if let Err(error) = store::purge(&self.db, now_s(), cutoff).await {
            tracing::error!(%error, "Aufräumen fehlgeschlagen");
        }
    }

    /// Startet den Zeitgeber (10 s) und das stündliche Aufräumen; endet mit `shutdown`.
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
