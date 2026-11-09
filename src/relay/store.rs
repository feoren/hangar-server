//! Dauerhafter Zustand des Relays. Jede Funktion ist eine Abfrage oder eine Transaktion;
//! Fachregeln liegen in `team.rs` und im Protokoll-Crate, hier nur Speicherung und die
//! Prüfungen, die atomar mit dem Schreiben passieren müssen (Ketten, Kontingente, Epochenfolge).

use sqlx::Row;

use crate::db::Tx;
use crate::db::{begin_write, i64_of, u64_of, Db};
use crate::ticket::Role;
use crate::util::random_id;
use crate::wire::{
    check_append, ChainHead, Ciphertext, DeviceId, DeviceInfo, DeviceKeys, Epoch, Holder, KeyProof,
    LogHash, MemberId, MemberLogAppend, MemberLogEntry, PublicKey, UnixMillis, WrappedKey,
};

pub type Result<T> = std::result::Result<T, sqlx::Error>;

/// Gespeicherter Zustand eines Teams (`relay_team_state`), roh als JSON-Texte.
#[derive(Debug, Clone)]
pub struct StoredState {
    pub book: String,
    pub position: String,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct TeamRow {
    /// Kennung für einen neuen Stream, falls kein gespeicherter Zustand weiterläuft.
    pub fresh_stream: String,
    pub epoch: u32,
    pub state: Option<StoredState>,
}

/// Lädt oder legt das Team an, samt gespeichertem Zustand (Buch, Log-Position, Notizen).
pub async fn load_team(db: &Db, team: &str, now: u64) -> Result<TeamRow> {
    let stream = random_id();
    sqlx::query(
        "INSERT INTO relay_teams (id, stream, created_at) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING",
    )
    .bind(team)
    .bind(&stream)
    .bind(i64_of(now))
    .execute(db)
    .await?;
    let epoch: i64 = sqlx::query_scalar("SELECT epoch FROM relay_teams WHERE id = ?")
        .bind(team)
        .fetch_one(db)
        .await?;
    let state: Option<(String, String, String)> =
        sqlx::query_as("SELECT book, position, notes FROM relay_team_state WHERE team_id = ?")
            .bind(team)
            .fetch_optional(db)
            .await?;
    Ok(TeamRow {
        fresh_stream: stream,
        epoch: u32::try_from(epoch).unwrap_or(0),
        state: state.map(|(book, position, notes)| StoredState {
            book,
            position,
            notes,
        }),
    })
}

/// Schreibt Buch, Log-Position und Notizen in einem Schritt. Erst danach darf ein Rahmen mit
/// einer `seq` bis zu dieser Position das Relay verlassen (Haltbarkeitsregel).
pub async fn save_state(
    db: &Db,
    team: &str,
    book: &str,
    position: &str,
    notes: &str,
    now: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_team_state (team_id, book, position, notes, updated_at) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (team_id) DO UPDATE SET book = excluded.book, position = excluded.position, \
         notes = excluded.notes, updated_at = excluded.updated_at",
    )
    .bind(team)
    .bind(book)
    .bind(position)
    .bind(notes)
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}

/// Neueste unzugestellte `notify` eines Mitglieds merken (ersetzt eine ältere).
pub async fn set_pending_notify(
    db: &Db,
    team: &str,
    member: &str,
    notify: &str,
    now: u64,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_pending_notify (team_id, member, notify, created_at) VALUES (?, ?, ?, ?) \
         ON CONFLICT (team_id, member) DO UPDATE SET notify = excluded.notify, created_at = excluded.created_at",
    )
    .bind(team)
    .bind(member)
    .bind(notify)
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}

pub async fn pending_notifies(db: &Db, team: &str) -> Result<Vec<(String, String)>> {
    sqlx::query_as("SELECT member, notify FROM relay_pending_notify WHERE team_id = ?")
        .bind(team)
        .fetch_all(db)
        .await
}

pub async fn clear_pending_notify(db: &Db, team: &str, member: &str) -> Result<()> {
    sqlx::query("DELETE FROM relay_pending_notify WHERE team_id = ? AND member = ?")
        .bind(team)
        .bind(member)
        .execute(db)
        .await?;
    Ok(())
}

/// Geräte, die ein Log-Eintrag aus dem Team genommen hat (`device.remove`, Mitglied entfernt):
/// sperren und ihre Schlüsselpakete und -angaben im Team vergessen. Läuft in der Transaktion,
/// die auch den Eintrag schreibt.
async fn drop_devices(
    tx: &mut Tx,
    team: &str,
    removed: &[Holder],
    by: &Holder,
    now: u64,
) -> Result<()> {
    for holder in removed {
        sqlx::query(
            "INSERT INTO relay_removed_devices (team_id, member, device, removed_at, by_member) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT DO NOTHING",
        )
        .bind(team)
        .bind(holder.member.as_str())
        .bind(holder.device.as_str())
        .bind(i64_of(now))
        .bind(by.member.as_str())
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "DELETE FROM relay_key_packages WHERE team_id = ? AND member = ? AND device = ?",
        )
        .bind(team)
        .bind(holder.member.as_str())
        .bind(holder.device.as_str())
        .execute(&mut **tx)
        .await?;
        sqlx::query(
            "DELETE FROM relay_device_keys WHERE team_id = ? AND member = ? AND device = ?",
        )
        .bind(team)
        .bind(holder.member.as_str())
        .bind(holder.device.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Wurde dieses Gerät aus dem Team entfernt?
pub async fn device_removed(db: &Db, team: &str, member: &str, device: &str) -> Result<bool> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM relay_removed_devices WHERE team_id = ? AND member = ? AND device = ?",
    )
    .bind(team)
    .bind(member)
    .bind(device)
    .fetch_optional(db)
    .await?;
    Ok(found.is_some())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberSeen {
    New,
    RoleChanged,
    Same,
    /// Entfernt (Selbstbetrieb oder Widerrufsliste der Webseite); ein vor der Entfernung
    /// ausgestelltes Ticket öffnet das Team nicht mehr.
    Removed,
    /// Das Ticket ist nicht jünger als die letzte Entfernung oder Rollenänderung
    /// (`relay_ticket_floors`); es trägt womöglich eine entzogene Rolle. Die App holt ein neues.
    Stale,
}

/// Wie alt ist ein Ticket gemessen an Entfernung und Rollenänderung (`ticket.renew`)?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketAge {
    Current,
    /// Ausgestellt bis zur (noch geltenden) Entfernung.
    BeforeRemoval,
    /// Ausgestellt bis zu einer Rollenänderung oder einer früheren Entfernung.
    Stale,
}

/// Untergrenze für Tickets anheben (nur vorwärts): Tickets mit `iat` bis `at_ms` gelten für
/// dieses Mitglied in diesem Team nicht mehr. Das Team muss angelegt sein.
pub async fn raise_ticket_floor(db: &Db, team: &str, member: &str, at_ms: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_ticket_floors (team_id, member, floor_ms) VALUES (?, ?, ?) \
         ON CONFLICT (team_id, member) DO UPDATE SET floor_ms = MAX(floor_ms, excluded.floor_ms)",
    )
    .bind(team)
    .bind(member)
    .bind(i64_of(at_ms))
    .execute(db)
    .await?;
    Ok(())
}

/// Prüft ein Ticket gegen Entfernung und Untergrenze (für `ticket.renew`).
pub async fn ticket_age(
    db: &Db,
    team: &str,
    member: &str,
    ticket_iat_ms: u64,
) -> Result<TicketAge> {
    let removed: Option<Option<i64>> =
        sqlx::query_scalar("SELECT removed_at FROM relay_members WHERE team_id = ? AND member = ?")
            .bind(team)
            .bind(member)
            .fetch_optional(db)
            .await?;
    if removed
        .flatten()
        .is_some_and(|at| ticket_iat_ms <= u64_of(at))
    {
        return Ok(TicketAge::BeforeRemoval);
    }
    let floor: Option<i64> = sqlx::query_scalar(
        "SELECT floor_ms FROM relay_ticket_floors WHERE team_id = ? AND member = ?",
    )
    .bind(team)
    .bind(member)
    .fetch_optional(db)
    .await?;
    Ok(if floor.is_some_and(|at| ticket_iat_ms <= u64_of(at)) {
        TicketAge::Stale
    } else {
        TicketAge::Current
    })
}

/// Ein Mitglied meldet sich mit einem geprüften Ticket an (`ticket_iat_ms`: Ausstellung des
/// Tickets). Ein entferntes Mitglied kommt nur mit einem Ticket wieder herein, das nach der
/// Entfernung ausgestellt wurde: dann hat die Webseite es wieder zugelassen.
pub async fn see_member(
    db: &Db,
    team: &str,
    member: &str,
    role: Role,
    ticket_iat_ms: u64,
    now: u64,
) -> Result<MemberSeen> {
    let mut tx = begin_write(db).await?;
    let current: Option<(String, Option<i64>)> = sqlx::query_as(
        "SELECT role, removed_at FROM relay_members WHERE team_id = ? AND member = ?",
    )
    .bind(team)
    .bind(member)
    .fetch_optional(&mut *tx)
    .await?;
    let floor: Option<i64> = sqlx::query_scalar(
        "SELECT floor_ms FROM relay_ticket_floors WHERE team_id = ? AND member = ?",
    )
    .bind(team)
    .bind(member)
    .fetch_optional(&mut *tx)
    .await?;
    let seen = match current {
        Some((_, Some(removed))) if ticket_iat_ms <= u64_of(removed) => MemberSeen::Removed,
        // Ticket von vor einer Rollenänderung oder früheren Entfernung: alte Rolle möglich.
        _ if floor.is_some_and(|at| ticket_iat_ms <= u64_of(at)) => MemberSeen::Stale,
        Some((_, Some(_))) | None => MemberSeen::New,
        Some((old, None)) if old == role.as_str() => MemberSeen::Same,
        Some(_) => MemberSeen::RoleChanged,
    };
    if !matches!(seen, MemberSeen::Removed | MemberSeen::Stale) {
        sqlx::query(
            "INSERT INTO relay_members (team_id, member, role, first_seen, last_seen) VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT (team_id, member) DO UPDATE SET role = excluded.role, last_seen = excluded.last_seen, removed_at = NULL",
        )
        .bind(team)
        .bind(member)
        .bind(role.as_str())
        .bind(i64_of(now))
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(seen)
}

/// Mitglied entfernen (Selbstbetrieb) oder wieder zulassen (erneuter Beitritt).
pub async fn set_member_removed(
    db: &Db,
    team: &str,
    member: &str,
    removed_at: Option<u64>,
) -> Result<()> {
    sqlx::query("UPDATE relay_members SET removed_at = ? WHERE team_id = ? AND member = ?")
        .bind(removed_at.map(i64_of))
        .bind(team)
        .bind(member)
        .execute(db)
        .await?;
    Ok(())
}

/// Mitglied als entfernt vermerken, auch wenn es sich nie verbunden hat: so kommt es mit
/// einem vor der Entfernung ausgestellten Ticket nicht mehr herein.
pub async fn mark_member_removed(db: &Db, team: &str, member: &str, now: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_members (team_id, member, role, first_seen, last_seen, removed_at) \
         VALUES (?, ?, 'member', ?, ?, ?) \
         ON CONFLICT (team_id, member) DO UPDATE SET removed_at = excluded.removed_at",
    )
    .bind(team)
    .bind(member)
    .bind(i64_of(now))
    .bind(i64_of(now))
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}

/// Neue Rolle eines Mitglieds (aus `ticket.renew`, Widerrufsliste oder Selbstbetrieb).
pub async fn set_member_role(
    db: &Db,
    team: &str,
    member: &str,
    role: Role,
    now: u64,
) -> Result<()> {
    sqlx::query(
        "UPDATE relay_members SET role = ?, last_seen = ? WHERE team_id = ? AND member = ?",
    )
    .bind(role.as_str())
    .bind(i64_of(now))
    .bind(team)
    .bind(member)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn members(db: &Db, team: &str) -> Result<Vec<(String, Role)>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT member, role FROM relay_members WHERE team_id = ? AND removed_at IS NULL",
    )
    .bind(team)
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(m, r)| Role::parse(&r).map(|r| (m, r)))
        .collect())
}

/// Vermerkt ein Gerät eines Mitglieds. Geräte-IDs sind nur je Mitglied eindeutig; das Gerät
/// ist damit an das Subjekt des Tickets gebunden, ein anderes Mitglied kann es nicht nennen.
pub async fn bind_device(db: &Db, device: &str, member: &str, now: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_devices (member, device, created_at, last_seen) VALUES (?, ?, ?, ?) \
         ON CONFLICT (member, device) DO UPDATE SET last_seen = excluded.last_seen",
    )
    .bind(member)
    .bind(device)
    .bind(i64_of(now))
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}

/// Ergebnis von `device.keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysStored {
    Stored,
    /// Mehr als `limits::MAX_DEVICES_PER_MEMBER` Geräte des Mitglieds oder `MAX_WRAPPED_KEYS`
    /// im Team.
    TooManyDevices,
}

/// `device.keys` eines Geräts im Team (Schlüssel und Besitznachweis, je Team). Neue Geräte nur
/// innerhalb der Grenzen je Mitglied und je Team.
pub async fn set_device_keys(
    db: &Db,
    team: &str,
    holder: &Holder,
    keys: &DeviceKeys,
    max_per_member: usize,
    max_per_team: usize,
    now: u64,
) -> Result<KeysStored> {
    let mut tx = begin_write(db).await?;
    let known: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM relay_device_keys WHERE team_id = ? AND member = ? AND device = ?",
    )
    .bind(team)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .fetch_optional(&mut *tx)
    .await?;
    if known.is_none() {
        let (of_member, of_team): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(member = ?), 0), COUNT(*) FROM relay_device_keys WHERE team_id = ?",
        )
        .bind(holder.member.as_str())
        .bind(team)
        .fetch_one(&mut *tx)
        .await?;
        if u64_of(of_member) >= max_per_member as u64 || u64_of(of_team) >= max_per_team as u64 {
            return Ok(KeysStored::TooManyDevices);
        }
    }
    sqlx::query(
        "INSERT INTO relay_device_keys (team_id, member, device, sign_key, kem_key, proof, keys_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (team_id, member, device) DO UPDATE SET sign_key = excluded.sign_key, \
         kem_key = excluded.kem_key, proof = excluded.proof, keys_at = excluded.keys_at",
    )
    .bind(team)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .bind(keys.sign.to_base64url())
    .bind(keys.kem.to_base64url())
    .bind(keys.proof.to_base64url())
    .bind(i64_of(now))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(KeysStored::Stored)
}

/// Die über die eigene Verbindung gesendeten Schlüssel eines Holders im Team
/// (`relay::check_registered_keys`).
pub async fn registered_keys(
    db: &Db,
    team: &str,
    holder: &Holder,
) -> Result<Option<(PublicKey, PublicKey)>> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT sign_key, kem_key FROM relay_device_keys WHERE team_id = ? AND member = ? AND device = ?",
    )
    .bind(team)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(sign, kem)| {
        Some((
            PublicKey::try_from(sign).ok()?,
            PublicKey::try_from(kem).ok()?,
        ))
    }))
}

/// Geräte aktueller Mitglieder mit Schlüsseln und Nachweis, ohne entfernte, höchstens `limit`.
pub async fn team_devices(db: &Db, team: &str, limit: usize) -> Result<Vec<DeviceInfo>> {
    let rows = sqlx::query(
        "SELECT k.member, k.device, k.sign_key, k.kem_key, k.proof, k.keys_at FROM relay_device_keys k \
         JOIN relay_members m ON m.team_id = k.team_id AND m.member = k.member \
         WHERE k.team_id = ? AND m.removed_at IS NULL \
         AND NOT EXISTS (SELECT 1 FROM relay_removed_devices r \
             WHERE r.team_id = k.team_id AND r.member = k.member AND r.device = k.device) \
         ORDER BY k.member, k.device LIMIT ?",
    )
    .bind(team)
    .bind(i64_of(limit as u64))
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(DeviceInfo {
                holder: Holder {
                    member: MemberId::new(r.get::<String, _>("member")).ok()?,
                    device: DeviceId::new(r.get::<String, _>("device")).ok()?,
                },
                sign: PublicKey::try_from(r.get::<String, _>("sign_key")).ok()?,
                kem: PublicKey::try_from(r.get::<String, _>("kem_key")).ok()?,
                proof: KeyProof::try_from(r.get::<String, _>("proof")).ok()?,
                at: UnixMillis(u64_of(r.get::<i64, _>("keys_at"))),
            })
        })
        .collect())
}

/// Verbraucht eine Ticket-ID. `false`: schon verwendet.
pub async fn use_jti(db: &Db, jti: &str, exp_s: i64) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO relay_used_tickets (jti, exp) VALUES (?, ?) ON CONFLICT (jti) DO NOTHING",
    )
    .bind(jti)
    .bind(exp_s)
    .execute(db)
    .await?;
    Ok(done.rows_affected() == 1)
}

pub async fn purge(db: &Db, now_s: i64, transcript_cutoff_ms: u64) -> Result<()> {
    sqlx::query("DELETE FROM relay_used_tickets WHERE exp < ?")
        .bind(now_s - 2 * crate::ticket::CLOCK_SKEW_S)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM relay_revocations_seen WHERE seen_at < ?")
        .bind(now_s.saturating_sub(30 * 86_400).saturating_mul(1000))
        .execute(db)
        .await?;
    let mut tx = begin_write(db).await?;
    sqlx::query(
        "UPDATE relay_teams SET blob_bytes = blob_bytes - COALESCE((SELECT SUM(size) FROM relay_blobs b \
         WHERE b.team_id = relay_teams.id AND b.kind = 'transcript' AND b.created_at < ?), 0)",
    )
    .bind(i64_of(transcript_cutoff_ms))
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM relay_blobs WHERE kind = 'transcript' AND created_at < ?")
        .bind(i64_of(transcript_cutoff_ms))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum BlobPut {
    Stored(String),
    Quota,
}

#[allow(clippy::too_many_arguments)]
pub async fn put_blob(
    db: &Db,
    team: &str,
    kind: &str,
    epoch: Epoch,
    data: &Ciphertext,
    holder: &Holder,
    quota: u64,
    now: u64,
) -> Result<BlobPut> {
    let size = i64_of(data.as_str().len() as u64);
    let mut tx = begin_write(db).await?;
    let used: i64 = sqlx::query_scalar("SELECT blob_bytes FROM relay_teams WHERE id = ?")
        .bind(team)
        .fetch_one(&mut *tx)
        .await?;
    if used.saturating_add(size) > i64_of(quota) {
        return Ok(BlobPut::Quota);
    }
    let id = random_id();
    sqlx::query(
        "INSERT INTO relay_blobs (id, team_id, kind, epoch, data, size, member, device, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(team)
    .bind(kind)
    .bind(i64::from(epoch.0))
    .bind(data.as_str())
    .bind(size)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .bind(i64_of(now))
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE relay_teams SET blob_bytes = blob_bytes + ? WHERE id = ?")
        .bind(size)
        .bind(team)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(BlobPut::Stored(id))
}

pub async fn get_blob(db: &Db, team: &str, id: &str) -> Result<Option<(Epoch, Ciphertext)>> {
    let row: Option<(i64, String)> =
        sqlx::query_as("SELECT epoch, data FROM relay_blobs WHERE team_id = ? AND id = ?")
            .bind(team)
            .bind(id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(epoch, data)| {
        Some((
            Epoch(u32::try_from(epoch).ok()?),
            Ciphertext::new(data).ok()?,
        ))
    }))
}

/// Schreibt einen Eintrag, den `LogVerifier` schon zugelassen hat. Prüft die Kette gegen die
/// gespeicherte als zweite Linie (`check_append`); `false` heißt, gespeichert ist etwas anderes
/// (dann bleibt alles, wie es war).
async fn insert_entry(
    tx: &mut Tx,
    team: &str,
    append: &MemberLogAppend,
    hash: &LogHash,
    by: &Holder,
    now: u64,
) -> Result<bool> {
    let last: Option<(i64, String)> = sqlx::query_as(
        "SELECT idx, hash FROM relay_member_log WHERE team_id = ? ORDER BY idx DESC LIMIT 1",
    )
    .bind(team)
    .fetch_optional(&mut **tx)
    .await?;
    let head = match last {
        Some((idx, stored)) => match LogHash::try_from(stored) {
            Ok(hash) => Some(ChainHead {
                index: u64_of(idx),
                hash,
            }),
            Err(_) => return Ok(false),
        },
        None => None,
    };
    match check_append(head.as_ref(), append) {
        Ok(next) if next.hash == *hash => {}
        _ => return Ok(false),
    }
    sqlx::query(
        "INSERT INTO relay_member_log (team_id, idx, hash, entry, member, device, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(team)
    .bind(i64_of(append.index))
    .bind(hash.to_hex())
    .bind(append.entry.as_str())
    .bind(by.member.as_str())
    .bind(by.device.as_str())
    .bind(i64_of(now))
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

/// `memberlog.append` oder `device.remove`: Eintrag schreiben und die Geräte, die er aus dem Team
/// nimmt, im selben Schritt sperren und vergessen. `false`: nichts geschrieben.
pub async fn log_append(
    db: &Db,
    team: &str,
    append: &MemberLogAppend,
    hash: &LogHash,
    removed: &[Holder],
    by: &Holder,
    now: u64,
) -> Result<bool> {
    let mut tx = begin_write(db).await?;
    if !insert_entry(&mut tx, team, append, hash, by, now).await? {
        return Ok(false);
    }
    drop_devices(&mut tx, team, removed, by, now).await?;
    tx.commit().await?;
    Ok(true)
}

/// Alle gespeicherten Einträge in Reihenfolge (zum Neuaufbau des `LogVerifier`).
pub async fn log_all(db: &Db, team: &str) -> Result<Vec<MemberLogEntry>> {
    log_get(db, team, 0, usize::MAX >> 1).await
}

/// Einträge nach `after`, höchstens `limit`; der Aufrufer fragt eins mehr ab, damit
/// `MemberLogEntries::page` weiß, ob es weitere gibt.
pub async fn log_get(db: &Db, team: &str, after: u64, limit: usize) -> Result<Vec<MemberLogEntry>> {
    let rows = sqlx::query(
        "SELECT idx, hash, entry, member, device, created_at FROM relay_member_log \
         WHERE team_id = ? AND idx > ? ORDER BY idx LIMIT ?",
    )
    .bind(team)
    .bind(i64_of(after))
    .bind(i64_of(limit as u64))
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(MemberLogEntry {
                index: u64_of(r.get("idx")),
                hash: LogHash::try_from(r.get::<String, _>("hash")).ok()?,
                entry: Ciphertext::new(r.get::<String, _>("entry")).ok()?,
                by: Holder {
                    member: MemberId::new(r.get::<String, _>("member")).ok()?,
                    device: DeviceId::new(r.get::<String, _>("device")).ok()?,
                },
                at: UnixMillis(u64_of(r.get("created_at"))),
            })
        })
        .collect())
}

#[derive(Debug, PartialEq, Eq)]
pub enum EpochChange {
    Done,
    /// Nicht genau aktuelle + 1, oder der Eintrag passt nicht an die gespeicherte Kette.
    WrongEpoch,
    /// `key.wrap`: dieser Absender hat schon ein Paket für das Ziel in dieser Epoche.
    AlreadyWrapped,
}

async fn insert_package(
    tx: &mut Tx,
    team: &str,
    epoch: Epoch,
    wrapped: &WrappedKey,
    by: &Holder,
    now: u64,
) -> Result<bool> {
    let seq: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM relay_key_packages WHERE team_id = ?",
    )
    .bind(team)
    .fetch_one(&mut **tx)
    .await?;
    let done = sqlx::query(
        "INSERT INTO relay_key_packages (team_id, epoch, member, device, by_member, by_device, data, created_at, seq) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(team)
    .bind(i64::from(epoch.0))
    .bind(wrapped.holder.member.as_str())
    .bind(wrapped.holder.device.as_str())
    .bind(by.member.as_str())
    .bind(by.device.as_str())
    .bind(wrapped.data.as_str())
    .bind(i64_of(now))
    .bind(seq)
    .execute(&mut **tx)
    .await?;
    Ok(done.rows_affected() == 1)
}

/// `key.rotate`: Eintrag der Rotation, neue Epoche und alle Pakete in einer Transaktion oder
/// nichts davon.
#[allow(clippy::too_many_arguments)]
pub async fn rotate_epoch(
    db: &Db,
    team: &str,
    epoch: Epoch,
    log: &MemberLogAppend,
    hash: &LogHash,
    wrapped: &[WrappedKey],
    by: &Holder,
    now: u64,
) -> Result<EpochChange> {
    let mut tx = begin_write(db).await?;
    let current: i64 = sqlx::query_scalar("SELECT epoch FROM relay_teams WHERE id = ?")
        .bind(team)
        .fetch_one(&mut *tx)
        .await?;
    if i64::from(epoch.0) != current + 1 || !insert_entry(&mut tx, team, log, hash, by, now).await?
    {
        return Ok(EpochChange::WrongEpoch);
    }
    sqlx::query("INSERT INTO relay_epochs (team_id, epoch, member, device, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(team)
        .bind(i64::from(epoch.0))
        .bind(by.member.as_str())
        .bind(by.device.as_str())
        .bind(i64_of(now))
        .execute(&mut *tx)
        .await?;
    for w in wrapped {
        insert_package(&mut tx, team, epoch, w, by, now).await?;
    }
    sqlx::query("UPDATE relay_teams SET epoch = ? WHERE id = ?")
        .bind(i64::from(epoch.0))
        .bind(team)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(EpochChange::Done)
}

/// Absender der gespeicherten Pakete eines Ziels in einer Epoche, in Reihenfolge des Eintreffens
/// (`stored_from` für `relay::check_wrap`).
pub async fn package_senders(
    db: &Db,
    team: &str,
    epoch: Epoch,
    target: &Holder,
) -> Result<Vec<Holder>> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT by_member, by_device FROM relay_key_packages \
         WHERE team_id = ? AND epoch = ? AND member = ? AND device = ? ORDER BY seq",
    )
    .bind(team)
    .bind(i64::from(epoch.0))
    .bind(target.member.as_str())
    .bind(target.device.as_str())
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(m, d)| {
            Some(Holder {
                member: MemberId::new(m).ok()?,
                device: DeviceId::new(d).ok()?,
            })
        })
        .collect())
}

/// `key.wrap`: ein weiteres Paket für das Ziel in der aktuellen Epoche; nie ersetzt.
pub async fn wrap_key(
    db: &Db,
    team: &str,
    epoch: Epoch,
    wrapped: &WrappedKey,
    by: &Holder,
    now: u64,
) -> Result<EpochChange> {
    let mut tx = begin_write(db).await?;
    let current: i64 = sqlx::query_scalar("SELECT epoch FROM relay_teams WHERE id = ?")
        .bind(team)
        .fetch_one(&mut *tx)
        .await?;
    if i64::from(epoch.0) != current || current == 0 {
        return Ok(EpochChange::WrongEpoch);
    }
    if !insert_package(&mut tx, team, epoch, wrapped, by, now).await? {
        return Ok(EpochChange::AlreadyWrapped);
    }
    tx.commit().await?;
    Ok(EpochChange::Done)
}

/// Alle Pakete eines Holders in einer Epoche, in Reihenfolge des Eintreffens (`key.get`).
pub async fn key_packages(
    db: &Db,
    team: &str,
    epoch: Epoch,
    holder: &Holder,
) -> Result<Vec<Ciphertext>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT data FROM relay_key_packages WHERE team_id = ? AND epoch = ? AND member = ? AND device = ? ORDER BY seq",
    )
    .bind(team)
    .bind(i64::from(epoch.0))
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|d| Ciphertext::new(d).ok())
        .collect())
}

/// Das erste Paket eines Holders in einer Epoche (das der Rotation), für `key.rotated`.
pub async fn key_package(
    db: &Db,
    team: &str,
    epoch: Epoch,
    holder: &Holder,
) -> Result<Option<Ciphertext>> {
    Ok(key_packages(db, team, epoch, holder)
        .await?
        .into_iter()
        .next())
}

/// Die Rolle, die ein Mitglied im Team zuletzt hatte (für Prüfungen ohne Ticket).
pub async fn member_role(db: &Db, team: &str, member: &str) -> Result<Option<Role>> {
    let role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM relay_members WHERE team_id = ? AND member = ? AND removed_at IS NULL",
    )
    .bind(team)
    .bind(member)
    .fetch_optional(db)
    .await?;
    Ok(role.and_then(|r| Role::parse(&r)))
}

// ---------------------------------------------------------------------------------------------
// Widerrufsliste der Webseite (offizieller Betrieb)

/// Letzter verarbeiteter Cursor (`last`) der Widerrufsliste; `None` vor dem ersten Abruf.
pub async fn revocation_cursor(db: &Db) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT cursor FROM relay_revocation_cursor WHERE id = 1")
        .fetch_optional(db)
        .await
}

pub async fn set_revocation_cursor(db: &Db, cursor: &str, now: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_revocation_cursor (id, cursor, updated_at) VALUES (1, ?, ?) \
         ON CONFLICT (id) DO UPDATE SET cursor = excluded.cursor, updated_at = excluded.updated_at",
    )
    .bind(cursor)
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}

/// Schon verarbeitete Widerrufs-ID?
pub async fn revocation_seen(db: &Db, rid: &str) -> Result<bool> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM relay_revocations_seen WHERE rid = ?")
            .bind(rid)
            .fetch_optional(db)
            .await?;
    Ok(found.is_some())
}

/// Widerrufs-ID als verarbeitet merken (nach dem Anwenden; die Wirkungen sind wiederholbar).
pub async fn mark_revocation(db: &Db, rid: &str, now: u64) -> Result<()> {
    sqlx::query(
        "INSERT INTO relay_revocations_seen (rid, seen_at) VALUES (?, ?) ON CONFLICT (rid) DO NOTHING",
    )
    .bind(rid)
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(())
}
