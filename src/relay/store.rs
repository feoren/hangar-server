//! Persistent state of the relay. Every function is a query or a transaction; domain rules
//! live in `team.rs` and in the protocol crate, here only storage and the checks that must
//! happen atomically with the write (chains, quotas, epoch order).

use sqlx::Row;

use crate::db::Tx;
use crate::db::{begin_write, i64_of, u64_of, Db};
use crate::ticket::Role;
use crate::util::random_id;
use crate::wire::{
    check_append, ChainHead, Ciphertext, DeviceId, DeviceInfo, DeviceKeys, Epoch, Holder, KeyProof,
    LogHash, MemberId, MemberLogAppend, MemberLogEntry, NotesKeysRecord, PublicKey, Sealed,
    UnixMillis, WrappedKey,
};

pub type Result<T> = std::result::Result<T, sqlx::Error>;

/// Stored state of a team (`relay_team_state`), raw as JSON texts.
#[derive(Debug, Clone)]
pub struct StoredState {
    pub book: String,
    pub position: String,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct TeamRow {
    /// Identifier for a new stream, in case no stored state continues.
    pub fresh_stream: String,
    pub epoch: u32,
    pub state: Option<StoredState>,
}

/// Devices in `relay_devices` not seen for this long are deleted by `purge`.
pub const DEVICE_RETENTION_DAYS: i64 = 90;

/// Loads or creates the team, including stored state (book, log position, notes).
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

/// Writes book, log position and notes in one step. Only afterwards may a frame with a `seq` up
/// to this position leave the relay (durability rule).
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

/// Remembers a member's latest undelivered `notify` (replaces an older one).
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

/// Devices that a log entry took out of the team (`device.remove`, member removed): block them
/// (with the index of the entry, `log_index`) and forget their key packages and key details in
/// the team. Runs in the transaction that also writes the entry.
async fn drop_devices(
    tx: &mut Tx,
    team: &str,
    removed: &[Holder],
    index: u64,
    by: &Holder,
    now: u64,
) -> Result<()> {
    for holder in removed {
        sqlx::query(
            "INSERT INTO relay_removed_devices (team_id, member, device, removed_at, by_member, log_index) \
             VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        )
        .bind(team)
        .bind(holder.member.as_str())
        .bind(holder.device.as_str())
        .bind(i64_of(now))
        .bind(by.member.as_str())
        .bind(i64_of(index))
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
        // A holder admitted again under the same IDs starts without a proof.
        sqlx::query(
            "DELETE FROM relay_device_proofs WHERE team_id = ? AND member = ? AND device = ?",
        )
        .bind(team)
        .bind(holder.member.as_str())
        .bind(holder.device.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Whether the holder once proved possession of its listed signing key on protocol version 3
/// in this team (downgrade protection: its `hello` of an older version is refused).
pub async fn device_proven(db: &Db, team: &str, holder: &Holder) -> Result<bool> {
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM relay_device_proofs WHERE team_id = ? AND member = ? AND device = ?",
    )
    .bind(team)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

/// Records that the holder counts as the log's device with a proven key. `true`: the row is
/// new.
pub async fn record_device_proof(db: &Db, team: &str, holder: &Holder, now: u64) -> Result<bool> {
    let done = sqlx::query(
        "INSERT INTO relay_device_proofs (team_id, member, device, proven_at) VALUES (?, ?, ?, ?)          ON CONFLICT DO NOTHING",
    )
    .bind(team)
    .bind(holder.member.as_str())
    .bind(holder.device.as_str())
    .bind(i64_of(now))
    .execute(db)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Was this device removed from the team? `Some(index)`: yes, by the log entry `index` (for
/// rows from before migration 0010, the last entry up to the time of the block; the same
/// transaction wrote both with the same timestamp; 0 if none can be found). Up to this entry
/// the device may still read the log.
pub async fn device_removed(
    db: &Db,
    team: &str,
    member: &str,
    device: &str,
) -> Result<Option<u64>> {
    let found: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT COALESCE(r.log_index, (SELECT MAX(l.idx) FROM relay_member_log l \
             WHERE l.team_id = r.team_id AND l.created_at <= r.removed_at)) \
         FROM relay_removed_devices r WHERE r.team_id = ? AND r.member = ? AND r.device = ?",
    )
    .bind(team)
    .bind(member)
    .bind(device)
    .fetch_optional(db)
    .await?;
    Ok(found.map(|index| index.map_or(0, u64_of)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberSeen {
    New,
    RoleChanged,
    Same,
    /// Removed (self-hosting or revocation list of the website); a ticket issued before the
    /// removal no longer opens the team.
    Removed,
    /// The ticket is not newer than the last removal or role change (`relay_ticket_floors`); it
    /// may carry a revoked role. The app fetches a new one.
    Stale,
}

/// How old is a ticket measured against removal and role change (`ticket.renew`)?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketAge {
    Current,
    /// Issued up to the (still effective) removal.
    BeforeRemoval,
    /// Issued up to a role change or an earlier removal.
    Stale,
}

/// Raises the floor for tickets (forward only): tickets with `iat` up to `at_ms` are no longer
/// valid for this member in this team. The team must exist.
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

/// Checks a ticket against removal and floor (for `ticket.renew`).
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

/// A member joins with a verified ticket (`ticket_iat_ms`: issue time of the ticket). A removed
/// member only gets back in with a ticket issued after the removal: then the website has
/// admitted the member again.
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
        // Ticket from before a role change or earlier removal: old role possible.
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

/// Removes a member (self-hosting) or admits them again (rejoin).
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

/// Records a member as removed, even if it never connected: this way it cannot get in with a
/// ticket issued before the removal.
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

/// New role of a member (from `ticket.renew`, revocation list or self-hosting).
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

/// Records a device of a member. Device IDs are only unique per member; the device is thus
/// bound to the subject of the ticket, another member cannot name it.
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

/// Result of `device.keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysStored {
    Stored,
    /// More than `limits::MAX_DEVICES_PER_MEMBER` devices of the member or `MAX_WRAPPED_KEYS`
    /// in the team.
    TooManyDevices,
}

/// `device.keys` of a device in the team (keys and proof of possession, per team). New devices
/// only within the limits per member and per team.
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

/// The keys of a holder in the team that were sent over its own connection
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

/// Devices of current members with keys and proof, without removed ones, at most `limit`.
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

/// Consumes a ticket ID. `false`: already used.
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

/// Old transcripts, at most one batch (bind: cutoff, batch size). A macro, so the test can
/// check the plan of exactly this query.
macro_rules! purge_transcripts_select {
    () => {
        "SELECT id FROM relay_blobs WHERE kind = 'transcript' AND created_at < ? LIMIT ?"
    };
}

/// Transcripts deleted per write transaction, so no purge holds the write lock for long.
const PURGE_BATCH: i64 = 500;

pub async fn purge(db: &Db, now_s: i64, transcript_cutoff_ms: u64) -> Result<()> {
    sqlx::query("DELETE FROM relay_used_tickets WHERE exp < ?")
        .bind(now_s - 2 * crate::ticket::CLOCK_SKEW_S)
        .execute(db)
        .await?;
    sqlx::query("DELETE FROM relay_revocations_seen WHERE seen_at < ?")
        .bind(now_s.saturating_sub(30 * 86_400).saturating_mul(1000))
        .execute(db)
        .await?;
    // Nothing reads `relay_devices` (device keys and blocks live per team in their own
    // tables); every `hello` refreshes `last_seen`, so only devices gone for long go.
    sqlx::query("DELETE FROM relay_devices WHERE last_seen < ?")
        .bind(
            now_s
                .saturating_sub(DEVICE_RETENTION_DAYS * 86_400)
                .saturating_mul(1000),
        )
        .execute(db)
        .await?;
    // In batches, each its own short write transaction: the index on (kind, created_at)
    // (migration 0011) finds them without scanning, and the quota shrinks by what was deleted.
    loop {
        let mut tx = begin_write(db).await?;
        let gone: Vec<(String, i64)> = sqlx::query_as(concat!(
            "DELETE FROM relay_blobs WHERE id IN (",
            purge_transcripts_select!(),
            ") RETURNING team_id, size"
        ))
        .bind(i64_of(transcript_cutoff_ms))
        .bind(PURGE_BATCH)
        .fetch_all(&mut *tx)
        .await?;
        let mut per_team: std::collections::BTreeMap<&str, i64> = Default::default();
        for (team, size) in &gone {
            *per_team.entry(team.as_str()).or_default() += size;
        }
        for (team, size) in per_team {
            sqlx::query("UPDATE relay_teams SET blob_bytes = blob_bytes - ? WHERE id = ?")
                .bind(size)
                .bind(team)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        if (gone.len() as i64) < PURGE_BATCH {
            return Ok(());
        }
    }
}

/// Blob bytes of one member over all teams, as a multiple of the quota per team.
pub const BLOB_TEAMS_PER_MEMBER: u64 = 2;

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
    // Over all teams one member may store `BLOB_TEAMS_PER_MEMBER` times the quota of a team:
    // otherwise a single account fills the disk through many teams of its own.
    let of_member: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(size), 0) FROM relay_blobs WHERE member = ?")
            .bind(holder.member.as_str())
            .fetch_one(&mut *tx)
            .await?;
    if of_member.saturating_add(size) > i64_of(quota.saturating_mul(BLOB_TEAMS_PER_MEMBER)) {
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

/// The member that stored a blob of the team, `None` if the team has no blob with this ID.
pub async fn blob_author(db: &Db, team: &str, id: &str) -> Result<Option<String>> {
    sqlx::query_scalar("SELECT member FROM relay_blobs WHERE team_id = ? AND id = ?")
        .bind(team)
        .bind(id)
        .fetch_optional(db)
        .await
}

/// `blob.delete`: removes the blob and frees its size in the team's quota in one transaction.
/// `false`: there was no such blob (any more; a concurrent delete won).
pub async fn delete_blob(db: &Db, team: &str, id: &str) -> Result<bool> {
    let mut tx = begin_write(db).await?;
    let size: Option<i64> =
        sqlx::query_scalar("DELETE FROM relay_blobs WHERE team_id = ? AND id = ? RETURNING size")
            .bind(team)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(size) = size else {
        return Ok(false);
    };
    sqlx::query("UPDATE relay_teams SET blob_bytes = MAX(blob_bytes - ?, 0) WHERE id = ?")
        .bind(size)
        .bind(team)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
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

/// Writes an entry that `LogVerifier` has already accepted. Checks the chain against the stored
/// one as a second line of defense (`check_append`); `false` means something else is stored
/// (then everything stays as it was).
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

/// `memberlog.append` or `device.remove`: writes the entry and, in the same step, blocks and
/// forgets the devices it takes out of the team. `false`: nothing written.
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
    drop_devices(&mut tx, team, removed, append.index, by, now).await?;
    tx.commit().await?;
    Ok(true)
}

/// All stored entries in order (for rebuilding the `LogVerifier`).
pub async fn log_all(db: &Db, team: &str) -> Result<Vec<MemberLogEntry>> {
    log_get(db, team, 0, usize::MAX >> 1).await
}

/// Entries after `after`, at most `limit`; the caller requests one more so that
/// `MemberLogEntries::page` knows whether there are more.
pub async fn log_get(db: &Db, team: &str, after: u64, limit: usize) -> Result<Vec<MemberLogEntry>> {
    log_get_until(db, team, after, u64::MAX, limit).await
}

/// Like `log_get`, but only entries up to and including `until` (for a removed device: up to
/// the entry that removed it).
pub async fn log_get_until(
    db: &Db,
    team: &str,
    after: u64,
    until: u64,
    limit: usize,
) -> Result<Vec<MemberLogEntry>> {
    let rows = sqlx::query(
        "SELECT idx, hash, entry, member, device, created_at FROM relay_member_log \
         WHERE team_id = ? AND idx > ? AND idx <= ? ORDER BY idx LIMIT ?",
    )
    .bind(team)
    .bind(i64_of(after))
    .bind(i64_of(until))
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
    /// Not exactly current + 1, or the entry does not fit the stored chain.
    WrongEpoch,
    /// `key.wrap`: this sender already has a package for the target in this epoch.
    AlreadyWrapped,
}

/// The `seq` for the team's next key package (order of arrival); read once per transaction
/// and counted up by the caller for each stored package.
async fn next_package_seq(tx: &mut Tx, team: &str) -> Result<i64> {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) + 1 FROM relay_key_packages WHERE team_id = ?")
        .bind(team)
        .fetch_one(&mut **tx)
        .await
}

/// Stores a package with `seq`; `false` if there already is one for the sender, target and
/// epoch (then `seq` stays unused).
async fn insert_package(
    tx: &mut Tx,
    team: &str,
    epoch: Epoch,
    wrapped: &WrappedKey,
    by: &Holder,
    now: u64,
    seq: i64,
) -> Result<bool> {
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

/// `key.rotate`: rotation entry, new epoch and all packages in one transaction, or none of
/// them.
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
    let mut seq = next_package_seq(&mut tx, team).await?;
    for w in wrapped {
        if insert_package(&mut tx, team, epoch, w, by, now, seq).await? {
            seq += 1;
        }
    }
    sqlx::query("UPDATE relay_teams SET epoch = ? WHERE id = ?")
        .bind(i64::from(epoch.0))
        .bind(team)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(EpochChange::Done)
}

/// Senders of the stored packages of a target in an epoch, in order of arrival (`stored_from`
/// for `relay::check_wrap`).
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

/// `key.wrap`: one more package for the target in the current epoch; never replaced.
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
    let seq = next_package_seq(&mut tx, team).await?;
    if !insert_package(&mut tx, team, epoch, wrapped, by, now, seq).await? {
        return Ok(EpochChange::AlreadyWrapped);
    }
    tx.commit().await?;
    Ok(EpochChange::Done)
}

/// All packages of a holder in an epoch, in order of arrival (`key.get`).
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

/// The first package of a holder in an epoch (the rotation's one), for `key.rotated`.
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

/// The team's stored notes key ring (`notes.keys.get`), `None` when none was written.
pub async fn notes_keys(db: &Db, team: &str) -> Result<Option<NotesKeysRecord>> {
    let row: Option<(i64, String, String, i64, String)> = sqlx::query_as(
        "SELECT version, by_member, by_device, epoch, content FROM relay_notes_keys WHERE team_id = ?",
    )
    .bind(team)
    .fetch_optional(db)
    .await?;
    let Some((version, member, device, epoch, content)) = row else {
        return Ok(None);
    };
    // Only what passed the protocol's checks was stored; anything else is corrupted data.
    let record = (|| {
        Some(NotesKeysRecord {
            version: u64::try_from(version).ok()?,
            by: Holder {
                member: MemberId::new(member).ok()?,
                device: DeviceId::new(device).ok()?,
            },
            content: Sealed {
                epoch: Epoch(u32::try_from(epoch).ok()?),
                data: Ciphertext::new(content).ok()?,
            },
        })
    })();
    if record.is_none() {
        tracing::error!("stored notes key ring cannot be read");
    }
    Ok(record)
}

/// Outcome of `set_notes_keys`.
#[derive(Debug, PartialEq, Eq)]
pub enum NotesKeysStored {
    /// Stored under this new version.
    Stored(u64),
    /// `base` is not the stored version (0: none stored).
    Conflict,
}

/// Compare and set of the team's notes key ring: stores `content` as version `base + 1` only if
/// the stored version is `base` (0 when there is none), in one write transaction. Durable
/// before the caller answers (`synchronous = FULL`).
pub async fn set_notes_keys(
    db: &Db,
    team: &str,
    base: u64,
    by: &Holder,
    content: &Sealed,
    now: u64,
) -> Result<NotesKeysStored> {
    let mut tx = begin_write(db).await?;
    let stored: Option<i64> =
        sqlx::query_scalar("SELECT version FROM relay_notes_keys WHERE team_id = ?")
            .bind(team)
            .fetch_optional(&mut *tx)
            .await?;
    let current = stored.map_or(0, u64_of);
    let next = match base.checked_add(1) {
        Some(next) if base == current && i64::try_from(next).is_ok() => next,
        _ => return Ok(NotesKeysStored::Conflict),
    };
    sqlx::query(
        "INSERT INTO relay_notes_keys (team_id, version, by_member, by_device, epoch, content, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (team_id) DO UPDATE SET version = excluded.version, by_member = excluded.by_member, \
         by_device = excluded.by_device, epoch = excluded.epoch, content = excluded.content, \
         updated_at = excluded.updated_at",
    )
    .bind(team)
    .bind(i64_of(next))
    .bind(by.member.as_str())
    .bind(by.device.as_str())
    .bind(i64::from(content.epoch.0))
    .bind(content.data.as_str())
    .bind(i64_of(now))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(NotesKeysStored::Stored(next))
}

/// The role a member last had in the team (for checks without a ticket).
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
// Revocation list of the website (official mode)

/// Last processed cursor (`last`) of the revocation list; `None` before the first fetch.
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

/// Revocation ID already processed?
pub async fn revocation_seen(db: &Db, rid: &str) -> Result<bool> {
    let found: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM relay_revocations_seen WHERE rid = ?")
            .bind(rid)
            .fetch_optional(db)
            .await?;
    Ok(found.is_some())
}

/// Remembers a revocation ID as processed (after applying; the effects are repeatable).
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

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> Db {
        let path = std::env::temp_dir().join(format!("hangar-store-test-{}.db", random_id()));
        crate::db::connect(&format!("sqlite://{}", path.display()))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn transcript_purge_uses_an_index() {
        let db = test_db().await;
        let plan: Vec<String> =
            sqlx::query(concat!("EXPLAIN QUERY PLAN ", purge_transcripts_select!()))
                .bind(0i64)
                .bind(PURGE_BATCH)
                .fetch_all(&db)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.get::<String, _>("detail"))
                .collect();
        assert!(
            plan.iter()
                .any(|step| step.contains("USING INDEX relay_blobs_kind_created")),
            "{plan:?}"
        );
    }

    #[tokio::test]
    async fn transcript_purge_removes_only_old_transcripts_in_batches() {
        let db = test_db().await;
        for team in ["t1", "t2"] {
            sqlx::query("INSERT INTO relay_teams (id, stream, created_at) VALUES (?, 's', 0)")
                .bind(team)
                .execute(&db)
                .await
                .unwrap();
        }
        let mut tx = begin_write(&db).await.unwrap();
        let add = |team: &'static str, kind: &'static str, created_at: i64, n: usize| {
            (0..n)
                .map(move |_| (team, kind, created_at))
                .collect::<Vec<_>>()
        };
        // More old transcripts than one batch, plus what must stay.
        let mut rows = add("t1", "transcript", 100, PURGE_BATCH as usize * 2 + 7);
        rows.extend(add("t2", "transcript", 100, 3));
        rows.extend(add("t1", "transcript", 5_000, 4));
        rows.extend(add("t2", "decision", 100, 2));
        for (team, kind, created_at) in &rows {
            sqlx::query(
                "INSERT INTO relay_blobs (id, team_id, kind, epoch, data, size, member, device, created_at) \
                 VALUES (?, ?, ?, 0, 'YQ', 10, 'm', 'd', ?)",
            )
            .bind(random_id())
            .bind(*team)
            .bind(*kind)
            .bind(*created_at)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query("UPDATE relay_teams SET blob_bytes = blob_bytes + 10 WHERE id = ?")
                .bind(*team)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();

        purge(&db, crate::util::now_s(), 1_000).await.unwrap();

        let left: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT team_id, kind, COUNT(*) FROM relay_blobs GROUP BY team_id, kind ORDER BY team_id, kind",
        )
        .fetch_all(&db)
        .await
        .unwrap();
        assert_eq!(
            left,
            vec![
                ("t1".into(), "transcript".into(), 4),
                ("t2".into(), "decision".into(), 2)
            ]
        );
        let bytes: Vec<i64> = sqlx::query_scalar("SELECT blob_bytes FROM relay_teams ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
        assert_eq!(bytes, vec![40, 20]);
    }
}
