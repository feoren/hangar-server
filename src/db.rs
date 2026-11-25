//! SQLite in WAL mode via sqlx. All queries use bound parameters; SQL texts are static
//! (`&'static str`), column and table names never come from input.

use std::str::FromStr;
use std::time::Duration;

use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Sqlite, SqlitePool, Transaction};

pub type Db = SqlitePool;
pub type Tx = Transaction<'static, Sqlite>;

pub async fn connect(url: &str) -> Result<Db, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        // FULL: a confirmed write survives even a power failure. The durability rule of the
        // event log (no `seq` before the stored head) requires this.
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .min_connections(1)
        .connect_with(options)
        .await?;
    let migrator = sqlx::migrate!("./migrations");
    repair_line_endings(&pool, &migrator).await?;
    migrator.run(&pool).await?;
    Ok(pool)
}

/// sqlx keeps a checksum (SHA-384 over the exact bytes) of every applied migration and refuses
/// to start when it differs from the embedded one. An image built from a Windows checkout
/// (`core.autocrlf`) applied migrations with CRLF; the release builds embed them with LF, so
/// such a database would no longer start although the SQL is the same. A stored checksum that
/// matches the embedded migration with other line endings is therefore set to the embedded
/// one. Any other difference stays an error.
async fn repair_line_endings(pool: &Db, migrator: &Migrator) -> Result<(), sqlx::Error> {
    let table: Option<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_optional(pool)
    .await?;
    if table.is_none() {
        return Ok(());
    }
    for migration in migrator.iter() {
        let stored: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = ?")
                .bind(migration.version)
                .fetch_optional(pool)
                .await?;
        let Some(stored) = stored else { continue };
        if stored.as_slice() == &*migration.checksum {
            continue;
        }
        if line_ending_variants(migration.sql.as_str()).contains(&stored) {
            sqlx::query(
                "UPDATE _sqlx_migrations SET checksum = ? WHERE version = ? AND checksum = ?",
            )
            .bind(&*migration.checksum)
            .bind(migration.version)
            .bind(&stored)
            .execute(pool)
            .await?;
            tracing::warn!(
                version = migration.version,
                "checksum of an applied migration differed only in line endings; corrected"
            );
        }
    }
    Ok(())
}

/// Checksums of `sql` with LF and with CRLF line endings, as sqlx computes them.
fn line_ending_variants(sql: &str) -> [Vec<u8>; 2] {
    use sha2::{Digest, Sha384};
    let lf = sql.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    [
        Sha384::digest(lf.as_bytes()).to_vec(),
        Sha384::digest(crlf.as_bytes()).to_vec(),
    ]
}

/// Write transaction that takes the write lock immediately. Without `IMMEDIATE`, two
/// transactions started as readers could run into `SQLITE_BUSY` on their first write; this way
/// they wait for each other instead (busy_timeout). This is the basis for "first one wins" for
/// seats and invitations.
pub async fn begin_write(db: &Db) -> Result<Tx, sqlx::Error> {
    db.begin_with("BEGIN IMMEDIATE").await
}

pub fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_line_endings_give_the_checksums_sqlx_stores() {
        // Migration 11 as the release builds embed it (LF) and as a Windows checkout had it.
        let lf = "-- a\nCREATE INDEX x ON y (z);\n";
        let [from_lf, from_crlf] = line_ending_variants(lf);
        let [again_lf, again_crlf] = line_ending_variants(&lf.replace('\n', "\r\n"));
        assert_eq!(from_lf, again_lf);
        assert_eq!(from_crlf, again_crlf);
        assert_ne!(from_lf, from_crlf);
        use sha2::{Digest, Sha384};
        assert_eq!(from_lf, Sha384::digest(lf.as_bytes()).to_vec());
    }
}
