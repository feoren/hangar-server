//! SQLite in WAL mode via sqlx. All queries use bound parameters; SQL texts are static
//! (`&'static str`), column and table names never come from input.

use std::str::FromStr;
use std::time::Duration;

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
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
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
