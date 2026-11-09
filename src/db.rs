//! SQLite im WAL-Modus über sqlx. Alle Abfragen mit gebundenen Parametern; SQL-Texte sind
//! statisch (`&'static str`), Spalten- und Tabellennamen kommen nie aus Eingaben.

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
        // FULL: eine bestätigte Schreibung übersteht auch einen Stromausfall. Die
        // Haltbarkeitsregel des Ereignislogs (kein `seq` vor dem gespeicherten head) braucht das.
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

/// Schreibende Transaktion, die die Schreibsperre sofort nimmt. Ohne `IMMEDIATE` könnten zwei
/// lesend begonnene Transaktionen beim ersten Schreiben in `SQLITE_BUSY` laufen; so warten sie
/// stattdessen (busy_timeout) nacheinander. Das ist die Grundlage für "erster gewinnt" bei
/// Plätzen und Einladungen.
pub async fn begin_write(db: &Db) -> Result<Tx, sqlx::Error> {
    db.begin_with("BEGIN IMMEDIATE").await
}

pub fn i64_of(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub fn u64_of(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
