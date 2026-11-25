//! Starting on a database whose applied migrations were stored with other line endings: images
//! built from a Windows checkout applied migration 11 with CRLF, the release builds embed LF.

use sha2::{Digest, Sha384};

fn database() -> (String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "hangar-migrations-{}",
        hangar_server::util::random_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("hangar-team.db").display());
    (url, dir)
}

fn embedded_sql(version: i64) -> String {
    let migrator = sqlx::migrate!("./migrations");
    let migration = migrator
        .iter()
        .find(|m| m.version == version)
        .expect("migration embedded");
    migration.sql.as_str().to_owned()
}

async fn stored_checksum(db: &hangar_server::db::Db, version: i64) -> Vec<u8> {
    sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = ?")
        .bind(version)
        .fetch_one(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_checksum_that_differs_only_in_line_endings_is_corrected() {
    let (url, dir) = database();
    let db = hangar_server::db::connect(&url).await.unwrap();
    let lf = embedded_sql(11);
    assert!(!lf.contains('\r'), "the build embeds LF");
    let crlf = Sha384::digest(lf.replace('\n', "\r\n").as_bytes()).to_vec();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 11")
        .bind(&crlf)
        .execute(&db)
        .await
        .unwrap();
    db.close().await;

    let db = hangar_server::db::connect(&url)
        .await
        .expect("starts despite the CRLF checksum");
    assert_eq!(
        stored_checksum(&db, 11).await,
        Sha384::digest(lf.as_bytes()).to_vec()
    );
    db.close().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_really_changed_migration_still_refuses_to_start() {
    let (url, dir) = database();
    let db = hangar_server::db::connect(&url).await.unwrap();
    let other = Sha384::digest(b"CREATE TABLE something_else (x INTEGER);").to_vec();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = ? WHERE version = 11")
        .bind(&other)
        .execute(&db)
        .await
        .unwrap();
    db.close().await;

    let error = hangar_server::db::connect(&url).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("previously applied but has been modified"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}
