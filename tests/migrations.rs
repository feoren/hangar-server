//! Starting on databases of earlier releases: applied migrations stored with other line
//! endings (images built from a Windows checkout applied migration 11 with CRLF, the release
//! builds embed LF), and new migrations on top of the previous release.

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

#[tokio::test]
async fn the_new_migrations_apply_on_a_database_of_release_0_6_3() {
    let (url, dir) = database();
    let db = hangar_server::db::connect(&url).await.unwrap();
    // The state of release 0.6.3: everything up to migration 15, with a team and a blob.
    sqlx::query("DROP TABLE relay_device_proofs")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("DROP INDEX relay_blobs_team_kind_row")
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version IN (16, 17)")
        .execute(&db)
        .await
        .unwrap();
    hangar_server::relay::store::load_team(&db, "t", 1)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO relay_blobs (id, team_id, kind, epoch, data, size, member, device, created_at) \
         VALUES ('b1', 't', 'decision', 0, 'ZGF0YQ', 6, 'alice', 'pc', 1)",
    )
    .execute(&db)
    .await
    .unwrap();
    db.close().await;

    let db = hangar_server::db::connect(&url).await.unwrap();
    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version IN (16, 17)")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(applied, 2);
    // The index of `blob.list` (17) is in place.
    let index: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'relay_blobs_team_kind_row'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(index, 1);
    let kept: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM relay_teams), (SELECT COUNT(*) FROM relay_blobs)",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(kept, (1, 1));
    sqlx::query(
        "INSERT INTO relay_device_proofs (team_id, member, device, proven_at) VALUES ('t', 'alice', 'pc', 2)",
    )
    .execute(&db)
    .await
    .unwrap();
    // The rows go with the team.
    sqlx::query("DELETE FROM relay_teams WHERE id = 't'")
        .execute(&db)
        .await
        .unwrap();
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM relay_device_proofs")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(left, 0);
    db.close().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn the_member_quota_sum_uses_its_index() {
    let (url, dir) = database();
    let db = hangar_server::db::connect(&url).await.unwrap();
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT COALESCE(SUM(size), 0) FROM relay_blobs WHERE member = ?",
    )
    .bind("alice")
    .fetch_all(&db)
    .await
    .unwrap();
    assert!(
        plan.iter()
            .any(|(.., detail)| detail.contains("USING INDEX relay_blobs_member")),
        "{plan:?}"
    );
    db.close().await;
    let _ = std::fs::remove_dir_all(dir);
}
