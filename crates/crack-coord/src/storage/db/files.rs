//! `files` table: hash files, wordlists, rules. Each row carries a UUID
//! `id` (used by tasks/campaigns to reference the file) plus the
//! sha256 the content cache addresses against. Tombstoned rows
//! (`gc_state != 'active'`) stay around as FK targets for historical
//! tasks but are filtered out of dedup / lookup.

use anyhow::{Context, Result};
use crack_common::models::FileRecord;
use sqlx::SqlitePool;

use super::row_to_file_record;

pub async fn insert_file_record(pool: &SqlitePool, record: &FileRecord) -> Result<()> {
    let uploaded_at = record.uploaded_at.to_rfc3339();

    sqlx::query(
        "INSERT INTO files (id, filename, file_type, size_bytes, sha256, disk_path, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&record.id)
    .bind(&record.filename)
    .bind(&record.file_type)
    .bind(record.size_bytes)
    .bind(&record.sha256)
    .bind(&record.disk_path)
    .bind(&uploaded_at)
    .execute(pool)
    .await
    .context("inserting file record")?;

    Ok(())
}

/// Fetch a file row by ID. Tombstoned rows (`gc_state != 'active'`) are
/// hidden — they exist only as FK targets for historical tasks/campaigns
/// and have no on-disk content, so callers (dedup, monitor, transport)
/// must not see them.
pub async fn get_file_record(pool: &SqlitePool, id: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query("SELECT * FROM files WHERE id = ?1 AND gc_state = 'active'")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("fetching file record")?;

    match row {
        Some(ref r) => Ok(Some(row_to_file_record(r)?)),
        None => Ok(None),
    }
}

/// Look up a file by its sha256 content hash. Returns the oldest matching
/// active row (by uploaded_at) when multiple exist — legacy deployments
/// may have duplicates that predate the upload-dedup short-circuit.
/// Tombstoned rows are skipped so dedup never returns a row whose
/// content has been reclaimed.
pub async fn find_file_by_sha256(pool: &SqlitePool, sha256: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query(
        "SELECT * FROM files WHERE sha256 = ?1 AND gc_state = 'active' \
         ORDER BY uploaded_at ASC LIMIT 1",
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await
    .context("fetching file record by sha256")?;

    match row {
        Some(ref r) => Ok(Some(row_to_file_record(r)?)),
        None => Ok(None),
    }
}

#[allow(dead_code)]
pub async fn delete_file_record(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM files WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("deleting file record")?;

    Ok(result.rows_affected() > 0)
}

/// All sha256s currently considered "live" on the coord — i.e. files with
/// `gc_state = 'active'`. Used by reconciliation to tell a (re)connecting
/// worker which content it's still allowed to keep cached.
pub async fn list_active_file_shas(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT sha256 FROM files \
         WHERE sha256 != '' AND gc_state = 'active'",
    )
    .fetch_all(pool)
    .await
    .context("listing active file shas")?;
    Ok(rows)
}

/// Every `files` row sharing this sha256. A legacy deployment can have more
/// than one — we delete all of them when the content is reclaimed.
pub async fn files_by_sha256(pool: &SqlitePool, sha256: &str) -> Result<Vec<FileRecord>> {
    let rows = sqlx::query("SELECT * FROM files WHERE sha256 = ?1")
        .bind(sha256)
        .fetch_all(pool)
        .await
        .context("fetching files by sha256")?;
    rows.iter().map(row_to_file_record).collect()
}

pub async fn list_file_records(pool: &SqlitePool) -> Result<Vec<FileRecord>> {
    let rows = sqlx::query("SELECT * FROM files ORDER BY uploaded_at DESC")
        .fetch_all(pool)
        .await
        .context("listing files")?;

    rows.iter().map(row_to_file_record).collect()
}
