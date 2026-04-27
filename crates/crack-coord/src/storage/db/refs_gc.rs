//! `file_refs` + `gc_queue`: the reference-counting layer that drives
//! file lifecycle. Every live claim on a file (sha256-keyed) — task,
//! campaign, pin, manual tag — gets a row in `file_refs`. When all rows
//! drop and the sha isn't pinned, `mark_for_gc` flips the file to
//! `gc_state='marked'` and enqueues it for the GC loop in `lifecycle.rs`.

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{Row, SqlitePool};

use super::get_file_record;

/// Insert a reference row for the given sha256 / kind / id. Idempotent
/// (INSERT OR IGNORE) so callers can safely re-run on retry.
pub async fn insert_file_ref(
    pool: &SqlitePool,
    sha256: &str,
    ref_kind: &str,
    ref_id: &str,
) -> Result<()> {
    if sha256.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT OR IGNORE INTO file_refs (file_sha256, ref_kind, ref_id, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(sha256)
    .bind(ref_kind)
    .bind(ref_id)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .context("inserting file_ref")?;
    Ok(())
}

/// Delete every ref row with the given kind/id. Returns the distinct set of
/// sha256s that were released — caller should run `maybe_mark_orphan_for_gc`
/// on each to queue any orphans for GC.
pub async fn delete_refs_by_ref(
    pool: &SqlitePool,
    ref_kind: &str,
    ref_id: &str,
) -> Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT file_sha256 FROM file_refs WHERE ref_kind = ?1 AND ref_id = ?2",
    )
    .bind(ref_kind)
    .bind(ref_id)
    .fetch_all(pool)
    .await
    .context("selecting refs to delete")?;

    sqlx::query("DELETE FROM file_refs WHERE ref_kind = ?1 AND ref_id = ?2")
        .bind(ref_kind)
        .bind(ref_id)
        .execute(pool)
        .await
        .context("deleting file_refs")?;

    Ok(rows)
}

/// How many rows in `file_refs` currently reference this sha256?
pub async fn count_refs_for_sha(pool: &SqlitePool, sha256: &str) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM file_refs WHERE file_sha256 = ?1")
        .bind(sha256)
        .fetch_one(pool)
        .await
        .context("counting refs for sha")
}

/// Returns true if any file with this sha256 has `pinned = 1`.
pub async fn is_sha_pinned(pool: &SqlitePool, sha256: &str) -> Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE sha256 = ?1 AND pinned = 1")
            .bind(sha256)
            .fetch_one(pool)
            .await
            .context("checking pinned state")?;
    Ok(count > 0)
}

/// Transition matching files to `gc_state = 'marked'` and enqueue for GC.
/// Only touches rows currently in `active` state (so re-calls during the
/// `deleting` window are no-ops).
pub async fn mark_for_gc(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'marked' WHERE sha256 = ?1 AND gc_state = 'active'")
        .bind(sha256)
        .execute(pool)
        .await
        .context("marking file for gc")?;
    sqlx::query(
        "INSERT OR IGNORE INTO gc_queue (file_sha256, queued_at, attempts) VALUES (?1, ?2, 0)",
    )
    .bind(sha256)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .context("inserting into gc_queue")?;
    Ok(())
}

/// If nothing references this sha and it's not pinned, queue it for GC.
/// Used by every entity teardown path that releases refs (task / campaign
/// terminal transitions, file unpin re-evaluation).
pub async fn maybe_mark_orphan_for_gc(pool: &SqlitePool, sha: &str) -> Result<()> {
    if count_refs_for_sha(pool, sha).await? > 0 {
        return Ok(());
    }
    if is_sha_pinned(pool, sha).await? {
        return Ok(());
    }
    mark_for_gc(pool, sha).await?;
    Ok(())
}

/// Drain the GC queue: returns every (sha256, attempts) currently enqueued.
pub async fn list_gc_queue(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query("SELECT file_sha256, attempts FROM gc_queue ORDER BY queued_at ASC")
        .fetch_all(pool)
        .await
        .context("listing gc_queue")?;
    rows.iter()
        .map(|r| {
            Ok((
                r.get::<String, _>("file_sha256"),
                r.get::<i64, _>("attempts"),
            ))
        })
        .collect()
}

/// Remove a sha from the GC queue (either because it was fully collected
/// or because refs came back).
pub async fn remove_from_gc_queue(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("DELETE FROM gc_queue WHERE file_sha256 = ?1")
        .bind(sha256)
        .execute(pool)
        .await
        .context("removing from gc_queue")?;
    Ok(())
}

/// Increment the attempt counter for a stuck GC entry (called when a pass
/// couldn't finish — e.g. file still open elsewhere). Currently
/// vestigial: soft-delete via `set_file_gc_state_deleted` always
/// succeeds, so the GC pass no longer needs to retry. Kept as a
/// primitive for future transient-failure modes (disk I/O hiccups
/// during the on-disk file delete, SQLite contention, etc.).
#[allow(dead_code)]
pub async fn bump_gc_attempts(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE gc_queue SET attempts = attempts + 1 WHERE file_sha256 = ?1")
        .bind(sha256)
        .execute(pool)
        .await
        .context("bumping gc_queue attempts")?;
    Ok(())
}

/// Transition a file from `marked` → `deleting` to reserve it for an
/// in-progress GC pass.
pub async fn set_gc_state_deleting(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'deleting' WHERE sha256 = ?1 AND gc_state = 'marked'")
        .bind(sha256)
        .execute(pool)
        .await
        .context("transitioning files to deleting")?;
    Ok(())
}

/// Soft-delete a file row: the disk file has been reclaimed but the row
/// stays as a tombstone because FK constraints from completed
/// `tasks.hash_file_id` / `campaigns.*` block hard deletion. The row is
/// filtered out of `find_file_by_sha256` and `get_file_record` so dedup
/// never returns a row whose content is gone, while historical joins
/// (audit log, finished tasks listing past hash files) still resolve.
pub async fn set_file_gc_state_deleted(pool: &SqlitePool, file_id: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'deleted' WHERE id = ?1")
        .bind(file_id)
        .execute(pool)
        .await
        .context("transitioning file to deleted")?;
    Ok(())
}

/// Toggle the `pinned` flag on a single file. Pinned files are skipped
/// by the GC loop even when their refcount is zero.
///
/// On unpin, also re-evaluate GC eligibility. The release path
/// (`maybe_mark_orphan_for_gc`) skips marking while a file is pinned,
/// so a file whose refs dropped to zero while pinned never lands in
/// the queue. Without the post-unpin re-check, `crackctl file unpin`
/// is a silent no-op for reclaim — the file stays at
/// `gc_state='active'` with refs=0 forever.
/// `maybe_mark_orphan_for_gc` short-circuits if refs>0 OR pinned, so
/// calling it unconditionally on every unpin is safe (only
/// orphan-eligible files get queued).
pub async fn set_file_pinned(pool: &SqlitePool, file_id: &str, pinned: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE files SET pinned = ?1 WHERE id = ?2")
        .bind(if pinned { 1i64 } else { 0 })
        .bind(file_id)
        .execute(pool)
        .await
        .context("updating files.pinned")?;

    if !pinned && result.rows_affected() > 0 {
        if let Some(rec) = get_file_record(pool, file_id).await? {
            if !rec.sha256.is_empty() {
                maybe_mark_orphan_for_gc(pool, &rec.sha256).await?;
            }
        }
    }
    Ok(result.rows_affected() > 0)
}
