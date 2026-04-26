//! `chunks` table: keyspace slices dispatched to workers. A chunk is
//! tied to its parent task, advances through `pending → dispatched →
//! running → {completed, exhausted, failed, abandoned}`, and carries
//! the last-reported progress + speed for the TUI.

use anyhow::{Context, Result};
use chrono::Utc;
use crack_common::models::{Chunk, ChunkStatus, Task};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::{get_task, now_iso, row_to_chunk, set_lifecycle_status};

pub async fn create_chunk(
    pool: &SqlitePool,
    task_id: Uuid,
    skip: u64,
    limit: u64,
) -> Result<Chunk> {
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO chunks (id, task_id, skip, \"limit\", status)
         VALUES (?1, ?2, ?3, ?4, 'pending')",
    )
    .bind(id.to_string())
    .bind(task_id.to_string())
    .bind(skip as i64)
    .bind(limit as i64)
    .execute(pool)
    .await
    .context("inserting chunk")?;

    get_chunk(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("chunk not found after insert"))
}

pub async fn get_chunk(pool: &SqlitePool, id: Uuid) -> Result<Option<Chunk>> {
    let row = sqlx::query("SELECT * FROM chunks WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching chunk")?;

    match row {
        Some(ref r) => Ok(Some(row_to_chunk(r)?)),
        None => Ok(None),
    }
}

pub async fn get_chunks_for_task(pool: &SqlitePool, task_id: Uuid) -> Result<Vec<Chunk>> {
    let rows = sqlx::query("SELECT * FROM chunks WHERE task_id = ?1 ORDER BY skip ASC")
        .bind(task_id.to_string())
        .fetch_all(pool)
        .await
        .context("fetching chunks for task")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn update_chunk_status(pool: &SqlitePool, id: Uuid, status: ChunkStatus) -> Result<()> {
    set_lifecycle_status(pool, "chunks", "id", &id.to_string(), &status).await
}

pub async fn update_chunk_progress(
    pool: &SqlitePool,
    id: Uuid,
    progress: f64,
    speed: u64,
) -> Result<()> {
    sqlx::query("UPDATE chunks SET progress = ?1, speed = ?2 WHERE id = ?3")
        .bind(progress)
        .bind(speed as i64)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("updating chunk progress")?;
    Ok(())
}

pub async fn finalize_chunk_progress(pool: &SqlitePool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE chunks SET progress = 100.0 WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("finalizing chunk progress")?;
    Ok(())
}

/// Claim the oldest pending chunk across all running tasks, assigning it to the
/// given worker. Returns the chunk and its parent task, or None if no pending
/// chunks exist.
pub async fn claim_pending_chunk(
    pool: &SqlitePool,
    worker_id: &str,
) -> Result<Option<(Task, Chunk)>> {
    let now = now_iso();

    // Find the oldest pending chunk from any running task, ordered by priority.
    let row = sqlx::query(
        "SELECT c.* FROM chunks c
         JOIN tasks t ON t.id = c.task_id
         WHERE c.status = 'pending' AND t.status = 'running'
         ORDER BY t.priority DESC, c.skip ASC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("finding pending chunk")?;

    let chunk = match row {
        Some(ref r) => row_to_chunk(r)?,
        None => return Ok(None),
    };

    // Atomic claim: only succeeds if the chunk is still pending.
    let result = sqlx::query(
        "UPDATE chunks SET status = 'dispatched', assigned_worker = ?1, assigned_at = ?2 WHERE id = ?3 AND status = 'pending'"
    )
    .bind(worker_id)
    .bind(&now)
    .bind(chunk.id.to_string())
    .execute(pool)
    .await
    .context("claiming pending chunk")?;

    // Another worker already claimed this chunk between the SELECT and UPDATE.
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    let task = get_task(pool, chunk.task_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found for pending chunk"))?;

    let chunk = get_chunk(pool, chunk.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("chunk not found after claim"))?;

    Ok(Some((task, chunk)))
}

#[allow(dead_code)]
pub async fn get_pending_chunks(
    pool: &SqlitePool,
    task_id: Uuid,
    limit: u32,
) -> Result<Vec<Chunk>> {
    let rows = sqlx::query(
        "SELECT * FROM chunks WHERE task_id = ?1 AND status = 'pending' ORDER BY skip ASC LIMIT ?2",
    )
    .bind(task_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("fetching pending chunks")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn get_abandoned_chunks(pool: &SqlitePool, timeout_secs: i64) -> Result<Vec<Chunk>> {
    let cutoff = (Utc::now() - chrono::Duration::seconds(timeout_secs)).to_rfc3339();

    // Only consider chunks abandoned if the assigned worker is disconnected.
    // Active workers with long-running chunks should not have their work stolen.
    let rows = sqlx::query(
        "SELECT c.* FROM chunks c
         JOIN workers w ON c.assigned_worker = w.id
         WHERE c.status IN ('dispatched', 'running')
           AND c.assigned_at < ?1
           AND w.status = 'disconnected'
         ORDER BY c.assigned_at ASC",
    )
    .bind(&cutoff)
    .fetch_all(pool)
    .await
    .context("fetching abandoned chunks")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn abandon_worker_chunks(pool: &SqlitePool, worker_id: &str) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE chunks SET status = 'abandoned', assigned_worker = NULL
         WHERE assigned_worker = ?1 AND status IN ('dispatched', 'running')",
    )
    .bind(worker_id)
    .execute(pool)
    .await
    .context("abandoning worker chunks")?;

    Ok(result.rows_affected())
}

/// Insert a chunk from a pre-built Chunk struct.
pub async fn insert_chunk(pool: &SqlitePool, chunk: &Chunk) -> Result<()> {
    let now = now_iso();

    sqlx::query(
        "INSERT INTO chunks (id, task_id, skip, \"limit\", status, assigned_worker, assigned_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(chunk.id.to_string())
    .bind(chunk.task_id.to_string())
    .bind(chunk.skip as i64)
    .bind(chunk.limit as i64)
    .bind(chunk.status.to_string())
    .bind(&chunk.assigned_worker)
    .bind(chunk.assigned_at.map(|t| t.to_rfc3339()).or(Some(now)))
    .execute(pool)
    .await
    .context("inserting chunk")?;

    Ok(())
}
