//! `tasks` table: top-level cracking jobs. A task carries an attack
//! config (BruteForce / Dictionary / DictionaryWithRules), a hash
//! file id, and a keyspace cursor (`next_skip`) that the dispatcher
//! advances atomically as it carves chunks out for workers.
//!
//! Task creation acquires file-refs for the hash file (and the
//! wordlist/rules if any), so the GC loop can't reclaim referenced
//! content while a task is still pending or running. Terminal status
//! transitions release those refs and queue any orphan files for GC.

use anyhow::{Context, Result};
use crack_common::models::{AttackConfig, Chunk, CreateTaskRequest, Task, TaskStatus, WorkerStatus};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use super::{
    delete_refs_by_ref, get_file_record, insert_file_ref, maybe_mark_orphan_for_gc, now_iso,
    row_to_task, set_lifecycle_status, LifecycleStatus,
};

pub async fn create_task(pool: &SqlitePool, req: &CreateTaskRequest) -> Result<Task> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let attack_config_json = serde_json::to_string(&req.attack_config)?;
    let extra_args_json = serde_json::to_string(&req.extra_args)?;

    sqlx::query(
        "INSERT INTO tasks (id, name, hash_mode, hash_file_id, attack_config, priority, extra_args, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)"
    )
    .bind(id.to_string())
    .bind(&req.name)
    .bind(req.hash_mode)
    .bind(&req.hash_file_id)
    .bind(&attack_config_json)
    .bind(req.priority)
    .bind(&extra_args_json)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting task")?;

    // Acquire refs for every file this task depends on. Keeps the GC loop
    // from reclaiming them out from under us.
    acquire_task_refs_inline(pool, id, &req.hash_file_id, &req.attack_config).await?;

    get_task(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found after insert"))
}

/// Walk the task's referenced files and insert a ref row for each that has
/// a sha256 on record. Silent no-op on files uploaded before Slice 2 (no
/// sha stored) — they're grandfathered in and won't be GC'd by accident.
pub(super) async fn acquire_task_refs_inline(
    pool: &SqlitePool,
    task_id: Uuid,
    hash_file_id: &str,
    attack_config: &AttackConfig,
) -> Result<()> {
    let mut file_ids: Vec<&str> = vec![hash_file_id];
    match attack_config {
        AttackConfig::BruteForce { .. } => {}
        AttackConfig::Dictionary { wordlist_file_id } => {
            file_ids.push(wordlist_file_id);
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            file_ids.push(wordlist_file_id);
            file_ids.push(rules_file_id);
        }
    }
    let task_id_str = task_id.to_string();
    for file_id in file_ids {
        if let Some(rec) = get_file_record(pool, file_id).await? {
            if !rec.sha256.is_empty() {
                insert_file_ref(pool, &rec.sha256, "task", &task_id_str).await?;
            }
        }
    }
    Ok(())
}

/// Drop all refs held by `task_id` and mark any freshly-orphaned files for
/// GC. Idempotent. Lives here (not `refs_gc`) so `update_task_status`
/// reads cleanly.
async fn release_task_refs_inline(pool: &SqlitePool, task_id: Uuid) -> Result<()> {
    let shas = delete_refs_by_ref(pool, "task", &task_id.to_string()).await?;
    for sha in shas {
        maybe_mark_orphan_for_gc(pool, &sha).await?;
    }
    Ok(())
}

pub async fn get_task(pool: &SqlitePool, id: Uuid) -> Result<Option<Task>> {
    let row = sqlx::query("SELECT * FROM tasks WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching task")?;

    match row {
        Some(ref r) => Ok(Some(row_to_task(r)?)),
        None => Ok(None),
    }
}

pub async fn list_tasks(pool: &SqlitePool) -> Result<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks ORDER BY priority DESC, created_at ASC")
        .fetch_all(pool)
        .await
        .context("listing tasks")?;

    rows.iter().map(row_to_task).collect()
}

pub async fn update_task_status(pool: &SqlitePool, id: Uuid, status: TaskStatus) -> Result<()> {
    let id_str = id.to_string();
    set_lifecycle_status(pool, "tasks", "id", &id_str, &status).await?;
    if status.is_terminal() {
        // Release this task's file refs — any now-orphan files get
        // queued for the GC loop to reclaim on its next pass.
        release_task_refs_inline(pool, id).await?;
    }
    Ok(())
}

pub async fn delete_task(pool: &SqlitePool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM tasks WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("deleting task")?;

    Ok(result.rows_affected() > 0)
}

pub async fn increment_task_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<u32> {
    let row = sqlx::query(
        "UPDATE tasks SET cracked_count = cracked_count + ?1 WHERE id = ?2 RETURNING cracked_count",
    )
    .bind(delta)
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .context("incrementing cracked count")?;

    Ok(row.get::<u32, _>("cracked_count"))
}

pub async fn set_task_keyspace(
    pool: &SqlitePool,
    id: Uuid,
    keyspace: u64,
    total_hashes: u32,
) -> Result<()> {
    sqlx::query("UPDATE tasks SET total_keyspace = ?1, total_hashes = ?2 WHERE id = ?3")
        .bind(keyspace as i64)
        .bind(total_hashes)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("setting task keyspace")?;
    Ok(())
}

/// Outcome of a transactional dispatch attempt — see [`try_dispatch_new_chunk`].
pub enum DispatchOutcome {
    /// All four operations committed.
    Dispatched,
    /// Another caller advanced `tasks.next_skip` between the SELECT and the
    /// conditional UPDATE; nothing was written. Retry by re-reading the
    /// task and computing a fresh chunk.
    CursorMoved,
}

/// Atomically advance a task's cursor, insert a new dispatched chunk, and
/// flip the worker to `Working` — or do none of those.
///
/// The caller has already SELECTed the task (so it observed
/// `expected_next_skip`) and computed `chunk` covering
/// `[expected_next_skip, expected_next_skip + chunk.limit)`. This function
/// runs the four steps inside one transaction with a *conditional* UPDATE
/// keyed on `next_skip = ?expected_next_skip`. If another caller advanced
/// the cursor in the meantime the UPDATE affects 0 rows, the transaction
/// rolls back, and we return `CursorMoved` so the caller can retry.
///
/// Without this, two parallel `assign_next_chunk` calls could both observe
/// the same cursor, dispatch overlapping `[skip, skip+limit)` ranges, and
/// double-assign a stretch of keyspace.
pub async fn try_dispatch_new_chunk(
    pool: &SqlitePool,
    task_id: Uuid,
    expected_next_skip: u64,
    chunk: &Chunk,
    worker_id: &str,
) -> Result<DispatchOutcome> {
    let new_skip = expected_next_skip.saturating_add(chunk.limit);
    let mut tx = pool.begin().await.context("begin dispatch tx")?;

    let cursor_update = sqlx::query(
        "UPDATE tasks SET next_skip = ?1 WHERE id = ?2 AND next_skip = ?3",
    )
    .bind(new_skip as i64)
    .bind(task_id.to_string())
    .bind(expected_next_skip as i64)
    .execute(&mut *tx)
    .await
    .context("conditional cursor advance")?;

    if cursor_update.rows_affected() == 0 {
        // Lost the race; let the caller retry against the moved cursor.
        return Ok(DispatchOutcome::CursorMoved);
    }

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
    .execute(&mut *tx)
    .await
    .context("inserting dispatched chunk")?;

    sqlx::query("UPDATE workers SET status = ?1 WHERE id = ?2")
        .bind(WorkerStatus::Working.to_string())
        .bind(worker_id)
        .execute(&mut *tx)
        .await
        .context("flipping worker to working")?;

    tx.commit().await.context("commit dispatch tx")?;
    Ok(DispatchOutcome::Dispatched)
}

/// Find all pending tasks (need keyspace computation and transition to running).
pub async fn get_pending_tasks(pool: &SqlitePool) -> Result<Vec<Task>> {
    let rows = sqlx::query(
        "SELECT * FROM tasks WHERE status = 'pending' ORDER BY priority DESC, created_at ASC",
    )
    .fetch_all(pool)
    .await
    .context("fetching pending tasks")?;

    rows.iter().map(row_to_task).collect()
}

/// Find the highest-priority running task that still has undispatched keyspace.
pub async fn find_next_dispatchable_task(pool: &SqlitePool) -> Result<Option<Task>> {
    let row = sqlx::query(
        "SELECT * FROM tasks
         WHERE status = 'running'
           AND total_keyspace IS NOT NULL
           AND next_skip < total_keyspace
         ORDER BY priority DESC, created_at ASC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("finding next dispatchable task")?;

    match row {
        Some(ref r) => Ok(Some(row_to_task(r)?)),
        None => Ok(None),
    }
}

pub async fn get_tasks_for_campaign(pool: &SqlitePool, campaign_id: Uuid) -> Result<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks WHERE campaign_id = ?1 ORDER BY created_at ASC")
        .bind(campaign_id.to_string())
        .fetch_all(pool)
        .await
        .context("fetching tasks for campaign")?;

    rows.iter().map(row_to_task).collect()
}

/// Insert a task that's owned by a campaign. Same flow as `create_task`
/// plus a `campaign_id` FK so the campaign engine can pick the task up
/// from `get_tasks_for_campaign` and `get_active_phase` joins.
pub async fn create_campaign_task(
    pool: &SqlitePool,
    req: &CreateTaskRequest,
    campaign_id: Uuid,
) -> Result<Task> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let attack_config_json = serde_json::to_string(&req.attack_config)?;
    let extra_args_json = serde_json::to_string(&req.extra_args)?;

    sqlx::query(
        "INSERT INTO tasks (id, name, hash_mode, hash_file_id, attack_config, priority, extra_args, status, campaign_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)"
    )
    .bind(id.to_string())
    .bind(&req.name)
    .bind(req.hash_mode)
    .bind(&req.hash_file_id)
    .bind(&attack_config_json)
    .bind(req.priority)
    .bind(&extra_args_json)
    .bind(campaign_id.to_string())
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting campaign task")?;

    // Campaign-spawned tasks acquire their own file refs, same as direct
    // task creation. When the task ends those refs release and any
    // orphaned files hit the GC queue.
    acquire_task_refs_inline(pool, id, &req.hash_file_id, &req.attack_config).await?;

    get_task(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found after insert"))
}
