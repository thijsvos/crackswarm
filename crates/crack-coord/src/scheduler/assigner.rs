use chrono::Utc;
use crack_common::models::{Chunk, ChunkStatus, Task, WorkerStatus};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::AppState;
use crate::storage::db;
use crate::storage::db::DispatchOutcome;

use super::chunker::calculate_chunk_size;

/// Maximum retry attempts on a `CursorMoved` outcome. With WAL serializing
/// SQLite writes, contention is rare; a small bound keeps the dispatch path
/// from looping forever if the system is genuinely overloaded.
const DISPATCH_MAX_ATTEMPTS: usize = 4;

/// Find the next available work and assign a chunk to the given worker.
///
/// First tries to claim an existing pending chunk (from abandoned chunk recovery).
/// If none exist, creates a new chunk from the task cursor.
/// Returns `Some((task, chunk))` if work was assigned, or `None` if there is no
/// remaining work across all running tasks.
pub async fn assign_next_chunk(
    state: &AppState,
    worker_id: &str,
) -> anyhow::Result<Option<(Task, Chunk)>> {
    // First: try to pick up an existing pending chunk (from recovery/reassignment)
    if let Some((task, chunk)) = db::claim_pending_chunk(&state.db, worker_id).await? {
        db::update_worker_status(&state.db, worker_id, WorkerStatus::Working).await?;
        info!(
            task_id = %task.id,
            chunk_id = %chunk.id,
            worker_id,
            skip = chunk.skip,
            limit = chunk.limit,
            "assigned pending chunk to worker"
        );
        return Ok(Some((task, chunk)));
    }

    // Second: create a new chunk from the task cursor.
    //
    // The flow is read-then-conditional-write to avoid double-dispatching
    // overlapping keyspace ranges when multiple workers ask for work at
    // once. `db::try_dispatch_new_chunk` returns `CursorMoved` if the
    // cursor was advanced by another caller between our SELECT and its
    // UPDATE; we re-read and try again, bounded by DISPATCH_MAX_ATTEMPTS.
    for attempt in 0..DISPATCH_MAX_ATTEMPTS {
        let task = match db::find_next_dispatchable_task(&state.db).await? {
            Some(t) => t,
            None => {
                debug!("no dispatchable tasks found");
                return Ok(None);
            }
        };

        let total_keyspace = match task.total_keyspace {
            Some(ks) => ks,
            None => {
                debug!(task_id = %task.id, "task has no computed keyspace yet");
                return Ok(None);
            }
        };

        // Cursor exhausted? Another caller may have just finished it.
        if task.next_skip >= total_keyspace {
            debug!(task_id = %task.id, "task keyspace fully dispatched");
            return Ok(None);
        }

        // Look up the worker's benchmark for this hash mode (if any).
        // Cached in AppState — first miss reads from DB and populates.
        let worker_speed = state.get_worker_speed(worker_id, task.hash_mode).await?;

        // Count connected workers for chunk-sizing heuristic.
        let num_workers = state.worker_connections.read().await.len();

        let chunk_size = calculate_chunk_size(worker_speed, total_keyspace, num_workers);
        let remaining = total_keyspace - task.next_skip;
        let limit = chunk_size.min(remaining);

        let chunk = Chunk {
            id: Uuid::new_v4(),
            task_id: task.id,
            skip: task.next_skip,
            limit,
            status: ChunkStatus::Dispatched,
            assigned_worker: Some(worker_id.to_string()),
            assigned_at: Some(Utc::now()),
            completed_at: None,
            progress: 0.0,
            speed: 0,
            cracked_count: 0,
        };

        match db::try_dispatch_new_chunk(&state.db, task.id, task.next_skip, &chunk, worker_id)
            .await?
        {
            DispatchOutcome::Dispatched => {
                info!(
                    task_id = %task.id,
                    chunk_id = %chunk.id,
                    worker_id,
                    skip = chunk.skip,
                    limit = chunk.limit,
                    attempt,
                    "assigned chunk to worker"
                );
                let mut task = task;
                task.next_skip = task.next_skip.saturating_add(limit);
                return Ok(Some((task, chunk)));
            }
            DispatchOutcome::CursorMoved => {
                debug!(
                    task_id = %task.id,
                    attempt,
                    "cursor moved between SELECT and UPDATE, retrying"
                );
                continue;
            }
        }
    }

    warn!(
        worker_id,
        attempts = DISPATCH_MAX_ATTEMPTS,
        "give up assigning chunk: cursor kept moving (high contention or stuck cursor)"
    );
    Ok(None)
}

/// Reassign an abandoned or failed chunk by creating a new chunk for the remaining work.
///
/// The original chunk's progress is used to compute how much work has already been done.
/// A new `Pending` chunk is created covering only the unfinished portion.
#[allow(dead_code)]
pub async fn reassign_chunk(state: &AppState, chunk: &Chunk) -> anyhow::Result<Chunk> {
    // Calculate how much of the chunk was already completed based on progress percentage.
    let consumed = if chunk.progress > 0.0 {
        ((chunk.limit as f64) * (chunk.progress / 100.0)) as u64
    } else {
        0
    };

    let new_skip = chunk.skip + consumed;
    let new_limit = chunk.limit.saturating_sub(consumed);

    // Guard against creating a zero-size chunk.
    let new_limit = new_limit.max(1);

    let new_chunk = Chunk {
        id: Uuid::new_v4(),
        task_id: chunk.task_id,
        skip: new_skip,
        limit: new_limit,
        status: ChunkStatus::Pending,
        assigned_worker: None,
        assigned_at: None,
        completed_at: None,
        progress: 0.0,
        speed: 0,
        cracked_count: 0,
    };

    db::insert_chunk(&state.db, &new_chunk).await?;

    info!(
        original_chunk = %chunk.id,
        new_chunk_id = %new_chunk.id,
        task_id = %chunk.task_id,
        new_skip,
        new_limit,
        "reassigned chunk for remaining work"
    );

    Ok(new_chunk)
}

/// Return the IDs of all workers currently in `Idle` status.
pub async fn find_idle_workers(state: &AppState) -> anyhow::Result<Vec<String>> {
    let workers = db::get_workers_by_status(&state.db, WorkerStatus::Idle).await?;
    Ok(workers.into_iter().map(|w| w.id).collect())
}
