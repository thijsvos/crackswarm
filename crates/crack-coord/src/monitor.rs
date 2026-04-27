//! Coordinator background monitor.
//!
//! One ticker (`HEARTBEAT_CHECK_INTERVAL`) drives four orthogonal passes
//! in sequence: prepare pending tasks, check worker liveness, reassign
//! abandoned chunks, and advance campaign phases. Each pass logs its
//! errors but never propagates — the ticker keeps running so a transient
//! DB hiccup can't take the loop down.
//!
//! Task preparation runs in spawned subtasks because hashcat `--keyspace`
//! on a large wordlist can take minutes — blocking this loop would also
//! stall heartbeat checks and the GC pass that shares the same cadence
//! (see `lifecycle::run_gc_loop`).

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use crack_common::models::Task;
use tracing::{error, info, warn};

use crate::scheduler::chunker;
use crate::state::{AppEvent, AppState};
use crate::storage::{db, files};

const HEARTBEAT_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);

/// Background task that monitors worker health, prepares pending tasks, and
/// reassigns abandoned chunks.
pub async fn run_monitor(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(HEARTBEAT_CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if let Err(e) = prepare_pending_tasks(&state).await {
            warn!("task preparation error: {e}");
        }

        if let Err(e) = check_worker_health(&state).await {
            warn!("health check error: {e}");
        }

        if let Err(e) = reassign_abandoned_chunks(&state).await {
            warn!("chunk reassignment error: {e}");
        }

        if let Err(e) = crate::campaign::check_campaign_progress(&state).await {
            warn!("campaign progress check error: {e}");
        }
    }
}

/// Find pending tasks and spawn a preparation task for each one that isn't
/// already being prepared. Prep can take minutes for large wordlists (hashcat
/// --keyspace linearly scans the file), so we must not block the monitor loop
/// or heartbeats stall for the duration of the scan.
async fn prepare_pending_tasks(state: &Arc<AppState>) -> anyhow::Result<()> {
    let pending = db::get_pending_tasks(&state.db).await?;

    for task in pending {
        let task_id = task.id;

        // Claim the task for preparation. If it's already being prepared (from
        // a prior tick), skip.
        {
            let mut preparing = state.preparing_tasks.write().await;
            if !preparing.insert(task_id) {
                continue;
            }
        }

        let state_for_spawn = state.clone();
        tokio::spawn(async move {
            if let Err(e) = prepare_one(&state_for_spawn, task).await {
                warn!(%task_id, error = %e, "task preparation failed");
            }
            state_for_spawn
                .preparing_tasks
                .write()
                .await
                .remove(&task_id);
        });
    }

    Ok(())
}

/// Prepare a single task: validate the hash file, count hashes, compute
/// the keyspace, then transition the task to `Running`. Runs inside a
/// spawned task so it doesn't block the monitor loop.
///
/// Side-effects: on any of the validation failures (hash-file row
/// missing, hash file unreadable, file empty, keyspace computation
/// failing) the task is transitioned to `TaskStatus::Failed` and the
/// function returns `Ok(())`. Callers must not treat success as
/// "task is now Running" — re-read the task status if that matters.
///
/// # Errors
/// Returns the underlying `db::*` error only when the failure-path
/// status update *itself* fails (i.e. we couldn't even mark the task
/// `Failed`). Validation failures are reported via the task status,
/// not the return value.
async fn prepare_one(state: &AppState, task: Task) -> anyhow::Result<()> {
    info!(task_id = %task.id, task_name = %task.name, "preparing pending task");

    // 1. Ensure the hash file still exists in the files table.
    if db::get_file_record(&state.db, &task.hash_file_id)
        .await?
        .is_none()
    {
        error!(task_id = %task.id, "hash file {} not found, failing task", task.hash_file_id);
        db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed)
            .await?;
        return Ok(());
    }

    // 2. Count hashes in the hash file.
    let file_data = match files::read_file(&state.files_dir(), &task.hash_file_id) {
        Ok(data) => data,
        Err(e) => {
            error!(task_id = %task.id, error = %e, "failed to read hash file");
            db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed)
                .await?;
            return Ok(());
        }
    };

    let content = String::from_utf8_lossy(&file_data);
    let total_hashes = content.lines().filter(|l| !l.trim().is_empty()).count() as u32;

    if total_hashes == 0 {
        error!(task_id = %task.id, "hash file is empty, failing task");
        db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed)
            .await?;
        return Ok(());
    }

    // 3. Compute keyspace via hashcat (cached for dictionary attacks).
    let keyspace = match chunker::compute_keyspace(
        &state.db,
        &state.hashcat_path,
        task.hash_mode,
        &task.attack_config,
        &state.files_dir(),
    )
    .await
    {
        Ok(ks) => ks,
        Err(e) => {
            error!(task_id = %task.id, error = %e, "failed to compute keyspace");
            db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed)
                .await?;
            return Ok(());
        }
    };

    info!(
        task_id = %task.id,
        total_hashes,
        keyspace,
        "task prepared, transitioning to running"
    );

    // 4. Store keyspace and hash count, then transition to running.
    db::set_task_keyspace(&state.db, task.id, keyspace, total_hashes).await?;
    db::update_task_status(
        &state.db,
        task.id,
        crack_common::models::TaskStatus::Running,
    )
    .await?;

    state.emit(AppEvent::TaskUpdated { task_id: task.id });
    Ok(())
}

async fn check_worker_health(state: &AppState) -> anyhow::Result<()> {
    let workers = db::list_workers(&state.db).await?;
    let now = Utc::now();
    let timeout = chrono::Duration::seconds(HEARTBEAT_TIMEOUT.as_secs() as i64);

    for worker in workers {
        if worker.status == crack_common::models::WorkerStatus::Disconnected {
            continue;
        }

        // Heartbeat writes are buffered and flushed every ~3s. Consult the
        // in-memory buffer too so a worker that pinged 1s ago doesn't get
        // marked timed-out because the row hasn't flushed yet.
        let last_seen = state
            .effective_last_seen(&worker.id, worker.last_seen_at)
            .await;
        let elapsed = now - last_seen;
        if elapsed > timeout {
            warn!(
                worker_id = %worker.id,
                worker_name = %worker.name,
                elapsed_secs = elapsed.num_seconds(),
                "worker heartbeat timeout, marking disconnected"
            );

            db::update_worker_status(
                &state.db,
                &worker.id,
                crack_common::models::WorkerStatus::Disconnected,
            )
            .await?;

            // Abandon any running chunks for this worker
            let abandoned = db::abandon_worker_chunks(&state.db, &worker.id).await?;
            if abandoned > 0 {
                info!(
                    worker_id = %worker.id,
                    count = abandoned,
                    "abandoned chunks from timed-out worker"
                );
            }

            // Remove from active connections
            state.worker_connections.write().await.remove(&worker.id);

            state.emit(AppEvent::WorkerDisconnected {
                worker_id: worker.id.clone(),
            });

            state.emit_audit(
                "worker_timeout",
                &format!(
                    "Worker {} timed out after {}s",
                    worker.name,
                    elapsed.num_seconds()
                ),
                None,
                Some(&worker.id),
            );
        }
    }

    Ok(())
}

async fn reassign_abandoned_chunks(state: &AppState) -> anyhow::Result<()> {
    let abandoned = db::get_abandoned_chunks(&state.db, 45).await?;

    for chunk in abandoned {
        let (new_skip, new_limit) =
            remaining_after_progress(chunk.skip, chunk.limit, chunk.progress);

        if new_limit == 0 {
            // Chunk was effectively complete
            db::update_chunk_status(
                &state.db,
                chunk.id,
                crack_common::models::ChunkStatus::Exhausted,
            )
            .await?;
            continue;
        }

        // Create a new pending chunk for the remaining work
        let new_chunk = db::create_chunk(&state.db, chunk.task_id, new_skip, new_limit).await?;

        // Mark the old chunk as fully abandoned (don't retry it again)
        db::update_chunk_status(
            &state.db,
            chunk.id,
            crack_common::models::ChunkStatus::Failed,
        )
        .await?;

        info!(
            old_chunk = %chunk.id,
            new_chunk = %new_chunk.id,
            task = %chunk.task_id,
            remaining = new_limit,
            "reassigned abandoned chunk"
        );
    }

    // Try to assign pending chunks to idle workers.
    //
    // `assign_next_chunk` is transaction-safe — the read-modify-write on
    // `tasks.next_skip` is wrapped in `try_dispatch_new_chunk` with an
    // optimistic conditional UPDATE — so parallel fanout via
    // `for_each_concurrent` is unblocked from a correctness standpoint.
    // Keeping the loop sequential because the remaining latency sits in
    // `build_assign_chunk_msg` (still re-reads the hash file every
    // dispatch — see X2 in the audit roadmap). Acquire the
    // connections-map read guard once instead of per-iteration so a slow
    // `worker_connections.write()` (new-worker registration) doesn't
    // serialize behind 8 dispatches.
    let idle_workers = crate::scheduler::assigner::find_idle_workers(state).await?;
    let conns = state.worker_connections.read().await;
    for worker_id in idle_workers {
        if let Some((task, chunk)) =
            crate::scheduler::assigner::assign_next_chunk(state, &worker_id).await?
        {
            if let Some(conn) = conns.get(&worker_id) {
                match crate::transport::handler::build_assign_chunk_msg(state, &task, &chunk).await
                {
                    Ok(msg) => {
                        let _ = conn.tx.send(msg).await;
                    }
                    Err(e) => {
                        error!(task_id = %task.id, error = %e, "failed to build assign chunk msg for dispatch");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Returns `(new_skip, new_limit)` for restarting an abandoned chunk.
///
/// `progress` is the worker-reported percentage and may be untrusted —
/// negative, NaN, Inf, or >100 — so it's clamped to `[0, 100]` before the
/// `f64 → u64` cast (which is implementation-defined for non-finite inputs).
/// The cast is also capped at `limit` so a slightly-over-100 progress can't
/// produce `consumed > limit` and walk `new_skip` past the task's keyspace.
fn remaining_after_progress(skip: u64, limit: u64, progress: f64) -> (u64, u64) {
    let pct = if progress.is_finite() {
        progress.clamp(0.0, 100.0)
    } else {
        0.0
    };
    let consumed = ((limit as f64) * (pct / 100.0)).min(limit as f64) as u64;
    (
        skip.saturating_add(consumed),
        limit.saturating_sub(consumed),
    )
}

#[cfg(test)]
mod tests {
    use super::remaining_after_progress;

    #[test]
    fn normal_progress_splits_chunk() {
        let (skip, rem) = remaining_after_progress(1000, 400, 25.0);
        assert_eq!(skip, 1100);
        assert_eq!(rem, 300);
    }

    #[test]
    fn zero_progress_keeps_full_chunk() {
        assert_eq!(remaining_after_progress(0, 100, 0.0), (0, 100));
    }

    #[test]
    fn complete_progress_zeroes_remainder() {
        assert_eq!(remaining_after_progress(0, 100, 100.0), (100, 0));
    }

    #[test]
    fn negative_progress_treated_as_zero() {
        assert_eq!(remaining_after_progress(0, 100, -5.0), (0, 100));
    }

    #[test]
    fn over_one_hundred_caps_at_limit() {
        assert_eq!(remaining_after_progress(0, 100, 999_999.0), (100, 0));
    }

    #[test]
    fn nan_treated_as_zero() {
        assert_eq!(remaining_after_progress(0, 100, f64::NAN), (0, 100));
    }

    #[test]
    fn infinity_treated_as_zero() {
        assert_eq!(remaining_after_progress(0, 100, f64::INFINITY), (0, 100));
        assert_eq!(
            remaining_after_progress(0, 100, f64::NEG_INFINITY),
            (0, 100)
        );
    }

    #[test]
    fn near_max_skip_saturates() {
        // skip + consumed must never overflow even with absurd inputs.
        let (skip, _) = remaining_after_progress(u64::MAX - 5, 1000, 100.0);
        assert_eq!(skip, u64::MAX);
    }
}
