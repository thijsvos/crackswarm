use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
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

/// Find pending tasks, compute their keyspace and hash count, and transition
/// them to running so they become dispatchable.
async fn prepare_pending_tasks(state: &AppState) -> anyhow::Result<()> {
    let pending = db::get_pending_tasks(&state.db).await?;

    for task in pending {
        info!(task_id = %task.id, task_name = %task.name, "preparing pending task");

        // 1. Count hashes in the hash file
        let hash_file = match db::get_file_record(&state.db, &task.hash_file_id).await? {
            Some(f) => f,
            None => {
                error!(task_id = %task.id, "hash file {} not found, failing task", task.hash_file_id);
                db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed).await?;
                continue;
            }
        };

        let file_data = match files::read_file(&state.files_dir(), &task.hash_file_id) {
            Ok(data) => data,
            Err(e) => {
                error!(task_id = %task.id, error = %e, "failed to read hash file");
                db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed).await?;
                continue;
            }
        };

        let content = String::from_utf8_lossy(&file_data);
        let total_hashes = content.lines().filter(|l| !l.trim().is_empty()).count() as u32;

        if total_hashes == 0 {
            error!(task_id = %task.id, "hash file is empty, failing task");
            db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed).await?;
            continue;
        }

        // 2. Compute keyspace via hashcat
        let keyspace = match chunker::compute_keyspace(
            &state.hashcat_path,
            task.hash_mode,
            &task.attack_config,
            &state.files_dir(),
        ).await {
            Ok(ks) => ks,
            Err(e) => {
                error!(task_id = %task.id, error = %e, "failed to compute keyspace");
                db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Failed).await?;
                continue;
            }
        };

        info!(
            task_id = %task.id,
            total_hashes,
            keyspace,
            "task prepared, transitioning to running"
        );

        // 3. Store keyspace and hash count
        db::set_task_keyspace(&state.db, task.id, keyspace, total_hashes).await?;

        // 4. Transition to running
        db::update_task_status(&state.db, task.id, crack_common::models::TaskStatus::Running).await?;

        state.emit(AppEvent::TaskUpdated { task_id: task.id });
    }

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

        let elapsed = now - worker.last_seen_at;
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

            db::insert_audit(
                &state.db,
                "worker_timeout",
                &format!("Worker {} timed out after {}s", worker.name, elapsed.num_seconds()),
                None,
                Some(&worker.id),
            )
            .await?;
        }
    }

    Ok(())
}

async fn reassign_abandoned_chunks(state: &AppState) -> anyhow::Result<()> {
    let abandoned = db::get_abandoned_chunks(&state.db, 45).await?;

    for chunk in abandoned {
        // Calculate remaining work
        let consumed = ((chunk.limit as f64) * (chunk.progress / 100.0)) as u64;
        let new_skip = chunk.skip + consumed;
        let new_limit = chunk.limit.saturating_sub(consumed);

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
        let new_chunk_id = uuid::Uuid::new_v4();
        db::create_chunk(&state.db, chunk.task_id, new_skip, new_limit).await?;

        // Mark the old chunk as fully abandoned (don't retry it again)
        db::update_chunk_status(
            &state.db,
            chunk.id,
            crack_common::models::ChunkStatus::Failed,
        )
        .await?;

        info!(
            old_chunk = %chunk.id,
            new_chunk = %new_chunk_id,
            task = %chunk.task_id,
            remaining = new_limit,
            "reassigned abandoned chunk"
        );
    }

    // Try to assign pending chunks to idle workers
    let idle_workers = crate::scheduler::assigner::find_idle_workers(state).await?;
    for worker_id in idle_workers {
        if let Some((task, chunk)) =
            crate::scheduler::assigner::assign_next_chunk(state, &worker_id).await?
        {
            // Send the chunk to the worker if connected
            let conns = state.worker_connections.read().await;
            if let Some(conn) = conns.get(&worker_id) {
                // Transfer wordlist/rules files before assigning the chunk
                if let Err(e) = crate::transport::handler::send_attack_files_via_tx(state, &task, &conn.tx).await {
                    error!(task_id = %task.id, error = %e, "failed to transfer attack files for dispatch");
                    continue;
                }
                match crate::transport::handler::build_assign_chunk_msg(state, &task, &chunk) {
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
