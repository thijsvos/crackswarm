use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tracing::{info, warn};

use crate::state::{AppEvent, AppState};
use crate::storage::db;

const HEARTBEAT_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);

/// Background task that monitors worker health and reassigns abandoned chunks.
pub async fn run_monitor(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(HEARTBEAT_CHECK_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;

        if let Err(e) = check_worker_health(&state).await {
            warn!("health check error: {e}");
        }

        if let Err(e) = reassign_abandoned_chunks(&state).await {
            warn!("chunk reassignment error: {e}");
        }
    }
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
    let abandoned = db::get_abandoned_chunks(&state.db, 120).await?;

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
        if let Some((_task, chunk)) =
            crate::scheduler::assigner::assign_next_chunk(state, &worker_id).await?
        {
            // Send the chunk to the worker if connected
            let conns = state.worker_connections.read().await;
            if let Some(conn) = conns.get(&worker_id) {
                let task = db::get_task(&state.db, chunk.task_id).await?;
                if let Some(task) = task {
                    let (mask, custom_charsets) = match &task.attack_config {
                        crack_common::models::AttackConfig::BruteForce {
                            mask,
                            custom_charsets,
                        } => (mask.clone(), custom_charsets.clone()),
                    };

                    let msg = crack_common::protocol::CoordMessage::AssignChunk {
                        chunk_id: chunk.id,
                        task_id: chunk.task_id,
                        hash_mode: task.hash_mode,
                        hash_file_url: format!("/api/v1/files/{}", task.hash_file_id),
                        skip: chunk.skip,
                        limit: chunk.limit,
                        mask,
                        custom_charsets,
                        extra_args: task.extra_args.clone(),
                    };

                    let _ = conn.tx.send(msg).await;
                }
            }
        }
    }

    Ok(())
}
