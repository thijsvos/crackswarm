//! File lifecycle management: garbage collection loop.
//!
//! The ref-counting half of the lifecycle (acquire on create, release on
//! terminal transition) lives inside `storage::db` — every
//! `db::create_task`, `db::update_task_status`, `db::create_campaign`,
//! `db::update_campaign_status` call automatically maintains `file_refs`.
//!
//! This module runs the GC pass: drains `gc_queue`, deletes coord-side
//! files whose ref count truly reached zero, removes the DB rows. The
//! state machine (`active` → `marked` → `deleting` → removed) plus the
//! queue row survive a coord restart, so an interrupted GC resumes on the
//! next pass.
//!
//! Slice 7 is coord-side only. Agent-side cache eviction and
//! reconciliation arrive in Slices 8 and 9. Until then, a file reclaimed
//! here stays resident in any agent that already cached it — the on-disk
//! staleness is bounded but non-zero, and fully resolved once those two
//! slices ship.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crack_common::protocol::CoordMessage;
use tracing::{debug, info, warn};

use crate::state::AppState;
use crate::storage::{db, files};

const GC_INTERVAL: Duration = Duration::from_secs(60);
const GC_MAX_ATTEMPTS: i64 = 5;

/// Background task: drain the GC queue every `GC_INTERVAL`. Each pass
/// re-checks each entry's ref count (race-safe: a task starting between
/// release and GC grabs the ref back and we skip the delete).
pub async fn run_gc_loop(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(GC_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Err(e) = gc_pass(&state).await {
            warn!("GC pass error: {e}");
        }
    }
}

/// Run one GC pass on demand. Same logic as the periodic loop —
/// callable from `POST /api/v1/files/gc` so operators can flush
/// reclaimed disk immediately instead of waiting for the next tick.
pub async fn run_gc_once(state: &AppState) -> Result<()> {
    gc_pass(state).await
}

async fn gc_pass(state: &AppState) -> Result<()> {
    let queued = db::list_gc_queue(&state.db).await?;
    for (sha, attempts) in queued {
        if attempts >= GC_MAX_ATTEMPTS {
            warn!(%sha, attempts, "GC gave up after too many retries — leaving file in place");
            db::remove_from_gc_queue(&state.db, &sha).await?;
            continue;
        }

        // Race-safe re-check. A newly-created task may have acquired a ref
        // between the release and now.
        if db::count_refs_for_sha(&state.db, &sha).await? > 0 {
            debug!(%sha, "GC: refs reappeared, dropping from queue");
            db::remove_from_gc_queue(&state.db, &sha).await?;
            continue;
        }
        if db::is_sha_pinned(&state.db, &sha).await? {
            debug!(%sha, "GC: file is pinned, dropping from queue");
            db::remove_from_gc_queue(&state.db, &sha).await?;
            continue;
        }

        // Reserve this entry for the current pass.
        db::set_gc_state_deleting(&state.db, &sha).await?;

        // Broadcast EvictFile to every connected worker that reportedly
        // holds this file. Misses are fine: a disconnected or late worker
        // picks it up on the next reconcile pass (Slice 9). Agents that
        // are currently running a chunk against the file defer the
        // eviction locally until the chunk finishes.
        let workers = match db::workers_with_file(&state.db, &sha).await {
            Ok(ws) => ws,
            Err(e) => {
                warn!(%sha, error = %e, "GC: workers_with_file lookup failed");
                Vec::new()
            }
        };
        if !workers.is_empty() {
            let conns = state.worker_connections.read().await;
            let mut dispatched = 0;
            for worker_id in &workers {
                if let Some(conn) = conns.get(worker_id) {
                    if conn
                        .tx
                        .send(CoordMessage::EvictFile { hash: sha.clone() })
                        .await
                        .is_ok()
                    {
                        dispatched += 1;
                    }
                }
            }
            drop(conns);
            debug!(
                %sha,
                workers = workers.len(),
                dispatched,
                "GC: sent EvictFile to workers"
            );
        }

        // Reclaim every files row (and disk file) sharing this sha. A
        // legacy deployment with duplicate sha rows may hit >1 here.
        // Disk: best-effort delete (tolerate "already gone").
        // DB: soft-delete via `gc_state = 'deleted'` instead of hard
        // DELETE. The `tasks.hash_file_id NOT NULL REFERENCES files(id)`
        // FK blocks hard deletes for any file ever consumed by a task,
        // so the row stays as a tombstone — invisible to dedup
        // (`find_file_by_sha256` / `get_file_record` filter out
        // non-active rows) but still resolvable as an FK target for
        // historical joins.
        let records = db::files_by_sha256(&state.db, &sha).await?;
        let files_dir = state.files_dir();
        for rec in &records {
            if let Err(e) = files::delete_file(&files_dir, &rec.id) {
                debug!(
                    file_id = %rec.id,
                    error = %e,
                    "GC: file already absent on disk (continuing)"
                );
            }
            db::set_file_gc_state_deleted(&state.db, &rec.id).await?;
        }

        db::remove_from_gc_queue(&state.db, &sha).await?;
        info!(
            %sha,
            tombstoned_rows = records.len(),
            "GC: reclaimed file (disk freed, rows soft-deleted)"
        );
    }
    Ok(())
}
