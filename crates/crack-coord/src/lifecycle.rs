//! File lifecycle management: garbage collection loop.
//!
//! The ref-counting half of the lifecycle (acquire on create, release on
//! terminal transition) lives inside `storage::db` — every
//! `db::create_task`, `db::update_task_status`, `db::create_campaign`,
//! `db::update_campaign_status` call automatically maintains `file_refs`.
//!
//! This module runs the GC pass: drains `gc_queue`, deletes coord-side
//! files whose ref count truly reached zero, then tombstones the DB rows.
//! The state machine (`active` → `marked` → `deleting` → `deleted`) plus
//! the queue row survive a coord restart, so an interrupted GC resumes on
//! the next pass. The terminal `deleted` state is a soft tombstone, not a
//! row removal: the `tasks.hash_file_id NOT NULL REFERENCES files(id)` FK
//! forbids a hard `DELETE` for any file ever consumed by a task.
//! Tombstoned rows are invisible to dedup (`find_file_by_sha256` /
//! `get_file_record` filter them out) but remain resolvable as FK targets
//! for historical joins.
//!
//! Together with Slice 8 (`EvictFile`, `dispatch_evict_for_sha`) and
//! Slice 9 (`CacheReconcile`), the GC pass closes the loop end-to-end:
//! reclaimed coord-side files are mirrored into agent caches via
//! targeted-or-broadcast `EvictFile` and reconciled on every (re)connect.
//! Agents defer eviction for any sha actively held by a running chunk —
//! see `crack-agent::ContentCache::evict` and the `running_chunks_using`
//! map in `crack-agent::connection`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crack_common::protocol::CoordMessage;
use tracing::{debug, info, warn};

use crate::state::{AppState, WorkerConnection};
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

        // Tell holders to drop this file from their cache. The DB-backed
        // list (`workers_with_file`) is heartbeat-driven and can lag a
        // freshly-pulled file by up to one heartbeat interval (~15s).
        // When the targeted list is empty we fall back to a broadcast
        // across every connected worker — agents without the file no-op
        // locally (`crack-agent::ContentCache::evict` returns false on a
        // missing path). See issue #45.
        let workers = match db::workers_with_file(&state.db, &sha).await {
            Ok(ws) => ws,
            Err(e) => {
                warn!(%sha, error = %e, "GC: workers_with_file lookup failed");
                Vec::new()
            }
        };
        let conns = state.worker_connections.read().await;
        let (dispatched, fallback) = dispatch_evict_for_sha(&conns, &sha, &workers).await;
        drop(conns);
        debug!(
            %sha,
            fallback,
            targeted = workers.len(),
            dispatched,
            "GC: EvictFile dispatch complete"
        );

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

/// Send `EvictFile` for `sha` to the workers that should drop it.
///
/// Two paths:
/// - **Targeted**: when `targeted` is non-empty, send only to those
///   worker IDs (the heartbeat-derived view said they hold the file).
/// - **Fallback broadcast**: when `targeted` is empty, send to every
///   connected worker. The coord's view of who-holds-what is
///   heartbeat-driven (every 15s), so a freshly-pulled file may not
///   yet appear in `worker_cache_entries`; broadcasting closes that
///   race. Agents without the file no-op locally
///   (`ContentCache::evict` returns `false`).
///
/// Returns `(dispatched, fallback)` — dispatch count and whether the
/// fallback path fired. Fully read-only on `conns`; safe to call while
/// holding the `worker_connections` read lock.
pub(crate) async fn dispatch_evict_for_sha(
    conns: &HashMap<String, WorkerConnection>,
    sha: &str,
    targeted: &[String],
) -> (usize, bool) {
    let mut dispatched = 0usize;
    let fallback = targeted.is_empty();

    if fallback {
        for (worker_id, conn) in conns.iter() {
            if conn
                .tx
                .send(CoordMessage::EvictFile {
                    hash: sha.to_string(),
                })
                .await
                .is_ok()
            {
                dispatched += 1;
            } else {
                debug!(%sha, %worker_id, "GC: fallback EvictFile send failed");
            }
        }
    } else {
        for worker_id in targeted {
            if let Some(conn) = conns.get(worker_id) {
                if conn
                    .tx
                    .send(CoordMessage::EvictFile {
                        hash: sha.to_string(),
                    })
                    .await
                    .is_ok()
                {
                    dispatched += 1;
                }
            }
        }
    }
    (dispatched, fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn fake_conn(worker_id: &str) -> (WorkerConnection, mpsc::Receiver<CoordMessage>) {
        let (tx, rx) = mpsc::channel(64);
        let conn = WorkerConnection {
            worker_id: worker_id.to_string(),
            name: worker_id.to_string(),
            tx,
            peer_addr: "127.0.0.1:0".to_string(),
        };
        (conn, rx)
    }

    #[tokio::test]
    async fn dispatch_evict_targets_only_known_holders() {
        let (c1, mut r1) = fake_conn("w1");
        let (c2, mut r2) = fake_conn("w2");
        let (c3, mut r3) = fake_conn("w3");
        let mut conns = HashMap::new();
        conns.insert("w1".to_string(), c1);
        conns.insert("w2".to_string(), c2);
        conns.insert("w3".to_string(), c3);

        let (dispatched, fallback) =
            dispatch_evict_for_sha(&conns, "sha-x", &["w1".to_string()]).await;

        assert_eq!(dispatched, 1);
        assert!(!fallback);
        // Only w1 received the message.
        assert!(matches!(r1.try_recv(), Ok(CoordMessage::EvictFile { hash }) if hash == "sha-x"));
        assert!(r2.try_recv().is_err());
        assert!(r3.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatch_evict_falls_back_to_broadcast_when_targeted_empty() {
        // Primary regression for #45: heartbeat hasn't yet sync'd the
        // freshly-pulled file, so workers_with_file returns empty. The
        // fallback must reach every connected worker.
        let (c1, mut r1) = fake_conn("w1");
        let (c2, mut r2) = fake_conn("w2");
        let (c3, mut r3) = fake_conn("w3");
        let mut conns = HashMap::new();
        conns.insert("w1".to_string(), c1);
        conns.insert("w2".to_string(), c2);
        conns.insert("w3".to_string(), c3);

        let (dispatched, fallback) = dispatch_evict_for_sha(&conns, "sha-y", &[]).await;

        assert_eq!(dispatched, 3);
        assert!(fallback);
        for r in [&mut r1, &mut r2, &mut r3] {
            assert!(
                matches!(r.try_recv(), Ok(CoordMessage::EvictFile { hash }) if hash == "sha-y")
            );
        }
    }

    #[tokio::test]
    async fn dispatch_evict_with_no_connections_is_safe_noop() {
        let conns: HashMap<String, WorkerConnection> = HashMap::new();
        let (dispatched, fallback) = dispatch_evict_for_sha(&conns, "sha-z", &[]).await;
        assert_eq!(dispatched, 0);
        assert!(fallback);
    }

    #[tokio::test]
    async fn dispatch_evict_with_failed_send_is_counted_as_miss() {
        let (c1, mut r1) = fake_conn("w1");
        let (c2, _r2_dropped) = fake_conn("w2"); // drop receiver below
        let (c3, mut r3) = fake_conn("w3");
        let mut conns = HashMap::new();
        conns.insert("w1".to_string(), c1);
        conns.insert("w2".to_string(), c2);
        conns.insert("w3".to_string(), c3);
        // Drop w2's receiver so its tx.send returns Err.
        drop(_r2_dropped);

        let (dispatched, fallback) = dispatch_evict_for_sha(&conns, "sha-q", &[]).await;

        assert_eq!(dispatched, 2, "w2's failed send must not be counted");
        assert!(fallback);
        assert!(matches!(r1.try_recv(), Ok(CoordMessage::EvictFile { hash }) if hash == "sha-q"));
        assert!(matches!(r3.try_recv(), Ok(CoordMessage::EvictFile { hash }) if hash == "sha-q"));
    }
}
