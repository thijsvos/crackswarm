//! Background flusher for the audit-log channel.
//!
//! Each `AppState::emit_audit` call drops an `AuditEntry` into a 4k-deep
//! mpsc; this task owns the receiver. It coalesces up to 64 entries (or
//! waits up to 500 ms for more after the first arrival) and writes the
//! batch as one transaction. Audit was previously inserted inline on
//! every connect/disconnect/chunk-failure — under reconnect storms or
//! large fleets, those serialized SQLite writes became a dispatch
//! bottleneck. Batching collapses N writes into one tx.
//!
//! Exits cleanly when every `audit_tx` clone has been dropped.

use std::time::Duration;

use anyhow::{Context, Result};
use crack_common::models::AuditEntry;
use sqlx::SqlitePool;
use tokio::sync::mpsc;

/// How long to coalesce after the first event arrives before flushing.
const COALESCE_WINDOW: Duration = Duration::from_millis(500);

/// Maximum batch size per flush. 64 keeps SQLite parameter usage trivial
/// and fits the natural cadence of "burst-then-quiet" event traffic.
const MAX_BATCH: usize = 64;

/// Drain the audit channel forever, flushing batched inserts to the
/// `audit_log` table.
///
/// Caller spawns this once at startup with the receiver returned by
/// [`crate::state::AppState::new`]. Returns when every sender has been
/// dropped.
pub async fn run_audit_flusher(pool: SqlitePool, mut rx: mpsc::Receiver<AuditEntry>) {
    let mut buf: Vec<AuditEntry> = Vec::with_capacity(MAX_BATCH);

    loop {
        // Block for the first event of a batch; this is the only place we
        // park indefinitely, so the task exits naturally when all senders
        // drop.
        let first = match rx.recv().await {
            Some(e) => e,
            None => break,
        };
        buf.push(first);

        // Coalesce additional events that arrive within the window or until
        // the batch is full.
        let deadline = tokio::time::Instant::now() + COALESCE_WINDOW;
        while buf.len() < MAX_BATCH {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(e)) => buf.push(e),
                Ok(None) => break, // channel closed mid-batch — flush what we have
                Err(_) => break,   // window elapsed
            }
        }

        if let Err(e) = flush_batch(&pool, &buf).await {
            // Audit is best-effort: log and drop on persistent DB failure
            // rather than block the producer or accumulate forever.
            tracing::error!(error = %e, count = buf.len(), "audit batch flush failed; dropping entries");
        }
        buf.clear();
    }

    // Sender side closed — write whatever's queued so shutdown audit
    // doesn't get lost.
    if !buf.is_empty() {
        if let Err(e) = flush_batch(&pool, &buf).await {
            tracing::error!(error = %e, count = buf.len(), "final audit batch flush failed");
        }
    }
}

async fn flush_batch(pool: &SqlitePool, batch: &[AuditEntry]) -> Result<()> {
    let mut tx = pool.begin().await.context("begin audit batch tx")?;
    for entry in batch {
        let created_at = entry.created_at.to_rfc3339();
        sqlx::query(
            "INSERT INTO audit_log (event_type, details, source_ip, worker_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&entry.event_type)
        .bind(&entry.details)
        .bind(&entry.source_ip)
        .bind(&entry.worker_id)
        .bind(&created_at)
        .execute(&mut *tx)
        .await
        .context("insert audit row")?;
    }
    tx.commit().await.context("commit audit batch tx")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    async fn mem_pool() -> SqlitePool {
        let opts = SqliteConnectOptions::from_str(":memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL,
                source_ip TEXT,
                worker_id TEXT,
                created_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    fn entry(event_type: &str) -> AuditEntry {
        AuditEntry {
            id: None,
            event_type: event_type.into(),
            details: format!("details for {event_type}"),
            source_ip: None,
            worker_id: None,
            created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn flusher_writes_batch_in_one_transaction() {
        let pool = mem_pool().await;
        let (tx, rx) = mpsc::channel(16);

        let pool_for_task = pool.clone();
        let handle = tokio::spawn(async move { run_audit_flusher(pool_for_task, rx).await });

        for i in 0..10 {
            tx.send(entry(&format!("evt-{i}"))).await.unwrap();
        }
        drop(tx); // signal the flusher to drain and exit

        handle.await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 10);
    }

    #[tokio::test]
    async fn flusher_drains_remaining_on_sender_close() {
        // Single event then immediate close — must still land in DB.
        let pool = mem_pool().await;
        let (tx, rx) = mpsc::channel(16);
        let pool_for_task = pool.clone();
        let handle = tokio::spawn(async move { run_audit_flusher(pool_for_task, rx).await });

        tx.send(entry("only-one")).await.unwrap();
        drop(tx);
        handle.await.unwrap();

        let evt: String = sqlx::query_scalar("SELECT event_type FROM audit_log LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(evt, "only-one");
    }
}
