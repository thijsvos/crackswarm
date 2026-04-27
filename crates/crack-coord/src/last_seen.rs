//! Background flusher for buffered `last_seen_at` heartbeat writes.
//!
//! Every heartbeat used to do a synchronous `UPDATE workers SET
//! last_seen_at = ? WHERE id = ?`. With N workers that's N writes per
//! 15 s — every one of them a serialized WAL transaction competing
//! with chunk dispatches and audit batches. Since the only consumers
//! of `last_seen_at` are the 60 s heartbeat-timeout monitor and the
//! TUI's "last seen" column, a few seconds of staleness is fine; we
//! buffer in `AppState::last_seen_buffer` and persist the latest per
//! worker on a 3 s tick.
//!
//! `monitor::check_worker_health` reads through `effective_last_seen`,
//! which consults the buffer before the DB column, so the timeout
//! check still sees fresh data even when the flusher hasn't run yet.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tracing::warn;

use crate::state::AppState;

const FLUSH_INTERVAL: Duration = Duration::from_secs(3);

/// Drain the heartbeat buffer on a 3 s tick, flushing all buffered
/// timestamps in one transaction. Runs forever; spawned at startup.
pub async fn run_last_seen_flusher(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;

        // Atomically take the buffer; new heartbeats during the flush
        // start fresh on the next tick.
        let snapshot = std::mem::take(&mut *state.last_seen_buffer.lock().await);
        if snapshot.is_empty() {
            continue;
        }

        if let Err(e) = flush(&state.db, &snapshot).await {
            warn!(error = %e, count = snapshot.len(), "last_seen flush failed");
            // Lost updates here are absorbed by the next heartbeat — the
            // buffer is already cleared so we don't accumulate forever.
        }
    }
}

async fn flush(
    pool: &SqlitePool,
    snapshot: &std::collections::HashMap<String, DateTime<Utc>>,
) -> Result<()> {
    let mut tx = pool.begin().await.context("begin last_seen tx")?;
    for (worker_id, ts) in snapshot {
        let ts_str = ts.to_rfc3339();
        sqlx::query("UPDATE workers SET last_seen_at = ?1 WHERE id = ?2")
            .bind(&ts_str)
            .bind(worker_id)
            .execute(&mut *tx)
            .await
            .context("flushing worker last_seen")?;
    }
    tx.commit().await.context("commit last_seen tx")?;
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
            "CREATE TABLE workers (
                id TEXT PRIMARY KEY,
                last_seen_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    #[tokio::test]
    async fn flush_writes_each_buffered_entry_once() {
        let pool = mem_pool().await;
        sqlx::query("INSERT INTO workers (id, last_seen_at) VALUES ('w1', '1970-01-01T00:00:00Z'), ('w2', '1970-01-01T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();

        let mut snap = std::collections::HashMap::new();
        let ts1 = "2026-04-25T10:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let ts2 = "2026-04-25T11:00:00+00:00"
            .parse::<DateTime<Utc>>()
            .unwrap();
        snap.insert("w1".into(), ts1);
        snap.insert("w2".into(), ts2);

        flush(&pool, &snap).await.unwrap();

        let w1: String = sqlx::query_scalar("SELECT last_seen_at FROM workers WHERE id = 'w1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let w2: String = sqlx::query_scalar("SELECT last_seen_at FROM workers WHERE id = 'w2'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(w1, ts1.to_rfc3339());
        assert_eq!(w2, ts2.to_rfc3339());
    }

    #[tokio::test]
    async fn flush_with_empty_snapshot_is_noop() {
        let pool = mem_pool().await;
        flush(&pool, &std::collections::HashMap::new())
            .await
            .unwrap();
        // No panic, no rows touched.
    }
}
