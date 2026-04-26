//! `worker_benchmarks` table: one (speed, measured_at) row per
//! (worker_id, hash_mode). Drives chunk-size sizing in the dispatcher.
//! Rare to write (one row per worker per hash mode for the lifetime of
//! the deployment) — `state.rs`'s `benchmark_cache` reads through this
//! lazily and avoids re-querying.

use anyhow::{Context, Result};
use crack_common::models::WorkerBenchmark;
use sqlx::SqlitePool;

use super::{now_iso, row_to_benchmark};

pub async fn upsert_benchmark(
    pool: &SqlitePool,
    worker_id: &str,
    hash_mode: u32,
    speed: u64,
) -> Result<()> {
    let now = now_iso();

    sqlx::query(
        "INSERT INTO worker_benchmarks (worker_id, hash_mode, speed, measured_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(worker_id, hash_mode) DO UPDATE SET
           speed = excluded.speed,
           measured_at = excluded.measured_at",
    )
    .bind(worker_id)
    .bind(hash_mode)
    .bind(speed as i64)
    .bind(&now)
    .execute(pool)
    .await
    .context("upserting benchmark")?;

    Ok(())
}

pub async fn get_benchmark(
    pool: &SqlitePool,
    worker_id: &str,
    hash_mode: u32,
) -> Result<Option<WorkerBenchmark>> {
    let row =
        sqlx::query("SELECT * FROM worker_benchmarks WHERE worker_id = ?1 AND hash_mode = ?2")
            .bind(worker_id)
            .bind(hash_mode)
            .fetch_optional(pool)
            .await
            .context("fetching benchmark")?;

    match row {
        Some(ref r) => Ok(Some(row_to_benchmark(r)?)),
        None => Ok(None),
    }
}
