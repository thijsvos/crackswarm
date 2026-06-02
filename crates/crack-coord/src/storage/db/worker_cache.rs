//! `worker_cache_entries`: coord-side mirror of each connected worker's
//! content-cache manifest. Updated on every heartbeat via
//! `sync_worker_cache_manifest`; consulted by the GC loop to target
//! `EvictFile` broadcasts only at workers that actually hold the
//! sha being reclaimed.

use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

/// Per-worker cache summary: how many entries the worker holds and the
/// total bytes those entries represent. Powers `crackctl status --cache`
/// and the TUI's workers-view cache column.
pub async fn cache_summary_per_worker(pool: &SqlitePool) -> Result<Vec<(String, i64, i64)>> {
    // Returns (worker_id, file_count, total_bytes) — including 0/0 rows
    // for connected workers with empty caches so the status output lists
    // every worker, not only the busy ones.
    let rows = sqlx::query(
        "SELECT w.id AS wid, \
                COALESCE(SUM(CASE WHEN wce.file_sha256 IS NOT NULL THEN 1 ELSE 0 END), 0) AS file_count, \
                COALESCE(SUM(wce.size_bytes), 0) AS total_bytes \
         FROM workers w \
         LEFT JOIN worker_cache_entries wce ON wce.worker_id = w.id \
         GROUP BY w.id \
         ORDER BY w.id",
    )
    .fetch_all(pool)
    .await
    .context("computing cache_summary_per_worker")?;
    rows.iter()
        .map(|r| {
            Ok((
                r.get::<String, _>("wid"),
                r.get::<i64, _>("file_count"),
                r.get::<i64, _>("total_bytes"),
            ))
        })
        .collect()
}

/// Replace this worker's cache manifest in `worker_cache_entries` with the
/// new set: upsert every entry in `manifest`, remove any rows not listed.
/// Runs as a single transaction so the coord never sees a half-synced
/// view.
pub async fn sync_worker_cache_manifest(
    pool: &SqlitePool,
    worker_id: &str,
    manifest: &[crack_common::protocol::CacheManifestEntry],
) -> Result<()> {
    let mut tx = pool.begin().await.context("begin sync tx")?;

    // Remove rows whose sha isn't present in the new manifest.
    if manifest.is_empty() {
        sqlx::query("DELETE FROM worker_cache_entries WHERE worker_id = ?1")
            .bind(worker_id)
            .execute(&mut *tx)
            .await
            .context("clearing worker cache entries")?;
    } else {
        // Stage the keep-set in a connection-scoped temp table and pivot the
        // DELETE through `NOT IN (SELECT …)`. This sidesteps SQLite's
        // bound-parameter cap (defaults to 999 on pre-3.32 builds, 32766 on
        // 3.32+). The temp table is connection-scoped, so we DROP it at the
        // end to avoid surprising the next heartbeat on a reused pool conn.
        sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _keep_shas (sha TEXT PRIMARY KEY)")
            .execute(&mut *tx)
            .await
            .context("creating temp keep table")?;
        sqlx::query("DELETE FROM _keep_shas")
            .execute(&mut *tx)
            .await
            .context("clearing temp keep table")?;

        // Each multi-row VALUES insert binds one parameter per row; cap the
        // batch well below the 999 ceiling so any older bundled libsqlite3
        // is happy.
        const KEEP_BATCH: usize = 500;
        for batch in manifest.chunks(KEEP_BATCH) {
            let placeholders = std::iter::repeat_n("(?)", batch.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!("INSERT OR IGNORE INTO _keep_shas(sha) VALUES {placeholders}");
            let mut q = sqlx::query(&sql);
            for entry in batch {
                q = q.bind(&entry.sha256);
            }
            q.execute(&mut *tx).await.context("populating keep set")?;
        }

        sqlx::query(
            "DELETE FROM worker_cache_entries
             WHERE worker_id = ?1
               AND file_sha256 NOT IN (SELECT sha FROM _keep_shas)",
        )
        .bind(worker_id)
        .execute(&mut *tx)
        .await
        .context("pruning stale worker cache entries")?;

        sqlx::query("DROP TABLE _keep_shas")
            .execute(&mut *tx)
            .await
            .context("dropping temp keep table")?;
    }

    // Upsert the new manifest in batched multi-row INSERTs rather than one
    // round-trip per entry. A worker with thousands of cached files used to
    // issue thousands of statements per heartbeat (every ~15s), stalling the
    // dispatcher/monitor loops; this collapses that to a handful of batches.
    //
    // De-duplicate by sha first (last-wins): a multi-row UPSERT may not target
    // the same row twice in one statement, and a manifest could (maliciously or
    // otherwise) repeat a sha. The per-entry loop tolerated repeats implicitly.
    let mut latest: std::collections::HashMap<&str, &crack_common::protocol::CacheManifestEntry> =
        std::collections::HashMap::with_capacity(manifest.len());
    for entry in manifest {
        latest.insert(entry.sha256.as_str(), entry);
    }
    let deduped: Vec<&crack_common::protocol::CacheManifestEntry> = latest.into_values().collect();

    // Each row binds 4 params; keep batches well under SQLite's 999 ceiling.
    const UPSERT_BATCH: usize = 200;
    for batch in deduped.chunks(UPSERT_BATCH) {
        let placeholders = std::iter::repeat_n("(?, ?, ?, ?)", batch.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "INSERT INTO worker_cache_entries \
             (worker_id, file_sha256, size_bytes, last_used_at) \
             VALUES {placeholders} \
             ON CONFLICT(worker_id, file_sha256) DO UPDATE SET \
             size_bytes = excluded.size_bytes, \
             last_used_at = excluded.last_used_at"
        );
        let mut q = sqlx::query(&sql);
        for entry in batch {
            q = q
                .bind(worker_id)
                .bind(&entry.sha256)
                .bind(entry.size_bytes as i64)
                .bind(&entry.last_used_at);
        }
        q.execute(&mut *tx)
            .await
            .context("upserting worker cache entries")?;
    }

    tx.commit().await.context("commit sync tx")?;
    Ok(())
}

/// All worker IDs that reportedly hold the given sha256 in their cache.
/// Used by the GC loop to target `EvictFile` broadcasts.
pub async fn workers_with_file(pool: &SqlitePool, sha256: &str) -> Result<Vec<String>> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT worker_id FROM worker_cache_entries WHERE file_sha256 = ?1")
            .bind(sha256)
            .fetch_all(pool)
            .await
            .context("selecting workers_with_file")?;
    Ok(rows)
}

/// Remove worker/sha pairs in one statement (batched), instead of a round-trip
/// per sha. Called by the `CacheAck` handler to flush the rows an agent has told
/// us it no longer holds; a one-element slice covers single-entry drops.
///
/// # Errors
/// Returns an error if a batched delete fails.
pub async fn remove_worker_cache_entries(
    pool: &SqlitePool,
    worker_id: &str,
    shas: &[String],
) -> Result<()> {
    if shas.is_empty() {
        return Ok(());
    }
    // Each row binds one sha (+1 for worker_id); stay under SQLite's param cap.
    const BATCH: usize = 400;
    for batch in shas.chunks(BATCH) {
        let placeholders = std::iter::repeat_n("?", batch.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "DELETE FROM worker_cache_entries \
             WHERE worker_id = ? AND file_sha256 IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql).bind(worker_id);
        for sha in batch {
            q = q.bind(sha);
        }
        q.execute(pool)
            .await
            .context("removing worker cache entries")?;
    }
    Ok(())
}
