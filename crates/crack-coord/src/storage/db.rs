use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crack_common::models::*;

// ── Schema (embedded inline) ──

const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    disk_path TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);

-- Non-unique: any existing deployment with duplicate sha256 rows would
-- otherwise refuse to start. Uniqueness is enforced at upload time by
-- short-circuiting on a match; new duplicates can't be introduced.
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);

CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hash_mode INTEGER NOT NULL,
    hash_file_id TEXT NOT NULL REFERENCES files(id),
    attack_config TEXT NOT NULL,
    total_keyspace INTEGER,
    next_skip INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 5,
    status TEXT NOT NULL DEFAULT 'pending',
    total_hashes INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0,
    extra_args TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    skip INTEGER NOT NULL,
    "limit" INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    assigned_worker TEXT,
    assigned_at TEXT,
    completed_at TEXT,
    progress REAL NOT NULL DEFAULT 0.0,
    speed INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cracked_hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    plaintext TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    cracked_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cracked_unique ON cracked_hashes(task_id, hash);

CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    devices TEXT NOT NULL DEFAULT '[]',
    hashcat_version TEXT,
    os TEXT,
    status TEXT NOT NULL DEFAULT 'disconnected',
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_pubkey ON workers(public_key);

CREATE TABLE IF NOT EXISTS worker_benchmarks (
    worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    hash_mode INTEGER NOT NULL,
    speed INTEGER NOT NULL,
    measured_at TEXT NOT NULL,
    PRIMARY KEY (worker_id, hash_mode)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    details TEXT NOT NULL,
    source_ip TEXT,
    worker_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hash_mode INTEGER NOT NULL,
    original_hash_file_id TEXT NOT NULL REFERENCES files(id),
    status TEXT NOT NULL DEFAULT 'draft',
    active_phase_index INTEGER,
    total_phases INTEGER NOT NULL DEFAULT 0,
    total_hashes INTEGER NOT NULL DEFAULT 0,
    cracked_count INTEGER NOT NULL DEFAULT 0,
    priority INTEGER NOT NULL DEFAULT 5,
    extra_args TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE TABLE IF NOT EXISTS campaign_phases (
    id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    phase_index INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    config TEXT NOT NULL,
    task_id TEXT REFERENCES tasks(id),
    hash_file_id TEXT REFERENCES files(id),
    cracked_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_campaign_phase_order ON campaign_phases(campaign_id, phase_index);

CREATE TABLE IF NOT EXISTS keyspace_cache (
    wordlist_sha256 TEXT NOT NULL,
    rules_sha256 TEXT NOT NULL DEFAULT '',
    hash_mode INTEGER NOT NULL,
    keyspace INTEGER NOT NULL,
    computed_at TEXT NOT NULL,
    PRIMARY KEY (wordlist_sha256, rules_sha256, hash_mode)
);

-- Reference-counting lifecycle for the file store.
--
-- Every live claim on a file (sha256-keyed) — by a task, a campaign, a pin,
-- or a manual tag — gets a row here. When no rows reference a given sha256
-- and the file isn't pinned, the file becomes eligible for GC.
CREATE TABLE IF NOT EXISTS file_refs (
    file_sha256   TEXT NOT NULL,
    ref_kind      TEXT NOT NULL,      -- 'task' | 'campaign' | 'pin' | 'manual'
    ref_id        TEXT NOT NULL,      -- task_id | campaign_id | 'pin' | user tag
    created_at    TEXT NOT NULL,
    PRIMARY KEY (file_sha256, ref_kind, ref_id)
);
CREATE INDEX IF NOT EXISTS idx_file_refs_sha ON file_refs(file_sha256);

-- Crash-safe GC work queue. `release_refs_if_last` inserts; the GC loop
-- drains.
CREATE TABLE IF NOT EXISTS gc_queue (
    file_sha256   TEXT PRIMARY KEY,
    queued_at     TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0
);

-- Coord-side view of what each worker has in its content-addressed cache.
-- Populated from the manifest carried on every agent heartbeat; used by
-- the GC loop to target `EvictFile` at only the workers that hold the
-- file, and by reconciliation (Slice 9) to correct drift across
-- reconnects and missed messages.
CREATE TABLE IF NOT EXISTS worker_cache_entries (
    worker_id     TEXT NOT NULL,
    file_sha256   TEXT NOT NULL,
    size_bytes    INTEGER NOT NULL,
    last_used_at  TEXT NOT NULL,
    PRIMARY KEY (worker_id, file_sha256)
);
CREATE INDEX IF NOT EXISTS idx_worker_cache_sha ON worker_cache_entries(file_sha256);

-- Hot-path indexes for the dispatch / monitor / TUI loops. All queries that
-- ride these were full-table scans before; coordinator overhead grew linearly
-- with the chunks/audit/cracked tables until added.
CREATE INDEX IF NOT EXISTS idx_chunks_task_id           ON chunks(task_id);
CREATE INDEX IF NOT EXISTS idx_chunks_status            ON chunks(status);
CREATE INDEX IF NOT EXISTS idx_chunks_assigned_status   ON chunks(assigned_worker, status);
CREATE INDEX IF NOT EXISTS idx_audit_created_at         ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cracked_cracked_at       ON cracked_hashes(cracked_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_status_priority    ON tasks(status, priority);
CREATE INDEX IF NOT EXISTS idx_workers_status           ON workers(status);
"#;

// ── Database init ──

pub async fn init_db(data_dir: &Path) -> Result<SqlitePool> {
    let db_path = data_dir.join("crack-coord.db");
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data directory: {}", data_dir.display()))?;

    let opts = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
        .with_context(|| format!("opening database: {}", db_path.display()))?;

    sqlx::raw_sql(INIT_SQL)
        .execute(&pool)
        .await
        .context("running init migration")?;

    // Migration: add campaign_id to tasks (idempotent)
    let _ = sqlx::query("ALTER TABLE tasks ADD COLUMN campaign_id TEXT REFERENCES campaigns(id)")
        .execute(&pool)
        .await;
    let _ = sqlx::query("CREATE INDEX IF NOT EXISTS idx_tasks_campaign_id ON tasks(campaign_id)")
        .execute(&pool)
        .await;

    // Migration: lifecycle columns on files (idempotent). `pinned` overrides
    // GC; `gc_state` tracks the reclaim state machine (active → marked →
    // deleting → row removed).
    let _ = sqlx::query("ALTER TABLE files ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
        .execute(&pool)
        .await;
    let _ = sqlx::query("ALTER TABLE files ADD COLUMN gc_state TEXT NOT NULL DEFAULT 'active'")
        .execute(&pool)
        .await;

    // Migration: enrollment tokens table
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS enrollment_tokens (
            nonce TEXT PRIMARY KEY,
            worker_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            used_by_pubkey TEXT
        );",
    )
    .execute(&pool)
    .await
    .context("creating enrollment_tokens table")?;

    // Migration: backfill files.sha256 for any pre-Slice-8 rows that were
    // written by the legacy (`TransferFileChunk`) push path before sha256
    // was a required column. Idempotent — only acts on `sha256 = ''` rows
    // and silently skips rows whose on-disk file is gone (legitimately or
    // because GC raced).
    if let Err(e) = backfill_empty_shas(&pool, &data_dir.join("files")).await {
        tracing::warn!(error = %e, "files.sha256 backfill ran with errors (non-fatal)");
    }

    tracing::info!("Database initialized at {}", db_path.display());
    Ok(pool)
}

/// Re-hash on-disk content for any `files` row missing its sha256 and
/// update the column.
///
/// Pre-Slice-8 deployments that used the legacy `TransferFileChunk`
/// eager-push path could end up with `sha256 = ''` rows. The pull-based
/// flow needs a real sha for cache addressing, so a one-shot scan at
/// startup walks empty-sha rows, opens the on-disk file, and writes the
/// computed digest back. Skips rows whose disk file is missing — those
/// are orphan rows the GC sweep will clean up regardless.
///
/// Streams the file (no whole-file allocation) so a multi-GiB hash dump
/// doesn't OOM init.
async fn backfill_empty_shas(pool: &SqlitePool, files_dir: &Path) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncReadExt as _;

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, filename FROM files WHERE sha256 = '' AND gc_state = 'active'",
    )
    .fetch_all(pool)
    .await
    .context("scanning files for empty sha")?;

    if rows.is_empty() {
        return Ok(());
    }
    tracing::info!(count = rows.len(), "backfilling sha256 for legacy file rows");

    let mut backfilled = 0usize;
    let mut skipped = 0usize;
    for (file_id, filename) in rows {
        let path = match crate::storage::files::locate_existing(files_dir, &file_id) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(%file_id, %filename, "backfill: disk file missing, skipping row");
                skipped += 1;
                continue;
            }
        };

        let mut file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(%file_id, error = %e, "backfill: open failed, skipping");
                skipped += 1;
                continue;
            }
        };

        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let sha_hex = loop {
            match file.read(&mut buf).await {
                Ok(0) => break format!("{:x}", hasher.finalize()),
                Ok(n) => hasher.update(&buf[..n]),
                Err(e) => {
                    tracing::warn!(%file_id, error = %e, "backfill: read failed, skipping");
                    skipped += 1;
                    break String::new();
                }
            }
        };
        if sha_hex.is_empty() {
            continue;
        }

        sqlx::query("UPDATE files SET sha256 = ?1 WHERE id = ?2 AND sha256 = ''")
            .bind(&sha_hex)
            .bind(&file_id)
            .execute(pool)
            .await
            .with_context(|| format!("backfill UPDATE for {file_id}"))?;
        backfilled += 1;
    }

    tracing::info!(backfilled, skipped, "files.sha256 backfill complete");
    Ok(())
}

// ── Helper: parse DateTime from ISO 8601 string ──

/// Parse an ISO-8601 timestamp from a `TEXT` column.
///
/// Tries RFC 3339 first (the format `now_iso()` writes); falls back to a
/// no-tz `YYYY-MM-DDTHH:MM:SS[.f]` form for any rows still around from an
/// older write path. Anything that doesn't match either form is a corrupt
/// timestamp — propagate as an error rather than collapse to UNIX_EPOCH,
/// because callers (heartbeat-timeout, abandoned-chunk reassignment, audit
/// ordering) make load-bearing decisions based on these values.
pub(super) fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    let ndt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .with_context(|| format!("unparseable timestamp: {s:?}"))?;
    Ok(ndt.and_utc())
}

pub(super) fn parse_dt_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|s| parse_dt(&s)).transpose()
}

pub(super) fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

// ── Row mapping helpers ──

pub(super) fn row_to_task(row: &sqlx::sqlite::SqliteRow) -> Result<Task> {
    let status_str: String = row.get("status");
    let attack_config_json: String = row.get("attack_config");
    let extra_args_json: String = row.get("extra_args");

    let campaign_id_str: Option<String> = row.get("campaign_id");
    let campaign_id = campaign_id_str
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()?;

    Ok(Task {
        id: Uuid::parse_str(row.get::<&str, _>("id"))?,
        name: row.get("name"),
        hash_mode: row.get::<u32, _>("hash_mode"),
        hash_file_id: row.get("hash_file_id"),
        attack_config: serde_json::from_str(&attack_config_json)
            .context("parsing attack_config JSON")?,
        total_keyspace: row
            .get::<Option<i64>, _>("total_keyspace")
            .map(|v| v as u64),
        next_skip: row.get::<i64, _>("next_skip") as u64,
        priority: row.get::<u8, _>("priority"),
        status: TaskStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        total_hashes: row.get::<u32, _>("total_hashes"),
        cracked_count: row.get::<u32, _>("cracked_count"),
        extra_args: serde_json::from_str(&extra_args_json).context("parsing extra_args JSON")?,
        campaign_id,
        created_at: parse_dt(row.get("created_at"))?,
        started_at: parse_dt_opt(row.get("started_at"))?,
        completed_at: parse_dt_opt(row.get("completed_at"))?,
    })
}

pub(super) fn row_to_chunk(row: &sqlx::sqlite::SqliteRow) -> Result<Chunk> {
    let status_str: String = row.get("status");
    Ok(Chunk {
        id: Uuid::parse_str(row.get::<&str, _>("id"))?,
        task_id: Uuid::parse_str(row.get::<&str, _>("task_id"))?,
        skip: row.get::<i64, _>("skip") as u64,
        limit: row.get::<i64, _>("limit") as u64,
        status: ChunkStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        assigned_worker: row.get("assigned_worker"),
        assigned_at: parse_dt_opt(row.get("assigned_at"))?,
        completed_at: parse_dt_opt(row.get("completed_at"))?,
        progress: row.get("progress"),
        speed: row.get::<i64, _>("speed") as u64,
        cracked_count: row.get::<u32, _>("cracked_count"),
    })
}

pub(super) fn row_to_worker(row: &sqlx::sqlite::SqliteRow) -> Result<Worker> {
    let status_str: String = row.get("status");
    let devices_json: String = row.get("devices");
    Ok(Worker {
        id: row.get("id"),
        name: row.get("name"),
        public_key: row.get("public_key"),
        devices: serde_json::from_str(&devices_json).context("parsing devices JSON")?,
        hashcat_version: row.get("hashcat_version"),
        os: row.get("os"),
        status: WorkerStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        created_at: parse_dt(row.get("created_at"))?,
        last_seen_at: parse_dt(row.get("last_seen_at"))?,
    })
}

pub(super) fn row_to_cracked(row: &sqlx::sqlite::SqliteRow) -> Result<CrackedHash> {
    Ok(CrackedHash {
        id: Some(row.get::<i64, _>("id")),
        task_id: Uuid::parse_str(row.get::<&str, _>("task_id"))?,
        hash: row.get("hash"),
        plaintext: row.get("plaintext"),
        worker_id: row.get("worker_id"),
        cracked_at: parse_dt(row.get("cracked_at"))?,
    })
}

pub(super) fn row_to_benchmark(row: &sqlx::sqlite::SqliteRow) -> Result<WorkerBenchmark> {
    Ok(WorkerBenchmark {
        worker_id: row.get("worker_id"),
        hash_mode: row.get::<u32, _>("hash_mode"),
        speed: row.get::<i64, _>("speed") as u64,
        measured_at: parse_dt(row.get("measured_at"))?,
    })
}

pub(super) fn row_to_audit(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    Ok(AuditEntry {
        id: Some(row.get::<i64, _>("id")),
        event_type: row.get("event_type"),
        details: row.get("details"),
        source_ip: row.get("source_ip"),
        worker_id: row.get("worker_id"),
        created_at: parse_dt(row.get("created_at"))?,
    })
}

pub(super) fn row_to_file_record(row: &sqlx::sqlite::SqliteRow) -> Result<FileRecord> {
    Ok(FileRecord {
        id: row.get("id"),
        filename: row.get("filename"),
        file_type: row.get("file_type"),
        size_bytes: row.get("size_bytes"),
        sha256: row.get("sha256"),
        disk_path: row.get("disk_path"),
        uploaded_at: parse_dt(row.get("uploaded_at"))?,
    })
}

// ── Generic lifecycle-status update ─────────────────────────────────────────
//
// Tasks / chunks / campaigns / phases all share the same "set status, plus
// stamp started_at on first transition into Running, plus stamp
// completed_at on first transition into a terminal state, plus run any
// side effects" shape. The trait + helper here collapse the four
// previously-parallel `update_X_status` functions to a single SQL
// dispatcher; per-entity wrappers keep the side effects (file-ref
// release, GC enqueue) since those differ per entity.

/// State-machine classifier for `update_*_status`. The DB-side shape is:
/// - `is_running()` → also stamp `started_at` (preserved if already set)
/// - `is_terminal()` → also stamp `completed_at`
/// - neither → status-only UPDATE
pub(super) trait LifecycleStatus: ToString {
    fn is_running(&self) -> bool;
    fn is_terminal(&self) -> bool;
}

impl LifecycleStatus for TaskStatus {
    fn is_running(&self) -> bool {
        matches!(self, TaskStatus::Running)
    }
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        )
    }
}

impl LifecycleStatus for ChunkStatus {
    // `chunks` has no `started_at` column; a chunk's start is recorded
    // as `assigned_at` at dispatch time.
    fn is_running(&self) -> bool {
        false
    }
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            ChunkStatus::Completed | ChunkStatus::Exhausted | ChunkStatus::Failed
        )
    }
}

impl LifecycleStatus for CampaignStatus {
    fn is_running(&self) -> bool {
        matches!(self, CampaignStatus::Running)
    }
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            CampaignStatus::Completed | CampaignStatus::Failed | CampaignStatus::Cancelled
        )
    }
}

impl LifecycleStatus for PhaseStatus {
    fn is_running(&self) -> bool {
        matches!(self, PhaseStatus::Running)
    }
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            PhaseStatus::Completed
                | PhaseStatus::Exhausted
                | PhaseStatus::Failed
                | PhaseStatus::Skipped
        )
    }
}

/// Run the SQL side of an `update_*_status` call. `table` and `id_col`
/// are static (no SQL injection risk); the status string is bound. The
/// caller wraps this with whatever per-entity side effects (file-ref
/// release, GC enqueue) the transition demands — those vary too much
/// to live inside a generic helper.
pub(super) async fn set_lifecycle_status<S: LifecycleStatus>(
    pool: &SqlitePool,
    table: &'static str,
    id_col: &'static str,
    id: &str,
    status: &S,
) -> Result<()> {
    let now = now_iso();
    let status_str = status.to_string();
    let sql = if status.is_running() {
        format!(
            "UPDATE {table} SET status = ?1, started_at = COALESCE(started_at, ?2) WHERE {id_col} = ?3"
        )
    } else if status.is_terminal() {
        format!("UPDATE {table} SET status = ?1, completed_at = ?2 WHERE {id_col} = ?3")
    } else {
        format!("UPDATE {table} SET status = ?1 WHERE {id_col} = ?2")
    };

    let q = sqlx::query(&sql).bind(&status_str);
    let q = if status.is_running() || status.is_terminal() {
        q.bind(&now).bind(id)
    } else {
        q.bind(id)
    };
    q.execute(pool)
        .await
        .with_context(|| format!("updating {table} status to {status_str}"))?;
    Ok(())
}

mod tasks;
pub use tasks::*;

mod chunks;
pub use chunks::*;

mod workers;
pub use workers::*;

mod enrollment;
pub use enrollment::*;

mod cracked;
pub use cracked::*;

mod benchmarks;
pub use benchmarks::*;

mod audit_log;
pub use audit_log::*;

// ════════════════════════════════════════════════════════════════════════════
// Per-entity sub-modules. As of PR 7's S1 split, sections of this file
// move out one at a time. Each `pub use mod::*` keeps the existing
// `db::function_name` import path intact for callers; nothing outside
// this file should change.
// ════════════════════════════════════════════════════════════════════════════

mod keyspace_cache;
pub use keyspace_cache::*;

mod refs_gc;
pub use refs_gc::*;

mod files;
pub use files::*;

mod worker_cache;
pub use worker_cache::*;

// ════════════════════════════════════════════════════════════════════════════
// System status
// ════════════════════════════════════════════════════════════════════════════

pub async fn get_system_status(pool: &SqlitePool) -> Result<SystemStatus> {
    let tasks_row = sqlx::query(
        "SELECT
           COUNT(*) as total_tasks,
           COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running_tasks
         FROM tasks",
    )
    .fetch_one(pool)
    .await
    .context("fetching task counts")?;

    let workers_row = sqlx::query(
        "SELECT
           COUNT(*) as total_workers,
           COALESCE(SUM(CASE WHEN status != 'disconnected' THEN 1 ELSE 0 END), 0) as connected_workers
         FROM workers"
    )
    .fetch_one(pool)
    .await
    .context("fetching worker counts")?;

    let cracked_row = sqlx::query("SELECT COUNT(*) as cnt FROM cracked_hashes")
        .fetch_one(pool)
        .await
        .context("fetching cracked count")?;

    let speed_row = sqlx::query(
        "SELECT COALESCE(SUM(speed), 0) as aggregate_speed
         FROM chunks
         WHERE status = 'running'",
    )
    .fetch_one(pool)
    .await
    .context("fetching aggregate speed")?;

    Ok(SystemStatus {
        total_tasks: tasks_row.get::<i32, _>("total_tasks") as u32,
        running_tasks: tasks_row.get::<i32, _>("running_tasks") as u32,
        total_workers: workers_row.get::<i32, _>("total_workers") as u32,
        connected_workers: workers_row.get::<i32, _>("connected_workers") as u32,
        total_cracked: cracked_row.get::<i64, _>("cnt") as u64,
        aggregate_speed: speed_row.get::<i64, _>("aggregate_speed") as u64,
    })
}

// ════════════════════════════════════════════════════════════════════════════
// Campaign operations
// ════════════════════════════════════════════════════════════════════════════

pub(super) fn row_to_campaign(row: &sqlx::sqlite::SqliteRow) -> Result<Campaign> {
    let status_str: String = row.get("status");
    let extra_args_json: String = row.get("extra_args");

    Ok(Campaign {
        id: Uuid::parse_str(row.get::<&str, _>("id"))?,
        name: row.get("name"),
        hash_mode: row.get::<u32, _>("hash_mode"),
        original_hash_file_id: row.get("original_hash_file_id"),
        status: CampaignStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        active_phase_index: row
            .get::<Option<i32>, _>("active_phase_index")
            .map(|v| v as u32),
        total_phases: row.get::<i32, _>("total_phases") as u32,
        total_hashes: row.get::<i32, _>("total_hashes") as u32,
        cracked_count: row.get::<i32, _>("cracked_count") as u32,
        priority: row.get::<u8, _>("priority"),
        extra_args: serde_json::from_str(&extra_args_json)
            .context("parsing campaign extra_args JSON")?,
        created_at: parse_dt(row.get("created_at"))?,
        started_at: parse_dt_opt(row.get("started_at"))?,
        completed_at: parse_dt_opt(row.get("completed_at"))?,
    })
}

pub(super) fn row_to_phase(row: &sqlx::sqlite::SqliteRow) -> Result<CampaignPhase> {
    let status_str: String = row.get("status");
    let config_json: String = row.get("config");
    let task_id_str: Option<String> = row.get("task_id");
    let task_id = task_id_str.as_deref().map(Uuid::parse_str).transpose()?;

    Ok(CampaignPhase {
        id: Uuid::parse_str(row.get::<&str, _>("id"))?,
        campaign_id: Uuid::parse_str(row.get::<&str, _>("campaign_id"))?,
        phase_index: row.get::<i32, _>("phase_index") as u32,
        name: row.get("name"),
        status: PhaseStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        config: serde_json::from_str(&config_json).context("parsing phase config JSON")?,
        task_id,
        hash_file_id: row.get("hash_file_id"),
        cracked_count: row.get::<i32, _>("cracked_count") as u32,
        created_at: parse_dt(row.get("created_at"))?,
        started_at: parse_dt_opt(row.get("started_at"))?,
        completed_at: parse_dt_opt(row.get("completed_at"))?,
    })
}

mod campaigns;
pub use campaigns::*;

mod phases;
pub use phases::*;

#[cfg(test)]
mod tests {
    use super::*;

    async fn mem_pool() -> SqlitePool {
        let opts = SqliteConnectOptions::from_str(":memory:")
            .unwrap()
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::raw_sql(INIT_SQL).execute(&pool).await.unwrap();
        // Match init_db's idempotent ALTER TABLE migrations so tests see the
        // same schema a running coord does.
        let _ =
            sqlx::query("ALTER TABLE tasks ADD COLUMN campaign_id TEXT REFERENCES campaigns(id)")
                .execute(&pool)
                .await;
        let _ =
            sqlx::query("CREATE INDEX IF NOT EXISTS idx_tasks_campaign_id ON tasks(campaign_id)")
                .execute(&pool)
                .await;
        let _ = sqlx::query("ALTER TABLE files ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0")
            .execute(&pool)
            .await;
        let _ = sqlx::query("ALTER TABLE files ADD COLUMN gc_state TEXT NOT NULL DEFAULT 'active'")
            .execute(&pool)
            .await;
        pool
    }

    #[test]
    fn parse_dt_accepts_rfc3339_and_naive_forms() {
        let rfc = parse_dt("2026-04-25T10:00:00Z").unwrap();
        assert_eq!(rfc.to_rfc3339(), "2026-04-25T10:00:00+00:00");
        let naive = parse_dt("2026-04-25T10:00:00.500").unwrap();
        assert_eq!(naive.to_rfc3339(), "2026-04-25T10:00:00.500+00:00");
    }

    #[test]
    fn parse_dt_propagates_garbage_instead_of_silent_epoch() {
        // Pre-S13 behaviour: unparseable strings collapsed to UNIX_EPOCH
        // and the monitor treated old chunks as eligible for reassignment.
        // Now they must surface as errors so the row mapper fails loudly.
        assert!(parse_dt("not a timestamp").is_err());
        assert!(parse_dt("").is_err());
        assert!(parse_dt("1970-01-01").is_err());
    }

    #[test]
    fn parse_dt_opt_handles_none_and_some() {
        assert!(parse_dt_opt(None).unwrap().is_none());
        assert!(parse_dt_opt(Some("2026-04-25T10:00:00Z".into())).unwrap().is_some());
        assert!(parse_dt_opt(Some("garbage".into())).is_err());
    }

    #[tokio::test]
    async fn keyspace_cache_miss_returns_none() {
        let pool = mem_pool().await;
        let result = get_cached_keyspace(&pool, "abc", None, 1000).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn keyspace_cache_roundtrip_without_rules() {
        let pool = mem_pool().await;
        insert_cached_keyspace(&pool, "wl_sha", None, 1000, 42_000_000)
            .await
            .unwrap();
        let result = get_cached_keyspace(&pool, "wl_sha", None, 1000)
            .await
            .unwrap();
        assert_eq!(result, Some(42_000_000));
    }

    #[tokio::test]
    async fn keyspace_cache_roundtrip_with_rules() {
        let pool = mem_pool().await;
        insert_cached_keyspace(&pool, "wl_sha", Some("rules_sha"), 1000, 99)
            .await
            .unwrap();
        let result = get_cached_keyspace(&pool, "wl_sha", Some("rules_sha"), 1000)
            .await
            .unwrap();
        assert_eq!(result, Some(99));
    }

    #[tokio::test]
    async fn keyspace_cache_rules_vs_no_rules_are_different_entries() {
        let pool = mem_pool().await;
        insert_cached_keyspace(&pool, "wl", None, 1000, 10)
            .await
            .unwrap();
        insert_cached_keyspace(&pool, "wl", Some("r"), 1000, 20)
            .await
            .unwrap();
        assert_eq!(
            get_cached_keyspace(&pool, "wl", None, 1000).await.unwrap(),
            Some(10)
        );
        assert_eq!(
            get_cached_keyspace(&pool, "wl", Some("r"), 1000)
                .await
                .unwrap(),
            Some(20)
        );
    }

    #[tokio::test]
    async fn keyspace_cache_hash_mode_partitions_keys() {
        let pool = mem_pool().await;
        insert_cached_keyspace(&pool, "wl", None, 1000, 10)
            .await
            .unwrap();
        insert_cached_keyspace(&pool, "wl", None, 22000, 20)
            .await
            .unwrap();
        assert_eq!(
            get_cached_keyspace(&pool, "wl", None, 1000).await.unwrap(),
            Some(10)
        );
        assert_eq!(
            get_cached_keyspace(&pool, "wl", None, 22000).await.unwrap(),
            Some(20)
        );
    }

    #[tokio::test]
    async fn keyspace_cache_insert_is_idempotent() {
        let pool = mem_pool().await;
        insert_cached_keyspace(&pool, "wl", None, 1000, 10)
            .await
            .unwrap();
        insert_cached_keyspace(&pool, "wl", None, 1000, 20)
            .await
            .unwrap();
        assert_eq!(
            get_cached_keyspace(&pool, "wl", None, 1000).await.unwrap(),
            Some(20)
        );
    }

    fn sample_file_record(id: &str, sha: &str, uploaded_at: DateTime<Utc>) -> FileRecord {
        FileRecord {
            id: id.to_string(),
            filename: format!("{id}.txt"),
            file_type: "wordlist".to_string(),
            size_bytes: 100,
            sha256: sha.to_string(),
            disk_path: format!("/tmp/{id}"),
            uploaded_at,
        }
    }

    #[tokio::test]
    async fn find_file_by_sha256_returns_none_when_missing() {
        let pool = mem_pool().await;
        let result = find_file_by_sha256(&pool, "absent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_file_by_sha256_finds_match() {
        let pool = mem_pool().await;
        let rec = sample_file_record("aaa-111", "deadbeef", Utc::now());
        insert_file_record(&pool, &rec).await.unwrap();

        let found = find_file_by_sha256(&pool, "deadbeef")
            .await
            .unwrap()
            .expect("should have found match");
        assert_eq!(found.id, "aaa-111");
    }

    #[tokio::test]
    async fn find_file_by_sha256_skips_deleted_rows() {
        let pool = mem_pool().await;
        let rec = sample_file_record("tomb-1", "tombsha", Utc::now());
        insert_file_record(&pool, &rec).await.unwrap();
        set_file_gc_state_deleted(&pool, "tomb-1").await.unwrap();

        let found = find_file_by_sha256(&pool, "tombsha").await.unwrap();
        assert!(
            found.is_none(),
            "tombstoned row must be invisible to dedup lookup"
        );
    }

    #[tokio::test]
    async fn get_file_record_skips_deleted_rows() {
        let pool = mem_pool().await;
        let rec = sample_file_record("tomb-2", "tombsha2", Utc::now());
        insert_file_record(&pool, &rec).await.unwrap();
        set_file_gc_state_deleted(&pool, "tomb-2").await.unwrap();

        let found = get_file_record(&pool, "tomb-2").await.unwrap();
        assert!(
            found.is_none(),
            "tombstoned row must be invisible to id lookup"
        );
    }

    #[tokio::test]
    async fn set_file_gc_state_deleted_is_idempotent() {
        let pool = mem_pool().await;
        let rec = sample_file_record("tomb-3", "tombsha3", Utc::now());
        insert_file_record(&pool, &rec).await.unwrap();
        set_file_gc_state_deleted(&pool, "tomb-3").await.unwrap();
        set_file_gc_state_deleted(&pool, "tomb-3").await.unwrap();
        // Second call must not error and the row stays tombstoned.
        let found = get_file_record(&pool, "tomb-3").await.unwrap();
        assert!(found.is_none());
    }

    async fn seed_file(pool: &SqlitePool, id: &str, sha: &str) {
        let rec = sample_file_record(id, sha, Utc::now());
        insert_file_record(pool, &rec).await.unwrap();
    }

    async fn make_task(pool: &SqlitePool, hash_file_id: &str) -> Task {
        let req = CreateTaskRequest {
            name: format!("t-{}", Uuid::new_v4()),
            hash_mode: 1000,
            hash_file_id: hash_file_id.to_string(),
            attack_config: AttackConfig::BruteForce {
                mask: "?a?a".to_string(),
                custom_charsets: None,
            },
            priority: 5,
            extra_args: vec![],
        };
        create_task(pool, &req).await.unwrap()
    }

    async fn make_dict_task(pool: &SqlitePool, hash_file_id: &str, wordlist_file_id: &str) -> Task {
        let req = CreateTaskRequest {
            name: format!("t-{}", Uuid::new_v4()),
            hash_mode: 1000,
            hash_file_id: hash_file_id.to_string(),
            attack_config: AttackConfig::Dictionary {
                wordlist_file_id: wordlist_file_id.to_string(),
            },
            priority: 5,
            extra_args: vec![],
        };
        create_task(pool, &req).await.unwrap()
    }

    #[tokio::test]
    async fn create_task_acquires_refs_for_referenced_files() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-001", "sha-hash").await;

        let task = make_task(&pool, "hash-001").await;

        assert_eq!(count_refs_for_sha(&pool, "sha-hash").await.unwrap(), 1);
        // Verify the ref is scoped to this task.
        let shas = delete_refs_by_ref(&pool, "task", &task.id.to_string())
            .await
            .unwrap();
        assert_eq!(shas, vec!["sha-hash".to_string()]);
    }

    #[tokio::test]
    async fn create_task_acquires_refs_for_dict_wordlist() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-002", "sha-hash").await;
        seed_file(&pool, "wl-001", "sha-wl").await;

        let _task = make_dict_task(&pool, "hash-002", "wl-001").await;

        assert_eq!(count_refs_for_sha(&pool, "sha-hash").await.unwrap(), 1);
        assert_eq!(count_refs_for_sha(&pool, "sha-wl").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn terminal_transition_marks_orphan_files_for_gc() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-003", "sha-orphan").await;

        let task = make_task(&pool, "hash-003").await;
        assert_eq!(count_refs_for_sha(&pool, "sha-orphan").await.unwrap(), 1);

        update_task_status(&pool, task.id, TaskStatus::Completed)
            .await
            .unwrap();

        // Ref released, file queued for GC.
        assert_eq!(count_refs_for_sha(&pool, "sha-orphan").await.unwrap(), 0);
        let queue = list_gc_queue(&pool).await.unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].0, "sha-orphan");
    }

    #[tokio::test]
    async fn terminal_transition_doesnt_gc_file_still_in_use() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-004", "sha-shared").await;

        let task_a = make_task(&pool, "hash-004").await;
        let _task_b = make_task(&pool, "hash-004").await;

        // Two tasks referencing the same hash file → refcount = 2.
        assert_eq!(count_refs_for_sha(&pool, "sha-shared").await.unwrap(), 2);

        update_task_status(&pool, task_a.id, TaskStatus::Completed)
            .await
            .unwrap();

        // One still active, so the file must not be queued for GC.
        assert_eq!(count_refs_for_sha(&pool, "sha-shared").await.unwrap(), 1);
        let queue = list_gc_queue(&pool).await.unwrap();
        assert!(
            queue.is_empty(),
            "expected empty GC queue while other task still references the file"
        );
    }

    #[tokio::test]
    async fn pinned_file_is_never_queued_for_gc() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-005", "sha-pinned").await;
        sqlx::query("UPDATE files SET pinned = 1 WHERE id = ?1")
            .bind("hash-005")
            .execute(&pool)
            .await
            .unwrap();

        let task = make_task(&pool, "hash-005").await;
        update_task_status(&pool, task.id, TaskStatus::Completed)
            .await
            .unwrap();

        assert!(is_sha_pinned(&pool, "sha-pinned").await.unwrap());
        let queue = list_gc_queue(&pool).await.unwrap();
        assert!(queue.is_empty(), "pinned file should not enter GC queue");
    }

    #[tokio::test]
    async fn failed_and_cancelled_tasks_also_release_refs() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-006", "sha-fail").await;
        seed_file(&pool, "hash-007", "sha-cancel").await;

        let t1 = make_task(&pool, "hash-006").await;
        let t2 = make_task(&pool, "hash-007").await;

        update_task_status(&pool, t1.id, TaskStatus::Failed)
            .await
            .unwrap();
        update_task_status(&pool, t2.id, TaskStatus::Cancelled)
            .await
            .unwrap();

        let queue = list_gc_queue(&pool).await.unwrap();
        assert_eq!(queue.len(), 2);
    }

    #[tokio::test]
    async fn mark_for_gc_is_idempotent() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-008", "sha-idem").await;
        mark_for_gc(&pool, "sha-idem").await.unwrap();
        mark_for_gc(&pool, "sha-idem").await.unwrap();
        let queue = list_gc_queue(&pool).await.unwrap();
        assert_eq!(queue.len(), 1, "duplicate mark should not duplicate queue");
    }

    #[tokio::test]
    async fn files_by_sha256_returns_all_legacy_duplicates() {
        let pool = mem_pool().await;
        seed_file(&pool, "dup-a", "sha-x").await;
        seed_file(&pool, "dup-b", "sha-x").await;
        let records = files_by_sha256(&pool, "sha-x").await.unwrap();
        assert_eq!(records.len(), 2);
    }

    fn manifest_entry(sha: &str, size: u64) -> crack_common::protocol::CacheManifestEntry {
        crack_common::protocol::CacheManifestEntry {
            sha256: sha.to_string(),
            size_bytes: size,
            last_used_at: Utc::now().to_rfc3339(),
        }
    }

    #[tokio::test]
    async fn sync_manifest_upserts_new_entries() {
        let pool = mem_pool().await;
        let manifest = vec![manifest_entry("aa", 100), manifest_entry("bb", 200)];
        sync_worker_cache_manifest(&pool, "worker-1", &manifest)
            .await
            .unwrap();

        let workers_aa = workers_with_file(&pool, "aa").await.unwrap();
        let workers_bb = workers_with_file(&pool, "bb").await.unwrap();
        assert_eq!(workers_aa, vec!["worker-1".to_string()]);
        assert_eq!(workers_bb, vec!["worker-1".to_string()]);
    }

    #[tokio::test]
    async fn sync_manifest_prunes_removed_entries() {
        let pool = mem_pool().await;
        // Initial: worker has aa + bb.
        sync_worker_cache_manifest(
            &pool,
            "worker-1",
            &[manifest_entry("aa", 100), manifest_entry("bb", 200)],
        )
        .await
        .unwrap();

        // Later heartbeat: only aa remains (worker evicted bb locally).
        sync_worker_cache_manifest(&pool, "worker-1", &[manifest_entry("aa", 100)])
            .await
            .unwrap();

        assert_eq!(
            workers_with_file(&pool, "aa").await.unwrap(),
            vec!["worker-1".to_string()]
        );
        assert!(
            workers_with_file(&pool, "bb").await.unwrap().is_empty(),
            "bb should have been pruned from worker_cache_entries"
        );
    }

    #[tokio::test]
    async fn sync_manifest_handles_large_manifest_without_param_cap() {
        // Regression for the chunked NOT IN path: a manifest larger than the
        // 500-row insert batch must round-trip through the temp-table
        // detour without tripping SQLite's bound-parameter ceiling.
        let pool = mem_pool().await;
        let initial: Vec<_> = (0..1200)
            .map(|i| manifest_entry(&format!("sha-{i:04}"), 10 + i as u64))
            .collect();
        sync_worker_cache_manifest(&pool, "w", &initial)
            .await
            .expect("initial sync should succeed");

        // Drop a couple of shas in the middle and make sure they're pruned
        // while the rest are kept.
        let kept: Vec<_> = initial
            .iter()
            .filter(|e| e.sha256 != "sha-0500" && e.sha256 != "sha-1000")
            .cloned()
            .collect();
        sync_worker_cache_manifest(&pool, "w", &kept)
            .await
            .expect("second sync should succeed");

        assert!(workers_with_file(&pool, "sha-0500").await.unwrap().is_empty());
        assert!(workers_with_file(&pool, "sha-1000").await.unwrap().is_empty());
        assert_eq!(
            workers_with_file(&pool, "sha-0123").await.unwrap(),
            vec!["w".to_string()]
        );
        assert_eq!(
            workers_with_file(&pool, "sha-1199").await.unwrap(),
            vec!["w".to_string()]
        );
    }

    #[tokio::test]
    async fn sync_manifest_empty_clears_all_entries_for_worker() {
        let pool = mem_pool().await;
        sync_worker_cache_manifest(&pool, "worker-1", &[manifest_entry("aa", 100)])
            .await
            .unwrap();
        sync_worker_cache_manifest(&pool, "worker-1", &[])
            .await
            .unwrap();
        assert!(workers_with_file(&pool, "aa").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sync_manifest_is_scoped_per_worker() {
        let pool = mem_pool().await;
        sync_worker_cache_manifest(&pool, "w-a", &[manifest_entry("shared", 50)])
            .await
            .unwrap();
        sync_worker_cache_manifest(&pool, "w-b", &[manifest_entry("shared", 50)])
            .await
            .unwrap();

        let mut workers = workers_with_file(&pool, "shared").await.unwrap();
        workers.sort();
        assert_eq!(workers, vec!["w-a".to_string(), "w-b".to_string()]);

        // Clearing one worker must leave the other's entry alone.
        sync_worker_cache_manifest(&pool, "w-a", &[]).await.unwrap();
        assert_eq!(
            workers_with_file(&pool, "shared").await.unwrap(),
            vec!["w-b".to_string()]
        );
    }

    #[tokio::test]
    async fn set_file_pinned_round_trip() {
        let pool = mem_pool().await;
        seed_file(&pool, "f-pin", "sha-pin").await;

        // Pin → reflected in is_sha_pinned and column.
        let updated = set_file_pinned(&pool, "f-pin", true).await.unwrap();
        assert!(updated);
        assert!(is_sha_pinned(&pool, "sha-pin").await.unwrap());

        // Unpin.
        let updated = set_file_pinned(&pool, "f-pin", false).await.unwrap();
        assert!(updated);
        assert!(!is_sha_pinned(&pool, "sha-pin").await.unwrap());

        // Missing file id returns false.
        assert!(!set_file_pinned(&pool, "nonexistent", true).await.unwrap());
    }

    #[tokio::test]
    async fn unpin_orphan_requeues_for_gc() {
        // Regression for issue #44: file pinned before its task completes
        // never lands in gc_queue (release path's pin gate skips
        // mark_for_gc). Unpinning afterwards must re-evaluate eligibility.
        let pool = mem_pool().await;
        seed_file(&pool, "hash-44a", "sha-44a").await;
        set_file_pinned(&pool, "hash-44a", true).await.unwrap();

        let task = make_task(&pool, "hash-44a").await;
        update_task_status(&pool, task.id, TaskStatus::Completed)
            .await
            .unwrap();

        // Pre-unpin baseline: no refs, pinned, queue empty.
        assert_eq!(count_refs_for_sha(&pool, "sha-44a").await.unwrap(), 0);
        assert!(is_sha_pinned(&pool, "sha-44a").await.unwrap());
        assert!(list_gc_queue(&pool).await.unwrap().is_empty());

        // Unpin — must re-evaluate and queue the now-orphan file.
        assert!(set_file_pinned(&pool, "hash-44a", false).await.unwrap());

        let queue = list_gc_queue(&pool).await.unwrap();
        assert_eq!(queue.len(), 1, "unpin must requeue an orphan file");
        assert_eq!(queue[0].0, "sha-44a");
    }

    #[tokio::test]
    async fn unpin_file_with_active_refs_does_not_queue() {
        // The refcount gate must still win — unpinning a file that's
        // actively in use by a running task must not queue it.
        let pool = mem_pool().await;
        seed_file(&pool, "hash-44b", "sha-44b").await;
        set_file_pinned(&pool, "hash-44b", true).await.unwrap();
        let _task = make_task(&pool, "hash-44b").await;

        assert_eq!(count_refs_for_sha(&pool, "sha-44b").await.unwrap(), 1);
        assert!(set_file_pinned(&pool, "hash-44b", false).await.unwrap());

        assert!(
            list_gc_queue(&pool).await.unwrap().is_empty(),
            "file with live refs must not be queued for GC even after unpin"
        );
    }

    #[tokio::test]
    async fn unpin_file_with_no_refs_and_no_prior_pin_still_queues() {
        // Boundary: a file with no refs and no pin is genuinely orphan.
        // Calling unpin on an already-unpinned file must still queue it
        // (the operation is the right trigger to re-evaluate even when
        // it's a no-op on the column).
        let pool = mem_pool().await;
        seed_file(&pool, "hash-44c", "sha-44c").await;

        assert!(set_file_pinned(&pool, "hash-44c", false).await.unwrap());

        let queue = list_gc_queue(&pool).await.unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].0, "sha-44c");
    }

    #[tokio::test]
    async fn unpin_nonexistent_file_is_safe_noop() {
        // Missing file id must not panic, must not queue anything.
        let pool = mem_pool().await;
        assert!(!set_file_pinned(&pool, "no-such-id", false).await.unwrap());
        assert!(list_gc_queue(&pool).await.unwrap().is_empty());
    }

    async fn seed_worker(pool: &SqlitePool, id: &str, name: &str) {
        let now = Utc::now();
        let worker = Worker {
            id: id.to_string(),
            name: name.to_string(),
            public_key: format!("pk-{id}"),
            devices: vec![],
            hashcat_version: None,
            os: None,
            status: WorkerStatus::Idle,
            created_at: now,
            last_seen_at: now,
        };
        create_or_update_worker(pool, &worker).await.unwrap();
    }

    #[tokio::test]
    async fn cache_summary_includes_workers_with_empty_caches() {
        let pool = mem_pool().await;
        seed_worker(&pool, "w-empty", "empty").await;
        seed_worker(&pool, "w-busy", "busy").await;
        sync_worker_cache_manifest(
            &pool,
            "w-busy",
            &[manifest_entry("aa", 100), manifest_entry("bb", 250)],
        )
        .await
        .unwrap();

        let mut summary = cache_summary_per_worker(&pool).await.unwrap();
        summary.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(summary.len(), 2);
        // w-busy: 2 files, 350 bytes total
        let busy = summary.iter().find(|s| s.0 == "w-busy").unwrap();
        assert_eq!(busy.1, 2);
        assert_eq!(busy.2, 350);
        // w-empty: 0/0, but still listed
        let empty = summary.iter().find(|s| s.0 == "w-empty").unwrap();
        assert_eq!(empty.1, 0);
        assert_eq!(empty.2, 0);
    }

    #[tokio::test]
    async fn list_active_file_shas_returns_active_only() {
        let pool = mem_pool().await;
        seed_file(&pool, "f-active", "sha-a").await;
        seed_file(&pool, "f-marked", "sha-m").await;
        seed_file(&pool, "f-deleting", "sha-d").await;
        seed_file(&pool, "f-empty", "").await;

        sqlx::query("UPDATE files SET gc_state = 'marked' WHERE id = 'f-marked'")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE files SET gc_state = 'deleting' WHERE id = 'f-deleting'")
            .execute(&pool)
            .await
            .unwrap();

        let shas = list_active_file_shas(&pool).await.unwrap();
        assert_eq!(shas, vec!["sha-a".to_string()]);
    }

    #[tokio::test]
    async fn list_active_file_shas_dedups_legacy_duplicates() {
        let pool = mem_pool().await;
        seed_file(&pool, "dup-a", "sha-x").await;
        seed_file(&pool, "dup-b", "sha-x").await;
        let shas = list_active_file_shas(&pool).await.unwrap();
        assert_eq!(shas, vec!["sha-x".to_string()]);
    }

    #[tokio::test]
    async fn remove_worker_cache_entry_targets_only_one_worker() {
        let pool = mem_pool().await;
        sync_worker_cache_manifest(&pool, "w-a", &[manifest_entry("shared", 50)])
            .await
            .unwrap();
        sync_worker_cache_manifest(&pool, "w-b", &[manifest_entry("shared", 50)])
            .await
            .unwrap();

        remove_worker_cache_entry(&pool, "w-a", "shared")
            .await
            .unwrap();

        let workers = workers_with_file(&pool, "shared").await.unwrap();
        assert_eq!(workers, vec!["w-b".to_string()]);
    }

    #[tokio::test]
    async fn sync_manifest_updates_size_and_mtime_on_upsert() {
        let pool = mem_pool().await;
        sync_worker_cache_manifest(&pool, "w1", &[manifest_entry("aa", 100)])
            .await
            .unwrap();
        // Updated size on next heartbeat (e.g. corrupt file now correct).
        sync_worker_cache_manifest(&pool, "w1", &[manifest_entry("aa", 999)])
            .await
            .unwrap();

        let row: i64 = sqlx::query_scalar(
            "SELECT size_bytes FROM worker_cache_entries WHERE worker_id = ?1 AND file_sha256 = ?2",
        )
        .bind("w1")
        .bind("aa")
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, 999);
    }

    #[tokio::test]
    async fn find_file_by_sha256_returns_oldest_when_duplicates_exist() {
        // Simulates a legacy deployment with two rows sharing a sha (the
        // dedup index is non-unique so this can exist). The helper must
        // pick the oldest, which is the canonical one the upload path
        // short-circuits to.
        let pool = mem_pool().await;
        let older = sample_file_record(
            "older-id",
            "shared-sha",
            DateTime::parse_from_rfc3339("2026-04-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let newer = sample_file_record(
            "newer-id",
            "shared-sha",
            DateTime::parse_from_rfc3339("2026-04-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        insert_file_record(&pool, &older).await.unwrap();
        insert_file_record(&pool, &newer).await.unwrap();

        let found = find_file_by_sha256(&pool, "shared-sha")
            .await
            .unwrap()
            .expect("should have found match");
        assert_eq!(found.id, "older-id");
    }

    async fn make_dispatchable_task(pool: &SqlitePool, hash_file_id: &str, keyspace: u64) -> Task {
        let task = make_task(pool, hash_file_id).await;
        set_task_keyspace(pool, task.id, keyspace, 100).await.unwrap();
        update_task_status(pool, task.id, TaskStatus::Running).await.unwrap();
        get_task(pool, task.id).await.unwrap().unwrap()
    }

    fn sample_chunk(task_id: Uuid, skip: u64, limit: u64, worker_id: &str) -> Chunk {
        Chunk {
            id: Uuid::new_v4(),
            task_id,
            skip,
            limit,
            status: ChunkStatus::Dispatched,
            assigned_worker: Some(worker_id.to_string()),
            assigned_at: Some(Utc::now()),
            completed_at: None,
            progress: 0.0,
            speed: 0,
            cracked_count: 0,
        }
    }

    #[tokio::test]
    async fn try_dispatch_advances_cursor_inserts_chunk_and_flips_worker() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-disp-1", "sha-disp-1").await;
        seed_worker(&pool, "w-1", "Worker One").await;
        let task = make_dispatchable_task(&pool, "hash-disp-1", 1_000_000).await;
        let chunk = sample_chunk(task.id, task.next_skip, 50_000, "w-1");

        let outcome =
            try_dispatch_new_chunk(&pool, task.id, task.next_skip, &chunk, "w-1").await.unwrap();
        assert!(matches!(outcome, DispatchOutcome::Dispatched));

        // Cursor advanced by limit.
        let task_after = get_task(&pool, task.id).await.unwrap().unwrap();
        assert_eq!(task_after.next_skip, 50_000);

        // Chunk inserted.
        assert!(get_chunk(&pool, chunk.id).await.unwrap().is_some());

        // Worker flipped to working.
        let workers = get_workers_by_status(&pool, WorkerStatus::Working).await.unwrap();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].id, "w-1");
    }

    #[tokio::test]
    async fn try_dispatch_returns_cursor_moved_when_expected_skip_stale() {
        let pool = mem_pool().await;
        seed_file(&pool, "hash-disp-2", "sha-disp-2").await;
        seed_worker(&pool, "w-2", "Worker Two").await;
        let task = make_dispatchable_task(&pool, "hash-disp-2", 1_000_000).await;

        // Simulate another dispatcher having moved the cursor first.
        sqlx::query("UPDATE tasks SET next_skip = ?1 WHERE id = ?2")
            .bind(123_i64)
            .bind(task.id.to_string())
            .execute(&pool)
            .await
            .unwrap();

        // Our caller still thinks next_skip is 0; the conditional UPDATE
        // must miss and the whole transaction must roll back.
        let chunk = sample_chunk(task.id, 0, 50_000, "w-2");
        let outcome = try_dispatch_new_chunk(&pool, task.id, 0, &chunk, "w-2")
            .await
            .unwrap();
        assert!(matches!(outcome, DispatchOutcome::CursorMoved));

        // No chunk row written.
        assert!(get_chunk(&pool, chunk.id).await.unwrap().is_none());
        // Worker not flipped.
        let task_after = get_task(&pool, task.id).await.unwrap().unwrap();
        assert_eq!(task_after.next_skip, 123, "cursor must remain at competing value");
    }

    /// Scratch directory cleaned up on drop; backfill tests need real files
    /// on disk to read.
    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("crack-coord-backfill-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Sha256 of a known string for assertions below.
    fn sha_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(bytes))
    }

    #[tokio::test]
    async fn backfill_fills_empty_shas_from_disk() {
        let pool = mem_pool().await;
        let dir = TempDir::new();
        let files_dir = dir.path.clone();

        // Seed a legacy row with an empty sha and a matching file on disk.
        let payload = b"legacy file content";
        std::fs::write(files_dir.join("legacy-1"), payload).unwrap();
        let mut rec = sample_file_record("legacy-1", "", Utc::now());
        rec.disk_path = files_dir.join("legacy-1").to_string_lossy().to_string();
        insert_file_record(&pool, &rec).await.unwrap();

        backfill_empty_shas(&pool, &files_dir).await.unwrap();

        let row: String = sqlx::query_scalar("SELECT sha256 FROM files WHERE id = 'legacy-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row, sha_hex(payload));
    }

    #[tokio::test]
    async fn backfill_skips_rows_with_missing_disk_files() {
        let pool = mem_pool().await;
        let dir = TempDir::new();

        // Row exists with empty sha; file is intentionally not on disk.
        let mut rec = sample_file_record("orphan-1", "", Utc::now());
        rec.disk_path = dir.path.join("orphan-1").to_string_lossy().to_string();
        insert_file_record(&pool, &rec).await.unwrap();

        backfill_empty_shas(&pool, &dir.path).await.unwrap();

        // Row's sha stays empty — backfill skipped, no panic, no UPDATE.
        let row: String = sqlx::query_scalar("SELECT sha256 FROM files WHERE id = 'orphan-1'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row, "");
    }

    #[tokio::test]
    async fn backfill_is_idempotent_on_already_filled_rows() {
        let pool = mem_pool().await;
        let dir = TempDir::new();

        // A row with a valid sha must not be re-hashed (the WHERE clause
        // filters it out). Sanity-check that the second backfill run is a
        // no-op even after the first one filled its empty siblings.
        let payload = b"xyz";
        std::fs::write(dir.path.join("filled"), payload).unwrap();
        let mut rec = sample_file_record("filled", &sha_hex(payload), Utc::now());
        rec.disk_path = dir.path.join("filled").to_string_lossy().to_string();
        insert_file_record(&pool, &rec).await.unwrap();

        // Two passes — neither should error or change the row.
        backfill_empty_shas(&pool, &dir.path).await.unwrap();
        backfill_empty_shas(&pool, &dir.path).await.unwrap();

        let row: String = sqlx::query_scalar("SELECT sha256 FROM files WHERE id = 'filled'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row, sha_hex(payload));
    }

    #[tokio::test]
    async fn schema_has_hot_path_indexes() {
        // Regression guard: dispatch / monitor / TUI hot paths assume these
        // indexes exist. Removing one silently degrades coordinator throughput
        // back to full table scans, so tie them to a test.
        let pool = mem_pool().await;
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let names: std::collections::HashSet<_> = names.into_iter().collect();
        for required in [
            "idx_chunks_task_id",
            "idx_chunks_status",
            "idx_chunks_assigned_status",
            "idx_audit_created_at",
            "idx_cracked_cracked_at",
            "idx_tasks_status_priority",
            "idx_tasks_campaign_id",
            "idx_workers_status",
        ] {
            assert!(names.contains(required), "missing index: {required}");
        }
    }
}
