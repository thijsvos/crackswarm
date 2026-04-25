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

    tracing::info!("Database initialized at {}", db_path.display());
    Ok(pool)
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
fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    let ndt = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
        .with_context(|| format!("unparseable timestamp: {s:?}"))?;
    Ok(ndt.and_utc())
}

fn parse_dt_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>> {
    s.map(|s| parse_dt(&s)).transpose()
}

fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

// ── Row mapping helpers ──

fn row_to_task(row: &sqlx::sqlite::SqliteRow) -> Result<Task> {
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

fn row_to_chunk(row: &sqlx::sqlite::SqliteRow) -> Result<Chunk> {
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

fn row_to_worker(row: &sqlx::sqlite::SqliteRow) -> Result<Worker> {
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

fn row_to_cracked(row: &sqlx::sqlite::SqliteRow) -> Result<CrackedHash> {
    Ok(CrackedHash {
        id: Some(row.get::<i64, _>("id")),
        task_id: Uuid::parse_str(row.get::<&str, _>("task_id"))?,
        hash: row.get("hash"),
        plaintext: row.get("plaintext"),
        worker_id: row.get("worker_id"),
        cracked_at: parse_dt(row.get("cracked_at"))?,
    })
}

fn row_to_benchmark(row: &sqlx::sqlite::SqliteRow) -> Result<WorkerBenchmark> {
    Ok(WorkerBenchmark {
        worker_id: row.get("worker_id"),
        hash_mode: row.get::<u32, _>("hash_mode"),
        speed: row.get::<i64, _>("speed") as u64,
        measured_at: parse_dt(row.get("measured_at"))?,
    })
}

fn row_to_audit(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    Ok(AuditEntry {
        id: Some(row.get::<i64, _>("id")),
        event_type: row.get("event_type"),
        details: row.get("details"),
        source_ip: row.get("source_ip"),
        worker_id: row.get("worker_id"),
        created_at: parse_dt(row.get("created_at"))?,
    })
}

fn row_to_file_record(row: &sqlx::sqlite::SqliteRow) -> Result<FileRecord> {
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

// ════════════════════════════════════════════════════════════════════════════
// Task CRUD
// ════════════════════════════════════════════════════════════════════════════

pub async fn create_task(pool: &SqlitePool, req: &CreateTaskRequest) -> Result<Task> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let attack_config_json = serde_json::to_string(&req.attack_config)?;
    let extra_args_json = serde_json::to_string(&req.extra_args)?;

    sqlx::query(
        "INSERT INTO tasks (id, name, hash_mode, hash_file_id, attack_config, priority, extra_args, status, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)"
    )
    .bind(id.to_string())
    .bind(&req.name)
    .bind(req.hash_mode)
    .bind(&req.hash_file_id)
    .bind(&attack_config_json)
    .bind(req.priority)
    .bind(&extra_args_json)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting task")?;

    // Acquire refs for every file this task depends on. Keeps the GC loop
    // from reclaiming them out from under us.
    acquire_task_refs_inline(pool, id, &req.hash_file_id, &req.attack_config).await?;

    get_task(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found after insert"))
}

/// Walk the task's referenced files and insert a ref row for each that has
/// a sha256 on record. Silent no-op on files uploaded before Slice 2 (no
/// sha stored) — they're grandfathered in and won't be GC'd by accident.
async fn acquire_task_refs_inline(
    pool: &SqlitePool,
    task_id: Uuid,
    hash_file_id: &str,
    attack_config: &AttackConfig,
) -> Result<()> {
    let mut file_ids: Vec<&str> = vec![hash_file_id];
    match attack_config {
        AttackConfig::BruteForce { .. } => {}
        AttackConfig::Dictionary { wordlist_file_id } => {
            file_ids.push(wordlist_file_id);
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            file_ids.push(wordlist_file_id);
            file_ids.push(rules_file_id);
        }
    }
    let task_id_str = task_id.to_string();
    for file_id in file_ids {
        if let Some(rec) = get_file_record(pool, file_id).await? {
            if !rec.sha256.is_empty() {
                insert_file_ref(pool, &rec.sha256, "task", &task_id_str).await?;
            }
        }
    }
    Ok(())
}

/// Drop all refs held by `task_id` and mark any freshly-orphaned files for
/// GC. Idempotent.
async fn release_task_refs_inline(pool: &SqlitePool, task_id: Uuid) -> Result<()> {
    let shas = delete_refs_by_ref(pool, "task", &task_id.to_string()).await?;
    for sha in shas {
        maybe_mark_orphan_for_gc(pool, &sha).await?;
    }
    Ok(())
}

/// If nothing references this sha and it's not pinned, queue it for GC.
async fn maybe_mark_orphan_for_gc(pool: &SqlitePool, sha: &str) -> Result<()> {
    if count_refs_for_sha(pool, sha).await? > 0 {
        return Ok(());
    }
    if is_sha_pinned(pool, sha).await? {
        return Ok(());
    }
    mark_for_gc(pool, sha).await?;
    Ok(())
}

pub async fn get_task(pool: &SqlitePool, id: Uuid) -> Result<Option<Task>> {
    let row = sqlx::query("SELECT * FROM tasks WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching task")?;

    match row {
        Some(ref r) => Ok(Some(row_to_task(r)?)),
        None => Ok(None),
    }
}

pub async fn list_tasks(pool: &SqlitePool) -> Result<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks ORDER BY priority DESC, created_at ASC")
        .fetch_all(pool)
        .await
        .context("listing tasks")?;

    rows.iter().map(row_to_task).collect()
}

pub async fn update_task_status(pool: &SqlitePool, id: Uuid, status: TaskStatus) -> Result<()> {
    let now = now_iso();
    let status_str = status.to_string();
    let id_str = id.to_string();

    match status {
        TaskStatus::Running => {
            // Set started_at only if not already set
            sqlx::query(
                "UPDATE tasks SET status = ?1, started_at = COALESCE(started_at, ?2) WHERE id = ?3",
            )
            .bind(&status_str)
            .bind(&now)
            .bind(&id_str)
            .execute(pool)
            .await
            .context("updating task status to running")?;
        }
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled => {
            sqlx::query("UPDATE tasks SET status = ?1, completed_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(&now)
                .bind(&id_str)
                .execute(pool)
                .await
                .context("updating task status to terminal")?;
            // Release this task's file refs — any now-orphan files get
            // queued for the GC loop to reclaim on its next pass.
            release_task_refs_inline(pool, id).await?;
        }
        _ => {
            sqlx::query("UPDATE tasks SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(&id_str)
                .execute(pool)
                .await
                .context("updating task status")?;
        }
    }

    Ok(())
}

pub async fn delete_task(pool: &SqlitePool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM tasks WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("deleting task")?;

    Ok(result.rows_affected() > 0)
}

pub async fn increment_task_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<u32> {
    let row = sqlx::query(
        "UPDATE tasks SET cracked_count = cracked_count + ?1 WHERE id = ?2 RETURNING cracked_count",
    )
    .bind(delta)
    .bind(id.to_string())
    .fetch_one(pool)
    .await
    .context("incrementing cracked count")?;

    Ok(row.get::<u32, _>("cracked_count"))
}

pub async fn set_task_keyspace(
    pool: &SqlitePool,
    id: Uuid,
    keyspace: u64,
    total_hashes: u32,
) -> Result<()> {
    sqlx::query("UPDATE tasks SET total_keyspace = ?1, total_hashes = ?2 WHERE id = ?3")
        .bind(keyspace as i64)
        .bind(total_hashes)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("setting task keyspace")?;
    Ok(())
}

/// Outcome of a transactional dispatch attempt — see [`try_dispatch_new_chunk`].
pub enum DispatchOutcome {
    /// All four operations committed.
    Dispatched,
    /// Another caller advanced `tasks.next_skip` between the SELECT and the
    /// conditional UPDATE; nothing was written. Retry by re-reading the
    /// task and computing a fresh chunk.
    CursorMoved,
}

/// Atomically advance a task's cursor, insert a new dispatched chunk, and
/// flip the worker to `Working` — or do none of those.
///
/// The caller has already SELECTed the task (so it observed
/// `expected_next_skip`) and computed `chunk` covering
/// `[expected_next_skip, expected_next_skip + chunk.limit)`. This function
/// runs the four steps inside one transaction with a *conditional* UPDATE
/// keyed on `next_skip = ?expected_next_skip`. If another caller advanced
/// the cursor in the meantime the UPDATE affects 0 rows, the transaction
/// rolls back, and we return `CursorMoved` so the caller can retry.
///
/// Without this, two parallel `assign_next_chunk` calls could both observe
/// the same cursor, dispatch overlapping `[skip, skip+limit)` ranges, and
/// double-assign a stretch of keyspace.
pub async fn try_dispatch_new_chunk(
    pool: &SqlitePool,
    task_id: Uuid,
    expected_next_skip: u64,
    chunk: &Chunk,
    worker_id: &str,
) -> Result<DispatchOutcome> {
    let new_skip = expected_next_skip.saturating_add(chunk.limit);
    let mut tx = pool.begin().await.context("begin dispatch tx")?;

    let cursor_update = sqlx::query(
        "UPDATE tasks SET next_skip = ?1 WHERE id = ?2 AND next_skip = ?3",
    )
    .bind(new_skip as i64)
    .bind(task_id.to_string())
    .bind(expected_next_skip as i64)
    .execute(&mut *tx)
    .await
    .context("conditional cursor advance")?;

    if cursor_update.rows_affected() == 0 {
        // Lost the race; let the caller retry against the moved cursor.
        return Ok(DispatchOutcome::CursorMoved);
    }

    let now = now_iso();
    sqlx::query(
        "INSERT INTO chunks (id, task_id, skip, \"limit\", status, assigned_worker, assigned_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(chunk.id.to_string())
    .bind(chunk.task_id.to_string())
    .bind(chunk.skip as i64)
    .bind(chunk.limit as i64)
    .bind(chunk.status.to_string())
    .bind(&chunk.assigned_worker)
    .bind(chunk.assigned_at.map(|t| t.to_rfc3339()).or(Some(now)))
    .execute(&mut *tx)
    .await
    .context("inserting dispatched chunk")?;

    sqlx::query("UPDATE workers SET status = ?1 WHERE id = ?2")
        .bind(WorkerStatus::Working.to_string())
        .bind(worker_id)
        .execute(&mut *tx)
        .await
        .context("flipping worker to working")?;

    tx.commit().await.context("commit dispatch tx")?;
    Ok(DispatchOutcome::Dispatched)
}

// ════════════════════════════════════════════════════════════════════════════
// Chunk operations
// ════════════════════════════════════════════════════════════════════════════

pub async fn create_chunk(
    pool: &SqlitePool,
    task_id: Uuid,
    skip: u64,
    limit: u64,
) -> Result<Chunk> {
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO chunks (id, task_id, skip, \"limit\", status)
         VALUES (?1, ?2, ?3, ?4, 'pending')",
    )
    .bind(id.to_string())
    .bind(task_id.to_string())
    .bind(skip as i64)
    .bind(limit as i64)
    .execute(pool)
    .await
    .context("inserting chunk")?;

    get_chunk(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("chunk not found after insert"))
}

pub async fn get_chunk(pool: &SqlitePool, id: Uuid) -> Result<Option<Chunk>> {
    let row = sqlx::query("SELECT * FROM chunks WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching chunk")?;

    match row {
        Some(ref r) => Ok(Some(row_to_chunk(r)?)),
        None => Ok(None),
    }
}

pub async fn get_chunks_for_task(pool: &SqlitePool, task_id: Uuid) -> Result<Vec<Chunk>> {
    let rows = sqlx::query("SELECT * FROM chunks WHERE task_id = ?1 ORDER BY skip ASC")
        .bind(task_id.to_string())
        .fetch_all(pool)
        .await
        .context("fetching chunks for task")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn update_chunk_status(pool: &SqlitePool, id: Uuid, status: ChunkStatus) -> Result<()> {
    let now = now_iso();
    let status_str = status.to_string();

    match status {
        ChunkStatus::Completed | ChunkStatus::Exhausted | ChunkStatus::Failed => {
            sqlx::query("UPDATE chunks SET status = ?1, completed_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(&now)
                .bind(id.to_string())
                .execute(pool)
                .await
                .context("updating chunk status (terminal)")?;
        }
        _ => {
            sqlx::query("UPDATE chunks SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(id.to_string())
                .execute(pool)
                .await
                .context("updating chunk status")?;
        }
    }

    Ok(())
}

pub async fn update_chunk_progress(
    pool: &SqlitePool,
    id: Uuid,
    progress: f64,
    speed: u64,
) -> Result<()> {
    sqlx::query("UPDATE chunks SET progress = ?1, speed = ?2 WHERE id = ?3")
        .bind(progress)
        .bind(speed as i64)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("updating chunk progress")?;
    Ok(())
}

pub async fn finalize_chunk_progress(pool: &SqlitePool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE chunks SET progress = 100.0 WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("finalizing chunk progress")?;
    Ok(())
}

/// Claim the oldest pending chunk across all running tasks, assigning it to the
/// given worker. Returns the chunk and its parent task, or None if no pending
/// chunks exist.
pub async fn claim_pending_chunk(
    pool: &SqlitePool,
    worker_id: &str,
) -> Result<Option<(Task, Chunk)>> {
    let now = now_iso();

    // Find the oldest pending chunk from any running task, ordered by priority
    let row = sqlx::query(
        "SELECT c.* FROM chunks c
         JOIN tasks t ON t.id = c.task_id
         WHERE c.status = 'pending' AND t.status = 'running'
         ORDER BY t.priority DESC, c.skip ASC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("finding pending chunk")?;

    let chunk = match row {
        Some(ref r) => row_to_chunk(r)?,
        None => return Ok(None),
    };

    // Claim it: set status to dispatched and assign worker
    let result = sqlx::query(
        "UPDATE chunks SET status = 'dispatched', assigned_worker = ?1, assigned_at = ?2 WHERE id = ?3 AND status = 'pending'"
    )
    .bind(worker_id)
    .bind(&now)
    .bind(chunk.id.to_string())
    .execute(pool)
    .await
    .context("claiming pending chunk")?;

    // Another worker already claimed this chunk between the SELECT and UPDATE
    if result.rows_affected() == 0 {
        return Ok(None);
    }

    let task = get_task(pool, chunk.task_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found for pending chunk"))?;

    // Re-fetch the chunk with updated fields
    let chunk = get_chunk(pool, chunk.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("chunk not found after claim"))?;

    Ok(Some((task, chunk)))
}

#[allow(dead_code)]
pub async fn get_pending_chunks(
    pool: &SqlitePool,
    task_id: Uuid,
    limit: u32,
) -> Result<Vec<Chunk>> {
    let rows = sqlx::query(
        "SELECT * FROM chunks WHERE task_id = ?1 AND status = 'pending' ORDER BY skip ASC LIMIT ?2",
    )
    .bind(task_id.to_string())
    .bind(limit)
    .fetch_all(pool)
    .await
    .context("fetching pending chunks")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn get_abandoned_chunks(pool: &SqlitePool, timeout_secs: i64) -> Result<Vec<Chunk>> {
    let cutoff = (Utc::now() - chrono::Duration::seconds(timeout_secs)).to_rfc3339();

    // Only consider chunks abandoned if the assigned worker is disconnected.
    // Active workers with long-running chunks should not have their work stolen.
    let rows = sqlx::query(
        "SELECT c.* FROM chunks c
         JOIN workers w ON c.assigned_worker = w.id
         WHERE c.status IN ('dispatched', 'running')
           AND c.assigned_at < ?1
           AND w.status = 'disconnected'
         ORDER BY c.assigned_at ASC",
    )
    .bind(&cutoff)
    .fetch_all(pool)
    .await
    .context("fetching abandoned chunks")?;

    rows.iter().map(row_to_chunk).collect()
}

pub async fn abandon_worker_chunks(pool: &SqlitePool, worker_id: &str) -> Result<u64> {
    let result = sqlx::query(
        "UPDATE chunks SET status = 'abandoned', assigned_worker = NULL
         WHERE assigned_worker = ?1 AND status IN ('dispatched', 'running')",
    )
    .bind(worker_id)
    .execute(pool)
    .await
    .context("abandoning worker chunks")?;

    Ok(result.rows_affected())
}

// ════════════════════════════════════════════════════════════════════════════
// Worker operations
// ════════════════════════════════════════════════════════════════════════════

#[allow(dead_code)]
pub async fn create_or_update_worker(pool: &SqlitePool, worker: &Worker) -> Result<()> {
    let now = now_iso();
    let devices_json = serde_json::to_string(&worker.devices)?;
    let status_str = worker.status.to_string();

    sqlx::query(
        "INSERT INTO workers (id, name, public_key, devices, hashcat_version, os, status, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)
         ON CONFLICT(id) DO UPDATE SET
           name = excluded.name,
           devices = excluded.devices,
           hashcat_version = excluded.hashcat_version,
           os = excluded.os,
           status = excluded.status,
           last_seen_at = excluded.last_seen_at"
    )
    .bind(&worker.id)
    .bind(&worker.name)
    .bind(&worker.public_key)
    .bind(&devices_json)
    .bind(&worker.hashcat_version)
    .bind(&worker.os)
    .bind(&status_str)
    .bind(&now)
    .execute(pool)
    .await
    .context("upserting worker")?;

    Ok(())
}

pub async fn get_worker(pool: &SqlitePool, id: &str) -> Result<Option<Worker>> {
    let row = sqlx::query("SELECT * FROM workers WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("fetching worker")?;

    match row {
        Some(ref r) => Ok(Some(row_to_worker(r)?)),
        None => Ok(None),
    }
}

pub async fn list_workers(pool: &SqlitePool) -> Result<Vec<Worker>> {
    let rows = sqlx::query("SELECT * FROM workers ORDER BY name ASC")
        .fetch_all(pool)
        .await
        .context("listing workers")?;

    rows.iter().map(row_to_worker).collect()
}

pub async fn update_worker_status(pool: &SqlitePool, id: &str, status: WorkerStatus) -> Result<()> {
    let status_str = status.to_string();

    sqlx::query("UPDATE workers SET status = ?1 WHERE id = ?2")
        .bind(&status_str)
        .bind(id)
        .execute(pool)
        .await
        .context("updating worker status")?;

    Ok(())
}

pub async fn update_worker_last_seen(pool: &SqlitePool, id: &str) -> Result<()> {
    let now = now_iso();

    sqlx::query("UPDATE workers SET last_seen_at = ?1 WHERE id = ?2")
        .bind(&now)
        .bind(id)
        .execute(pool)
        .await
        .context("updating worker last_seen")?;

    Ok(())
}

pub async fn get_worker_by_pubkey(pool: &SqlitePool, public_key: &str) -> Result<Option<Worker>> {
    let row = sqlx::query("SELECT * FROM workers WHERE public_key = ?1")
        .bind(public_key)
        .fetch_optional(pool)
        .await
        .context("fetching worker by pubkey")?;

    match row {
        Some(ref r) => Ok(Some(row_to_worker(r)?)),
        None => Ok(None),
    }
}

pub async fn is_worker_authorized(pool: &SqlitePool, public_key: &str) -> Result<bool> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM workers WHERE public_key = ?1")
        .bind(public_key)
        .fetch_one(pool)
        .await
        .context("checking worker authorization")?;

    let count: i64 = row.get("cnt");
    Ok(count > 0)
}

pub async fn authorize_worker(pool: &SqlitePool, public_key: &str, name: &str) -> Result<Worker> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_iso();

    sqlx::query(
        "INSERT INTO workers (id, name, public_key, status, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, 'disconnected', ?4, ?4)
         ON CONFLICT(public_key) DO UPDATE SET
           name = excluded.name",
    )
    .bind(&id)
    .bind(name)
    .bind(public_key)
    .bind(&now)
    .execute(pool)
    .await
    .context("authorizing worker")?;

    // Return the worker (either the newly created one or the existing one)
    get_worker_by_pubkey(pool, public_key)
        .await?
        .ok_or_else(|| anyhow::anyhow!("worker not found after authorize"))
}

// ════════════════════════════════════════════════════════════════════════════
// Enrollment tokens
// ════════════════════════════════════════════════════════════════════════════

pub async fn create_enrollment_token(
    pool: &SqlitePool,
    nonce: &str,
    worker_name: &str,
    expires_at: &str,
) -> Result<()> {
    let now = now_iso();
    sqlx::query(
        "INSERT INTO enrollment_tokens (nonce, worker_name, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(nonce)
    .bind(worker_name)
    .bind(&now)
    .bind(expires_at)
    .execute(pool)
    .await
    .context("creating enrollment token")?;
    Ok(())
}

pub async fn validate_enrollment_nonce(pool: &SqlitePool, nonce: &str) -> Result<Option<String>> {
    let now = now_iso();
    let row = sqlx::query(
        "SELECT worker_name FROM enrollment_tokens
         WHERE nonce = ?1 AND used_at IS NULL AND expires_at > ?2",
    )
    .bind(nonce)
    .bind(&now)
    .fetch_optional(pool)
    .await
    .context("validating enrollment nonce")?;

    Ok(row.map(|r| r.get("worker_name")))
}

pub async fn mark_nonce_used(pool: &SqlitePool, nonce: &str, pubkey: &str) -> Result<()> {
    let now = now_iso();
    sqlx::query("UPDATE enrollment_tokens SET used_at = ?1, used_by_pubkey = ?2 WHERE nonce = ?3")
        .bind(&now)
        .bind(pubkey)
        .bind(nonce)
        .execute(pool)
        .await
        .context("marking enrollment nonce as used")?;
    Ok(())
}

// ════════════════════════════════════════════════════════════════════════════
// Cracked hashes
// ════════════════════════════════════════════════════════════════════════════

pub async fn insert_cracked_hash(
    pool: &SqlitePool,
    task_id: Uuid,
    hash: &str,
    plaintext: &str,
    worker_id: &str,
) -> Result<bool> {
    let now = now_iso();

    let result = sqlx::query(
        "INSERT OR IGNORE INTO cracked_hashes (task_id, hash, plaintext, worker_id, cracked_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(task_id.to_string())
    .bind(hash)
    .bind(plaintext)
    .bind(worker_id)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting cracked hash")?;

    // Returns true if a new row was actually inserted (not a duplicate)
    Ok(result.rows_affected() > 0)
}

pub async fn get_cracked_for_task(pool: &SqlitePool, task_id: Uuid) -> Result<Vec<CrackedHash>> {
    let rows =
        sqlx::query("SELECT * FROM cracked_hashes WHERE task_id = ?1 ORDER BY cracked_at ASC")
            .bind(task_id.to_string())
            .fetch_all(pool)
            .await
            .context("fetching cracked hashes for task")?;

    rows.iter().map(row_to_cracked).collect()
}

#[allow(dead_code)]
pub async fn check_potfile(pool: &SqlitePool, hash: &str) -> Result<Option<CrackedHash>> {
    let row = sqlx::query("SELECT * FROM cracked_hashes WHERE hash = ?1 LIMIT 1")
        .bind(hash)
        .fetch_optional(pool)
        .await
        .context("checking potfile for hash")?;

    match row {
        Some(ref r) => Ok(Some(row_to_cracked(r)?)),
        None => Ok(None),
    }
}

#[allow(dead_code)]
pub async fn get_all_cracked_plaintexts(pool: &SqlitePool) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query("SELECT hash, plaintext FROM cracked_hashes ORDER BY cracked_at ASC")
        .fetch_all(pool)
        .await
        .context("fetching all cracked plaintexts")?;

    Ok(rows
        .iter()
        .map(|r| {
            let hash: String = r.get("hash");
            let plaintext: String = r.get("plaintext");
            (hash, plaintext)
        })
        .collect())
}

#[allow(dead_code)]
pub async fn count_total_cracked(pool: &SqlitePool) -> Result<u64> {
    let row = sqlx::query("SELECT COUNT(*) as cnt FROM cracked_hashes")
        .fetch_one(pool)
        .await
        .context("counting total cracked")?;

    let count: i64 = row.get("cnt");
    Ok(count as u64)
}

// ════════════════════════════════════════════════════════════════════════════
// Worker benchmarks
// ════════════════════════════════════════════════════════════════════════════

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

// ════════════════════════════════════════════════════════════════════════════
// Audit log
// ════════════════════════════════════════════════════════════════════════════

pub async fn get_recent_audit(pool: &SqlitePool, limit: u32) -> Result<Vec<AuditEntry>> {
    let rows = sqlx::query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?1")
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("fetching recent audit entries")?;

    rows.iter().map(row_to_audit).collect()
}

// ════════════════════════════════════════════════════════════════════════════
// File records
// ════════════════════════════════════════════════════════════════════════════

pub async fn insert_file_record(pool: &SqlitePool, record: &FileRecord) -> Result<()> {
    let uploaded_at = record.uploaded_at.to_rfc3339();

    sqlx::query(
        "INSERT INTO files (id, filename, file_type, size_bytes, sha256, disk_path, uploaded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(&record.id)
    .bind(&record.filename)
    .bind(&record.file_type)
    .bind(record.size_bytes)
    .bind(&record.sha256)
    .bind(&record.disk_path)
    .bind(&uploaded_at)
    .execute(pool)
    .await
    .context("inserting file record")?;

    Ok(())
}

/// Fetch a file row by ID. Tombstoned rows (`gc_state != 'active'`) are
/// hidden — they exist only as FK targets for historical tasks/campaigns
/// and have no on-disk content, so callers (dedup, monitor, transport)
/// must not see them.
pub async fn get_file_record(pool: &SqlitePool, id: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query("SELECT * FROM files WHERE id = ?1 AND gc_state = 'active'")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("fetching file record")?;

    match row {
        Some(ref r) => Ok(Some(row_to_file_record(r)?)),
        None => Ok(None),
    }
}

/// Look up a file by its sha256 content hash. Returns the oldest matching
/// active row (by uploaded_at) when multiple exist — legacy deployments
/// may have duplicates that predate the upload-dedup short-circuit.
/// Tombstoned rows are skipped so dedup never returns a row whose
/// content has been reclaimed.
pub async fn find_file_by_sha256(pool: &SqlitePool, sha256: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query(
        "SELECT * FROM files WHERE sha256 = ?1 AND gc_state = 'active' \
         ORDER BY uploaded_at ASC LIMIT 1",
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await
    .context("fetching file record by sha256")?;

    match row {
        Some(ref r) => Ok(Some(row_to_file_record(r)?)),
        None => Ok(None),
    }
}

#[allow(dead_code)]
pub async fn delete_file_record(pool: &SqlitePool, id: &str) -> Result<bool> {
    let result = sqlx::query("DELETE FROM files WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await
        .context("deleting file record")?;

    Ok(result.rows_affected() > 0)
}

// ════════════════════════════════════════════════════════════════════════════
// Additional helpers (used by API, transport, scheduler, monitor)
// ════════════════════════════════════════════════════════════════════════════

pub async fn get_cached_keyspace(
    pool: &SqlitePool,
    wordlist_sha256: &str,
    rules_sha256: Option<&str>,
    hash_mode: u32,
) -> Result<Option<u64>> {
    let rules = rules_sha256.unwrap_or("");
    let row = sqlx::query(
        "SELECT keyspace FROM keyspace_cache \
         WHERE wordlist_sha256 = ?1 AND rules_sha256 = ?2 AND hash_mode = ?3",
    )
    .bind(wordlist_sha256)
    .bind(rules)
    .bind(hash_mode as i64)
    .fetch_optional(pool)
    .await
    .context("reading keyspace cache")?;
    Ok(row.map(|r| r.get::<i64, _>("keyspace") as u64))
}

pub async fn insert_cached_keyspace(
    pool: &SqlitePool,
    wordlist_sha256: &str,
    rules_sha256: Option<&str>,
    hash_mode: u32,
    keyspace: u64,
) -> Result<()> {
    let rules = rules_sha256.unwrap_or("");
    sqlx::query(
        "INSERT OR REPLACE INTO keyspace_cache \
         (wordlist_sha256, rules_sha256, hash_mode, keyspace, computed_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(wordlist_sha256)
    .bind(rules)
    .bind(hash_mode as i64)
    .bind(keyspace as i64)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .context("writing keyspace cache")?;
    Ok(())
}

// ── Reference counting + GC ──────────────────────────────────────────────────

/// Insert a reference row for the given sha256 / kind / id. Idempotent
/// (INSERT OR IGNORE) so callers can safely re-run on retry.
pub async fn insert_file_ref(
    pool: &SqlitePool,
    sha256: &str,
    ref_kind: &str,
    ref_id: &str,
) -> Result<()> {
    if sha256.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT OR IGNORE INTO file_refs (file_sha256, ref_kind, ref_id, created_at) \
         VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(sha256)
    .bind(ref_kind)
    .bind(ref_id)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .context("inserting file_ref")?;
    Ok(())
}

/// Delete every ref row with the given kind/id. Returns the distinct set of
/// sha256s that were released — caller should run `release_refs_if_last` on
/// each to queue any orphans for GC.
pub async fn delete_refs_by_ref(
    pool: &SqlitePool,
    ref_kind: &str,
    ref_id: &str,
) -> Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT file_sha256 FROM file_refs WHERE ref_kind = ?1 AND ref_id = ?2",
    )
    .bind(ref_kind)
    .bind(ref_id)
    .fetch_all(pool)
    .await
    .context("selecting refs to delete")?;

    sqlx::query("DELETE FROM file_refs WHERE ref_kind = ?1 AND ref_id = ?2")
        .bind(ref_kind)
        .bind(ref_id)
        .execute(pool)
        .await
        .context("deleting file_refs")?;

    Ok(rows)
}

/// How many rows in `file_refs` currently reference this sha256?
pub async fn count_refs_for_sha(pool: &SqlitePool, sha256: &str) -> Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM file_refs WHERE file_sha256 = ?1")
        .bind(sha256)
        .fetch_one(pool)
        .await
        .context("counting refs for sha")
}

/// Returns true if any file with this sha256 has `pinned = 1`.
pub async fn is_sha_pinned(pool: &SqlitePool, sha256: &str) -> Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM files WHERE sha256 = ?1 AND pinned = 1")
            .bind(sha256)
            .fetch_one(pool)
            .await
            .context("checking pinned state")?;
    Ok(count > 0)
}

/// Transition matching files to `gc_state = 'marked'` and enqueue for GC.
/// Only touches rows currently in `active` state (so re-calls during the
/// `deleting` window are no-ops).
pub async fn mark_for_gc(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'marked' WHERE sha256 = ?1 AND gc_state = 'active'")
        .bind(sha256)
        .execute(pool)
        .await
        .context("marking file for gc")?;
    sqlx::query(
        "INSERT OR IGNORE INTO gc_queue (file_sha256, queued_at, attempts) VALUES (?1, ?2, 0)",
    )
    .bind(sha256)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .context("inserting into gc_queue")?;
    Ok(())
}

/// Drain the GC queue: returns every (sha256, attempts) currently enqueued.
pub async fn list_gc_queue(pool: &SqlitePool) -> Result<Vec<(String, i64)>> {
    let rows = sqlx::query("SELECT file_sha256, attempts FROM gc_queue ORDER BY queued_at ASC")
        .fetch_all(pool)
        .await
        .context("listing gc_queue")?;
    rows.iter()
        .map(|r| {
            Ok((
                r.get::<String, _>("file_sha256"),
                r.get::<i64, _>("attempts"),
            ))
        })
        .collect()
}

/// Remove a sha from the GC queue (either because it was fully collected
/// or because refs came back).
pub async fn remove_from_gc_queue(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("DELETE FROM gc_queue WHERE file_sha256 = ?1")
        .bind(sha256)
        .execute(pool)
        .await
        .context("removing from gc_queue")?;
    Ok(())
}

/// Increment the attempt counter for a stuck GC entry (called when a pass
/// couldn't finish — e.g. file still open elsewhere). Currently
/// vestigial: soft-delete via `set_file_gc_state_deleted` always
/// succeeds, so the GC pass no longer needs to retry. Kept as a
/// primitive for future transient-failure modes (disk I/O hiccups
/// during the on-disk file delete, SQLite contention, etc.).
#[allow(dead_code)]
pub async fn bump_gc_attempts(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE gc_queue SET attempts = attempts + 1 WHERE file_sha256 = ?1")
        .bind(sha256)
        .execute(pool)
        .await
        .context("bumping gc_queue attempts")?;
    Ok(())
}

/// Transition a file from `marked` → `deleting` to reserve it for an
/// in-progress GC pass.
pub async fn set_gc_state_deleting(pool: &SqlitePool, sha256: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'deleting' WHERE sha256 = ?1 AND gc_state = 'marked'")
        .bind(sha256)
        .execute(pool)
        .await
        .context("transitioning files to deleting")?;
    Ok(())
}

/// Soft-delete a file row: the disk file has been reclaimed but the row
/// stays as a tombstone because FK constraints from completed
/// `tasks.hash_file_id` / `campaigns.*` block hard deletion. The row is
/// filtered out of `find_file_by_sha256` and `get_file_record` so dedup
/// never returns a row whose content is gone, while historical joins
/// (audit log, finished tasks listing past hash files) still resolve.
pub async fn set_file_gc_state_deleted(pool: &SqlitePool, file_id: &str) -> Result<()> {
    sqlx::query("UPDATE files SET gc_state = 'deleted' WHERE id = ?1")
        .bind(file_id)
        .execute(pool)
        .await
        .context("transitioning file to deleted")?;
    Ok(())
}

/// Toggle the `pinned` flag on a single file. Pinned files are skipped
/// by the GC loop even when their refcount is zero.
///
/// On unpin, also re-evaluate GC eligibility. The release path
/// (`maybe_mark_orphan_for_gc`) skips marking while a file is pinned,
/// so a file whose refs dropped to zero while pinned never lands in
/// the queue. Without the post-unpin re-check, `crackctl file unpin`
/// is a silent no-op for reclaim — the file stays at
/// `gc_state='active'` with refs=0 forever.
/// `maybe_mark_orphan_for_gc` short-circuits if refs>0 OR pinned, so
/// calling it unconditionally on every unpin is safe (only
/// orphan-eligible files get queued).
pub async fn set_file_pinned(pool: &SqlitePool, file_id: &str, pinned: bool) -> Result<bool> {
    let result = sqlx::query("UPDATE files SET pinned = ?1 WHERE id = ?2")
        .bind(if pinned { 1i64 } else { 0 })
        .bind(file_id)
        .execute(pool)
        .await
        .context("updating files.pinned")?;

    if !pinned && result.rows_affected() > 0 {
        if let Some(rec) = get_file_record(pool, file_id).await? {
            if !rec.sha256.is_empty() {
                maybe_mark_orphan_for_gc(pool, &rec.sha256).await?;
            }
        }
    }
    Ok(result.rows_affected() > 0)
}

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

/// All sha256s currently considered "live" on the coord — i.e. files with
/// `gc_state = 'active'`. Used by reconciliation to tell a (re)connecting
/// worker which content it's still allowed to keep cached.
pub async fn list_active_file_shas(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT sha256 FROM files \
         WHERE sha256 != '' AND gc_state = 'active'",
    )
    .fetch_all(pool)
    .await
    .context("listing active file shas")?;
    Ok(rows)
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
        sqlx::query(
            "CREATE TEMP TABLE IF NOT EXISTS _keep_shas (sha TEXT PRIMARY KEY)",
        )
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
            q.execute(&mut *tx)
                .await
                .context("populating keep set")?;
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

    // Upsert each entry in the new manifest.
    for entry in manifest {
        sqlx::query(
            "INSERT INTO worker_cache_entries \
             (worker_id, file_sha256, size_bytes, last_used_at) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(worker_id, file_sha256) DO UPDATE SET \
             size_bytes = excluded.size_bytes, \
             last_used_at = excluded.last_used_at",
        )
        .bind(worker_id)
        .bind(&entry.sha256)
        .bind(entry.size_bytes as i64)
        .bind(&entry.last_used_at)
        .execute(&mut *tx)
        .await
        .context("upserting worker cache entry")?;
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

/// Remove a single worker/sha pair. Called by the `CacheAck` handler to
/// flush stale rows the agent has told us it no longer has; also handy
/// for explicit cache-drop operator actions.
pub async fn remove_worker_cache_entry(
    pool: &SqlitePool,
    worker_id: &str,
    sha256: &str,
) -> Result<()> {
    sqlx::query("DELETE FROM worker_cache_entries WHERE worker_id = ?1 AND file_sha256 = ?2")
        .bind(worker_id)
        .bind(sha256)
        .execute(pool)
        .await
        .context("deleting worker cache entry")?;
    Ok(())
}

/// Every `files` row sharing this sha256. A legacy deployment can have more
/// than one — we delete all of them when the content is reclaimed.
pub async fn files_by_sha256(pool: &SqlitePool, sha256: &str) -> Result<Vec<FileRecord>> {
    let rows = sqlx::query("SELECT * FROM files WHERE sha256 = ?1")
        .bind(sha256)
        .fetch_all(pool)
        .await
        .context("fetching files by sha256")?;
    rows.iter().map(row_to_file_record).collect()
}

pub async fn list_file_records(pool: &SqlitePool) -> Result<Vec<FileRecord>> {
    let rows = sqlx::query("SELECT * FROM files ORDER BY uploaded_at DESC")
        .fetch_all(pool)
        .await
        .context("listing files")?;

    rows.iter().map(row_to_file_record).collect()
}

/// Find all pending tasks (need keyspace computation and transition to running).
pub async fn get_pending_tasks(pool: &SqlitePool) -> Result<Vec<Task>> {
    let rows = sqlx::query(
        "SELECT * FROM tasks WHERE status = 'pending' ORDER BY priority DESC, created_at ASC",
    )
    .fetch_all(pool)
    .await
    .context("fetching pending tasks")?;

    rows.iter().map(row_to_task).collect()
}

/// Find the highest-priority running task that still has undispatched keyspace.
pub async fn find_next_dispatchable_task(pool: &SqlitePool) -> Result<Option<Task>> {
    let row = sqlx::query(
        "SELECT * FROM tasks
         WHERE status = 'running'
           AND total_keyspace IS NOT NULL
           AND next_skip < total_keyspace
         ORDER BY priority DESC, created_at ASC
         LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .context("finding next dispatchable task")?;

    match row {
        Some(ref r) => Ok(Some(row_to_task(r)?)),
        None => Ok(None),
    }
}

/// Get workers filtered by status.
pub async fn get_workers_by_status(pool: &SqlitePool, status: WorkerStatus) -> Result<Vec<Worker>> {
    let rows = sqlx::query("SELECT * FROM workers WHERE status = ?1 ORDER BY name ASC")
        .bind(status.to_string())
        .fetch_all(pool)
        .await
        .context("fetching workers by status")?;

    rows.iter().map(row_to_worker).collect()
}

/// Potfile stats: (total_cracked, unique_hashes, unique_plaintexts)
pub async fn get_potfile_stats(pool: &SqlitePool) -> Result<(u64, u64, u64)> {
    let row = sqlx::query(
        "SELECT
           COUNT(*) as total,
           COUNT(DISTINCT hash) as unique_hashes,
           COUNT(DISTINCT plaintext) as unique_plaintexts
         FROM cracked_hashes",
    )
    .fetch_one(pool)
    .await
    .context("fetching potfile stats")?;

    Ok((
        row.get::<i64, _>("total") as u64,
        row.get::<i64, _>("unique_hashes") as u64,
        row.get::<i64, _>("unique_plaintexts") as u64,
    ))
}

/// Get recently cracked hashes across all tasks (for TUI).
pub async fn get_recent_cracked(pool: &SqlitePool, limit: u32) -> Result<Vec<CrackedHash>> {
    let rows = sqlx::query("SELECT * FROM cracked_hashes ORDER BY cracked_at DESC LIMIT ?1")
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("fetching recent cracked hashes")?;

    rows.iter().map(row_to_cracked).collect()
}

/// Get or create a worker by public key. Returns the existing worker if found,
/// otherwise creates a new one.
pub async fn get_or_create_worker(
    pool: &SqlitePool,
    pubkey_b64: &str,
    name: &str,
) -> Result<Worker> {
    if let Some(worker) = get_worker_by_pubkey(pool, pubkey_b64).await? {
        return Ok(worker);
    }

    let id = uuid::Uuid::new_v4().to_string();
    let now = now_iso();

    sqlx::query(
        "INSERT INTO workers (id, name, public_key, status, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, 'idle', ?4, ?4)",
    )
    .bind(&id)
    .bind(name)
    .bind(pubkey_b64)
    .bind(&now)
    .execute(pool)
    .await
    .context("creating worker")?;

    get_worker(pool, &id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("worker not found after insert"))
}

/// Update worker metadata (hashcat version, OS, devices).
pub async fn update_worker_info(
    pool: &SqlitePool,
    id: &str,
    hashcat_version: &str,
    os: &str,
    devices: &[DeviceInfo],
) -> Result<()> {
    let devices_json = serde_json::to_string(devices)?;
    let now = now_iso();

    sqlx::query(
        "UPDATE workers SET hashcat_version = ?1, os = ?2, devices = ?3, last_seen_at = ?4
         WHERE id = ?5",
    )
    .bind(hashcat_version)
    .bind(os)
    .bind(&devices_json)
    .bind(&now)
    .bind(id)
    .execute(pool)
    .await
    .context("updating worker info")?;

    Ok(())
}

/// Insert a chunk from a pre-built Chunk struct.
pub async fn insert_chunk(pool: &SqlitePool, chunk: &Chunk) -> Result<()> {
    let now = now_iso();

    sqlx::query(
        "INSERT INTO chunks (id, task_id, skip, \"limit\", status, assigned_worker, assigned_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(chunk.id.to_string())
    .bind(chunk.task_id.to_string())
    .bind(chunk.skip as i64)
    .bind(chunk.limit as i64)
    .bind(chunk.status.to_string())
    .bind(&chunk.assigned_worker)
    .bind(chunk.assigned_at.map(|t| t.to_rfc3339()).or(Some(now)))
    .execute(pool)
    .await
    .context("inserting chunk")?;

    Ok(())
}

/// Export all cracked plaintexts as a list of strings.
pub async fn get_all_plaintexts(pool: &SqlitePool) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT DISTINCT plaintext FROM cracked_hashes ORDER BY plaintext ASC")
        .fetch_all(pool)
        .await
        .context("fetching all plaintexts")?;

    Ok(rows
        .iter()
        .map(|r| r.get::<String, _>("plaintext"))
        .collect())
}

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

fn row_to_campaign(row: &sqlx::sqlite::SqliteRow) -> Result<Campaign> {
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

fn row_to_phase(row: &sqlx::sqlite::SqliteRow) -> Result<CampaignPhase> {
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

pub async fn create_campaign(
    pool: &SqlitePool,
    req: &CreateCampaignRequest,
    total_phases: u32,
) -> Result<Campaign> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let extra_args_json = serde_json::to_string(&req.extra_args)?;

    sqlx::query(
        "INSERT INTO campaigns (id, name, hash_mode, original_hash_file_id, status, total_phases, priority, extra_args, created_at)
         VALUES (?1, ?2, ?3, ?4, 'draft', ?5, ?6, ?7, ?8)"
    )
    .bind(id.to_string())
    .bind(&req.name)
    .bind(req.hash_mode)
    .bind(&req.hash_file_id)
    .bind(total_phases as i32)
    .bind(req.priority)
    .bind(&extra_args_json)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting campaign")?;

    // Acquire a campaign-level ref for the original hash file. Per-phase
    // filtered hash files and wordlists/rules get refs through the tasks
    // the campaign engine spawns.
    if let Some(rec) = get_file_record(pool, &req.hash_file_id).await? {
        if !rec.sha256.is_empty() {
            insert_file_ref(pool, &rec.sha256, "campaign", &id.to_string()).await?;
        }
    }

    get_campaign(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("campaign not found after insert"))
}

pub async fn get_campaign(pool: &SqlitePool, id: Uuid) -> Result<Option<Campaign>> {
    let row = sqlx::query("SELECT * FROM campaigns WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching campaign")?;

    match row {
        Some(ref r) => Ok(Some(row_to_campaign(r)?)),
        None => Ok(None),
    }
}

pub async fn list_campaigns(pool: &SqlitePool) -> Result<Vec<Campaign>> {
    let rows = sqlx::query("SELECT * FROM campaigns ORDER BY priority DESC, created_at ASC")
        .fetch_all(pool)
        .await
        .context("listing campaigns")?;

    rows.iter().map(row_to_campaign).collect()
}

pub async fn update_campaign_status(
    pool: &SqlitePool,
    id: Uuid,
    status: CampaignStatus,
) -> Result<()> {
    let now = now_iso();
    let status_str = status.to_string();
    let id_str = id.to_string();

    match status {
        CampaignStatus::Running => {
            sqlx::query(
                "UPDATE campaigns SET status = ?1, started_at = COALESCE(started_at, ?2) WHERE id = ?3",
            )
            .bind(&status_str)
            .bind(&now)
            .bind(&id_str)
            .execute(pool)
            .await
            .context("updating campaign status to running")?;
        }
        CampaignStatus::Completed | CampaignStatus::Failed | CampaignStatus::Cancelled => {
            sqlx::query("UPDATE campaigns SET status = ?1, completed_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(&now)
                .bind(&id_str)
                .execute(pool)
                .await
                .context("updating campaign status to terminal")?;
            // Release campaign-level refs; mark any orphans for GC.
            let shas = delete_refs_by_ref(pool, "campaign", &id_str).await?;
            for sha in shas {
                maybe_mark_orphan_for_gc(pool, &sha).await?;
            }
        }
        _ => {
            sqlx::query("UPDATE campaigns SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(&id_str)
                .execute(pool)
                .await
                .context("updating campaign status")?;
        }
    }

    Ok(())
}

#[allow(dead_code)]
pub async fn increment_campaign_cracked_count(
    pool: &SqlitePool,
    id: Uuid,
    delta: u32,
) -> Result<()> {
    sqlx::query("UPDATE campaigns SET cracked_count = cracked_count + ?1 WHERE id = ?2")
        .bind(delta)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("incrementing campaign cracked count")?;
    Ok(())
}

pub async fn set_campaign_total_hashes(pool: &SqlitePool, id: Uuid, total: u32) -> Result<()> {
    sqlx::query("UPDATE campaigns SET total_hashes = ?1 WHERE id = ?2")
        .bind(total)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("setting campaign total hashes")?;
    Ok(())
}

pub async fn delete_campaign(pool: &SqlitePool, id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM campaigns WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("deleting campaign")?;
    Ok(result.rows_affected() > 0)
}

pub async fn get_campaigns_by_status(
    pool: &SqlitePool,
    status: CampaignStatus,
) -> Result<Vec<Campaign>> {
    let rows = sqlx::query(
        "SELECT * FROM campaigns WHERE status = ?1 ORDER BY priority DESC, created_at ASC",
    )
    .bind(status.to_string())
    .fetch_all(pool)
    .await
    .context("fetching campaigns by status")?;

    rows.iter().map(row_to_campaign).collect()
}

// ── Campaign Phase operations ──

pub async fn create_phase(
    pool: &SqlitePool,
    campaign_id: Uuid,
    phase_index: u32,
    name: &str,
    config: &PhaseConfig,
) -> Result<CampaignPhase> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let config_json = serde_json::to_string(config)?;

    sqlx::query(
        "INSERT INTO campaign_phases (id, campaign_id, phase_index, name, status, config, created_at)
         VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)"
    )
    .bind(id.to_string())
    .bind(campaign_id.to_string())
    .bind(phase_index as i32)
    .bind(name)
    .bind(&config_json)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting campaign phase")?;

    get_phase(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("phase not found after insert"))
}

pub async fn create_phases_batch(
    pool: &SqlitePool,
    campaign_id: Uuid,
    phases: &[CreatePhaseRequest],
) -> Result<Vec<CampaignPhase>> {
    let mut result = Vec::with_capacity(phases.len());
    for (i, p) in phases.iter().enumerate() {
        let phase = create_phase(pool, campaign_id, i as u32, &p.name, &p.config).await?;
        result.push(phase);
    }
    Ok(result)
}

pub async fn get_phase(pool: &SqlitePool, id: Uuid) -> Result<Option<CampaignPhase>> {
    let row = sqlx::query("SELECT * FROM campaign_phases WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(pool)
        .await
        .context("fetching campaign phase")?;

    match row {
        Some(ref r) => Ok(Some(row_to_phase(r)?)),
        None => Ok(None),
    }
}

pub async fn get_phases_for_campaign(
    pool: &SqlitePool,
    campaign_id: Uuid,
) -> Result<Vec<CampaignPhase>> {
    let rows = sqlx::query(
        "SELECT * FROM campaign_phases WHERE campaign_id = ?1 ORDER BY phase_index ASC",
    )
    .bind(campaign_id.to_string())
    .fetch_all(pool)
    .await
    .context("fetching phases for campaign")?;

    rows.iter().map(row_to_phase).collect()
}

pub async fn get_active_phase(
    pool: &SqlitePool,
    campaign_id: Uuid,
) -> Result<Option<CampaignPhase>> {
    let row = sqlx::query(
        "SELECT cp.* FROM campaign_phases cp
         JOIN campaigns c ON c.id = cp.campaign_id
         WHERE cp.campaign_id = ?1 AND cp.phase_index = c.active_phase_index",
    )
    .bind(campaign_id.to_string())
    .fetch_optional(pool)
    .await
    .context("fetching active phase")?;

    match row {
        Some(ref r) => Ok(Some(row_to_phase(r)?)),
        None => Ok(None),
    }
}

pub async fn update_phase_status(pool: &SqlitePool, id: Uuid, status: PhaseStatus) -> Result<()> {
    let now = now_iso();
    let status_str = status.to_string();

    match status {
        PhaseStatus::Running => {
            sqlx::query(
                "UPDATE campaign_phases SET status = ?1, started_at = COALESCE(started_at, ?2) WHERE id = ?3",
            )
            .bind(&status_str)
            .bind(&now)
            .bind(id.to_string())
            .execute(pool)
            .await
            .context("updating phase status to running")?;
        }
        PhaseStatus::Completed
        | PhaseStatus::Exhausted
        | PhaseStatus::Failed
        | PhaseStatus::Skipped => {
            sqlx::query("UPDATE campaign_phases SET status = ?1, completed_at = ?2 WHERE id = ?3")
                .bind(&status_str)
                .bind(&now)
                .bind(id.to_string())
                .execute(pool)
                .await
                .context("updating phase status to terminal")?;
        }
        _ => {
            sqlx::query("UPDATE campaign_phases SET status = ?1 WHERE id = ?2")
                .bind(&status_str)
                .bind(id.to_string())
                .execute(pool)
                .await
                .context("updating phase status")?;
        }
    }

    Ok(())
}

pub async fn set_phase_task_id(pool: &SqlitePool, phase_id: Uuid, task_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE campaign_phases SET task_id = ?1 WHERE id = ?2")
        .bind(task_id.to_string())
        .bind(phase_id.to_string())
        .execute(pool)
        .await
        .context("setting phase task_id")?;
    Ok(())
}

pub async fn set_phase_hash_file_id(
    pool: &SqlitePool,
    phase_id: Uuid,
    hash_file_id: &str,
) -> Result<()> {
    sqlx::query("UPDATE campaign_phases SET hash_file_id = ?1 WHERE id = ?2")
        .bind(hash_file_id)
        .bind(phase_id.to_string())
        .execute(pool)
        .await
        .context("setting phase hash_file_id")?;
    Ok(())
}

#[allow(dead_code)]
pub async fn increment_phase_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<()> {
    sqlx::query("UPDATE campaign_phases SET cracked_count = cracked_count + ?1 WHERE id = ?2")
        .bind(delta)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("incrementing phase cracked count")?;
    Ok(())
}

pub async fn advance_campaign_phase(
    pool: &SqlitePool,
    campaign_id: Uuid,
    new_index: u32,
) -> Result<()> {
    sqlx::query("UPDATE campaigns SET active_phase_index = ?1 WHERE id = ?2")
        .bind(new_index as i32)
        .bind(campaign_id.to_string())
        .execute(pool)
        .await
        .context("advancing campaign phase")?;
    Ok(())
}

// ── Cross-queries ──

pub async fn get_tasks_for_campaign(pool: &SqlitePool, campaign_id: Uuid) -> Result<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks WHERE campaign_id = ?1 ORDER BY created_at ASC")
        .bind(campaign_id.to_string())
        .fetch_all(pool)
        .await
        .context("fetching tasks for campaign")?;

    rows.iter().map(row_to_task).collect()
}

pub async fn get_cracked_hashes_for_campaign(
    pool: &SqlitePool,
    campaign_id: Uuid,
) -> Result<Vec<CrackedHash>> {
    let rows = sqlx::query(
        "SELECT ch.* FROM cracked_hashes ch
         JOIN tasks t ON t.id = ch.task_id
         WHERE t.campaign_id = ?1
         ORDER BY ch.cracked_at ASC",
    )
    .bind(campaign_id.to_string())
    .fetch_all(pool)
    .await
    .context("fetching cracked hashes for campaign")?;

    rows.iter().map(row_to_cracked).collect()
}

pub async fn sync_campaign_cracked_count(pool: &SqlitePool, campaign_id: Uuid) -> Result<u32> {
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM cracked_hashes ch
         JOIN tasks t ON t.id = ch.task_id
         WHERE t.campaign_id = ?1",
    )
    .bind(campaign_id.to_string())
    .fetch_one(pool)
    .await
    .context("syncing campaign cracked count")?;

    let count = row.get::<i32, _>("cnt") as u32;
    sqlx::query("UPDATE campaigns SET cracked_count = ?1 WHERE id = ?2")
        .bind(count as i32)
        .bind(campaign_id.to_string())
        .execute(pool)
        .await
        .context("updating campaign cracked_count")?;

    Ok(count)
}

pub async fn create_campaign_task(
    pool: &SqlitePool,
    req: &CreateTaskRequest,
    campaign_id: Uuid,
) -> Result<Task> {
    let id = Uuid::new_v4();
    let now = now_iso();
    let attack_config_json = serde_json::to_string(&req.attack_config)?;
    let extra_args_json = serde_json::to_string(&req.extra_args)?;

    sqlx::query(
        "INSERT INTO tasks (id, name, hash_mode, hash_file_id, attack_config, priority, extra_args, status, campaign_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)"
    )
    .bind(id.to_string())
    .bind(&req.name)
    .bind(req.hash_mode)
    .bind(&req.hash_file_id)
    .bind(&attack_config_json)
    .bind(req.priority)
    .bind(&extra_args_json)
    .bind(campaign_id.to_string())
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting campaign task")?;

    // Campaign-spawned tasks acquire their own file refs, same as direct
    // task creation. When the task ends, those refs release and any
    // orphaned files hit the GC queue.
    acquire_task_refs_inline(pool, id, &req.hash_file_id, &req.attack_config).await?;

    get_task(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found after insert"))
}

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
