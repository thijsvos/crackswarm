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

    sqlx::raw_sql(INIT_SQL).execute(&pool).await.context("running init migration")?;

    // Migration: add campaign_id to tasks (idempotent)
    let _ = sqlx::query("ALTER TABLE tasks ADD COLUMN campaign_id TEXT REFERENCES campaigns(id)")
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
        );"
    )
    .execute(&pool)
    .await
    .context("creating enrollment_tokens table")?;

    tracing::info!("Database initialized at {}", db_path.display());
    Ok(pool)
}

// ── Helper: parse DateTime from ISO 8601 string ──

fn parse_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| {
            // Fall back to parsing without timezone suffix
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f")
                .map(|ndt| ndt.and_utc())
                .unwrap_or_default()
        })
}

fn parse_dt_opt(s: Option<String>) -> Option<DateTime<Utc>> {
    s.map(|s| parse_dt(&s))
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
        total_keyspace: row.get::<Option<i64>, _>("total_keyspace").map(|v| v as u64),
        next_skip: row.get::<i64, _>("next_skip") as u64,
        priority: row.get::<u8, _>("priority"),
        status: TaskStatus::from_str(&status_str).map_err(|e| anyhow::anyhow!(e))?,
        total_hashes: row.get::<u32, _>("total_hashes"),
        cracked_count: row.get::<u32, _>("cracked_count"),
        extra_args: serde_json::from_str(&extra_args_json)
            .context("parsing extra_args JSON")?,
        campaign_id,
        created_at: parse_dt(row.get("created_at")),
        started_at: parse_dt_opt(row.get("started_at")),
        completed_at: parse_dt_opt(row.get("completed_at")),
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
        assigned_at: parse_dt_opt(row.get("assigned_at")),
        completed_at: parse_dt_opt(row.get("completed_at")),
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
        created_at: parse_dt(row.get("created_at")),
        last_seen_at: parse_dt(row.get("last_seen_at")),
    })
}

fn row_to_cracked(row: &sqlx::sqlite::SqliteRow) -> Result<CrackedHash> {
    Ok(CrackedHash {
        id: Some(row.get::<i64, _>("id")),
        task_id: Uuid::parse_str(row.get::<&str, _>("task_id"))?,
        hash: row.get("hash"),
        plaintext: row.get("plaintext"),
        worker_id: row.get("worker_id"),
        cracked_at: parse_dt(row.get("cracked_at")),
    })
}

fn row_to_benchmark(row: &sqlx::sqlite::SqliteRow) -> Result<WorkerBenchmark> {
    Ok(WorkerBenchmark {
        worker_id: row.get("worker_id"),
        hash_mode: row.get::<u32, _>("hash_mode"),
        speed: row.get::<i64, _>("speed") as u64,
        measured_at: parse_dt(row.get("measured_at")),
    })
}

fn row_to_audit(row: &sqlx::sqlite::SqliteRow) -> Result<AuditEntry> {
    Ok(AuditEntry {
        id: Some(row.get::<i64, _>("id")),
        event_type: row.get("event_type"),
        details: row.get("details"),
        source_ip: row.get("source_ip"),
        worker_id: row.get("worker_id"),
        created_at: parse_dt(row.get("created_at")),
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
        uploaded_at: parse_dt(row.get("uploaded_at")),
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

    get_task(pool, id).await?.ok_or_else(|| anyhow::anyhow!("task not found after insert"))
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

pub async fn increment_task_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<()> {
    sqlx::query("UPDATE tasks SET cracked_count = cracked_count + ?1 WHERE id = ?2")
        .bind(delta)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("incrementing cracked count")?;
    Ok(())
}

pub async fn set_task_keyspace(
    pool: &SqlitePool,
    id: Uuid,
    keyspace: u64,
    total_hashes: u32,
) -> Result<()> {
    sqlx::query(
        "UPDATE tasks SET total_keyspace = ?1, total_hashes = ?2 WHERE id = ?3",
    )
    .bind(keyspace as i64)
    .bind(total_hashes)
    .bind(id.to_string())
    .execute(pool)
    .await
    .context("setting task keyspace")?;
    Ok(())
}

pub async fn advance_task_cursor(pool: &SqlitePool, id: Uuid, new_skip: u64) -> Result<()> {
    sqlx::query("UPDATE tasks SET next_skip = ?1 WHERE id = ?2")
        .bind(new_skip as i64)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("advancing task cursor")?;
    Ok(())
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
         VALUES (?1, ?2, ?3, ?4, 'pending')"
    )
    .bind(id.to_string())
    .bind(task_id.to_string())
    .bind(skip as i64)
    .bind(limit as i64)
    .execute(pool)
    .await
    .context("inserting chunk")?;

    get_chunk(pool, id).await?.ok_or_else(|| anyhow::anyhow!("chunk not found after insert"))
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

pub async fn update_chunk_status(
    pool: &SqlitePool,
    id: Uuid,
    status: ChunkStatus,
) -> Result<()> {
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
    sqlx::query(
        "UPDATE chunks SET progress = ?1, speed = ?2 WHERE id = ?3",
    )
    .bind(progress)
    .bind(speed as i64)
    .bind(id.to_string())
    .execute(pool)
    .await
    .context("updating chunk progress")?;
    Ok(())
}

pub async fn finalize_chunk_progress(pool: &SqlitePool, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE chunks SET progress = 100.0 WHERE id = ?1",
    )
    .bind(id.to_string())
    .execute(pool)
    .await
    .context("finalizing chunk progress")?;
    Ok(())
}

/// Claim the oldest pending chunk across all running tasks, assigning it to the
/// given worker. Returns the chunk and its parent task, or None if no pending
/// chunks exist.
pub async fn claim_pending_chunk(pool: &SqlitePool, worker_id: &str) -> Result<Option<(Task, Chunk)>> {
    let now = now_iso();

    // Find the oldest pending chunk from any running task, ordered by priority
    let row = sqlx::query(
        "SELECT c.* FROM chunks c
         JOIN tasks t ON t.id = c.task_id
         WHERE c.status = 'pending' AND t.status = 'running'
         ORDER BY t.priority DESC, c.skip ASC
         LIMIT 1"
    )
    .fetch_optional(pool)
    .await
    .context("finding pending chunk")?;

    let chunk = match row {
        Some(ref r) => row_to_chunk(r)?,
        None => return Ok(None),
    };

    // Claim it: set status to dispatched and assign worker
    sqlx::query(
        "UPDATE chunks SET status = 'dispatched', assigned_worker = ?1, assigned_at = ?2 WHERE id = ?3 AND status = 'pending'"
    )
    .bind(worker_id)
    .bind(&now)
    .bind(chunk.id.to_string())
    .execute(pool)
    .await
    .context("claiming pending chunk")?;

    let task = get_task(pool, chunk.task_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("task not found for pending chunk"))?;

    // Re-fetch the chunk with updated fields
    let chunk = get_chunk(pool, chunk.id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("chunk not found after claim"))?;

    Ok(Some((task, chunk)))
}

pub async fn get_pending_chunks(pool: &SqlitePool, task_id: Uuid, limit: u32) -> Result<Vec<Chunk>> {
    let rows = sqlx::query(
        "SELECT * FROM chunks WHERE task_id = ?1 AND status = 'pending' ORDER BY skip ASC LIMIT ?2"
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

    let rows = sqlx::query(
        "SELECT * FROM chunks
         WHERE status IN ('dispatched', 'running')
           AND assigned_at < ?1
         ORDER BY assigned_at ASC"
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
         WHERE assigned_worker = ?1 AND status IN ('dispatched', 'running')"
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

pub async fn authorize_worker(
    pool: &SqlitePool,
    public_key: &str,
    name: &str,
) -> Result<Worker> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = now_iso();

    sqlx::query(
        "INSERT INTO workers (id, name, public_key, status, created_at, last_seen_at)
         VALUES (?1, ?2, ?3, 'disconnected', ?4, ?4)
         ON CONFLICT(public_key) DO UPDATE SET
           name = excluded.name"
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
         VALUES (?1, ?2, ?3, ?4)"
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
         WHERE nonce = ?1 AND used_at IS NULL AND expires_at > ?2"
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
    sqlx::query(
        "UPDATE enrollment_tokens SET used_at = ?1, used_by_pubkey = ?2 WHERE nonce = ?3"
    )
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
         VALUES (?1, ?2, ?3, ?4, ?5)"
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
    let rows = sqlx::query(
        "SELECT * FROM cracked_hashes WHERE task_id = ?1 ORDER BY cracked_at ASC"
    )
    .bind(task_id.to_string())
    .fetch_all(pool)
    .await
    .context("fetching cracked hashes for task")?;

    rows.iter().map(row_to_cracked).collect()
}

pub async fn check_potfile(pool: &SqlitePool, hash: &str) -> Result<Option<CrackedHash>> {
    let row = sqlx::query(
        "SELECT * FROM cracked_hashes WHERE hash = ?1 LIMIT 1"
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
    .context("checking potfile for hash")?;

    match row {
        Some(ref r) => Ok(Some(row_to_cracked(r)?)),
        None => Ok(None),
    }
}

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
           measured_at = excluded.measured_at"
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
    let row = sqlx::query(
        "SELECT * FROM worker_benchmarks WHERE worker_id = ?1 AND hash_mode = ?2"
    )
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

pub async fn insert_audit(
    pool: &SqlitePool,
    event_type: &str,
    details: &str,
    source_ip: Option<&str>,
    worker_id: Option<&str>,
) -> Result<()> {
    let now = now_iso();

    sqlx::query(
        "INSERT INTO audit_log (event_type, details, source_ip, worker_id, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )
    .bind(event_type)
    .bind(details)
    .bind(source_ip)
    .bind(worker_id)
    .bind(&now)
    .execute(pool)
    .await
    .context("inserting audit entry")?;

    Ok(())
}

pub async fn get_recent_audit(pool: &SqlitePool, limit: u32) -> Result<Vec<AuditEntry>> {
    let rows = sqlx::query(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?1"
    )
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
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
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

pub async fn get_file_record(pool: &SqlitePool, id: &str) -> Result<Option<FileRecord>> {
    let row = sqlx::query("SELECT * FROM files WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .context("fetching file record")?;

    match row {
        Some(ref r) => Ok(Some(row_to_file_record(r)?)),
        None => Ok(None),
    }
}

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
    let rows = sqlx::query(
        "SELECT * FROM cracked_hashes ORDER BY cracked_at DESC LIMIT ?1",
    )
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
    .bind(chunk.assigned_at.map(|t| t.to_rfc3339()).or_else(|| Some(now)))
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

    Ok(rows.iter().map(|r| r.get::<String, _>("plaintext")).collect())
}

// ════════════════════════════════════════════════════════════════════════════
// System status
// ════════════════════════════════════════════════════════════════════════════

pub async fn get_system_status(pool: &SqlitePool) -> Result<SystemStatus> {
    let tasks_row = sqlx::query(
        "SELECT
           COUNT(*) as total_tasks,
           COALESCE(SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END), 0) as running_tasks
         FROM tasks"
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
         WHERE status = 'running'"
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
        active_phase_index: row.get::<Option<i32>, _>("active_phase_index").map(|v| v as u32),
        total_phases: row.get::<i32, _>("total_phases") as u32,
        total_hashes: row.get::<i32, _>("total_hashes") as u32,
        cracked_count: row.get::<i32, _>("cracked_count") as u32,
        priority: row.get::<u8, _>("priority"),
        extra_args: serde_json::from_str(&extra_args_json)
            .context("parsing campaign extra_args JSON")?,
        created_at: parse_dt(row.get("created_at")),
        started_at: parse_dt_opt(row.get("started_at")),
        completed_at: parse_dt_opt(row.get("completed_at")),
    })
}

fn row_to_phase(row: &sqlx::sqlite::SqliteRow) -> Result<CampaignPhase> {
    let status_str: String = row.get("status");
    let config_json: String = row.get("config");
    let task_id_str: Option<String> = row.get("task_id");
    let task_id = task_id_str
        .as_deref()
        .map(Uuid::parse_str)
        .transpose()?;

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
        created_at: parse_dt(row.get("created_at")),
        started_at: parse_dt_opt(row.get("started_at")),
        completed_at: parse_dt_opt(row.get("completed_at")),
    })
}

pub async fn create_campaign(pool: &SqlitePool, req: &CreateCampaignRequest, total_phases: u32) -> Result<Campaign> {
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

    get_campaign(pool, id).await?.ok_or_else(|| anyhow::anyhow!("campaign not found after insert"))
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

pub async fn update_campaign_status(pool: &SqlitePool, id: Uuid, status: CampaignStatus) -> Result<()> {
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

pub async fn increment_campaign_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<()> {
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

pub async fn get_campaigns_by_status(pool: &SqlitePool, status: CampaignStatus) -> Result<Vec<Campaign>> {
    let rows = sqlx::query("SELECT * FROM campaigns WHERE status = ?1 ORDER BY priority DESC, created_at ASC")
        .bind(status.to_string())
        .fetch_all(pool)
        .await
        .context("fetching campaigns by status")?;

    rows.iter().map(row_to_campaign).collect()
}

// ── Campaign Phase operations ──

pub async fn create_phase(pool: &SqlitePool, campaign_id: Uuid, phase_index: u32, name: &str, config: &PhaseConfig) -> Result<CampaignPhase> {
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

    get_phase(pool, id).await?.ok_or_else(|| anyhow::anyhow!("phase not found after insert"))
}

pub async fn create_phases_batch(pool: &SqlitePool, campaign_id: Uuid, phases: &[CreatePhaseRequest]) -> Result<Vec<CampaignPhase>> {
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

pub async fn get_phases_for_campaign(pool: &SqlitePool, campaign_id: Uuid) -> Result<Vec<CampaignPhase>> {
    let rows = sqlx::query("SELECT * FROM campaign_phases WHERE campaign_id = ?1 ORDER BY phase_index ASC")
        .bind(campaign_id.to_string())
        .fetch_all(pool)
        .await
        .context("fetching phases for campaign")?;

    rows.iter().map(row_to_phase).collect()
}

pub async fn get_active_phase(pool: &SqlitePool, campaign_id: Uuid) -> Result<Option<CampaignPhase>> {
    let row = sqlx::query(
        "SELECT cp.* FROM campaign_phases cp
         JOIN campaigns c ON c.id = cp.campaign_id
         WHERE cp.campaign_id = ?1 AND cp.phase_index = c.active_phase_index"
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
        PhaseStatus::Completed | PhaseStatus::Exhausted | PhaseStatus::Failed | PhaseStatus::Skipped => {
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

pub async fn set_phase_hash_file_id(pool: &SqlitePool, phase_id: Uuid, hash_file_id: &str) -> Result<()> {
    sqlx::query("UPDATE campaign_phases SET hash_file_id = ?1 WHERE id = ?2")
        .bind(hash_file_id)
        .bind(phase_id.to_string())
        .execute(pool)
        .await
        .context("setting phase hash_file_id")?;
    Ok(())
}

pub async fn increment_phase_cracked_count(pool: &SqlitePool, id: Uuid, delta: u32) -> Result<()> {
    sqlx::query("UPDATE campaign_phases SET cracked_count = cracked_count + ?1 WHERE id = ?2")
        .bind(delta)
        .bind(id.to_string())
        .execute(pool)
        .await
        .context("incrementing phase cracked count")?;
    Ok(())
}

pub async fn advance_campaign_phase(pool: &SqlitePool, campaign_id: Uuid, new_index: u32) -> Result<()> {
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

pub async fn get_cracked_hashes_for_campaign(pool: &SqlitePool, campaign_id: Uuid) -> Result<Vec<CrackedHash>> {
    let rows = sqlx::query(
        "SELECT ch.* FROM cracked_hashes ch
         JOIN tasks t ON t.id = ch.task_id
         WHERE t.campaign_id = ?1
         ORDER BY ch.cracked_at ASC"
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
         WHERE t.campaign_id = ?1"
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

pub async fn create_campaign_task(pool: &SqlitePool, req: &CreateTaskRequest, campaign_id: Uuid) -> Result<Task> {
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

    get_task(pool, id).await?.ok_or_else(|| anyhow::anyhow!("task not found after insert"))
}
