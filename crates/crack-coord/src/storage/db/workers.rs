//! `workers` table: worker identity (pubkey-keyed) + status + heartbeat
//! metadata. Authorization is bool: a row exists in `workers` iff the
//! pubkey was either pre-authorized via `crackctl worker authorize` or
//! enrolled via a one-shot enrollment token.

use anyhow::{Context, Result};
use crack_common::models::{DeviceInfo, Worker, WorkerStatus};
use sqlx::{Row, SqlitePool};

use super::{now_iso, row_to_worker};

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

/// Get workers filtered by status.
pub async fn get_workers_by_status(pool: &SqlitePool, status: WorkerStatus) -> Result<Vec<Worker>> {
    let rows = sqlx::query("SELECT * FROM workers WHERE status = ?1 ORDER BY name ASC")
        .bind(status.to_string())
        .fetch_all(pool)
        .await
        .context("fetching workers by status")?;

    rows.iter().map(row_to_worker).collect()
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
