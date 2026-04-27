//! `audit_log` table: persistent record of security-relevant events
//! (worker connect/disconnect, enrollment outcomes, chunk failures,
//! campaign state transitions). Inserts go through the
//! `crate::audit::run_audit_flusher` background task; this module
//! exists for the read-side helper the TUI consumes.

use anyhow::{Context, Result};
use crack_common::models::AuditEntry;
use sqlx::SqlitePool;

use super::row_to_audit;

pub async fn get_recent_audit(pool: &SqlitePool, limit: u32) -> Result<Vec<AuditEntry>> {
    let rows = sqlx::query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?1")
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("fetching recent audit entries")?;

    rows.iter().map(row_to_audit).collect()
}
