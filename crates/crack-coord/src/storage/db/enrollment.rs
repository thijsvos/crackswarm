//! `enrollment_tokens` table: one-shot nonces for first-connect worker
//! enrollment. The coord issues a token via `crackctl worker enroll`,
//! the agent presents the nonce on first handshake, and the coord
//! marks it used so it can't be replayed.

use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

use super::now_iso;

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

/// Atomically consume a one-shot enrollment nonce.
///
/// The `WHERE ... AND used_at IS NULL` clause makes the check-and-mark a single
/// atomic statement, closing the TOCTOU window where two concurrent handshakes
/// could both validate (and enroll under different pubkeys) from one token.
///
/// Returns `Ok(true)` only if this call transitioned the nonce from unused to
/// used (i.e. it won the race). `Ok(false)` means the nonce was already
/// consumed — the caller MUST reject the worker.
///
/// # Errors
/// Returns an error if the database update fails.
pub async fn mark_nonce_used(pool: &SqlitePool, nonce: &str, pubkey: &str) -> Result<bool> {
    let now = now_iso();
    let result = sqlx::query(
        "UPDATE enrollment_tokens SET used_at = ?1, used_by_pubkey = ?2
         WHERE nonce = ?3 AND used_at IS NULL",
    )
    .bind(&now)
    .bind(pubkey)
    .bind(nonce)
    .execute(pool)
    .await
    .context("marking enrollment nonce as used")?;
    Ok(result.rows_affected() > 0)
}
