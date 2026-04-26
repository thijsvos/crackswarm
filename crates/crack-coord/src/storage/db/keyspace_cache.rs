//! `keyspace_cache` table: memoize the result of `hashcat --keyspace`
//! for a given (wordlist_sha, rules_sha, hash_mode) tuple. Computing
//! keyspace requires hashcat to scan the wordlist linearly, which is
//! the slow part of starting a dictionary task — caching the answer
//! shaves minutes off subsequent task creations against the same input.

use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{Row, SqlitePool};

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
