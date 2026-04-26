//! `campaigns` table: long-running multi-phase cracking jobs. A
//! campaign owns a sequence of `campaign_phases` (each phase resolves
//! to a child `tasks` row), an active phase index, and a campaign-level
//! file ref on the original hash file. Per-phase filtered hash files +
//! wordlists/rules acquire their refs through the spawned tasks.

use anyhow::{Context, Result};
use crack_common::models::{Campaign, CampaignStatus, CreateCampaignRequest};
use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use super::{
    delete_refs_by_ref, get_file_record, insert_file_ref, maybe_mark_orphan_for_gc, now_iso,
    row_to_campaign, set_lifecycle_status, LifecycleStatus,
};

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
    let id_str = id.to_string();
    set_lifecycle_status(pool, "campaigns", "id", &id_str, &status).await?;
    if status.is_terminal() {
        // Release campaign-level refs; mark any orphans for GC.
        let shas = delete_refs_by_ref(pool, "campaign", &id_str).await?;
        for sha in shas {
            maybe_mark_orphan_for_gc(pool, &sha).await?;
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

/// Recompute `campaigns.cracked_count` from the live `cracked_hashes`
/// JOIN. Called after any task in the campaign reports a new cracked
/// hash so the TUI / API see the current total.
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
