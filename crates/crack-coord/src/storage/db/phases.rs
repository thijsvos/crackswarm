//! `campaign_phases` table: ordered sub-tasks of a campaign. A phase
//! has a `PhaseConfig` (mask / dictionary / auto-generated / hybrid),
//! tracks its own status, and points at the `tasks` row that runs it.

use anyhow::{Context, Result};
use crack_common::models::{CampaignPhase, CreatePhaseRequest, PhaseConfig, PhaseStatus};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::{now_iso, row_to_phase, set_lifecycle_status};

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
    set_lifecycle_status(pool, "campaign_phases", "id", &id.to_string(), &status).await
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
