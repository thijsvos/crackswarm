use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::Utc;
use tracing::{info, warn};
use uuid::Uuid;

use crack_common::models::*;

use crate::state::{AppEvent, AppState};
use crate::storage::{db, files};

use super::analyzer::{self, AnalyzerConfig};

/// Start a campaign: Draft -> Running, activate phase 0, create task for it.
pub async fn start_campaign(state: &Arc<AppState>, campaign_id: Uuid) -> Result<()> {
    let campaign = db::get_campaign(&state.db, campaign_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("campaign {campaign_id} not found"))?;

    if campaign.status != CampaignStatus::Draft {
        anyhow::bail!(
            "campaign {} is not in draft status (current: {})",
            campaign_id,
            campaign.status
        );
    }

    // Count hashes in the original file
    let file_data = files::read_file(&state.files_dir(), &campaign.original_hash_file_id)
        .context("reading original hash file")?;
    let content = String::from_utf8_lossy(&file_data);
    let total_hashes = content.lines().filter(|l| !l.trim().is_empty()).count() as u32;

    if total_hashes == 0 {
        anyhow::bail!("hash file is empty");
    }

    db::set_campaign_total_hashes(&state.db, campaign_id, total_hashes).await?;
    db::update_campaign_status(&state.db, campaign_id, CampaignStatus::Running).await?;
    db::advance_campaign_phase(&state.db, campaign_id, 0).await?;

    state.emit(AppEvent::CampaignCreated { campaign_id });

    // Start phase 0
    let phases = db::get_phases_for_campaign(&state.db, campaign_id).await?;
    if let Some(phase) = phases.first() {
        start_phase(state, &campaign, phase, &campaign.original_hash_file_id).await?;
    }

    db::insert_audit(
        &state.db,
        "campaign_started",
        &format!(
            "Campaign '{}' started with {} hashes, {} phases",
            campaign.name, total_hashes, campaign.total_phases
        ),
        None,
        None,
    )
    .await?;

    Ok(())
}

/// Called when a task completes (from transport handler or monitor).
pub async fn on_task_completed(state: &Arc<AppState>, task_id: Uuid) -> Result<()> {
    let task = match db::get_task(&state.db, task_id).await? {
        Some(t) => t,
        None => return Ok(()),
    };

    let campaign_id = match task.campaign_id {
        Some(id) => id,
        None => return Ok(()),
    };

    let campaign = match db::get_campaign(&state.db, campaign_id).await? {
        Some(c) => c,
        None => return Ok(()),
    };

    if campaign.status != CampaignStatus::Running {
        return Ok(());
    }

    // Find the active phase
    let phase = match db::get_active_phase(&state.db, campaign_id).await? {
        Some(p) => p,
        None => return Ok(()),
    };

    // Only process if this task belongs to the active phase
    if phase.task_id != Some(task_id) {
        return Ok(());
    }

    // Only act on terminal tasks
    if !matches!(
        task.status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    ) {
        return Ok(());
    }

    // Sync cracked count
    db::sync_campaign_cracked_count(&state.db, campaign_id).await?;

    // Reload campaign to get updated counts
    let campaign = db::get_campaign(&state.db, campaign_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("campaign disappeared"))?;

    // Check if all hashes cracked
    if campaign.cracked_count >= campaign.total_hashes && campaign.total_hashes > 0 {
        info!(campaign_id = %campaign_id, "all hashes cracked, completing campaign");
        db::update_phase_status(&state.db, phase.id, PhaseStatus::Completed).await?;
        db::update_campaign_status(&state.db, campaign_id, CampaignStatus::Completed).await?;
        state.emit(AppEvent::CampaignCompleted { campaign_id });
        return Ok(());
    }

    // Determine the hash file for this phase (use phase's file or original)
    let hash_file_id = phase
        .hash_file_id
        .as_deref()
        .unwrap_or(&campaign.original_hash_file_id)
        .to_string();

    // Try to continue within the same phase (next sub-task)
    if task.status != TaskStatus::Failed {
        if let Some(next) = find_next_subtask(state, &campaign, &phase, &task).await? {
            // Create the next sub-task within this phase
            let new_task = create_phase_task(
                state,
                &campaign,
                &phase,
                &hash_file_id,
                &next.mask,
                next.custom_charsets,
                &next.name,
            )
            .await?;
            db::set_phase_task_id(&state.db, phase.id, new_task.id).await?;
            return Ok(());
        }
    }

    // No more sub-tasks in this phase — mark phase done and advance
    let phase_status = if task.status == TaskStatus::Failed {
        PhaseStatus::Failed
    } else if task.cracked_count > 0 || campaign.cracked_count > 0 {
        PhaseStatus::Completed
    } else {
        PhaseStatus::Exhausted
    };
    db::update_phase_status(&state.db, phase.id, phase_status).await?;

    advance_phase(state, campaign_id).await?;

    Ok(())
}

/// A sub-task to create next within the current phase.
struct NextSubTask {
    mask: String,
    custom_charsets: Option<Vec<String>>,
    name: String,
}

/// Determine if there's another sub-task to run within the current phase.
/// Returns None if the phase is fully exhausted.
async fn find_next_subtask(
    state: &Arc<AppState>,
    campaign: &Campaign,
    phase: &CampaignPhase,
    completed_task: &Task,
) -> Result<Option<NextSubTask>> {
    let completed_mask = match &completed_task.attack_config {
        AttackConfig::BruteForce { mask, .. } => mask.clone(),
        // Dictionary and DictionaryWithRules are single-task phases; no sub-task chaining.
        AttackConfig::Dictionary { .. } | AttackConfig::DictionaryWithRules { .. } => {
            return Ok(None);
        }
    };

    match &phase.config {
        PhaseConfig::MultiMask { masks } => {
            // Find which mask index just completed
            let current_idx = masks.iter().position(|m| m.mask == completed_mask);
            let next_idx = match current_idx {
                Some(i) => i + 1,
                None => return Ok(None),
            };
            if next_idx >= masks.len() {
                return Ok(None); // All masks done
            }
            let entry = &masks[next_idx];
            Ok(Some(NextSubTask {
                mask: entry.mask.clone(),
                custom_charsets: entry.custom_charsets.clone(),
                name: format!(
                    "{} — {} [{}/{}]",
                    campaign.name,
                    phase.name,
                    next_idx + 1,
                    masks.len()
                ),
            }))
        }

        PhaseConfig::ExpandingBrute {
            charset,
            min_length: _,
            max_length,
            custom_charsets,
        } => {
            // Current length = number of charset tokens in the completed mask
            let charset_len = charset.len();
            let current_length = if charset_len > 0 {
                completed_mask.len() / charset_len
            } else {
                return Ok(None);
            };
            let next_length = current_length + 1;
            if next_length > *max_length as usize {
                return Ok(None); // All lengths done
            }
            let mask = charset.repeat(next_length);
            Ok(Some(NextSubTask {
                mask,
                custom_charsets: custom_charsets.clone(),
                name: format!("{} — {} [len={}]", campaign.name, phase.name, next_length),
            }))
        }

        PhaseConfig::AutoGenerated {
            min_sample_size,
            max_masks,
        } => {
            // Re-run the analyzer to find the next unrun mask
            let cracked = db::get_cracked_hashes_for_campaign(&state.db, campaign.id).await?;

            // Collect all masks already run (from all phases + the current completed one)
            let mut already_run = HashSet::new();
            let all_phases = db::get_phases_for_campaign(&state.db, campaign.id).await?;
            for p in &all_phases {
                collect_masks_from_config(&p.config, &mut already_run);
            }
            // Also add masks from all tasks in this campaign
            let campaign_tasks = db::get_tasks_for_campaign(&state.db, campaign.id).await?;
            for t in &campaign_tasks {
                if let AttackConfig::BruteForce { mask, .. } = &t.attack_config {
                    already_run.insert(mask.clone());
                }
            }

            let config = AnalyzerConfig {
                min_sample_size: *min_sample_size,
                max_masks_to_generate: *max_masks as usize,
                ..Default::default()
            };

            let result = analyzer::analyze(&cracked, &already_run, &config);
            if let Some(gm) = result.masks.first() {
                Ok(Some(NextSubTask {
                    mask: gm.mask.clone(),
                    custom_charsets: gm.custom_charsets.clone(),
                    name: format!("{} — {} [auto]", campaign.name, phase.name),
                }))
            } else {
                Ok(None)
            }
        }

        // StaticMask, Dictionary, Hybrid — single task, no chaining
        _ => Ok(None),
    }
}

/// Advance to the next phase in the campaign.
fn advance_phase<'a>(
    state: &'a Arc<AppState>,
    campaign_id: Uuid,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(advance_phase_inner(state, campaign_id))
}

async fn advance_phase_inner(state: &Arc<AppState>, campaign_id: Uuid) -> Result<()> {
    let campaign = db::get_campaign(&state.db, campaign_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("campaign not found"))?;

    let current_index = campaign.active_phase_index.unwrap_or(0);
    let next_index = current_index + 1;

    // Check if all hashes are cracked
    let cracked_count = db::sync_campaign_cracked_count(&state.db, campaign_id).await?;
    if cracked_count >= campaign.total_hashes && campaign.total_hashes > 0 {
        info!(campaign_id = %campaign_id, "all hashes cracked during advance");
        db::update_campaign_status(&state.db, campaign_id, CampaignStatus::Completed).await?;
        state.emit(AppEvent::CampaignCompleted { campaign_id });
        return Ok(());
    }

    if next_index >= campaign.total_phases {
        info!(campaign_id = %campaign_id, "all phases exhausted, completing campaign");
        db::update_campaign_status(&state.db, campaign_id, CampaignStatus::Completed).await?;
        state.emit(AppEvent::CampaignCompleted { campaign_id });
        return Ok(());
    }

    // Get next phase
    let phases = db::get_phases_for_campaign(&state.db, campaign_id).await?;
    let next_phase = phases
        .iter()
        .find(|p| p.phase_index == next_index)
        .ok_or_else(|| {
            anyhow::anyhow!("phase {next_index} not found for campaign {campaign_id}")
        })?;

    db::advance_campaign_phase(&state.db, campaign_id, next_index).await?;

    // Create filtered hash file
    let filtered_file_id =
        create_filtered_hash_file(state, campaign_id, &campaign.original_hash_file_id).await?;

    state.emit(AppEvent::CampaignPhaseAdvanced {
        campaign_id,
        phase_index: next_index,
    });

    start_phase(state, &campaign, next_phase, &filtered_file_id).await?;

    Ok(())
}

/// Start a specific phase by resolving its config and creating the first task.
fn start_phase<'a>(
    state: &'a Arc<AppState>,
    campaign: &'a Campaign,
    phase: &'a CampaignPhase,
    hash_file_id: &'a str,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(start_phase_inner(state, campaign, phase, hash_file_id))
}

async fn start_phase_inner(
    state: &Arc<AppState>,
    campaign: &Campaign,
    phase: &CampaignPhase,
    hash_file_id: &str,
) -> Result<()> {
    db::update_phase_status(&state.db, phase.id, PhaseStatus::Running).await?;
    db::set_phase_hash_file_id(&state.db, phase.id, hash_file_id).await?;

    match &phase.config {
        PhaseConfig::StaticMask {
            mask,
            custom_charsets,
        } => {
            let task = create_phase_task(
                state,
                campaign,
                phase,
                hash_file_id,
                mask,
                custom_charsets.clone(),
                &format!("{} — {}", campaign.name, phase.name),
            )
            .await?;
            db::set_phase_task_id(&state.db, phase.id, task.id).await?;
        }

        PhaseConfig::MultiMask { masks } => {
            if let Some(entry) = masks.first() {
                let task = create_phase_task(
                    state,
                    campaign,
                    phase,
                    hash_file_id,
                    &entry.mask,
                    entry.custom_charsets.clone(),
                    &format!("{} — {} [1/{}]", campaign.name, phase.name, masks.len()),
                )
                .await?;
                db::set_phase_task_id(&state.db, phase.id, task.id).await?;
            }
        }

        PhaseConfig::AutoGenerated {
            min_sample_size,
            max_masks,
        } => {
            let cracked = db::get_cracked_hashes_for_campaign(&state.db, campaign.id).await?;

            if (cracked.len() as u32) < *min_sample_size {
                info!(campaign_id = %campaign.id, phase = phase.phase_index,
                    cracked = cracked.len(), min_sample = min_sample_size,
                    "not enough samples for auto-generation, skipping phase");
                db::update_phase_status(&state.db, phase.id, PhaseStatus::Skipped).await?;
                advance_phase(state, campaign.id).await?;
                return Ok(());
            }

            let mut already_run = HashSet::new();
            let all_phases = db::get_phases_for_campaign(&state.db, campaign.id).await?;
            for p in &all_phases {
                collect_masks_from_config(&p.config, &mut already_run);
            }
            let campaign_tasks = db::get_tasks_for_campaign(&state.db, campaign.id).await?;
            for t in &campaign_tasks {
                if let AttackConfig::BruteForce { mask, .. } = &t.attack_config {
                    already_run.insert(mask.clone());
                }
            }

            let config = AnalyzerConfig {
                min_sample_size: *min_sample_size,
                max_masks_to_generate: *max_masks as usize,
                ..Default::default()
            };

            let result = analyzer::analyze(&cracked, &already_run, &config);

            if result.masks.is_empty() {
                info!(campaign_id = %campaign.id, phase = phase.phase_index,
                    "pattern analyzer produced no new masks, skipping phase");
                db::update_phase_status(&state.db, phase.id, PhaseStatus::Skipped).await?;
                db::insert_audit(
                    &state.db,
                    "campaign_phase_skipped",
                    &format!(
                        "Phase {} '{}' skipped: no new masks ({} passwords, {} skeletons)",
                        phase.phase_index,
                        phase.name,
                        result.summary.total_passwords,
                        result.summary.unique_skeletons
                    ),
                    None,
                    None,
                )
                .await?;
                advance_phase(state, campaign.id).await?;
                return Ok(());
            }

            db::insert_audit(
                &state.db,
                "campaign_auto_masks",
                &format!(
                    "Phase {} '{}' generated {} masks from {} passwords ({} skeletons)",
                    phase.phase_index,
                    phase.name,
                    result.masks.len(),
                    result.summary.total_passwords,
                    result.summary.unique_skeletons
                ),
                None,
                None,
            )
            .await?;

            if let Some(gm) = result.masks.first() {
                let task = create_phase_task(
                    state,
                    campaign,
                    phase,
                    hash_file_id,
                    &gm.mask,
                    gm.custom_charsets.clone(),
                    &format!(
                        "{} — {} [auto 1/{}]",
                        campaign.name,
                        phase.name,
                        result.masks.len()
                    ),
                )
                .await?;
                db::set_phase_task_id(&state.db, phase.id, task.id).await?;
            }
        }

        PhaseConfig::ExpandingBrute {
            charset,
            min_length,
            max_length: _,
            custom_charsets,
        } => {
            let mask = charset.repeat(*min_length as usize);
            let task = create_phase_task(
                state,
                campaign,
                phase,
                hash_file_id,
                &mask,
                custom_charsets.clone(),
                &format!("{} — {} [len={}]", campaign.name, phase.name, min_length),
            )
            .await?;
            db::set_phase_task_id(&state.db, phase.id, task.id).await?;
        }

        PhaseConfig::Dictionary {
            wordlist_file_id,
            rules,
        } => {
            let attack_config = if rules.is_empty() {
                AttackConfig::Dictionary {
                    wordlist_file_id: wordlist_file_id.clone(),
                }
            } else {
                // For campaigns with rules, use the first rules file.
                // Future: support multiple rules files.
                AttackConfig::DictionaryWithRules {
                    wordlist_file_id: wordlist_file_id.clone(),
                    rules_file_id: rules[0].clone(),
                }
            };

            let req = CreateTaskRequest {
                name: format!("{} — {}", campaign.name, phase.name),
                hash_mode: campaign.hash_mode,
                hash_file_id: hash_file_id.to_string(),
                attack_config,
                priority: campaign.priority,
                extra_args: campaign.extra_args.clone(),
            };

            let task = db::create_campaign_task(&state.db, &req, campaign.id).await?;
            state.emit(AppEvent::TaskCreated { task_id: task.id });
            db::set_phase_task_id(&state.db, phase.id, task.id).await?;

            info!(campaign_id = %campaign.id, phase = phase.phase_index,
                task_id = %task.id, "created dictionary task for campaign phase");
        }

        PhaseConfig::Hybrid { .. } => {
            warn!(campaign_id = %campaign.id, phase = phase.phase_index,
                "hybrid attacks not yet implemented, skipping phase");
            db::update_phase_status(&state.db, phase.id, PhaseStatus::Skipped).await?;
            advance_phase(state, campaign.id).await?;
        }
    }

    Ok(())
}

/// Create a single task for a phase.
async fn create_phase_task(
    state: &Arc<AppState>,
    campaign: &Campaign,
    phase: &CampaignPhase,
    hash_file_id: &str,
    mask: &str,
    custom_charsets: Option<Vec<String>>,
    name: &str,
) -> Result<Task> {
    let req = CreateTaskRequest {
        name: name.to_string(),
        hash_mode: campaign.hash_mode,
        hash_file_id: hash_file_id.to_string(),
        attack_config: AttackConfig::BruteForce {
            mask: mask.to_string(),
            custom_charsets,
        },
        priority: campaign.priority,
        extra_args: campaign.extra_args.clone(),
    };

    let task = db::create_campaign_task(&state.db, &req, campaign.id).await?;
    state.emit(AppEvent::TaskCreated { task_id: task.id });

    info!(campaign_id = %campaign.id, phase = phase.phase_index,
        task_id = %task.id, mask = %mask, "created task for campaign phase");

    Ok(task)
}

/// Create a filtered hash file containing only uncracked hashes.
async fn create_filtered_hash_file(
    state: &Arc<AppState>,
    campaign_id: Uuid,
    original_file_id: &str,
) -> Result<String> {
    let file_data = files::read_file(&state.files_dir(), original_file_id)
        .context("reading original hash file for filtering")?;
    let content = String::from_utf8_lossy(&file_data);

    let cracked = db::get_cracked_hashes_for_campaign(&state.db, campaign_id).await?;
    let cracked_set: HashSet<&str> = cracked.iter().map(|c| c.hash.as_str()).collect();

    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !cracked_set.contains(trimmed)
        })
        .collect();

    if filtered.is_empty() {
        return Ok(original_file_id.to_string());
    }

    let filtered_content = filtered.join("\n") + "\n";
    let filename = format!("campaign_{campaign_id}_filtered.txt");

    let (file_id, sha256) =
        files::save_file(&state.files_dir(), &filename, filtered_content.as_bytes())?;

    let record = FileRecord {
        id: file_id.clone(),
        filename,
        file_type: "hash".to_string(),
        size_bytes: filtered_content.len() as i64,
        sha256,
        disk_path: file_id.clone(),
        uploaded_at: Utc::now(),
    };
    db::insert_file_record(&state.db, &record).await?;

    info!(campaign_id = %campaign_id,
        original_hashes = content.lines().filter(|l| !l.trim().is_empty()).count(),
        remaining_hashes = filtered.len(),
        file_id = %file_id, "created filtered hash file");

    Ok(file_id)
}

/// Collect all masks referenced in a PhaseConfig into a set.
fn collect_masks_from_config(config: &PhaseConfig, set: &mut HashSet<String>) {
    match config {
        PhaseConfig::StaticMask { mask, .. } => {
            set.insert(mask.clone());
        }
        PhaseConfig::MultiMask { masks } => {
            for entry in masks {
                set.insert(entry.mask.clone());
            }
        }
        PhaseConfig::ExpandingBrute {
            charset,
            min_length,
            max_length,
            ..
        } => {
            for len in *min_length..=*max_length {
                set.insert(charset.repeat(len as usize));
            }
        }
        _ => {}
    }
}

/// Monitor check: sync campaign progress for all running campaigns.
pub async fn check_campaign_progress(state: &Arc<AppState>) -> Result<()> {
    let running = db::get_campaigns_by_status(&state.db, CampaignStatus::Running).await?;

    for campaign in running {
        db::sync_campaign_cracked_count(&state.db, campaign.id).await?;

        if let Some(phase) = db::get_active_phase(&state.db, campaign.id).await? {
            if phase.status == PhaseStatus::Running {
                if let Some(task_id) = phase.task_id {
                    if let Some(task) = db::get_task(&state.db, task_id).await? {
                        if matches!(
                            task.status,
                            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                        ) {
                            on_task_completed(state, task_id).await?;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    use crack_common::models::{MaskEntry, PhaseConfig};

    #[test]
    fn collect_static_mask() {
        let config = PhaseConfig::StaticMask {
            mask: "?a?a?a?a".to_string(),
            custom_charsets: None,
        };
        let mut set = HashSet::new();
        collect_masks_from_config(&config, &mut set);
        assert_eq!(set.len(), 1);
        assert!(set.contains("?a?a?a?a"));
    }

    #[test]
    fn collect_multi_mask() {
        let config = PhaseConfig::MultiMask {
            masks: vec![
                MaskEntry {
                    mask: "?d?d?d?d".to_string(),
                    custom_charsets: None,
                    increment: false,
                },
                MaskEntry {
                    mask: "?l?l?l?l".to_string(),
                    custom_charsets: None,
                    increment: false,
                },
                MaskEntry {
                    mask: "?u?l?d?s".to_string(),
                    custom_charsets: None,
                    increment: false,
                },
            ],
        };
        let mut set = HashSet::new();
        collect_masks_from_config(&config, &mut set);
        assert_eq!(set.len(), 3);
        assert!(set.contains("?d?d?d?d"));
        assert!(set.contains("?l?l?l?l"));
        assert!(set.contains("?u?l?d?s"));
    }

    #[test]
    fn collect_expanding_brute() {
        let config = PhaseConfig::ExpandingBrute {
            charset: "?a".to_string(),
            min_length: 1,
            max_length: 3,
            custom_charsets: None,
        };
        let mut set = HashSet::new();
        collect_masks_from_config(&config, &mut set);
        let expected: HashSet<String> = ["?a", "?a?a", "?a?a?a"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(set, expected);
    }

    #[test]
    fn collect_dictionary_inserts_nothing() {
        let config = PhaseConfig::Dictionary {
            wordlist_file_id: "wl-001".to_string(),
            rules: vec![],
        };
        let mut set = HashSet::new();
        collect_masks_from_config(&config, &mut set);
        assert!(set.is_empty());
    }

    #[test]
    fn collect_auto_generated_inserts_nothing() {
        let config = PhaseConfig::AutoGenerated {
            min_sample_size: 10,
            max_masks: 5,
        };
        let mut set = HashSet::new();
        collect_masks_from_config(&config, &mut set);
        assert!(set.is_empty());
    }
}
