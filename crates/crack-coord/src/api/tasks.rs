use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crack_common::models::*;

use crate::state::{AppEvent, AppState};
use crate::storage::db;

use super::{ApiError, ApiResult};

// ── Response types ──

#[derive(Serialize)]
pub struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: Task,
    pub chunks: Vec<Chunk>,
}

#[derive(Serialize)]
pub struct PotfileStats {
    pub total_cracked: u64,
    pub unique_hashes: u64,
    pub unique_plaintexts: u64,
}

// ── Handlers ──

pub async fn create_task(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateTaskRequest>,
) -> ApiResult<impl IntoResponse> {
    let _file = db::get_file_record(&state.db, &req.hash_file_id)
        .await?
        .ok_or_else(|| {
            ApiError::BadRequest(format!("hash file not found: {}", req.hash_file_id))
        })?;

    // Validate referenced files in the attack config.
    match &req.attack_config {
        AttackConfig::Dictionary { wordlist_file_id } => {
            db::get_file_record(&state.db, wordlist_file_id)
                .await?
                .ok_or_else(|| {
                    ApiError::BadRequest(format!("wordlist file not found: {wordlist_file_id}"))
                })?;
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            db::get_file_record(&state.db, wordlist_file_id)
                .await?
                .ok_or_else(|| {
                    ApiError::BadRequest(format!("wordlist file not found: {wordlist_file_id}"))
                })?;
            db::get_file_record(&state.db, rules_file_id)
                .await?
                .ok_or_else(|| {
                    ApiError::BadRequest(format!("rules file not found: {rules_file_id}"))
                })?;
        }
        AttackConfig::BruteForce { .. } => {}
    }

    let task = db::create_task(&state.db, &req).await?;
    state.emit(AppEvent::TaskCreated { task_id: task.id });

    Ok((StatusCode::CREATED, Json(task)))
}

pub async fn list_tasks(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<Task>>> {
    let tasks = db::list_tasks(&state.db).await?;
    Ok(Json(tasks))
}

pub async fn get_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TaskDetailResponse>> {
    let task = db::get_task(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("task {id} not found")))?;

    let chunks = db::get_chunks_for_task(&state.db, id).await?;

    Ok(Json(TaskDetailResponse { task, chunks }))
}

pub async fn update_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTaskRequest>,
) -> ApiResult<Json<Task>> {
    let _existing = db::get_task(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("task {id} not found")))?;

    if let Some(new_status) = req.status {
        db::update_task_status(&state.db, id, new_status).await?;
    }

    state.emit(AppEvent::TaskUpdated { task_id: id });

    let task = db::get_task(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("task {id} not found")))?;

    Ok(Json(task))
}

pub async fn delete_task(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let _existing = db::get_task(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("task {id} not found")))?;

    db::delete_task(&state.db, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_task_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<CrackedHash>>> {
    let _existing = db::get_task(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("task {id} not found")))?;

    let results = db::get_cracked_for_task(&state.db, id).await?;
    Ok(Json(results))
}

pub async fn system_status(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<SystemStatus>> {
    let status = db::get_system_status(&state.db).await?;
    Ok(Json(status))
}

pub async fn potfile_stats(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<PotfileStats>> {
    let (total_cracked, unique_hashes, unique_plaintexts) =
        db::get_potfile_stats(&state.db).await?;
    Ok(Json(PotfileStats {
        total_cracked,
        unique_hashes,
        unique_plaintexts,
    }))
}

pub async fn potfile_plaintexts(
    State(state): State<Arc<AppState>>,
) -> ApiResult<impl IntoResponse> {
    let plaintexts = db::get_all_plaintexts(&state.db).await?;
    let body = plaintexts.join("\n");

    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        body,
    ))
}
