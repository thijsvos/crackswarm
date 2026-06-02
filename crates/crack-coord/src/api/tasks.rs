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

/// A task plus its chunks — body of `GET /api/v1/tasks/:id`.
#[derive(Serialize)]
pub struct TaskDetailResponse {
    #[serde(flatten)]
    pub task: Task,
    pub chunks: Vec<Chunk>,
}

/// Aggregate potfile counters — body of `GET /api/v1/potfile/stats`.
#[derive(Serialize)]
pub struct PotfileStats {
    pub total_cracked: u64,
    pub unique_hashes: u64,
    pub unique_plaintexts: u64,
}

// ── Handlers ──

/// `POST /api/v1/tasks` — create a task and prepare it (hash count + keyspace).
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

pub async fn list_tasks(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<Task>>> {
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

pub async fn system_status(State(state): State<Arc<AppState>>) -> ApiResult<Json<SystemStatus>> {
    let status = db::get_system_status(&state.db).await?;
    Ok(Json(status))
}

pub async fn potfile_stats(State(state): State<Arc<AppState>>) -> ApiResult<Json<PotfileStats>> {
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
    use axum::body::{Body, Bytes};
    use futures_util::TryStreamExt;
    use sqlx::Row;

    // Stream rows from SQLite straight to the response instead of loading every
    // plaintext into a Vec and re-allocating via join — a huge potfile would
    // otherwise spike coordinator memory. Errors propagate as a broken body
    // (the client sees a failed transfer) rather than silent truncation.
    let pool = state.db.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);
    tokio::spawn(async move {
        let mut rows =
            sqlx::query("SELECT DISTINCT plaintext FROM cracked_hashes ORDER BY plaintext ASC")
                .fetch(&pool);
        loop {
            match rows.try_next().await {
                Ok(Some(row)) => {
                    let mut line: String = match row.try_get("plaintext") {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    line.push('\n');
                    if tx.send(Ok(Bytes::from(line))).await.is_err() {
                        break; // client hung up
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                    break;
                }
            }
        }
    });

    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));
    Ok((
        StatusCode::OK,
        [("content-type", "text/plain; charset=utf-8")],
        Body::from_stream(stream),
    ))
}
