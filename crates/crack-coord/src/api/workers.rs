use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;

use crack_common::models::Worker;

use crate::state::AppState;
use crate::storage::db;

use super::ApiResult;

// ── Request types ──

#[derive(Debug, Deserialize)]
pub struct AuthorizeWorkerRequest {
    pub public_key: String,
    pub name: String,
}

// ── Handlers ──

/// GET /api/v1/workers - List all known workers.
pub async fn list_workers(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<Worker>>> {
    let workers = db::list_workers(&state.db).await?;
    Ok(Json(workers))
}

/// POST /api/v1/workers/authorize - Pre-authorize a worker by public key.
pub async fn authorize_worker(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AuthorizeWorkerRequest>,
) -> ApiResult<impl IntoResponse> {
    let worker = db::authorize_worker(&state.db, &req.public_key, &req.name).await?;
    Ok((StatusCode::CREATED, Json(worker)))
}
