mod campaigns;
mod files;
mod tasks;
mod workers;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::state::AppState;

// ── API Error ──

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("internal error: {err:#}");
        ApiError::Internal("internal server error".to_string())
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("database error: {err}");
        ApiError::Internal("internal database error".to_string())
    }
}

impl From<std::io::Error> for ApiError {
    fn from(err: std::io::Error) -> Self {
        tracing::error!("IO error: {err}");
        ApiError::Internal("internal IO error".to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };

        let body = ErrorResponse { error: message };
        (status, Json(body)).into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub type ApiResult<T> = Result<T, ApiError>;

// ── Router ──

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Tasks
        .route(
            "/api/v1/tasks",
            post(tasks::create_task).get(tasks::list_tasks),
        )
        .route(
            "/api/v1/tasks/{id}",
            get(tasks::get_task)
                .patch(tasks::update_task)
                .delete(tasks::delete_task),
        )
        .route("/api/v1/tasks/{id}/results", get(tasks::get_task_results))
        // Files — uploads are streamed directly to disk, so the global
        // 512 MiB limit doesn't apply. Disabled only on this route.
        .route(
            "/api/v1/files",
            post(files::upload_file)
                .get(files::list_files)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/api/v1/files/{id}", get(files::download_file))
        // Workers
        .route("/api/v1/workers", get(workers::list_workers))
        .route("/api/v1/workers/authorize", post(workers::authorize_worker))
        .route("/api/v1/workers/enroll", post(workers::enroll_worker))
        // Campaigns
        .route(
            "/api/v1/campaigns",
            post(campaigns::create_campaign).get(campaigns::list_campaigns),
        )
        .route(
            "/api/v1/campaigns/{id}",
            get(campaigns::get_campaign)
                .patch(campaigns::update_campaign)
                .delete(campaigns::delete_campaign),
        )
        .route(
            "/api/v1/campaigns/{id}/phases",
            get(campaigns::get_campaign_phases),
        )
        .route(
            "/api/v1/campaigns/{id}/start",
            post(campaigns::start_campaign_handler),
        )
        .route(
            "/api/v1/campaigns/{id}/results",
            get(campaigns::get_campaign_results),
        )
        .route(
            "/api/v1/campaigns/templates",
            get(campaigns::list_templates),
        )
        // System
        .route("/api/v1/status", get(tasks::system_status))
        .route("/api/v1/potfile/stats", get(tasks::potfile_stats))
        .route("/api/v1/potfile/plaintexts", get(tasks::potfile_plaintexts))
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
        .with_state(state)
}
