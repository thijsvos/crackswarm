use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crack_common::models::{EnrollmentToken, Worker};

use crate::state::AppState;
use crate::storage::db;

use super::ApiResult;

// ── Request types ──

#[derive(Debug, Deserialize)]
pub struct AuthorizeWorkerRequest {
    pub public_key: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct EnrollWorkerRequest {
    pub name: String,
    #[serde(default = "default_expires_minutes")]
    pub expires_minutes: u64,
}

fn default_expires_minutes() -> u64 {
    60
}

#[derive(Debug, Serialize)]
pub struct EnrollWorkerResponse {
    pub token: String,
    pub message: String,
}

// ── Handlers ──

/// GET /api/v1/workers - List all known workers.
pub async fn list_workers(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<Worker>>> {
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

/// POST /api/v1/workers/enroll - Generate an enrollment token for a new worker.
pub async fn enroll_worker(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrollWorkerRequest>,
) -> ApiResult<impl IntoResponse> {
    // Generate 16 random bytes as hex nonce
    let nonce_bytes: [u8; 16] = rand::random();
    let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    // Compute expires_at
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(req.expires_minutes as i64);
    let expires_at_str = expires_at.to_rfc3339();

    // Store in DB
    db::create_enrollment_token(&state.db, &nonce, &req.name, &expires_at_str).await?;

    // Build EnrollmentToken
    let token = EnrollmentToken {
        coord_pubkey: state.keypair.public_key_b64(),
        nonce,
        worker_name: req.name.clone(),
        expires_at: expires_at_str,
        server_addr: state.bind_addr.clone(),
    };

    // Serialize to JSON, then base64-encode
    let token_json = serde_json::to_vec(&token)
        .map_err(|e| super::ApiError::Internal(format!("serialization error: {e}")))?;
    let token_b64 = base64::engine::general_purpose::STANDARD.encode(&token_json);

    let message = format!(
        "On the worker, run:\n  crack-agent enroll --token '{token_b64}'\n\n\
         To override the server address:\n  crack-agent enroll --token '{token_b64}' --server <ip>:8443"
    );

    Ok((
        StatusCode::CREATED,
        Json(EnrollWorkerResponse {
            token: token_b64,
            message,
        }),
    ))
}
