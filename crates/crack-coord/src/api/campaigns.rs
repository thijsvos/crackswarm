use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

use crack_common::models::*;

use crate::campaign;
use crate::state::AppState;
use crate::storage::db;

use super::{ApiError, ApiResult};

// ── Response types ──

#[derive(Serialize)]
pub struct CampaignDetailResponse {
    #[serde(flatten)]
    pub campaign: Campaign,
    pub phases: Vec<CampaignPhase>,
}

// ── Handlers ──

pub async fn create_campaign(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCampaignRequest>,
) -> ApiResult<impl IntoResponse> {
    // Verify hash file exists
    let _file = db::get_file_record(&state.db, &req.hash_file_id)
        .await?
        .ok_or_else(|| ApiError::BadRequest(format!("hash file not found: {}", req.hash_file_id)))?;

    // Resolve phases from template or request
    let phases: Vec<CreatePhaseRequest> = if let Some(template_name) = &req.template {
        let templates = campaign::templates::builtin_templates();
        let template = templates
            .iter()
            .find(|t| t.name == *template_name)
            .ok_or_else(|| ApiError::BadRequest(format!("unknown template: {template_name}")))?;

        template
            .phases
            .iter()
            .map(|p| CreatePhaseRequest {
                name: p.name.clone(),
                config: p.config.clone(),
            })
            .collect()
    } else if !req.phases.is_empty() {
        req.phases.clone()
    } else {
        return Err(ApiError::BadRequest(
            "either 'phases' or 'template' must be provided".to_string(),
        ));
    };

    let total_phases = phases.len() as u32;
    let c = db::create_campaign(&state.db, &req, total_phases).await?;
    db::create_phases_batch(&state.db, c.id, &phases).await?;

    // Re-fetch with correct total_phases
    let c = db::get_campaign(&state.db, c.id)
        .await?
        .ok_or_else(|| ApiError::Internal("campaign not found after create".to_string()))?;

    Ok((StatusCode::CREATED, Json(c)))
}

pub async fn list_campaigns(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<Campaign>>> {
    let campaigns = db::list_campaigns(&state.db).await?;
    Ok(Json(campaigns))
}

pub async fn get_campaign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CampaignDetailResponse>> {
    let c = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    let phases = db::get_phases_for_campaign(&state.db, id).await?;

    Ok(Json(CampaignDetailResponse {
        campaign: c,
        phases,
    }))
}

pub async fn update_campaign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCampaignRequest>,
) -> ApiResult<Json<Campaign>> {
    let _existing = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    if let Some(new_status) = req.status {
        db::update_campaign_status(&state.db, id, new_status).await?;
    }

    let c = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    Ok(Json(c))
}

pub async fn delete_campaign(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let _existing = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    db::delete_campaign(&state.db, id).await?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn start_campaign_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Campaign>> {
    campaign::start_campaign(&state, id)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let c = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    Ok(Json(c))
}

pub async fn get_campaign_phases(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<CampaignPhase>>> {
    let _existing = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    let phases = db::get_phases_for_campaign(&state.db, id).await?;
    Ok(Json(phases))
}

pub async fn get_campaign_results(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<CrackedHash>>> {
    let _existing = db::get_campaign(&state.db, id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("campaign {id} not found")))?;

    let results = db::get_cracked_hashes_for_campaign(&state.db, id).await?;
    Ok(Json(results))
}

pub async fn list_templates() -> ApiResult<Json<Vec<CampaignTemplate>>> {
    Ok(Json(campaign::templates::builtin_templates()))
}
