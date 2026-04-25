use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::info;

use crack_common::models::FileRecord;

use crate::state::AppState;
use crate::storage::{db, files};

use super::{ApiError, ApiResult};

pub async fn upload_file(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let files_dir = state.files_dir();

    let mut file_type = "hash".to_string();
    let mut saved: Option<(String, String, u64, String)> = None; // (file_id, sha256, size, filename)

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart error: {e}")))?
    {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                let filename = field.file_name().unwrap_or("upload").to_string();

                // Stream the field straight to a `.partial` file while hashing
                // incrementally. Nothing is buffered in RAM beyond the current
                // chunk — supports arbitrary upload sizes bounded only by disk.
                let mut writer = files::FileWriter::create(&files_dir, &filename)
                    .await
                    .map_err(|e| {
                        ApiError::Internal(format!("failed to open file for writing: {e}"))
                    })?;

                loop {
                    match field.chunk().await {
                        Ok(Some(chunk)) => {
                            if let Err(e) = writer.write_chunk(&chunk).await {
                                writer.abort().await;
                                return Err(ApiError::Internal(format!(
                                    "failed to write chunk: {e}"
                                )));
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            writer.abort().await;
                            return Err(ApiError::BadRequest(format!(
                                "failed to read upload stream: {e}"
                            )));
                        }
                    }
                }

                let (file_id, sha256, size) = writer
                    .finalize()
                    .await
                    .map_err(|e| ApiError::Internal(format!("failed to finalize upload: {e}")))?;

                saved = Some((file_id, sha256, size, filename));
            }
            "file_type" => {
                let value = field
                    .text()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("failed to read file_type: {e}")))?;
                if !value.is_empty() {
                    file_type = value;
                }
            }
            _ => {}
        }
    }

    let (file_id, sha256, size_bytes, filename) =
        saved.ok_or_else(|| ApiError::BadRequest("missing 'file' field".to_string()))?;

    // Content dedup: if we already have a file with this sha256, drop the
    // one we just wrote and return the existing record. Keeps the operator
    // command identical (`crackctl file upload …`) while avoiding duplicate
    // on-disk copies of the same content across re-uploads.
    if let Some(existing) = db::find_file_by_sha256(&state.db, &sha256).await? {
        if let Err(e) = files::delete_file(&files_dir, &file_id) {
            // Not fatal — disk orphan will get picked up by future GC.
            tracing::warn!(
                file_id = %file_id,
                error = %e,
                "dedup: failed to remove newly-written duplicate from disk"
            );
        }
        info!(
            existing_id = %existing.id,
            filename = %filename,
            sha256 = %sha256,
            "dedup: returning existing file record for matching sha256"
        );
        return Ok((StatusCode::OK, Json(existing)));
    }

    // Build disk path for the record
    let disk_path = files_dir.join(&file_id).to_string_lossy().to_string();

    // Create DB record
    let record = FileRecord {
        id: file_id,
        filename,
        file_type,
        size_bytes: size_bytes as i64,
        sha256,
        disk_path,
        uploaded_at: Utc::now(),
    };
    db::insert_file_record(&state.db, &record).await?;

    Ok((StatusCode::CREATED, Json(record)))
}

pub async fn list_files(State(state): State<Arc<AppState>>) -> ApiResult<Json<Vec<FileRecord>>> {
    let records = db::list_file_records(&state.db).await?;
    Ok(Json(records))
}

/// Returned by `GET /api/v1/server-info`. Clients use this to detect
/// whether their upload source is on the same device as the coord's
/// file store; on a match, they can request a hard-link instead of
/// streaming bytes.
#[derive(Serialize, Deserialize)]
pub struct ServerInfo {
    /// Absolute path to the coord's `files_dir` on disk.
    pub files_dir: String,
    /// Device ID of the files_dir's filesystem (0 on non-Unix platforms).
    pub device_id: u64,
}

pub async fn server_info(State(state): State<Arc<AppState>>) -> ApiResult<Json<ServerInfo>> {
    let files_dir = state.files_dir();
    tokio::fs::create_dir_all(&files_dir).await?;
    let device_id = device_id_of(&files_dir)?;
    Ok(Json(ServerInfo {
        files_dir: files_dir.to_string_lossy().to_string(),
        device_id,
    }))
}

#[derive(Deserialize)]
pub struct HardlinkRequest {
    /// Absolute path on the coord's local filesystem.
    pub source_path: String,
    pub file_type: String,
    pub filename: String,
}

pub async fn hardlink_file(
    State(state): State<Arc<AppState>>,
    Json(req): Json<HardlinkRequest>,
) -> ApiResult<impl IntoResponse> {
    let source_path = PathBuf::from(&req.source_path);
    if !source_path.is_absolute() {
        return Err(ApiError::BadRequest(
            "source_path must be absolute".to_string(),
        ));
    }

    let files_dir = state.files_dir();
    tokio::fs::create_dir_all(&files_dir).await?;

    // Verify source is on the same device as files_dir (hard links can't
    // cross filesystems), and that it's a regular file.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let source_meta = tokio::fs::metadata(&source_path)
            .await
            .map_err(|e| ApiError::BadRequest(format!("source not readable: {e}")))?;
        if !source_meta.is_file() {
            return Err(ApiError::BadRequest(
                "source must be a regular file".to_string(),
            ));
        }
        let files_meta = tokio::fs::metadata(&files_dir).await?;
        if source_meta.dev() != files_meta.dev() {
            return Err(ApiError::BadRequest(
                "source is on a different device than files_dir".to_string(),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = &source_path;
        return Err(ApiError::BadRequest(
            "hardlink fast path requires a Unix-like OS".to_string(),
        ));
    }

    let (file_id, sha256, size_bytes) =
        files::hard_link_from(&files_dir, &source_path, &req.filename)
            .await
            .map_err(|e| ApiError::Internal(format!("hard-link failed: {e}")))?;

    // Dedup: if we already have this content, remove the newly-created link
    // and return the existing record. The source file is untouched.
    if let Some(existing) = db::find_file_by_sha256(&state.db, &sha256).await? {
        if let Err(e) = files::delete_file(&files_dir, &file_id) {
            tracing::warn!(
                file_id = %file_id,
                error = %e,
                "dedup: failed to remove newly-created hardlink from disk"
            );
        }
        info!(
            existing_id = %existing.id,
            filename = %req.filename,
            sha256 = %sha256,
            "dedup: returning existing file record for matching sha256 (hardlink path)"
        );
        return Ok((StatusCode::OK, Json(existing)));
    }

    let disk_path = files_dir.join(&file_id).to_string_lossy().to_string();
    let record = FileRecord {
        id: file_id,
        filename: req.filename,
        file_type: req.file_type,
        size_bytes: size_bytes as i64,
        sha256,
        disk_path,
        uploaded_at: Utc::now(),
    };
    db::insert_file_record(&state.db, &record).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

fn device_id_of(path: &std::path::Path) -> ApiResult<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| ApiError::Internal(format!("stat {}: {e}", path.display())))?;
        Ok(meta.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0)
    }
}

/// Pin a file so it's never auto-GC'd. Idempotent.
pub async fn pin_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if !db::set_file_pinned(&state.db, &id, true).await? {
        return Err(ApiError::NotFound(format!("file {id} not found")));
    }
    info!(file_id = %id, "pinned file");
    Ok((StatusCode::OK, Json(serde_json::json!({"pinned": true}))))
}

/// Unpin a file. Subsequent terminal task transitions can mark it for
/// GC in the normal way.
pub async fn unpin_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    if !db::set_file_pinned(&state.db, &id, false).await? {
        return Err(ApiError::NotFound(format!("file {id} not found")));
    }
    info!(file_id = %id, "unpinned file");
    Ok((StatusCode::OK, Json(serde_json::json!({"pinned": false}))))
}

/// Trigger a GC pass right now instead of waiting for the periodic
/// loop. Returns once the pass completes (or errors).
pub async fn gc_now(State(state): State<Arc<AppState>>) -> ApiResult<impl IntoResponse> {
    crate::lifecycle::run_gc_once(&state)
        .await
        .map_err(|e| ApiError::Internal(format!("gc_pass failed: {e}")))?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "completed"})),
    ))
}

#[derive(Serialize)]
pub struct WorkerCacheStatus {
    pub worker_id: String,
    pub file_count: i64,
    pub total_bytes: i64,
}

/// Per-worker cache summary used by `crackctl status --cache` and the
/// TUI workers view.
pub async fn cache_status(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Vec<WorkerCacheStatus>>> {
    let rows = db::cache_summary_per_worker(&state.db).await?;
    let entries: Vec<WorkerCacheStatus> = rows
        .into_iter()
        .map(|(worker_id, file_count, total_bytes)| WorkerCacheStatus {
            worker_id,
            file_count,
            total_bytes,
        })
        .collect();
    Ok(Json(entries))
}

pub async fn download_file(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let record = db::get_file_record(&state.db, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("file {id} not found")))?;

    let files_dir = state.files_dir();
    let data = files::read_file(&files_dir, &record.id)
        .map_err(|e| ApiError::Internal(format!("failed to read file: {e}")))?;

    // Sanitize filename to prevent header injection via quotes, newlines, or null bytes.
    let safe_filename = record
        .filename
        .replace('"', "'")
        .replace(['\n', '\r', '\0'], "");
    let content_disposition = format!("attachment; filename=\"{}\"", safe_filename);

    Ok((
        StatusCode::OK,
        [
            ("content-type", "application/octet-stream".to_string()),
            ("content-disposition", content_disposition),
        ],
        data,
    ))
}
