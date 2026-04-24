use std::sync::Arc;

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use chrono::Utc;
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
