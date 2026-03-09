use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Save file data to disk with a UUID-based filename.
///
/// Returns `(file_id, sha256_hex)` where `file_id` is the UUID used as the on-disk filename.
pub fn save_file(files_dir: &Path, filename: &str, data: &[u8]) -> Result<(String, String)> {
    std::fs::create_dir_all(files_dir)
        .with_context(|| format!("creating files directory: {}", files_dir.display()))?;

    let file_id = Uuid::new_v4().to_string();

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = format!("{:x}", hasher.finalize());

    // Preserve the original extension for convenience (e.g. .txt, .hash)
    let ext = Path::new(filename)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    let disk_name = if ext.is_empty() {
        file_id.clone()
    } else {
        format!("{file_id}.{ext}")
    };

    let disk_path = files_dir.join(&disk_name);

    std::fs::write(&disk_path, data)
        .with_context(|| format!("writing file to {}", disk_path.display()))?;

    tracing::debug!(
        file_id = %file_id,
        filename = %filename,
        size = data.len(),
        sha256 = %sha256,
        "Saved file to disk"
    );

    Ok((file_id, sha256))
}

/// Read a file from disk by its file_id.
///
/// Tries the bare file_id first, then falls back to any file whose name starts with the file_id
/// (to handle files stored with an extension).
pub fn read_file(files_dir: &Path, file_id: &str) -> Result<Vec<u8>> {
    // Try exact match first
    let exact = files_dir.join(file_id);
    if exact.is_file() {
        return std::fs::read(&exact)
            .with_context(|| format!("reading file {}", exact.display()));
    }

    // Fall back: look for file_id.* (with extension)
    let prefix = format!("{file_id}.");
    if let Ok(entries) = std::fs::read_dir(files_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) {
                    return std::fs::read(entry.path())
                        .with_context(|| format!("reading file {}", entry.path().display()));
                }
            }
        }
    }

    anyhow::bail!("file not found: {file_id} in {}", files_dir.display())
}

/// Delete a file from disk by its file_id.
///
/// Tries the bare file_id first, then falls back to any file whose name starts with the file_id.
pub fn delete_file(files_dir: &Path, file_id: &str) -> Result<()> {
    // Try exact match first
    let exact = files_dir.join(file_id);
    if exact.is_file() {
        std::fs::remove_file(&exact)
            .with_context(|| format!("deleting file {}", exact.display()))?;
        return Ok(());
    }

    // Fall back: look for file_id.* (with extension)
    let prefix = format!("{file_id}.");
    if let Ok(entries) = std::fs::read_dir(files_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) {
                    std::fs::remove_file(entry.path())
                        .with_context(|| format!("deleting file {}", entry.path().display()))?;
                    return Ok(());
                }
            }
        }
    }

    anyhow::bail!("file not found for deletion: {file_id} in {}", files_dir.display())
}
