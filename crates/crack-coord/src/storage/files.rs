use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Extract a disk-safe extension from a caller-supplied filename.
///
/// `Path::extension` alone isn't enough — it accepts `"foo/bar"` etc., which
/// would land outside `files_dir` once joined. Whitelist `[A-Za-z0-9]{1,16}`
/// (ascii alnum, length-bounded). Anything else collapses to no extension —
/// the file is still stored, just under the bare UUID.
fn safe_disk_ext(filename: &str) -> Option<String> {
    let ext = Path::new(filename).extension()?.to_str()?;
    if ext.is_empty() || ext.len() > 16 {
        return None;
    }
    if !ext.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(ext.to_string())
}

/// The on-disk filename for a stored file: `<file_id>.<safe_ext>`, or the bare
/// `file_id` when the original extension isn't disk-safe. Stored in the DB's
/// `disk_path` so files can be resolved in O(1) without a directory scan.
pub fn disk_name_for(file_id: &str, filename: &str) -> String {
    match safe_disk_ext(filename) {
        Some(ext) => format!("{file_id}.{ext}"),
        None => file_id.to_string(),
    }
}

/// Streaming writer for an incoming upload. Writes to a `.partial` companion
/// file so a crash or error leaves no half-finished entry in the canonical
/// name slot; only a successful `finalize()` does the atomic rename.
///
/// SHA-256 and size are computed incrementally as chunks arrive. Callers
/// drive the write loop (no axum/multipart types here — storage stays
/// transport-agnostic).
pub struct FileWriter {
    file_id: String,
    partial_path: PathBuf,
    final_path: PathBuf,
    file: tokio::fs::File,
    hasher: Sha256,
    size: u64,
}

impl FileWriter {
    pub async fn create(files_dir: &Path, filename: &str) -> Result<Self> {
        tokio::fs::create_dir_all(files_dir)
            .await
            .with_context(|| format!("creating files directory: {}", files_dir.display()))?;

        let file_id = Uuid::new_v4().to_string();
        let disk_name = disk_name_for(&file_id, filename);

        let final_path = files_dir.join(&disk_name);
        let partial_path = files_dir.join(format!("{disk_name}.partial"));

        let file = tokio::fs::File::create(&partial_path)
            .await
            .with_context(|| format!("creating {}", partial_path.display()))?;

        Ok(Self {
            file_id,
            partial_path,
            final_path,
            file,
            hasher: Sha256::new(),
            size: 0,
        })
    }

    /// Append `bytes` to the partial file, updating the rolling SHA-256 and
    /// byte count.
    ///
    /// # Errors
    /// Returns an error if writing to the partial file fails.
    pub async fn write_chunk(&mut self, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .await
            .with_context(|| format!("writing to {}", self.partial_path.display()))?;
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
        Ok(())
    }

    /// Total bytes written so far. Used by the upload handler to enforce a
    /// per-request size cap as the stream arrives — no buffering, no
    /// post-finalize cleanup.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Finish the upload: flush to disk, rename `.partial` to the final name,
    /// and return `(file_id, sha256_hex, size_bytes)`.
    pub async fn finalize(mut self) -> Result<(String, String, u64)> {
        self.file
            .flush()
            .await
            .with_context(|| format!("flushing {}", self.partial_path.display()))?;
        drop(self.file);

        let sha256 = format!("{:x}", self.hasher.finalize());

        tokio::fs::rename(&self.partial_path, &self.final_path)
            .await
            .with_context(|| {
                format!(
                    "renaming {} -> {}",
                    self.partial_path.display(),
                    self.final_path.display()
                )
            })?;

        tracing::debug!(
            file_id = %self.file_id,
            size = self.size,
            sha256 = %sha256,
            "Saved file to disk (streaming)"
        );

        Ok((self.file_id, sha256, self.size))
    }

    /// Remove the `.partial` file if the upload was aborted. Best-effort; a
    /// leftover `.partial` will be tolerated by future GC sweeps.
    pub async fn abort(self) {
        let _ = tokio::fs::remove_file(&self.partial_path).await;
    }
}

/// Hard-link an existing file on the coord's filesystem into the file store
/// without copying bytes. The caller is responsible for verifying the source
/// is on the same device as `files_dir` (hard links can't cross filesystems).
///
/// sha256 is computed by streaming the linked file; returns `(file_id, sha256, size)`.
pub async fn hard_link_from(
    files_dir: &Path,
    source_path: &Path,
    filename: &str,
) -> Result<(String, String, u64)> {
    tokio::fs::create_dir_all(files_dir)
        .await
        .with_context(|| format!("creating files directory: {}", files_dir.display()))?;

    let file_id = Uuid::new_v4().to_string();
    let disk_name = disk_name_for(&file_id, filename);
    let dest = files_dir.join(&disk_name);

    tokio::fs::hard_link(source_path, &dest)
        .await
        .with_context(|| {
            format!(
                "hard-linking {} -> {}",
                source_path.display(),
                dest.display()
            )
        })?;

    // Stream sha256 of the linked content. No second on-disk copy, but we
    // still have to read all bytes once to compute the hash.
    let mut file = tokio::fs::File::open(&dest)
        .await
        .with_context(|| format!("opening hard-linked {}", dest.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = file
            .read(&mut buf)
            .await
            .with_context(|| format!("reading hard-linked {}", dest.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    let sha256 = format!("{:x}", hasher.finalize());

    tracing::debug!(
        file_id = %file_id,
        source = %source_path.display(),
        size,
        sha256 = %sha256,
        "Hard-linked file into store"
    );

    Ok((file_id, sha256, size))
}

/// Save file data to disk with a UUID-based filename.
///
/// Returns `(file_id, sha256_hex, size_bytes)`, matching the shape returned by
/// [`FileWriter::finalize`] and [`hard_link_from`] so callers don't recompute
/// the size separately.
///
/// # Errors
/// Returns an error if the files directory can't be created or the write fails.
pub fn save_file(files_dir: &Path, filename: &str, data: &[u8]) -> Result<(String, String, u64)> {
    std::fs::create_dir_all(files_dir)
        .with_context(|| format!("creating files directory: {}", files_dir.display()))?;

    let file_id = Uuid::new_v4().to_string();

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let sha256 = format!("{:x}", hasher.finalize());

    // Use the same disk-safe naming as the streaming/hardlink paths so the
    // on-disk name matches what callers store in `disk_path`.
    let disk_name = disk_name_for(&file_id, filename);
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

    Ok((file_id, sha256, data.len() as u64))
}

/// Resolve a `file_id` to the actual path on disk.
///
/// Tries `<files_dir>/<file_id>` first (uploads with no extension), then
/// scans for the first entry matching `<file_id>.*` (uploads with an
/// extension — the on-disk name carries `<uuid>.<ext>`, but the DB's
/// `disk_path` column predates the extension fix-up and currently doesn't
/// include it).
///
/// Returns `Ok(path)` on the first match, `Err` if neither form exists.
///
/// The prefix scan is bounded in practice by `safe_disk_ext` (uploads
/// can't write filenames outside `<uuid>.[A-Za-z0-9]{1,16}`), but it is
/// still O(files_count) per call and a clean candidate for retirement
/// once the upload path stores the full disk path in DB.
pub(crate) fn locate_existing(files_dir: &Path, file_id: &str) -> Result<PathBuf> {
    // Defense in depth: `file_id` is used directly as a path component, so
    // reject anything that could escape `files_dir`. Legitimate ids are UUIDs.
    if file_id.is_empty()
        || file_id.contains('/')
        || file_id.contains('\\')
        || file_id.contains("..")
        || file_id.contains('\0')
    {
        anyhow::bail!("invalid file id: {file_id:?}");
    }

    let exact = files_dir.join(file_id);
    if is_regular_file(&exact) {
        return Ok(exact);
    }

    let prefix = format!("{file_id}.");
    // Surface read errors instead of masking them as "not found" — a transient
    // FS failure should not look identical to a missing file.
    let entries = std::fs::read_dir(files_dir)
        .with_context(|| format!("reading files directory: {}", files_dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("reading entry in {}", files_dir.display()))?;
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with(&prefix) {
                let path = entry.path();
                if is_regular_file(&path) {
                    return Ok(path);
                }
            }
        }
    }

    anyhow::bail!("file not found: {file_id} in {}", files_dir.display())
}

/// True if `name` is a single safe path component (non-empty, no separators,
/// parent refs, or NUL) — gates a stored `disk_path` before it is joined.
fn disk_name_is_safe(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains("..")
        && !name.contains('\0')
}

/// Resolve a file's on-disk path, preferring the stored `disk_path` (an O(1)
/// join) and falling back to a directory scan for legacy rows whose stored
/// value predates the relative-name fix.
///
/// `disk_path` is trusted only when it is a single safe component pointing at a
/// real regular file; legacy absolute paths (which contain separators) and
/// stale values fall through to [`locate_existing`].
///
/// # Errors
/// Returns an error if neither the stored path nor the scan locates the file.
pub fn resolve_record_path(files_dir: &Path, file_id: &str, disk_path: &str) -> Result<PathBuf> {
    if disk_name_is_safe(disk_path) {
        let candidate = files_dir.join(disk_path);
        if is_regular_file(&candidate) {
            return Ok(candidate);
        }
    }
    locate_existing(files_dir, file_id)
}

/// True only if `path` is a *regular* file and not a symlink.
///
/// Uses `symlink_metadata` (lstat), so a symlink planted in `files_dir` by
/// another local user cannot redirect a read to an arbitrary target such as
/// `/etc/passwd` — `is_file()` on lstat metadata is false for symlinks.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|m| m.file_type().is_file())
        .unwrap_or(false)
}

/// Read a file from disk by its file_id.
pub fn read_file(files_dir: &Path, file_id: &str) -> Result<Vec<u8>> {
    let path = locate_existing(files_dir, file_id)?;
    std::fs::read(&path).with_context(|| format!("reading file {}", path.display()))
}

/// Resolve a file_id to its full path on disk.
pub fn resolve_file_path(files_dir: &Path, file_id: &str) -> Result<PathBuf> {
    locate_existing(files_dir, file_id)
}

/// Delete a file from disk by its file_id.
pub fn delete_file(files_dir: &Path, file_id: &str) -> Result<()> {
    let path = locate_existing(files_dir, file_id)
        .with_context(|| format!("file not found for deletion: {file_id}"))?;
    std::fs::remove_file(&path).with_context(|| format!("deleting file {}", path.display()))
}

/// Delete a file from disk, resolving via the stored `disk_path` (O(1)) with a
/// directory-scan fallback for legacy rows — avoids a scan per delete in the
/// GC loop.
///
/// # Errors
/// Returns an error if the file can't be located or removed.
pub fn delete_record(files_dir: &Path, file_id: &str, disk_path: &str) -> Result<()> {
    let path = resolve_record_path(files_dir, file_id, disk_path)
        .with_context(|| format!("file not found for deletion: {file_id}"))?;
    std::fs::remove_file(&path).with_context(|| format!("deleting file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a unique scratch directory under the OS temp dir. Cleanup is
    /// best-effort via `Drop` on the returned guard.
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("crack-coord-test-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn safe_disk_ext_accepts_normal_extensions() {
        assert_eq!(safe_disk_ext("foo.txt"), Some("txt".into()));
        assert_eq!(safe_disk_ext("bar.HASH"), Some("HASH".into()));
        assert_eq!(safe_disk_ext("rule.rule"), Some("rule".into()));
        assert_eq!(safe_disk_ext("dump.7z"), Some("7z".into()));
    }

    #[test]
    fn safe_disk_ext_rejects_path_components() {
        // `Path::extension` on a path with separators returns `None` on Unix
        // for the easy cases — but a backslash on Unix is treated as a
        // literal in the last component, so `Path::new("y.foo\\bar")` reports
        // an extension of `"foo\\bar"`. The whitelist catches it via the
        // ascii-alnum filter even though `Path` itself does not.
        assert_eq!(safe_disk_ext("x.foo/bar"), None);
        assert_eq!(safe_disk_ext("y.foo\\bar"), None);
        assert_eq!(safe_disk_ext("../../etc/passwd"), None);
    }

    #[test]
    fn safe_disk_ext_rejects_overlong_or_empty() {
        assert_eq!(safe_disk_ext("noext"), None);
        assert_eq!(safe_disk_ext("foo."), None);
        let long = format!("foo.{}", "a".repeat(17));
        assert_eq!(safe_disk_ext(&long), None);
        // Right at the boundary, 16 chars is allowed.
        let max = format!("foo.{}", "a".repeat(16));
        assert_eq!(safe_disk_ext(&max), Some("a".repeat(16)));
    }

    #[test]
    fn safe_disk_ext_rejects_non_ascii_or_punctuation() {
        assert_eq!(safe_disk_ext("foo.tar.gz"), Some("gz".into())); // ok
        assert_eq!(safe_disk_ext("foo.t-x"), None);
        assert_eq!(safe_disk_ext("foo.tä"), None);
        assert_eq!(safe_disk_ext("foo. "), None);
    }

    #[test]
    fn disk_name_collapses_unsafe_extensions() {
        assert_eq!(disk_name_for("uuid", "x.foo/bar"), "uuid");
        assert_eq!(disk_name_for("uuid", "x.txt"), "uuid.txt");
    }

    #[test]
    fn locate_existing_finds_regular_file_with_ext() {
        let dir = TempDir::new();
        let id = "22222222-2222-2222-2222-222222222222";
        std::fs::write(dir.path.join(format!("{id}.hash")), b"data").unwrap();
        let p = locate_existing(&dir.path, id).unwrap();
        assert!(p.ends_with(format!("{id}.hash")));
    }

    #[test]
    fn locate_existing_rejects_path_escape_ids() {
        let dir = TempDir::new();
        for bad in ["../etc/passwd", "a/b", "..", "with\0null", ""] {
            assert!(
                locate_existing(&dir.path, bad).is_err(),
                "must reject id {bad:?}"
            );
        }
    }

    #[test]
    fn resolve_record_path_prefers_disk_path_then_falls_back() {
        let dir = TempDir::new();
        let id = "33333333-3333-3333-3333-333333333333";
        let disk_name = format!("{id}.txt");
        std::fs::write(dir.path.join(&disk_name), b"data").unwrap();

        // Stored disk_path → O(1) resolution, no scan.
        let p = resolve_record_path(&dir.path, id, &disk_name).unwrap();
        assert!(p.ends_with(&disk_name));

        // Legacy/empty disk_path → falls back to the directory scan.
        let p2 = resolve_record_path(&dir.path, id, "").unwrap();
        assert!(p2.ends_with(&disk_name));

        // A path-traversal disk_path is rejected and falls back to the scan.
        let p3 = resolve_record_path(&dir.path, id, "../../etc/passwd").unwrap();
        assert!(p3.ends_with(&disk_name));
    }

    #[cfg(unix)]
    #[test]
    fn locate_existing_rejects_symlink_entries() {
        // A symlink planted in files_dir (e.g. by another local user) must not
        // be returned — otherwise read_file would follow it to an arbitrary
        // target such as /etc/passwd.
        let dir = TempDir::new();
        let secret = dir.path.join("secret.txt");
        std::fs::write(&secret, b"top secret").unwrap();
        let id = "11111111-1111-1111-1111-111111111111";
        std::os::unix::fs::symlink(&secret, dir.path.join(format!("{id}.txt"))).unwrap();

        assert!(
            locate_existing(&dir.path, id).is_err(),
            "symlinked entry must not be located"
        );
    }

    #[tokio::test]
    async fn file_writer_roundtrip_computes_sha_and_size() {
        let dir = TempDir::new();
        let mut writer = FileWriter::create(&dir.path, "sample.txt").await.unwrap();
        writer.write_chunk(b"hello").await.unwrap();
        writer.write_chunk(b" world").await.unwrap();
        let (file_id, sha256, size) = writer.finalize().await.unwrap();

        assert_eq!(size, 11);
        // sha256("hello world")
        assert_eq!(
            sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let on_disk = resolve_file_path(&dir.path, &file_id).unwrap();
        let data = std::fs::read(&on_disk).unwrap();
        assert_eq!(data, b"hello world");
    }

    #[tokio::test]
    async fn file_writer_partial_is_renamed_on_finalize() {
        let dir = TempDir::new();
        let mut writer = FileWriter::create(&dir.path, "note.md").await.unwrap();
        writer.write_chunk(b"x").await.unwrap();
        let partial = writer.partial_path.clone();
        assert!(partial.exists(), ".partial should exist during write");

        writer.finalize().await.unwrap();
        assert!(!partial.exists(), ".partial should be renamed on finalize");
    }

    #[tokio::test]
    async fn file_writer_abort_removes_partial() {
        let dir = TempDir::new();
        let mut writer = FileWriter::create(&dir.path, "note.md").await.unwrap();
        writer.write_chunk(b"abc").await.unwrap();
        let partial = writer.partial_path.clone();
        assert!(partial.exists());

        writer.abort().await;
        assert!(!partial.exists(), "abort should remove the .partial file");
    }

    #[tokio::test]
    async fn file_writer_empty_upload_produces_empty_file() {
        let dir = TempDir::new();
        let writer = FileWriter::create(&dir.path, "empty.bin").await.unwrap();
        let (file_id, sha256, size) = writer.finalize().await.unwrap();

        assert_eq!(size, 0);
        // sha256 of empty string
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let on_disk = resolve_file_path(&dir.path, &file_id).unwrap();
        assert_eq!(std::fs::metadata(&on_disk).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn hard_link_from_roundtrip_computes_sha_and_size() {
        let dir = TempDir::new();
        let source = dir.path.join("source.txt");
        std::fs::write(&source, b"hello world").unwrap();

        let files_dir = dir.path.join("store");
        let (file_id, sha256, size) = hard_link_from(&files_dir, &source, "source.txt")
            .await
            .unwrap();

        assert_eq!(size, 11);
        assert_eq!(
            sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        let on_disk = resolve_file_path(&files_dir, &file_id).unwrap();
        assert_eq!(std::fs::read(&on_disk).unwrap(), b"hello world");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hard_link_from_shares_inode_with_source() {
        use std::os::unix::fs::MetadataExt;
        let dir = TempDir::new();
        let source = dir.path.join("source.bin");
        std::fs::write(&source, b"shared").unwrap();

        let files_dir = dir.path.join("store");
        let (file_id, _, _) = hard_link_from(&files_dir, &source, "source.bin")
            .await
            .unwrap();
        let on_disk = resolve_file_path(&files_dir, &file_id).unwrap();

        let src_inode = std::fs::metadata(&source).unwrap().ino();
        let dst_inode = std::fs::metadata(&on_disk).unwrap().ino();
        assert_eq!(
            src_inode, dst_inode,
            "hard link should share inode with source"
        );
    }

    #[tokio::test]
    async fn hard_link_from_missing_source_errors() {
        let dir = TempDir::new();
        let missing = dir.path.join("does-not-exist");
        let result = hard_link_from(&dir.path, &missing, "x.txt").await;
        assert!(result.is_err());
    }
}
