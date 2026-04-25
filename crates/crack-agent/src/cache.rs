//! Content-addressed file cache for the agent.
//!
//! Files are stored on disk at `<root>/cas/<hh>/<hash>` where `hash` is the
//! sha256 hex and `hh` is its first two characters (shard). Lookups go by
//! content hash, not upload UUID — so a wordlist renamed on the coord, or
//! re-uploaded under a new file ID, still hits the same cache entry.
//!
//! Missing entries are pulled from the coord via the Noise channel using
//! the `WorkerMessage::RequestFileRange` / `CoordMessage::FileRange` RPC
//! pair. The agent issues requests sequentially and only advances once the
//! matching response arrives — natural backpressure, bounded memory.
//!
//! Concurrent calls to `ensure()` for the *same* hash serialize on a
//! per-hash mutex; the second caller waits for the first to finish and
//! then sees the already-cached path.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use crack_common::protocol::{CacheManifestEntry, WorkerMessage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

/// Bytes requested per `RequestFileRange`. Coord caps responses to this same
/// value (see `FILE_RANGE_MAX_BYTES` in `crack-coord::transport::handler`);
/// keeping them aligned avoids protocol-level surprises.
const CHUNK_SIZE: u32 = 2 * 1024 * 1024;

/// On-disk record of when each cached entry was last used. Persisted to
/// `<root>/cas-ledger.json` after every update so the LRU order survives
/// agent restarts. mtime would be a free fallback but isn't reliably
/// updated by every filesystem on read.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Ledger {
    /// Map sha256 → RFC3339 timestamp of last use.
    entries: HashMap<String, String>,
}

/// One LRU candidate returned to the agent main loop for eviction
/// decisions: which sha to drop, how big it is, and when it was last
/// used.
#[derive(Debug, Clone)]
pub struct LruCandidate {
    pub sha256: String,
    pub size_bytes: u64,
    pub last_used_at: DateTime<Utc>,
}

/// Content-addressed file cache. Cheap to clone via `Arc`.
pub struct ContentCache {
    root: PathBuf,
    /// Hard ceiling on bytes stored under `<root>/cas/`. The main loop
    /// uses `lru_candidates()` to make room before issuing a pull;
    /// `cache_max_bytes` is the budget that decision is measured against.
    cache_max_bytes: u64,
    /// Per-hash serialization — prevents two concurrent `ensure()` calls
    /// for the same hash from racing on the same `.partial` file.
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Pending pulls by hash. The dispatcher's `on_file_range` /
    /// `on_file_error` hooks forward incoming messages through here so the
    /// `ensure()` loop can consume them.
    pending: Mutex<HashMap<String, mpsc::UnboundedSender<ChunkResult>>>,
    /// In-memory mirror of the on-disk LRU ledger. Touched on every
    /// `ensure()` (hit or miss) and persisted after each update.
    ledger: Mutex<Ledger>,
}

/// Internal message the dispatcher uses to feed `ensure()`.
enum ChunkResult {
    Range {
        offset: u64,
        data: Vec<u8>,
        eof: bool,
    },
    Error(String),
}

impl ContentCache {
    pub fn new(root: PathBuf, cache_max_bytes: u64) -> Arc<Self> {
        let ledger_path = root.join("cas-ledger.json");
        let ledger = std::fs::read(&ledger_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Ledger>(&bytes).ok())
            .unwrap_or_default();
        Arc::new(Self {
            root,
            cache_max_bytes,
            locks: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            ledger: Mutex::new(ledger),
        })
    }

    pub fn cache_max_bytes(&self) -> u64 {
        self.cache_max_bytes
    }

    fn ledger_path(&self) -> PathBuf {
        self.root.join("cas-ledger.json")
    }

    /// Mark `hash` as used now. Persists the ledger to disk best-effort.
    pub async fn touch(&self, hash: &str) {
        let mut ledger = self.ledger.lock().await;
        ledger
            .entries
            .insert(hash.to_string(), Utc::now().to_rfc3339());
        let snapshot = match serde_json::to_vec(&*ledger) {
            Ok(b) => b,
            Err(_) => return,
        };
        drop(ledger);
        if let Some(parent) = self.ledger_path().parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let _ = tokio::fs::write(self.ledger_path(), snapshot).await;
    }

    async fn ledger_remove(&self, hash: &str) {
        let mut ledger = self.ledger.lock().await;
        if ledger.entries.remove(hash).is_none() {
            return;
        }
        let snapshot = match serde_json::to_vec(&*ledger) {
            Ok(b) => b,
            Err(_) => return,
        };
        drop(ledger);
        let _ = tokio::fs::write(self.ledger_path(), snapshot).await;
    }

    /// `<root>/cas/<first-two-chars>/<hash>`.
    pub fn path_for(&self, hash: &str) -> PathBuf {
        let shard = if hash.len() >= 2 { &hash[..2] } else { "xx" };
        self.root.join("cas").join(shard).join(hash)
    }

    /// Return true when a cached file for `hash` exists on disk and its
    /// size matches `expected_size`. Mismatched size → treat as miss.
    pub async fn has(&self, hash: &str, expected_size: u64) -> bool {
        match tokio::fs::metadata(self.path_for(hash)).await {
            Ok(m) => m.is_file() && m.len() == expected_size,
            Err(_) => false,
        }
    }

    /// Get a local path for `hash`. If absent or size-mismatched, pull via
    /// `RequestFileRange`. Returns the final on-disk path.
    ///
    /// The caller passes the outbound `WorkerMessage` sender; the
    /// dispatcher must forward any `FileRange` / `FileError` messages for
    /// this hash to `on_file_range` / `on_file_error` while the pull is in
    /// flight.
    ///
    /// Both cache hits and successful pulls touch the LRU ledger so the
    /// most-recently-used entries float to the top.
    pub async fn ensure(
        self: &Arc<Self>,
        hash: &str,
        size: u64,
        outbound_tx: &mpsc::Sender<WorkerMessage>,
    ) -> Result<PathBuf> {
        if hash.len() < 2 {
            anyhow::bail!("invalid hash: too short");
        }

        let hash_lock = self.per_hash_lock(hash).await;
        let _guard = hash_lock.lock().await;

        if self.has(hash, size).await {
            self.touch(hash).await;
            return Ok(self.path_for(hash));
        }

        let result = self.pull_to_disk(hash, size, outbound_tx).await;
        if result.is_ok() {
            self.touch(hash).await;
        }
        result
    }

    async fn per_hash_lock(&self, hash: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks
            .entry(hash.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn pull_to_disk(
        &self,
        hash: &str,
        size: u64,
        outbound_tx: &mpsc::Sender<WorkerMessage>,
    ) -> Result<PathBuf> {
        let final_path = self.path_for(hash);
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating cache dir {}", parent.display()))?;
        }
        let partial_path = final_path.with_extension("partial");

        let (chunk_tx, mut chunk_rx) = mpsc::unbounded_channel::<ChunkResult>();
        self.pending.lock().await.insert(hash.to_string(), chunk_tx);

        // Do the work in a helper so we can guarantee `pending` cleanup on
        // every exit path.
        let result = self
            .pull_loop(hash, size, outbound_tx, &partial_path, &mut chunk_rx)
            .await;

        self.pending.lock().await.remove(hash);

        match result {
            Ok(()) => {
                tokio::fs::rename(&partial_path, &final_path)
                    .await
                    .with_context(|| {
                        format!(
                            "renaming {} -> {}",
                            partial_path.display(),
                            final_path.display()
                        )
                    })?;
                Ok(final_path)
            }
            Err(e) => {
                // Best-effort cleanup of the .partial file.
                let _ = tokio::fs::remove_file(&partial_path).await;
                Err(e)
            }
        }
    }

    async fn pull_loop(
        &self,
        hash: &str,
        size: u64,
        outbound_tx: &mpsc::Sender<WorkerMessage>,
        partial_path: &Path,
        chunk_rx: &mut mpsc::UnboundedReceiver<ChunkResult>,
    ) -> Result<()> {
        let mut file = tokio::fs::File::create(partial_path)
            .await
            .with_context(|| format!("creating {}", partial_path.display()))?;
        let mut hasher = Sha256::new();
        let mut offset: u64 = 0;

        while offset < size {
            let remaining = size - offset;
            let length = CHUNK_SIZE.min(remaining.min(u32::MAX as u64) as u32);

            outbound_tx
                .send(WorkerMessage::RequestFileRange {
                    hash: hash.to_string(),
                    offset,
                    length,
                })
                .await
                .context("sending RequestFileRange")?;

            match chunk_rx.recv().await {
                Some(ChunkResult::Range {
                    offset: resp_offset,
                    data,
                    eof,
                }) => {
                    if resp_offset != offset {
                        anyhow::bail!("offset mismatch: requested {}, got {}", offset, resp_offset);
                    }
                    if data.is_empty() && !eof {
                        anyhow::bail!("coord returned empty non-eof chunk at offset {}", offset);
                    }
                    hasher.update(&data);
                    file.write_all(&data)
                        .await
                        .with_context(|| format!("writing to {}", partial_path.display()))?;
                    offset += data.len() as u64;
                    if eof {
                        break;
                    }
                }
                Some(ChunkResult::Error(reason)) => {
                    anyhow::bail!("coord refused file range: {reason}");
                }
                None => {
                    anyhow::bail!("pending channel closed before completion");
                }
            }
        }

        file.flush().await?;
        drop(file);

        if offset != size {
            anyhow::bail!(
                "short read: expected {} bytes, got {} before eof",
                size,
                offset
            );
        }

        let actual = format!("{:x}", hasher.finalize());
        if actual != hash {
            anyhow::bail!(
                "hash mismatch: expected sha256 {}, computed {}",
                hash,
                actual
            );
        }

        Ok(())
    }

    /// Walk `<root>/cas/<hh>/<hash>` and return a compact digest of every
    /// valid cached file. Entries the agent considers incomplete (missing,
    /// unreadable, zero-byte `.partial` leftovers) are skipped. Called on
    /// every heartbeat tick so the coord can reconcile its view.
    pub async fn manifest(&self) -> Vec<CacheManifestEntry> {
        let cas_root = self.root.join("cas");
        let mut out = Vec::new();
        let mut shard_entries = match tokio::fs::read_dir(&cas_root).await {
            Ok(d) => d,
            Err(_) => return out,
        };
        while let Ok(Some(shard)) = shard_entries.next_entry().await {
            let shard_path = shard.path();
            if !shard_path.is_dir() {
                continue;
            }
            let mut files_iter = match tokio::fs::read_dir(&shard_path).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = files_iter.next_entry().await {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                // Skip in-progress partials — they aren't cache entries yet.
                if name_str.ends_with(".partial") {
                    continue;
                }
                let meta = match entry.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !meta.is_file() {
                    continue;
                }
                let last_used_at = meta
                    .modified()
                    .ok()
                    .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| {
                        DateTime::<Utc>::from_timestamp(d.as_secs() as i64, d.subsec_nanos())
                            .unwrap_or_else(Utc::now)
                            .to_rfc3339()
                    })
                    .unwrap_or_else(|| Utc::now().to_rfc3339());
                out.push(CacheManifestEntry {
                    sha256: name_str.to_string(),
                    size_bytes: meta.len(),
                    last_used_at,
                });
            }
        }
        out
    }

    /// Best-effort removal of a cached file. Returns true if the canonical
    /// entry was deleted (we also sweep any stale `.partial` and the
    /// matching ledger entry). A missing file is not an error — it means
    /// the cache was already clean.
    pub async fn evict(&self, hash: &str) -> bool {
        let final_path = self.path_for(hash);
        let partial = final_path.with_extension("partial");
        let removed_final = tokio::fs::remove_file(&final_path).await.is_ok();
        let _ = tokio::fs::remove_file(&partial).await;
        if removed_final {
            self.ledger_remove(hash).await;
        }
        removed_final
    }

    /// Total bytes currently consumed by canonical cache entries (skips
    /// `.partial` companions). Walks the cas/ tree once per call — fine
    /// for budget checks on the assignment path; not a hot loop.
    pub async fn total_size(&self) -> u64 {
        let cas_root = self.root.join("cas");
        let mut total: u64 = 0;
        let mut shards = match tokio::fs::read_dir(&cas_root).await {
            Ok(d) => d,
            Err(_) => return 0,
        };
        while let Ok(Some(shard)) = shards.next_entry().await {
            let p = shard.path();
            if !p.is_dir() {
                continue;
            }
            let mut files = match tokio::fs::read_dir(&p).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = files.next_entry().await {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if name_str.ends_with(".partial") {
                    continue;
                }
                if let Ok(meta) = entry.metadata().await {
                    if meta.is_file() {
                        total = total.saturating_add(meta.len());
                    }
                }
            }
        }
        total
    }

    /// LRU-sorted snapshot of every canonical cache entry, oldest-used
    /// first. Entries without a ledger record fall back to file mtime.
    /// Returned `last_used_at` is what the caller should compare against
    /// "is older than" — the agent's main loop walks this list, skipping
    /// any sha currently in use, evicting until enough room is free.
    pub async fn lru_candidates(&self) -> Vec<LruCandidate> {
        let ledger = self.ledger.lock().await;
        let ledger_snapshot: HashMap<String, String> = ledger.entries.clone();
        drop(ledger);

        let cas_root = self.root.join("cas");
        let mut out = Vec::new();
        let mut shards = match tokio::fs::read_dir(&cas_root).await {
            Ok(d) => d,
            Err(_) => return out,
        };
        while let Ok(Some(shard)) = shards.next_entry().await {
            let p = shard.path();
            if !p.is_dir() {
                continue;
            }
            let mut files = match tokio::fs::read_dir(&p).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            while let Ok(Some(entry)) = files.next_entry().await {
                let name = entry.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if name_str.ends_with(".partial") {
                    continue;
                }
                let meta = match entry.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !meta.is_file() {
                    continue;
                }
                let last_used_at = ledger_snapshot
                    .get(name_str)
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.with_timezone(&Utc))
                    .or_else(|| {
                        meta.modified()
                            .ok()
                            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                            .and_then(|d| {
                                DateTime::<Utc>::from_timestamp(
                                    d.as_secs() as i64,
                                    d.subsec_nanos(),
                                )
                            })
                    })
                    .unwrap_or_else(Utc::now);
                out.push(LruCandidate {
                    sha256: name_str.to_string(),
                    size_bytes: meta.len(),
                    last_used_at,
                });
            }
        }
        out.sort_by_key(|c| c.last_used_at);
        out
    }

    /// Hook for the agent's message dispatcher: forward an incoming
    /// `CoordMessage::FileRange` to the matching in-flight `ensure()`.
    /// `data_b64` is the base64 payload as wired.
    pub async fn on_file_range(&self, hash: &str, offset: u64, data_b64: &str, eof: bool) {
        let data = match general_purpose::STANDARD.decode(data_b64) {
            Ok(b) => b,
            Err(e) => {
                self.on_file_error(hash, format!("base64 decode: {e}"))
                    .await;
                return;
            }
        };
        if let Some(tx) = self.pending.lock().await.get(hash) {
            let _ = tx.send(ChunkResult::Range { offset, data, eof });
        }
    }

    /// Hook for the agent's message dispatcher: fail the matching
    /// in-flight `ensure()` with `reason`.
    pub async fn on_file_error(&self, hash: &str, reason: String) {
        if let Some(tx) = self.pending.lock().await.remove(hash) {
            let _ = tx.send(ChunkResult::Error(reason));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    struct TempDir {
        path: PathBuf,
    }
    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("crack-agent-cache-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        format!("{:x}", Sha256::digest(data))
    }

    #[test]
    fn path_for_shards_by_prefix() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let p = cache.path_for("abcdef0123456789");
        assert_eq!(p, dir.path.join("cas").join("ab").join("abcdef0123456789"));
    }

    #[tokio::test]
    async fn has_returns_false_when_missing() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        assert!(!cache.has("deadbeef00000000", 100).await);
    }

    #[tokio::test]
    async fn has_returns_false_on_size_mismatch() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let hash = sha256_hex(b"hello");
        let p = cache.path_for(&hash);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"hello").unwrap();
        assert!(cache.has(&hash, 5).await);
        assert!(!cache.has(&hash, 6).await);
    }

    /// Spawn a task that plays the role of the coord: for each
    /// `RequestFileRange` received on `outbound_rx`, slice `data` at the
    /// requested offset and drive it back through `cache.on_file_range`.
    fn spawn_fake_coord(
        cache: Arc<ContentCache>,
        mut outbound_rx: mpsc::Receiver<WorkerMessage>,
        data: Vec<u8>,
        expected_hash: String,
    ) {
        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                match msg {
                    WorkerMessage::RequestFileRange {
                        hash,
                        offset,
                        length,
                    } => {
                        assert_eq!(hash, expected_hash);
                        let start = offset as usize;
                        let end = (start + length as usize).min(data.len());
                        let chunk = &data[start..end];
                        let eof = end == data.len();
                        let b64 = general_purpose::STANDARD.encode(chunk);
                        cache.on_file_range(&hash, offset, &b64, eof).await;
                    }
                    _ => panic!("unexpected outbound message"),
                }
            }
        });
    }

    #[tokio::test]
    async fn ensure_pulls_and_caches_on_miss() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let (tx, rx) = mpsc::channel(16);

        let data = b"hello world".to_vec();
        let hash = sha256_hex(&data);
        spawn_fake_coord(cache.clone(), rx, data.clone(), hash.clone());

        let path = cache.ensure(&hash, data.len() as u64, &tx).await.unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        assert!(cache.has(&hash, data.len() as u64).await);
    }

    #[tokio::test]
    async fn ensure_hit_skips_network_roundtrip() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);

        // Pre-seed the cache.
        let data = b"already cached".to_vec();
        let hash = sha256_hex(&data);
        let p = cache.path_for(&hash);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &data).unwrap();

        let (tx, mut rx) = mpsc::channel::<WorkerMessage>(1);
        let path = cache.ensure(&hash, data.len() as u64, &tx).await.unwrap();
        assert_eq!(path, p);
        // No message should have been sent.
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ensure_large_file_pulls_multiple_chunks() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let (tx, rx) = mpsc::channel(64);

        // 5 MiB — forces at least 3 chunks at the 2 MiB default.
        let data: Vec<u8> = (0..5 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let hash = sha256_hex(&data);
        spawn_fake_coord(cache.clone(), rx, data.clone(), hash.clone());

        let path = cache.ensure(&hash, data.len() as u64, &tx).await.unwrap();
        let on_disk = tokio::fs::read(&path).await.unwrap();
        assert_eq!(on_disk.len(), data.len());
        assert_eq!(sha256_hex(&on_disk), hash);
    }

    #[tokio::test]
    async fn ensure_hash_mismatch_aborts_and_cleans_partial() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let (tx, rx) = mpsc::channel(16);

        let correct_data = b"correct".to_vec();
        let wrong_data = b"WRONG!".to_vec();
        let declared_hash = sha256_hex(&correct_data); // doesn't match wrong_data
        spawn_fake_coord(cache.clone(), rx, wrong_data.clone(), declared_hash.clone());

        let result = cache
            .ensure(&declared_hash, correct_data.len() as u64, &tx)
            .await;
        assert!(result.is_err(), "expected hash-mismatch error");

        // Cache must not have a permanent entry, and the .partial must be gone.
        let p = cache.path_for(&declared_hash);
        assert!(!p.exists(), "final path should not exist after mismatch");
        let partial = p.with_extension("partial");
        assert!(!partial.exists(), ".partial should be cleaned up");
    }

    #[tokio::test]
    async fn ensure_surfaces_file_error_from_coord() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let (tx, mut rx) = mpsc::channel::<WorkerMessage>(16);

        let fake_hash = sha256_hex(b"nope");
        let cache_clone = cache.clone();
        let hash_clone = fake_hash.clone();
        tokio::spawn(async move {
            if let Some(WorkerMessage::RequestFileRange { hash, .. }) = rx.recv().await {
                assert_eq!(hash, hash_clone);
                cache_clone
                    .on_file_error(&hash, "file not found".to_string())
                    .await;
            }
        });

        let err = cache.ensure(&fake_hash, 10, &tx).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("file not found"), "got: {msg}");
    }

    #[tokio::test]
    async fn manifest_returns_empty_when_no_cache_dir() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let m = cache.manifest().await;
        assert!(m.is_empty());
    }

    #[tokio::test]
    async fn manifest_lists_cached_files_with_size() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);

        // Seed two entries directly on disk (as a successful pull would).
        let data_a = vec![0u8; 123];
        let data_b = vec![1u8; 456];
        let hash_a = sha256_hex(&data_a);
        let hash_b = sha256_hex(&data_b);
        for (hash, data) in [(&hash_a, &data_a), (&hash_b, &data_b)] {
            let p = cache.path_for(hash);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, data).unwrap();
        }

        let mut entries = cache.manifest().await;
        entries.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        assert_eq!(entries.len(), 2);
        let by_hash: std::collections::HashMap<_, _> = entries
            .into_iter()
            .map(|e| (e.sha256, e.size_bytes))
            .collect();
        assert_eq!(by_hash.get(&hash_a).copied(), Some(123));
        assert_eq!(by_hash.get(&hash_b).copied(), Some(456));
    }

    #[tokio::test]
    async fn manifest_ignores_partial_files() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let data = b"done".to_vec();
        let hash = sha256_hex(&data);
        let p = cache.path_for(&hash);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &data).unwrap();
        // Stray .partial from an aborted pull.
        std::fs::write(p.with_extension("partial"), b"halfway").unwrap();

        let entries = cache.manifest().await;
        assert_eq!(entries.len(), 1, ".partial must not appear in manifest");
        assert_eq!(entries[0].sha256, hash);
    }

    #[tokio::test]
    async fn evict_removes_cached_file_and_partial() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let data = b"gone".to_vec();
        let hash = sha256_hex(&data);
        let p = cache.path_for(&hash);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, &data).unwrap();
        std::fs::write(p.with_extension("partial"), b"stale").unwrap();

        let removed = cache.evict(&hash).await;
        assert!(removed);
        assert!(!p.exists());
        assert!(!p.with_extension("partial").exists());
    }

    #[tokio::test]
    async fn evict_missing_file_returns_false_without_error() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 100 * 1024 * 1024);
        let removed = cache.evict("nonexistent-hash").await;
        assert!(!removed);
    }

    #[tokio::test]
    async fn total_size_sums_canonical_files_only() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 1_000_000);

        for (sha, payload) in [("aabb", vec![0u8; 100]), ("ccdd", vec![1u8; 250])] {
            let p = cache.path_for(sha);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, &payload).unwrap();
        }
        // .partial files are excluded.
        let p = cache.path_for("eeff");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p.with_extension("partial"), vec![9u8; 999]).unwrap();

        assert_eq!(cache.total_size().await, 350);
    }

    #[tokio::test]
    async fn touch_persists_ledger_across_new() {
        let dir = TempDir::new();
        {
            let cache = ContentCache::new(dir.path.clone(), 1_000_000);
            cache.touch("aabb").await;
        }
        // New instance over the same root should pick up the ledger.
        let cache = ContentCache::new(dir.path.clone(), 1_000_000);
        let ledger = cache.ledger.lock().await;
        assert!(
            ledger.entries.contains_key("aabb"),
            "ledger entry should survive new() over same root"
        );
    }

    #[tokio::test]
    async fn lru_candidates_orders_by_last_used_ascending() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 1_000_000);

        for (sha, size) in [("aaone", 100u64), ("aatwo", 200), ("aathree", 300)] {
            let p = cache.path_for(sha);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, vec![0u8; size as usize]).unwrap();
        }
        // Touch in a deliberate order: three (oldest), one, two (newest).
        cache.touch("aathree").await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        cache.touch("aaone").await;
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        cache.touch("aatwo").await;

        let cands = cache.lru_candidates().await;
        let order: Vec<&str> = cands.iter().map(|c| c.sha256.as_str()).collect();
        assert_eq!(order, vec!["aathree", "aaone", "aatwo"]);
        // Sizes round-trip through the candidate metadata.
        assert_eq!(cands[0].size_bytes, 300);
        assert_eq!(cands[1].size_bytes, 100);
        assert_eq!(cands[2].size_bytes, 200);
    }

    #[tokio::test]
    async fn evict_clears_ledger_entry() {
        let dir = TempDir::new();
        let cache = ContentCache::new(dir.path.clone(), 1_000_000);
        let p = cache.path_for("aabb");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"x").unwrap();
        cache.touch("aabb").await;

        assert!(cache.ledger.lock().await.entries.contains_key("aabb"));
        assert!(cache.evict("aabb").await);
        assert!(
            !cache.ledger.lock().await.entries.contains_key("aabb"),
            "ledger should be cleaned up after eviction"
        );
    }
}
