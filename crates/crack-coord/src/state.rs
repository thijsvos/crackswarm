use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use crack_common::auth::Keypair;
use crack_common::models::AuditEntry;
use crack_common::protocol::CoordMessage;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, mpsc, RwLock};
use uuid::Uuid;

/// Buffer depth for the audit-log channel feeding the background flusher.
/// Sized to absorb a reconnect storm (every connect emits an audit event)
/// without blocking the producer; events drop with a `warn!` past this.
const AUDIT_CHANNEL_CAPACITY: usize = 4096;

/// How long an active-sha snapshot is reused before re-querying.
/// 30s gives the heartbeat path a stable view across the typical 15s
/// heartbeat cadence: the first heartbeat in a window rebuilds, the next
/// few read from cache. Bounded staleness is acceptable here — at worst
/// drift correction either sends an unnecessary `EvictFile` (the agent's
/// `evict` is idempotent) or misses one for 30s (next heartbeat catches
/// it).
const ACTIVE_SHAS_TTL: Duration = Duration::from_secs(30);

/// Cached snapshot of every sha256 currently considered "live"
/// (`gc_state = 'active'` in the `files` table). See [`AppState::get_active_shas`].
struct ActiveShasCache {
    snapshot: Arc<HashSet<String>>,
    loaded_at: Instant,
}

/// Shared application state accessible from REST API, transport handler, scheduler, and TUI.
pub struct AppState {
    pub db: SqlitePool,
    pub data_dir: PathBuf,
    pub keypair: Keypair,

    /// Path to the hashcat binary (for keyspace computation).
    pub hashcat_path: String,

    /// Worker Noise transport bind address (included in enrollment tokens).
    pub bind_addr: String,

    /// Connected workers: worker_id → sender for Noise messages.
    pub worker_connections: RwLock<HashMap<String, WorkerConnection>>,

    /// Task IDs currently being prepared by the monitor (keyspace + hash count).
    /// Prevents double-spawn when a prep takes longer than one monitor tick.
    pub preparing_tasks: RwLock<HashSet<Uuid>>,

    /// Broadcast channel for TUI events.
    pub events: broadcast::Sender<AppEvent>,

    /// Outbound side of the audit log channel. Drained by
    /// `crate::audit::run_audit_flusher`, which batches inserts every
    /// ~500ms or 64 events. Use [`Self::emit_audit`] to send.
    pub audit_tx: mpsc::Sender<AuditEntry>,

    /// `(worker_id, hash_mode) → speed (h/s)` cache, populated by
    /// `record_benchmark` on every BenchmarkResult and on first read-through
    /// from `worker_benchmarks`. Avoids hitting SQLite for the speed lookup
    /// on every chunk dispatch — the assigner reads this on the hot path
    /// per worker per chunk.
    pub benchmark_cache: RwLock<HashMap<(String, u32), u64>>,

    /// TTL-cached snapshot of the active-sha set. Invalidates passively after
    /// [`ACTIVE_SHAS_TTL`]; see [`Self::get_active_shas`] for the exact
    /// staleness contract. `None` until the first read repopulates.
    active_shas: RwLock<Option<ActiveShasCache>>,
}

#[allow(dead_code)]
pub struct WorkerConnection {
    pub worker_id: String,
    pub name: String,
    pub tx: tokio::sync::mpsc::Sender<CoordMessage>,
    pub peer_addr: String,
}

/// Events broadcast to the TUI for live updates.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum AppEvent {
    WorkerConnected {
        worker_id: String,
        name: String,
    },
    WorkerDisconnected {
        worker_id: String,
    },
    TaskCreated {
        task_id: Uuid,
    },
    TaskUpdated {
        task_id: Uuid,
    },
    ChunkProgress {
        task_id: Uuid,
        chunk_id: Uuid,
        progress: f64,
        speed: u64,
    },
    HashCracked {
        task_id: Uuid,
        hash: String,
    },
    TaskCompleted {
        task_id: Uuid,
    },
    AuditEntry {
        event_type: String,
        details: String,
    },
    CampaignCreated {
        campaign_id: Uuid,
    },
    CampaignPhaseAdvanced {
        campaign_id: Uuid,
        phase_index: u32,
    },
    CampaignCompleted {
        campaign_id: Uuid,
    },
}

impl AppState {
    /// Construct shared coord state and the audit-log receiver that the
    /// caller hands to [`crate::audit::run_audit_flusher`] in a spawned
    /// task. The receiver is returned (not owned by `AppState`) because
    /// `Receiver` is single-consumer and threading it through `Arc`
    /// would require interior mutability.
    pub fn new(
        db: SqlitePool,
        data_dir: PathBuf,
        keypair: Keypair,
        hashcat_path: String,
        bind_addr: String,
    ) -> (Arc<Self>, mpsc::Receiver<AuditEntry>) {
        let (events, _) = broadcast::channel(1024);
        let (audit_tx, audit_rx) = mpsc::channel(AUDIT_CHANNEL_CAPACITY);
        let state = Arc::new(Self {
            db,
            data_dir,
            keypair,
            hashcat_path,
            bind_addr,
            worker_connections: RwLock::new(HashMap::new()),
            preparing_tasks: RwLock::new(HashSet::new()),
            events,
            audit_tx,
            benchmark_cache: RwLock::new(HashMap::new()),
            active_shas: RwLock::new(None),
        });
        (state, audit_rx)
    }

    /// Emit an event to the TUI broadcast channel.
    pub fn emit(&self, event: AppEvent) {
        // Ignore send errors (no TUI subscribers in headless mode)
        let _ = self.events.send(event);
    }

    /// Queue an audit-log entry for the background flusher.
    ///
    /// Best-effort: drops with a `warn!` if the channel buffer (4096 events)
    /// is full. Audit is a side-channel — if we're sustained-overrunning a
    /// 4k-deep buffer, the system has bigger problems than a few missing
    /// audit rows.
    pub fn emit_audit(
        &self,
        event_type: &str,
        details: &str,
        source_ip: Option<&str>,
        worker_id: Option<&str>,
    ) {
        let entry = AuditEntry {
            id: None,
            event_type: event_type.to_string(),
            details: details.to_string(),
            source_ip: source_ip.map(String::from),
            worker_id: worker_id.map(String::from),
            created_at: Utc::now(),
        };
        if let Err(err) = self.audit_tx.try_send(entry) {
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!(event_type, "audit channel full, dropping event");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::warn!(event_type, "audit channel closed, dropping event");
                }
            }
        }
    }

    /// Read-through cache for the worker speed used in chunk-size sizing.
    ///
    /// Returns `Ok(None)` when the worker has never reported a benchmark
    /// for this hash mode. The cache is populated on first hit so subsequent
    /// dispatches skip the SELECT.
    pub async fn get_worker_speed(
        &self,
        worker_id: &str,
        hash_mode: u32,
    ) -> anyhow::Result<Option<u64>> {
        if let Some(&speed) = self
            .benchmark_cache
            .read()
            .await
            .get(&(worker_id.to_string(), hash_mode))
        {
            return Ok(Some(speed));
        }
        match crate::storage::db::get_benchmark(&self.db, worker_id, hash_mode).await? {
            Some(b) => {
                self.benchmark_cache
                    .write()
                    .await
                    .insert((worker_id.to_string(), hash_mode), b.speed);
                Ok(Some(b.speed))
            }
            None => Ok(None),
        }
    }

    /// Persist a freshly-reported benchmark and update the cache.
    pub async fn record_benchmark(
        &self,
        worker_id: &str,
        hash_mode: u32,
        speed: u64,
    ) -> anyhow::Result<()> {
        crate::storage::db::upsert_benchmark(&self.db, worker_id, hash_mode, speed).await?;
        self.benchmark_cache
            .write()
            .await
            .insert((worker_id.to_string(), hash_mode), speed);
        Ok(())
    }

    /// Snapshot of every sha256 with `gc_state = 'active'` in `files`.
    ///
    /// Cached for [`ACTIVE_SHAS_TTL`]; the heartbeat handler hits this on
    /// every drift-correction tick (per worker, every 15s) and the
    /// register handler hits it on every connect. Without the cache that
    /// was N × `SELECT DISTINCT sha256 FROM files` round-trips per 30s
    /// window; with it, ~1.
    ///
    /// Returned `Arc` is a snapshot — callers can iterate without holding
    /// any lock past this call.
    pub async fn get_active_shas(&self) -> anyhow::Result<Arc<HashSet<String>>> {
        // Fast path: read lock + freshness check.
        if let Some(cache) = self.active_shas.read().await.as_ref() {
            if cache.loaded_at.elapsed() < ACTIVE_SHAS_TTL {
                return Ok(cache.snapshot.clone());
            }
        }

        // Stale or empty: rebuild under write lock, re-checking in case
        // another caller raced us to the rebuild.
        let mut wguard = self.active_shas.write().await;
        if let Some(cache) = wguard.as_ref() {
            if cache.loaded_at.elapsed() < ACTIVE_SHAS_TTL {
                return Ok(cache.snapshot.clone());
            }
        }
        let list = crate::storage::db::list_active_file_shas(&self.db).await?;
        let snap: Arc<HashSet<String>> = Arc::new(list.into_iter().collect());
        *wguard = Some(ActiveShasCache {
            snapshot: snap.clone(),
            loaded_at: Instant::now(),
        });
        Ok(snap)
    }

    /// Get the files storage directory.
    pub fn files_dir(&self) -> PathBuf {
        self.data_dir.join("files")
    }
}
