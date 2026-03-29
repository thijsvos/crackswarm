use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crack_common::auth::Keypair;
use crack_common::protocol::CoordMessage;
use sqlx::SqlitePool;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

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

    /// Broadcast channel for TUI events.
    pub events: broadcast::Sender<AppEvent>,
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
    pub fn new(
        db: SqlitePool,
        data_dir: PathBuf,
        keypair: Keypair,
        hashcat_path: String,
        bind_addr: String,
    ) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self {
            db,
            data_dir,
            keypair,
            hashcat_path,
            bind_addr,
            worker_connections: RwLock::new(HashMap::new()),
            events,
        })
    }

    /// Emit an event to the TUI broadcast channel.
    pub fn emit(&self, event: AppEvent) {
        // Ignore send errors (no TUI subscribers in headless mode)
        let _ = self.events.send(event);
    }

    /// Get the files storage directory.
    pub fn files_dir(&self) -> PathBuf {
        self.data_dir.join("files")
    }
}
