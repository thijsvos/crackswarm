//! Shared data model: tasks, chunks, workers, campaigns, and the REST
//! request/response shapes wrapping them.
//!
//! Every type here is `Serialize + Deserialize` and crosses two
//! boundaries: the SQLite tables behind `crack-coord::storage::db` and
//! the public REST API. Field names are wire-format contracts —
//! renaming is a breaking change for both the agent build and any
//! external API consumer.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Task ──

/// A cracking task: a single attack configuration applied to a single
/// hash file. Has a lifecycle (`TaskStatus`) driven by the coord's
/// monitor loop; `next_skip` tracks the cursor used to allocate the next
/// chunk. `total_keyspace` is filled in during preparation by
/// `hashcat --keyspace`. A task may belong to a `Campaign` (multi-phase
/// orchestration) or stand alone (`campaign_id == None`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub name: String,
    pub hash_mode: u32,
    pub hash_file_id: String,
    pub attack_config: AttackConfig,
    pub total_keyspace: Option<u64>,
    pub next_skip: u64,
    pub priority: u8,
    pub status: TaskStatus,
    pub total_hashes: u32,
    pub cracked_count: u32,
    pub extra_args: Vec<String>,
    pub campaign_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lifecycle states of a [`Task`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Created, awaiting preparation (hash count + keyspace).
    Pending,
    /// Prepared, no chunk has been dispatched yet.
    Ready,
    /// At least one chunk has been dispatched or is in flight.
    Running,
    /// Keyspace fully exhausted (or all hashes cracked).
    Completed,
    /// Prep failed or all chunks failed.
    Failed,
    /// Manually stopped via the API.
    Cancelled,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Ready => write!(f, "ready"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for TaskStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("unknown task status: {s}")),
        }
    }
}

// ── Attack Config ──

/// Attack mode for a [`Task`]. Maps onto hashcat attack modes 3 (mask),
/// 0 (dictionary), and 0 + `-r` (dictionary with rules). The chunker
/// uses this both to compute keyspace and to assemble the per-chunk
/// `AssignChunkAttack` sent to the worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AttackConfig {
    BruteForce {
        mask: String,
        custom_charsets: Option<Vec<String>>,
    },
    Dictionary {
        wordlist_file_id: String,
    },
    DictionaryWithRules {
        wordlist_file_id: String,
        rules_file_id: String,
    },
}

// ── Chunk ──

/// A unit of work assigned to a single worker. `skip`/`limit` are
/// hashcat restore points carved out of the parent task's keyspace;
/// `assigned_worker` is `None` until dispatch. `progress` is a 0–100
/// percentage updated from `WorkerMessage::ChunkProgress`. `speed` is
/// the most recent observed hash rate (H/s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    pub id: Uuid,
    pub task_id: Uuid,
    pub skip: u64,
    pub limit: u64,
    pub status: ChunkStatus,
    pub assigned_worker: Option<String>,
    pub assigned_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub progress: f64,
    pub speed: u64,
    pub cracked_count: u32,
}

/// Lifecycle of a [`Chunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    /// Carved out but not yet dispatched.
    Pending,
    /// Assignment was sent; no `ChunkStarted` ack received yet.
    Dispatched,
    /// Worker has spawned hashcat for this chunk.
    Running,
    /// Hashcat exited with results found.
    Completed,
    /// Hashcat exited without finding any hashes (keyspace consumed).
    Exhausted,
    /// Hashcat failed (spawn error, killed, or unrecognized exit).
    Failed,
    /// Worker stopped sending heartbeats with the chunk in flight; the
    /// chunk is re-cut and re-dispatched.
    Abandoned,
}

impl std::fmt::Display for ChunkStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Dispatched => write!(f, "dispatched"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Exhausted => write!(f, "exhausted"),
            Self::Failed => write!(f, "failed"),
            Self::Abandoned => write!(f, "abandoned"),
        }
    }
}

impl std::str::FromStr for ChunkStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "dispatched" => Ok(Self::Dispatched),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "exhausted" => Ok(Self::Exhausted),
            "failed" => Ok(Self::Failed),
            "abandoned" => Ok(Self::Abandoned),
            _ => Err(format!("unknown chunk status: {s}")),
        }
    }
}

// ── Worker ──

/// A registered cracking node. `id` is the coord's stable identifier
/// (derived from the worker's static public key); `public_key` is the
/// authorized Noise static key (base64) used to authenticate every
/// reconnect. `last_seen_at` is updated on every heartbeat and drives
/// the disconnect-on-timeout logic in the monitor loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub devices: Vec<DeviceInfo>,
    pub hashcat_version: Option<String>,
    pub os: Option<String>,
    pub status: WorkerStatus,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// One compute device attached to a worker (CPU/GPU). `speed` is `None`
/// until a benchmark has run for the device's preferred hash mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: u32,
    pub name: String,
    pub device_type: String,
    pub speed: Option<u64>,
}

/// Liveness state for a [`Worker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    /// Connected, no chunk in flight.
    Idle,
    /// At least one chunk is being processed.
    Working,
    /// Currently running `hashcat --benchmark`.
    Benchmarking,
    /// Heartbeat timeout exceeded; chunks are reassigned.
    Disconnected,
    /// Will not accept new chunks but is finishing in-flight work.
    Draining,
}

impl std::fmt::Display for WorkerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Working => write!(f, "working"),
            Self::Benchmarking => write!(f, "benchmarking"),
            Self::Disconnected => write!(f, "disconnected"),
            Self::Draining => write!(f, "draining"),
        }
    }
}

impl std::str::FromStr for WorkerStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "idle" => Ok(Self::Idle),
            "working" => Ok(Self::Working),
            "benchmarking" => Ok(Self::Benchmarking),
            "disconnected" => Ok(Self::Disconnected),
            "draining" => Ok(Self::Draining),
            _ => Err(format!("unknown worker status: {s}")),
        }
    }
}

// ── Cracked Hash ──

/// One discovered (hash, plaintext) pair. Inserted as soon as the
/// worker emits `WorkerMessage::HashCracked` so operators see results
/// in real time rather than at chunk completion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackedHash {
    pub id: Option<i64>,
    pub task_id: Uuid,
    pub hash: String,
    pub plaintext: String,
    pub worker_id: String,
    pub cracked_at: DateTime<Utc>,
}

// ── File Record ──

/// A file stored under the coord's content-addressed cache. `id` is a
/// per-row UUID; `sha256` is the content hash used for dedup and for
/// agent-side cache addressing. Soft-deleted rows (`gc_state =
/// 'deleted'`) are filtered out by the lookup helpers in
/// `storage::db` but remain as FK targets for historical joins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub id: String,
    pub filename: String,
    pub file_type: String,
    pub size_bytes: i64,
    pub sha256: String,
    pub disk_path: String,
    pub uploaded_at: DateTime<Utc>,
}

// ── Worker Benchmark ──

/// Most recent measured hash rate for a `(worker, hash_mode)` pair.
/// Used by `chunker::calculate_chunk_size` to target ~10 minutes of
/// work per chunk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBenchmark {
    pub worker_id: String,
    pub hash_mode: u32,
    pub speed: u64,
    pub measured_at: DateTime<Utc>,
}

// ── Audit Log ──

/// One row of the security/operations audit log. Recorded for any state
/// transition that crosses a trust boundary (worker enrollment,
/// authorization, task creation, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Option<i64>,
    pub event_type: String,
    pub details: String,
    pub source_ip: Option<String>,
    pub worker_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ── System Status ──

/// Coord-wide counters returned by `GET /api/v1/status` for the TUI and
/// `crackctl status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub total_tasks: u32,
    pub running_tasks: u32,
    pub total_workers: u32,
    pub connected_workers: u32,
    pub total_cracked: u64,
    pub aggregate_speed: u64,
}

// ── Enrollment Token ──

/// One-shot bootstrap credential the operator hands to a new worker.
///
/// Bundles everything an unenrolled agent needs for first contact: the
/// coord's static public key (so the IK handshake authenticates the
/// responder), the single-use `nonce` the coord expects in the
/// worker's `Enroll` message, the assigned `worker_name`, an expiry,
/// and the coord's transport address.
///
/// `server_addr` is `#[serde(default)]` for backwards compatibility
/// with tokens issued before the field was added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    /// Coordinator's static public key, base64-encoded.
    pub coord_pubkey: String,
    /// Single-use, 16-byte hex nonce.
    pub nonce: String,
    /// Friendly name assigned to this worker on enrollment.
    pub worker_name: String,
    /// ISO 8601 expiry timestamp (rejected after this).
    pub expires_at: String,
    /// Coordinator transport address as `host:port`.
    #[serde(default)]
    pub server_addr: String,
}

// ── API request/response types ──

#[derive(Debug, Deserialize)]
pub struct CreateTaskRequest {
    pub name: String,
    pub hash_mode: u32,
    pub hash_file_id: String,
    pub attack_config: AttackConfig,
    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default)]
    pub extra_args: Vec<String>,
}

fn default_priority() -> u8 {
    5
}

#[derive(Debug, Deserialize)]
pub struct UpdateTaskRequest {
    pub status: Option<TaskStatus>,
}

// ── Campaign ──

/// Multi-phase orchestration over a single hash file. Each phase
/// produces a downstream `Task`; remaining-hashes are passed forward so
/// later phases only attack what earlier phases didn't crack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: Uuid,
    pub name: String,
    pub hash_mode: u32,
    pub original_hash_file_id: String,
    pub status: CampaignStatus,
    pub active_phase_index: Option<u32>,
    pub total_phases: u32,
    pub total_hashes: u32,
    pub cracked_count: u32,
    pub priority: u8,
    pub extra_args: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lifecycle states of a [`Campaign`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    /// Created but not yet started.
    Draft,
    /// At least one phase has been launched.
    Running,
    /// All phases completed (or all hashes cracked).
    Completed,
    /// A phase failed terminally and the campaign aborted.
    Failed,
    /// Manually stopped via the API.
    Cancelled,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for CampaignStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "draft" => Ok(Self::Draft),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(format!("unknown campaign status: {s}")),
        }
    }
}

// ── Campaign Phase ──

/// One attack phase within a [`Campaign`]. Spawns a `Task` when
/// activated; `hash_file_id` is the (possibly remaining-only) input
/// for this phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignPhase {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub phase_index: u32,
    pub name: String,
    pub status: PhaseStatus,
    pub config: PhaseConfig,
    pub task_id: Option<Uuid>,
    pub hash_file_id: Option<String>,
    pub cracked_count: u32,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Lifecycle states of a [`CampaignPhase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    /// Not yet activated.
    Pending,
    /// Phase task is in flight.
    Running,
    /// Phase task completed with results found.
    Completed,
    /// Phase task ran but found nothing.
    Exhausted,
    /// Phase task failed; campaign aborted.
    Failed,
    /// Auto-skipped (e.g. all hashes already cracked by a prior phase).
    Skipped,
}

impl std::fmt::Display for PhaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Exhausted => write!(f, "exhausted"),
            Self::Failed => write!(f, "failed"),
            Self::Skipped => write!(f, "skipped"),
        }
    }
}

impl std::str::FromStr for PhaseStatus {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "exhausted" => Ok(Self::Exhausted),
            "failed" => Ok(Self::Failed),
            "skipped" => Ok(Self::Skipped),
            _ => Err(format!("unknown phase status: {s}")),
        }
    }
}

// ── Phase Config ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PhaseConfig {
    StaticMask {
        mask: String,
        custom_charsets: Option<Vec<String>>,
    },
    MultiMask {
        masks: Vec<MaskEntry>,
    },
    AutoGenerated {
        min_sample_size: u32,
        max_masks: u32,
    },
    ExpandingBrute {
        charset: String,
        min_length: u32,
        max_length: u32,
        custom_charsets: Option<Vec<String>>,
    },
    Dictionary {
        wordlist_file_id: String,
        rules: Vec<String>,
    },
    Hybrid {
        wordlist_file_id: String,
        mask: String,
        mode: u32,
    },
}

/// One mask in a `MultiMask` phase. `increment` toggles hashcat's
/// `--increment` flag for variable-length attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskEntry {
    pub mask: String,
    pub custom_charsets: Option<Vec<String>>,
    #[serde(default)]
    pub increment: bool,
}

// ── Campaign Template ──

/// A reusable named recipe for a campaign — produces a series of
/// [`TemplatePhase`]s when instantiated. Loaded from
/// `<data_dir>/templates/`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTemplate {
    pub name: String,
    pub description: String,
    pub hash_mode: Option<u32>,
    pub phases: Vec<TemplatePhase>,
}

/// One phase entry inside a [`CampaignTemplate`]. Materializes into a
/// [`CampaignPhase`] at instantiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplatePhase {
    pub name: String,
    pub config: PhaseConfig,
}

// ── Campaign API request types ──

#[derive(Debug, Deserialize)]
pub struct CreateCampaignRequest {
    pub name: String,
    pub hash_mode: u32,
    pub hash_file_id: String,
    #[serde(default)]
    pub phases: Vec<CreatePhaseRequest>,
    pub template: Option<String>,
    #[serde(default = "default_priority")]
    pub priority: u8,
    #[serde(default)]
    pub extra_args: Vec<String>,
    /// Wordlist file ID for dictionary phases in templates.
    pub wordlist_file_id: Option<String>,
    /// Rules file ID for dictionary+rules phases in templates.
    pub rules_file_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreatePhaseRequest {
    pub name: String,
    pub config: PhaseConfig,
}

#[derive(Debug, Deserialize)]
pub struct UpdateCampaignRequest {
    pub status: Option<CampaignStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrollment_token_with_server_addr() {
        let token = EnrollmentToken {
            coord_pubkey: "abc123".to_string(),
            nonce: "deadbeef".to_string(),
            worker_name: "gpu-1".to_string(),
            expires_at: "2026-01-01T00:00:00Z".to_string(),
            server_addr: "198.51.100.1:8443".to_string(),
        };
        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("server_addr"));
        assert!(json.contains("198.51.100.1:8443"));

        let decoded: EnrollmentToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.server_addr, "198.51.100.1:8443");
        assert_eq!(decoded.coord_pubkey, "abc123");
    }

    #[test]
    fn test_enrollment_token_backward_compat_no_server_addr() {
        // Old tokens without server_addr should deserialize with empty default
        let json = r#"{
            "coord_pubkey": "abc123",
            "nonce": "deadbeef",
            "worker_name": "gpu-1",
            "expires_at": "2026-01-01T00:00:00Z"
        }"#;
        let token: EnrollmentToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.server_addr, "");
        assert_eq!(token.worker_name, "gpu-1");
    }

    #[test]
    fn test_enrollment_token_base64_roundtrip() {
        use base64::Engine;
        let token = EnrollmentToken {
            coord_pubkey: "AABBCC==".to_string(),
            nonce: "0123456789abcdef".to_string(),
            worker_name: "test-worker".to_string(),
            expires_at: "2026-03-15T12:00:00Z".to_string(),
            server_addr: "0.0.0.0:8443".to_string(),
        };
        let json = serde_json::to_vec(&token).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&json);

        let decoded_json = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap();
        let decoded: EnrollmentToken = serde_json::from_slice(&decoded_json).unwrap();
        assert_eq!(decoded.server_addr, "0.0.0.0:8443");
        assert_eq!(decoded.worker_name, "test-worker");
    }

    // ── AttackConfig serde round-trips ──

    #[test]
    fn attack_config_brute_force_serde() {
        let config = AttackConfig::BruteForce {
            mask: "?a?a?a?a".to_string(),
            custom_charsets: Some(vec!["?l?d".to_string()]),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"brute_force\""));
        let decoded: AttackConfig = serde_json::from_str(&json).unwrap();
        match decoded {
            AttackConfig::BruteForce {
                mask,
                custom_charsets,
            } => {
                assert_eq!(mask, "?a?a?a?a");
                assert_eq!(custom_charsets, Some(vec!["?l?d".to_string()]));
            }
            other => panic!("expected BruteForce, got {other:?}"),
        }
    }

    #[test]
    fn attack_config_dictionary_serde() {
        let config = AttackConfig::Dictionary {
            wordlist_file_id: "wl-42".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"dictionary\""));
        let decoded: AttackConfig = serde_json::from_str(&json).unwrap();
        match decoded {
            AttackConfig::Dictionary { wordlist_file_id } => {
                assert_eq!(wordlist_file_id, "wl-42");
            }
            other => panic!("expected Dictionary, got {other:?}"),
        }
    }

    #[test]
    fn attack_config_dict_rules_serde() {
        let config = AttackConfig::DictionaryWithRules {
            wordlist_file_id: "wl-1".to_string(),
            rules_file_id: "rl-1".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"dictionary_with_rules\""));
        let decoded: AttackConfig = serde_json::from_str(&json).unwrap();
        match decoded {
            AttackConfig::DictionaryWithRules {
                wordlist_file_id,
                rules_file_id,
            } => {
                assert_eq!(wordlist_file_id, "wl-1");
                assert_eq!(rules_file_id, "rl-1");
            }
            other => panic!("expected DictionaryWithRules, got {other:?}"),
        }
    }

    // ── Status enum Display + FromStr round-trips ──

    #[test]
    fn task_status_roundtrip() {
        let variants = [
            TaskStatus::Pending,
            TaskStatus::Ready,
            TaskStatus::Running,
            TaskStatus::Completed,
            TaskStatus::Failed,
            TaskStatus::Cancelled,
        ];
        for variant in variants {
            let s = variant.to_string();
            let parsed: TaskStatus = s.parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn chunk_status_roundtrip() {
        let variants = [
            ChunkStatus::Pending,
            ChunkStatus::Dispatched,
            ChunkStatus::Running,
            ChunkStatus::Completed,
            ChunkStatus::Exhausted,
            ChunkStatus::Failed,
            ChunkStatus::Abandoned,
        ];
        for variant in variants {
            let s = variant.to_string();
            let parsed: ChunkStatus = s.parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn campaign_status_roundtrip() {
        let variants = [
            CampaignStatus::Draft,
            CampaignStatus::Running,
            CampaignStatus::Completed,
            CampaignStatus::Failed,
            CampaignStatus::Cancelled,
        ];
        for variant in variants {
            let s = variant.to_string();
            let parsed: CampaignStatus = s.parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn phase_status_roundtrip() {
        let variants = [
            PhaseStatus::Pending,
            PhaseStatus::Running,
            PhaseStatus::Completed,
            PhaseStatus::Exhausted,
            PhaseStatus::Failed,
            PhaseStatus::Skipped,
        ];
        for variant in variants {
            let s = variant.to_string();
            let parsed: PhaseStatus = s.parse().unwrap();
            assert_eq!(parsed, variant);
        }
    }
}
