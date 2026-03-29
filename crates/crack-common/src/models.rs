use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Task ──

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Pending,
    Ready,
    Running,
    Completed,
    Failed,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Pending,
    Dispatched,
    Running,
    Completed,
    Exhausted,
    Failed,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: u32,
    pub name: String,
    pub device_type: String,
    pub speed: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStatus {
    Idle,
    Working,
    Benchmarking,
    Disconnected,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerBenchmark {
    pub worker_id: String,
    pub hash_mode: u32,
    pub speed: u64,
    pub measured_at: DateTime<Utc>,
}

// ── Audit Log ──

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentToken {
    pub coord_pubkey: String, // base64
    pub nonce: String,        // hex 16 bytes
    pub worker_name: String,
    pub expires_at: String, // ISO 8601
    #[serde(default)]
    pub server_addr: String, // coordinator transport address (host:port)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Running,
    Completed,
    Failed,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    Pending,
    Running,
    Completed,
    Exhausted,
    Failed,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskEntry {
    pub mask: String,
    pub custom_charsets: Option<Vec<String>>,
    #[serde(default)]
    pub increment: bool,
}

// ── Campaign Template ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignTemplate {
    pub name: String,
    pub description: String,
    pub hash_mode: Option<u32>,
    pub phases: Vec<TemplatePhase>,
}

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
}
