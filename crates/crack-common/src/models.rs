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
