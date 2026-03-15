use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::models::DeviceInfo;

/// Messages sent from coordinator to worker over the Noise-encrypted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordMessage {
    Welcome {
        worker_id: String,
    },
    AssignChunk {
        chunk_id: Uuid,
        task_id: Uuid,
        hash_mode: u32,
        /// Hash file content (base64-encoded) sent over the encrypted channel.
        hash_file_b64: String,
        hash_file_id: String,
        skip: u64,
        limit: u64,
        mask: String,
        custom_charsets: Option<Vec<String>>,
        extra_args: Vec<String>,
    },
    AbortChunk {
        chunk_id: Uuid,
    },
    RequestBenchmark {
        hash_mode: u32,
    },
    Shutdown,
}

/// Messages sent from worker to coordinator over the Noise-encrypted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerMessage {
    Register {
        worker_name: String,
        hashcat_version: String,
        os: String,
        devices: Vec<DeviceInfo>,
    },
    Enroll {
        nonce: String,
        worker_name: String,
    },
    Heartbeat,
    ChunkStarted {
        chunk_id: Uuid,
    },
    ChunkProgress {
        chunk_id: Uuid,
        progress_pct: f64,
        speed: u64,
        estimated_remaining_secs: Option<u64>,
    },
    HashCracked {
        chunk_id: Uuid,
        task_id: Uuid,
        hash: String,
        plaintext: String,
    },
    ChunkCompleted {
        chunk_id: Uuid,
        exit_code: i32,
        total_cracked: u32,
    },
    ChunkFailed {
        chunk_id: Uuid,
        error: String,
        exit_code: Option<i32>,
    },
    BenchmarkResult {
        hash_mode: u32,
        speed: u64,
    },
    Draining,
    Leaving,
}

/// Length-prefixed framing for Noise transport messages.
/// Wire format: [4 bytes big-endian length][encrypted payload]
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB

/// Encode a message to bytes for transmission.
pub fn encode_message<T: Serialize>(msg: &T) -> crate::error::Result<Vec<u8>> {
    let json = serde_json::to_vec(msg)?;
    let len = (json.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Read a length-prefixed message from a stream of bytes.
/// Returns the deserialized message and the number of bytes consumed.
pub fn decode_message<T: for<'de> Deserialize<'de>>(buf: &[u8]) -> crate::error::Result<Option<(T, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(crate::error::CrackError::Protocol(format!(
            "message too large: {len} bytes"
        )));
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let msg: T = serde_json::from_slice(&buf[4..4 + len])?;
    Ok(Some((msg, 4 + len)))
}
