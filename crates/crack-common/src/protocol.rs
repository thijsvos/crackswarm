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
    /// Stream a file to the worker in chunks. The agent reconstructs
    /// the file from ordered chunks and caches it by file_id.
    TransferFileChunk {
        file_id: String,
        filename: String,
        chunk_index: u32,
        total_chunks: u32,
        /// ~40KB of raw data, base64-encoded (fits in a single Noise frame).
        data_b64: String,
    },
    /// Response to `WorkerMessage::RequestFileRange`. Carries a byte range
    /// of the file identified by `hash` (sha256 hex). `eof = true` when
    /// `offset + data.len() >= total file size`, signalling the worker to
    /// stop its pull loop.
    FileRange {
        hash: String,
        offset: u64,
        /// Raw bytes, base64-encoded to fit the JSON wire format.
        data_b64: String,
        eof: bool,
    },
    /// Sent in place of `FileRange` when the coord can't serve the request
    /// (file not found, read error, etc.). The worker aborts its pull and
    /// surfaces the reason.
    FileError {
        hash: String,
        reason: String,
    },
    /// Instruct the worker to evict a file from its content-addressed cache.
    /// Issued by the coord's GC loop after a file's reference count drops
    /// to zero and pin state is clear. The worker defers eviction until no
    /// running chunk is using the file.
    EvictFile {
        hash: String,
    },
    /// Sent once when a worker (re)connects: the authoritative list of
    /// sha256s the coord still has on its end. The agent compares against
    /// its own cache manifest and evicts anything not in `expected` —
    /// catches missed `EvictFile` messages from prior sessions and any
    /// drift accumulated while the agent was disconnected. Eviction
    /// defers as usual when a sha is in use by a running chunk.
    CacheReconcile {
        expected: Vec<String>,
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
        attack: AssignChunkAttack,
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

/// Attack-specific fields for chunk assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AssignChunkAttack {
    BruteForce {
        mask: String,
        custom_charsets: Option<Vec<String>>,
    },
    /// Legacy: agent receives the wordlist bytes eagerly via TransferFileChunk
    /// before this message. Kept for backwards compatibility; new coord
    /// code prefers `DictionaryByHash` for dictionary attacks.
    Dictionary { wordlist_file_id: String },
    /// Legacy: same as `Dictionary` but with a rules file also pushed eagerly.
    DictionaryWithRules {
        wordlist_file_id: String,
        rules_file_id: String,
    },
    /// Pull-based dispatch: the agent looks up the referenced files in its
    /// content-addressed cache by sha256; on miss, it fetches them via
    /// `RequestFileRange`/`FileRange` from the coord. No eager push.
    DictionaryByHash {
        wordlist_sha256: String,
        wordlist_size: u64,
        rules_sha256: Option<String>,
        rules_size: Option<u64>,
    },
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
    /// Periodic heartbeat. Carries a compact digest of the worker's
    /// content-addressed cache so the coord can maintain an authoritative
    /// view of what each worker has on disk — used for targeted
    /// `EvictFile` dispatch (Slice 8) and full reconciliation on
    /// (re)connect (Slice 9).
    ///
    /// `cache_manifest` is `#[serde(default)]` for backwards compatibility
    /// with older agents whose heartbeat carries no manifest.
    Heartbeat {
        #[serde(default)]
        cache_manifest: Vec<CacheManifestEntry>,
    },
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
    /// Ask the coord to send a byte range of a file identified by content
    /// hash (sha256 hex). The coord responds with one or more
    /// `CoordMessage::FileRange` messages, or a `CoordMessage::FileError`
    /// if the request can't be served. The worker drives the pull loop
    /// (next request sent after the previous response arrives).
    RequestFileRange {
        hash: String,
        offset: u64,
        length: u32,
    },
    /// Response to `CoordMessage::CacheReconcile`. `kept` is the set of
    /// sha256s the worker still has after the reconcile pass; `evicted`
    /// is what was removed (informational). The coord uses `kept` to
    /// rewrite `worker_cache_entries` for this worker.
    CacheAck {
        kept: Vec<String>,
        evicted: Vec<String>,
    },
    /// Worker couldn't fetch a file required by a chunk (insufficient
    /// disk after LRU eviction, content cache budget exhausted, etc.).
    /// Coord treats this like `ChunkFailed` but with a clearer reason —
    /// the chunk gets reassigned, ideally to a worker with more cache
    /// headroom.
    PullFailed {
        chunk_id: Uuid,
        hash: String,
        reason: String,
    },
}

/// Compact digest of a single cached file, carried on every agent
/// heartbeat so the coord can reconcile the agent's cache against its
/// own view of `worker_cache_entries`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheManifestEntry {
    /// Content hash of the cached file.
    pub sha256: String,
    /// Size in bytes (must match the coord's `files.size_bytes` for the
    /// entry to be considered valid).
    pub size_bytes: u64,
    /// RFC3339 timestamp of last use (approximated from file mtime until
    /// Slice 10 introduces an explicit ledger).
    pub last_used_at: String,
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
pub fn decode_message<T: for<'de> Deserialize<'de>>(
    buf: &[u8],
) -> crate::error::Result<Option<(T, usize)>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DeviceInfo;
    use uuid::Uuid;

    // ── CoordMessage round-trips ──

    #[test]
    fn roundtrip_welcome() {
        let msg = CoordMessage::Welcome {
            worker_id: "test-123".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::Welcome { worker_id } => assert_eq!(worker_id, "test-123"),
            other => panic!("expected Welcome, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_transfer_file_chunk() {
        let msg = CoordMessage::TransferFileChunk {
            file_id: "file-abc".to_string(),
            filename: "rockyou.txt".to_string(),
            chunk_index: 3,
            total_chunks: 10,
            data_b64: "SGVsbG8gV29ybGQ=".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::TransferFileChunk {
                file_id,
                filename,
                chunk_index,
                total_chunks,
                data_b64,
            } => {
                assert_eq!(file_id, "file-abc");
                assert_eq!(filename, "rockyou.txt");
                assert_eq!(chunk_index, 3);
                assert_eq!(total_chunks, 10);
                assert_eq!(data_b64, "SGVsbG8gV29ybGQ=");
            }
            other => panic!("expected TransferFileChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_assign_chunk_brute_force() {
        let chunk_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let msg = CoordMessage::AssignChunk {
            chunk_id,
            task_id,
            hash_mode: 1000,
            hash_file_b64: "aGFzaGVz".to_string(),
            hash_file_id: "hf-001".to_string(),
            skip: 0,
            limit: 50000,
            attack: AssignChunkAttack::BruteForce {
                mask: "?a?a?a?a".to_string(),
                custom_charsets: Some(vec!["?l?d".to_string()]),
            },
            extra_args: vec!["--force".to_string()],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::AssignChunk {
                chunk_id: cid,
                task_id: tid,
                hash_mode,
                hash_file_b64,
                hash_file_id,
                skip,
                limit,
                attack,
                extra_args,
            } => {
                assert_eq!(cid, chunk_id);
                assert_eq!(tid, task_id);
                assert_eq!(hash_mode, 1000);
                assert_eq!(hash_file_b64, "aGFzaGVz");
                assert_eq!(hash_file_id, "hf-001");
                assert_eq!(skip, 0);
                assert_eq!(limit, 50000);
                match attack {
                    AssignChunkAttack::BruteForce {
                        mask,
                        custom_charsets,
                    } => {
                        assert_eq!(mask, "?a?a?a?a");
                        assert_eq!(custom_charsets, Some(vec!["?l?d".to_string()]));
                    }
                    other => panic!("expected BruteForce, got {other:?}"),
                }
                assert_eq!(extra_args, vec!["--force".to_string()]);
            }
            other => panic!("expected AssignChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_assign_chunk_dictionary() {
        let chunk_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let msg = CoordMessage::AssignChunk {
            chunk_id,
            task_id,
            hash_mode: 0,
            hash_file_b64: "dGVzdA==".to_string(),
            hash_file_id: "hf-002".to_string(),
            skip: 100,
            limit: 200,
            attack: AssignChunkAttack::Dictionary {
                wordlist_file_id: "wl-001".to_string(),
            },
            extra_args: vec![],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::AssignChunk { attack, .. } => match attack {
                AssignChunkAttack::Dictionary { wordlist_file_id } => {
                    assert_eq!(wordlist_file_id, "wl-001");
                }
                other => panic!("expected Dictionary, got {other:?}"),
            },
            other => panic!("expected AssignChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_assign_chunk_dict_rules() {
        let chunk_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let msg = CoordMessage::AssignChunk {
            chunk_id,
            task_id,
            hash_mode: 1000,
            hash_file_b64: "cnVsZXM=".to_string(),
            hash_file_id: "hf-003".to_string(),
            skip: 0,
            limit: 999,
            attack: AssignChunkAttack::DictionaryWithRules {
                wordlist_file_id: "wl-002".to_string(),
                rules_file_id: "rl-001".to_string(),
            },
            extra_args: vec![],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::AssignChunk { attack, .. } => match attack {
                AssignChunkAttack::DictionaryWithRules {
                    wordlist_file_id,
                    rules_file_id,
                } => {
                    assert_eq!(wordlist_file_id, "wl-002");
                    assert_eq!(rules_file_id, "rl-001");
                }
                other => panic!("expected DictionaryWithRules, got {other:?}"),
            },
            other => panic!("expected AssignChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_abort_chunk() {
        let id = Uuid::new_v4();
        let msg = CoordMessage::AbortChunk { chunk_id: id };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::AbortChunk { chunk_id } => assert_eq!(chunk_id, id),
            other => panic!("expected AbortChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_shutdown() {
        let msg = CoordMessage::Shutdown;
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(matches!(decoded, CoordMessage::Shutdown));
    }

    // ── WorkerMessage round-trips ──

    #[test]
    fn roundtrip_register() {
        let msg = WorkerMessage::Register {
            worker_name: "gpu-node-1".to_string(),
            hashcat_version: "6.2.6".to_string(),
            os: "Linux".to_string(),
            devices: vec![DeviceInfo {
                id: 1,
                name: "RTX 4090".to_string(),
                device_type: "GPU".to_string(),
                speed: Some(100_000_000),
            }],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::Register {
                worker_name,
                hashcat_version,
                os,
                devices,
            } => {
                assert_eq!(worker_name, "gpu-node-1");
                assert_eq!(hashcat_version, "6.2.6");
                assert_eq!(os, "Linux");
                assert_eq!(devices.len(), 1);
                assert_eq!(devices[0].name, "RTX 4090");
                assert_eq!(devices[0].speed, Some(100_000_000));
            }
            other => panic!("expected Register, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_enroll() {
        let msg = WorkerMessage::Enroll {
            nonce: "abcdef0123456789".to_string(),
            worker_name: "worker-1".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::Enroll { nonce, worker_name } => {
                assert_eq!(nonce, "abcdef0123456789");
                assert_eq!(worker_name, "worker-1");
            }
            other => panic!("expected Enroll, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_heartbeat_empty_manifest() {
        let msg = WorkerMessage::Heartbeat {
            cache_manifest: vec![],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::Heartbeat { cache_manifest } => {
                assert!(cache_manifest.is_empty());
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_heartbeat_with_manifest() {
        let msg = WorkerMessage::Heartbeat {
            cache_manifest: vec![
                CacheManifestEntry {
                    sha256: "aa".to_string(),
                    size_bytes: 100,
                    last_used_at: "2026-04-24T00:00:00Z".to_string(),
                },
                CacheManifestEntry {
                    sha256: "bb".to_string(),
                    size_bytes: 200,
                    last_used_at: "2026-04-24T01:00:00Z".to_string(),
                },
            ],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::Heartbeat { cache_manifest } => {
                assert_eq!(cache_manifest.len(), 2);
                assert_eq!(cache_manifest[0].sha256, "aa");
                assert_eq!(cache_manifest[0].size_bytes, 100);
                assert_eq!(cache_manifest[1].sha256, "bb");
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn decode_legacy_heartbeat_without_manifest_field() {
        // Simulates an old agent (pre-Slice-8) whose heartbeat carries
        // just `{"type":"heartbeat"}`. The `#[serde(default)]` on
        // cache_manifest should let it deserialize cleanly with an empty
        // manifest on the new coord.
        let legacy_json = r#"{"type":"heartbeat"}"#;
        let len = (legacy_json.len() as u32).to_be_bytes();
        let mut buf = Vec::new();
        buf.extend_from_slice(&len);
        buf.extend_from_slice(legacy_json.as_bytes());
        let (decoded, _): (WorkerMessage, usize) = decode_message(&buf).unwrap().unwrap();
        match decoded {
            WorkerMessage::Heartbeat { cache_manifest } => {
                assert!(cache_manifest.is_empty(), "legacy should deserialize empty");
            }
            other => panic!("expected Heartbeat, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_pull_failed() {
        let chunk_id = Uuid::new_v4();
        let msg = WorkerMessage::PullFailed {
            chunk_id,
            hash: "deadbeef".to_string(),
            reason: "insufficient disk after LRU".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, _): (WorkerMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            WorkerMessage::PullFailed {
                chunk_id: cid,
                hash,
                reason,
            } => {
                assert_eq!(cid, chunk_id);
                assert_eq!(hash, "deadbeef");
                assert!(reason.contains("disk"));
            }
            other => panic!("expected PullFailed, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_cache_reconcile() {
        let msg = CoordMessage::CacheReconcile {
            expected: vec!["aa".to_string(), "bb".to_string(), "cc".to_string()],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, _): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            CoordMessage::CacheReconcile { expected } => {
                assert_eq!(expected.len(), 3);
                assert_eq!(expected[0], "aa");
                assert_eq!(expected[2], "cc");
            }
            other => panic!("expected CacheReconcile, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_cache_ack() {
        let msg = WorkerMessage::CacheAck {
            kept: vec!["aa".to_string()],
            evicted: vec!["bb".to_string(), "cc".to_string()],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, _): (WorkerMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        match decoded {
            WorkerMessage::CacheAck { kept, evicted } => {
                assert_eq!(kept, vec!["aa".to_string()]);
                assert_eq!(evicted.len(), 2);
            }
            other => panic!("expected CacheAck, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_evict_file() {
        let msg = CoordMessage::EvictFile {
            hash: "deadbeef".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::EvictFile { hash } => assert_eq!(hash, "deadbeef"),
            other => panic!("expected EvictFile, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_chunk_progress() {
        let id = Uuid::new_v4();
        let msg = WorkerMessage::ChunkProgress {
            chunk_id: id,
            progress_pct: 45.7,
            speed: 500_000,
            estimated_remaining_secs: Some(120),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::ChunkProgress {
                chunk_id,
                progress_pct,
                speed,
                estimated_remaining_secs,
            } => {
                assert_eq!(chunk_id, id);
                assert!((progress_pct - 45.7).abs() < f64::EPSILON);
                assert_eq!(speed, 500_000);
                assert_eq!(estimated_remaining_secs, Some(120));
            }
            other => panic!("expected ChunkProgress, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_hash_cracked() {
        let chunk_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let msg = WorkerMessage::HashCracked {
            chunk_id,
            task_id,
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            plaintext: "password".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::HashCracked {
                chunk_id: cid,
                task_id: tid,
                hash,
                plaintext,
            } => {
                assert_eq!(cid, chunk_id);
                assert_eq!(tid, task_id);
                assert_eq!(hash, "5f4dcc3b5aa765d61d8327deb882cf99");
                assert_eq!(plaintext, "password");
            }
            other => panic!("expected HashCracked, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_chunk_completed() {
        let id = Uuid::new_v4();
        let msg = WorkerMessage::ChunkCompleted {
            chunk_id: id,
            exit_code: 0,
            total_cracked: 42,
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::ChunkCompleted {
                chunk_id,
                exit_code,
                total_cracked,
            } => {
                assert_eq!(chunk_id, id);
                assert_eq!(exit_code, 0);
                assert_eq!(total_cracked, 42);
            }
            other => panic!("expected ChunkCompleted, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_chunk_failed_with_exit_code() {
        let id = Uuid::new_v4();
        let msg = WorkerMessage::ChunkFailed {
            chunk_id: id,
            error: "GPU memory error".to_string(),
            exit_code: Some(-1),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::ChunkFailed {
                chunk_id,
                error,
                exit_code,
            } => {
                assert_eq!(chunk_id, id);
                assert_eq!(error, "GPU memory error");
                assert_eq!(exit_code, Some(-1));
            }
            other => panic!("expected ChunkFailed, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_chunk_failed_no_exit_code() {
        let id = Uuid::new_v4();
        let msg = WorkerMessage::ChunkFailed {
            chunk_id: id,
            error: "process killed".to_string(),
            exit_code: None,
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::ChunkFailed {
                exit_code, error, ..
            } => {
                assert_eq!(exit_code, None);
                assert_eq!(error, "process killed");
            }
            other => panic!("expected ChunkFailed, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_benchmark_result() {
        let msg = WorkerMessage::BenchmarkResult {
            hash_mode: 1000,
            speed: 5_000_000_000,
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::BenchmarkResult { hash_mode, speed } => {
                assert_eq!(hash_mode, 1000);
                assert_eq!(speed, 5_000_000_000);
            }
            other => panic!("expected BenchmarkResult, got {other:?}"),
        }
    }

    // ── Edge cases ──

    #[test]
    fn decode_empty_buffer() {
        let result: crate::error::Result<Option<(CoordMessage, usize)>> = decode_message(&[]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn decode_partial_header() {
        let result: crate::error::Result<Option<(CoordMessage, usize)>> =
            decode_message(&[0, 0, 0]);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn decode_truncated_payload() {
        // Header says 100 bytes, but buffer only has 50 bytes after header
        let mut buf = vec![0u8; 4 + 50];
        buf[0..4].copy_from_slice(&100u32.to_be_bytes());
        let result: crate::error::Result<Option<(CoordMessage, usize)>> = decode_message(&buf);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn decode_oversized_message() {
        let too_large = (MAX_MESSAGE_SIZE as u32) + 1;
        let buf = too_large.to_be_bytes();
        let result: crate::error::Result<Option<(CoordMessage, usize)>> = decode_message(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn roundtrip_assign_chunk_dict_by_hash() {
        let chunk_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let msg = CoordMessage::AssignChunk {
            chunk_id,
            task_id,
            hash_mode: 0,
            hash_file_b64: "aGY=".to_string(),
            hash_file_id: "hf-099".to_string(),
            skip: 0,
            limit: 12345,
            attack: AssignChunkAttack::DictionaryByHash {
                wordlist_sha256: "a1b2c3".to_string(),
                wordlist_size: 1_234_567,
                rules_sha256: Some("deadbeef".to_string()),
                rules_size: Some(9876),
            },
            extra_args: vec![],
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::AssignChunk { attack, .. } => match attack {
                AssignChunkAttack::DictionaryByHash {
                    wordlist_sha256,
                    wordlist_size,
                    rules_sha256,
                    rules_size,
                } => {
                    assert_eq!(wordlist_sha256, "a1b2c3");
                    assert_eq!(wordlist_size, 1_234_567);
                    assert_eq!(rules_sha256.as_deref(), Some("deadbeef"));
                    assert_eq!(rules_size, Some(9876));
                }
                other => panic!("expected DictionaryByHash, got {other:?}"),
            },
            other => panic!("expected AssignChunk, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_file_range() {
        let msg = CoordMessage::FileRange {
            hash: "deadbeef".to_string(),
            offset: 4096,
            data_b64: "YWJjZA==".to_string(),
            eof: false,
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::FileRange {
                hash,
                offset,
                data_b64,
                eof,
            } => {
                assert_eq!(hash, "deadbeef");
                assert_eq!(offset, 4096);
                assert_eq!(data_b64, "YWJjZA==");
                assert!(!eof);
            }
            other => panic!("expected FileRange, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_file_error() {
        let msg = CoordMessage::FileError {
            hash: "cafe".to_string(),
            reason: "not found".to_string(),
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (CoordMessage, usize) = decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            CoordMessage::FileError { hash, reason } => {
                assert_eq!(hash, "cafe");
                assert_eq!(reason, "not found");
            }
            other => panic!("expected FileError, got {other:?}"),
        }
    }

    #[test]
    fn roundtrip_request_file_range() {
        let msg = WorkerMessage::RequestFileRange {
            hash: "feed".to_string(),
            offset: 0,
            length: 2_097_152,
        };
        let encoded = encode_message(&msg).unwrap();
        let (decoded, consumed): (WorkerMessage, usize) =
            decode_message(&encoded).unwrap().unwrap();
        assert_eq!(consumed, encoded.len());
        match decoded {
            WorkerMessage::RequestFileRange {
                hash,
                offset,
                length,
            } => {
                assert_eq!(hash, "feed");
                assert_eq!(offset, 0);
                assert_eq!(length, 2_097_152);
            }
            other => panic!("expected RequestFileRange, got {other:?}"),
        }
    }

    #[test]
    fn decode_two_messages() {
        let msg1 = CoordMessage::Shutdown;
        let msg2 = CoordMessage::Welcome {
            worker_id: "w-2".to_string(),
        };
        let enc1 = encode_message(&msg1).unwrap();
        let enc2 = encode_message(&msg2).unwrap();

        let mut combined = enc1.clone();
        combined.extend_from_slice(&enc2);

        // Decode first message
        let (decoded1, consumed1): (CoordMessage, usize) =
            decode_message(&combined).unwrap().unwrap();
        assert_eq!(consumed1, enc1.len());
        assert!(matches!(decoded1, CoordMessage::Shutdown));

        // Decode second message from remaining bytes
        let (decoded2, consumed2): (CoordMessage, usize) =
            decode_message(&combined[consumed1..]).unwrap().unwrap();
        assert_eq!(consumed2, enc2.len());
        match decoded2 {
            CoordMessage::Welcome { worker_id } => assert_eq!(worker_id, "w-2"),
            other => panic!("expected Welcome, got {other:?}"),
        }
    }
}
