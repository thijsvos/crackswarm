use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use base64::Engine;
use crack_common::auth::{build_responder, encode_public_key, pubkey_fingerprint};
use crack_common::models::*;
use crack_common::protocol::{AssignChunkAttack, CoordMessage, WorkerMessage, MAX_MESSAGE_SIZE};

use crate::scheduler;
use crate::state::{AppEvent, AppState, WorkerConnection};
use crate::storage::{db, files};

/// Maximum Noise transport message payload (just under the 65535 limit to
/// leave room for the 16-byte AEAD tag that snow appends).
const NOISE_MAX_PLAINTEXT: usize = 65535 - 16;

/// Handle a single worker connection end-to-end: handshake, auth check,
/// message loop, and cleanup.
pub async fn handle_connection(state: Arc<AppState>, mut stream: TcpStream, peer_addr: SocketAddr) {
    if let Err(e) = run_connection(&state, &mut stream, peer_addr).await {
        debug!(%peer_addr, error = %e, "connection ended");
    }
}

// ── Handshake + session ─────────────────────────────────────────────────────

async fn run_connection(
    state: &Arc<AppState>,
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
) -> anyhow::Result<()> {
    // ── 1. Noise IK handshake (coordinator is responder) ────────────────

    let mut handshake =
        build_responder(&state.keypair).context("failed to build noise responder")?;

    // Read the initiator's first message (e, es, s, ss).
    let msg1 = read_noise_frame(stream)
        .await
        .context("failed to read handshake message 1")?;

    let mut buf = vec![0u8; 65535];
    let _payload_len = handshake
        .read_message(&msg1, &mut buf)
        .context("noise handshake: failed to process initiator message")?;

    // Extract the client's static public key.
    let remote_static = handshake
        .get_remote_static()
        .context("noise handshake: no remote static key")?
        .to_vec();
    let pubkey_b64 = encode_public_key(&remote_static);
    let pubkey_fp = pubkey_fingerprint(&pubkey_b64);

    // Check authorization.
    let authorized = db::is_worker_authorized(&state.db, &pubkey_b64)
        .await
        .context("failed to check worker authorization")?;

    // Always complete the Noise handshake so unauthorized workers can
    // attempt enrollment over the encrypted channel.

    // Send the responder's reply message (e, ee, se).
    let len = handshake
        .write_message(&[], &mut buf)
        .context("noise handshake: failed to write responder message")?;
    write_noise_frame(stream, &buf[..len])
        .await
        .context("failed to send handshake message 2")?;

    // Transition to transport mode.
    let mut transport = handshake
        .into_transport_mode()
        .context("failed to enter noise transport mode")?;

    // Log a fingerprint, not the full pubkey: tracing output lands on disk
    // under default umask; the audit_log table keeps the full key.
    info!(%peer_addr, pubkey_fp = %pubkey_fp, "noise handshake complete");

    // If not authorized, wait for an Enroll message (with timeout).
    if !authorized {
        info!(%peer_addr, pubkey_fp = %pubkey_fp, "worker not pre-authorized, waiting for enrollment");

        let enroll_result =
            tokio::time::timeout(std::time::Duration::from_secs(5), read_noise_frame(stream)).await;

        let ciphertext = match enroll_result {
            Ok(Ok(ct)) => ct,
            Ok(Err(e)) => {
                warn!(%peer_addr, error = %e, "enrollment read error");
                return Ok(());
            }
            Err(_) => {
                warn!(%peer_addr, pubkey_fp = %pubkey_fp, "enrollment timeout, disconnecting");
                state.emit_audit(
                    "auth_rejected",
                    &format!("Unauthorized connection from {peer_addr} with key {pubkey_b64} (enrollment timeout)"),
                    Some(&peer_addr.to_string()),
                    None,
                );
                return Ok(());
            }
        };

        // Decrypt the message
        let mut enroll_buf = vec![0u8; 65535];
        let plaintext_len = match transport.read_message(&ciphertext, &mut enroll_buf) {
            Ok(n) => n,
            Err(e) => {
                warn!(%peer_addr, error = %e, "enrollment decrypt failed");
                return Ok(());
            }
        };

        let msg: WorkerMessage = match serde_json::from_slice(&enroll_buf[..plaintext_len]) {
            Ok(m) => m,
            Err(e) => {
                warn!(%peer_addr, error = %e, "invalid enrollment message");
                return Ok(());
            }
        };

        match msg {
            WorkerMessage::Enroll { nonce, worker_name } => {
                info!(%peer_addr, %worker_name, "received enrollment request");

                // Validate the nonce
                let valid_name = db::validate_enrollment_nonce(&state.db, &nonce).await?;
                match valid_name {
                    Some(token_name) => {
                        // Mark nonce as used, authorize the worker
                        db::mark_nonce_used(&state.db, &nonce, &pubkey_b64).await?;
                        db::authorize_worker(&state.db, &pubkey_b64, &token_name).await?;

                        state.emit_audit(
                            "worker_enrolled",
                            &format!("Worker '{token_name}' enrolled via token from {peer_addr} with key {pubkey_b64}"),
                            Some(&peer_addr.to_string()),
                            None,
                        );

                        info!(%peer_addr, name = %token_name, "worker enrolled successfully via token");
                        // Fall through to the normal message loop
                    }
                    None => {
                        warn!(%peer_addr, "invalid or expired enrollment nonce");
                        state.emit_audit(
                            "enroll_rejected",
                            &format!(
                                "Invalid enrollment nonce from {peer_addr} with key {pubkey_b64}"
                            ),
                            Some(&peer_addr.to_string()),
                            None,
                        );
                        return Ok(());
                    }
                }
            }
            _ => {
                warn!(%peer_addr, pubkey_fp = %pubkey_fp, "unauthorized worker sent non-Enroll message, disconnecting");
                state.emit_audit(
                    "auth_rejected",
                    &format!("Unauthorized connection from {peer_addr} with key {pubkey_b64} (no enrollment)"),
                    Some(&peer_addr.to_string()),
                    None,
                );
                return Ok(());
            }
        }
    }

    // ── 2. Message loop ─────────────────────────────────────────────────

    let (outbound_tx, mut outbound_rx) = mpsc::channel::<CoordMessage>(64);

    // We track the worker_id once the Register message arrives.
    let mut worker_id: Option<String> = None;

    // Reusable buffers.
    let mut read_buf = vec![0u8; 65535];
    let mut write_buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // ── Inbound: read encrypted message from TCP ────────────
            frame = read_noise_frame(stream) => {
                let ciphertext = match frame {
                    Ok(ct) => ct,
                    Err(e) => {
                        debug!(%peer_addr, error = %e, "connection read error");
                        break;
                    }
                };

                let plaintext_len = match transport.read_message(&ciphertext, &mut read_buf) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(%peer_addr, error = %e, "noise decrypt failed");
                        break;
                    }
                };

                let msg: WorkerMessage = match serde_json::from_slice(&read_buf[..plaintext_len]) {
                    Ok(m) => m,
                    Err(e) => {
                        warn!(%peer_addr, error = %e, "invalid worker message");
                        continue;
                    }
                };

                debug!(%peer_addr, ?msg, "received worker message");

                if let Err(e) = handle_worker_message(
                    state,
                    &msg,
                    &outbound_tx,
                    &pubkey_b64,
                    peer_addr,
                    &mut worker_id,
                ).await {
                    error!(%peer_addr, error = %e, "error handling worker message");
                }
            }

            // ── Outbound: send encrypted message to TCP ─────────────
            Some(coord_msg) = outbound_rx.recv() => {
                let json = match serde_json::to_vec(&coord_msg) {
                    Ok(j) => j,
                    Err(e) => {
                        error!(%peer_addr, error = %e, "failed to serialize coord message");
                        continue;
                    }
                };

                if json.len() > NOISE_MAX_PLAINTEXT {
                    error!(
                        %peer_addr,
                        size = json.len(),
                        "outbound message exceeds noise limit, dropping"
                    );
                    continue;
                }

                let ct_len = match transport.write_message(&json, &mut write_buf) {
                    Ok(n) => n,
                    Err(e) => {
                        error!(%peer_addr, error = %e, "noise encrypt failed");
                        break;
                    }
                };

                if let Err(e) = write_noise_frame(stream, &write_buf[..ct_len]).await {
                    debug!(%peer_addr, error = %e, "connection write error");
                    break;
                }
            }
        }
    }

    // ── 3. Cleanup on disconnect ────────────────────────────────────────

    cleanup(state, worker_id.as_deref(), peer_addr).await;

    Ok(())
}

// ── Wire framing ────────────────────────────────────────────────────────────

/// Read a single length-prefixed frame from the TCP stream.
/// Wire format: [4-byte BE length][payload].
async fn read_noise_frame(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        bail!("frame too large: {len} bytes (max {MAX_MESSAGE_SIZE})");
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

/// Write a single length-prefixed frame to the TCP stream.
async fn write_noise_frame(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

// ── Message dispatch ────────────────────────────────────────────────────────

async fn handle_worker_message(
    state: &Arc<AppState>,
    msg: &WorkerMessage,
    outbound_tx: &mpsc::Sender<CoordMessage>,
    pubkey_b64: &str,
    peer_addr: SocketAddr,
    worker_id: &mut Option<String>,
) -> anyhow::Result<()> {
    match msg {
        WorkerMessage::Register {
            worker_name,
            hashcat_version,
            os,
            devices,
        } => {
            handle_register(
                state,
                outbound_tx,
                pubkey_b64,
                peer_addr,
                worker_name,
                hashcat_version,
                os,
                devices,
                worker_id,
            )
            .await
        }

        WorkerMessage::Heartbeat { cache_manifest } => {
            if let Some(wid) = worker_id.as_deref() {
                // Buffered: a background flusher persists every ~3s so the
                // hot path does an in-memory HashMap insert, not a write.
                state.note_heartbeat(wid).await;
                // Sync the coord's view of this worker's cache. Entries
                // present here but missing from the DB are upserted;
                // entries in the DB but missing from this manifest are
                // removed (the agent evicted them locally since last tick).
                if let Err(e) = db::sync_worker_cache_manifest(&state.db, wid, cache_manifest).await
                {
                    warn!(worker = %wid, error = %e, "failed to sync cache manifest");
                }

                // Drift-correction tick (issue #45). If the manifest carries
                // a sha that is no longer active on the coord, tell the agent
                // to evict it. Catches: missed `EvictFile` (mpsc backpressure
                // / transient drop), post-coord-restart staleness, and any
                // other cause of view divergence between coord and agent.
                // Same-cycle double-fires (this PR's gc_pass fallback +
                // heartbeat re-evict) are harmless: agent's `evict` is
                // idempotent and no-ops a second call.
                match state.get_active_shas().await {
                    Ok(active) => {
                        for entry in cache_manifest {
                            if !active.contains(&entry.sha256) {
                                let _ = outbound_tx
                                    .send(CoordMessage::EvictFile {
                                        hash: entry.sha256.clone(),
                                    })
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(worker = %wid, error = %e, "drift-correction lookup failed")
                    }
                }
            }
            Ok(())
        }

        WorkerMessage::ChunkStarted { chunk_id } => {
            db::update_chunk_status(&state.db, *chunk_id, ChunkStatus::Running).await?;
            Ok(())
        }

        WorkerMessage::ChunkProgress {
            chunk_id,
            progress_pct,
            speed,
            ..
        } => {
            db::update_chunk_progress(&state.db, *chunk_id, *progress_pct, *speed).await?;

            // Look up the task_id for this chunk so we can emit the event.
            if let Some(chunk) = db::get_chunk(&state.db, *chunk_id).await? {
                state.emit(AppEvent::ChunkProgress {
                    task_id: chunk.task_id,
                    chunk_id: *chunk_id,
                    progress: *progress_pct,
                    speed: *speed,
                });
            }
            Ok(())
        }

        WorkerMessage::HashCracked {
            chunk_id: _,
            task_id,
            hash,
            plaintext,
        } => {
            let wid = worker_id.as_deref().unwrap_or("unknown");
            info!(
                task_id = %task_id,
                hash = %hash,
                worker_id = %wid,
                "received HashCracked from worker"
            );
            let inserted =
                db::insert_cracked_hash(&state.db, *task_id, hash, plaintext, wid).await?;

            // Only increment the count and check completion if the hash was
            // actually new (not a duplicate).
            if !inserted {
                debug!(task_id = %task_id, hash = %hash, "duplicate hash ignored");
                return Ok(());
            }

            let new_count = db::increment_task_cracked_count(&state.db, *task_id, 1).await?;

            state.emit(AppEvent::HashCracked {
                task_id: *task_id,
                hash: hash.clone(),
            });

            // Check if all hashes for this task have been cracked.
            if let Some(task) = db::get_task(&state.db, *task_id).await? {
                if new_count >= task.total_hashes {
                    info!(task_id = %task_id, "all hashes cracked, completing task");
                    db::update_task_status(&state.db, *task_id, TaskStatus::Completed).await?;

                    state.emit(AppEvent::TaskCompleted { task_id: *task_id });

                    // Abort all running chunks on this task across all workers.
                    abort_task_chunks(state, *task_id).await?;

                    // Advance campaign if this task is campaign-owned
                    if task.campaign_id.is_some() {
                        if let Err(e) = crate::campaign::on_task_completed(state, *task_id).await {
                            error!(task_id = %task_id, error = %e, "campaign advance error");
                        }
                    }
                }
            }
            Ok(())
        }

        WorkerMessage::ChunkCompleted {
            chunk_id,
            exit_code,
            total_cracked: _,
        } => {
            let status = if *exit_code == 1 {
                ChunkStatus::Exhausted
            } else {
                ChunkStatus::Completed
            };

            // Mark progress as 100% without clobbering the last-reported speed —
            // for fast hashes, hashcat may finish before any status update is sent.
            db::finalize_chunk_progress(&state.db, *chunk_id).await?;
            db::update_chunk_status(&state.db, *chunk_id, status).await?;

            let chunk = db::get_chunk(&state.db, *chunk_id).await?;
            let task_id = chunk.as_ref().map(|c| c.task_id);

            // Try to assign more work to this worker.
            if let Some(wid) = worker_id.as_deref() {
                if let Some((task, new_chunk)) = scheduler::assign_next_chunk(state, wid).await? {
                    let msg = build_assign_chunk_msg(state, &task, &new_chunk).await?;
                    let _ = outbound_tx.send(msg).await;
                } else {
                    db::update_worker_status(&state.db, wid, WorkerStatus::Idle).await?;
                }
            }

            // Check if all chunks for this task are done.
            if let Some(tid) = task_id {
                check_task_completion(state, tid).await?;
            }
            Ok(())
        }

        WorkerMessage::ChunkFailed {
            chunk_id,
            error: err_msg,
            exit_code,
        } => {
            db::update_chunk_status(&state.db, *chunk_id, ChunkStatus::Failed).await?;

            let wid = worker_id.as_deref().unwrap_or("unknown");
            error!(
                %chunk_id,
                worker_id = %wid,
                exit_code = ?exit_code,
                error = %err_msg,
                "chunk failed"
            );

            state.emit_audit(
                "chunk_failed",
                &format!("Chunk {chunk_id} failed: {err_msg}"),
                None,
                Some(wid),
            );

            // Try to assign next work to keep the worker busy.
            if let Some(wid) = worker_id.as_deref() {
                try_assign_work(state, wid, outbound_tx).await?;
            }
            Ok(())
        }

        WorkerMessage::BenchmarkResult { hash_mode, speed } => {
            if let Some(wid) = worker_id.as_deref() {
                state.record_benchmark(wid, *hash_mode, *speed).await?;

                // If the worker was idle, try to give it work now.
                try_assign_work(state, wid, outbound_tx).await?;
            }
            Ok(())
        }

        WorkerMessage::Draining => {
            if let Some(wid) = worker_id.as_deref() {
                db::update_worker_status(&state.db, wid, WorkerStatus::Draining).await?;
                info!(worker_id = %wid, "worker is draining");
            }
            Ok(())
        }

        WorkerMessage::Leaving => {
            if let Some(wid) = worker_id.as_deref() {
                info!(worker_id = %wid, "worker leaving gracefully");
                db::update_worker_status(&state.db, wid, WorkerStatus::Disconnected).await?;
                state.worker_connections.write().await.remove(wid);
                state.emit(AppEvent::WorkerDisconnected {
                    worker_id: wid.to_string(),
                });
            }
            Ok(())
        }

        WorkerMessage::Enroll { .. } => {
            // Enrollment is handled before the message loop. If we get here,
            // the worker is already authorized, so we just ignore it.
            debug!(%peer_addr, "ignoring Enroll message in message loop (already authorized)");
            Ok(())
        }

        WorkerMessage::RequestFileRange {
            hash,
            offset,
            length,
        } => {
            handle_request_file_range(state, outbound_tx, hash, *offset, *length).await?;
            Ok(())
        }

        WorkerMessage::PullFailed {
            chunk_id,
            hash,
            reason,
        } => {
            // The agent couldn't fetch a file required by this chunk
            // (cache budget, disk full, etc.). Treat it like a chunk
            // failure so the abandoned-chunk reassigner picks it up
            // for a different worker.
            db::update_chunk_status(&state.db, *chunk_id, ChunkStatus::Failed).await?;

            let wid = worker_id.as_deref().unwrap_or("unknown");
            warn!(
                %chunk_id,
                worker_id = %wid,
                %hash,
                %reason,
                "pull failed: chunk will be reassigned"
            );

            state.emit_audit(
                "pull_failed",
                &format!("Worker {wid} couldn't fetch {hash} for chunk {chunk_id}: {reason}"),
                None,
                Some(wid),
            );

            if let Some(wid) = worker_id.as_deref() {
                try_assign_work(state, wid, outbound_tx).await?;
            }
            Ok(())
        }

        WorkerMessage::CacheAck { kept, evicted } => {
            // The agent has already evicted what we asked. Drop the
            // evicted shas from our coord-side view immediately so the
            // GC loop doesn't keep re-targeting this worker. The next
            // heartbeat will deliver the full ground-truth manifest.
            if let Some(wid) = worker_id.as_deref() {
                for sha in evicted {
                    if let Err(e) = db::remove_worker_cache_entry(&state.db, wid, sha).await {
                        warn!(worker = %wid, %sha, error = %e, "remove_worker_cache_entry failed");
                    }
                }
                debug!(
                    worker = %wid,
                    kept = kept.len(),
                    evicted_count = evicted.len(),
                    "received CacheAck"
                );
            }
            Ok(())
        }
    }
}

/// Cap any single `RequestFileRange` response at this many raw bytes. Larger
/// caps bloat the Noise frame (MAX_MESSAGE_SIZE = 16 MiB, base64 adds 33%),
/// so we keep a safe margin. The worker decides how fast to pull by issuing
/// the next request after each response arrives.
const FILE_RANGE_MAX_BYTES: u32 = 2 * 1024 * 1024;

async fn handle_request_file_range(
    state: &Arc<AppState>,
    outbound_tx: &mpsc::Sender<CoordMessage>,
    hash: &str,
    offset: u64,
    length: u32,
) -> anyhow::Result<()> {
    let record = match db::find_file_by_sha256(&state.db, hash).await? {
        Some(r) => r,
        None => {
            outbound_tx
                .send(CoordMessage::FileError {
                    hash: hash.to_string(),
                    reason: "file not found".to_string(),
                })
                .await
                .ok();
            return Ok(());
        }
    };

    let path = match files::resolve_file_path(&state.files_dir(), &record.id) {
        Ok(p) => p,
        Err(e) => {
            outbound_tx
                .send(CoordMessage::FileError {
                    hash: hash.to_string(),
                    reason: format!("resolve path: {e}"),
                })
                .await
                .ok();
            return Ok(());
        }
    };

    let total_size = record.size_bytes.max(0) as u64;
    let capped = length.min(FILE_RANGE_MAX_BYTES) as usize;
    // Don't read past EOF.
    let remaining = total_size.saturating_sub(offset) as usize;
    let to_read = capped.min(remaining);

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            outbound_tx
                .send(CoordMessage::FileError {
                    hash: hash.to_string(),
                    reason: format!("open: {e}"),
                })
                .await
                .ok();
            return Ok(());
        }
    };

    if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
        outbound_tx
            .send(CoordMessage::FileError {
                hash: hash.to_string(),
                reason: format!("seek: {e}"),
            })
            .await
            .ok();
        return Ok(());
    }

    let mut buf = vec![0u8; to_read];
    let n = match file.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            outbound_tx
                .send(CoordMessage::FileError {
                    hash: hash.to_string(),
                    reason: format!("read: {e}"),
                })
                .await
                .ok();
            return Ok(());
        }
    };
    buf.truncate(n);

    let eof = offset.saturating_add(n as u64) >= total_size;
    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&buf);

    debug!(
        hash = %hash,
        offset,
        length = n,
        eof,
        "serving FileRange"
    );

    outbound_tx
        .send(CoordMessage::FileRange {
            hash: hash.to_string(),
            offset,
            data_b64,
            eof,
        })
        .await
        .context("send FileRange")?;
    Ok(())
}

// ── Register ────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_register(
    state: &Arc<AppState>,
    outbound_tx: &mpsc::Sender<CoordMessage>,
    pubkey_b64: &str,
    peer_addr: SocketAddr,
    worker_name: &str,
    hashcat_version: &str,
    os: &str,
    devices: &[DeviceInfo],
    worker_id: &mut Option<String>,
) -> anyhow::Result<()> {
    // Look up or create the worker record by public key.
    let worker = db::get_or_create_worker(&state.db, pubkey_b64, worker_name).await?;
    let wid = worker.id.clone();

    // Update the worker's metadata.
    db::update_worker_info(&state.db, &wid, hashcat_version, os, devices).await?;
    db::update_worker_status(&state.db, &wid, WorkerStatus::Idle).await?;

    *worker_id = Some(wid.clone());

    // Store the connection handle so other parts of the system can send
    // messages to this worker (e.g., scheduler, monitor, API-initiated aborts).
    {
        let conn = WorkerConnection {
            worker_id: wid.clone(),
            name: worker_name.to_string(),
            tx: outbound_tx.clone(),
            peer_addr: peer_addr.to_string(),
        };
        state
            .worker_connections
            .write()
            .await
            .insert(wid.clone(), conn);
    }

    // Send the Welcome response.
    let _ = outbound_tx
        .send(CoordMessage::Welcome {
            worker_id: wid.clone(),
        })
        .await;

    state.emit(AppEvent::WorkerConnected {
        worker_id: wid.clone(),
        name: worker_name.to_string(),
    });

    info!(
        worker_id = %wid,
        worker_name = %worker_name,
        %peer_addr,
        "worker registered"
    );

    state.emit_audit(
        "worker_registered",
        &format!("Worker {worker_name} ({wid}) connected from {peer_addr}"),
        Some(&peer_addr.to_string()),
        Some(&wid),
    );

    // Cache reconciliation: tell the (re)connecting worker which sha256s
    // we still consider live. Anything in its cache that's not on this
    // list gets evicted (deferred if currently in use). Catches missed
    // EvictFile messages from prior sessions and any drift while the
    // agent was disconnected.
    match state.get_active_shas().await {
        Ok(active) => {
            let expected: Vec<String> = active.iter().cloned().collect();
            let count = expected.len();
            if let Err(e) = outbound_tx
                .send(CoordMessage::CacheReconcile { expected })
                .await
            {
                debug!(error = %e, "failed to send CacheReconcile");
            } else {
                debug!(worker = %wid, expected_count = count, "sent CacheReconcile");
            }
        }
        Err(e) => warn!(error = %e, "failed to list active file shas for reconcile"),
    }

    // Try to immediately assign work to the newly registered worker.
    try_assign_work(state, &wid, outbound_tx).await?;

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a CoordMessage::AssignChunk with the hash file data embedded.
///
/// All dictionary-based attacks emit `DictionaryByHash` — the agent looks
/// the referenced files up in its content-addressed cache and pulls on
/// miss via `RequestFileRange`/`FileRange`. The pre-Slice-8 push paths
/// (`TransferFileChunk` + `Dictionary` / `DictionaryWithRules` variants)
/// were retired in PR5b after a one-shot sha256 backfill in `init_db`.
///
/// # Errors
/// Returns an error if a referenced file row is missing or has no
/// `sha256`. Both should be impossible after `backfill_empty_shas` has
/// run; surfacing it as an error makes operator-noticeable rather than
/// silently dispatching with broken metadata.
pub(crate) async fn build_assign_chunk_msg(
    state: &AppState,
    task: &Task,
    chunk: &Chunk,
) -> anyhow::Result<CoordMessage> {
    let attack = match &task.attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => AssignChunkAttack::BruteForce {
            mask: mask.clone(),
            custom_charsets: custom_charsets.clone(),
        },
        AttackConfig::Dictionary { wordlist_file_id } => {
            let (sha, size) = file_ref(&state.db, wordlist_file_id).await?;
            AssignChunkAttack::DictionaryByHash {
                wordlist_sha256: sha,
                wordlist_size: size,
                rules_sha256: None,
                rules_size: None,
            }
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            let (w_sha, w_size) = file_ref(&state.db, wordlist_file_id).await?;
            let (r_sha, r_size) = file_ref(&state.db, rules_file_id).await?;
            AssignChunkAttack::DictionaryByHash {
                wordlist_sha256: w_sha,
                wordlist_size: w_size,
                rules_sha256: Some(r_sha),
                rules_size: Some(r_size),
            }
        }
    };

    // Hash file is content-addressed exactly like wordlists/rules — the
    // agent pulls it via `RequestFileRange`/`FileRange` on cache miss.
    let (hash_file_sha256, hash_file_size) = file_ref(&state.db, &task.hash_file_id).await?;

    Ok(CoordMessage::AssignChunk {
        chunk_id: chunk.id,
        task_id: chunk.task_id,
        hash_mode: task.hash_mode,
        hash_file_sha256,
        hash_file_size,
        skip: chunk.skip,
        limit: chunk.limit,
        attack,
        extra_args: task.extra_args.clone(),
    })
}

/// Look up a file's `(sha256, size_bytes)` by UUID. Errors if the record
/// is missing or has no sha — both indicate a broken DB row that the
/// startup backfill should have caught.
async fn file_ref(pool: &sqlx::SqlitePool, file_id: &str) -> anyhow::Result<(String, u64)> {
    let record = db::get_file_record(pool, file_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("file {file_id} not found"))?;
    if record.sha256.is_empty() {
        anyhow::bail!("file {file_id} has no sha256 (backfill may have skipped it)");
    }
    if record.size_bytes < 0 {
        anyhow::bail!("file {file_id} has invalid size_bytes={}", record.size_bytes);
    }
    Ok((record.sha256, record.size_bytes as u64))
}

/// Try to assign the next pending chunk to a worker and send it via the
/// outbound channel.
async fn try_assign_work(
    state: &Arc<AppState>,
    wid: &str,
    outbound_tx: &mpsc::Sender<CoordMessage>,
) -> anyhow::Result<()> {
    if let Some((task, chunk)) = scheduler::assign_next_chunk(state, wid).await? {
        let msg = build_assign_chunk_msg(state, &task, &chunk).await?;
        let _ = outbound_tx.send(msg).await;
    }
    Ok(())
}

/// Send AbortChunk to every connected worker that has running chunks on the
/// given task.
async fn abort_task_chunks(state: &Arc<AppState>, task_id: Uuid) -> anyhow::Result<()> {
    let chunks = db::get_chunks_for_task(&state.db, task_id).await?;
    let conns = state.worker_connections.read().await;

    for chunk in chunks {
        if chunk.status == ChunkStatus::Running || chunk.status == ChunkStatus::Dispatched {
            if let Some(ref assigned) = chunk.assigned_worker {
                if let Some(conn) = conns.get(assigned) {
                    let _ = conn
                        .tx
                        .send(CoordMessage::AbortChunk { chunk_id: chunk.id })
                        .await;
                }
            }
        }
    }
    Ok(())
}

/// Check whether all chunks for a task are terminal (Completed, Exhausted, or
/// Failed). If so, mark the task as Completed and emit an event.
async fn check_task_completion(state: &Arc<AppState>, task_id: Uuid) -> anyhow::Result<()> {
    let chunks = db::get_chunks_for_task(&state.db, task_id).await?;
    let all_done = !chunks.is_empty()
        && chunks.iter().all(|c| {
            matches!(
                c.status,
                ChunkStatus::Completed
                    | ChunkStatus::Exhausted
                    | ChunkStatus::Failed
                    | ChunkStatus::Abandoned
            )
        });

    if all_done {
        db::update_task_status(&state.db, task_id, TaskStatus::Completed).await?;
        state.emit(AppEvent::TaskCompleted { task_id });
        state.emit(AppEvent::TaskUpdated { task_id });

        // Advance campaign if this task is campaign-owned
        if let Some(task) = db::get_task(&state.db, task_id).await? {
            if task.campaign_id.is_some() {
                if let Err(e) = crate::campaign::on_task_completed(state, task_id).await {
                    error!(task_id = %task_id, error = %e, "campaign advance error after chunk completion");
                }
            }
        }
    }
    Ok(())
}

/// Remove the worker from the in-memory connection map, mark it disconnected
/// in the database, and abandon any of its running chunks.
async fn cleanup(state: &Arc<AppState>, worker_id: Option<&str>, peer_addr: SocketAddr) {
    let Some(wid) = worker_id else {
        debug!(%peer_addr, "connection closed before registration");
        return;
    };

    info!(worker_id = %wid, %peer_addr, "worker disconnected, cleaning up");

    state.worker_connections.write().await.remove(wid);

    if let Err(e) = db::update_worker_status(&state.db, wid, WorkerStatus::Disconnected).await {
        error!(worker_id = %wid, error = %e, "failed to update worker status on disconnect");
    }

    match db::abandon_worker_chunks(&state.db, wid).await {
        Ok(count) if count > 0 => {
            info!(worker_id = %wid, count, "abandoned running chunks for disconnected worker");
        }
        Err(e) => {
            error!(worker_id = %wid, error = %e, "failed to abandon worker chunks");
        }
        _ => {}
    }

    state.emit(AppEvent::WorkerDisconnected {
        worker_id: wid.to_string(),
    });
}
