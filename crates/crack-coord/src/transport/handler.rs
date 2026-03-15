use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use base64::Engine;
use crack_common::auth::{build_responder, encode_public_key};
use crack_common::models::*;
use crack_common::protocol::{CoordMessage, WorkerMessage, MAX_MESSAGE_SIZE};

use crate::scheduler;
use crate::state::{AppEvent, AppState, WorkerConnection};
use crate::storage::db;

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

    let mut handshake = build_responder(&state.keypair)
        .context("failed to build noise responder")?;

    // Read the initiator's first message (e, es, s, ss).
    let msg1 = read_noise_frame(stream).await
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
    write_noise_frame(stream, &buf[..len]).await
        .context("failed to send handshake message 2")?;

    // Transition to transport mode.
    let mut transport = handshake
        .into_transport_mode()
        .context("failed to enter noise transport mode")?;

    info!(%peer_addr, pubkey = %pubkey_b64, "noise handshake complete");

    // If not authorized, wait for an Enroll message (with timeout).
    if !authorized {
        info!(%peer_addr, pubkey = %pubkey_b64, "worker not pre-authorized, waiting for enrollment");

        let enroll_result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_noise_frame(stream),
        )
        .await;

        let ciphertext = match enroll_result {
            Ok(Ok(ct)) => ct,
            Ok(Err(e)) => {
                warn!(%peer_addr, error = %e, "enrollment read error");
                return Ok(());
            }
            Err(_) => {
                warn!(%peer_addr, pubkey = %pubkey_b64, "enrollment timeout, disconnecting");
                db::insert_audit(
                    &state.db,
                    "auth_rejected",
                    &format!("Unauthorized connection from {peer_addr} with key {pubkey_b64} (enrollment timeout)"),
                    Some(&peer_addr.to_string()),
                    None,
                )
                .await
                .ok();
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

                        db::insert_audit(
                            &state.db,
                            "worker_enrolled",
                            &format!("Worker '{token_name}' enrolled via token from {peer_addr} with key {pubkey_b64}"),
                            Some(&peer_addr.to_string()),
                            None,
                        )
                        .await
                        .ok();

                        info!(%peer_addr, name = %token_name, "worker enrolled successfully via token");
                        // Fall through to the normal message loop
                    }
                    None => {
                        warn!(%peer_addr, "invalid or expired enrollment nonce");
                        db::insert_audit(
                            &state.db,
                            "enroll_rejected",
                            &format!("Invalid enrollment nonce from {peer_addr} with key {pubkey_b64}"),
                            Some(&peer_addr.to_string()),
                            None,
                        )
                        .await
                        .ok();
                        return Ok(());
                    }
                }
            }
            _ => {
                warn!(%peer_addr, pubkey = %pubkey_b64, "unauthorized worker sent non-Enroll message, disconnecting");
                db::insert_audit(
                    &state.db,
                    "auth_rejected",
                    &format!("Unauthorized connection from {peer_addr} with key {pubkey_b64} (no enrollment)"),
                    Some(&peer_addr.to_string()),
                    None,
                )
                .await
                .ok();
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

        WorkerMessage::Heartbeat => {
            if let Some(wid) = worker_id.as_deref() {
                db::update_worker_last_seen(&state.db, wid).await?;
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
            db::insert_cracked_hash(&state.db, *task_id, hash, plaintext, wid).await?;
            db::increment_task_cracked_count(&state.db, *task_id, 1).await?;

            state.emit(AppEvent::HashCracked {
                task_id: *task_id,
                hash: hash.clone(),
            });

            // Check if all hashes for this task have been cracked.
            if let Some(task) = db::get_task(&state.db, *task_id).await? {
                if task.cracked_count + 1 >= task.total_hashes {
                    info!(task_id = %task_id, "all hashes cracked, completing task");
                    db::update_task_status(&state.db, *task_id, TaskStatus::Completed).await?;

                    state.emit(AppEvent::TaskCompleted {
                        task_id: *task_id,
                    });

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
                if let Some((task, new_chunk)) =
                    scheduler::assign_next_chunk(state, wid).await?
                {
                    let msg = build_assign_chunk_msg(state, &task, &new_chunk)?;
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

            db::insert_audit(
                &state.db,
                "chunk_failed",
                &format!("Chunk {chunk_id} failed: {err_msg}"),
                None,
                Some(wid),
            )
            .await?;

            // Try to assign next work to keep the worker busy.
            if let Some(wid) = worker_id.as_deref() {
                try_assign_work(state, wid, outbound_tx).await?;
            }
            Ok(())
        }

        WorkerMessage::BenchmarkResult { hash_mode, speed } => {
            if let Some(wid) = worker_id.as_deref() {
                db::upsert_benchmark(&state.db, wid, *hash_mode, *speed).await?;

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
    }
}

// ── Register ────────────────────────────────────────────────────────────────

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
        state.worker_connections.write().await.insert(wid.clone(), conn);
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

    db::insert_audit(
        &state.db,
        "worker_registered",
        &format!("Worker {worker_name} ({wid}) connected from {peer_addr}"),
        Some(&peer_addr.to_string()),
        Some(&wid),
    )
    .await?;

    // Try to immediately assign work to the newly registered worker.
    try_assign_work(state, &wid, outbound_tx).await?;

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a CoordMessage::AssignChunk with the hash file data embedded.
fn build_assign_chunk_msg(
    state: &AppState,
    task: &Task,
    chunk: &Chunk,
) -> anyhow::Result<CoordMessage> {
    let (mask, custom_charsets) = match &task.attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => (mask.clone(), custom_charsets.clone()),
    };

    // Read the hash file and base64-encode it for transfer over the Noise channel.
    let file_data = crate::storage::files::read_file(&state.files_dir(), &task.hash_file_id)
        .context("reading hash file for chunk assignment")?;
    let hash_file_b64 = base64::engine::general_purpose::STANDARD.encode(&file_data);

    Ok(CoordMessage::AssignChunk {
        chunk_id: chunk.id,
        task_id: chunk.task_id,
        hash_mode: task.hash_mode,
        hash_file_b64,
        hash_file_id: task.hash_file_id.clone(),
        skip: chunk.skip,
        limit: chunk.limit,
        mask,
        custom_charsets,
        extra_args: task.extra_args.clone(),
    })
}

/// Try to assign the next pending chunk to a worker and send it via the
/// outbound channel.
async fn try_assign_work(
    state: &Arc<AppState>,
    wid: &str,
    outbound_tx: &mpsc::Sender<CoordMessage>,
) -> anyhow::Result<()> {
    if let Some((task, chunk)) = scheduler::assign_next_chunk(state, wid).await? {
        let msg = build_assign_chunk_msg(state, &task, &chunk)?;
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
                        .send(CoordMessage::AbortChunk {
                            chunk_id: chunk.id,
                        })
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
                ChunkStatus::Completed | ChunkStatus::Exhausted | ChunkStatus::Failed | ChunkStatus::Abandoned
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
