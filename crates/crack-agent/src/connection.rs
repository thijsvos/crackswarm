use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context};
use base64::Engine;
use crack_common::auth::{self, Keypair};
use crack_common::protocol::{CoordMessage, WorkerMessage, MAX_MESSAGE_SIZE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::RunConfig;
use crate::runner::{HashcatRunConfig, HashcatRunner, RunnerEvent};
use crate::status;

/// Maximum Noise transport message (plaintext side). 64 KiB is well within
/// the 65535-byte Noise limit.
const NOISE_MAX_PLAINTEXT: usize = 65000;

/// Main entry point: connect to the coordinator and run the message loop.
///
/// On disconnect the function returns an `Err` so the caller can apply
/// exponential backoff and reconnect.
pub async fn run_connection(config: &RunConfig) -> anyhow::Result<()> {
    let keypair = Keypair::load_from_dir(&config.data_dir)
        .map_err(|e| anyhow!("failed to load agent keypair: {e}"))?;
    let coord_pubkey = auth::load_remote_key(&config.data_dir, "coordinator.pub")
        .map_err(|e| anyhow!("failed to load coordinator public key: {e}"))?;

    let mut backoff = ExponentialBackoff::new();

    loop {
        info!(server = %config.server, "connecting to coordinator");

        match connect_and_run(config, &keypair, &coord_pubkey).await {
            Ok(()) => {
                // Clean shutdown requested by coordinator
                info!("coordinator requested shutdown, exiting");
                return Ok(());
            }
            Err(e) => {
                error!(error = %e, "connection lost");
                let delay = backoff.next_delay();
                info!(delay_secs = delay.as_secs(), "reconnecting after backoff");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Perform handshake, register, and run the message loop for a single
/// connection lifetime.
async fn connect_and_run(
    config: &RunConfig,
    keypair: &Keypair,
    coord_pubkey: &[u8],
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(&config.server)
        .await
        .context("TCP connect failed")?;

    info!("TCP connected, starting Noise IK handshake");

    // ── Noise IK handshake (agent = initiator) ──

    let mut handshake = auth::build_initiator(keypair, coord_pubkey)
        .map_err(|e| anyhow!("failed to build Noise initiator: {e}"))?;

    // Step 1: initiator writes first message (e, es, s, ss)
    let mut buf = vec![0u8; 65535];
    let len = handshake
        .write_message(&[], &mut buf)
        .map_err(|e| anyhow!("handshake write_message failed: {e}"))?;
    write_framed(&mut stream, &buf[..len]).await?;
    debug!(bytes = len, "sent handshake message 1");

    // Step 2: read responder's reply (e, ee, se)
    let msg2 = read_framed(&mut stream).await?;
    handshake
        .read_message(&msg2, &mut buf)
        .map_err(|e| anyhow!("handshake read_message failed: {e}"))?;
    debug!("received handshake message 2");

    // Transition to transport mode
    let mut transport = handshake
        .into_transport_mode()
        .map_err(|e| anyhow!("failed to enter transport mode: {e}"))?;
    info!("Noise handshake complete, channel encrypted");

    // ── Registration ──

    let hashcat_version = status::detect_hashcat(&config.hashcat_path).await?;
    let devices = status::get_devices(&config.hashcat_path).await?;
    let os_info = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);

    let register = WorkerMessage::Register {
        worker_name: config.worker_name(),
        hashcat_version,
        os: os_info,
        devices,
    };
    send_message(&mut stream, &mut transport, &register).await?;
    info!("sent Register, waiting for Welcome");

    // Wait for Welcome
    let welcome = recv_message(&mut stream, &mut transport).await?;
    let _worker_id = match welcome {
        CoordMessage::Welcome { ref worker_id } => {
            info!(worker_id = %worker_id, "registered with coordinator");
            worker_id.clone()
        }
        other => {
            return Err(anyhow!(
                "expected Welcome, got {:?}",
                std::mem::discriminant(&other)
            ));
        }
    };

    // ── Message loop ──
    //
    // Because `snow::TransportState` is `!Send`, we keep everything on a
    // single task and use `tokio::select!` to multiplex:
    //   1. Heartbeat timer
    //   2. Incoming CoordMessages from TCP (via `readable()` to avoid borrow conflicts)
    //   3. RunnerEvents from hashcat subprocess(es)

    let (runner_tx, mut runner_rx) = mpsc::channel::<(Uuid, Uuid, RunnerEvent)>(256);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));

    // Track running chunks: chunk_id -> kill signal sender
    let mut active_chunks: HashMap<Uuid, oneshot::Sender<()>> = HashMap::new();
    // Track chunk -> task mapping (reserved for future use, e.g. reconnection)
    let mut _chunk_task: HashMap<Uuid, Uuid> = HashMap::new();

    loop {
        // We use `stream.readable()` in the select to detect when there is
        // data to read, without actually borrowing `stream` mutably.  After
        // the select completes, we perform the read (and writes for other
        // arms) sequentially -- which satisfies the borrow checker.
        enum Action {
            Heartbeat,
            RunnerEvent(Uuid, Uuid, RunnerEvent),
            TcpReadable,
        }

        let action = tokio::select! {
            _ = heartbeat.tick() => Action::Heartbeat,
            Some((cid, tid, ev)) = runner_rx.recv() => Action::RunnerEvent(cid, tid, ev),
            result = stream.readable() => {
                result.context("TCP stream error")?;
                Action::TcpReadable
            }
        };

        match action {
            Action::Heartbeat => {
                send_message(&mut stream, &mut transport, &WorkerMessage::Heartbeat).await?;
                debug!("sent heartbeat");
            }

            Action::RunnerEvent(chunk_id, task_id, event) => {
                handle_runner_event(
                    &mut stream,
                    &mut transport,
                    &mut active_chunks,
                    chunk_id,
                    task_id,
                    event,
                )
                .await?;
            }

            Action::TcpReadable => {
                // Now we can borrow stream mutably for the read
                let cipher = read_framed(&mut stream).await?;

                // Decrypt
                let mut plain = vec![0u8; 65535];
                let n = transport
                    .read_message(&cipher, &mut plain)
                    .map_err(|e| anyhow!("decrypt failed: {e}"))?;
                let msg: CoordMessage = serde_json::from_slice(&plain[..n])
                    .context("failed to deserialize CoordMessage")?;

                match msg {
                    CoordMessage::Welcome { worker_id: wid } => {
                        info!(worker_id = %wid, "received duplicate Welcome");
                    }

                    CoordMessage::AssignChunk {
                        chunk_id,
                        task_id,
                        hash_mode,
                        hash_file_b64,
                        hash_file_id,
                        skip,
                        limit,
                        mask,
                        custom_charsets,
                        extra_args,
                    } => {
                        info!(
                            chunk_id = %chunk_id,
                            task_id = %task_id,
                            hash_mode,
                            mask = %mask,
                            skip, limit,
                            "received chunk assignment"
                        );

                        // Decode hash file from the message and cache locally
                        let hash_file_path =
                            save_hash_file(config, &hash_file_id, &hash_file_b64).await?;

                        let outfile_path =
                            config.cache_dir().join(format!("out_{chunk_id}.txt"));

                        let run_config = HashcatRunConfig {
                            hashcat_path: config.hashcat_path.clone(),
                            hash_file_path,
                            hash_mode,
                            mask,
                            skip,
                            limit,
                            custom_charsets,
                            extra_args,
                            outfile_path,
                        };

                        match HashcatRunner::start(&run_config) {
                            Ok(runner) => {
                                // Notify coordinator that we started
                                send_message(
                                    &mut stream,
                                    &mut transport,
                                    &WorkerMessage::ChunkStarted { chunk_id },
                                )
                                .await?;

                                _chunk_task.insert(chunk_id, task_id);

                                // Create a kill channel so AbortChunk can stop this runner
                                let (kill_tx, kill_rx) = oneshot::channel::<()>();
                                active_chunks.insert(chunk_id, kill_tx);

                                // Spawn a dedicated task that owns the runner.
                                // It monitors hashcat and listens for kill signals.
                                let tx = runner_tx.clone();
                                let cid = chunk_id;
                                let tid = task_id;
                                tokio::spawn(async move {
                                    let mut runner = runner;
                                    let event_tx = wrap_sender(tx, cid, tid);
                                    tokio::select! {
                                        result = runner.monitor(event_tx.clone()) => {
                                            if let Err(e) = result {
                                                let _ = event_tx.send(RunnerEvent::Failed {
                                                    error: e.to_string(),
                                                }).await;
                                            }
                                        }
                                        _ = kill_rx => {
                                            warn!(chunk_id = %cid, "received kill signal");
                                            let _ = runner.kill().await;
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                error!(error = %e, chunk_id = %chunk_id, "failed to start hashcat");
                                send_message(
                                    &mut stream,
                                    &mut transport,
                                    &WorkerMessage::ChunkFailed {
                                        chunk_id,
                                        error: e.to_string(),
                                        exit_code: None,
                                    },
                                )
                                .await?;
                            }
                        }
                    }

                    CoordMessage::AbortChunk { chunk_id } => {
                        info!(chunk_id = %chunk_id, "aborting chunk");
                        if let Some(kill_tx) = active_chunks.remove(&chunk_id) {
                            let _ = kill_tx.send(());
                        }
                        _chunk_task.remove(&chunk_id);
                    }

                    CoordMessage::RequestBenchmark { hash_mode } => {
                        info!(hash_mode, "benchmark requested");
                        let speed = run_benchmark(&config.hashcat_path, hash_mode).await;
                        send_message(
                            &mut stream,
                            &mut transport,
                            &WorkerMessage::BenchmarkResult { hash_mode, speed },
                        )
                        .await?;
                    }

                    CoordMessage::Shutdown => {
                        info!("coordinator requested shutdown");
                        // Kill all running hashcat processes by sending kill signals
                        for (cid, kill_tx) in active_chunks.drain() {
                            info!(chunk_id = %cid, "killing hashcat for shutdown");
                            let _ = kill_tx.send(());
                        }
                        send_message(
                            &mut stream,
                            &mut transport,
                            &WorkerMessage::Leaving,
                        )
                        .await?;
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Handle a runner event by forwarding the appropriate WorkerMessage.
async fn handle_runner_event(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    active_chunks: &mut HashMap<Uuid, oneshot::Sender<()>>,
    chunk_id: Uuid,
    task_id: Uuid,
    event: RunnerEvent,
) -> anyhow::Result<()> {
    match event {
        RunnerEvent::StatusUpdate {
            progress_pct,
            speed,
            est_remaining,
        } => {
            send_message(
                stream,
                transport,
                &WorkerMessage::ChunkProgress {
                    chunk_id,
                    progress_pct,
                    speed,
                    estimated_remaining_secs: est_remaining,
                },
            )
            .await?;
        }
        RunnerEvent::HashCracked { hash, plaintext } => {
            send_message(
                stream,
                transport,
                &WorkerMessage::HashCracked {
                    chunk_id,
                    task_id,
                    hash,
                    plaintext,
                },
            )
            .await?;
        }
        RunnerEvent::Completed { exit_code } => {
            info!(chunk_id = %chunk_id, exit_code, "chunk completed");
            active_chunks.remove(&chunk_id);
            send_message(
                stream,
                transport,
                &WorkerMessage::ChunkCompleted {
                    chunk_id,
                    exit_code,
                    total_cracked: 0, // the coordinator counts from HashCracked messages
                },
            )
            .await?;
        }
        RunnerEvent::Failed { error } => {
            error!(chunk_id = %chunk_id, error = %error, "chunk failed");
            active_chunks.remove(&chunk_id);
            send_message(
                stream,
                transport,
                &WorkerMessage::ChunkFailed {
                    chunk_id,
                    error,
                    exit_code: None,
                },
            )
            .await?;
        }
    }
    Ok(())
}

// ── Wire format helpers ──
//
// All Noise transport messages are framed as:
//   [4 bytes big-endian ciphertext length][ciphertext]

/// Write a length-framed blob to TCP.
async fn write_framed(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a length-framed blob from TCP. Returns the payload.
async fn read_framed(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(anyhow!("message too large: {len} bytes"));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Encrypt a WorkerMessage and send it over the Noise transport.
async fn send_message(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
    msg: &WorkerMessage,
) -> anyhow::Result<()> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > NOISE_MAX_PLAINTEXT {
        return Err(anyhow!(
            "message too large for single Noise frame ({} bytes)",
            json.len()
        ));
    }
    let mut cipher = vec![0u8; json.len() + 128]; // room for AEAD tag
    let n = transport
        .write_message(&json, &mut cipher)
        .map_err(|e| anyhow!("encrypt failed: {e}"))?;
    write_framed(stream, &cipher[..n]).await?;
    Ok(())
}

/// Decrypt and deserialize a CoordMessage from the Noise transport.
async fn recv_message(
    stream: &mut TcpStream,
    transport: &mut snow::TransportState,
) -> anyhow::Result<CoordMessage> {
    let cipher = read_framed(stream).await?;
    let mut plain = vec![0u8; 65535];
    let n = transport
        .read_message(&cipher, &mut plain)
        .map_err(|e| anyhow!("decrypt failed: {e}"))?;
    let msg: CoordMessage =
        serde_json::from_slice(&plain[..n]).context("failed to deserialize CoordMessage")?;
    Ok(msg)
}

// ── Hash file caching ──

/// Save a base64-encoded hash file received over the Noise channel to the local cache.
async fn save_hash_file(config: &RunConfig, file_id: &str, b64_data: &str) -> anyhow::Result<PathBuf> {
    let cache_dir = config.cache_dir();
    tokio::fs::create_dir_all(&cache_dir).await?;

    let cached_path = cache_dir.join(file_id);

    // If already cached, reuse it
    if cached_path.exists() {
        info!(path = %cached_path.display(), "using cached hash file");
        return Ok(cached_path);
    }

    // Decode from base64 and write to disk
    let data = base64::engine::general_purpose::STANDARD
        .decode(b64_data)
        .context("failed to decode hash file from base64")?;

    tokio::fs::write(&cached_path, &data).await?;
    info!(
        path = %cached_path.display(),
        size = data.len(),
        "hash file saved from coordinator"
    );

    Ok(cached_path)
}

// ── Benchmarking ──

/// Run `hashcat --benchmark -m <hash_mode>` and return the aggregate speed.
async fn run_benchmark(hashcat_path: &str, hash_mode: u32) -> u64 {
    info!(hash_mode, "running benchmark");
    let result = tokio::process::Command::new(hashcat_path)
        .arg("--benchmark")
        .arg("-m")
        .arg(hash_mode.to_string())
        .arg("--machine-readable")
        .output()
        .await;

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Machine-readable benchmark output has lines like:
            //   <hash_mode>:<device_id>:<speed_h_s>
            let speed: u64 = stdout
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.trim().split(':').collect();
                    if parts.len() >= 3 {
                        parts[2].parse::<u64>().ok()
                    } else {
                        None
                    }
                })
                .sum();
            info!(hash_mode, speed, "benchmark complete");
            speed
        }
        Err(e) => {
            error!(error = %e, "benchmark failed");
            0
        }
    }
}

// ── Helpers ──

/// Create an mpsc::Sender that wraps runner events with chunk/task IDs.
fn wrap_sender(
    tx: mpsc::Sender<(Uuid, Uuid, RunnerEvent)>,
    chunk_id: Uuid,
    task_id: Uuid,
) -> mpsc::Sender<RunnerEvent> {
    let (inner_tx, mut inner_rx) = mpsc::channel::<RunnerEvent>(64);
    tokio::spawn(async move {
        while let Some(event) = inner_rx.recv().await {
            if tx.send((chunk_id, task_id, event)).await.is_err() {
                break;
            }
        }
    });
    inner_tx
}

/// Simple exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 60s max.
struct ExponentialBackoff {
    current: Duration,
}

impl ExponentialBackoff {
    fn new() -> Self {
        Self {
            current: Duration::from_secs(0),
        }
    }

    fn next_delay(&mut self) -> Duration {
        if self.current.is_zero() {
            self.current = Duration::from_secs(1);
        } else {
            self.current = (self.current * 2).min(Duration::from_secs(60));
        }
        self.current
    }
}
