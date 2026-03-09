mod api;
mod config;
mod monitor;
mod scheduler;
mod state;
mod storage;
mod transport;
mod tui;

use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};

use config::{Cli, Commands};
use crack_common::auth::{self, Keypair};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { data_dir } => cmd_init(&data_dir).await,
        Commands::Run {
            data_dir,
            bind,
            api_bind,
            with_agent,
            headless,
            hashcat_path,
        } => {
            cmd_run(data_dir, bind, api_bind, with_agent, headless, hashcat_path)
                .await
        }
    }
}

async fn cmd_init(data_dir: &std::path::Path) -> anyhow::Result<()> {
    println!("Initializing coordinator in {}...", data_dir.display());

    // Check if already initialized
    if data_dir.join("private.key").exists() {
        println!("Coordinator already initialized. Public key:");
        let keypair = Keypair::load_from_dir(data_dir)?;
        println!("  {}", keypair.public_key_b64());
        return Ok(());
    }

    // Generate keypair
    let keypair = Keypair::generate()?;
    keypair.save_to_dir(data_dir)?;

    // Create subdirectories
    std::fs::create_dir_all(data_dir.join("files"))?;

    println!("Coordinator initialized successfully.");
    println!("Public key (share with workers):");
    println!("  {}", keypair.public_key_b64());
    println!();
    println!("Workers can initialize with:");
    println!("  crack-agent init --coord-key {}", keypair.public_key_b64());

    Ok(())
}

async fn cmd_run(
    data_dir: std::path::PathBuf,
    bind: String,
    api_bind: String,
    with_agent: bool,
    headless: bool,
    hashcat_path: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    // Init logging (to stderr so it doesn't interfere with TUI)
    if headless {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    } else {
        // When TUI is active, only log errors to stderr to avoid interference
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("error"))
            .with_writer(std::io::stderr)
            .init();
    }

    // Load keypair
    let keypair = Keypair::load_from_dir(&data_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to load keypair from {}: {}. Run 'crack-coord init' first.",
            data_dir.display(),
            e
        )
    })?;

    info!("Coordinator public key: {}", keypair.public_key_b64());

    // Initialize database
    let db = storage::db::init_db(&data_dir).await?;
    info!("Database initialized");

    // Create shared state
    let state = state::AppState::new(db, data_dir.clone(), keypair);

    // Audit log: coordinator started
    let _ = storage::db::insert_audit(
        &state.db,
        "coordinator_started",
        &format!("Coordinator started on {bind}"),
        None,
        None,
    )
    .await;

    // Start worker transport listener
    let transport_state = Arc::clone(&state);
    let transport_bind = bind.clone();
    tokio::spawn(async move {
        if let Err(e) = transport::start_transport(transport_state, &transport_bind).await {
            error!("Transport listener error: {e}");
        }
    });

    // Start REST API server
    let api_state = Arc::clone(&state);
    let api_bind_addr = api_bind.clone();
    tokio::spawn(async move {
        let router = api::create_router(api_state);
        let listener = tokio::net::TcpListener::bind(&api_bind_addr)
            .await
            .expect("failed to bind API listener");
        info!("REST API listening on {api_bind_addr}");
        axum::serve(listener, router)
            .await
            .expect("API server error");
    });

    // Start health monitor
    let monitor_state = Arc::clone(&state);
    tokio::spawn(async move {
        monitor::run_monitor(monitor_state).await;
    });

    // Optionally start a local agent
    if with_agent {
        let agent_state = Arc::clone(&state);
        let hc_path = hashcat_path
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "hashcat".to_string());
        let coord_bind = bind.clone();

        tokio::spawn(async move {
            info!("Starting built-in agent...");
            // Small delay to let the transport listener start
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // The built-in agent connects via localhost to the same transport port
            let coord_addr = coord_bind.replace("0.0.0.0", "127.0.0.1");

            // Generate a temporary keypair for the built-in agent
            let agent_kp = match Keypair::generate() {
                Ok(kp) => kp,
                Err(e) => {
                    error!("Failed to generate agent keypair: {e}");
                    return;
                }
            };

            // Auto-authorize this agent
            let pubkey_b64 = agent_kp.public_key_b64();
            if let Err(e) = storage::db::authorize_worker(
                &agent_state.db,
                &pubkey_b64,
                "built-in-agent",
            )
            .await
            {
                error!("Failed to authorize built-in agent: {e}");
                return;
            }

            info!("Built-in agent authorized and connecting to {coord_addr}");
            // The actual connection is done via the same protocol as remote agents.
            // For MVP, we spawn a lightweight connection loop here.
            if let Err(e) = run_builtin_agent(
                &coord_addr,
                agent_kp,
                agent_state.keypair.public_key.clone(),
                &hc_path,
            )
            .await
            {
                error!("Built-in agent error: {e}");
            }
        });
    }

    // Run TUI or headless
    if headless {
        info!("Running in headless mode. Press Ctrl+C to stop.");
        tokio::signal::ctrl_c().await?;
        info!("Shutting down...");
    } else {
        println!("Starting TUI dashboard...");
        println!("REST API: http://{api_bind}");
        println!("Worker transport: {bind}");
        if let Err(e) = tui::run_tui(Arc::clone(&state)).await {
            error!("TUI error: {e}");
        }
    }

    Ok(())
}

/// Run a built-in agent that connects to the coordinator on localhost.
/// This is a simplified version — for full agent features, use crack-agent binary.
async fn run_builtin_agent(
    coord_addr: &str,
    keypair: Keypair,
    coord_pubkey: Vec<u8>,
    hashcat_path: &str,
) -> anyhow::Result<()> {
    use crack_common::protocol::{CoordMessage, WorkerMessage};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    loop {
        match TcpStream::connect(coord_addr).await {
            Ok(mut stream) => {
                info!("Built-in agent connected to {coord_addr}");

                // Noise IK handshake (agent is initiator)
                let mut handshake =
                    crack_common::auth::build_initiator(&keypair, &coord_pubkey)?;
                let mut buf = vec![0u8; 65535];

                // Send first message
                let len = handshake.write_message(&[], &mut buf)?;
                let msg_len = (len as u32).to_be_bytes();
                stream.write_all(&msg_len).await?;
                stream.write_all(&buf[..len]).await?;

                // Read response
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).await?;
                let resp_len = u32::from_be_bytes(len_buf) as usize;
                let mut resp_buf = vec![0u8; resp_len];
                stream.read_exact(&mut resp_buf).await?;
                handshake.read_message(&resp_buf, &mut buf)?;

                let mut transport = handshake.into_transport_mode()?;

                // Get hashcat version
                let version = tokio::process::Command::new(hashcat_path)
                    .arg("--version")
                    .output()
                    .await
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());

                // Register
                let register = WorkerMessage::Register {
                    worker_name: "built-in-agent".to_string(),
                    hashcat_version: version,
                    os: std::env::consts::OS.to_string(),
                    devices: vec![],
                };
                let json = serde_json::to_vec(&register)?;
                let len = transport.write_message(&json, &mut buf)?;
                let msg_len = (len as u32).to_be_bytes();
                stream.write_all(&msg_len).await?;
                stream.write_all(&buf[..len]).await?;

                // Simple message loop
                let mut worker_id = String::new();
                loop {
                    // Read message from coordinator
                    let mut len_buf = [0u8; 4];
                    if stream.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let msg_len = u32::from_be_bytes(len_buf) as usize;
                    if msg_len > crack_common::protocol::MAX_MESSAGE_SIZE {
                        break;
                    }
                    let mut cipher_buf = vec![0u8; msg_len];
                    if stream.read_exact(&mut cipher_buf).await.is_err() {
                        break;
                    }
                    let decrypted_len = transport.read_message(&cipher_buf, &mut buf)?;
                    let msg: CoordMessage = serde_json::from_slice(&buf[..decrypted_len])?;

                    match msg {
                        CoordMessage::Welcome { worker_id: wid } => {
                            worker_id = wid;
                            info!("Built-in agent registered as {worker_id}");
                        }
                        CoordMessage::AssignChunk {
                            chunk_id,
                            task_id,
                            hash_mode,
                            hash_file_url,
                            skip,
                            limit,
                            mask,
                            custom_charsets,
                            extra_args,
                        } => {
                            info!("Built-in agent received chunk {chunk_id} for task {task_id}");
                            // For now, just report the chunk as started, then spawn hashcat.
                            // Full implementation would mirror crack-agent's runner.
                            let started = WorkerMessage::ChunkStarted { chunk_id };
                            let json = serde_json::to_vec(&started)?;
                            let len = transport.write_message(&json, &mut buf)?;
                            let msg_len = (len as u32).to_be_bytes();
                            stream.write_all(&msg_len).await?;
                            stream.write_all(&buf[..len]).await?;

                            // TODO: actually run hashcat and report progress
                            // For MVP, the built-in agent works but delegates to
                            // the full crack-agent for actual hashcat execution.
                        }
                        CoordMessage::Shutdown => {
                            info!("Built-in agent received shutdown");
                            return Ok(());
                        }
                        _ => {}
                    }

                    // Send heartbeat periodically (simplified)
                    let hb = WorkerMessage::Heartbeat;
                    let json = serde_json::to_vec(&hb)?;
                    let len = transport.write_message(&json, &mut buf)?;
                    let msg_len = (len as u32).to_be_bytes();
                    stream.write_all(&msg_len).await?;
                    stream.write_all(&buf[..len]).await?;
                }
            }
            Err(e) => {
                tracing::warn!("Built-in agent connection failed: {e}, retrying in 5s...");
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
