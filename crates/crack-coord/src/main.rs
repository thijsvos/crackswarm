mod admin_token;
mod api;
mod audit;
mod campaign;
mod config;
mod last_seen;
mod lifecycle;
mod monitor;
mod scheduler;
mod state;
mod storage;
mod transport;
mod tui;

use std::sync::Arc;

use clap::Parser;
use tracing::{error, info};

use config::{Cli, Commands, RunConfig};
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
            let config =
                RunConfig::from_cli(data_dir, bind, api_bind, with_agent, headless, hashcat_path);
            cmd_run(config).await
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
    println!(
        "  crack-agent init --coord-key {}",
        keypair.public_key_b64()
    );

    Ok(())
}

async fn cmd_run(config: RunConfig) -> anyhow::Result<()> {
    let RunConfig {
        data_dir,
        bind,
        api_bind,
        with_agent,
        headless,
        hashcat_path,
    } = config;

    // Ensure data directory exists before anything else
    std::fs::create_dir_all(&data_dir)?;

    // Init logging (to stderr so it doesn't interfere with TUI)
    if headless {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();
    } else {
        // When TUI is active, log to a file to avoid corrupting the terminal
        let log_file = std::fs::File::create(data_dir.join("crack-coord.log"))
            .expect("failed to create log file");
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .with_writer(std::sync::Mutex::new(log_file))
            .with_ansi(false)
            .init();
    }

    // Auto-init: generate keypair + files dir if not present
    let keypair = if data_dir.join("private.key").exists() {
        Keypair::load_from_dir(&data_dir).map_err(|e| {
            anyhow::anyhow!("Failed to load keypair from {}: {}", data_dir.display(), e)
        })?
    } else {
        info!(
            "No keypair found, auto-initializing coordinator in {}...",
            data_dir.display()
        );
        let kp = Keypair::generate()?;
        kp.save_to_dir(&data_dir)?;
        std::fs::create_dir_all(data_dir.join("files"))?;
        info!("Auto-initialized. Public key: {}", kp.public_key_b64());
        kp
    };

    // Ensure files directory exists
    std::fs::create_dir_all(data_dir.join("files"))?;

    info!("Coordinator public key: {}", keypair.public_key_b64());

    // Initialize database
    let db = storage::db::init_db(&data_dir).await?;
    info!("Database initialized");

    // Determine hashcat path
    let hc_path_str = hashcat_path
        .as_ref()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "hashcat".to_string());

    // Create shared state
    let (state, audit_rx) = state::AppState::new(
        db,
        data_dir.clone(),
        keypair,
        hc_path_str.clone(),
        bind.clone(),
    );

    // Spin up the audit-log batcher before we emit the first event.
    let audit_pool = state.db.clone();
    tokio::spawn(async move {
        audit::run_audit_flusher(audit_pool, audit_rx).await;
    });

    // Background flusher for buffered heartbeat writes.
    let last_seen_state = Arc::clone(&state);
    tokio::spawn(async move {
        last_seen::run_last_seen_flusher(last_seen_state).await;
    });

    state.emit_audit(
        "coordinator_started",
        &format!("Coordinator started on {bind}"),
        None,
        None,
    );

    // Start worker transport listener
    let transport_state = Arc::clone(&state);
    let transport_bind = bind.clone();
    tokio::spawn(async move {
        if let Err(e) = transport::start_transport(transport_state, &transport_bind).await {
            error!("Transport listener error: {e}");
        }
    });

    // Generate or load the REST admin token before starting the API
    // listener so any client that races startup gets a 401 rather than
    // an unauthenticated response.
    let admin_token = Arc::new(
        admin_token::AdminToken::load_or_create(&data_dir)
            .expect("failed to load or generate REST admin token"),
    );
    info!(
        "REST admin token at {} (chmod 600 on Unix)",
        data_dir.join("admin.token").display()
    );

    // Start REST API server
    let api_state = Arc::clone(&state);
    let api_token = Arc::clone(&admin_token);
    let api_bind_addr = api_bind.clone();
    tokio::spawn(async move {
        let router = api::create_router(api_state, api_token);
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

    // Start GC loop: drains gc_queue and reclaims files whose refs dropped
    // to zero while tasks/campaigns were transitioning to terminal states.
    let gc_state = Arc::clone(&state);
    tokio::spawn(async move {
        lifecycle::run_gc_loop(gc_state).await;
    });

    // Optionally start a local agent (pre-check hashcat availability)
    if with_agent {
        match crack_agent::status::detect_hashcat(&hc_path_str).await {
            Ok(version) => {
                info!("Built-in agent hashcat: {version}");
            }
            Err(e) => {
                eprintln!("WARNING: --with-agent requires hashcat but it was not found.");
                eprintln!("  {e}");
                eprintln!("  Install hashcat or specify: --hashcat-path /path/to/hashcat");
                eprintln!("  The coordinator will still run (remote workers can connect).");
                eprintln!();
            }
        }
        let agent_state = Arc::clone(&state);
        let hc_path = hc_path_str.clone();
        let coord_bind = bind.clone();
        let agent_data_dir = data_dir.join("built-in-agent");

        tokio::spawn(async move {
            info!("Starting built-in agent...");
            // Small delay to let the transport listener start
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // The built-in agent connects via localhost to the same transport port
            let coord_addr = coord_bind.replace("0.0.0.0", "127.0.0.1");

            // Set up a data directory for the built-in agent with its own keypair
            if let Err(e) = tokio::fs::create_dir_all(&agent_data_dir).await {
                error!("Failed to create built-in agent data dir: {e}");
                return;
            }

            // Generate keypair if not already present
            let agent_kp = if agent_data_dir.join("private.key").exists() {
                match Keypair::load_from_dir(&agent_data_dir) {
                    Ok(kp) => kp,
                    Err(e) => {
                        error!("Failed to load built-in agent keypair: {e}");
                        return;
                    }
                }
            } else {
                let kp = match Keypair::generate() {
                    Ok(kp) => kp,
                    Err(e) => {
                        error!("Failed to generate agent keypair: {e}");
                        return;
                    }
                };
                if let Err(e) = kp.save_to_dir(&agent_data_dir) {
                    error!("Failed to save built-in agent keypair: {e}");
                    return;
                }
                kp
            };

            // Save coordinator's public key so the agent can authenticate
            if let Err(e) = auth::save_remote_key(
                &agent_data_dir,
                "coordinator.pub",
                &agent_state.keypair.public_key,
            ) {
                error!("Failed to save coordinator pubkey for built-in agent: {e}");
                return;
            }

            // Auto-authorize this agent in the coordinator's DB
            let pubkey_b64 = agent_kp.public_key_b64();
            if let Err(e) =
                storage::db::authorize_worker(&agent_state.db, &pubkey_b64, "built-in-agent").await
            {
                error!("Failed to authorize built-in agent: {e}");
                return;
            }

            info!("Built-in agent authorized, connecting to {coord_addr}");

            // Reuse the full crack-agent connection logic
            let run_config = crack_agent::config::RunConfig {
                server: coord_addr,
                name: Some("built-in-agent".to_string()),
                data_dir: agent_data_dir,
                hashcat_path: hc_path,
                headless: true,
                // Built-in agent shares the coord's data dir; default
                // 80 GiB cache budget is fine for most local setups
                // (operator can set CRACK_AGENT_CACHE_MAX to override).
                cache_max_bytes: std::env::var("CRACK_AGENT_CACHE_MAX")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(80 * 1024 * 1024 * 1024),
            };

            if let Err(e) = crack_agent::connection::run_connection(&run_config, None).await {
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
