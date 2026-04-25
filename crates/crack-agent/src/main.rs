use anyhow::Context;
use base64::Engine;
use clap::Parser;
use tracing::{error, info};

use crack_agent::config::{Cli, Commands, RunConfig};
use crack_agent::{connection, status, tui};
use crack_common::models::EnrollmentToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            coord_key,
            data_dir,
        } => {
            init_tracing();
            cmd_init(&coord_key, &data_dir).await?;
        }
        Commands::Run(run_config) => {
            if run_config.headless {
                init_tracing();
            } else {
                // When TUI is active, log to a file to avoid corrupting the terminal
                init_tracing_to_file(&run_config.data_dir);
            }
            cmd_run(&run_config).await?;
        }
        Commands::Enroll {
            token,
            server,
            data_dir,
            hashcat_path,
        } => {
            init_tracing();
            cmd_enroll(&token, server.as_deref(), &data_dir, &hashcat_path).await?;
        }
    }

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crack_agent=info,warn".into()),
        )
        .with_ansi(!cfg!(windows))
        .init();
}

fn init_tracing_to_file(data_dir: &std::path::Path) {
    let _ = std::fs::create_dir_all(data_dir);
    let log_file = match std::fs::File::create(data_dir.join("crack-agent.log")) {
        Ok(f) => f,
        Err(_) => {
            // Fall back to stderr logging
            init_tracing();
            return;
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crack_agent=info,warn".into()),
        )
        .with_writer(std::sync::Mutex::new(log_file))
        .with_ansi(false)
        .init();
}

/// `crack-agent init` -- generate a keypair and save the coordinator's public key.
async fn cmd_init(coord_key_b64: &str, data_dir: &std::path::Path) -> anyhow::Result<()> {
    use crack_common::auth;

    info!(data_dir = %data_dir.display(), "initializing agent");

    // Decode and validate the coordinator's public key
    let coord_pubkey = auth::decode_public_key(coord_key_b64)
        .context("invalid coordinator public key (expected base64-encoded 32-byte key)")?;
    if coord_pubkey.len() != 32 {
        anyhow::bail!(
            "coordinator public key must be 32 bytes, got {}",
            coord_pubkey.len()
        );
    }

    // Generate agent keypair
    let keypair = auth::Keypair::generate().context("failed to generate keypair")?;

    // Save keypair (private.key + public.key)
    keypair
        .save_to_dir(data_dir)
        .context("failed to save keypair")?;

    // Save coordinator public key
    auth::save_remote_key(data_dir, "coordinator.pub", &coord_pubkey)
        .context("failed to save coordinator public key")?;

    println!("Agent initialized successfully.");
    println!("  Data directory : {}", data_dir.display());
    println!("  Agent public key (share with coordinator):");
    println!("  {}", keypair.public_key_b64());

    Ok(())
}

/// `crack-agent enroll` -- enroll using a token, then connect and start processing work.
async fn cmd_enroll(
    token_b64: &str,
    server_override: Option<&str>,
    data_dir: &std::path::Path,
    hashcat_path: &str,
) -> anyhow::Result<()> {
    use crack_common::auth;

    // 1. Decode the enrollment token
    let token_json = base64::engine::general_purpose::STANDARD
        .decode(token_b64)
        .context("failed to decode enrollment token (invalid base64)")?;
    let token: EnrollmentToken =
        serde_json::from_slice(&token_json).context("failed to parse enrollment token")?;

    // 2. Resolve server address: CLI override > token > error
    let server = match server_override {
        Some(s) => s.to_string(),
        None if !token.server_addr.is_empty() => token.server_addr.clone(),
        None => {
            anyhow::bail!(
                "No server address available. The enrollment token does not contain a \
                 server address. Use --server <host:port> to specify the coordinator address."
            );
        }
    };

    info!(worker_name = %token.worker_name, server = %server, "enrolling with coordinator");

    // 3. Save coordinator public key
    let coord_pubkey = auth::decode_public_key(&token.coord_pubkey)
        .context("invalid coordinator public key in token")?;
    if coord_pubkey.len() != 32 {
        anyhow::bail!(
            "coordinator public key must be 32 bytes, got {}",
            coord_pubkey.len()
        );
    }

    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("creating data directory: {}", data_dir.display()))?;

    auth::save_remote_key(data_dir, "coordinator.pub", &coord_pubkey)
        .context("failed to save coordinator public key")?;

    // 4. Generate keypair if not present
    let keypair = if data_dir.join("private.key").exists() && data_dir.join("public.key").exists() {
        info!("using existing agent keypair");
        auth::Keypair::load_from_dir(data_dir).context("failed to load existing keypair")?
    } else {
        info!("generating new agent keypair");
        let kp = auth::Keypair::generate().context("failed to generate keypair")?;
        kp.save_to_dir(data_dir).context("failed to save keypair")?;
        kp
    };

    println!("Agent initialized.");
    println!("  Data directory : {}", data_dir.display());
    println!("  Agent public key: {}", keypair.public_key_b64());
    println!("  Coordinator key : {}", token.coord_pubkey);

    // 5. Validate hashcat
    match status::detect_hashcat(hashcat_path).await {
        Ok(version) => {
            info!(version = %version, "hashcat detected");
        }
        Err(e) => {
            print_hashcat_guidance(hashcat_path, &e);
            std::process::exit(1);
        }
    }

    // 6. Build RunConfig and connect (with enrollment nonce)
    let run_config = RunConfig {
        server: server.clone(),
        name: Some(token.worker_name.clone()),
        data_dir: data_dir.to_path_buf(),
        hashcat_path: hashcat_path.to_string(),
        headless: false,
        cache_max_bytes: std::env::var("CRACK_AGENT_CACHE_MAX")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(80 * 1024 * 1024 * 1024),
    };

    // Create cache directory
    tokio::fs::create_dir_all(run_config.cache_dir()).await?;

    println!("Connecting to coordinator at {} ...", server);

    // Use the enrollment-aware connection
    connection::run_connection_with_enroll(&run_config, &token.nonce, &token.worker_name, None)
        .await
}

/// `crack-agent run` -- connect to the coordinator and start processing work.
async fn cmd_run(config: &RunConfig) -> anyhow::Result<()> {
    info!(
        server = %config.server,
        name = %config.worker_name(),
        data_dir = %config.data_dir.display(),
        hashcat = %config.hashcat_path,
        "starting agent"
    );

    // Validate that the keypair exists
    let _keypair = crack_common::auth::Keypair::load_from_dir(&config.data_dir)
        .context("keypair not found -- run 'crack-agent init' first")?;

    // Validate that the coordinator public key exists
    let _coord_key = crack_common::auth::load_remote_key(&config.data_dir, "coordinator.pub")
        .context("coordinator public key not found -- run 'crack-agent init' first")?;

    // Validate that hashcat is available
    let hashcat_version = match status::detect_hashcat(&config.hashcat_path).await {
        Ok(version) => {
            info!(version = %version, "hashcat detected");
            version
        }
        Err(e) => {
            print_hashcat_guidance(&config.hashcat_path, &e);
            std::process::exit(1);
        }
    };

    // Create cache directory
    tokio::fs::create_dir_all(config.cache_dir()).await?;

    if config.headless {
        // Headless mode: run connection directly (current behavior)
        connection::run_connection(config, None).await
    } else {
        // TUI mode: spawn connection in background, run TUI on main thread
        let devices = status::get_devices(&config.hashcat_path)
            .await
            .unwrap_or_default();

        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let config_clone = config.clone();
        tokio::spawn(async move {
            if let Err(e) = connection::run_connection(&config_clone, Some(event_tx)).await {
                error!(error = %e, "connection error");
            }
        });

        tui::run_tui(
            &config.worker_name(),
            &config.server,
            &hashcat_version,
            &devices,
            event_rx,
        )
        .await
    }
}

/// Print detailed hashcat installation guidance on detection failure.
fn print_hashcat_guidance(hashcat_path: &str, error: &dyn std::fmt::Display) {
    eprintln!("Error: hashcat not found at '{}'", hashcat_path);
    eprintln!();
    eprintln!("  {error}");
    eprintln!();
    eprintln!("To fix this:");
    eprintln!("  1. Install hashcat:");
    if cfg!(target_os = "macos") {
        eprintln!("       brew install hashcat");
    } else if cfg!(target_os = "linux") {
        eprintln!("       sudo apt install hashcat    # Debian/Ubuntu");
        eprintln!("       sudo dnf install hashcat    # Fedora/RHEL");
        eprintln!("       sudo pacman -S hashcat      # Arch");
    } else if cfg!(target_os = "windows") {
        eprintln!("       Download from https://hashcat.net/hashcat/");
    }
    eprintln!("     Or download from: https://hashcat.net/hashcat/");
    eprintln!();
    eprintln!("  2. If hashcat is installed but not in PATH:");
    eprintln!("       crack-agent run --hashcat-path /path/to/hashcat");
    eprintln!();
    eprintln!("  3. Verify it works:");
    eprintln!("       hashcat --version");
}
