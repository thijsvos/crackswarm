mod config;
mod connection;
mod runner;
mod status;

use anyhow::Context;
use clap::Parser;
use tracing::{error, info};

use crate::config::{Cli, Commands};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing (respects RUST_LOG env var)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "crack_agent=info,warn".into()),
        )
        .with_ansi(!cfg!(windows))
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { coord_key, data_dir } => {
            cmd_init(&coord_key, &data_dir).await?;
        }
        Commands::Run(run_config) => {
            cmd_run(&run_config).await?;
        }
    }

    Ok(())
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
    let keypair =
        auth::Keypair::generate().context("failed to generate keypair")?;

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

/// `crack-agent run` -- connect to the coordinator and start processing work.
async fn cmd_run(config: &config::RunConfig) -> anyhow::Result<()> {
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
    match status::detect_hashcat(&config.hashcat_path).await {
        Ok(version) => {
            info!(version = %version, "hashcat detected");
        }
        Err(e) => {
            error!(error = %e, "hashcat not found or not working");
            anyhow::bail!(
                "hashcat at '{}' is not available: {e}",
                config.hashcat_path
            );
        }
    }

    // Create cache directory
    tokio::fs::create_dir_all(config.cache_dir()).await?;

    // Enter the connection loop (reconnects automatically)
    connection::run_connection(config).await
}
