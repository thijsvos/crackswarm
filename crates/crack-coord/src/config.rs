use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "crack-coord", about = "Distributed hashcat coordinator")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the coordinator (generate keypair, create data directory)
    Init {
        /// Data directory for keys, database, and file storage
        #[arg(long, default_value_os_t = crack_common::auth::coordinator_data_dir())]
        data_dir: PathBuf,
    },
    /// Start the coordinator server
    Run {
        /// Data directory
        #[arg(long, env = "CRACK_COORD_DATA_DIR", default_value_os_t = crack_common::auth::coordinator_data_dir())]
        data_dir: PathBuf,

        /// Bind address for the worker Noise transport
        #[arg(long, env = "CRACK_COORD_BIND", default_value = "0.0.0.0:8443")]
        bind: String,

        /// Bind address for the REST API (localhost only for security)
        #[arg(long, env = "CRACK_COORD_API_BIND", default_value = "127.0.0.1:9443")]
        api_bind: String,

        /// Also run a local worker agent
        #[arg(long)]
        with_agent: bool,

        /// Run without TUI (headless mode for services)
        #[arg(long)]
        headless: bool,

        /// Path to hashcat binary (for --with-agent mode)
        #[arg(long)]
        hashcat_path: Option<PathBuf>,
    },
}

/// TOML configuration file structure.
/// Loaded from `<data-dir>/config.toml` if present.
/// Merge order: defaults < TOML < env vars < CLI flags.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ConfigFile {
    pub bind: Option<String>,
    pub api_bind: Option<String>,
    pub with_agent: Option<bool>,
    pub headless: Option<bool>,
    pub hashcat_path: Option<String>,
}

impl ConfigFile {
    /// Load config from `<data_dir>/config.toml`, returning defaults if not found.
    pub fn load(data_dir: &std::path::Path) -> Self {
        let config_path = data_dir.join("config.toml");
        match std::fs::read_to_string(&config_path) {
            Ok(contents) => match toml::from_str(&contents) {
                Ok(config) => {
                    tracing::info!("Loaded config from {}", config_path.display());
                    config
                }
                Err(e) => {
                    tracing::warn!("Failed to parse {}: {e}", config_path.display());
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }
}

/// Resolved runtime configuration after merging TOML + env + CLI.
pub struct RunConfig {
    pub data_dir: PathBuf,
    pub bind: String,
    pub api_bind: String,
    pub with_agent: bool,
    pub headless: bool,
    pub hashcat_path: Option<PathBuf>,
}

impl RunConfig {
    /// Merge CLI args with config file. CLI/env args take precedence over TOML.
    pub fn from_cli(
        data_dir: PathBuf,
        bind: String,
        api_bind: String,
        with_agent: bool,
        headless: bool,
        hashcat_path: Option<PathBuf>,
    ) -> Self {
        let config_file = ConfigFile::load(&data_dir);

        // CLI defaults are the clap defaults. If the user didn't provide a flag,
        // clap still gives the default. We can't distinguish "user passed --bind"
        // from "clap default" easily. So TOML values are only used when the CLI
        // value matches the default AND the TOML has a value.
        // For boolean flags, the TOML value is an OR with the CLI flag.

        let bind = if bind == "0.0.0.0:8443" {
            config_file.bind.unwrap_or(bind)
        } else {
            bind
        };

        let api_bind = if api_bind == "127.0.0.1:9443" {
            config_file.api_bind.unwrap_or(api_bind)
        } else {
            api_bind
        };

        let with_agent = with_agent || config_file.with_agent.unwrap_or(false);
        let headless = headless || config_file.headless.unwrap_or(false);

        let hashcat_path = hashcat_path.or_else(|| config_file.hashcat_path.map(PathBuf::from));

        RunConfig {
            data_dir,
            bind,
            api_bind,
            with_agent,
            headless,
            hashcat_path,
        }
    }
}
