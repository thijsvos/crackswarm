use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "crack-agent", about = "Distributed hashcat worker agent")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize the agent (generate keypair, save coordinator public key)
    Init {
        /// Coordinator's public key (base64-encoded)
        #[arg(long)]
        coord_key: String,

        /// Data directory for keys and cache
        #[arg(long, default_value_os_t = crack_common::auth::agent_data_dir())]
        data_dir: PathBuf,
    },
    /// Start the agent and connect to the coordinator
    Run(RunConfig),
    /// Enroll using a token from the coordinator
    Enroll {
        /// Enrollment token from `crackctl worker enroll`
        #[arg(long)]
        token: String,

        /// Override the server address from the token
        #[arg(long, env = "CRACK_AGENT_SERVER")]
        server: Option<String>,

        /// Data directory for keys and cache
        #[arg(long, env = "CRACK_AGENT_DATA_DIR", default_value_os_t = crack_common::auth::agent_data_dir())]
        data_dir: PathBuf,

        /// Path to the hashcat binary
        #[arg(long, default_value = "hashcat")]
        hashcat_path: String,
    },
}

/// Configuration for the `run` subcommand.
#[derive(Debug, Clone, clap::Args)]
pub struct RunConfig {
    /// Coordinator Noise transport address (host:port)
    #[arg(long, env = "CRACK_AGENT_SERVER")]
    pub server: String,

    /// Worker name (defaults to hostname)
    #[arg(long)]
    pub name: Option<String>,

    /// Data directory for keys and cache
    #[arg(long, env = "CRACK_AGENT_DATA_DIR", default_value_os_t = crack_common::auth::agent_data_dir())]
    pub data_dir: PathBuf,

    /// Path to the hashcat binary
    #[arg(long, default_value = "hashcat")]
    pub hashcat_path: String,

    /// Run without TUI (log output only)
    #[arg(long)]
    pub headless: bool,

    /// Maximum bytes the content-addressed cache may consume on disk.
    /// When a new pull would push past this ceiling, the cache evicts
    /// least-recently-used entries (skipping any that are currently in
    /// use by a running chunk) to make room. If still insufficient, the
    /// chunk is reported as `PullFailed` and the coord reassigns it.
    ///
    /// Default: 80 GiB. Override with `--cache-max-bytes` or
    /// `CRACK_AGENT_CACHE_MAX` (raw bytes).
    #[arg(long, env = "CRACK_AGENT_CACHE_MAX", default_value_t = 80 * 1024 * 1024 * 1024)]
    pub cache_max_bytes: u64,
}

impl RunConfig {
    /// Derive the coordinator REST API base URL from the Noise server address.
    ///
    /// Takes the host from `--server` (e.g. `203.0.113.10:8443`) and builds
    /// `http://<host>:9443`.
    pub fn api_base_url(&self) -> String {
        let host = self
            .server
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(&self.server);
        format!("http://{}:9443", host)
    }

    /// Effective worker name: the `--name` flag, or the system hostname.
    pub fn worker_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "unknown-agent".to_string())
        })
    }

    /// Cache directory for downloaded hash files.
    pub fn cache_dir(&self) -> PathBuf {
        self.data_dir.join("cache")
    }
}
