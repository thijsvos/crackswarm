use std::path::PathBuf;

use clap::{Parser, Subcommand};

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
        #[arg(long, default_value_os_t = crack_common::auth::coordinator_data_dir())]
        data_dir: PathBuf,

        /// Bind address for the worker Noise transport
        #[arg(long, default_value = "0.0.0.0:8443")]
        bind: String,

        /// Bind address for the REST API (localhost only for security)
        #[arg(long, default_value = "127.0.0.1:9443")]
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
