mod client;
mod display;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crack_common::models::AttackConfig;

use crate::client::{Client, CreateTaskPayload};

// ── CLI definition ──

/// crackctl - CLI tool for managing the crack-coord coordinator
#[derive(Parser)]
#[command(name = "crackctl", version, about)]
struct Cli {
    /// Coordinator API URL
    #[arg(long, default_value = "http://127.0.0.1:9443", global = true)]
    api_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage cracking tasks
    Task {
        #[command(subcommand)]
        action: TaskAction,
    },
    /// Manage uploaded files
    File {
        #[command(subcommand)]
        action: FileAction,
    },
    /// Manage workers
    Worker {
        #[command(subcommand)]
        action: WorkerAction,
    },
    /// Potfile operations
    Potfile {
        #[command(subcommand)]
        action: PotfileAction,
    },
    /// Show system overview
    Status,
}

// ── Task subcommands ──

#[derive(Subcommand)]
enum TaskAction {
    /// Create a new cracking task
    Create {
        /// Task name
        #[arg(long)]
        name: String,

        /// Hash mode (e.g. 1000 for NTLM)
        #[arg(long)]
        hash_mode: u32,

        /// Hash file ID (from `file upload`)
        #[arg(long)]
        hash_file: String,

        /// Brute-force mask (required)
        #[arg(long)]
        mask: String,

        /// Custom charset 1 (-1)
        #[arg(long)]
        charset1: Option<String>,

        /// Custom charset 2 (-2)
        #[arg(long)]
        charset2: Option<String>,

        /// Custom charset 3 (-3)
        #[arg(long)]
        charset3: Option<String>,

        /// Custom charset 4 (-4)
        #[arg(long)]
        charset4: Option<String>,

        /// Priority 1-10 (default: 5)
        #[arg(long, default_value_t = 5)]
        priority: u8,

        /// Extra hashcat arguments (space-separated)
        #[arg(long)]
        extra_args: Option<String>,
    },
    /// List all tasks
    List,
    /// Show task details including chunks
    Show {
        /// Task ID
        id: String,
    },
    /// Cancel a running task
    Cancel {
        /// Task ID
        id: String,
    },
    /// Delete a task
    Delete {
        /// Task ID
        id: String,
    },
    /// Show cracked hashes for a task
    Results {
        /// Task ID
        id: String,
    },
}

// ── File subcommands ──

#[derive(Subcommand)]
enum FileAction {
    /// Upload a file
    Upload {
        /// Path to the file
        path: PathBuf,

        /// File type: hash, wordlist
        #[arg(long, default_value = "hash")]
        r#type: String,
    },
    /// List uploaded files
    List,
}

// ── Worker subcommands ──

#[derive(Subcommand)]
enum WorkerAction {
    /// List all workers
    List,
    /// Authorize a worker
    Authorize {
        /// Worker's public key (base64)
        #[arg(long)]
        pubkey: String,

        /// Worker name
        #[arg(long)]
        name: String,
    },
}

// ── Potfile subcommands ──

#[derive(Subcommand)]
enum PotfileAction {
    /// Show potfile statistics
    Stats,
    /// Export cracked plaintexts
    Export {
        /// Output file path
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

// ── Main ──

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let client = Client::new(&cli.api_url);

    match cli.command {
        Commands::Task { action } => handle_task(&client, action).await?,
        Commands::File { action } => handle_file(&client, action).await?,
        Commands::Worker { action } => handle_worker(&client, action).await?,
        Commands::Potfile { action } => handle_potfile(&client, action).await?,
        Commands::Status => handle_status(&client).await?,
    }

    Ok(())
}

// ── Handlers ──

async fn handle_task(client: &Client, action: TaskAction) -> Result<()> {
    match action {
        TaskAction::Create {
            name,
            hash_mode,
            hash_file,
            mask,
            charset1,
            charset2,
            charset3,
            charset4,
            priority,
            extra_args,
        } => {
            // Build custom charsets list from the individual --charset flags
            let custom_charsets = {
                let slots = [charset1, charset2, charset3, charset4];
                let charsets: Vec<String> = slots.into_iter().flatten().collect();
                if charsets.is_empty() {
                    None
                } else {
                    Some(charsets)
                }
            };

            let extra = extra_args
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default();

            let payload = CreateTaskPayload {
                name,
                hash_mode,
                hash_file_id: hash_file,
                attack_config: AttackConfig::BruteForce {
                    mask,
                    custom_charsets,
                },
                priority,
                extra_args: extra,
            };

            let task = client.create_task(payload).await?;
            println!("Task created: {}", task.id);
        }

        TaskAction::List => {
            let tasks = client.list_tasks().await?;
            display::print_tasks(&tasks);
        }

        TaskAction::Show { id } => {
            let detail = client.get_task(&id).await?;
            display::print_task_detail(&detail.task, &detail.chunks);
        }

        TaskAction::Cancel { id } => {
            client.cancel_task(&id).await?;
            println!("Task {id} cancelled.");
        }

        TaskAction::Delete { id } => {
            client.delete_task(&id).await?;
            println!("Task {id} deleted.");
        }

        TaskAction::Results { id } => {
            let results = client.get_task_results(&id).await?;
            display::print_results(&results);
        }
    }

    Ok(())
}

async fn handle_file(client: &Client, action: FileAction) -> Result<()> {
    match action {
        FileAction::Upload { path, r#type } => {
            let record = client.upload_file(&path, &r#type).await?;
            println!("File uploaded: {} ({})", record.id, record.filename);
        }

        FileAction::List => {
            let files = client.list_files().await?;
            display::print_files(&files);
        }
    }

    Ok(())
}

async fn handle_worker(client: &Client, action: WorkerAction) -> Result<()> {
    match action {
        WorkerAction::List => {
            let workers = client.list_workers().await?;
            display::print_workers(&workers);
        }

        WorkerAction::Authorize { pubkey, name } => {
            client.authorize_worker(&pubkey, &name).await?;
            println!("Worker '{name}' authorized.");
        }
    }

    Ok(())
}

async fn handle_potfile(client: &Client, action: PotfileAction) -> Result<()> {
    match action {
        PotfileAction::Stats => {
            let stats = client.get_potfile_stats().await?;
            display::print_potfile_stats(&stats);
        }

        PotfileAction::Export { output } => {
            let plaintexts = client.export_potfile().await?;

            if plaintexts.is_empty() {
                println!("No cracked plaintexts to export.");
                return Ok(());
            }

            match output {
                Some(path) => {
                    let content = plaintexts.join("\n") + "\n";
                    tokio::fs::write(&path, content.as_bytes()).await?;
                    println!(
                        "Exported {} plaintext(s) to {}",
                        plaintexts.len(),
                        path.display()
                    );
                }
                None => {
                    for p in &plaintexts {
                        println!("{p}");
                    }
                    eprintln!();
                    eprintln!("{} plaintext(s) total", plaintexts.len());
                }
            }
        }
    }

    Ok(())
}

async fn handle_status(client: &Client) -> Result<()> {
    let status = client.get_status().await?;
    display::print_status(&status);
    Ok(())
}
