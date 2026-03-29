mod client;
mod display;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crack_common::models::AttackConfig;

use crate::client::{Client, CreateCampaignPayload, CreateTaskPayload};

// ── CLI definition ──

/// crackctl - CLI tool for managing the crack-coord coordinator
#[derive(Parser)]
#[command(name = "crackctl", version, about)]
struct Cli {
    /// Coordinator API URL
    #[arg(
        long,
        env = "CRACKCTL_API_URL",
        default_value = "http://127.0.0.1:9443",
        global = true
    )]
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
    /// Manage cracking campaigns
    Campaign {
        #[command(subcommand)]
        action: CampaignAction,
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
#[allow(clippy::large_enum_variant)]
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

        /// Brute-force mask (for mask/brute-force attack)
        #[arg(long)]
        mask: Option<String>,

        /// Wordlist file ID (for dictionary attack, from `file upload`)
        #[arg(long)]
        wordlist: Option<String>,

        /// Rules file ID (for dictionary+rules attack, from `file upload`)
        #[arg(long)]
        rules_file: Option<String>,

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
    /// Generate an enrollment token for a new worker
    Enroll {
        /// Worker name
        #[arg(long)]
        name: String,

        /// Token validity in minutes (default: 60)
        #[arg(long, default_value_t = 60)]
        expires_minutes: u64,
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

// ── Campaign subcommands ──

#[derive(Subcommand)]
enum CampaignAction {
    /// Create a new campaign
    Create {
        /// Campaign name
        #[arg(long)]
        name: String,

        /// Hash mode (e.g. 1000 for NTLM)
        #[arg(long)]
        hash_mode: u32,

        /// Hash file ID (from `file upload`). Required unless --hash-file-path is given.
        #[arg(long, default_value = "")]
        hash_file: String,

        /// Use a built-in template (e.g. ntlm-standard, wpa-quick, generic-quick)
        #[arg(long)]
        template: Option<String>,

        /// Priority 1-10 (default: 5)
        #[arg(long, default_value_t = 5)]
        priority: u8,

        /// Extra hashcat arguments (space-separated)
        #[arg(long)]
        extra_args: Option<String>,

        /// Automatically start the campaign after creation
        #[arg(long)]
        auto_start: bool,

        /// Path to a hash file on disk (auto-uploads before creating campaign)
        #[arg(long)]
        hash_file_path: Option<PathBuf>,
    },
    /// List all campaigns
    List,
    /// Show campaign details including phases
    Show {
        /// Campaign ID
        id: String,
    },
    /// Start a draft campaign
    Start {
        /// Campaign ID
        id: String,
    },
    /// Cancel a running campaign
    Cancel {
        /// Campaign ID
        id: String,
    },
    /// Delete a campaign
    Delete {
        /// Campaign ID
        id: String,
    },
    /// Show cracked hashes across all campaign phases
    Results {
        /// Campaign ID
        id: String,
    },
    /// List built-in campaign templates
    Templates,
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
        Commands::Campaign { action } => handle_campaign(&client, action).await?,
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
            wordlist,
            rules_file,
            charset1,
            charset2,
            charset3,
            charset4,
            priority,
            extra_args,
        } => {
            // Determine the attack config based on which flags were provided.
            let attack_config = match (mask, wordlist) {
                (Some(m), None) => {
                    // Brute-force / mask attack
                    let custom_charsets = {
                        let slots = [charset1, charset2, charset3, charset4];
                        let charsets: Vec<String> = slots.into_iter().flatten().collect();
                        if charsets.is_empty() {
                            None
                        } else {
                            Some(charsets)
                        }
                    };
                    AttackConfig::BruteForce {
                        mask: m,
                        custom_charsets,
                    }
                }
                (None, Some(wl)) => {
                    // Dictionary attack (optionally with rules)
                    if let Some(rf) = rules_file {
                        AttackConfig::DictionaryWithRules {
                            wordlist_file_id: wl,
                            rules_file_id: rf,
                        }
                    } else {
                        AttackConfig::Dictionary {
                            wordlist_file_id: wl,
                        }
                    }
                }
                (Some(_), Some(_)) => {
                    anyhow::bail!("Cannot specify both --mask and --wordlist. Use --mask for brute-force or --wordlist for dictionary attacks.");
                }
                (None, None) => {
                    anyhow::bail!("Either --mask or --wordlist is required.");
                }
            };

            let extra = extra_args
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default();

            let payload = CreateTaskPayload {
                name,
                hash_mode,
                hash_file_id: hash_file,
                attack_config,
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

        WorkerAction::Enroll {
            name,
            expires_minutes,
        } => {
            let resp = client.enroll_worker(&name, expires_minutes).await?;
            println!(
                "Token generated for worker '{}' (expires in {} minutes).",
                name, expires_minutes
            );
            println!();
            println!("Token: {}", resp.token);
            println!();
            println!("On the worker machine, run:");
            println!("  crack-agent enroll --token '{}'", resp.token);
            println!();
            println!("To override the server address:");
            println!(
                "  crack-agent enroll --token '{}' --server <ip>:8443",
                resp.token
            );
        }
    }

    Ok(())
}

async fn handle_campaign(client: &Client, action: CampaignAction) -> Result<()> {
    match action {
        CampaignAction::Create {
            name,
            hash_mode,
            hash_file,
            template,
            priority,
            extra_args,
            auto_start,
            hash_file_path,
        } => {
            // Resolve hash file ID: either from --hash-file or auto-upload from --hash-file-path
            let hash_file_id = if let Some(path) = hash_file_path {
                let record = client.upload_file(&path, "hash").await?;
                println!("File uploaded: {} ({})", record.id, record.filename);
                record.id
            } else if hash_file.is_empty() {
                anyhow::bail!("Either --hash-file or --hash-file-path is required");
            } else {
                hash_file
            };

            let extra = extra_args
                .map(|s| s.split_whitespace().map(String::from).collect())
                .unwrap_or_default();

            let payload = CreateCampaignPayload {
                name,
                hash_mode,
                hash_file_id,
                template,
                priority,
                extra_args: extra,
            };

            let campaign = client.create_campaign(payload).await?;
            println!("Campaign created: {}", campaign.id);

            if auto_start {
                client.start_campaign(&campaign.id.to_string()).await?;
                println!("Campaign {} started.", campaign.id);
            } else {
                println!("Start it with: crackctl campaign start {}", campaign.id);
            }
        }

        CampaignAction::List => {
            let campaigns = client.list_campaigns().await?;
            display::print_campaigns(&campaigns);
        }

        CampaignAction::Show { id } => {
            let detail = client.get_campaign(&id).await?;
            display::print_campaign_detail(&detail);
        }

        CampaignAction::Start { id } => {
            client.start_campaign(&id).await?;
            println!("Campaign {id} started.");
        }

        CampaignAction::Cancel { id } => {
            client.cancel_campaign(&id).await?;
            println!("Campaign {id} cancelled.");
        }

        CampaignAction::Delete { id } => {
            client.delete_campaign(&id).await?;
            println!("Campaign {id} deleted.");
        }

        CampaignAction::Results { id } => {
            let results = client.get_campaign_results(&id).await?;
            display::print_results(&results);
        }

        CampaignAction::Templates => {
            let templates = client.list_templates().await?;
            display::print_templates(&templates);
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
