use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::status;

/// Events emitted by the hashcat runner to the connection loop.
#[derive(Debug, Clone)]
pub enum RunnerEvent {
    StatusUpdate {
        progress_pct: f64,
        speed: u64,
        est_remaining: Option<u64>,
    },
    HashCracked {
        hash: String,
        plaintext: String,
    },
    Completed {
        exit_code: i32,
    },
    Failed {
        error: String,
    },
}

/// Configuration for a single hashcat run.
#[derive(Debug, Clone)]
pub struct HashcatRunConfig {
    pub hashcat_path: String,
    pub hash_file_path: PathBuf,
    pub hash_mode: u32,
    pub mask: String,
    pub skip: u64,
    pub limit: u64,
    pub custom_charsets: Option<Vec<String>>,
    pub extra_args: Vec<String>,
    pub outfile_path: PathBuf,
}

/// Manages a hashcat subprocess.
pub struct HashcatRunner {
    child: Child,
    outfile_path: PathBuf,
}

impl HashcatRunner {
    /// Start a new hashcat process with the given configuration.
    pub fn start(config: &HashcatRunConfig) -> anyhow::Result<Self> {
        let mut cmd = Command::new(&config.hashcat_path);

        // Attack mode 3 = brute-force / mask
        cmd.arg("-a").arg("3");

        // Hash mode
        cmd.arg("-m").arg(config.hash_mode.to_string());

        // Hash file
        cmd.arg(&config.hash_file_path);

        // Mask
        cmd.arg(&config.mask);

        // Keyspace range
        cmd.arg("--skip").arg(config.skip.to_string());
        cmd.arg("--limit").arg(config.limit.to_string());

        // Unique session name per chunk to prevent session file conflicts
        let session_name = config
            .outfile_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("crack")
            .to_string();
        cmd.arg("--session").arg(&session_name);

        // Status output
        cmd.arg("--status");
        cmd.arg("--status-json");
        cmd.arg("--status-timer=5");

        // Disable potfile and restore (we manage state externally)
        // Use a per-chunk potfile path to avoid reading any existing system potfile
        let potfile_path = config.outfile_path.with_extension("potfile");
        cmd.arg("--potfile-path").arg(&potfile_path);
        cmd.arg("--restore-disable");

        // Output file
        cmd.arg("-o").arg(&config.outfile_path);
        cmd.arg("--outfile-format=3");

        // Custom charsets (-1, -2, -3, -4)
        if let Some(charsets) = &config.custom_charsets {
            for (i, cs) in charsets.iter().enumerate() {
                cmd.arg(format!("-{}", i + 1)).arg(cs);
            }
        }

        // Extra user-supplied arguments
        for arg in &config.extra_args {
            cmd.arg(arg);
        }

        // Set working directory to hashcat's folder so it can find kernels/modules
        if let Some(parent) = Path::new(&config.hashcat_path).parent() {
            if !parent.as_os_str().is_empty() {
                cmd.current_dir(parent);
            }
        }

        // Pipe stdout so we can parse status JSON; inherit stderr for error visibility
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        info!(
            hashcat = %config.hashcat_path,
            hash_mode = config.hash_mode,
            mask = %config.mask,
            skip = config.skip,
            limit = config.limit,
            "starting hashcat process"
        );

        let child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn hashcat at '{}'", config.hashcat_path))?;

        Ok(Self {
            child,
            outfile_path: config.outfile_path.clone(),
        })
    }

    /// Monitor the running hashcat process, sending events through the channel.
    ///
    /// This reads stdout line-by-line for JSON status updates and watches the
    /// outfile for newly cracked hashes.  Returns when the process exits.
    pub async fn monitor(&mut self, tx: mpsc::Sender<RunnerEvent>) -> anyhow::Result<i32> {
        let stdout = self
            .child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("hashcat stdout not captured"))?;

        let stderr = self
            .child
            .stderr
            .take()
            .ok_or_else(|| anyhow!("hashcat stderr not captured"))?;

        let outfile = self.outfile_path.clone();
        let tx_outfile = tx.clone();
        let tx_stderr = tx.clone();

        // Spawn a task to watch the outfile for new cracked hashes
        let outfile_handle = tokio::spawn(async move {
            watch_outfile(&outfile, tx_outfile).await;
        });

        // Spawn a task to capture stderr
        let stderr_handle = tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim_end_matches('\r').to_string();
                if !line.is_empty() {
                    warn!(stderr = %line, "hashcat stderr");
                    // Check for fatal errors
                    if line.contains("No hashes loaded")
                        || line.contains("Hashfile")
                        || line.contains("ERROR")
                    {
                        let _ = tx_stderr
                            .send(RunnerEvent::Failed {
                                error: line.clone(),
                            })
                            .await;
                    }
                }
            }
        });

        // Read stdout for status JSON
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        while let Ok(Some(line)) = lines.next_line().await {
            let line = line.trim_end_matches('\r').to_string();
            if line.is_empty() {
                continue;
            }

            if let Some(hc_status) = status::parse_status_line(&line) {
                let speed = hc_status.total_speed();
                let progress_pct = hc_status.progress_pct();
                let est_remaining = match (&hc_status.estimated_stop, &hc_status.time_start) {
                    (Some(stop), Some(start)) if *stop > *start => {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(*stop);
                        Some(stop.saturating_sub(now))
                    }
                    _ => None,
                };

                let _ = tx
                    .send(RunnerEvent::StatusUpdate {
                        progress_pct,
                        speed,
                        est_remaining,
                    })
                    .await;
            } else if let Some((hash, plaintext)) = status::parse_outfile_line(&line) {
                // hashcat prints cracked hashes to stdout as "hash:plaintext"
                info!(hash = %hash, "hash cracked (stdout)");
                let _ = tx
                    .send(RunnerEvent::HashCracked { hash, plaintext })
                    .await;
            } else {
                debug!(line = %line, "hashcat stdout (non-JSON)");
            }
        }

        // Wait for hashcat to exit
        let exit_status = self
            .child
            .wait()
            .await
            .context("failed to wait for hashcat process")?;

        let code = exit_status.code().unwrap_or(-1);

        // Stop the background watchers
        outfile_handle.abort();
        stderr_handle.abort();

        // Final read of the outfile to catch any cracked hashes the watcher missed.
        // The watcher polls every 2s, but hashcat can complete faster than that.
        info!(
            outfile = %self.outfile_path.display(),
            exit_code = code,
            "reading outfile after hashcat exit"
        );
        match tokio::fs::read_to_string(&self.outfile_path).await {
            Ok(contents) => {
                info!(
                    outfile = %self.outfile_path.display(),
                    size = contents.len(),
                    lines = contents.lines().count(),
                    "outfile contents read"
                );
                if contents.is_empty() {
                    info!("outfile is empty (no cracked hashes)");
                }
                for line in contents.lines() {
                    info!(raw_line = %line, "outfile line");
                    if let Some((hash, plaintext)) = status::parse_outfile_line(line) {
                        info!(hash = %hash, plaintext = %plaintext, "hash cracked (final outfile read)");
                        let _ = tx
                            .send(RunnerEvent::HashCracked { hash, plaintext })
                            .await;
                    } else {
                        warn!(line = %line, "outfile line could not be parsed");
                    }
                }
            }
            Err(e) => {
                info!(
                    outfile = %self.outfile_path.display(),
                    error = %e,
                    "outfile does not exist or could not be read"
                );
            }
        }

        // Hashcat exit codes:
        //   0 = cracked / exhausted successfully
        //   1 = exhausted (no hashes cracked)
        //  -1 = error
        //  -2 = aborted by user
        match code {
            0 | 1 => {
                info!(exit_code = code, "hashcat completed");
                let _ = tx.send(RunnerEvent::Completed { exit_code: code }).await;
            }
            _ => {
                warn!(exit_code = code, "hashcat exited with error");
                let _ = tx
                    .send(RunnerEvent::Failed {
                        error: format!("hashcat exited with code {code}"),
                    })
                    .await;
            }
        }

        Ok(code)
    }

    /// Kill the hashcat process (e.g. on AbortChunk).
    pub async fn kill(&mut self) -> anyhow::Result<()> {
        info!("killing hashcat process");
        self.child.kill().await.context("failed to kill hashcat")?;
        Ok(())
    }
}

/// Watch an outfile for newly appended lines (cracked hashes).
///
/// This polls the file periodically.  Each new line in format `hash:plaintext`
/// is sent through the channel.
async fn watch_outfile(path: &Path, tx: mpsc::Sender<RunnerEvent>) {
    use tokio::fs;
    use tokio::time::{interval, Duration};

    let mut tick = interval(Duration::from_secs(2));
    let mut last_size: u64 = 0;

    loop {
        tick.tick().await;

        let meta = match fs::metadata(path).await {
            Ok(m) => m,
            Err(_) => continue, // file doesn't exist yet
        };

        let size = meta.len();
        if size <= last_size {
            continue;
        }

        // Read the new portion
        match fs::read_to_string(path).await {
            Ok(contents) => {
                // We need to skip bytes we already processed
                let new_data = if last_size as usize <= contents.len() {
                    &contents[last_size as usize..]
                } else {
                    &contents
                };

                for line in new_data.lines() {
                    if let Some((hash, plaintext)) = status::parse_outfile_line(line) {
                        info!(hash = %hash, "hash cracked!");
                        if tx
                            .send(RunnerEvent::HashCracked { hash, plaintext })
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "failed to read outfile");
            }
        }

        last_size = size;
    }
}
