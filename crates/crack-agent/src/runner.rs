use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    pub attack_mode: u32,
    pub mask: Option<String>,
    pub skip: u64,
    pub limit: u64,
    pub custom_charsets: Option<Vec<String>>,
    pub wordlist_path: Option<PathBuf>,
    pub rules_path: Option<PathBuf>,
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

        // Attack mode
        cmd.arg("-a").arg(config.attack_mode.to_string());

        // Hash mode
        cmd.arg("-m").arg(config.hash_mode.to_string());

        // Hash file
        cmd.arg(&config.hash_file_path);

        // Attack-specific positional argument
        match config.attack_mode {
            0 => {
                // Dictionary: wordlist is the positional argument
                if let Some(ref wl) = config.wordlist_path {
                    cmd.arg(wl);
                }
                // Optional rules file
                if let Some(ref rules) = config.rules_path {
                    cmd.arg("-r").arg(rules);
                }
            }
            3 => {
                // Brute-force: mask is the positional argument
                if let Some(ref mask) = config.mask {
                    cmd.arg(mask);
                }
            }
            _ => {}
        }

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
        // hashcat 7.x uses comma-separated format values (not bitmask like 6.x).
        // 1 = hash, 2 = plain → "hash<sep>plain" output.
        cmd.arg("--outfile-format=1,2");
        // Use tab separator to avoid ambiguity with hashes or plaintexts that
        // contain colons (the default separator).
        cmd.arg("--separator").arg("\t");

        // Custom charsets (-1, -2, -3, -4)
        if let Some(charsets) = &config.custom_charsets {
            for (i, cs) in charsets.iter().enumerate() {
                cmd.arg(format!("-{}", i + 1)).arg(cs);
            }
        }

        // Extra user-supplied arguments (filtered for safety)
        for arg in &config.extra_args {
            if is_dangerous_arg(arg) {
                warn!(arg = %arg, "rejecting dangerous extra_arg");
                continue;
            }
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
            attack_mode = config.attack_mode,
            mask = ?config.mask,
            wordlist = ?config.wordlist_path,
            rules = ?config.rules_path,
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

        // Cracked hashes can arrive via stdout, the polling outfile
        // watcher, or the final post-exit sweep. The dedup set funnels
        // all three through one "have we already reported this?" check.
        let seen = CrackedHashDedup::new();

        // Concurrent helpers: outfile poller and stderr line drainer.
        let outfile_handle = {
            let outfile = self.outfile_path.clone();
            let tx = tx.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                watch_outfile(&outfile, tx, seen.into_arc()).await;
            })
        };
        let stderr_handle = tokio::spawn(drain_stderr_for_fatal(stderr, tx.clone()));

        // Drive stdout on this task — parses status JSON + reports cracks
        // hashcat prints to stdout. Returns when stdout EOFs (process exit).
        monitor_stdout(stdout, &tx, &seen).await;

        // Reap hashcat.
        let exit_status = self
            .child
            .wait()
            .await
            .context("failed to wait for hashcat process")?;
        let code = exit_status.code().unwrap_or(-1);

        // Stop helpers and reconcile the outfile one last time before
        // cleanup wipes it. The poller runs every 2s; hashcat can finish
        // in less than that, so a final sweep catches the tail of cracks.
        outfile_handle.abort();
        stderr_handle.abort();
        final_outfile_sweep(&self.outfile_path, &tx, &seen, code).await;

        self.cleanup_temp_files().await;
        report_exit(code, &tx).await;
        Ok(code)
    }

    /// Kill the hashcat process (e.g. on AbortChunk).
    pub async fn kill(&mut self) -> anyhow::Result<()> {
        info!("killing hashcat process");
        self.child.kill().await.context("failed to kill hashcat")?;
        self.cleanup_temp_files().await;
        Ok(())
    }

    /// Remove temporary outfile and potfile created for this chunk.
    async fn cleanup_temp_files(&self) {
        // Remove outfile (out_<chunk_id>.txt)
        if let Err(e) = tokio::fs::remove_file(&self.outfile_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(path = %self.outfile_path.display(), error = %e, "failed to remove outfile");
            }
        }
        // Remove potfile (out_<chunk_id>.potfile)
        let potfile_path = self.outfile_path.with_extension("potfile");
        if let Err(e) = tokio::fs::remove_file(&potfile_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                debug!(path = %potfile_path.display(), error = %e, "failed to remove potfile");
            }
        }
    }
}

/// Reject extra_args that could interfere with orchestration or write to
/// arbitrary paths.
fn is_dangerous_arg(arg: &str) -> bool {
    const BLOCKED_PREFIXES: &[&str] = &[
        "-o",
        "--outfile",
        "--potfile",
        "--session",
        "--remove",
        "--restore",
        "--keyspace",
        "--stdout",
        "--separator",
    ];
    let lower = arg.to_ascii_lowercase();
    BLOCKED_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Watch an outfile for newly appended lines (cracked hashes).
///
/// This polls the file periodically.  Each new line in format `hash\tplaintext`
/// is sent through the channel.  Uses raw bytes + lossy conversion to avoid
/// panicking on non-UTF-8 outfile content.
async fn watch_outfile(
    path: &Path,
    tx: mpsc::Sender<RunnerEvent>,
    seen: Arc<Mutex<HashSet<String>>>,
) {
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

        // Read the file as raw bytes to avoid UTF-8 panics
        match fs::read(path).await {
            Ok(bytes) => {
                // Skip bytes we already processed
                let new_bytes = if (last_size as usize) <= bytes.len() {
                    &bytes[last_size as usize..]
                } else {
                    &bytes
                };

                let new_data = String::from_utf8_lossy(new_bytes);

                for line in new_data.lines() {
                    if let Some((hash, plaintext)) = status::parse_outfile_line(line) {
                        let is_new = seen.lock().unwrap().insert(hash.clone());
                        if is_new {
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
            }
            Err(e) => {
                error!(error = %e, "failed to read outfile");
            }
        }

        last_size = size;
    }
}

// ── Internal helpers for `HashcatRunner::monitor` ────────────────────────────

/// Funnel for "have we already reported this hash?" across the three
/// channels that emit cracks (stdout, outfile poller, final sweep).
/// Cheap-to-clone wrapper around `Arc<Mutex<HashSet<String>>>`.
#[derive(Clone)]
struct CrackedHashDedup {
    inner: Arc<Mutex<HashSet<String>>>,
}

impl CrackedHashDedup {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Returns true if this is the first time we've seen `hash`.
    fn record(&self, hash: &str) -> bool {
        self.inner.lock().unwrap().insert(hash.to_string())
    }

    /// Hand off to the polling outfile watcher, which still uses the
    /// raw `Arc<Mutex<HashSet<String>>>` form.
    fn into_arc(self) -> Arc<Mutex<HashSet<String>>> {
        self.inner
    }
}

/// Read hashcat's stdout line-by-line. Each line is either:
/// - a `--status-json` payload → forward as `StatusUpdate`
/// - a `hash\tplaintext` outfile line (hashcat occasionally double-prints
///   to stdout) → forward as `HashCracked` if not already seen
/// - free-form info/progress text → debug-log and drop
///
/// Returns when stdout EOFs, which happens when the child exits.
async fn monitor_stdout(
    stdout: tokio::process::ChildStdout,
    tx: &mpsc::Sender<RunnerEvent>,
    seen: &CrackedHashDedup,
) {
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
            // hashcat occasionally writes the outfile-format line to
            // stdout. Filter out info noise (spaces / ellipses / too-short
            // hash-side bytes) before treating as a crack.
            let is_info_line = hash.contains(' ') || hash.contains("...") || hash.len() < 16;
            if !is_info_line && seen.record(&hash) {
                info!(hash = %hash, "hash cracked (stdout)");
                let _ = tx.send(RunnerEvent::HashCracked { hash, plaintext }).await;
            }
        } else {
            debug!(line = %line, "hashcat stdout (non-JSON)");
        }
    }
}

/// Drain hashcat's stderr line-by-line. Lines containing fatal markers
/// (`No hashes loaded`, `Hashfile`, `ERROR`) emit a `Failed` event so
/// the runner short-circuits the dispatch instead of silently exiting.
async fn drain_stderr_for_fatal(
    stderr: tokio::process::ChildStderr,
    tx: mpsc::Sender<RunnerEvent>,
) {
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim_end_matches('\r').to_string();
        if line.is_empty() {
            continue;
        }
        warn!(stderr = %line, "hashcat stderr");
        if line.contains("No hashes loaded")
            || line.contains("Hashfile")
            || line.contains("ERROR")
        {
            let _ = tx
                .send(RunnerEvent::Failed {
                    error: line.clone(),
                })
                .await;
        }
    }
}

/// Race catch-up after hashcat exits. The outfile poller runs every 2 s,
/// so a sub-second hashcat run can land cracks the poller never observed;
/// reading the outfile once more before cleanup picks them up.
///
/// A missing outfile on `exit_code = 1` (exhausted, nothing cracked) is
/// the expected case and logged at debug.
async fn final_outfile_sweep(
    path: &Path,
    tx: &mpsc::Sender<RunnerEvent>,
    seen: &CrackedHashDedup,
    exit_code: i32,
) {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let contents = String::from_utf8_lossy(&bytes);
            for line in contents.lines() {
                if let Some((hash, plaintext)) = status::parse_outfile_line(line) {
                    if seen.record(&hash) {
                        // Plaintext deliberately omitted from agent INFO logs —
                        // see runner::HashcatRunner::monitor; coord persists
                        // them in the access-controlled cracked_hashes table.
                        info!(hash = %hash, "hash cracked (final outfile read)");
                        let _ = tx.send(RunnerEvent::HashCracked { hash, plaintext }).await;
                    }
                }
            }
        }
        Err(_) if exit_code == 1 => {
            debug!(outfile = %path.display(), "no outfile (exhausted)");
        }
        Err(e) => {
            warn!(outfile = %path.display(), error = %e, "outfile could not be read");
        }
    }
}

/// Translate a hashcat exit code into the corresponding `RunnerEvent`.
///
/// Exit codes:
///   0 = cracked / exhausted successfully
///   1 = exhausted (no hashes cracked)
///  -1 = error
///  -2 = aborted by user
async fn report_exit(code: i32, tx: &mpsc::Sender<RunnerEvent>) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_outfile() {
        assert!(is_dangerous_arg("-o"));
        assert!(is_dangerous_arg("-o/tmp/evil"));
    }

    #[test]
    fn dangerous_outfile_long() {
        assert!(is_dangerous_arg("--outfile"));
        assert!(is_dangerous_arg("--outfile=/tmp"));
    }

    #[test]
    fn dangerous_potfile() {
        assert!(is_dangerous_arg("--potfile-path"));
    }

    #[test]
    fn dangerous_session() {
        assert!(is_dangerous_arg("--session=test"));
    }

    #[test]
    fn dangerous_remove() {
        assert!(is_dangerous_arg("--remove"));
        assert!(is_dangerous_arg("--remove-timer=5"));
    }

    #[test]
    fn dangerous_restore() {
        assert!(is_dangerous_arg("--restore"));
    }

    #[test]
    fn dangerous_keyspace() {
        assert!(is_dangerous_arg("--keyspace"));
    }

    #[test]
    fn dangerous_stdout() {
        assert!(is_dangerous_arg("--stdout"));
    }

    #[test]
    fn dangerous_separator() {
        assert!(is_dangerous_arg("--separator"));
    }

    #[test]
    fn dangerous_case_insensitive() {
        assert!(is_dangerous_arg("--OUTFILE"));
        assert!(is_dangerous_arg("--Potfile-Path"));
    }

    #[test]
    fn safe_args_pass() {
        assert!(!is_dangerous_arg("--force"));
        assert!(!is_dangerous_arg("-w3"));
        assert!(!is_dangerous_arg("--optimized-kernel-enable"));
        assert!(!is_dangerous_arg("-r"));
        assert!(!is_dangerous_arg("--increment"));
    }

    #[test]
    fn empty_arg_is_safe() {
        assert!(!is_dangerous_arg(""));
    }
}
