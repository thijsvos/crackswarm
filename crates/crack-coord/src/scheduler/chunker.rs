use anyhow::{bail, Context};
use crack_common::models::AttackConfig;
use tokio::process::Command;
use tracing::debug;

/// Run `hashcat --keyspace` to compute the total keyspace for an attack configuration.
///
/// For brute-force attacks this invokes:
///   `hashcat --keyspace -a 3 -m <hash_mode> [-1 cs1] [-2 cs2] ... '<mask>'`
///
/// Returns the keyspace as a `u64`.
pub async fn compute_keyspace(
    hashcat_path: &str,
    hash_mode: u32,
    attack_config: &AttackConfig,
) -> anyhow::Result<u64> {
    match attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => {
            let mut cmd = Command::new(hashcat_path);
            cmd.arg("--keyspace")
                .arg("-a")
                .arg("3")
                .arg("-m")
                .arg(hash_mode.to_string());

            // Add custom charset arguments (-1, -2, -3, -4) if provided.
            if let Some(charsets) = custom_charsets {
                for (i, cs) in charsets.iter().enumerate() {
                    if i >= 4 {
                        break; // hashcat supports at most 4 custom charsets
                    }
                    cmd.arg(format!("-{}", i + 1)).arg(cs);
                }
            }

            cmd.arg(mask);

            debug!(?cmd, "computing keyspace");

            let output = cmd
                .output()
                .await
                .context("failed to execute hashcat for keyspace computation")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                bail!(
                    "hashcat --keyspace exited with {}: {}",
                    output.status,
                    stderr.trim()
                );
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let keyspace: u64 = stdout
                .trim()
                .parse()
                .with_context(|| format!("failed to parse keyspace from hashcat output: {stdout:?}"))?;

            Ok(keyspace)
        }
    }
}

/// Calculate how large each chunk should be for a given worker.
///
/// Strategy:
/// - If the worker has a known benchmark speed, target 10 minutes of work per chunk:
///   `worker_speed * 600`.
/// - Otherwise, divide the keyspace evenly across workers with a 20x multiplier for
///   granularity: `total_keyspace / (num_workers * 20)`.
/// - The result is clamped to `[10_000, total_keyspace]`.
pub fn calculate_chunk_size(
    worker_speed: Option<u64>,
    total_keyspace: u64,
    num_workers: usize,
) -> u64 {
    const MIN_CHUNK: u64 = 10_000;

    let raw = if let Some(speed) = worker_speed {
        speed.saturating_mul(600)
    } else {
        total_keyspace / (num_workers.max(1) as u64 * 20)
    };

    // Clamp: at least MIN_CHUNK but never exceed total_keyspace.
    // When total_keyspace < MIN_CHUNK, just use total_keyspace.
    let min = MIN_CHUNK.min(total_keyspace);
    raw.clamp(min, total_keyspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_size_with_speed() {
        // 1 million hashes/sec * 600 = 600 million
        let size = calculate_chunk_size(Some(1_000_000), 10_000_000_000, 4);
        assert_eq!(size, 600_000_000);
    }

    #[test]
    fn chunk_size_without_speed() {
        // 1_000_000 / (4 * 20) = 12_500
        let size = calculate_chunk_size(None, 1_000_000, 4);
        assert_eq!(size, 12_500);
    }

    #[test]
    fn chunk_size_clamp_min() {
        // Speed is very low: 1 * 600 = 600, should clamp to 10_000
        let size = calculate_chunk_size(Some(1), 1_000_000, 1);
        assert_eq!(size, 10_000);
    }

    #[test]
    fn chunk_size_clamp_max() {
        // Speed is enormous: overflows 600 * huge, but saturating_mul keeps it in range,
        // then clamp to total_keyspace
        let size = calculate_chunk_size(Some(u64::MAX), 1_000_000, 1);
        assert_eq!(size, 1_000_000);
    }

    #[test]
    fn chunk_size_zero_workers_no_speed() {
        // num_workers = 0, should be treated as 1 via max(1)
        let size = calculate_chunk_size(None, 1_000_000, 0);
        // 1_000_000 / (1 * 20) = 50_000
        assert_eq!(size, 50_000);
    }

    #[test]
    fn chunk_size_small_keyspace_no_speed() {
        // total_keyspace smaller than MIN_CHUNK: result is total_keyspace
        let size = calculate_chunk_size(None, 5_000, 10);
        // 5_000 / (10 * 20) = 25, min = min(10_000, 5_000) = 5_000
        // clamp(25, 5_000, 5_000) = 5_000
        assert_eq!(size, 5_000);
    }

    #[test]
    fn chunk_size_exact_boundary() {
        // Exactly 10_000 total keyspace, no speed, 1 worker
        // 10_000 / (1 * 20) = 500, clamp(10_000, 10_000) = 10_000
        let size = calculate_chunk_size(None, 10_000, 1);
        assert_eq!(size, 10_000);
    }
}
