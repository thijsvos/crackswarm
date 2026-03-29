use std::path::Path;

use anyhow::{bail, Context};
use crack_common::models::AttackConfig;
use tracing::info;

use crate::storage::files;

/// Compute the total keyspace for an attack configuration.
///
/// Calls `hashcat --keyspace` to get the exact base keyspace (restore points)
/// that hashcat uses for `--skip`/`--limit`. This accounts for hashcat's
/// optimizer which may merge multiple trailing mask positions into the
/// amplifier, resulting in a smaller base keyspace than a naive calculation.
pub async fn compute_keyspace(
    hashcat_path: &str,
    hash_mode: u32,
    attack_config: &AttackConfig,
    files_dir: &Path,
) -> anyhow::Result<u64> {
    match attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => {
            let keyspace = compute_keyspace_via_hashcat(
                hashcat_path,
                hash_mode,
                mask,
                custom_charsets.as_deref(),
            )
            .await?;
            info!(mask = %mask, keyspace, "computed base keyspace via hashcat --keyspace");
            Ok(keyspace)
        }
        AttackConfig::Dictionary { wordlist_file_id } => {
            let wordlist_path = files::resolve_file_path(files_dir, wordlist_file_id)?;
            let keyspace = compute_dictionary_keyspace(
                hashcat_path,
                hash_mode,
                &wordlist_path.to_string_lossy(),
                None,
            )
            .await?;
            info!(wordlist = %wordlist_file_id, keyspace, "computed dictionary keyspace via hashcat --keyspace");
            Ok(keyspace)
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            let wordlist_path = files::resolve_file_path(files_dir, wordlist_file_id)?;
            let rules_path = files::resolve_file_path(files_dir, rules_file_id)?;
            let keyspace = compute_dictionary_keyspace(
                hashcat_path,
                hash_mode,
                &wordlist_path.to_string_lossy(),
                Some(&rules_path.to_string_lossy()),
            )
            .await?;
            info!(wordlist = %wordlist_file_id, rules = %rules_file_id, keyspace, "computed dictionary+rules keyspace via hashcat --keyspace");
            Ok(keyspace)
        }
    }
}

/// Run `hashcat --keyspace` for a dictionary attack (mode 0).
async fn compute_dictionary_keyspace(
    hashcat_path: &str,
    hash_mode: u32,
    wordlist_path: &str,
    rules_path: Option<&str>,
) -> anyhow::Result<u64> {
    let mut cmd = tokio::process::Command::new(hashcat_path);
    cmd.arg("-a").arg("0");
    cmd.arg("-m").arg(hash_mode.to_string());
    cmd.arg("--keyspace");
    cmd.arg(wordlist_path);

    if let Some(rules) = rules_path {
        cmd.arg("-r").arg(rules);
    }

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to run hashcat --keyspace (dict) at '{hashcat_path}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "hashcat --keyspace (dict) failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let keyspace: u64 = stdout.trim().parse().with_context(|| {
        format!(
            "failed to parse hashcat --keyspace output: '{}'",
            stdout.trim()
        )
    })?;

    Ok(keyspace)
}

/// Run `hashcat --keyspace` to get the exact restore-point count.
async fn compute_keyspace_via_hashcat(
    hashcat_path: &str,
    hash_mode: u32,
    mask: &str,
    custom_charsets: Option<&[String]>,
) -> anyhow::Result<u64> {
    let mut cmd = tokio::process::Command::new(hashcat_path);
    cmd.arg("-a").arg("3");
    cmd.arg("-m").arg(hash_mode.to_string());
    cmd.arg("--keyspace");
    cmd.arg(mask);

    if let Some(charsets) = custom_charsets {
        for (i, cs) in charsets.iter().enumerate() {
            cmd.arg(format!("-{}", i + 1)).arg(cs);
        }
    }

    let output = cmd
        .output()
        .await
        .with_context(|| format!("failed to run hashcat --keyspace at '{hashcat_path}'"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "hashcat --keyspace failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            stderr.trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let keyspace: u64 = stdout.trim().parse().with_context(|| {
        format!(
            "failed to parse hashcat --keyspace output: '{}'",
            stdout.trim()
        )
    })?;

    Ok(keyspace)
}

/// Compute the base keyspace (restore points) for a hashcat brute-force mask.
///
/// hashcat splits the mask into base positions and an amplifier (last position).
/// `--keyspace` reports the base = product of all charset sizes except the last.
/// `--skip` and `--limit` operate on this base keyspace.
///
/// Built-in charsets:
///   ?l = 26 (lowercase), ?u = 26 (uppercase), ?d = 10 (digits),
///   ?s = 33 (special), ?a = 95 (all printable), ?b = 256 (all bytes),
///   ?h = 16 (hex lower), ?H = 16 (hex upper)
///
/// Custom charsets ?1..?4 are defined via the custom_charsets parameter.
#[allow(dead_code)]
fn compute_mask_keyspace(mask: &str, custom_charsets: Option<&[String]>) -> anyhow::Result<u64> {
    // First, collect all the charset sizes for each mask position
    let mut position_sizes: Vec<u64> = Vec::new();
    let chars: Vec<char> = mask.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            let charset_size = match chars[i + 1] {
                'l' => 26,  // abcdefghijklmnopqrstuvwxyz
                'u' => 26,  // ABCDEFGHIJKLMNOPQRSTUVWXYZ
                'd' => 10,  // 0123456789
                's' => 33,  // «space»!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
                'a' => 95,  // ?l?u?d?s
                'b' => 256, // 0x00 - 0xff
                'h' => 16,  // 0123456789abcdef
                'H' => 16,  // 0123456789ABCDEF
                '1' | '2' | '3' | '4' => {
                    let idx = (chars[i + 1] as u8 - b'1') as usize;
                    custom_charset_size(idx, custom_charsets)?
                }
                '?' => {
                    // Literal '?' character (escaped as ??)
                    i += 2;
                    continue;
                }
                other => {
                    bail!("unknown charset specifier '?{other}' in mask");
                }
            };
            position_sizes.push(charset_size);
            i += 2;
        } else {
            // Literal character — exactly 1 candidate for this position
            position_sizes.push(1);
            i += 1;
        }
    }

    if position_sizes.is_empty() {
        return Ok(0);
    }

    // Base keyspace = product of all positions EXCEPT the last one (amplifier).
    // This matches what hashcat --keyspace reports and what --skip/--limit use.
    let base_positions = &position_sizes[..position_sizes.len() - 1];
    let mut keyspace: u64 = 1;
    for &size in base_positions {
        keyspace = keyspace
            .checked_mul(size)
            .ok_or_else(|| anyhow::anyhow!("keyspace overflow for mask '{mask}'"))?;
    }

    Ok(keyspace)
}

/// Compute the size of a custom charset (?1..?4).
///
/// Custom charsets can reference built-in charsets (e.g., "?l?d" = 36 chars)
/// or list literal characters (e.g., "abc" = 3 chars).
#[allow(dead_code)]
fn custom_charset_size(idx: usize, custom_charsets: Option<&[String]>) -> anyhow::Result<u64> {
    let charsets = custom_charsets
        .ok_or_else(|| anyhow::anyhow!("mask uses ?{} but no custom charsets defined", idx + 1))?;
    let cs = charsets.get(idx).ok_or_else(|| {
        anyhow::anyhow!(
            "mask uses ?{} but only {} custom charsets defined",
            idx + 1,
            charsets.len()
        )
    })?;

    let mut size: u64 = 0;
    let chars: Vec<char> = cs.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' && i + 1 < chars.len() {
            size += match chars[i + 1] {
                'l' => 26,
                'u' => 26,
                'd' => 10,
                's' => 33,
                'a' => 95,
                'b' => 256,
                'h' => 16,
                'H' => 16,
                '?' => 1,
                other => bail!("unknown charset specifier '?{other}' in custom charset"),
            };
            i += 2;
        } else {
            size += 1;
            i += 1;
        }
    }

    Ok(size)
}

/// Calculate how large each chunk should be for a given worker.
///
/// Strategy:
/// - If the worker has a known benchmark speed, target 10 minutes of work per chunk:
///   `worker_speed * 600`.
/// - Otherwise, divide the keyspace evenly across workers with a 4x multiplier for
///   granularity: `total_keyspace / (num_workers * 4)`.
/// - The result is clamped to `[10_000, total_keyspace]`.
/// - Additionally, when the speed-based chunk exceeds the remaining keyspace divided
///   by the number of workers, we cap it to ensure all workers get a share.
pub fn calculate_chunk_size(
    worker_speed: Option<u64>,
    total_keyspace: u64,
    num_workers: usize,
) -> u64 {
    const MIN_CHUNK: u64 = 10_000;

    let raw = if let Some(speed) = worker_speed {
        speed.saturating_mul(600)
    } else {
        total_keyspace / (num_workers.max(1) as u64 * 4)
    };

    // When multiple workers are available, cap the chunk so each worker gets
    // a fair share of the remaining keyspace rather than one worker consuming
    // it all in a single chunk.
    let fair_share = total_keyspace / num_workers.max(1) as u64;
    let raw = if num_workers > 1 && raw > fair_share && fair_share >= MIN_CHUNK {
        fair_share
    } else {
        raw
    };

    // Clamp: at least MIN_CHUNK but never exceed total_keyspace.
    // When total_keyspace < MIN_CHUNK, just use total_keyspace.
    let min = MIN_CHUNK.min(total_keyspace);
    raw.clamp(min, total_keyspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: compute_mask_keyspace is kept as a helper but is no longer
    // used in production. The real keyspace is obtained via hashcat --keyspace.
    // These tests verify the math helper still works for simple cases.

    #[test]
    fn keyspace_lowercase_5() {
        // ?l?l?l?l?l: our helper gives 26^4, hashcat also gives 26^4
        let ks = compute_mask_keyspace("?l?l?l?l?l", None).unwrap();
        assert_eq!(ks, 26u64.pow(4));
    }

    #[test]
    fn keyspace_lowercase_3() {
        let ks = compute_mask_keyspace("?l?l?l", None).unwrap();
        assert_eq!(ks, 26u64.pow(2));
    }

    #[test]
    fn keyspace_lowercase_2() {
        let ks = compute_mask_keyspace("?l?l", None).unwrap();
        assert_eq!(ks, 26);
    }

    #[test]
    fn keyspace_mixed() {
        let ks = compute_mask_keyspace("?u?l?d", None).unwrap();
        assert_eq!(ks, 26 * 26);
    }

    #[test]
    fn keyspace_all_printable_4() {
        // ?a?a?a?a: helper gives 95^3, hashcat also gives 95^3
        let ks = compute_mask_keyspace("?a?a?a?a", None).unwrap();
        assert_eq!(ks, 95u64.pow(3));
    }

    #[test]
    fn keyspace_with_literal() {
        let ks = compute_mask_keyspace("abc?d", None).unwrap();
        assert_eq!(ks, 1);
    }

    #[test]
    fn keyspace_custom_charset() {
        let charsets = vec!["?l?d".to_string()];
        let ks = compute_mask_keyspace("?1?1", Some(&charsets)).unwrap();
        assert_eq!(ks, 36);
    }

    #[test]
    fn keyspace_escaped_question_mark() {
        let ks = compute_mask_keyspace("???d", None).unwrap();
        assert_eq!(ks, 1);
    }

    #[test]
    fn keyspace_single_position() {
        let ks = compute_mask_keyspace("?l", None).unwrap();
        assert_eq!(ks, 1);
    }

    #[test]
    fn chunk_size_with_speed() {
        // 1 million hashes/sec * 600 = 600 million
        // total_keyspace = 10B, 4 workers → fair_share = 2.5B > 600M, so speed wins
        let size = calculate_chunk_size(Some(1_000_000), 10_000_000_000, 4);
        assert_eq!(size, 600_000_000);
    }

    #[test]
    fn chunk_size_fair_share_caps_fast_worker() {
        // Speed-based: 15 GH/s * 600 = 9 trillion — way more than total keyspace
        // With 2 workers, fair_share = 50M, which is >= MIN_CHUNK
        // So chunk should be 50M, not 100M
        let size = calculate_chunk_size(Some(15_000_000_000), 100_000_000, 2);
        assert_eq!(size, 50_000_000);
    }

    #[test]
    fn chunk_size_fair_share_not_applied_single_worker() {
        // With only 1 worker, fair_share logic doesn't kick in
        let size = calculate_chunk_size(Some(15_000_000_000), 100_000_000, 1);
        assert_eq!(size, 100_000_000);
    }

    #[test]
    fn chunk_size_fair_share_too_small_skipped() {
        // fair_share = 2500, below MIN_CHUNK, so we fall back to normal clamping
        let size = calculate_chunk_size(Some(1_000_000), 5_000, 2);
        assert_eq!(size, 5_000);
    }

    #[test]
    fn chunk_size_without_speed() {
        // 1_000_000 / (4 * 4) = 62_500
        let size = calculate_chunk_size(None, 1_000_000, 4);
        assert_eq!(size, 62_500);
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
        // 1_000_000 / (1 * 4) = 250_000
        assert_eq!(size, 250_000);
    }

    #[test]
    fn chunk_size_small_keyspace_no_speed() {
        // total_keyspace smaller than MIN_CHUNK: result is total_keyspace
        let size = calculate_chunk_size(None, 5_000, 10);
        // 5_000 / (10 * 4) = 125, min = min(10_000, 5_000) = 5_000
        // clamp(125, 5_000, 5_000) = 5_000
        assert_eq!(size, 5_000);
    }

    #[test]
    fn chunk_size_exact_boundary() {
        // Exactly 10_000 total keyspace, no speed, 1 worker
        // 10_000 / (1 * 4) = 2_500, clamp(10_000, 10_000) = 10_000
        let size = calculate_chunk_size(None, 10_000, 1);
        assert_eq!(size, 10_000);
    }
}
