use anyhow::bail;
use crack_common::models::AttackConfig;
use tracing::info;

/// Compute the total keyspace for an attack configuration.
///
/// For brute-force masks, computes mathematically from the mask charset sizes.
/// This avoids depending on a local hashcat installation on the coordinator
/// (which may have platform-specific bugs, e.g. macOS Homebrew hashcat
/// returns wrong keyspace values).
pub async fn compute_keyspace(
    _hashcat_path: &str,
    _hash_mode: u32,
    attack_config: &AttackConfig,
) -> anyhow::Result<u64> {
    match attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => {
            let keyspace = compute_mask_keyspace(mask, custom_charsets.as_deref())?;
            info!(mask = %mask, keyspace, "computed keyspace from mask");
            Ok(keyspace)
        }
    }
}

/// Compute keyspace for a hashcat brute-force mask by multiplying charset sizes.
///
/// Built-in charsets:
///   ?l = 26 (lowercase), ?u = 26 (uppercase), ?d = 10 (digits),
///   ?s = 33 (special), ?a = 95 (all printable), ?b = 256 (all bytes),
///   ?h = 16 (hex lower), ?H = 16 (hex upper)
///
/// Custom charsets ?1..?4 are defined via the custom_charsets parameter.
fn compute_mask_keyspace(mask: &str, custom_charsets: Option<&[String]>) -> anyhow::Result<u64> {
    let mut keyspace: u64 = 1;
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
                    // A literal char = 1 candidate, doesn't multiply keyspace
                    continue;
                }
                other => {
                    bail!("unknown charset specifier '?{other}' in mask");
                }
            };
            keyspace = keyspace
                .checked_mul(charset_size)
                .ok_or_else(|| anyhow::anyhow!("keyspace overflow for mask '{mask}'"))?;
            i += 2;
        } else {
            // Literal character — exactly 1 candidate for this position
            i += 1;
        }
    }

    Ok(keyspace)
}

/// Compute the size of a custom charset (?1..?4).
///
/// Custom charsets can reference built-in charsets (e.g., "?l?d" = 36 chars)
/// or list literal characters (e.g., "abc" = 3 chars).
fn custom_charset_size(idx: usize, custom_charsets: Option<&[String]>) -> anyhow::Result<u64> {
    let charsets = custom_charsets
        .ok_or_else(|| anyhow::anyhow!("mask uses ?{} but no custom charsets defined", idx + 1))?;
    let cs = charsets
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("mask uses ?{} but only {} custom charsets defined", idx + 1, charsets.len()))?;

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
    fn keyspace_lowercase_5() {
        // ?l?l?l?l?l = 26^5
        let ks = compute_mask_keyspace("?l?l?l?l?l", None).unwrap();
        assert_eq!(ks, 26u64.pow(5));
    }

    #[test]
    fn keyspace_mixed() {
        // ?u?l?d = 26 * 26 * 10
        let ks = compute_mask_keyspace("?u?l?d", None).unwrap();
        assert_eq!(ks, 26 * 26 * 10);
    }

    #[test]
    fn keyspace_all_printable() {
        // ?a?a?a?a = 95^4
        let ks = compute_mask_keyspace("?a?a?a?a", None).unwrap();
        assert_eq!(ks, 95u64.pow(4));
    }

    #[test]
    fn keyspace_with_literal() {
        // abc?d = 1*1*1*10 = 10
        let ks = compute_mask_keyspace("abc?d", None).unwrap();
        assert_eq!(ks, 10);
    }

    #[test]
    fn keyspace_custom_charset() {
        // ?1?1 with charset 1 = "?l?d" (36 chars) = 36^2
        let charsets = vec!["?l?d".to_string()];
        let ks = compute_mask_keyspace("?1?1", Some(&charsets)).unwrap();
        assert_eq!(ks, 36 * 36);
    }

    #[test]
    fn keyspace_escaped_question_mark() {
        // ?? is a literal '?', so "???d" = 1 literal '?' + 10 digits = 10
        let ks = compute_mask_keyspace("???d", None).unwrap();
        assert_eq!(ks, 10);
    }

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
