use std::collections::{HashMap, HashSet};

use crack_common::models::CrackedHash;

// ── Config ──

pub struct AnalyzerConfig {
    pub min_sample_size: u32,
    pub max_skeletons_to_analyze: usize,
    pub min_skeleton_count: u32,
    pub charset_coverage_pct: f64,
    pub max_keyspace: u64,
    pub max_masks_to_generate: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            max_skeletons_to_analyze: 50,
            min_skeleton_count: 3,
            charset_coverage_pct: 0.90,
            max_keyspace: 100_000_000_000_000, // 10^14
            max_masks_to_generate: 20,
        }
    }
}

// ── Result types ──

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub masks: Vec<GeneratedMask>,
    pub summary: AnalysisSummary,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct GeneratedMask {
    pub mask: String,
    pub custom_charsets: Option<Vec<String>>,
    pub score: f64,
    pub source: MaskSource,
    pub estimated_keyspace: u64,
}

#[derive(Debug, Clone)]
pub enum MaskSource {
    DirectSkeleton,
    CustomCharset,
    LengthVariant,
    SuffixAnchored,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AnalysisSummary {
    pub total_passwords: usize,
    pub unique_skeletons: usize,
    pub masks_generated: usize,
}

// ── Skeleton ──

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Skeleton(String);

impl Skeleton {
    fn from_plaintext(s: &str) -> Self {
        let mut skel = String::with_capacity(s.len());
        for ch in s.chars() {
            if ch.is_ascii_uppercase() {
                skel.push('U');
            } else if ch.is_ascii_lowercase() {
                skel.push('L');
            } else if ch.is_ascii_digit() {
                skel.push('D');
            } else {
                skel.push('S');
            }
        }
        Skeleton(skel)
    }

    fn to_mask(&self) -> String {
        let mut mask = String::with_capacity(self.0.len() * 2);
        for ch in self.0.chars() {
            match ch {
                'U' => mask.push_str("?u"),
                'L' => mask.push_str("?l"),
                'D' => mask.push_str("?d"),
                'S' => mask.push_str("?s"),
                _ => mask.push_str("?a"),
            }
        }
        mask
    }

    fn keyspace(&self) -> u64 {
        let mut ks: u64 = 1;
        for ch in self.0.chars() {
            let size: u64 = match ch {
                'U' => 26,
                'L' => 26,
                'D' => 10,
                'S' => 33,
                _ => 95,
            };
            ks = ks.saturating_mul(size);
        }
        ks
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

// ── Position analysis ──

struct PositionStats {
    chars: HashMap<char, u32>,
    total: u32,
}

impl PositionStats {
    fn new() -> Self {
        Self {
            chars: HashMap::new(),
            total: 0,
        }
    }

    fn record(&mut self, ch: char) {
        *self.chars.entry(ch).or_insert(0) += 1;
        self.total += 1;
    }

    /// Check if a small subset of chars covers `threshold` fraction of occurrences.
    /// Returns the subset if so.
    fn dominant_subset(&self, threshold: f64) -> Option<String> {
        if self.total == 0 {
            return None;
        }

        let mut sorted: Vec<(char, u32)> = self.chars.iter().map(|(&c, &n)| (c, n)).collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        let mut coverage = 0u32;
        let needed = (self.total as f64 * threshold) as u32;
        let mut subset = Vec::new();

        for (ch, count) in &sorted {
            coverage += count;
            subset.push(*ch);
            if coverage >= needed {
                break;
            }
        }

        // Only worthwhile if subset is significantly smaller than the full charset class
        if subset.len() <= 12 && subset.len() < self.chars.len() {
            let mut s: Vec<char> = subset;
            s.sort();
            Some(s.into_iter().collect())
        } else {
            None
        }
    }
}

// ── Public API ──

pub fn analyze(
    passwords: &[CrackedHash],
    already_run: &HashSet<String>,
    config: &AnalyzerConfig,
) -> AnalysisResult {
    let plaintexts: Vec<&str> = passwords.iter().map(|p| p.plaintext.as_str()).collect();

    if (plaintexts.len() as u32) < config.min_sample_size {
        return AnalysisResult {
            masks: Vec::new(),
            summary: AnalysisSummary {
                total_passwords: plaintexts.len(),
                unique_skeletons: 0,
                masks_generated: 0,
            },
        };
    }

    // Pass 1: skeleton frequency
    let mut skeleton_counts: HashMap<Skeleton, u32> = HashMap::new();
    for &pw in &plaintexts {
        let skel = Skeleton::from_plaintext(pw);
        *skeleton_counts.entry(skel).or_insert(0) += 1;
    }

    let unique_skeletons = skeleton_counts.len();

    // Sort by frequency descending
    let mut ranked: Vec<(Skeleton, u32)> = skeleton_counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1));

    // Filter: minimum count threshold
    ranked.retain(|(_, count)| *count >= config.min_skeleton_count);
    ranked.truncate(config.max_skeletons_to_analyze);

    let total = plaintexts.len() as f64;
    let mut all_masks: Vec<GeneratedMask> = Vec::new();

    // Phase A: Direct skeleton masks
    for (skel, count) in &ranked {
        let mask = skel.to_mask();
        if already_run.contains(&mask) {
            continue;
        }
        let ks = skel.keyspace();
        if ks > config.max_keyspace || ks == 0 {
            continue;
        }
        let freq_pct = *count as f64 / total;
        let score = freq_pct / (ks as f64).log2().max(1.0);
        all_masks.push(GeneratedMask {
            mask,
            custom_charsets: None,
            score,
            source: MaskSource::DirectSkeleton,
            estimated_keyspace: ks,
        });
    }

    // Pass 2: Position-level analysis for top skeletons (Phase B)
    for (skel, _count) in ranked.iter().take(20) {
        let mut positions: Vec<PositionStats> =
            (0..skel.len()).map(|_| PositionStats::new()).collect();

        for &pw in &plaintexts {
            let pw_skel = Skeleton::from_plaintext(pw);
            if pw_skel != *skel {
                continue;
            }
            for (i, ch) in pw.chars().enumerate() {
                if i < positions.len() {
                    positions[i].record(ch);
                }
            }
        }

        // Try to build custom charset masks (up to 4 custom charsets)
        let mut custom_defs: Vec<String> = Vec::new();
        let mut custom_mask = String::new();
        let mut custom_ks: u64 = 1;
        let mut has_narrowing = false;

        for (i, pos) in positions.iter().enumerate() {
            if custom_defs.len() >= 4 {
                // Already used all 4 custom charset slots; use skeleton class
                let class_char = skel.0.chars().nth(i).unwrap_or('L');
                let (token, size) = class_to_mask_token(class_char);
                custom_mask.push_str(token);
                custom_ks = custom_ks.saturating_mul(size);
                continue;
            }

            if let Some(subset) = pos.dominant_subset(config.charset_coverage_pct) {
                let class_char = skel.0.chars().nth(i).unwrap_or('L');
                let class_size = class_size(class_char);
                if (subset.len() as u64) < class_size {
                    // Worth narrowing
                    let slot = custom_defs.len() + 1;
                    custom_mask.push_str(&format!("?{slot}"));
                    custom_ks = custom_ks.saturating_mul(subset.len() as u64);
                    custom_defs.push(subset);
                    has_narrowing = true;
                    continue;
                }
            }

            let class_char = skel.0.chars().nth(i).unwrap_or('L');
            let (token, size) = class_to_mask_token(class_char);
            custom_mask.push_str(token);
            custom_ks = custom_ks.saturating_mul(size);
        }

        if has_narrowing
            && !already_run.contains(&custom_mask)
            && custom_ks <= config.max_keyspace
            && custom_ks > 0
        {
            let base_skel_ks = skel.keyspace();
            let reduction = if base_skel_ks > 0 {
                1.0 - (custom_ks as f64 / base_skel_ks as f64)
            } else {
                0.0
            };
            let freq_pct = *_count as f64 / total;
            let score = freq_pct / (custom_ks as f64).log2().max(1.0) * (1.0 + reduction);

            all_masks.push(GeneratedMask {
                mask: custom_mask,
                custom_charsets: Some(custom_defs),
                score,
                source: MaskSource::CustomCharset,
                estimated_keyspace: custom_ks,
            });
        }
    }

    // Phase C: Length variants (extend longest run by +-1)
    for (skel, count) in ranked.iter().take(10) {
        let freq_pct = *count as f64 / total;
        for delta in [-1i32, 1, 2] {
            if let Some(variant) = length_variant(skel, delta) {
                let mask = variant.to_mask();
                if already_run.contains(&mask) {
                    continue;
                }
                let ks = variant.keyspace();
                if ks > config.max_keyspace || ks == 0 {
                    continue;
                }
                let score = freq_pct / (ks as f64).log2().max(1.0) * 0.5;
                all_masks.push(GeneratedMask {
                    mask,
                    custom_charsets: None,
                    score,
                    source: MaskSource::LengthVariant,
                    estimated_keyspace: ks,
                });
            }
        }
    }

    // Phase D: Suffix-anchored masks
    let mut suffix_counts: HashMap<String, u32> = HashMap::new();
    for &pw in &plaintexts {
        for suffix_len in 1..=4.min(pw.len()) {
            let suffix = &pw[pw.len() - suffix_len..];
            *suffix_counts.entry(suffix.to_string()).or_insert(0) += 1;
        }
    }

    let mut suffix_ranked: Vec<(String, u32)> = suffix_counts.into_iter().collect();
    suffix_ranked.sort_by(|a, b| b.1.cmp(&a.1));

    for (suffix, count) in suffix_ranked.iter().take(10) {
        if *count < config.min_skeleton_count {
            break;
        }
        // Build mask: ?a * N + literal suffix chars
        for prefix_len in 4..=8 {
            let mut mask = "?a".repeat(prefix_len);
            for ch in suffix.chars() {
                if ch == '?' {
                    mask.push_str("??");
                } else {
                    mask.push(ch);
                }
            }
            if already_run.contains(&mask) {
                continue;
            }
            let ks = 95u64.saturating_pow(prefix_len as u32);
            if ks > config.max_keyspace {
                continue;
            }
            let freq_pct = *count as f64 / total;
            let score = freq_pct / (ks as f64).log2().max(1.0) * 0.3;
            all_masks.push(GeneratedMask {
                mask,
                custom_charsets: None,
                score,
                source: MaskSource::SuffixAnchored,
                estimated_keyspace: ks,
            });
        }
    }

    // Deduplicate and rank
    let mut seen = HashSet::new();
    all_masks.retain(|m| seen.insert(m.mask.clone()));
    all_masks.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    all_masks.truncate(config.max_masks_to_generate);

    let masks_generated = all_masks.len();

    AnalysisResult {
        masks: all_masks,
        summary: AnalysisSummary {
            total_passwords: plaintexts.len(),
            unique_skeletons,
            masks_generated,
        },
    }
}

// ── Helpers ──

fn class_to_mask_token(class_char: char) -> (&'static str, u64) {
    match class_char {
        'U' => ("?u", 26),
        'L' => ("?l", 26),
        'D' => ("?d", 10),
        'S' => ("?s", 33),
        _ => ("?a", 95),
    }
}

fn class_size(class_char: char) -> u64 {
    match class_char {
        'U' => 26,
        'L' => 26,
        'D' => 10,
        'S' => 33,
        _ => 95,
    }
}

/// Generate a length variant of a skeleton by extending/shrinking the longest
/// consecutive run of the same class.
fn length_variant(skel: &Skeleton, delta: i32) -> Option<Skeleton> {
    if skel.0.is_empty() {
        return None;
    }

    // Find the longest consecutive run
    let chars: Vec<char> = skel.0.chars().collect();
    let mut best_start = 0;
    let mut best_len = 1;
    let mut cur_start = 0;
    let mut cur_len = 1;

    for i in 1..chars.len() {
        if chars[i] == chars[i - 1] {
            cur_len += 1;
        } else {
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_start = i;
            cur_len = 1;
        }
    }
    if cur_len > best_len {
        best_start = cur_start;
        best_len = cur_len;
    }

    let new_len = (best_len as i32 + delta) as usize;
    if new_len == 0 || new_len > 20 {
        return None;
    }

    let run_char = chars[best_start];
    let mut result = String::new();
    result.push_str(&skel.0[..best_start]);
    for _ in 0..new_len {
        result.push(run_char);
    }
    let after = best_start + best_len;
    if after < skel.0.len() {
        result.push_str(&skel.0[after..]);
    }

    Some(Skeleton(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_cracked(plaintext: &str) -> CrackedHash {
        CrackedHash {
            id: None,
            task_id: Uuid::new_v4(),
            hash: format!("hash_{plaintext}"),
            plaintext: plaintext.to_string(),
            worker_id: "test".to_string(),
            cracked_at: Utc::now(),
        }
    }

    #[test]
    fn test_skeleton_from_plaintext() {
        assert_eq!(Skeleton::from_plaintext("Password1!").0, "ULLLLLLLDS");
        assert_eq!(Skeleton::from_plaintext("qwerty123").0, "LLLLLLDDD");
        assert_eq!(Skeleton::from_plaintext("ABC").0, "UUU");
        assert_eq!(Skeleton::from_plaintext("123").0, "DDD");
        assert_eq!(Skeleton::from_plaintext("!@#").0, "SSS");
    }

    #[test]
    fn test_skeleton_to_mask() {
        let skel = Skeleton::from_plaintext("Password1!");
        assert_eq!(skel.to_mask(), "?u?l?l?l?l?l?l?l?d?s");
    }

    #[test]
    fn test_skeleton_keyspace() {
        let skel = Skeleton("LLD".to_string());
        assert_eq!(skel.keyspace(), 26 * 26 * 10);
    }

    #[test]
    fn test_analyze_empty() {
        let config = AnalyzerConfig::default();
        let result = analyze(&[], &HashSet::new(), &config);
        assert!(result.masks.is_empty());
        assert_eq!(result.summary.total_passwords, 0);
    }

    #[test]
    fn test_analyze_below_min_sample() {
        let passwords: Vec<CrackedHash> = (0..5).map(|i| make_cracked(&format!("pw{i}"))).collect();
        let config = AnalyzerConfig {
            min_sample_size: 10,
            ..Default::default()
        };
        let result = analyze(&passwords, &HashSet::new(), &config);
        assert!(result.masks.is_empty());
    }

    #[test]
    fn test_analyze_generates_masks() {
        let mut passwords = Vec::new();
        // Create a clear pattern: uppercase + lowercase * 5 + digits * 2
        for _ in 0..20 {
            passwords.push(make_cracked("Passwd12"));
        }
        for _ in 0..15 {
            passwords.push(make_cracked("Summer24"));
        }
        for _ in 0..10 {
            passwords.push(make_cracked("Winter99"));
        }

        let config = AnalyzerConfig {
            min_sample_size: 5,
            min_skeleton_count: 3,
            ..Default::default()
        };

        let result = analyze(&passwords, &HashSet::new(), &config);
        assert!(!result.masks.is_empty());
        assert!(result.summary.masks_generated > 0);

        // The top mask should be for ULLLLLDD pattern
        let top = &result.masks[0];
        assert!(
            top.mask.contains("?u") && top.mask.contains("?l") && top.mask.contains("?d"),
            "top mask should contain ?u, ?l, ?d: {}",
            top.mask
        );
    }

    #[test]
    fn test_analyze_filters_already_run() {
        let mut passwords = Vec::new();
        for _ in 0..20 {
            passwords.push(make_cracked("Test1234"));
        }

        let mut already_run = HashSet::new();
        already_run.insert("?u?l?l?l?d?d?d?d".to_string());

        let config = AnalyzerConfig {
            min_sample_size: 5,
            min_skeleton_count: 3,
            ..Default::default()
        };

        let result = analyze(&passwords, &already_run, &config);
        // The direct skeleton mask should be filtered out
        assert!(
            !result.masks.iter().any(|m| m.mask == "?u?l?l?l?d?d?d?d"),
            "already-run mask should be filtered"
        );
    }

    #[test]
    fn test_length_variant() {
        let skel = Skeleton("ULLLDD".to_string());
        let longer = length_variant(&skel, 1).unwrap();
        assert_eq!(longer.0, "ULLLLDD");

        let shorter = length_variant(&skel, -1).unwrap();
        assert_eq!(shorter.0, "ULLDD");
    }
}
