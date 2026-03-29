use chrono::{DateTime, Utc};
use crack_common::models::*;

use crate::client::{CampaignDetailResponse, PotfileStats};

// ── Helpers ──

/// Truncate a string to `max` bytes, appending "..." if truncated.
/// Ensures the truncation point falls on a valid UTF-8 char boundary.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = s
        .char_indices()
        .take_while(|(i, _)| *i + 3 < max)
        .last()
        .map(|(i, c)| i + c.len_utf8())
        .unwrap_or(0);
    format!("{}...", &s[..end])
}

/// First 8 characters of an ID (for UUID or other string IDs).
fn short_id(id: &str) -> &str {
    if id.len() >= 8 {
        &id[..8]
    } else {
        id
    }
}

/// Format bytes into human-readable size.
fn human_size(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let b = bytes as f64;
    if b >= GB {
        format!("{:.1} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Format a speed value (H/s) into human-readable form.
fn human_speed(speed: u64) -> String {
    if speed >= 1_000_000_000 {
        format!("{:.1} GH/s", speed as f64 / 1_000_000_000.0)
    } else if speed >= 1_000_000 {
        format!("{:.1} MH/s", speed as f64 / 1_000_000.0)
    } else if speed >= 1_000 {
        format!("{:.1} kH/s", speed as f64 / 1_000.0)
    } else {
        format!("{speed} H/s")
    }
}

/// Format a datetime for display (compact).
fn fmt_time(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M").to_string()
}

/// Format an optional datetime.
fn fmt_opt_time(dt: &Option<DateTime<Utc>>) -> String {
    match dt {
        Some(t) => fmt_time(t),
        None => "-".to_string(),
    }
}

/// Print a horizontal separator line.
fn separator(width: usize) {
    println!("{}", "\u{2500}".repeat(width));
}

// ── Tasks ──

pub fn print_tasks(tasks: &[Task]) {
    if tasks.is_empty() {
        println!("No tasks found.");
        return;
    }

    println!(
        "{:<38} {:<24} {:<10} {:<12} {:<14} {:<16}",
        "ID", "Name", "HashMode", "Status", "Progress", "Created"
    );
    separator(114);

    for task in tasks {
        let name = truncate(&task.name, 22);
        let progress = format!("{}/{}", task.cracked_count, task.total_hashes);

        println!(
            "{:<38} {:<24} {:<10} {:<12} {:<14} {:<16}",
            task.id,
            name,
            task.hash_mode,
            task.status,
            progress,
            fmt_time(&task.created_at),
        );
    }

    println!();
    println!("{} task(s) total", tasks.len());
}

pub fn print_task_detail(task: &Task, chunks: &[Chunk]) {
    println!("\u{2550}\u{2550}\u{2550} Task Detail \u{2550}\u{2550}\u{2550}");
    println!();
    println!("  ID:          {}", task.id);
    println!("  Name:        {}", task.name);
    println!("  Hash Mode:   {}", task.hash_mode);
    println!("  Status:      {}", task.status);
    println!("  Priority:    {}", task.priority);
    println!("  Hash File:   {}", task.hash_file_id);
    println!(
        "  Progress:    {}/{} cracked",
        task.cracked_count, task.total_hashes
    );

    match &task.attack_config {
        AttackConfig::BruteForce {
            mask,
            custom_charsets,
        } => {
            println!("  Attack:      brute-force");
            println!("  Mask:        {mask}");
            if let Some(charsets) = custom_charsets {
                for (i, cs) in charsets.iter().enumerate() {
                    println!("  Charset {}:   {cs}", i + 1);
                }
            }
        }
        AttackConfig::Dictionary { wordlist_file_id } => {
            println!("  Attack:      dictionary");
            println!("  Wordlist:    {wordlist_file_id}");
        }
        AttackConfig::DictionaryWithRules {
            wordlist_file_id,
            rules_file_id,
        } => {
            println!("  Attack:      dictionary + rules");
            println!("  Wordlist:    {wordlist_file_id}");
            println!("  Rules:       {rules_file_id}");
        }
    }

    if let Some(ks) = task.total_keyspace {
        println!("  Keyspace:    {ks}");
    }
    println!("  Next Skip:   {}", task.next_skip);

    if !task.extra_args.is_empty() {
        println!("  Extra Args:  {}", task.extra_args.join(" "));
    }

    println!("  Created:     {}", fmt_time(&task.created_at));
    println!("  Started:     {}", fmt_opt_time(&task.started_at));
    println!("  Completed:   {}", fmt_opt_time(&task.completed_at));

    // Chunks table
    println!();
    if chunks.is_empty() {
        println!("  No chunks yet.");
    } else {
        println!(
            "  {:<10} {:<12} {:<14} {:<14} {:<8} {:<12} {:<10}",
            "Chunk", "Status", "Skip", "Limit", "Prog%", "Speed", "Cracked"
        );
        separator(82);

        for chunk in chunks {
            let chunk_id_str = chunk.id.to_string();
            let id = short_id(&chunk_id_str);
            let progress = format!("{:.1}%", chunk.progress);
            let speed = human_speed(chunk.speed);

            println!(
                "  {:<10} {:<12} {:<14} {:<14} {:<8} {:<12} {:<10}",
                id, chunk.status, chunk.skip, chunk.limit, progress, speed, chunk.cracked_count,
            );
        }

        println!();
        println!("  {} chunk(s) total", chunks.len());
    }
}

// ── Workers ──

pub fn print_workers(workers: &[Worker]) {
    if workers.is_empty() {
        println!("No workers registered.");
        return;
    }

    println!(
        "{:<10} {:<20} {:<14} {:<8} {:<16}",
        "ID", "Name", "Status", "Devices", "Last Seen"
    );
    separator(68);

    for w in workers {
        let id = short_id(&w.id);
        let name = truncate(&w.name, 18);
        let devices = w.devices.len();

        println!(
            "{:<10} {:<20} {:<14} {:<8} {:<16}",
            id,
            name,
            w.status,
            devices,
            fmt_time(&w.last_seen_at),
        );
    }

    println!();
    println!("{} worker(s) total", workers.len());
}

// ── Results ──

pub fn print_results(results: &[CrackedHash]) {
    if results.is_empty() {
        println!("No cracked hashes found for this task.");
        return;
    }

    println!(
        "{:<40} {:<24} {:<10} {:<16}",
        "Hash", "Plaintext", "Worker", "Cracked At"
    );
    separator(90);

    for r in results {
        let hash = truncate(&r.hash, 38);
        let plaintext = truncate(&r.plaintext, 22);
        let worker = short_id(&r.worker_id);

        println!(
            "{:<40} {:<24} {:<10} {:<16}",
            hash,
            plaintext,
            worker,
            fmt_time(&r.cracked_at),
        );
    }

    println!();
    println!("{} result(s) total", results.len());
}

// ── Files ──

pub fn print_files(files: &[FileRecord]) {
    if files.is_empty() {
        println!("No files uploaded.");
        return;
    }

    println!(
        "{:<38} {:<28} {:<10} {:<10} {:<16}",
        "ID", "Filename", "Type", "Size", "Uploaded"
    );
    separator(102);

    for f in files {
        let filename = truncate(&f.filename, 26);
        let size = human_size(f.size_bytes);

        println!(
            "{:<38} {:<28} {:<10} {:<10} {:<16}",
            f.id,
            filename,
            f.file_type,
            size,
            fmt_time(&f.uploaded_at),
        );
    }

    println!();
    println!("{} file(s) total", files.len());
}

// ── Status ──

pub fn print_status(status: &SystemStatus) {
    println!("\u{2550}\u{2550}\u{2550} System Status \u{2550}\u{2550}\u{2550}");
    println!();
    println!(
        "  Tasks:            {} total, {} running",
        status.total_tasks, status.running_tasks
    );
    println!(
        "  Workers:          {} total, {} connected",
        status.total_workers, status.connected_workers
    );
    println!("  Total Cracked:    {}", status.total_cracked);
    println!(
        "  Aggregate Speed:  {}",
        human_speed(status.aggregate_speed)
    );
}

// ── Potfile ──

pub fn print_potfile_stats(stats: &PotfileStats) {
    println!("\u{2550}\u{2550}\u{2550} Potfile Statistics \u{2550}\u{2550}\u{2550}");
    println!();
    println!("  Total Cracked:      {}", stats.total_cracked);
    println!("  Unique Hashes:      {}", stats.unique_hashes);
    println!("  Unique Plaintexts:  {}", stats.unique_plaintexts);
}

// ── Campaigns ──

pub fn print_campaigns(campaigns: &[Campaign]) {
    if campaigns.is_empty() {
        println!("No campaigns found.");
        return;
    }

    println!(
        "{:<38} {:<24} {:<10} {:<12} {:<14} {:<8} {:<16}",
        "ID", "Name", "HashMode", "Status", "Progress", "Phase", "Created"
    );
    separator(122);

    for c in campaigns {
        let name = truncate(&c.name, 22);
        let progress = format!("{}/{}", c.cracked_count, c.total_hashes);
        let phase = c
            .active_phase_index
            .map(|i| format!("{}/{}", i + 1, c.total_phases))
            .unwrap_or_else(|| "-".to_string());

        println!(
            "{:<38} {:<24} {:<10} {:<12} {:<14} {:<8} {:<16}",
            c.id,
            name,
            c.hash_mode,
            c.status,
            progress,
            phase,
            fmt_time(&c.created_at),
        );
    }

    println!();
    println!("{} campaign(s) total", campaigns.len());
}

pub fn print_campaign_detail(detail: &CampaignDetailResponse) {
    let c = &detail.campaign;
    println!("\u{2550}\u{2550}\u{2550} Campaign Detail \u{2550}\u{2550}\u{2550}");
    println!();
    println!("  ID:          {}", c.id);
    println!("  Name:        {}", c.name);
    println!("  Hash Mode:   {}", c.hash_mode);
    println!("  Status:      {}", c.status);
    println!("  Priority:    {}", c.priority);
    println!("  Hash File:   {}", c.original_hash_file_id);
    println!(
        "  Progress:    {}/{} cracked",
        c.cracked_count, c.total_hashes
    );
    println!(
        "  Phase:       {}/{}",
        c.active_phase_index.map(|i| i + 1).unwrap_or(0),
        c.total_phases
    );
    if !c.extra_args.is_empty() {
        println!("  Extra Args:  {}", c.extra_args.join(" "));
    }
    println!("  Created:     {}", fmt_time(&c.created_at));
    println!("  Started:     {}", fmt_opt_time(&c.started_at));
    println!("  Completed:   {}", fmt_opt_time(&c.completed_at));

    // Phases table
    println!();
    if detail.phases.is_empty() {
        println!("  No phases defined.");
    } else {
        println!(
            "  {:<4} {:<24} {:<12} {:<10} {:<10} {:<38}",
            "#", "Name", "Status", "Cracked", "Type", "Task"
        );
        separator(100);

        for phase in &detail.phases {
            let phase_type = match &phase.config {
                PhaseConfig::StaticMask { .. } => "static",
                PhaseConfig::MultiMask { masks } => {
                    if masks.len() > 1 {
                        "multi"
                    } else {
                        "mask"
                    }
                }
                PhaseConfig::AutoGenerated { .. } => "auto",
                PhaseConfig::ExpandingBrute { .. } => "brute",
                PhaseConfig::Dictionary { .. } => "dict",
                PhaseConfig::Hybrid { .. } => "hybrid",
            };

            let task_id = phase
                .task_id
                .map(|id| short_id(&id.to_string()).to_string())
                .unwrap_or_else(|| "-".to_string());

            println!(
                "  {:<4} {:<24} {:<12} {:<10} {:<10} {:<38}",
                phase.phase_index + 1,
                truncate(&phase.name, 22),
                phase.status,
                phase.cracked_count,
                phase_type,
                task_id,
            );
        }

        println!();
        println!("  {} phase(s) total", detail.phases.len());
    }
}

pub fn print_templates(templates: &[CampaignTemplate]) {
    if templates.is_empty() {
        println!("No templates available.");
        return;
    }

    for t in templates {
        println!(
            "\u{2550}\u{2550}\u{2550} {} \u{2550}\u{2550}\u{2550}",
            t.name
        );
        println!("  {}", t.description);
        if let Some(mode) = t.hash_mode {
            println!("  Hash Mode: {mode}");
        } else {
            println!("  Hash Mode: any");
        }
        println!("  Phases: {}", t.phases.len());
        for (i, phase) in t.phases.iter().enumerate() {
            let phase_type = match &phase.config {
                PhaseConfig::StaticMask { mask, .. } => format!("mask: {mask}"),
                PhaseConfig::MultiMask { masks } => format!("{} masks", masks.len()),
                PhaseConfig::AutoGenerated { max_masks, .. } => {
                    format!("auto-generate up to {max_masks} masks")
                }
                PhaseConfig::ExpandingBrute {
                    charset,
                    min_length,
                    max_length,
                    ..
                } => {
                    format!("brute {charset} len {min_length}-{max_length}")
                }
                PhaseConfig::Dictionary { .. } => "dictionary".to_string(),
                PhaseConfig::Hybrid { .. } => "hybrid".to_string(),
            };
            println!("    {}. {} — {}", i + 1, phase.name, phase_type);
        }
        println!();
    }
}
