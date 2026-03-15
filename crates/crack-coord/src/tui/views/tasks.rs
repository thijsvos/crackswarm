use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::tui::app::TuiState;
use crate::tui::theme::{status_color, Theme};
use crack_common::models::{AttackConfig, ChunkStatus};

/// Render the task list in the left panel.
pub fn render_task_list(f: &mut Frame, area: Rect, state: &TuiState) {
    let items: Vec<ListItem> = state
        .tasks
        .iter()
        .map(|task| {
            let status_str = task.status.to_string();
            let color = status_color(&status_str);
            let progress = if task.total_hashes > 0 {
                format!("{}/{}", task.cracked_count, task.total_hashes)
            } else {
                "-".to_string()
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", if state.tasks.get(state.task_list_index).map(|t| t.id) == Some(task.id) { "▶" } else { " " }),
                    Style::default().fg(Theme::BLUE),
                ),
                Span::styled(&task.name, Style::default().fg(Theme::TEXT)),
                Span::raw("  "),
                Span::styled(progress, Style::default().fg(Theme::SUBTEXT0)),
                Span::raw("  "),
                Span::styled(status_str, Style::default().fg(color)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Tasks ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1)),
        )
        .highlight_style(Style::default().bg(Theme::SURFACE0).add_modifier(Modifier::BOLD));

    let mut list_state = ListState::default();
    list_state.select(Some(state.task_list_index));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Render task detail in the right panel (mut for chunk scroll state).
pub fn render_task_detail(f: &mut Frame, area: Rect, state: &mut TuiState) {
    let task = match state.selected_task() {
        Some(t) => t,
        None => {
            let block = Block::default()
                .title(" Task Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1));
            let p = Paragraph::new("No task selected")
                .style(Style::default().fg(Theme::SUBTEXT0))
                .block(block);
            f.render_widget(p, area);
            return;
        }
    };

    let status_str = task.status.to_string();
    let attack_str = match &task.attack_config {
        AttackConfig::BruteForce { mask, .. } => format!("Brute Force: {mask}"),
    };

    let progress_pct = if let Some(ks) = task.total_keyspace {
        if ks > 0 {
            (task.next_skip as f64 / ks as f64).min(1.0)
        } else {
            0.0
        }
    } else {
        0.0
    };

    // Compute aggregate speed from running chunks
    let task_chunks: Vec<_> = state
        .chunks
        .iter()
        .filter(|c| c.task_id == task.id)
        .collect();
    let total_speed: u64 = task_chunks
        .iter()
        .filter(|c| c.status == ChunkStatus::Running)
        .map(|c| c.speed)
        .sum();

    let active_workers = task_chunks
        .iter()
        .filter(|c| c.status == ChunkStatus::Running)
        .filter_map(|c| c.assigned_worker.as_ref())
        .collect::<std::collections::HashSet<_>>()
        .len();

    // Compute ETA
    let eta_str = if task.status == crack_common::models::TaskStatus::Completed {
        "done".to_string()
    } else if total_speed == 0 {
        "calculating...".to_string()
    } else if let Some(ks) = task.total_keyspace {
        let remaining = ks.saturating_sub(task.next_skip);
        if remaining == 0 {
            "done".to_string()
        } else {
            let secs = remaining / total_speed;
            format_eta(secs)
        }
    } else {
        "unknown".to_string()
    };

    let lines = vec![
        Line::from(vec![
            Span::styled("  Hash Mode:  ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(format!("{}", task.hash_mode), Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Attack:     ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(&attack_str, Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Status:     ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(&status_str, Style::default().fg(status_color(&status_str))),
        ]),
        Line::from(vec![
            Span::styled("  Cracked:    ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                format!("{} / {} hashes", task.cracked_count, task.total_hashes),
                Style::default().fg(Theme::GREEN),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Speed:      ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                format!("{} ({} workers)", format_speed(total_speed), active_workers),
                Style::default().fg(Theme::PEACH),
            ),
        ]),
        Line::from(vec![
            Span::styled("  ETA:        ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(&eta_str, Style::default().fg(Theme::YELLOW)),
        ]),
        Line::from(vec![
            Span::styled("  Keyspace:   ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                format!(
                    "{} / {}",
                    format_count(task.next_skip),
                    task.total_keyspace.map_or("-".to_string(), format_count)
                ),
                Style::default().fg(Theme::TEXT),
            ),
        ]),
        Line::default(),
    ];

    let block = Block::default()
        .title(format!(" {} ", task.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::SURFACE1));

    // Split right panel: info top, progress bar, chunks table bottom
    let chunks_layout = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            Constraint::Length(lines.len() as u16 + 2),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);

    let info = Paragraph::new(lines).block(block);
    f.render_widget(info, chunks_layout[0]);

    // Progress gauge
    let gauge = Gauge::default()
        .block(
            Block::default()
                .title(" Progress ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1)),
        )
        .gauge_style(Style::default().fg(Theme::BLUE).bg(Theme::SURFACE0))
        .percent((progress_pct * 100.0) as u16)
        .label(format!("{:.1}%", progress_pct * 100.0));
    f.render_widget(gauge, chunks_layout[1]);

    // Chunks table
    let chunk_rows: Vec<Row> = task_chunks
        .iter()
        .map(|chunk| {
            let chunk_status = chunk.status.to_string();
            let is_terminal = matches!(
                chunk.status,
                ChunkStatus::Completed | ChunkStatus::Exhausted | ChunkStatus::Failed | ChunkStatus::Abandoned
            );
            let worker = chunk
                .assigned_worker
                .as_deref()
                .unwrap_or("-")
                .chars()
                .take(8)
                .collect::<String>();
            let speed_str = if chunk.speed > 0 {
                format_speed(chunk.speed)
            } else if is_terminal {
                "-".to_string()
            } else {
                "0 H/s".to_string()
            };
            Row::new(vec![
                chunk.id.to_string()[..8].to_string(),
                worker,
                format!("{:.0}%", chunk.progress),
                speed_str,
                chunk_status,
            ])
            .style(Style::default().fg(Theme::TEXT))
        })
        .collect();

    let chunk_table = Table::new(
        chunk_rows,
        [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(vec!["Chunk", "Worker", "Progress", "Speed", "Status"])
            .style(Style::default().fg(Theme::MAUVE).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(format!(" Chunks ({}) ", task_chunks.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SURFACE1)),
    )
    .row_highlight_style(Style::default().bg(Theme::SURFACE0));

    // Clamp scroll offset
    let max_offset = task_chunks.len().saturating_sub(1);
    if state.chunk_scroll_offset > max_offset {
        state.chunk_scroll_offset = max_offset;
    }

    let mut table_state = TableState::default();
    table_state.select(Some(state.chunk_scroll_offset));
    f.render_stateful_widget(chunk_table, chunks_layout[2], &mut table_state);
}

fn format_speed(hps: u64) -> String {
    if hps >= 1_000_000_000 {
        format!("{:.1} GH/s", hps as f64 / 1_000_000_000.0)
    } else if hps >= 1_000_000 {
        format!("{:.1} MH/s", hps as f64 / 1_000_000.0)
    } else if hps >= 1_000 {
        format!("{:.1} KH/s", hps as f64 / 1_000.0)
    } else {
        format!("{hps} H/s")
    }
}

fn format_eta(total_secs: u64) -> String {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m {secs}s")
    } else if mins > 0 {
        format!("{mins}m {secs}s")
    } else {
        format!("{secs}s")
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000_000_000 {
        format!("{:.1}T", n as f64 / 1_000_000_000_000.0)
    } else if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}
