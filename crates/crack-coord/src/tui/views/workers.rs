use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::tui::app::TuiState;
use crate::tui::theme::{status_color, status_icon, Theme};

/// Render the worker list in the left panel.
pub fn render_worker_list(f: &mut Frame, area: Rect, state: &TuiState) {
    let items: Vec<ListItem> = state
        .workers
        .iter()
        .map(|worker| {
            let status_str = worker.status.to_string();
            let icon = status_icon(&status_str);
            let color = status_color(&status_str);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {icon} "), Style::default().fg(color)),
                Span::styled(worker.name.clone(), Style::default().fg(Theme::TEXT)),
                Span::raw("  "),
                Span::styled(status_str, Style::default().fg(color)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(format!(" Workers ({}) ", state.workers.len()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1)),
        )
        .highlight_style(
            Style::default()
                .bg(Theme::SURFACE0)
                .add_modifier(Modifier::BOLD),
        );

    let mut list_state = ListState::default();
    list_state.select(Some(state.worker_list_index));

    f.render_stateful_widget(list, area, &mut list_state);
}

/// Render worker detail in the right panel.
pub fn render_worker_detail(f: &mut Frame, area: Rect, state: &TuiState) {
    let worker = match state.selected_worker() {
        Some(w) => w,
        None => {
            let block = Block::default()
                .title(" Worker Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1));
            let p = Paragraph::new("No worker selected")
                .style(Style::default().fg(Theme::SUBTEXT0))
                .block(block);
            f.render_widget(p, area);
            return;
        }
    };

    let status_str = worker.status.to_string();
    let _devices_str = if worker.devices.is_empty() {
        "None detected".to_string()
    } else {
        worker
            .devices
            .iter()
            .map(|d| format!("  {} ({})", d.name, d.device_type))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let elapsed = chrono::Utc::now() - worker.last_seen_at;
    let last_seen = if elapsed.num_seconds() < 60 {
        format!("{}s ago", elapsed.num_seconds())
    } else if elapsed.num_minutes() < 60 {
        format!("{}m ago", elapsed.num_minutes())
    } else {
        format!("{}h ago", elapsed.num_hours())
    };

    let cache_summary = state
        .cache_summary
        .get(&worker.id)
        .copied()
        .unwrap_or((0, 0));
    let cache_str = format!(
        "{} files, {}",
        cache_summary.0,
        format_bytes(cache_summary.1)
    );

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  ID:           ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(&worker.id, Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Status:       ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                format!("{} {}", status_icon(&status_str), &status_str),
                Style::default().fg(status_color(&status_str)),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Last Seen:    ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(last_seen, Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  OS:           ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                worker.os.as_deref().unwrap_or("unknown"),
                Style::default().fg(Theme::TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Hashcat:      ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(
                worker.hashcat_version.as_deref().unwrap_or("unknown"),
                Style::default().fg(Theme::TEXT),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Cache:        ", Style::default().fg(Theme::SUBTEXT0)),
            Span::styled(cache_str, Style::default().fg(Theme::TEXT)),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "  Devices:",
            Style::default().fg(Theme::SUBTEXT0),
        )),
    ];

    for device in &worker.devices {
        lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(&device.name, Style::default().fg(Theme::TEAL)),
            Span::styled(
                format!(" ({})", device.device_type),
                Style::default().fg(Theme::SUBTEXT0),
            ),
        ]));
    }

    let block = Block::default()
        .title(format!(" {} ", worker.name))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::SURFACE1));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

/// Render `bytes` in IEC units (KiB / MiB / GiB / TiB) with one decimal
/// place. Negative values clamp to "0 B" — they shouldn't happen, but the
/// underlying SUM(...) i64 leaves the door open and we'd rather not panic
/// inside the render path.
fn format_bytes(bytes: i64) -> String {
    if bytes <= 0 {
        return "0 B".to_string();
    }
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} B", bytes)
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
