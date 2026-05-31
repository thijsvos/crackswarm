//! Results tab: renders recently cracked hashes across all tasks.

use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Row, Table, TableState},
    Frame,
};

use crate::tui::app::TuiState;
use crate::tui::theme::Theme;

/// Render the cracked results table.
pub fn render_results(f: &mut Frame, area: Rect, state: &TuiState) {
    // Index tasks by id once so the per-result name lookup is O(1), not
    // O(tasks) — the table was previously O(results * tasks) per render.
    let task_by_id: std::collections::HashMap<_, _> =
        state.tasks.iter().map(|t| (t.id, t)).collect();
    let rows: Vec<Row> = state
        .results
        .iter()
        .map(|r| {
            let hash_display = if r.hash.len() > 32 {
                format!("{}...", &r.hash[..32])
            } else {
                r.hash.clone()
            };
            let time = r.cracked_at.format("%Y-%m-%d %H:%M").to_string();
            let task_name = task_by_id
                .get(&r.task_id)
                .map(|t| {
                    // Truncate by characters, not bytes — byte-slicing a name
                    // with multi-byte UTF-8 at the cut point panics.
                    if t.name.chars().count() > 16 {
                        format!("{}...", t.name.chars().take(13).collect::<String>())
                    } else {
                        t.name.clone()
                    }
                })
                .unwrap_or_else(|| r.task_id.to_string()[..8].to_string());
            Row::new(vec![
                task_name,
                hash_display,
                r.plaintext.clone(),
                r.worker_id.chars().take(8).collect::<String>(),
                time,
            ])
            .style(Style::default().fg(Theme::TEXT))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Percentage(15),
            Constraint::Percentage(30),
            Constraint::Percentage(20),
            Constraint::Percentage(12),
            Constraint::Percentage(23),
        ],
    )
    .header(
        Row::new(vec!["Task", "Hash", "Plaintext", "Worker", "Cracked At"]).style(
            Style::default()
                .fg(Theme::MAUVE)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(format!(" Results ({}) ", state.results.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SURFACE1)),
    )
    .row_highlight_style(Style::default().bg(Theme::SURFACE0));

    let mut table_state = TableState::default();
    table_state.select(Some(state.result_list_index));

    f.render_stateful_widget(table, area, &mut table_state);
}
