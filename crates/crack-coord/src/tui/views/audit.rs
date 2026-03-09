use ratatui::{
    layout::{Constraint, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Row, Table, TableState},
    Frame,
};

use crate::tui::app::TuiState;
use crate::tui::theme::Theme;

/// Render the audit log table.
pub fn render_audit_log(f: &mut Frame, area: Rect, state: &TuiState) {
    let rows: Vec<Row> = state
        .audit_entries
        .iter()
        .map(|entry| {
            let time = entry.created_at.format("%Y-%m-%d %H:%M:%S").to_string();
            let worker = entry
                .worker_id
                .as_deref()
                .map(|w| w.chars().take(8).collect::<String>())
                .unwrap_or_else(|| "-".to_string());
            Row::new(vec![
                time,
                entry.event_type.clone(),
                worker,
                entry.details.clone(),
            ])
            .style(Style::default().fg(Theme::TEXT))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Min(30),
        ],
    )
    .header(
        Row::new(vec!["Time", "Event", "Worker", "Details"])
            .style(
                Style::default()
                    .fg(Theme::MAUVE)
                    .add_modifier(Modifier::BOLD),
            ),
    )
    .block(
        Block::default()
            .title(format!(" Audit Log ({}) ", state.audit_entries.len()))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Theme::SURFACE1)),
    )
    .row_highlight_style(Style::default().bg(Theme::SURFACE0));

    let mut table_state = TableState::default();
    table_state.select(Some(state.audit_list_index));

    f.render_stateful_widget(table, area, &mut table_state);
}
