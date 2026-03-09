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
            Row::new(vec![
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
            Constraint::Percentage(35),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
        ],
    )
    .header(
        Row::new(vec!["Hash", "Plaintext", "Worker", "Cracked At"])
            .style(
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
