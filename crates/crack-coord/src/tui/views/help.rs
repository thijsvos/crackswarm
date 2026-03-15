use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

use crate::tui::theme::Theme;

/// Render the help overlay.
pub fn render_help(f: &mut Frame, area: Rect) {
    // Center the help popup
    let popup = centered_rect(65, 80, area);

    let help_text = vec![
        Line::from(Span::styled(
            " Keybindings",
            Style::default()
                .fg(Theme::MAUVE)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        section_header("Navigation"),
        help_line("j / ↓", "Move down"),
        help_line("k / ↑", "Move up"),
        help_line("g", "Go to top"),
        help_line("G", "Go to bottom"),
        help_line("Ctrl+d", "Page down"),
        help_line("Ctrl+u", "Page up"),
        Line::default(),
        section_header("Panels & Tabs"),
        help_line("Tab", "Switch panel focus"),
        help_line("Shift+Tab", "Switch panel focus (reverse)"),
        help_line("1-5", "Jump to tab"),
        help_line("Enter", "Select item"),
        Line::default(),
        section_header("Search & Commands"),
        help_line("/", "Search / filter current list"),
        help_line(":", "Enter command mode"),
        help_line("Esc", "Cancel search/command, clear filter"),
        Line::default(),
        section_header("Commands (via :)"),
        help_line(":cancel", "Cancel selected task/campaign"),
        help_line(":start", "Start selected campaign"),
        help_line(":delete", "Delete selected task"),
        help_line(":quit", "Quit"),
        Line::default(),
        section_header("Other"),
        help_line("?", "Toggle help"),
        help_line("q", "Quit"),
    ];

    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Help ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::LAVENDER))
        .style(Style::default().bg(Theme::MANTLE));

    let paragraph = Paragraph::new(help_text).block(block);
    f.render_widget(paragraph, popup);
}

fn section_header(title: &str) -> Line<'_> {
    Line::from(Span::styled(
        format!("  {title}"),
        Style::default()
            .fg(Theme::LAVENDER)
            .add_modifier(Modifier::BOLD),
    ))
}

fn help_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {key:<14}"),
            Style::default()
                .fg(Theme::TEAL)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(desc, Style::default().fg(Theme::TEXT)),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
