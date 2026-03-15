use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Compute the main layout: header, body (split pane), and footer.
pub struct AppLayout {
    pub header: Rect,
    pub body: Rect,
    pub left_panel: Rect,
    pub right_panel: Rect,
    pub footer: Rect,
}

impl AppLayout {
    pub fn new(area: Rect) -> Self {
        let vertical = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Header + tab bar
                Constraint::Min(10),   // Body
                Constraint::Length(1),  // Footer / status bar
            ])
            .split(area);

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),  // Left panel (list)
                Constraint::Percentage(70),  // Right panel (detail)
            ])
            .split(vertical[1]);

        Self {
            header: vertical[0],
            body: vertical[1],
            left_panel: body[0],
            right_panel: body[1],
            footer: vertical[2],
        }
    }
}
