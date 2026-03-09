pub mod app;
pub mod event;
pub mod keys;
pub mod layout;
pub mod theme;
pub mod views;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Tabs},
    Terminal,
};

use crate::state::AppState;
use crate::storage::db;
use app::{ActiveTab, FocusPanel, TuiState};
use event::{spawn_event_reader, TermEvent};
use keys::{map_key, KeyAction};
use layout::AppLayout;
use theme::Theme;

const TICK_RATE: Duration = Duration::from_millis(250);
const DATA_REFRESH_INTERVAL: Duration = Duration::from_secs(1);

/// Run the TUI dashboard. Blocks until the user quits.
pub async fn run_tui(state: Arc<AppState>) -> anyhow::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_tui_loop(&mut terminal, state).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let mut tui_state = TuiState::new();
    let mut event_rx = spawn_event_reader(TICK_RATE);
    let mut last_refresh = std::time::Instant::now();

    // Initial data load
    refresh_data(&state, &mut tui_state).await;

    loop {
        // Render
        terminal.draw(|f| render(f, &tui_state))?;

        // Handle events
        if let Some(event) = event_rx.recv().await {
            match event {
                TermEvent::Key(key) => {
                    let action = map_key(key);
                    handle_action(&mut tui_state, action);
                    if tui_state.should_quit {
                        break;
                    }
                }
                TermEvent::Resize(_, _) => {
                    // Terminal will re-render on next loop
                }
                TermEvent::Tick => {
                    // Periodic data refresh
                    if last_refresh.elapsed() >= DATA_REFRESH_INTERVAL {
                        refresh_data(&state, &mut tui_state).await;
                        last_refresh = std::time::Instant::now();
                    }
                }
            }
        }
    }

    Ok(())
}

async fn refresh_data(state: &AppState, tui_state: &mut TuiState) {
    if let Ok(tasks) = db::list_tasks(&state.db).await {
        tui_state.tasks = tasks;
    }
    if let Ok(workers) = db::list_workers(&state.db).await {
        tui_state.workers = workers;
    }

    // Load chunks for the selected task
    if let Some(task) = tui_state.selected_task() {
        let task_id = task.id;
        if let Ok(chunks) = db::get_chunks_for_task(&state.db, task_id).await {
            tui_state.chunks = chunks;
        }
    }

    // Load results (limit to recent)
    if let Ok(results) = db::get_recent_cracked(&state.db, 100).await {
        tui_state.results = results;
    }

    if let Ok(audit) = db::get_recent_audit(&state.db, 100).await {
        tui_state.audit_entries = audit;
    }

    if let Ok(status) = db::get_system_status(&state.db).await {
        tui_state.status = Some(status);
    }
}

fn handle_action(state: &mut TuiState, action: KeyAction) {
    if state.show_help {
        match action {
            KeyAction::Help | KeyAction::Escape | KeyAction::Quit => {
                state.show_help = false;
            }
            _ => {}
        }
        return;
    }

    match action {
        KeyAction::Quit => state.should_quit = true,
        KeyAction::Up => state.move_up(),
        KeyAction::Down => state.move_down(),
        KeyAction::Top => state.move_top(),
        KeyAction::Bottom => state.move_bottom(),
        KeyAction::PageUp => state.page_up(),
        KeyAction::PageDown => state.page_down(),
        KeyAction::Tab => {
            if state.focus == FocusPanel::Left {
                state.focus = FocusPanel::Right;
            } else {
                state.active_tab = state.active_tab.next();
                state.focus = FocusPanel::Left;
            }
        }
        KeyAction::BackTab => {
            if state.focus == FocusPanel::Right {
                state.focus = FocusPanel::Left;
            } else {
                state.active_tab = state.active_tab.prev();
                state.focus = FocusPanel::Left;
            }
        }
        KeyAction::Help => state.show_help = true,
        KeyAction::Tab1 => {
            state.active_tab = ActiveTab::Tasks;
            state.focus = FocusPanel::Left;
        }
        KeyAction::Tab2 => {
            state.active_tab = ActiveTab::Workers;
            state.focus = FocusPanel::Left;
        }
        KeyAction::Tab3 => {
            state.active_tab = ActiveTab::Results;
            state.focus = FocusPanel::Left;
        }
        KeyAction::Tab4 => {
            state.active_tab = ActiveTab::AuditLog;
            state.focus = FocusPanel::Left;
        }
        KeyAction::Escape => {
            state.focus = FocusPanel::Left;
        }
        KeyAction::Enter | KeyAction::None => {}
    }
}

fn render(f: &mut ratatui::Frame, state: &TuiState) {
    let area = f.area();
    let layout = AppLayout::new(area);

    // Header with tab bar
    render_header(f, layout.header, state);

    // Body: split pane
    match state.active_tab {
        ActiveTab::Tasks => {
            views::tasks::render_task_list(f, layout.left_panel, state);
            views::tasks::render_task_detail(f, layout.right_panel, state);
        }
        ActiveTab::Workers => {
            views::workers::render_worker_list(f, layout.left_panel, state);
            views::workers::render_worker_detail(f, layout.right_panel, state);
        }
        ActiveTab::Results => {
            views::results::render_results(f, area, state);
        }
        ActiveTab::AuditLog => {
            views::audit::render_audit_log(f, area, state);
        }
    }

    // Footer / status bar
    render_footer(f, layout.footer, state);

    // Help overlay
    if state.show_help {
        views::help::render_help(f, area);
    }
}

fn render_header(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let tab_titles = vec!["Tasks", "Workers", "Results", "Audit Log"];
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .title(" CRACK-COORD ")
                .title_style(
                    Style::default()
                        .fg(Theme::MAUVE)
                        .add_modifier(Modifier::BOLD),
                )
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Theme::SURFACE1)),
        )
        .select(state.active_tab.index())
        .style(Style::default().fg(Theme::SUBTEXT0))
        .highlight_style(
            Style::default()
                .fg(Theme::BLUE)
                .add_modifier(Modifier::BOLD),
        )
        .divider("│");

    f.render_widget(tabs, area);
}

fn render_footer(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let status_info = state
        .status
        .as_ref()
        .map(|s| {
            format!(
                " {} tasks | {} workers | {} cracked | {} H/s",
                s.running_tasks, s.connected_workers, s.total_cracked, s.aggregate_speed
            )
        })
        .unwrap_or_default();

    let footer = Line::from(vec![
        Span::styled(
            " j/k:nav  Tab:switch  1-4:tabs  ?:help  q:quit ",
            Style::default().fg(Theme::SUBTEXT0),
        ),
        Span::styled(status_info, Style::default().fg(Theme::OVERLAY0)),
    ]);

    f.render_widget(
        ratatui::widgets::Paragraph::new(footer)
            .style(Style::default().bg(Theme::MANTLE)),
        area,
    );
}
