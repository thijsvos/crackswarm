pub mod app;
pub mod event;
pub mod keys;
pub mod layout;
pub mod theme;
pub mod views;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::KeyCode;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Tabs},
    Terminal,
};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::state::{AppEvent, AppState};
use crate::storage::db;
use app::{ActiveTab, FocusPanel, InputMode, NotificationLevel, TuiData, TuiState};
use event::{spawn_event_reader, TermEvent};
use keys::{map_key, KeyAction};
use layout::AppLayout;
use theme::Theme;

const TICK_RATE: Duration = Duration::from_millis(250);
const DATA_REFRESH_INTERVAL: Duration = Duration::from_millis(500);

/// Commands that need async execution (sent from TUI key handler to async runtime).
enum TuiCommand {
    CancelTask(Uuid),
    DeleteTask(Uuid),
    StartCampaign(Uuid),
    CancelCampaign(Uuid),
}

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

/// Hints sent to the background refresh task so it can fetch context-dependent
/// data (chunks for selected task, phases for selected campaign) without
/// blocking the UI loop.
struct RefreshHints {
    selected_task_id: Option<Uuid>,
    selected_campaign_id: Option<Uuid>,
}

/// Spawn a background task that periodically fetches all TUI data from the DB
/// and sends snapshots over a channel.
fn spawn_data_refresher(
    state: Arc<AppState>,
    hint_rx: mpsc::UnboundedReceiver<RefreshHints>,
) -> mpsc::UnboundedReceiver<TuiData> {
    let (data_tx, data_rx) = mpsc::unbounded_channel();
    let mut hint_rx = hint_rx;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(DATA_REFRESH_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut selected_task_id: Option<Uuid> = None;
        let mut selected_campaign_id: Option<Uuid> = None;

        loop {
            // Wait for the next tick
            interval.tick().await;

            // Drain any pending hints (take the latest)
            while let Ok(hints) = hint_rx.try_recv() {
                selected_task_id = hints.selected_task_id;
                selected_campaign_id = hints.selected_campaign_id;
            }

            // Fetch all data — these queries run on a background task,
            // so the UI loop is never blocked.
            let tasks = db::list_tasks(&state.db).await.unwrap_or_default();
            let workers = db::list_workers(&state.db).await.unwrap_or_default();
            let results = db::get_recent_cracked(&state.db, 100)
                .await
                .unwrap_or_default();
            let audit_entries = db::get_recent_audit(&state.db, 100)
                .await
                .unwrap_or_default();
            let status = db::get_system_status(&state.db).await.ok();
            let campaigns = db::list_campaigns(&state.db).await.unwrap_or_default();
            let cache_summary = db::cache_summary_per_worker(&state.db)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|(wid, count, bytes)| (wid, (count, bytes)))
                .collect::<std::collections::HashMap<_, _>>();

            let chunks = if let Some(tid) = selected_task_id {
                Some(
                    db::get_chunks_for_task(&state.db, tid)
                        .await
                        .unwrap_or_default(),
                )
            } else {
                None
            };

            let campaign_phases = if let Some(cid) = selected_campaign_id {
                Some(
                    db::get_phases_for_campaign(&state.db, cid)
                        .await
                        .unwrap_or_default(),
                )
            } else {
                None
            };

            let data = TuiData {
                tasks,
                workers,
                results,
                audit_entries,
                chunks,
                status,
                campaigns,
                campaign_phases,
                cache_summary,
            };

            if data_tx.send(data).is_err() {
                break; // TUI loop exited
            }
        }
    });

    data_rx
}

/// Spawn a command executor that processes TuiCommands asynchronously.
fn spawn_command_executor(
    state: Arc<AppState>,
    mut cmd_rx: mpsc::UnboundedReceiver<TuiCommand>,
    result_tx: mpsc::UnboundedSender<(String, NotificationLevel)>,
) {
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            let (msg, level) = match cmd {
                TuiCommand::CancelTask(id) => {
                    match db::update_task_status(
                        &state.db,
                        id,
                        crack_common::models::TaskStatus::Cancelled,
                    )
                    .await
                    {
                        Ok(_) => {
                            state.emit(AppEvent::TaskUpdated { task_id: id });
                            (
                                format!("Task {} cancelled", &id.to_string()[..8]),
                                NotificationLevel::Success,
                            )
                        }
                        Err(e) => (
                            format!("Failed to cancel task: {e}"),
                            NotificationLevel::Error,
                        ),
                    }
                }
                TuiCommand::DeleteTask(id) => match db::delete_task(&state.db, id).await {
                    Ok(_) => (
                        format!("Task {} deleted", &id.to_string()[..8]),
                        NotificationLevel::Success,
                    ),
                    Err(e) => (
                        format!("Failed to delete task: {e}"),
                        NotificationLevel::Error,
                    ),
                },
                TuiCommand::StartCampaign(id) => {
                    match crate::campaign::start_campaign(&state, id).await {
                        Ok(_) => (
                            format!("Campaign {} started", &id.to_string()[..8]),
                            NotificationLevel::Success,
                        ),
                        Err(e) => (
                            format!("Failed to start campaign: {e}"),
                            NotificationLevel::Error,
                        ),
                    }
                }
                TuiCommand::CancelCampaign(id) => {
                    match db::update_campaign_status(
                        &state.db,
                        id,
                        crack_common::models::CampaignStatus::Cancelled,
                    )
                    .await
                    {
                        Ok(_) => (
                            format!("Campaign {} cancelled", &id.to_string()[..8]),
                            NotificationLevel::Success,
                        ),
                        Err(e) => (
                            format!("Failed to cancel campaign: {e}"),
                            NotificationLevel::Error,
                        ),
                    }
                }
            };
            let _ = result_tx.send((msg, level));
        }
    });
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: Arc<AppState>,
) -> anyhow::Result<()> {
    let mut tui_state = TuiState::new();
    let mut event_rx = spawn_event_reader(TICK_RATE);

    // Spawn background data refresher
    let (hint_tx, hint_rx) = mpsc::unbounded_channel();
    let mut data_rx = spawn_data_refresher(Arc::clone(&state), hint_rx);

    // Spawn command executor
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (cmd_result_tx, mut cmd_result_rx) = mpsc::unbounded_channel();
    spawn_command_executor(Arc::clone(&state), cmd_rx, cmd_result_tx);

    // Subscribe to app events for toast notifications
    let mut event_broadcast_rx = state.events.subscribe();

    // Send initial hints
    let _ = hint_tx.send(RefreshHints {
        selected_task_id: None,
        selected_campaign_id: None,
    });

    loop {
        // Expire old notifications
        tui_state.expire_notifications();

        // Render
        terminal.draw(|f| render(f, &mut tui_state))?;

        // Select between terminal events, data updates, broadcast events, and command results
        tokio::select! {
            // Terminal events (keys, resize, tick) — always responsive
            event = event_rx.recv() => {
                let Some(event) = event else { break };
                match event {
                    TermEvent::Key(key) => {
                        match tui_state.input_mode {
                            InputMode::Normal => {
                                let action = map_key(key);
                                handle_action(&mut tui_state, action, &cmd_tx);
                            }
                            InputMode::Command | InputMode::Search => {
                                handle_input_key(&mut tui_state, key, &cmd_tx);
                            }
                        }
                        if tui_state.should_quit {
                            break;
                        }
                        // Send updated hints
                        let _ = hint_tx.send(RefreshHints {
                            selected_task_id: tui_state.selected_task().map(|t| t.id),
                            selected_campaign_id: tui_state.selected_campaign().map(|c| c.id),
                        });
                    }
                    TermEvent::Resize(_, _) => {}
                    TermEvent::Tick => {}
                }
            }
            // Data snapshot from background refresh — apply instantly
            data = data_rx.recv() => {
                if let Some(data) = data {
                    tui_state.apply_data(data);
                }
            }
            // App events → toast notifications
            event = event_broadcast_rx.recv() => {
                if let Ok(event) = event {
                    if let Some((msg, level)) = event_to_notification(&event) {
                        tui_state.notify(msg, level);
                    }
                }
            }
            // Command execution results → toast notifications
            result = cmd_result_rx.recv() => {
                if let Some((msg, level)) = result {
                    tui_state.notify(msg, level);
                }
            }
        }
    }

    Ok(())
}

/// Convert an AppEvent into a notification string (if appropriate).
fn event_to_notification(event: &AppEvent) -> Option<(String, NotificationLevel)> {
    match event {
        AppEvent::WorkerConnected { name, .. } => Some((
            format!("Worker '{}' connected", name),
            NotificationLevel::Info,
        )),
        AppEvent::WorkerDisconnected { worker_id } => Some((
            format!(
                "Worker {} disconnected",
                &worker_id[..8.min(worker_id.len())]
            ),
            NotificationLevel::Info,
        )),
        AppEvent::TaskCompleted { task_id } => Some((
            format!("Task {} completed", &task_id.to_string()[..8]),
            NotificationLevel::Success,
        )),
        AppEvent::HashCracked { hash, .. } => {
            let hash_short = if hash.len() > 16 { &hash[..16] } else { hash };
            Some((
                format!("Hash cracked: {}...", hash_short),
                NotificationLevel::Success,
            ))
        }
        AppEvent::CampaignCompleted { campaign_id } => Some((
            format!("Campaign {} completed", &campaign_id.to_string()[..8]),
            NotificationLevel::Success,
        )),
        AppEvent::CampaignPhaseAdvanced { phase_index, .. } => Some((
            format!("Campaign advanced to phase {}", phase_index + 1),
            NotificationLevel::Info,
        )),
        _ => None,
    }
}

fn handle_action(
    state: &mut TuiState,
    action: KeyAction,
    _cmd_tx: &mpsc::UnboundedSender<TuiCommand>,
) {
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
        KeyAction::Up => {
            if state.focus == FocusPanel::Right && state.active_tab == ActiveTab::Tasks {
                state.chunk_scroll_offset = state.chunk_scroll_offset.saturating_sub(1);
            } else {
                state.move_up();
            }
        }
        KeyAction::Down => {
            if state.focus == FocusPanel::Right && state.active_tab == ActiveTab::Tasks {
                state.chunk_scroll_offset = state.chunk_scroll_offset.saturating_add(1);
            } else {
                state.move_down();
            }
        }
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
        KeyAction::Tab5 => {
            state.active_tab = ActiveTab::Campaigns;
            state.focus = FocusPanel::Left;
        }
        KeyAction::EnterCommand => {
            state.input_mode = InputMode::Command;
            state.input_buffer.clear();
        }
        KeyAction::EnterSearch => {
            state.input_mode = InputMode::Search;
            state.input_buffer.clear();
        }
        KeyAction::Escape => {
            if !state.search_filter.is_empty() {
                state.search_filter.clear();
            } else {
                state.focus = FocusPanel::Left;
            }
        }
        KeyAction::Enter | KeyAction::None => {}
    }
}

/// Handle key events when in Command or Search input mode.
fn handle_input_key(
    state: &mut TuiState,
    key: crossterm::event::KeyEvent,
    cmd_tx: &mpsc::UnboundedSender<TuiCommand>,
) {
    let was_mode = state.input_mode;

    match key.code {
        KeyCode::Esc => {
            state.input_mode = InputMode::Normal;
            state.input_buffer.clear();
            if was_mode == InputMode::Search {
                state.search_filter.clear();
            }
        }
        KeyCode::Enter => {
            let input = state.input_buffer.clone();
            state.input_buffer.clear();
            state.input_mode = InputMode::Normal;

            if was_mode == InputMode::Command && !input.is_empty() {
                execute_command(state, &input, cmd_tx);
            }
            // Search: filter stays active after Enter (Esc clears it)
        }
        KeyCode::Backspace => {
            state.input_buffer.pop();
            if was_mode == InputMode::Search {
                state.search_filter = state.input_buffer.clone();
            }
        }
        KeyCode::Char(c) => {
            state.input_buffer.push(c);
            if was_mode == InputMode::Search {
                state.search_filter = state.input_buffer.clone();
            }
        }
        _ => {}
    }
}

/// Execute a command entered via the `:` command bar.
fn execute_command(state: &mut TuiState, input: &str, cmd_tx: &mpsc::UnboundedSender<TuiCommand>) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let cmd = parts.first().copied().unwrap_or("");

    match cmd {
        "cancel" => match state.active_tab {
            ActiveTab::Tasks => {
                if let Some(task) = state.selected_task() {
                    let _ = cmd_tx.send(TuiCommand::CancelTask(task.id));
                } else {
                    state.notify("No task selected".into(), NotificationLevel::Error);
                }
            }
            ActiveTab::Campaigns => {
                if let Some(campaign) = state.selected_campaign() {
                    let _ = cmd_tx.send(TuiCommand::CancelCampaign(campaign.id));
                } else {
                    state.notify("No campaign selected".into(), NotificationLevel::Error);
                }
            }
            _ => {
                state.notify(
                    "Cancel not available on this tab".into(),
                    NotificationLevel::Error,
                );
            }
        },
        "start" => {
            if state.active_tab == ActiveTab::Campaigns {
                if let Some(campaign) = state.selected_campaign() {
                    let _ = cmd_tx.send(TuiCommand::StartCampaign(campaign.id));
                } else {
                    state.notify("No campaign selected".into(), NotificationLevel::Error);
                }
            } else {
                state.notify(
                    "Start only available on Campaigns tab".into(),
                    NotificationLevel::Error,
                );
            }
        }
        "delete" => {
            if state.active_tab == ActiveTab::Tasks {
                if let Some(task) = state.selected_task() {
                    let _ = cmd_tx.send(TuiCommand::DeleteTask(task.id));
                } else {
                    state.notify("No task selected".into(), NotificationLevel::Error);
                }
            } else {
                state.notify(
                    "Delete only available on Tasks tab".into(),
                    NotificationLevel::Error,
                );
            }
        }
        "q" | "quit" => {
            state.should_quit = true;
        }
        _ => {
            state.notify(format!("Unknown command: {cmd}"), NotificationLevel::Error);
        }
    }
}

fn render(f: &mut ratatui::Frame, state: &mut TuiState) {
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
            views::results::render_results(f, layout.body, state);
        }
        ActiveTab::AuditLog => {
            views::audit::render_audit_log(f, layout.body, state);
        }
        ActiveTab::Campaigns => {
            views::campaigns::render_campaign_list(f, layout.left_panel, state);
            views::campaigns::render_campaign_detail(f, layout.right_panel, state);
        }
    }

    // Footer / status bar / command input
    render_footer(f, layout.footer, state);

    // Toast notifications (bottom-right overlay)
    render_notifications(f, area, state);

    // Help overlay
    if state.show_help {
        views::help::render_help(f, area);
    }
}

fn render_header(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &TuiState) {
    let tab_titles = vec!["Tasks", "Workers", "Results", "Audit Log", "Campaigns"];
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
    match state.input_mode {
        InputMode::Command => {
            let input_line = Line::from(vec![
                Span::styled(
                    ":",
                    Style::default()
                        .fg(Theme::MAUVE)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&state.input_buffer, Style::default().fg(Theme::TEXT)),
                Span::styled(
                    "_",
                    Style::default()
                        .fg(Theme::TEXT)
                        .add_modifier(Modifier::SLOW_BLINK),
                ),
            ]);
            f.render_widget(
                Paragraph::new(input_line).style(Style::default().bg(Theme::MANTLE)),
                area,
            );
        }
        InputMode::Search => {
            let input_line = Line::from(vec![
                Span::styled(
                    "/",
                    Style::default()
                        .fg(Theme::TEAL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&state.input_buffer, Style::default().fg(Theme::TEXT)),
                Span::styled(
                    "_",
                    Style::default()
                        .fg(Theme::TEXT)
                        .add_modifier(Modifier::SLOW_BLINK),
                ),
            ]);
            f.render_widget(
                Paragraph::new(input_line).style(Style::default().bg(Theme::MANTLE)),
                area,
            );
        }
        InputMode::Normal => {
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

            let mut hints =
                String::from(" j/k:nav  Tab:switch  1-5:tabs  /:search  ::cmd  ?:help  q:quit ");
            if !state.search_filter.is_empty() {
                hints.push_str(&format!(" [filter: {}]", state.search_filter));
            }

            let footer = Line::from(vec![
                Span::styled(hints, Style::default().fg(Theme::SUBTEXT0)),
                Span::styled(status_info, Style::default().fg(Theme::OVERLAY0)),
            ]);

            f.render_widget(
                Paragraph::new(footer).style(Style::default().bg(Theme::MANTLE)),
                area,
            );
        }
    }
}

fn render_notifications(f: &mut ratatui::Frame, area: Rect, state: &TuiState) {
    if state.notifications.is_empty() {
        return;
    }

    let notif_lines: Vec<Line> = state
        .notifications
        .iter()
        .map(|(msg, _, level)| {
            let color = match level {
                NotificationLevel::Info => Theme::BLUE,
                NotificationLevel::Success => Theme::GREEN,
                NotificationLevel::Error => Theme::RED,
            };
            Line::from(Span::styled(format!(" {msg} "), Style::default().fg(color)))
        })
        .collect();

    let height = notif_lines.len() as u16 + 2; // +2 for borders
    let width = notif_lines
        .iter()
        .map(|l| l.width() as u16)
        .max()
        .unwrap_or(20)
        .max(20)
        + 2; // +2 for borders

    // Position in bottom-right corner, above the footer
    let x = area.width.saturating_sub(width).saturating_sub(1);
    let y = area.height.saturating_sub(height).saturating_sub(2);
    let notif_area = Rect::new(x, y, width.min(area.width), height.min(area.height));

    f.render_widget(Clear, notif_area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Theme::SURFACE1))
        .style(Style::default().bg(Theme::MANTLE));
    let paragraph = Paragraph::new(notif_lines).block(block);
    f.render_widget(paragraph, notif_area);
}
