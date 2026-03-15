use std::collections::VecDeque;
use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::sync::mpsc;
use uuid::Uuid;

use crack_common::models::DeviceInfo;

// ── Catppuccin Mocha theme (subset) ──

const BASE: Color = Color::Rgb(30, 30, 46);
#[allow(dead_code)]
const MANTLE: Color = Color::Rgb(24, 24, 37);
const SURFACE0: Color = Color::Rgb(49, 50, 68);
const SURFACE1: Color = Color::Rgb(69, 71, 90);
const TEXT: Color = Color::Rgb(205, 214, 244);
const SUBTEXT0: Color = Color::Rgb(166, 173, 200);
const OVERLAY0: Color = Color::Rgb(108, 112, 134);
const BLUE: Color = Color::Rgb(137, 180, 250);
const GREEN: Color = Color::Rgb(166, 227, 161);
const RED: Color = Color::Rgb(243, 139, 168);
const YELLOW: Color = Color::Rgb(249, 226, 175);
const PEACH: Color = Color::Rgb(250, 179, 135);
const MAUVE: Color = Color::Rgb(203, 166, 247);
const TEAL: Color = Color::Rgb(148, 226, 213);

// ── Events from the connection loop ──

#[derive(Debug, Clone)]
pub enum AgentEvent {
    Connected { worker_id: String },
    Disconnected,
    Reconnecting { attempt: u32 },
    ChunkAssigned {
        task_id: Uuid,
        chunk_id: Uuid,
        hash_mode: u32,
        mask: String,
    },
    ChunkProgress {
        progress_pct: f64,
        speed: u64,
        est_remaining: Option<u64>,
    },
    HashCracked {
        hash: String,
        plaintext: String,
    },
    ChunkCompleted {
        exit_code: i32,
    },
    ChunkFailed {
        error: String,
    },
}

// ── Connection status ──

#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Reconnecting(u32),
    Disconnected,
}

impl ConnectionStatus {
    fn label(&self) -> &str {
        match self {
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Reconnecting(_) => "Reconnecting",
            Self::Disconnected => "Disconnected",
        }
    }

    fn color(&self) -> Color {
        match self {
            Self::Connected => GREEN,
            Self::Connecting | Self::Reconnecting(_) => YELLOW,
            Self::Disconnected => RED,
        }
    }
}

// ── Current work info ──

#[derive(Debug, Clone)]
struct ChunkWork {
    task_id: Uuid,
    chunk_id: Uuid,
    hash_mode: u32,
    mask: String,
    progress_pct: f64,
    speed: u64,
    est_remaining: Option<u64>,
    cracked_this_chunk: u32,
}

// ── TUI state ──

pub struct AgentTuiState {
    worker_name: String,
    server_addr: String,
    hashcat_version: String,
    devices: Vec<DeviceInfo>,
    connection_status: ConnectionStatus,
    current_chunk: Option<ChunkWork>,
    recent_cracks: VecDeque<(String, String)>, // (hash_short, plaintext)
    chunks_completed: u64,
    total_cracked: u64,
    started_at: Instant,
    reconnect_count: u32,
    should_quit: bool,
}

impl AgentTuiState {
    fn new(
        worker_name: String,
        server_addr: String,
        hashcat_version: String,
        devices: Vec<DeviceInfo>,
    ) -> Self {
        Self {
            worker_name,
            server_addr,
            hashcat_version,
            devices,
            connection_status: ConnectionStatus::Connecting,
            current_chunk: None,
            recent_cracks: VecDeque::new(),
            chunks_completed: 0,
            total_cracked: 0,
            started_at: Instant::now(),
            reconnect_count: 0,
            should_quit: false,
        }
    }

    fn handle_event(&mut self, event: AgentEvent) {
        match event {
            AgentEvent::Connected { .. } => {
                self.connection_status = ConnectionStatus::Connected;
            }
            AgentEvent::Disconnected => {
                self.connection_status = ConnectionStatus::Disconnected;
                self.current_chunk = None;
            }
            AgentEvent::Reconnecting { attempt } => {
                self.reconnect_count += 1;
                self.connection_status = ConnectionStatus::Reconnecting(attempt);
                self.current_chunk = None;
            }
            AgentEvent::ChunkAssigned {
                task_id,
                chunk_id,
                hash_mode,
                mask,
            } => {
                self.current_chunk = Some(ChunkWork {
                    task_id,
                    chunk_id,
                    hash_mode,
                    mask,
                    progress_pct: 0.0,
                    speed: 0,
                    est_remaining: None,
                    cracked_this_chunk: 0,
                });
            }
            AgentEvent::ChunkProgress {
                progress_pct,
                speed,
                est_remaining,
            } => {
                if let Some(ref mut chunk) = self.current_chunk {
                    chunk.progress_pct = progress_pct;
                    chunk.speed = speed;
                    chunk.est_remaining = est_remaining;
                }
            }
            AgentEvent::HashCracked { hash, plaintext } => {
                if let Some(ref mut chunk) = self.current_chunk {
                    chunk.cracked_this_chunk += 1;
                }
                self.total_cracked += 1;
                let hash_short = if hash.len() > 12 {
                    format!("{}...", &hash[..12])
                } else {
                    hash
                };
                self.recent_cracks.push_front((hash_short, plaintext));
                if self.recent_cracks.len() > 10 {
                    self.recent_cracks.pop_back();
                }
            }
            AgentEvent::ChunkCompleted { .. } => {
                self.chunks_completed += 1;
                self.current_chunk = None;
            }
            AgentEvent::ChunkFailed { .. } => {
                self.current_chunk = None;
            }
        }
    }
}

// ── Terminal event reader ──

enum TermEvent {
    Key(KeyEvent),
    Tick,
}

fn spawn_event_reader(tick_rate: Duration) -> mpsc::UnboundedReceiver<TermEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || loop {
        if event::poll(tick_rate).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if tx.send(TermEvent::Key(key)).is_err() {
                    return;
                }
            }
        } else if tx.send(TermEvent::Tick).is_err() {
            return;
        }
    });
    rx
}

// ── Public entry point ──

pub async fn run_tui(
    worker_name: &str,
    server_addr: &str,
    hashcat_version: &str,
    devices: &[DeviceInfo],
    event_rx: mpsc::UnboundedReceiver<AgentEvent>,
) -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let result = run_tui_loop(
        &mut terminal,
        worker_name,
        server_addr,
        hashcat_version,
        devices,
        event_rx,
    )
    .await;

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    worker_name: &str,
    server_addr: &str,
    hashcat_version: &str,
    devices: &[DeviceInfo],
    mut event_rx: mpsc::UnboundedReceiver<AgentEvent>,
) -> anyhow::Result<()> {
    let mut state = AgentTuiState::new(
        worker_name.to_string(),
        server_addr.to_string(),
        hashcat_version.to_string(),
        devices.to_vec(),
    );

    let mut term_rx = spawn_event_reader(Duration::from_millis(250));

    loop {
        terminal.draw(|f| render(f, &state))?;

        tokio::select! {
            ev = term_rx.recv() => {
                match ev {
                    Some(TermEvent::Key(key)) => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => {
                                state.should_quit = true;
                            }
                            KeyCode::Char('c') if key.modifiers.contains(
                                crossterm::event::KeyModifiers::CONTROL
                            ) => {
                                state.should_quit = true;
                            }
                            _ => {}
                        }
                    }
                    Some(TermEvent::Tick) => {}
                    None => break,
                }
            }
            ev = event_rx.recv() => {
                match ev {
                    Some(agent_event) => state.handle_event(agent_event),
                    None => {
                        // Connection loop exited
                        state.connection_status = ConnectionStatus::Disconnected;
                        state.current_chunk = None;
                    }
                }
            }
        }

        if state.should_quit {
            break;
        }
    }

    Ok(())
}

// ── Rendering ──

fn render(f: &mut ratatui::Frame, state: &AgentTuiState) {
    let area = f.area();

    // Outer block
    let title = format!(" CRACK-AGENT: {} ", state.worker_name);
    let outer_block = Block::default()
        .title(title)
        .title_style(
            Style::default()
                .fg(MAUVE)
                .add_modifier(Modifier::BOLD),
        )
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE1))
        .style(Style::default().bg(BASE));

    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    // Split inner vertically into 4 sections
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // Status header
            Constraint::Length(7),  // Current work + progress
            Constraint::Min(3),    // Recent cracks
            Constraint::Length(2), // Session stats + key hints
        ])
        .split(inner);

    render_status(f, sections[0], state);
    render_work(f, sections[1], state);
    render_cracks(f, sections[2], state);
    render_stats(f, sections[3], state);
}

fn render_status(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &AgentTuiState) {
    let status_label = state.connection_status.label();
    let status_color = state.connection_status.color();

    let gpu_summary = if state.devices.is_empty() {
        "none detected".to_string()
    } else if state.devices.len() == 1 {
        format!("1x {}", state.devices[0].name)
    } else {
        format!("{}x devices", state.devices.len())
    };

    let lines = vec![
        Line::from(vec![
            Span::styled(" Server: ", Style::default().fg(OVERLAY0)),
            Span::styled(&state.server_addr, Style::default().fg(TEXT)),
            Span::styled("    Status: ", Style::default().fg(OVERLAY0)),
            Span::styled(status_label, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(" Hashcat: ", Style::default().fg(OVERLAY0)),
            Span::styled(&state.hashcat_version, Style::default().fg(TEXT)),
            Span::styled("    GPUs: ", Style::default().fg(OVERLAY0)),
            Span::styled(gpu_summary, Style::default().fg(TEXT)),
        ]),
    ];

    f.render_widget(Paragraph::new(lines), area);
}

fn render_work(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &AgentTuiState) {
    let block = Block::default()
        .title(" Current Work ")
        .title_style(Style::default().fg(TEAL))
        .borders(Borders::TOP)
        .border_style(Style::default().fg(SURFACE0));

    let inner = block.inner(area);
    f.render_widget(block, area);

    match &state.current_chunk {
        None => {
            let msg = match state.connection_status {
                ConnectionStatus::Connected => "Waiting for work assignment...",
                ConnectionStatus::Connecting => "Connecting to coordinator...",
                ConnectionStatus::Reconnecting(_) => "Reconnecting...",
                ConnectionStatus::Disconnected => "Disconnected from coordinator",
            };
            let style = Style::default().fg(SUBTEXT0);
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(format!(" {msg}"), style))),
                inner,
            );
        }
        Some(chunk) => {
            let task_short = &chunk.task_id.to_string()[..8];
            let chunk_short = &chunk.chunk_id.to_string()[..8];

            let info_lines = vec![
                Line::from(vec![
                    Span::styled(" Task: ", Style::default().fg(OVERLAY0)),
                    Span::styled(task_short, Style::default().fg(TEXT)),
                    Span::styled("   Mode: ", Style::default().fg(OVERLAY0)),
                    Span::styled(chunk.hash_mode.to_string(), Style::default().fg(TEXT)),
                ]),
                Line::from(vec![
                    Span::styled(" Mask: ", Style::default().fg(OVERLAY0)),
                    Span::styled(&chunk.mask, Style::default().fg(TEXT)),
                    Span::styled("   Chunk: ", Style::default().fg(OVERLAY0)),
                    Span::styled(chunk_short, Style::default().fg(TEXT)),
                ]),
            ];

            // Split inner for info + gauge + speed
            let work_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2), // Task/mask info
                    Constraint::Length(1), // Progress gauge
                    Constraint::Length(2), // Speed/ETA/Cracked
                ])
                .split(inner);

            f.render_widget(Paragraph::new(info_lines), work_layout[0]);

            // Progress gauge
            let pct = chunk.progress_pct.clamp(0.0, 100.0);
            let gauge = Gauge::default()
                .gauge_style(Style::default().fg(BLUE).bg(SURFACE0))
                .label(format!("{pct:.1}%"))
                .ratio(pct / 100.0);
            f.render_widget(gauge, work_layout[1]);

            // Speed / ETA / Cracked
            let eta_str = chunk
                .est_remaining
                .map(format_duration)
                .unwrap_or_else(|| "—".to_string());

            let speed_lines = vec![
                Line::from(vec![
                    Span::styled(" Speed: ", Style::default().fg(OVERLAY0)),
                    Span::styled(format_speed(chunk.speed), Style::default().fg(GREEN)),
                    Span::styled("    ETA: ", Style::default().fg(OVERLAY0)),
                    Span::styled(eta_str, Style::default().fg(TEXT)),
                ]),
                Line::from(vec![
                    Span::styled(" Cracked: ", Style::default().fg(OVERLAY0)),
                    Span::styled(
                        format!("{} this chunk", chunk.cracked_this_chunk),
                        Style::default().fg(if chunk.cracked_this_chunk > 0 { GREEN } else { TEXT }),
                    ),
                ]),
            ];
            f.render_widget(Paragraph::new(speed_lines), work_layout[2]);
        }
    }
}

fn render_cracks(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &AgentTuiState) {
    let block = Block::default()
        .title(" Recent Cracks ")
        .title_style(Style::default().fg(PEACH))
        .borders(Borders::TOP)
        .border_style(Style::default().fg(SURFACE0));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.recent_cracks.is_empty() {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                " No cracks yet",
                Style::default().fg(SUBTEXT0),
            ))),
            inner,
        );
    } else {
        let max_lines = inner.height as usize;
        let lines: Vec<Line> = state
            .recent_cracks
            .iter()
            .take(max_lines)
            .map(|(hash, plain)| {
                Line::from(vec![
                    Span::styled(format!(" {hash}"), Style::default().fg(YELLOW)),
                    Span::styled(" → ", Style::default().fg(OVERLAY0)),
                    Span::styled(plain, Style::default().fg(GREEN)),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines), inner);
    }
}

fn render_stats(f: &mut ratatui::Frame, area: ratatui::layout::Rect, state: &AgentTuiState) {
    let uptime = format_duration(state.started_at.elapsed().as_secs());

    let lines = vec![
        Line::from(vec![
            Span::styled(" Chunks: ", Style::default().fg(OVERLAY0)),
            Span::styled(state.chunks_completed.to_string(), Style::default().fg(TEXT)),
            Span::styled(" completed   Cracked: ", Style::default().fg(OVERLAY0)),
            Span::styled(state.total_cracked.to_string(), Style::default().fg(if state.total_cracked > 0 { GREEN } else { TEXT })),
            Span::styled(" total   Uptime: ", Style::default().fg(OVERLAY0)),
            Span::styled(&uptime, Style::default().fg(TEXT)),
            Span::styled("   Reconnects: ", Style::default().fg(OVERLAY0)),
            Span::styled(state.reconnect_count.to_string(), Style::default().fg(if state.reconnect_count > 0 { YELLOW } else { TEXT })),
        ]),
        Line::from(Span::styled(
            " q: quit",
            Style::default().fg(SUBTEXT0),
        )),
    ];

    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(SURFACE0));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(Paragraph::new(lines), inner);
}

// ── Formatting helpers ──

fn format_speed(speed: u64) -> String {
    if speed >= 1_000_000_000_000 {
        format!("{:.1} TH/s", speed as f64 / 1_000_000_000_000.0)
    } else if speed >= 1_000_000_000 {
        format!("{:.1} GH/s", speed as f64 / 1_000_000_000.0)
    } else if speed >= 1_000_000 {
        format!("{:.1} MH/s", speed as f64 / 1_000_000.0)
    } else if speed >= 1_000 {
        format!("{:.1} kH/s", speed as f64 / 1_000.0)
    } else {
        format!("{} H/s", speed)
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> AgentTuiState {
        AgentTuiState::new(
            "test-gpu".to_string(),
            "10.0.1.5:8443".to_string(),
            "v6.2.6".to_string(),
            vec![DeviceInfo {
                id: 1,
                name: "RTX 4090".to_string(),
                device_type: "GPU".to_string(),
                speed: None,
            }],
        )
    }

    fn make_chunk_id() -> (Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4())
    }

    // ── format_speed tests ──

    #[test]
    fn test_format_speed_zero() {
        assert_eq!(format_speed(0), "0 H/s");
    }

    #[test]
    fn test_format_speed_low() {
        assert_eq!(format_speed(500), "500 H/s");
    }

    #[test]
    fn test_format_speed_kilo() {
        assert_eq!(format_speed(1_500), "1.5 kH/s");
        assert_eq!(format_speed(1_000), "1.0 kH/s");
        assert_eq!(format_speed(999_999), "1000.0 kH/s");
    }

    #[test]
    fn test_format_speed_mega() {
        assert_eq!(format_speed(1_000_000), "1.0 MH/s");
        assert_eq!(format_speed(12_400_000), "12.4 MH/s");
    }

    #[test]
    fn test_format_speed_giga() {
        assert_eq!(format_speed(1_000_000_000), "1.0 GH/s");
        assert_eq!(format_speed(12_400_000_000), "12.4 GH/s");
    }

    #[test]
    fn test_format_speed_tera() {
        assert_eq!(format_speed(1_000_000_000_000), "1.0 TH/s");
        assert_eq!(format_speed(2_500_000_000_000), "2.5 TH/s");
    }

    // ── format_duration tests ──

    #[test]
    fn test_format_duration_seconds() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(1), "1s");
        assert_eq!(format_duration(59), "59s");
    }

    #[test]
    fn test_format_duration_minutes() {
        assert_eq!(format_duration(60), "1m 0s");
        assert_eq!(format_duration(154), "2m 34s");
        assert_eq!(format_duration(3599), "59m 59s");
    }

    #[test]
    fn test_format_duration_hours() {
        assert_eq!(format_duration(3600), "1h 0m");
        assert_eq!(format_duration(8040), "2h 14m");
        assert_eq!(format_duration(86400), "24h 0m");
    }

    // ── ConnectionStatus tests ──

    #[test]
    fn test_connection_status_labels() {
        assert_eq!(ConnectionStatus::Connecting.label(), "Connecting");
        assert_eq!(ConnectionStatus::Connected.label(), "Connected");
        assert_eq!(ConnectionStatus::Reconnecting(3).label(), "Reconnecting");
        assert_eq!(ConnectionStatus::Disconnected.label(), "Disconnected");
    }

    #[test]
    fn test_connection_status_colors() {
        assert_eq!(ConnectionStatus::Connected.color(), GREEN);
        assert_eq!(ConnectionStatus::Connecting.color(), YELLOW);
        assert_eq!(ConnectionStatus::Reconnecting(1).color(), YELLOW);
        assert_eq!(ConnectionStatus::Disconnected.color(), RED);
    }

    // ── AgentTuiState initial state ──

    #[test]
    fn test_initial_state() {
        let state = make_state();
        assert_eq!(state.worker_name, "test-gpu");
        assert_eq!(state.server_addr, "10.0.1.5:8443");
        assert_eq!(state.hashcat_version, "v6.2.6");
        assert_eq!(state.devices.len(), 1);
        assert!(matches!(state.connection_status, ConnectionStatus::Connecting));
        assert!(state.current_chunk.is_none());
        assert!(state.recent_cracks.is_empty());
        assert_eq!(state.chunks_completed, 0);
        assert_eq!(state.total_cracked, 0);
        assert_eq!(state.reconnect_count, 0);
        assert!(!state.should_quit);
    }

    // ── Event handling: connection lifecycle ──

    #[test]
    fn test_connected_event() {
        let mut state = make_state();
        state.handle_event(AgentEvent::Connected {
            worker_id: "w-123".to_string(),
        });
        assert!(matches!(state.connection_status, ConnectionStatus::Connected));
    }

    #[test]
    fn test_disconnected_event_clears_chunk() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        // Assign a chunk, then disconnect
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a?a?a".to_string(),
        });
        assert!(state.current_chunk.is_some());

        state.handle_event(AgentEvent::Disconnected);
        assert!(matches!(state.connection_status, ConnectionStatus::Disconnected));
        assert!(state.current_chunk.is_none());
    }

    #[test]
    fn test_reconnecting_increments_count() {
        let mut state = make_state();
        assert_eq!(state.reconnect_count, 0);

        state.handle_event(AgentEvent::Reconnecting { attempt: 1 });
        assert_eq!(state.reconnect_count, 1);
        assert!(matches!(state.connection_status, ConnectionStatus::Reconnecting(1)));

        state.handle_event(AgentEvent::Reconnecting { attempt: 2 });
        assert_eq!(state.reconnect_count, 2);
    }

    #[test]
    fn test_reconnecting_clears_chunk() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a".to_string(),
        });
        assert!(state.current_chunk.is_some());

        state.handle_event(AgentEvent::Reconnecting { attempt: 1 });
        assert!(state.current_chunk.is_none());
    }

    // ── Event handling: chunk lifecycle ──

    #[test]
    fn test_chunk_assigned() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?u?l?l?l?d?d".to_string(),
        });

        let chunk = state.current_chunk.as_ref().unwrap();
        assert_eq!(chunk.task_id, task_id);
        assert_eq!(chunk.chunk_id, chunk_id);
        assert_eq!(chunk.hash_mode, 1000);
        assert_eq!(chunk.mask, "?u?l?l?l?d?d");
        assert_eq!(chunk.progress_pct, 0.0);
        assert_eq!(chunk.speed, 0);
        assert!(chunk.est_remaining.is_none());
        assert_eq!(chunk.cracked_this_chunk, 0);
    }

    #[test]
    fn test_chunk_progress_updates() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a?a".to_string(),
        });

        state.handle_event(AgentEvent::ChunkProgress {
            progress_pct: 58.3,
            speed: 12_400_000_000,
            est_remaining: Some(154),
        });

        let chunk = state.current_chunk.as_ref().unwrap();
        assert!((chunk.progress_pct - 58.3).abs() < f64::EPSILON);
        assert_eq!(chunk.speed, 12_400_000_000);
        assert_eq!(chunk.est_remaining, Some(154));
    }

    #[test]
    fn test_chunk_progress_without_active_chunk_is_noop() {
        let mut state = make_state();
        // Progress with no active chunk should not panic
        state.handle_event(AgentEvent::ChunkProgress {
            progress_pct: 50.0,
            speed: 1000,
            est_remaining: None,
        });
        assert!(state.current_chunk.is_none());
    }

    #[test]
    fn test_chunk_completed_increments_counter() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a".to_string(),
        });
        assert_eq!(state.chunks_completed, 0);

        state.handle_event(AgentEvent::ChunkCompleted { exit_code: 0 });
        assert_eq!(state.chunks_completed, 1);
        assert!(state.current_chunk.is_none());

        // Second chunk
        let (task_id2, chunk_id2) = make_chunk_id();
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id: task_id2,
            chunk_id: chunk_id2,
            hash_mode: 1000,
            mask: "?a?a".to_string(),
        });
        state.handle_event(AgentEvent::ChunkCompleted { exit_code: 1 });
        assert_eq!(state.chunks_completed, 2);
    }

    #[test]
    fn test_chunk_failed_clears_chunk() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a".to_string(),
        });

        state.handle_event(AgentEvent::ChunkFailed {
            error: "hashcat segfault".to_string(),
        });
        assert!(state.current_chunk.is_none());
        // Failed chunks do NOT increment chunks_completed
        assert_eq!(state.chunks_completed, 0);
    }

    // ── Event handling: hash cracking ──

    #[test]
    fn test_hash_cracked_updates_counters() {
        let mut state = make_state();
        let (task_id, chunk_id) = make_chunk_id();

        state.handle_event(AgentEvent::ChunkAssigned {
            task_id,
            chunk_id,
            hash_mode: 1000,
            mask: "?a?a?a?a".to_string(),
        });

        state.handle_event(AgentEvent::HashCracked {
            hash: "5d41402abc4b2a76b9719d911017c592".to_string(),
            plaintext: "hello".to_string(),
        });

        assert_eq!(state.total_cracked, 1);
        assert_eq!(state.current_chunk.as_ref().unwrap().cracked_this_chunk, 1);
        assert_eq!(state.recent_cracks.len(), 1);
        assert_eq!(state.recent_cracks[0].1, "hello");
    }

    #[test]
    fn test_hash_cracked_without_chunk_still_counts() {
        let mut state = make_state();
        // Crack without active chunk — should still record
        state.handle_event(AgentEvent::HashCracked {
            hash: "abc123".to_string(),
            plaintext: "pass".to_string(),
        });
        assert_eq!(state.total_cracked, 1);
        assert_eq!(state.recent_cracks.len(), 1);
    }

    #[test]
    fn test_hash_truncation_short() {
        let mut state = make_state();
        state.handle_event(AgentEvent::HashCracked {
            hash: "short".to_string(),
            plaintext: "pw".to_string(),
        });
        // Hash <= 12 chars should NOT be truncated
        assert_eq!(state.recent_cracks[0].0, "short");
    }

    #[test]
    fn test_hash_truncation_long() {
        let mut state = make_state();
        state.handle_event(AgentEvent::HashCracked {
            hash: "5d41402abc4b2a76b9719d911017c592".to_string(),
            plaintext: "hello".to_string(),
        });
        // Hash > 12 chars should be truncated to 12 + "..."
        assert_eq!(state.recent_cracks[0].0, "5d41402abc4b...");
    }

    #[test]
    fn test_recent_cracks_max_10() {
        let mut state = make_state();
        for i in 0..15 {
            state.handle_event(AgentEvent::HashCracked {
                hash: format!("hash_{i:02}"),
                plaintext: format!("plain_{i}"),
            });
        }
        assert_eq!(state.recent_cracks.len(), 10);
        assert_eq!(state.total_cracked, 15);
        // Most recent should be first
        assert_eq!(state.recent_cracks[0].1, "plain_14");
        // Oldest visible should be #5 (0-4 were evicted)
        assert_eq!(state.recent_cracks[9].1, "plain_5");
    }

    #[test]
    fn test_recent_cracks_ordering() {
        let mut state = make_state();
        state.handle_event(AgentEvent::HashCracked {
            hash: "first".to_string(),
            plaintext: "pw1".to_string(),
        });
        state.handle_event(AgentEvent::HashCracked {
            hash: "second".to_string(),
            plaintext: "pw2".to_string(),
        });
        // Most recent first
        assert_eq!(state.recent_cracks[0].1, "pw2");
        assert_eq!(state.recent_cracks[1].1, "pw1");
    }

    // ── Full lifecycle simulation ──

    #[test]
    fn test_full_lifecycle() {
        let mut state = make_state();

        // 1. Connect
        state.handle_event(AgentEvent::Connected { worker_id: "w-1".to_string() });
        assert!(matches!(state.connection_status, ConnectionStatus::Connected));

        // 2. Get chunk
        let (tid, cid) = make_chunk_id();
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id: tid, chunk_id: cid,
            hash_mode: 1000, mask: "?a?a?a?a".to_string(),
        });

        // 3. Progress updates
        state.handle_event(AgentEvent::ChunkProgress {
            progress_pct: 25.0, speed: 5_000_000, est_remaining: Some(300),
        });
        state.handle_event(AgentEvent::ChunkProgress {
            progress_pct: 50.0, speed: 5_500_000, est_remaining: Some(150),
        });

        // 4. Crack some hashes
        state.handle_event(AgentEvent::HashCracked {
            hash: "aaaa".to_string(), plaintext: "test1".to_string(),
        });
        state.handle_event(AgentEvent::HashCracked {
            hash: "bbbb".to_string(), plaintext: "test2".to_string(),
        });

        // Verify mid-chunk state
        let chunk = state.current_chunk.as_ref().unwrap();
        assert!((chunk.progress_pct - 50.0).abs() < f64::EPSILON);
        assert_eq!(chunk.cracked_this_chunk, 2);
        assert_eq!(state.total_cracked, 2);

        // 5. Chunk completes
        state.handle_event(AgentEvent::ChunkCompleted { exit_code: 0 });
        assert!(state.current_chunk.is_none());
        assert_eq!(state.chunks_completed, 1);

        // 6. Disconnect + reconnect
        state.handle_event(AgentEvent::Disconnected);
        assert!(matches!(state.connection_status, ConnectionStatus::Disconnected));

        state.handle_event(AgentEvent::Reconnecting { attempt: 1 });
        assert_eq!(state.reconnect_count, 1);

        state.handle_event(AgentEvent::Connected { worker_id: "w-1".to_string() });

        // 7. Second chunk + failure
        let (tid2, cid2) = make_chunk_id();
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id: tid2, chunk_id: cid2,
            hash_mode: 2500, mask: "?d?d?d?d?d?d?d?d".to_string(),
        });
        state.handle_event(AgentEvent::ChunkFailed {
            error: "GPU memory error".to_string(),
        });
        assert!(state.current_chunk.is_none());
        assert_eq!(state.chunks_completed, 1); // failed chunk not counted

        // Verify final counters
        assert_eq!(state.total_cracked, 2);
        assert_eq!(state.recent_cracks.len(), 2);
        assert_eq!(state.reconnect_count, 1);
    }

    // ── New chunk replaces old chunk ──

    #[test]
    fn test_new_chunk_replaces_current() {
        let mut state = make_state();

        let (tid1, cid1) = make_chunk_id();
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id: tid1, chunk_id: cid1,
            hash_mode: 1000, mask: "?a?a".to_string(),
        });

        // Assign second chunk without completing the first (edge case)
        let (tid2, cid2) = make_chunk_id();
        state.handle_event(AgentEvent::ChunkAssigned {
            task_id: tid2, chunk_id: cid2,
            hash_mode: 2500, mask: "?d?d?d?d".to_string(),
        });

        let chunk = state.current_chunk.as_ref().unwrap();
        assert_eq!(chunk.task_id, tid2);
        assert_eq!(chunk.hash_mode, 2500);
    }
}
