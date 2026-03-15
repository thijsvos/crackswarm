use std::collections::VecDeque;
use std::time::Instant;

use crack_common::models::*;

/// Input mode for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Command,
    Search,
}

/// Notification severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationLevel {
    Info,
    Success,
    Error,
}

/// Active tab in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Tasks,
    Workers,
    Results,
    AuditLog,
    Campaigns,
}

impl ActiveTab {
    pub fn index(&self) -> usize {
        match self {
            Self::Tasks => 0,
            Self::Workers => 1,
            Self::Results => 2,
            Self::AuditLog => 3,
            Self::Campaigns => 4,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Self::Tasks,
            1 => Self::Workers,
            2 => Self::Results,
            3 => Self::AuditLog,
            4 => Self::Campaigns,
            _ => Self::Tasks,
        }
    }

    pub fn next(&self) -> Self {
        Self::from_index((self.index() + 1) % 5)
    }

    pub fn prev(&self) -> Self {
        Self::from_index((self.index() + 4) % 5)
    }
}

/// Which panel has focus in the split-pane layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPanel {
    Left,
    Right,
}

/// TUI application state (separate from the server's AppState).
pub struct TuiState {
    pub active_tab: ActiveTab,
    pub focus: FocusPanel,
    pub show_help: bool,
    pub should_quit: bool,

    // List selections
    pub task_list_index: usize,
    pub worker_list_index: usize,
    pub result_list_index: usize,
    pub audit_list_index: usize,
    pub campaign_list_index: usize,

    // Chunk scroll (for right panel on Tasks tab)
    pub chunk_scroll_offset: usize,

    // Input mode (command bar / search)
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub search_filter: String,

    // Toast notifications
    pub notifications: VecDeque<(String, Instant, NotificationLevel)>,

    // Cached data (refreshed each tick)
    pub tasks: Vec<Task>,
    pub workers: Vec<Worker>,
    pub results: Vec<CrackedHash>,
    pub audit_entries: Vec<AuditEntry>,
    pub chunks: Vec<Chunk>,
    pub status: Option<SystemStatus>,
    pub campaigns: Vec<Campaign>,
    pub campaign_phases: Vec<CampaignPhase>,
}

impl TuiState {
    pub fn new() -> Self {
        Self {
            active_tab: ActiveTab::Tasks,
            focus: FocusPanel::Left,
            show_help: false,
            should_quit: false,
            task_list_index: 0,
            worker_list_index: 0,
            result_list_index: 0,
            audit_list_index: 0,
            campaign_list_index: 0,
            chunk_scroll_offset: 0,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            search_filter: String::new(),
            notifications: VecDeque::new(),
            tasks: Vec::new(),
            workers: Vec::new(),
            results: Vec::new(),
            audit_entries: Vec::new(),
            chunks: Vec::new(),
            status: None,
            campaigns: Vec::new(),
            campaign_phases: Vec::new(),
        }
    }

    /// Get the currently selected list length for the active tab.
    pub fn current_list_len(&self) -> usize {
        match self.active_tab {
            ActiveTab::Tasks => self.tasks.len(),
            ActiveTab::Workers => self.workers.len(),
            ActiveTab::Results => self.results.len(),
            ActiveTab::AuditLog => self.audit_entries.len(),
            ActiveTab::Campaigns => self.campaigns.len(),
        }
    }

    /// Get the currently selected index for the active tab.
    pub fn current_index(&self) -> usize {
        match self.active_tab {
            ActiveTab::Tasks => self.task_list_index,
            ActiveTab::Workers => self.worker_list_index,
            ActiveTab::Results => self.result_list_index,
            ActiveTab::AuditLog => self.audit_list_index,
            ActiveTab::Campaigns => self.campaign_list_index,
        }
    }

    /// Set the currently selected index for the active tab.
    pub fn set_current_index(&mut self, i: usize) {
        let max = self.current_list_len().saturating_sub(1);
        let clamped = i.min(max);
        match self.active_tab {
            ActiveTab::Tasks => self.task_list_index = clamped,
            ActiveTab::Workers => self.worker_list_index = clamped,
            ActiveTab::Results => self.result_list_index = clamped,
            ActiveTab::AuditLog => self.audit_list_index = clamped,
            ActiveTab::Campaigns => self.campaign_list_index = clamped,
        }
    }

    pub fn move_up(&mut self) {
        let idx = self.current_index();
        if idx > 0 {
            self.set_current_index(idx - 1);
        }
    }

    pub fn move_down(&mut self) {
        let idx = self.current_index();
        self.set_current_index(idx + 1);
    }

    pub fn move_top(&mut self) {
        self.set_current_index(0);
    }

    pub fn move_bottom(&mut self) {
        let len = self.current_list_len();
        if len > 0 {
            self.set_current_index(len - 1);
        }
    }

    pub fn page_up(&mut self) {
        let idx = self.current_index();
        self.set_current_index(idx.saturating_sub(10));
    }

    pub fn page_down(&mut self) {
        let idx = self.current_index();
        self.set_current_index(idx + 10);
    }

    /// Get the selected task (if any).
    pub fn selected_task(&self) -> Option<&Task> {
        self.tasks.get(self.task_list_index)
    }

    /// Get the selected worker (if any).
    pub fn selected_worker(&self) -> Option<&Worker> {
        self.workers.get(self.worker_list_index)
    }

    /// Get the selected campaign (if any).
    pub fn selected_campaign(&self) -> Option<&Campaign> {
        self.campaigns.get(self.campaign_list_index)
    }

    /// Add a toast notification.
    pub fn notify(&mut self, msg: String, level: NotificationLevel) {
        self.notifications.push_back((msg, Instant::now(), level));
        // Keep at most 5 notifications
        while self.notifications.len() > 5 {
            self.notifications.pop_front();
        }
    }

    /// Remove expired notifications (older than 5 seconds).
    pub fn expire_notifications(&mut self) {
        let cutoff = Instant::now() - std::time::Duration::from_secs(5);
        while let Some((_, ts, _)) = self.notifications.front() {
            if *ts < cutoff {
                self.notifications.pop_front();
            } else {
                break;
            }
        }
    }

    /// Get the filtered list length for the active tab (respecting search filter).
    #[allow(dead_code)]
    pub fn filtered_list_len(&self) -> usize {
        if self.search_filter.is_empty() {
            return self.current_list_len();
        }
        let filter = self.search_filter.to_lowercase();
        match self.active_tab {
            ActiveTab::Tasks => self.tasks.iter().filter(|t| t.name.to_lowercase().contains(&filter)).count(),
            ActiveTab::Workers => self.workers.iter().filter(|w| w.name.to_lowercase().contains(&filter)).count(),
            ActiveTab::Results => self.results.iter().filter(|r| r.hash.to_lowercase().contains(&filter) || r.plaintext.to_lowercase().contains(&filter)).count(),
            ActiveTab::AuditLog => self.audit_entries.iter().filter(|a| a.details.to_lowercase().contains(&filter)).count(),
            ActiveTab::Campaigns => self.campaigns.iter().filter(|c| c.name.to_lowercase().contains(&filter)).count(),
        }
    }

    /// Apply a data snapshot from the background refresh task.
    pub fn apply_data(&mut self, data: TuiData) {
        self.tasks = data.tasks;
        self.workers = data.workers;
        self.results = data.results;
        self.audit_entries = data.audit_entries;
        self.status = data.status;
        self.campaigns = data.campaigns;

        if let Some(chunks) = data.chunks {
            self.chunks = chunks;
        }
        if let Some(phases) = data.campaign_phases {
            self.campaign_phases = phases;
        }
    }
}

/// Snapshot of all data fetched by the background refresh task.
pub struct TuiData {
    pub tasks: Vec<Task>,
    pub workers: Vec<Worker>,
    pub results: Vec<CrackedHash>,
    pub audit_entries: Vec<AuditEntry>,
    pub chunks: Option<Vec<Chunk>>,
    pub status: Option<SystemStatus>,
    pub campaigns: Vec<Campaign>,
    pub campaign_phases: Option<Vec<CampaignPhase>>,
}
