use crack_common::models::*;

/// Active tab in the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Tasks,
    Workers,
    Results,
    AuditLog,
}

impl ActiveTab {
    pub fn index(&self) -> usize {
        match self {
            Self::Tasks => 0,
            Self::Workers => 1,
            Self::Results => 2,
            Self::AuditLog => 3,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Self::Tasks,
            1 => Self::Workers,
            2 => Self::Results,
            3 => Self::AuditLog,
            _ => Self::Tasks,
        }
    }

    pub fn next(&self) -> Self {
        Self::from_index((self.index() + 1) % 4)
    }

    pub fn prev(&self) -> Self {
        Self::from_index((self.index() + 3) % 4)
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

    // Cached data (refreshed each tick)
    pub tasks: Vec<Task>,
    pub workers: Vec<Worker>,
    pub results: Vec<CrackedHash>,
    pub audit_entries: Vec<AuditEntry>,
    pub chunks: Vec<Chunk>,
    pub status: Option<SystemStatus>,
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
            tasks: Vec::new(),
            workers: Vec::new(),
            results: Vec::new(),
            audit_entries: Vec::new(),
            chunks: Vec::new(),
            status: None,
        }
    }

    /// Get the currently selected list length for the active tab.
    pub fn current_list_len(&self) -> usize {
        match self.active_tab {
            ActiveTab::Tasks => self.tasks.len(),
            ActiveTab::Workers => self.workers.len(),
            ActiveTab::Results => self.results.len(),
            ActiveTab::AuditLog => self.audit_entries.len(),
        }
    }

    /// Get the currently selected index for the active tab.
    pub fn current_index(&self) -> usize {
        match self.active_tab {
            ActiveTab::Tasks => self.task_list_index,
            ActiveTab::Workers => self.worker_list_index,
            ActiveTab::Results => self.result_list_index,
            ActiveTab::AuditLog => self.audit_list_index,
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
}
