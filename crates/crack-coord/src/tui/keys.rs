use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Recognized key actions for the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    Quit,
    Up,
    Down,
    Top,
    Bottom,
    PageUp,
    PageDown,
    Enter,
    Tab,
    BackTab,
    Help,
    Tab1,
    Tab2,
    Tab3,
    Tab4,
    Tab5,
    Escape,
    EnterCommand,
    EnterSearch,
    None,
}

/// Map a key event to a key action (vim-style keybindings).
/// Only used in Normal mode — Command/Search modes handle keys directly.
pub fn map_key(key: KeyEvent) -> KeyAction {
    match key.code {
        KeyCode::Char('q') if key.modifiers.is_empty() => KeyAction::Quit,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::Quit,
        KeyCode::Char('k') | KeyCode::Up => KeyAction::Up,
        KeyCode::Char('j') | KeyCode::Down => KeyAction::Down,
        KeyCode::Char('g') => KeyAction::Top,
        KeyCode::Char('G') => KeyAction::Bottom,
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::PageUp,
        KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => KeyAction::PageDown,
        KeyCode::Enter => KeyAction::Enter,
        KeyCode::Tab => KeyAction::Tab,
        KeyCode::BackTab => KeyAction::BackTab,
        KeyCode::Char('?') => KeyAction::Help,
        KeyCode::Char('1') => KeyAction::Tab1,
        KeyCode::Char('2') => KeyAction::Tab2,
        KeyCode::Char('3') => KeyAction::Tab3,
        KeyCode::Char('4') => KeyAction::Tab4,
        KeyCode::Char('5') => KeyAction::Tab5,
        KeyCode::Char(':') => KeyAction::EnterCommand,
        KeyCode::Char('/') => KeyAction::EnterSearch,
        KeyCode::Esc => KeyAction::Escape,
        _ => KeyAction::None,
    }
}
