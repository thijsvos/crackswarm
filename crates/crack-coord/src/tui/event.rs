use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent};
use tokio::sync::mpsc;

/// Terminal events (keyboard input, resize, tick).
#[derive(Debug)]
pub enum TermEvent {
    Key(KeyEvent),
    Resize(u16, u16),
    Tick,
}

/// Spawn a background thread that polls for terminal events and ticks.
pub fn spawn_event_reader(tick_rate: Duration) -> mpsc::UnboundedReceiver<TermEvent> {
    let (tx, rx) = mpsc::unbounded_channel();

    std::thread::spawn(move || {
        loop {
            if event::poll(tick_rate).unwrap_or(false) {
                match event::read() {
                    Ok(Event::Key(key)) => {
                        if tx.send(TermEvent::Key(key)).is_err() {
                            return;
                        }
                    }
                    Ok(Event::Resize(w, h)) => {
                        if tx.send(TermEvent::Resize(w, h)).is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            } else {
                // Tick event for periodic TUI refresh
                if tx.send(TermEvent::Tick).is_err() {
                    return;
                }
            }
        }
    });

    rx
}
