use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crack_common::models::*;

use crate::tui::app::{FocusPanel, TuiState};
use crate::tui::theme::Theme;

pub fn render_campaign_list(f: &mut Frame, area: Rect, state: &TuiState) {
    let focused = state.focus == FocusPanel::Left;
    let border_color = if focused { Theme::BLUE } else { Theme::SURFACE1 };

    let block = Block::default()
        .title(" Campaigns ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    if state.campaigns.is_empty() {
        let msg = Paragraph::new(" No campaigns").style(Style::default().fg(Theme::OVERLAY0)).block(block);
        f.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = state
        .campaigns
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let selected = i == state.campaign_list_index;
            let status_color = match c.status {
                CampaignStatus::Running => Theme::GREEN,
                CampaignStatus::Completed => Theme::BLUE,
                CampaignStatus::Failed => Theme::RED,
                CampaignStatus::Cancelled => Theme::YELLOW,
                CampaignStatus::Draft => Theme::OVERLAY0,
            };

            let phase_info = c
                .active_phase_index
                .map(|i| format!("{}/{}", i + 1, c.total_phases))
                .unwrap_or_else(|| "-".to_string());

            let line = Line::from(vec![
                Span::styled(
                    format!(" {:<20}", truncate(&c.name, 18)),
                    Style::default().fg(if selected { Theme::TEXT } else { Theme::SUBTEXT0 }),
                ),
                Span::styled(
                    format!("{:<10}", c.status),
                    Style::default().fg(status_color),
                ),
                Span::styled(
                    format!("{}/{}", c.cracked_count, c.total_hashes),
                    Style::default().fg(Theme::TEAL),
                ),
                Span::styled(
                    format!("  P:{phase_info}"),
                    Style::default().fg(Theme::OVERLAY0),
                ),
            ]);

            let style = if selected {
                Style::default().bg(Theme::SURFACE0).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    f.render_widget(list, area);
}

pub fn render_campaign_detail(f: &mut Frame, area: Rect, state: &TuiState) {
    let focused = state.focus == FocusPanel::Right;
    let border_color = if focused { Theme::BLUE } else { Theme::SURFACE1 };

    let block = Block::default()
        .title(" Phase Detail ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let Some(campaign) = state.selected_campaign() else {
        let msg = Paragraph::new(" Select a campaign")
            .style(Style::default().fg(Theme::OVERLAY0))
            .block(block);
        f.render_widget(msg, area);
        return;
    };

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  ID: ", Style::default().fg(Theme::OVERLAY0)),
            Span::styled(campaign.id.to_string(), Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Mode: ", Style::default().fg(Theme::OVERLAY0)),
            Span::styled(campaign.hash_mode.to_string(), Style::default().fg(Theme::TEXT)),
        ]),
        Line::from(vec![
            Span::styled("  Progress: ", Style::default().fg(Theme::OVERLAY0)),
            Span::styled(
                format!("{}/{}", campaign.cracked_count, campaign.total_hashes),
                Style::default().fg(Theme::TEAL),
            ),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "  Phases:",
            Style::default().fg(Theme::MAUVE).add_modifier(Modifier::BOLD),
        )),
    ];

    for phase in &state.campaign_phases {
        let status_icon = match phase.status {
            PhaseStatus::Pending => "\u{25cb}",   // ○
            PhaseStatus::Running => "\u{25cf}",   // ●
            PhaseStatus::Completed => "\u{2714}", // ✔
            PhaseStatus::Exhausted => "\u{2713}", // ✓
            PhaseStatus::Failed => "\u{2718}",    // ✘
            PhaseStatus::Skipped => "\u{2192}",   // →
        };

        let status_color = match phase.status {
            PhaseStatus::Running => Theme::GREEN,
            PhaseStatus::Completed => Theme::BLUE,
            PhaseStatus::Exhausted => Theme::TEAL,
            PhaseStatus::Failed => Theme::RED,
            PhaseStatus::Skipped => Theme::OVERLAY0,
            PhaseStatus::Pending => Theme::SUBTEXT0,
        };

        lines.push(Line::from(vec![
            Span::styled(
                format!("  {status_icon} {}. ", phase.phase_index + 1),
                Style::default().fg(status_color),
            ),
            Span::styled(
                truncate(&phase.name, 20),
                Style::default().fg(Theme::TEXT),
            ),
            Span::styled(
                format!("  [{}]", phase.status),
                Style::default().fg(status_color),
            ),
            if phase.cracked_count > 0 {
                Span::styled(
                    format!("  +{}", phase.cracked_count),
                    Style::default().fg(Theme::TEAL),
                )
            } else {
                Span::raw("")
            },
        ]));
    }

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}
