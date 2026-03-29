use ratatui::style::Color;

/// Catppuccin Mocha color palette.
pub struct Theme;

#[allow(dead_code)]
impl Theme {
    // Base colors
    pub const BASE: Color = Color::Rgb(30, 30, 46);
    pub const MANTLE: Color = Color::Rgb(24, 24, 37);
    pub const CRUST: Color = Color::Rgb(17, 17, 27);
    pub const SURFACE0: Color = Color::Rgb(49, 50, 68);
    pub const SURFACE1: Color = Color::Rgb(69, 71, 90);
    pub const SURFACE2: Color = Color::Rgb(88, 91, 112);

    // Text colors
    pub const TEXT: Color = Color::Rgb(205, 214, 244);
    pub const SUBTEXT0: Color = Color::Rgb(166, 173, 200);
    pub const SUBTEXT1: Color = Color::Rgb(186, 194, 222);
    pub const OVERLAY0: Color = Color::Rgb(108, 112, 134);

    // Accent colors
    pub const BLUE: Color = Color::Rgb(137, 180, 250);
    pub const GREEN: Color = Color::Rgb(166, 227, 161);
    pub const RED: Color = Color::Rgb(243, 139, 168);
    pub const YELLOW: Color = Color::Rgb(249, 226, 175);
    pub const PEACH: Color = Color::Rgb(250, 179, 135);
    pub const MAUVE: Color = Color::Rgb(203, 166, 247);
    pub const TEAL: Color = Color::Rgb(148, 226, 213);
    pub const LAVENDER: Color = Color::Rgb(180, 190, 254);
    pub const SAPPHIRE: Color = Color::Rgb(116, 199, 236);
    pub const ROSEWATER: Color = Color::Rgb(245, 224, 220);
}

/// Status indicator colors.
pub fn status_color(status: &str) -> Color {
    match status {
        "running" | "working" | "idle" => Theme::GREEN,
        "pending" | "ready" | "dispatched" | "benchmarking" => Theme::YELLOW,
        "completed" | "exhausted" => Theme::BLUE,
        "failed" | "disconnected" | "abandoned" => Theme::RED,
        "cancelled" | "draining" => Theme::PEACH,
        _ => Theme::SUBTEXT0,
    }
}

/// Status indicator symbol.
pub fn status_icon(status: &str) -> &'static str {
    match status {
        "idle" | "running" | "working" => "●",
        "disconnected" => "○",
        "benchmarking" => "◐",
        "draining" => "◑",
        _ => "•",
    }
}
