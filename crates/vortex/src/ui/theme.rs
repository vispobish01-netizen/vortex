use ratatui::{
    prelude::*,
    widgets::{Block, BorderType},
};
use std::borrow::Cow;
use vortex_core::store::Kind;

pub const BLACK: Color = Color::Rgb(0x00, 0x0a, 0x0d);
pub const BG_DARK: Color = Color::Rgb(0x06, 0x17, 0x1c);
pub const FG: Color = Color::Rgb(0xd2, 0xf7, 0xee); // Phosphor Ice-White
pub const FG_DIM: Color = Color::Rgb(0x60, 0x8a, 0x8e); // Tactical Cyan-Gray
pub const DIM: Color = Color::Rgb(0x2a, 0x46, 0x4c); // Dark Matrix Dim
pub const CYAN: Color = Color::Rgb(0x00, 0xf0, 0xff); // Electric Cyan
pub const PURPLE: Color = Color::Rgb(0xbd, 0x42, 0xff); // Plasma Violet
pub const BLUE: Color = Color::Rgb(0x2d, 0x9c, 0xff); // Cobalt Blue
pub const GREEN: Color = Color::Rgb(0x00, 0xff, 0x66); // Neon Lime Phosphor
pub const YELLOW: Color = Color::Rgb(0xff, 0xb8, 0x00); // Amber Warning
pub const RED: Color = Color::Rgb(0xff, 0x22, 0x55); // Breach Red
pub const BORDER: Color = Color::Rgb(0x16, 0x3d, 0x44); // Deep Cyber Teal Border
pub const BORDER_ACTIVE: Color = Color::Rgb(0x00, 0xf0, 0xff); // Active Cyan Frame
pub const SEL_BG: Color = Color::Rgb(0x0a, 0x26, 0x2c); // Tactical Selection Glow
pub const SEL_FG: Color = Color::Rgb(0x00, 0xff, 0xcc); // Highlight Active
pub const SPIN: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
pub const HIST: usize = 240;


pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < 3 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn fmt_dur(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60)
}

pub fn kind_color(k: Kind) -> Color {
    match k {
        Kind::Vless => CYAN,
        Kind::Vmess => Color::Rgb(0x00, 0xdf, 0xa2), // Mint Green
        Kind::Trojan => BLUE,
        Kind::Hy2 => PURPLE,
        Kind::Tuic => Color::Rgb(0xd9, 0x46, 0xef), // Fuchsia
        Kind::Ss => Color::Rgb(0x06, 0xb6, 0xd4),   // Electric Teal
        Kind::Wg => GREEN,
        Kind::Awg => Color::Rgb(0x10, 0xb9, 0x81), // Emerald
        Kind::Ovpn => YELLOW,
        Kind::Xray => Color::Rgb(0x00, 0xf0, 0xff), // Electric Cyan
    }
}

pub fn kind_badge(k: Kind) -> &'static str {
    match k {
        Kind::Vless => "VLESS",
        Kind::Vmess => "VMESS",
        Kind::Trojan => "TROJN",
        Kind::Ss => "SS-AE",
        Kind::Hy2 => "HYST2",
        Kind::Tuic => "TUIC ",
        Kind::Wg => "WG-0 ",
        Kind::Awg => "AMN-W",
        Kind::Ovpn => "OVPN ",
        Kind::Xray => "X-RAY",
    }
}

pub fn ms_color(ms: u32) -> Color {
    if ms < 60 {
        GREEN
    } else if ms < 120 {
        CYAN
    } else if ms < 250 {
        YELLOW
    } else {
        RED
    }
}

pub const SPACES: &str = "                                                                                                                        ";

pub fn spaces(n: usize) -> &'static str {
    &SPACES[..n.min(SPACES.len())]
}

pub fn trunc<'a>(s: &'a str, n: usize) -> Cow<'a, str> {
    if s.chars().count() <= n {
        Cow::Borrowed(s)
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        Cow::Owned(out)
    }
}

pub fn block(title: &str, active: bool) -> Block<'static> {
    let border_color = if active { BORDER_ACTIVE } else { BORDER };
    Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(border_color))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(border_color)),
            Span::styled(
                title.to_string(),
                Style::new().fg(if active { CYAN } else { FG }).bold(),
            ),
            Span::styled(" ] ", Style::new().fg(border_color)),
        ]))
}

pub fn kv<'a>(k: &str, v: impl Into<Cow<'a, str>>, c: Color) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!(" {:<11} ", k.to_ascii_uppercase()),
            Style::new().fg(FG_DIM).bold(),
        ),
        Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
        Span::styled(v.into(), Style::new().fg(c).bold()),
    ])
}

