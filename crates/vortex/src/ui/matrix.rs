use super::*;
use crate::keymap::Mode;
use ratatui::{prelude::*, widgets::*};
use vortex_core::ping::Ping;

pub(crate) fn ping_cell(app: &App, id: &str) -> Span<'static> {
    if app.pending.contains(id) {
        return Span::styled("  ⌁ PROBING ", Style::new().fg(CYAN).bold());
    }
    match app.pings.get(id) {
        Some(Ping::Ms(ms)) => {
            let (bars, col) = if *ms < 60 {
                ("▰▰▰▰▰", GREEN)
            } else if *ms < 120 {
                ("▰▰▰▰▱", CYAN)
            } else if *ms < 250 {
                ("▰▰▰▱▱", YELLOW)
            } else if *ms < 400 {
                ("▰▰▱▱▱", Color::Rgb(0xff, 0x88, 0x00))
            } else {
                ("▰▱▱▱▱", RED)
            };
            Span::styled(format!("{bars} {ms:>3}ms "), Style::new().fg(col).bold())
        }
        Some(Ping::Timeout) => Span::styled("  ✕ TIMEOUT ", Style::new().fg(RED).bold()),
        None => Span::styled(" ▱▱▱▱▱ --ms ", Style::new().fg(DIM)),
    }
}

pub(crate) fn profiles(f: &mut Frame, area: Rect, app: &mut App) {
    let is_focused = app.focused_panel == 1;
    let mut title = format!("[1] TARGET MATRIX [ {:02} NODES ]", app.view.len());
    if !app.filter.is_empty() {
        title = format!(
            "[1] TARGET MATRIX [ SCAN: \"{}\"█ · {} MATCHES ]",
            trunc(&app.filter, 12),
            app.view.len()
        );
    } else {
        match app.sort_mode {
            SortMode::Latency => {
                title = format!("[1] TARGET MATRIX [ {:02} NODES · ↑RTT ]", app.view.len());
            }
            SortMode::Transport => {
                title = format!(
                    "[1] TARGET MATRIX [ {:02} NODES · TRANSPORT ]",
                    app.view.len()
                );
            }
            SortMode::Name => {
                if app.sort_ping {
                    title = format!("[1] TARGET MATRIX [ {:02} NODES · ↑RTT ]", app.view.len());
                } else if app.transport_filter != TransportFilter::All {
                    title = format!(
                        "[1] TARGET MATRIX [ {:02} NODES · {} ]",
                        app.view.len(),
                        app.transport_filter.label()
                    );
                }
            }
        }
    }
    if let Mode::Search(s) = &app.mode {
        title = format!("[1] TARGET MATRIX [ SEARCH: \"{}\"█ ]", trunc(s, 16));
    }
    let blk = block(&title, is_focused);
    if app.view.is_empty() {
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let msg = if app.profiles.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "[!] NO TARGET TUNNELS CONFIGURED",
                    Style::new().fg(YELLOW).bold(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "  A  // INJECT LINK · SUBSCRIPTION · FILE",
                    Style::new().fg(CYAN),
                )),
                Line::from(Span::styled(
                    "  V  // INJECT TARGET FROM CLIPBOARD",
                    Style::new().fg(FG_DIM),
                )),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "[!] PATTERN SCAN: NO MATCHING TARGETS",
                    Style::new().fg(RED).bold(),
                )),
                Line::from(Span::styled(
                    "  ESC // CLEAR SCAN FILTER",
                    Style::new().fg(FG_DIM),
                )),
            ]
        };
        f.render_widget(Paragraph::new(msg).alignment(Alignment::Center), inner);
        return;
    }
    let w = (area.width as usize).saturating_sub(4);
    let active = app.session.as_ref().map(|s| s.id.clone());
    let show_transport = f.area().width >= 100;
    let transport_col_w = if show_transport { 12 } else { 0 }; // 1 space + 11 chars
    let fixed_w = 4 + 3 + 12 + 1 + 7 + 1 + transport_col_w; // marker(4) + num(3) + ping(12) + space(1) + tag(7) + space(1) [+ transport]
    let items: Vec<ListItem> = app
        .view
        .iter()
        .enumerate()
        .map(|(idx, &i)| {
            let p = &app.profiles[i];
            let on = active.as_deref() == Some(p.id.as_str());
            let num = format!("{:02} ", idx + 1);
            let tag_str = format!("[{}]", kind_badge(p.kind));
            let nw = w.saturating_sub(fixed_w).max(4);
            let name = trunc(&p.name, nw);
            let pad = nw.saturating_sub(name.chars().count());
            let mut spans = vec![
                Span::styled(
                    if on { "[●] " } else { "[○] " },
                    Style::new().fg(if on { GREEN } else { DIM }).bold(),
                ),
                Span::styled(num, Style::new().fg(if on { GREEN } else { FG_DIM })),
                Span::styled(
                    name.into_owned(),
                    Style::new().fg(if on { GREEN } else { FG }).bold(),
                ),
                Span::raw(spaces(pad + 1)),
                ping_cell(app, &p.id),
                Span::raw(" "),
                Span::styled(tag_str, Style::new().fg(kind_color(p.kind)).bold()),
            ];
            if show_transport {
                spans.push(Span::raw(" "));
                spans.push(Span::styled(
                    format!("{:<11}", trunc(&p.display_transport(), 11)),
                    Style::new().fg(FG_DIM),
                ));
            }
            Line::from(spans).into()
        })
        .collect();
    let list = List::new(items)
        .block(blk)
        .highlight_style(Style::new().bg(SEL_BG).fg(SEL_FG).bold())
        .highlight_symbol("► ");
    f.render_stateful_widget(list, area, &mut app.list);
}

