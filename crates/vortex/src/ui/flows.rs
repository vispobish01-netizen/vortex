use super::*;
use ratatui::{prelude::*, widgets::*};
use vortex_core::tunnel::ActiveFlow;

pub(crate) fn extract_dst_port(flow: &ActiveFlow) -> String {
    let parse_p = |s: &str| -> Option<String> {
        if let Some(pos) = s.rfind(':') {
            let part = &s[pos + 1..];
            if !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()) {
                return Some(part.to_string());
            }
        }
        None
    };
    parse_p(&flow.destination)
        .or_else(|| parse_p(&flow.host))
        .unwrap_or_else(|| "--".to_string())
}

pub(crate) fn flows_table(f: &mut Frame, area: Rect, app: &App) {
    let blk = block(
        &format!("0x03 // [3] PACKET FLOWS [ {:02} ACTIVE ]", app.flows.len()),
        app.focused_panel == 3,
    );
    let inner = blk.inner(area).inner(Margin::new(1, 0));
    f.render_widget(blk, area);

    let tcp_count = app
        .flows
        .iter()
        .filter(|f| f.network.eq_ignore_ascii_case("tcp"))
        .count();
    let udp_count = app
        .flows
        .iter()
        .filter(|f| f.network.eq_ignore_ascii_case("udp"))
        .count();
    let icmp_count = app
        .flows
        .iter()
        .filter(|f| f.network.eq_ignore_ascii_case("icmp"))
        .count();

    if app.flows.is_empty() {
        let msg = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                "  TCP 0 · UDP 0",
                Style::new().fg(FG_DIM).bold(),
            )]),
            Line::from(""),
            Line::from(Span::styled(
                "[○] NO ACTIVE FLOWS INTERCEPTED // SYSTEM IDLE",
                Style::new().fg(FG_DIM).bold(),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  ◈ SOCKS5/HTTP PROXY: ", Style::new().fg(DIM).bold()),
                Span::styled("127.0.0.1:1080", Style::new().fg(CYAN).bold()),
                Span::styled(
                    " (READY FOR BURP / NMAP / CURL / PROXYCHAINS)",
                    Style::new().fg(FG_DIM),
                ),
            ]),
            Line::from(vec![
                Span::styled("  ◈ CLASH API BRIDGE : ", Style::new().fg(DIM).bold()),
                Span::styled("127.0.0.1:9090", Style::new().fg(PURPLE).bold()),
                Span::styled(" (TRAFFIC CONTROLLER READY)", Style::new().fg(FG_DIM)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "  [F] TOGGLE SPECTRUM / FLOWS  ·  [W] BENCHMARK SPEED",
                Style::new().fg(FG_DIM),
            )]),
        ];
        f.render_widget(Paragraph::new(msg), inner);
        return;
    }

    let filtered_flows: Vec<_> = app
        .flows
        .iter()
        .filter(|flow| app.flows_filter.matches_flow(flow))
        .collect();

    let mut lines = vec![];

    let summary_line = Line::from(vec![
        Span::styled(
            format!("TCP {tcp_count} · UDP {udp_count}"),
            Style::new().fg(FG).bold(),
        ),
        if icmp_count > 0 {
            Span::styled(
                format!(" · ICMP {icmp_count}"),
                Style::new().fg(YELLOW).bold(),
            )
        } else {
            Span::raw("")
        },
        Span::styled(
            format!("   [FILTER: {}] [P] CYCLE", app.flows_filter.label()),
            Style::new().fg(FG_DIM),
        ),
    ]);
    lines.push(summary_line);

    let header_line = if inner.width >= 75 {
        Line::from(vec![
            Span::styled(" PROTO ", Style::new().fg(CYAN).bold()),
            Span::styled("PORT  ", Style::new().fg(CYAN).bold()),
            Span::styled("SOURCE          ", Style::new().fg(CYAN).bold()),
            Span::styled("DESTINATION / TARGET    ", Style::new().fg(CYAN).bold()),
            Span::styled("PROCESS   ", Style::new().fg(CYAN).bold()),
            Span::styled("STATS", Style::new().fg(CYAN).bold()),
        ])
    } else {
        Line::from(vec![
            Span::styled(" PROTO ", Style::new().fg(CYAN).bold()),
            Span::styled("PORT  ", Style::new().fg(CYAN).bold()),
            Span::styled("DESTINATION / TARGET ", Style::new().fg(CYAN).bold()),
            Span::styled("PROCESS   ", Style::new().fg(CYAN).bold()),
            Span::styled("STATS", Style::new().fg(CYAN).bold()),
        ])
    };
    lines.push(header_line);
    lines.push(Line::from(Span::styled(
        " ─────────────────────────────────────────────────────────────────────────────",
        Style::new().fg(BORDER),
    )));

    let max_rows = (inner.height as usize).saturating_sub(3);
    for flow in filtered_flows.iter().take(max_rows) {
        let proto = flow.network.to_ascii_uppercase();
        let port = extract_dst_port(flow);
        let target = if !flow.host.is_empty() {
            &flow.host
        } else {
            &flow.destination
        };
        let stats = if flow.download > 0 || flow.upload > 0 {
            format!("↓{} ↑{}", fmt_bytes(flow.download), fmt_bytes(flow.upload))
        } else {
            "OK".to_string()
        };
        let proto_color = match proto.as_str() {
            "TCP" => CYAN,
            "UDP" => PURPLE,
            "ICMP" => YELLOW,
            _ => FG_DIM,
        };
        if inner.width >= 75 {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:<5} ", proto),
                    Style::new().fg(proto_color).bold(),
                ),
                Span::styled(format!("{:<6}", port), Style::new().fg(FG_DIM)),
                Span::styled(
                    format!("{:<16} ", trunc(&flow.source, 15)),
                    Style::new().fg(FG_DIM),
                ),
                Span::styled(
                    format!("{:<24} ", trunc(target, 23)),
                    Style::new().fg(FG).bold(),
                ),
                Span::styled(
                    format!("{:<10} ", trunc(&flow.process, 9)),
                    Style::new().fg(YELLOW),
                ),
                Span::styled(stats, Style::new().fg(GREEN)),
            ]));
        } else {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:<5} ", proto),
                    Style::new().fg(proto_color).bold(),
                ),
                Span::styled(format!("{:<6}", port), Style::new().fg(FG_DIM)),
                Span::styled(
                    format!("{:<21} ", trunc(target, 20)),
                    Style::new().fg(FG).bold(),
                ),
                Span::styled(
                    format!("{:<10} ", trunc(&flow.process, 9)),
                    Style::new().fg(YELLOW),
                ),
                Span::styled(stats, Style::new().fg(GREEN)),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines), inner);
}

