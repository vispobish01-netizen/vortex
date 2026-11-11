use super::*;
use ratatui::{prelude::*, widgets::*};
use vortex_core::model::OperationalMode;
use vortex_core::ping::Ping;
use vortex_core::shield;
use vortex_core::store::{self, Kind};
use vortex_core::tunnel;

pub(crate) fn header(f: &mut Frame, a: Rect, app: &App) {
    if a.height == 0 {
        return;
    }
    let cur_mode = vortex_core::storage::get_mode_preference();
    let mode_btn = match cur_mode {
        OperationalMode::Tunnel => vec![
            Span::styled(" [m] ", Style::new().fg(BLACK).bg(CYAN).bold()),
            Span::styled("● TUNNEL ", Style::new().fg(BLACK).bg(CYAN).bold()),
            Span::styled("○ proxy ", Style::new().fg(FG_DIM).bg(BG_DARK)),
        ],
        OperationalMode::Proxy => vec![
            Span::styled(" [m] ", Style::new().fg(BLACK).bg(YELLOW).bold()),
            Span::styled("○ tunnel ", Style::new().fg(FG_DIM).bg(BG_DARK)),
            Span::styled("● PROXY ", Style::new().fg(BLACK).bg(YELLOW).bold()),
        ],
    };
    let mut left_spans = vec![
        Span::styled("⚡ VORTEX", Style::new().fg(GREEN).bold()),
        Span::styled(" // ", Style::new().fg(BORDER)),
        Span::styled("CYBER WARFARE NETWORK TUNNEL", Style::new().fg(CYAN).bold()),
        Span::styled(
            format!("  v{}", env!("CARGO_PKG_VERSION")),
            Style::new().fg(FG_DIM),
        ),
        Span::styled("  ", Style::new()),
    ];
    left_spans.extend(mode_btn);
    let left_title = Line::from(left_spans);

    let right_status = if let Some(b) = app.busy {
        let sp = SPIN[(app.busy_since.elapsed().as_millis() / 90) as usize % SPIN.len()];
        Line::from(vec![
            Span::styled(
                format!("[⌁ SWEEP: {b} {sp}] "),
                Style::new().fg(YELLOW).bold(),
            ),
            Span::styled("SCANNING ROUTE...", Style::new().fg(FG_DIM)),
        ])
    } else if let Some(s) = &app.session {
        let mut v = vec![
            Span::styled("[● LINK ENGAGED] ", Style::new().fg(GREEN).bold()),
            Span::styled(
                format!("{}: ", s.kind.tag()),
                Style::new().fg(kind_color(s.kind)).bold(),
            ),
            Span::styled(
                format!("{} ", trunc(&s.name, 18)),
                Style::new().fg(FG).bold(),
            ),
        ];
        if let Some(ms) = app.rtt {
            v.push(Span::styled(
                format!("{ms}ms "),
                Style::new().fg(ms_color(ms)).bold(),
            ));
        }
        v.push(Span::styled(
            format!("[UP: {}] ", fmt_dur(tunnel::now().saturating_sub(s.since))),
            Style::new().fg(FG_DIM),
        ));
        Line::from(v)
    } else {
        Line::from(vec![
            Span::styled(
                "[○ STANDBY // DIRECT PROBE ACTIVE] ",
                Style::new().fg(FG_DIM),
            ),
            Span::styled("[PROXY: 127.0.0.1:1080] ", Style::new().fg(PURPLE).bold()),
        ])
    };

    if a.height == 1 {
        f.render_widget(Paragraph::new(left_title), a);
        f.render_widget(Paragraph::new(right_status).alignment(Alignment::Right), a);
        return;
    }

    let armed = app.shield_armed || shield::is_armed();
    let (core_tag, core_val) = if let Some(s) = &app.session {
        match s.backend.as_deref() {
            Some("sing-box+xray") => {
                let ver = vortex_core::xray::active_xray_version().unwrap_or_default();
                (
                    "  BRIDGE: ",
                    if ver.is_empty() {
                        "sing-box + xray".to_string()
                    } else {
                        format!("sing-box + xray {ver}")
                    },
                )
            }
            Some("xray") | Some("xray-bridge") => {
                let ver = vortex_core::xray::active_xray_version().unwrap_or_default();
                (
                    "  XRAY: ",
                    if ver.is_empty() {
                        "xray-core".to_string()
                    } else {
                        format!("xray {ver}")
                    },
                )
            }
            Some("wireguard") => ("  SYS: ", "wireguard".to_string()),
            Some("amnezia") => ("  SYS: ", "amneziawg".to_string()),
            Some("openvpn") => ("  SYS: ", "openvpn".to_string()),
            Some("hysteria2") => ("  SYS: ", "hysteria2".to_string()),
            Some("sing-box") => ("  SYS: ", "sing-box/bpf".to_string()),
            _ if s.kind == Kind::Xray || s.conf.contains("xray") => {
                let ver = vortex_core::xray::active_xray_version().unwrap_or_default();
                (
                    "  XRAY: ",
                    if ver.is_empty() {
                        "xray-core".to_string()
                    } else {
                        format!("xray {ver}")
                    },
                )
            }
            _ if s.kind == Kind::Wg => ("  SYS: ", "wireguard".to_string()),
            _ if s.kind == Kind::Awg => ("  SYS: ", "amneziawg".to_string()),
            _ if s.kind == Kind::Ovpn => ("  SYS: ", "openvpn".to_string()),
            _ => ("  SYS: ", "sing-box/bpf".to_string()),
        }
    } else if vortex_core::privilege::resolve_singbox_binary().is_some()
        && vortex_core::xray::active_xray_version().is_some()
    {
        ("  BRIDGE: ", "sing-box + xray".to_string())
    } else if let Some(ver) = vortex_core::xray::active_xray_version() {
        ("  XRAY: ", format!("xray {ver}"))
    } else {
        ("  SYS: ", "sing-box/bpf".to_string())
    };

    let kernel_val = if cur_mode.is_tunnel() {
        "vx0"
    } else {
        "none (proxy)"
    };
    let (mode_lbl, mode_lbl_color) = match cur_mode {
        OperationalMode::Tunnel => ("TUNNEL", CYAN),
        OperationalMode::Proxy => ("PROXY", YELLOW),
    };

    let (sub_line, right_sub) = if a.width >= 100 {
        (
            Line::from(vec![
                Span::styled(core_tag, Style::new().fg(DIM).bold()),
                Span::styled(core_val.clone(), Style::new().fg(CYAN)),
                Span::styled("  ◈  KERNEL: ", Style::new().fg(DIM).bold()),
                Span::styled(kernel_val, Style::new().fg(FG)),
                Span::styled("  ◈  PROXY: ", Style::new().fg(DIM).bold()),
                Span::styled("127.0.0.1:1080", Style::new().fg(CYAN)),
                Span::styled("  ◈  DNS: ", Style::new().fg(DIM).bold()),
                Span::styled("1.1.1.1:DoH", Style::new().fg(GREEN)),
            ]),
            Line::from(vec![
                Span::styled("[MODE: ", Style::new().fg(DIM)),
                Span::styled(mode_lbl, Style::new().fg(mode_lbl_color).bold()),
                Span::styled(" · SHIELD: ", Style::new().fg(DIM)),
                if armed {
                    Span::styled("ARMED] ", Style::new().fg(GREEN).bold())
                } else {
                    Span::styled("OFF] ", Style::new().fg(RED).bold())
                },
            ]),
        )
    } else {
        (
            Line::from(vec![
                Span::styled("  CORE: ", Style::new().fg(DIM).bold()),
                Span::styled(core_val, Style::new().fg(CYAN)),
                Span::styled("  ◈  PROXY: :1080  ◈  DNS: DoH", Style::new().fg(FG_DIM)),
            ]),
            Line::from(vec![
                Span::styled("[", Style::new().fg(DIM)),
                Span::styled(mode_lbl, Style::new().fg(mode_lbl_color).bold()),
                Span::styled(" · SHIELD: ", Style::new().fg(DIM)),
                if armed {
                    Span::styled("ARMED] ", Style::new().fg(GREEN).bold())
                } else {
                    Span::styled("OFF] ", Style::new().fg(RED).bold())
                },
            ]),
        )
    };

    let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(a);
    f.render_widget(Paragraph::new(left_title), rows[0]);
    f.render_widget(
        Paragraph::new(right_status).alignment(Alignment::Right),
        rows[0],
    );
    let right_len = if a.width >= 100 { 44 } else { 22 };
    let sub_cols =
        Layout::horizontal([Constraint::Min(20), Constraint::Length(right_len)]).split(rows[1]);
    f.render_widget(Paragraph::new(sub_line), sub_cols[0]);
    f.render_widget(
        Paragraph::new(right_sub).alignment(Alignment::Right),
        sub_cols[1],
    );
}

pub(crate) fn circuit_diagram(
    local_iface: &str,
    node: &str,
    cipher: &str,
    exit_ip: &str,
    width: usize,
) -> Line<'static> {
    let clean_exit = if exit_ip.is_empty() {
        "ANALYZING..."
    } else {
        exit_ip
    };
    if width >= 58 {
        let fixed = 2 + local_iface.len() + 6 + cipher.len() + 7 + 7 + clean_exit.len() + 4;
        let max_node_w = width.saturating_sub(fixed).max(6);
        Line::from(vec![
            Span::styled(" [", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled("] ══[ ", Style::new().fg(BORDER)),
            Span::styled(cipher.to_string(), Style::new().fg(PURPLE).bold()),
            Span::styled(" ]══► [", Style::new().fg(BORDER)),
            Span::styled(
                trunc(node, max_node_w).into_owned(),
                Style::new().fg(FG).bold(),
            ),
            Span::styled("] ══► [", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
            Span::styled(" 🌐]", Style::new().fg(GREEN)),
        ])
    } else if width >= 44 {
        Line::from(vec![
            Span::styled(" [", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled("] ──► [", Style::new().fg(BORDER)),
            Span::styled(trunc(node, 12).into_owned(), Style::new().fg(FG).bold()),
            Span::styled("] ──► [", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
            Span::styled("]", Style::new().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" TUNNEL: ", Style::new().fg(DIM)),
            Span::styled(local_iface.to_string(), Style::new().fg(CYAN).bold()),
            Span::styled(" ──► ", Style::new().fg(BORDER)),
            Span::styled(clean_exit.to_string(), Style::new().fg(GREEN).bold()),
        ])
    }
}

pub(crate) fn circuit_diagram_direct(width: usize) -> Line<'static> {
    if width >= 66 {
        Line::from(vec![
            Span::styled(" [LOCAL: DIRECT] ", Style::new().fg(DIM)),
            Span::styled(
                "──────[ UNENCRYPTED CLEAR-NET ]──────► ",
                Style::new().fg(RED).bold(),
            ),
            Span::styled("[PUBLIC GATEWAY]", Style::new().fg(DIM)),
        ])
    } else if width >= 50 {
        Line::from(vec![
            Span::styled(" [LOCAL: DIRECT] ", Style::new().fg(DIM)),
            Span::styled("──[ UNENCRYPTED ]──► ", Style::new().fg(RED).bold()),
            Span::styled("[GATEWAY]", Style::new().fg(DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [DIRECT] ", Style::new().fg(DIM)),
            Span::styled("──[ CLEAR-NET ]──► ", Style::new().fg(RED).bold()),
            Span::styled("[GATEWAY]", Style::new().fg(DIM)),
        ])
    }
}

pub(crate) fn spark(f: &mut Frame, r: Rect, data: &[u64], c: Color) {
    let w = r.width as usize;
    let d = &data[data.len().saturating_sub(w)..];
    f.render_widget(Sparkline::default().data(d).style(Style::new().fg(c)), r);
}

pub(crate) fn info(f: &mut Frame, area: Rect, app: &App) {
    if app.show_log {
        let blk = block(
            "0x04 // [2] KERNEL AUDIT & CORE LOGS",
            app.focused_panel == 2,
        );
        let inner = blk.inner(area);
        f.render_widget(blk, area);
        let inner = inner.inner(Margin::new(1, 1));
        let lines: Vec<Line> = tunnel::tail_log(inner.height as usize)
            .into_iter()
            .map(|l| {
                let lower = l.to_lowercase();
                let (prefix, c) = if lower.contains("error")
                    || lower.contains("fatal")
                    || lower.contains("panic")
                {
                    ("[✕ ALERT] ", RED)
                } else if lower.contains("warn") {
                    ("[! WARN ] ", YELLOW)
                } else if lower.contains("connected")
                    || lower.contains("ready")
                    || lower.contains("success")
                    || lower.contains("started")
                {
                    ("[✔ OK   ] ", GREEN)
                } else if lower.contains("dns")
                    || lower.contains("route")
                    || lower.contains("tun")
                    || lower.contains("inbound")
                {
                    ("[◈ NET  ] ", CYAN)
                } else {
                    ("[· CORE ] ", FG_DIM)
                };
                Line::from(vec![
                    Span::styled(prefix, Style::new().fg(c).bold()),
                    Span::styled(l, Style::new().fg(if c == RED { RED } else { FG })),
                ])
            })
            .collect();
        f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
        return;
    }

    let sel = app.cur();
    let shown = match (&app.session, sel) {
        (Some(s), _) => Some((s.name.clone(), s.kind, s.server.clone())),
        (None, Some(p)) => Some((p.name.clone(), p.kind, p.server.clone())),
        _ => None,
    };
    let Some((name, kind, server)) = shown else {
        if app.show_flows {
            flows_table(f, area, app);
            return;
        }
        f.render_widget(
            block(
                "0x02 // [2] TELEMETRY // NO SELECTION",
                app.focused_panel == 2,
            ),
            area,
        );
        return;
    };

    let parts = Layout::vertical([Constraint::Length(14), Constraint::Min(4)]).split(area);
    let is_connected = app.session.is_some();

    let cur_p = match &app.session {
        Some(s) => app.profiles.iter().find(|p| p.id == s.id).or(sel),
        None => sel,
    };
    let transport_str = cur_p
        .map(|p| p.display_transport())
        .unwrap_or_else(|| "--".to_string());
    let (sec_str, is_warn_sec) = if let Some(p) = cur_p {
        let s_disp = p.display_security();
        let is_warn = p.security == vortex_core::model::Security::None
            && p.kind != Kind::Wg
            && p.kind != Kind::Awg;
        (s_disp, is_warn)
    } else {
        ("--".to_string(), false)
    };
    let ep_str = if let Some(port) = cur_p.and_then(|p| p.port) {
        if server.ends_with(&format!(":{port}")) {
            format!("{server} (port {port})")
        } else {
            format!("{server}:{port} (port {port})")
        }
    } else {
        server.clone()
    };

    // ── connection card
    let blk = block("0x02 // [2] TELEMETRY", app.focused_panel == 2);
    let inner = blk.inner(parts[0]).inner(Margin::new(1, 0));
    f.render_widget(blk, parts[0]);
    let nw = (inner.width as usize).saturating_sub(16);
    let mut lines = vec![];
    match &app.session {
        Some(s) => {
            let cipher_tag = if inner.width >= 72 {
                "CHACHA20-POLY1305"
            } else {
                "CHACHA20"
            };
            lines.push(circuit_diagram(
                &s.iface,
                &s.server,
                cipher_tag,
                &app.ip,
                inner.width as usize,
            ));
            lines.push(Line::from(""));
            lines.push(kv("status", "● ENGAGED // ENCRYPTED TUNNEL ACTIVE", GREEN));
            lines.push(kv("target", trunc(&name, nw), FG));
            lines.push(kv(
                "protocol",
                format!("{} [STRICT-ROUTE / TUN]", s.kind.tag()),
                kind_color(s.kind),
            ));
            lines.push(kv("transport", transport_str, CYAN));
            if is_warn_sec {
                lines.push(kv("security", format!("⚠ {sec_str}"), YELLOW));
            } else {
                lines.push(kv("security", sec_str, CYAN));
            }
            lines.push(kv("endpoint", trunc(&ep_str, nw), FG));
            if is_warn_sec {
                lines.push(Line::from(vec![
                    Span::styled("  [!] WARN: ", Style::new().fg(YELLOW).bold()),
                    Span::styled(
                        "Unencrypted transport without TLS / encapsulation poses interception risk",
                        Style::new().fg(YELLOW),
                    ),
                ]));
            }
            lines.push(kv(
                "exit ip",
                if app.ip.is_empty() {
                    "ANALYZING IP..."
                } else {
                    &app.ip
                },
                CYAN,
            ));
            lines.push(kv(
                "uptime",
                format!(
                    "{} [SESSION: 0x{:04X}]",
                    fmt_dur(tunnel::now().saturating_sub(s.since)),
                    s.pid.unwrap_or(0) & 0xFFFF
                ),
                FG_DIM,
            ));
            lines.push(match app.rtt {
                Some(ms) => kv(
                    "latency",
                    format!("{ms} ms [REALTIME ICMP ECHO]"),
                    ms_color(ms),
                ),
                None => kv("latency", "PROBING ICMP...", FG_DIM),
            });
            lines.push(kv(
                "proxy",
                "127.0.0.1:1080 [SOCKS5 / HTTP MIXED BRIDGE]",
                PURPLE,
            ));
            lines.push(kv(
                "shield",
                if app.shield_armed || shield::is_armed() {
                    "ARMED // STRICT LEAK-PREVENTION ACTIVE"
                } else {
                    "OFF // CLEAR-NET UNPROTECTED ON DROP"
                },
                if app.shield_armed || shield::is_armed() {
                    GREEN
                } else {
                    RED
                },
            ));
        }
        None => {
            lines.push(circuit_diagram_direct(inner.width as usize));
            lines.push(Line::from(vec![
                Span::styled("  [!] ALERT: ", Style::new().fg(RED).bold()),
                Span::styled(
                    "INTERNET TRAFFIC UNPROTECTED · LOCAL IP VISIBLE",
                    Style::new().fg(FG_DIM),
                ),
            ]));
            lines.push(Line::from(""));
            lines.push(kv("status", "○ STANDBY // ROUTE DISENGAGED", FG_DIM));
            lines.push(kv("target", trunc(&name, nw), FG));
            lines.push(kv("protocol", kind.tag(), kind_color(kind)));
            lines.push(kv("transport", transport_str, CYAN));
            if is_warn_sec {
                lines.push(kv("security", format!("⚠ {sec_str}"), YELLOW));
            } else {
                lines.push(kv("security", sec_str, CYAN));
            }
            lines.push(kv("endpoint", trunc(&ep_str, nw), FG));
            if is_warn_sec {
                lines.push(Line::from(vec![
                    Span::styled("  [!] WARN: ", Style::new().fg(YELLOW).bold()),
                    Span::styled(
                        "Unencrypted transport without TLS / encapsulation poses interception risk",
                        Style::new().fg(YELLOW),
                    ),
                ]));
            }
            let id = sel.map(|p| p.id.as_str()).unwrap_or("");
            lines.push(match app.pings.get(id) {
                Some(Ping::Ms(ms)) => kv(
                    "probe rtt",
                    format!("{ms} ms [TELEMETRY OPTIMAL]"),
                    ms_color(*ms),
                ),
                Some(Ping::Timeout) => kv("probe rtt", "UNREACHABLE / TIMEOUT [✕]", RED),
                None => kv("probe rtt", "NO TELEMETRY [PRESS T TO PROBE]", FG_DIM),
            });
            lines.push(kv("proxy", "127.0.0.1:1080 [READY ON TUNNEL UP]", DIM));
            lines.push(kv(
                "shield",
                if app.shield_armed || shield::is_armed() {
                    "ARMED // WILL ENGAGE ON CONNECT"
                } else {
                    "OFF // DISARMED"
                },
                if app.shield_armed || shield::is_armed() {
                    GREEN
                } else {
                    RED
                },
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("  [⏎] ENGAGE NODE  ", Style::new().fg(CYAN).bold()),
                Span::styled(" [T] PROBE LATENCY  ", Style::new().fg(YELLOW).bold()),
                Span::styled(" [I] DEEP RECON", Style::new().fg(GREEN).bold()),
            ]));
        }
    }
    f.render_widget(Paragraph::new(lines), inner);

    // ── traffic (connected) / details (idle) / flows (when show_flows)
    if app.show_flows {
        flows_table(f, parts[1], app);
    } else if is_connected {
        let blk = block("0x03 // [3] PACKET FLOW", app.focused_panel == 3);
        let inner = blk.inner(parts[1]).inner(Margin::new(1, 0));
        f.render_widget(blk, parts[1]);
        let mut tcp_bytes: u64 = 0;
        let mut udp_bytes: u64 = 0;
        for flow in &app.flows {
            let b = flow.upload.saturating_add(flow.download);
            if flow.network.eq_ignore_ascii_case("tcp") {
                tcp_bytes = tcp_bytes.saturating_add(b);
            } else if flow.network.eq_ignore_ascii_case("udp") {
                udp_bytes = udp_bytes.saturating_add(b);
            }
        }
        let total_flow_bytes = tcp_bytes.saturating_add(udp_bytes);
        let split_opt = if total_flow_bytes > 0 {
            let tcp_pct = (tcp_bytes as f64 / total_flow_bytes as f64 * 100.0).round() as u64;
            let udp_pct = 100u64.saturating_sub(tcp_pct);
            Some((tcp_pct, udp_pct))
        } else {
            None
        };

        let mut constraints = vec![Constraint::Length(1), Constraint::Length(1)];
        if split_opt.is_some() {
            constraints.push(Constraint::Length(1));
        }
        constraints.extend_from_slice(&[
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Min(0),
        ]);
        let rows = Layout::vertical(constraints).split(inner);
        let dn = app.down.last().copied().unwrap_or(0);
        let upn = app.up.last().copied().unwrap_or(0);
        let tot = app
            .last
            .map(|(r, t)| (r.saturating_sub(app.base.0), t.saturating_sub(app.base.1)))
            .unwrap_or((0, 0));
        let line = if inner.width >= 62 {
            Line::from(vec![
                Span::styled("RX (DOWN) ▼ ", Style::new().fg(CYAN).bold()),
                Span::styled(format!("{}/s", fmt_bytes(dn)), Style::new().fg(FG).bold()),
                Span::styled(
                    format!(" [PEAK: {}/s]", fmt_bytes(app.down_peak)),
                    Style::new().fg(FG_DIM),
                ),
                Span::raw("   "),
                Span::styled("TX (UP) ▲ ", Style::new().fg(PURPLE).bold()),
                Span::styled(format!("{}/s", fmt_bytes(upn)), Style::new().fg(FG).bold()),
                Span::styled(
                    format!(" [PEAK: {}/s]", fmt_bytes(app.up_peak)),
                    Style::new().fg(FG_DIM),
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled("RX ▼ ", Style::new().fg(CYAN).bold()),
                Span::styled(format!("{}/s ", fmt_bytes(dn)), Style::new().fg(FG).bold()),
                Span::styled("  TX ▲ ", Style::new().fg(PURPLE).bold()),
                Span::styled(format!("{}/s", fmt_bytes(upn)), Style::new().fg(FG).bold()),
            ])
        };
        let sub = if inner.width >= 62 {
            Line::from(vec![
                Span::styled("CUMULATIVE: ", Style::new().fg(DIM).bold()),
                Span::styled(
                    format!(
                        "RX (DOWN) {} · TX (UP) {}",
                        fmt_bytes(tot.0),
                        fmt_bytes(tot.1)
                    ),
                    Style::new().fg(FG_DIM),
                ),
                Span::styled("  │  MTU: 9000  │  BBR: ENGAGED", Style::new().fg(GREEN)),
            ])
        } else {
            Line::from(vec![
                Span::styled("TOTAL: ", Style::new().fg(DIM)),
                Span::styled(
                    format!("RX {} · TX {}", fmt_bytes(tot.0), fmt_bytes(tot.1)),
                    Style::new().fg(FG_DIM),
                ),
            ])
        };
        let mut r = 0;
        f.render_widget(Paragraph::new(line), rows[r]);
        r += 1;
        f.render_widget(Paragraph::new(sub), rows[r]);
        r += 1;
        if let Some((tcp_pct, udp_pct)) = split_opt {
            let split_line = Line::from(vec![
                Span::styled(format!("TCP {tcp_pct}%"), Style::new().fg(CYAN).bold()),
                Span::styled(" · ", Style::new().fg(FG_DIM)),
                Span::styled(format!("UDP {udp_pct}%"), Style::new().fg(PURPLE).bold()),
            ]);
            f.render_widget(Paragraph::new(split_line), rows[r]);
            r += 1;
        }
        spark(f, rows[r], &app.down, CYAN);
        r += 1;
        spark(f, rows[r], &app.up, PURPLE);
        r += 1;
        let (lo, hi) = (app.rtt_hist.iter().min(), app.rtt_hist.iter().max());
        let cur_rtt = app.rtt.unwrap_or(0);
        let rtt_txt = match (lo, hi) {
            (Some(l), Some(h)) => format!(
                "⌁ RTT JITTER SPECTRUM   MIN {l}ms · CUR {cur_rtt}ms · MAX {h}ms   [ICMP ECHO]"
            ),
            _ => "⌁ RTT JITTER SPECTRUM".to_string(),
        };
        f.render_widget(
            Paragraph::new(Span::styled(rtt_txt, Style::new().fg(FG_DIM).bold())),
            rows[r],
        );
        r += 1;
        spark(f, rows[r], &app.rtt_hist, YELLOW);
    } else {
        let blk = block("0x03 // [3] TARGET PARAMETERS", app.focused_panel == 3);
        let inner = blk.inner(parts[1]).inner(Margin::new(1, 0));
        f.render_widget(blk, parts[1]);
        let mut lines: Vec<Line> = sel
            .map(store::details)
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(i, (k, v))| {
                let prefix = format!("0x{:02X} {:<11} ", i + 1, k.to_ascii_uppercase());
                Line::from(vec![
                    Span::styled(prefix, Style::new().fg(FG_DIM).bold()),
                    Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
                    Span::styled(trunc(&v, nw).into_owned(), Style::new().fg(FG).bold()),
                ])
            })
            .collect();

        if inner.height >= 9 && inner.width >= 60 {
            let core_desc = match sel.map(|p| p.effective_engine()) {
                Some(vortex_core::model::CoreEngine::Xray) => "sing-box+xray     ",
                Some(vortex_core::model::CoreEngine::WireGuard) => "wireguard/kern    ",
                Some(vortex_core::model::CoreEngine::AmneziaWg) => "amneziawg/kern    ",
                Some(vortex_core::model::CoreEngine::OpenVpn) => "openvpn           ",
                _ => "sing-box/bpf      ",
            };
            let routing_desc = if vortex_core::storage::get_mode_preference().is_proxy() {
                "PROXY (:1080)      "
            } else {
                "STRICT-ROUTE (vx0) "
            };
            let armed = app.shield_armed || shield::is_armed();
            let shield_desc = if armed {
                "KILL-SWITCH ARMED  "
            } else {
                "STANDBY (OFF)      "
            };
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                " ┌─[ TARGET VECTOR INTELLIGENCE ]──────────────────────────┐",
                Style::new().fg(BORDER),
            )));
            lines.push(Line::from(vec![
                Span::styled(" │ CORE: ", Style::new().fg(BORDER)),
                Span::styled(core_desc, Style::new().fg(CYAN)),
                Span::styled(" ROUTING: ", Style::new().fg(BORDER)),
                Span::styled(routing_desc, Style::new().fg(FG)),
                Span::styled("│", Style::new().fg(BORDER)),
            ]));
            lines.push(Line::from(vec![
                Span::styled(" │ DNS : ", Style::new().fg(BORDER)),
                Span::styled("1.1.1.1 (DoH)      ", Style::new().fg(GREEN)),
                Span::styled(" SHIELD : ", Style::new().fg(BORDER)),
                Span::styled(
                    shield_desc,
                    Style::new().fg(if armed { PURPLE } else { FG_DIM }),
                ),
                Span::styled("│", Style::new().fg(BORDER)),
            ]));
            lines.push(Line::from(Span::styled(
                " └────────────────────────────────────────────────────────┘",
                Style::new().fg(BORDER),
            )));
        }
        f.render_widget(Paragraph::new(lines), inner);
    }
}
