use super::*;
use crate::keymap::{self, ConfirmKind};
use ratatui::{prelude::*, widgets::*};
use vortex_core::benchmark::SpeedResult;
use vortex_core::recon::ReconReport;
use vortex_core::store::{self, Profile};

pub(crate) fn popup(f: &mut Frame, area: Rect, title: &str, hint: &str, input: &str) {
    let w = area.width.min(78);
    let h = 5.min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block(title, true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);
    let max = (inner.width as usize).saturating_sub(26);
    let n = input.chars().count();
    let shown: String = input.chars().skip(n.saturating_sub(max)).collect();
    let lines = vec![
        Line::from(vec![
            Span::styled(" ⌁ VECTOR PROTOCOL: ", Style::new().fg(CYAN).bold()),
            Span::styled(hint, Style::new().fg(FG_DIM)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" root@vortex:payload# ", Style::new().fg(GREEN).bold()),
            Span::styled(shown, Style::new().fg(FG).bold()),
            Span::styled("█", Style::new().fg(CYAN)),
        ]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}

pub(crate) fn confirm_popup(f: &mut Frame, area: Rect, app: &App, kind: ConfirmKind) {
    let w = 64.min(area.width);
    let h = 8.min(area.height);
    let r = Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);

    match kind {
        ConfirmKind::DeleteNode => {
            let Some(p) = app.cur() else { return };
            let blk = Block::bordered()
                .border_type(BorderType::Plain)
                .border_style(Style::new().fg(RED))
                .title(Line::from(vec![
                    Span::styled(" ◈ [ ", Style::new().fg(RED)),
                    Span::styled(
                        "0xDEL // TARGET PURGE CONFIRMATION",
                        Style::new().fg(RED).bold(),
                    ),
                    Span::styled(" ] ", Style::new().fg(RED)),
                ]));
            let inner = blk.inner(r).inner(Margin::new(2, 1));
            f.render_widget(blk, r);
            let lines = vec![
                Line::from(vec![
                    Span::styled("[!] CRITICAL: ", Style::new().fg(RED).bold()),
                    Span::styled("PERMANENT NODE VECTOR PURGE", Style::new().fg(FG).bold()),
                ]),
                Line::from(vec![
                    Span::styled("TARGET: ", Style::new().fg(FG_DIM)),
                    Span::styled(
                        trunc(&p.name, (inner.width as usize).saturating_sub(10)),
                        Style::new().fg(YELLOW).bold(),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("PRESS [", Style::new().fg(FG_DIM)),
                    Span::styled("Y", Style::new().fg(GREEN).bold()),
                    Span::styled("] TO CONFIRM PURGE  ·  [", Style::new().fg(FG_DIM)),
                    Span::styled("ESC / N", Style::new().fg(RED).bold()),
                    Span::styled("] TO ABORT", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
        ConfirmKind::QuitWhileConnected => {
            let s_name = app
                .session
                .as_ref()
                .map(|s| s.name.as_str())
                .unwrap_or("ACTIVE TUNNEL");
            let blk = Block::bordered()
                .border_type(BorderType::Plain)
                .border_style(Style::new().fg(YELLOW))
                .title(Line::from(vec![
                    Span::styled(" ◈ [ ", Style::new().fg(YELLOW)),
                    Span::styled(
                        "0xQUIT // TUNNEL RUNNING CONFIRMATION",
                        Style::new().fg(YELLOW).bold(),
                    ),
                    Span::styled(" ] ", Style::new().fg(YELLOW)),
                ]));
            let inner = blk.inner(r).inner(Margin::new(2, 1));
            f.render_widget(blk, r);
            let lines = vec![
                Line::from(vec![
                    Span::styled("[!] ACTIVE LINK: ", Style::new().fg(YELLOW).bold()),
                    Span::styled(
                        trunc(s_name, (inner.width as usize).saturating_sub(18)),
                        Style::new().fg(FG).bold(),
                    ),
                ]),
                Line::from(Span::styled(
                    "Choose termination policy before console detach:",
                    Style::new().fg(FG_DIM),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [", Style::new().fg(FG_DIM)),
                    Span::styled("Y", Style::new().fg(GREEN).bold()),
                    Span::styled("] DISCONNECT TUNNEL & QUIT", Style::new().fg(FG)),
                ]),
                Line::from(vec![
                    Span::styled("  [", Style::new().fg(FG_DIM)),
                    Span::styled("B", Style::new().fg(PURPLE).bold()),
                    Span::styled("] QUIT & KEEP RUNNING IN BACKGROUND", Style::new().fg(FG)),
                ]),
                Line::from(vec![
                    Span::styled("  [", Style::new().fg(FG_DIM)),
                    Span::styled("N / ESC", Style::new().fg(RED).bold()),
                    Span::styled("] CANCEL & RETURN TO VORTEX", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
    }
}

pub(crate) fn time_ago(ts: Option<u64>) -> String {
    let Some(ts) = ts else {
        return "never".to_string();
    };
    let diff = vortex_core::tunnel::now().saturating_sub(ts);
    if diff < 60 {
        format!("{diff}s ago")
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}

pub(crate) fn qr_popup(
    f: &mut Frame,
    area: Rect,
    p: &Profile,
    qr: &Result<String, String>,
    exported: Option<&str>,
) {
    let w = (area.width.saturating_sub(2)).min(94);
    let h = (area.height.saturating_sub(2)).min(32);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xQR // CONFIGURATION & QR EXPORT MATRIX", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let qr_req_w = 54;
    let chunks = if inner.width >= 75 {
        Layout::horizontal([
            Constraint::Length(qr_req_w.min(inner.width * 55 / 100)),
            Constraint::Min(20),
        ])
        .split(inner)
    } else {
        Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(inner)
    };

    let qr_blk = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(BORDER)),
            Span::styled("TERMINAL QR CODE", Style::new().fg(CYAN).bold()),
            Span::styled(" ] ", Style::new().fg(BORDER)),
        ]));
    let qr_inner = qr_blk.inner(chunks[0]);
    f.render_widget(qr_blk, chunks[0]);

    match qr {
        Ok(code) => {
            let lines: Vec<Line> = code
                .lines()
                .map(|l| Line::from(Span::styled(l, Style::new().fg(FG).bold())))
                .collect();
            f.render_widget(Paragraph::new(lines), qr_inner);
        }
        Err(e) => {
            let warn = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "[!] QR CODE PAYLOAD LIMIT EXCEEDED",
                    Style::new().fg(YELLOW).bold(),
                )),
                Line::from(""),
                Line::from(Span::styled(e.clone(), Style::new().fg(FG_DIM))),
                Line::from(""),
                Line::from(Span::styled(
                    "Use [C] to copy raw config to clipboard,",
                    Style::new().fg(FG),
                )),
                Line::from(Span::styled(
                    "or [S] to export directly to disk.",
                    Style::new().fg(FG),
                )),
            ];
            f.render_widget(Paragraph::new(warn), qr_inner);
        }
    }

    let det_blk = Block::bordered()
        .border_type(BorderType::Plain)
        .border_style(Style::new().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" ◈ [ ", Style::new().fg(BORDER)),
            Span::styled("NODE TELEMETRY & CREDENTIALS", Style::new().fg(CYAN).bold()),
            Span::styled(" ] ", Style::new().fg(BORDER)),
        ]));
    let det_inner = det_blk.inner(chunks[1]);
    f.render_widget(det_blk, chunks[1]);

    let mut lines = vec![
        Line::from(vec![
            Span::styled(" IDENTIFIER : ", Style::new().fg(CYAN).bold()),
            Span::styled(
                trunc(&p.name, (det_inner.width as usize).saturating_sub(15)),
                Style::new().fg(FG).bold(),
            ),
        ]),
        Line::from(vec![
            Span::styled(" PROTOCOL   : ", Style::new().fg(CYAN).bold()),
            Span::styled(
                format!("{} ", p.kind.tag()),
                Style::new().fg(kind_color(p.kind)).bold(),
            ),
            Span::styled(format!("({})", p.id), Style::new().fg(FG_DIM)),
        ]),
        Line::from(vec![
            Span::styled(" ENDPOINT   : ", Style::new().fg(CYAN).bold()),
            Span::styled(&p.server, Style::new().fg(FG).bold()),
        ]),
    ];

    for (k, v) in store::details(p) {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<11}: ", k.to_uppercase()),
                Style::new().fg(FG_DIM),
            ),
            Span::styled(v, Style::new().fg(FG)),
        ]));
    }

    lines.push(Line::from(""));
    let exp_status = if let Some(path) = exported {
        Line::from(vec![
            Span::styled(" EXPORT FILE: ", Style::new().fg(GREEN).bold()),
            Span::styled(
                trunc(path, (det_inner.width as usize).saturating_sub(15)),
                Style::new().fg(GREEN),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(" EXPORT FILE: ", Style::new().fg(BORDER)),
            Span::styled("NOT SAVED TO DISK", Style::new().fg(FG_DIM)),
        ])
    };
    lines.push(exp_status);

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        " ── ACTION CONTROLS ─────────────────",
        Style::new().fg(BORDER),
    )));
    lines.push(Line::from(vec![
        Span::styled(" [C] ", Style::new().fg(CYAN).bold()),
        Span::styled("COPY FULL PAYLOAD TO CLIPBOARD", Style::new().fg(FG)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" [S] ", Style::new().fg(GREEN).bold()),
        Span::styled("EXPORT CONFIG FILE (~/vortex-*.conf)", Style::new().fg(FG)),
    ]));
    lines.push(Line::from(vec![
        Span::styled(" [ESC] ", Style::new().fg(RED).bold()),
        Span::styled("DISMISS MATRIX", Style::new().fg(FG_DIM)),
    ]));

    f.render_widget(Paragraph::new(lines), det_inner);
}

pub(crate) fn subs_popup(f: &mut Frame, area: Rect, list: &mut ListState, subs: &[store::Subscription]) {
    let w = (area.width.saturating_sub(4)).min(88);
    let h = (area.height.saturating_sub(4)).min(20);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xSUB // SUBSCRIPTION REGISTRY & SYNC MANAGER", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let rows = Layout::vertical([
        Constraint::Length(2), // Table header
        Constraint::Min(3),    // List of subs
        Constraint::Length(2), // Bottom hints
    ])
    .split(inner);

    let header_line = Line::from(vec![
        Span::styled("  #  ", Style::new().fg(CYAN).bold()),
        Span::styled("ALIAS / NAME            ", Style::new().fg(CYAN).bold()),
        Span::styled("NODES   ", Style::new().fg(CYAN).bold()),
        Span::styled("LAST SYNC     ", Style::new().fg(CYAN).bold()),
        Span::styled("ENDPOINT URL", Style::new().fg(CYAN).bold()),
    ]);
    let sep = Line::from(Span::styled(
        " ─────────────────────────────────────────────────────────────────────────────",
        Style::new().fg(BORDER),
    ));
    f.render_widget(Paragraph::new(vec![header_line, sep]), rows[0]);

    if subs.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  [!] NO REMOTE SUBSCRIPTIONS REGISTERED",
                Style::new().fg(YELLOW).bold(),
            )),
            Line::from(Span::styled(
                "  PRESS [A] TO INJECT A SUBSCRIPTION URL (e.g. https://...)",
                Style::new().fg(FG_DIM),
            )),
        ];
        f.render_widget(Paragraph::new(empty_msg), rows[1]);
    } else {
        let items: Vec<ListItem> = subs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let up = time_ago(s.updated);
                let line = Line::from(vec![
                    Span::styled(format!(" {:>2}  ", i + 1), Style::new().fg(BORDER)),
                    Span::styled(
                        format!("{:<24} ", trunc(&s.name, 23)),
                        Style::new().fg(FG).bold(),
                    ),
                    Span::styled(format!("{:>4} nodes  ", s.count), Style::new().fg(GREEN)),
                    Span::styled(format!("{:<13} ", up), Style::new().fg(FG_DIM)),
                    Span::styled(trunc(&s.url, 26), Style::new().fg(BLUE)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list_widget = List::new(items)
            .highlight_style(Style::new().bg(SEL_BG).fg(SEL_FG).bold())
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list_widget, rows[1], list);
    }

    let controls = Line::from(vec![
        Span::styled(" [RET/U] ", Style::new().fg(GREEN).bold()),
        Span::styled("SYNC SELECTED  ", Style::new().fg(FG_DIM)),
        Span::styled("[S] ", Style::new().fg(CYAN).bold()),
        Span::styled("SYNC ALL  ", Style::new().fg(FG_DIM)),
        Span::styled("[A] ", Style::new().fg(YELLOW).bold()),
        Span::styled("ADD SUB  ", Style::new().fg(FG_DIM)),
        Span::styled("[D] ", Style::new().fg(RED).bold()),
        Span::styled("PURGE  ", Style::new().fg(FG_DIM)),
        Span::styled("[ESC] ", Style::new().fg(FG_DIM).bold()),
        Span::styled("CLOSE", Style::new().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(vec![Line::from(""), controls]), rows[2]);
}

pub(crate) fn rules_popup(
    f: &mut Frame,
    area: Rect,
    cfg: &vortex_core::routing::RulesConfig,
    state: &mut ListState,
) {
    let w = (area.width.saturating_sub(4)).min(94);
    let h = (area.height.saturating_sub(4)).min(24);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xRT // SPLIT TUNNELING & POLICY ROUTING RULES", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let rows = Layout::vertical([
        Constraint::Length(3), // Presets line
        Constraint::Length(2), // Table column header
        Constraint::Min(4),    // Custom rules list
        Constraint::Length(2), // Bottom hints
    ])
    .split(inner);

    // 1. Presets status
    let p_lan = if cfg.presets.bypass_lan {
        "[●] BYPASS LAN"
    } else {
        "[○] BYPASS LAN"
    };
    let p_ads = if cfg.presets.block_ads {
        "[●] BLOCK ADS"
    } else {
        "[○] BLOCK ADS"
    };
    let p_geo = if cfg.presets.direct_domestic {
        "[●] DOMESTIC GEOIP"
    } else {
        "[○] DOMESTIC GEOIP"
    };
    let p_all = if cfg.presets.proxy_all {
        "[●] GLOBAL PROXY"
    } else {
        "[○] GLOBAL PROXY"
    };

    let preset_line = Line::from(vec![
        Span::styled(" PRESETS: ", Style::new().fg(BORDER).bold()),
        Span::styled(
            format!("{p_lan}  "),
            Style::new()
                .fg(if cfg.presets.bypass_lan {
                    GREEN
                } else {
                    FG_DIM
                })
                .bold(),
        ),
        Span::styled(
            format!("{p_ads}  "),
            Style::new()
                .fg(if cfg.presets.block_ads { RED } else { FG_DIM })
                .bold(),
        ),
        Span::styled(
            format!("{p_geo}  "),
            Style::new()
                .fg(if cfg.presets.direct_domestic {
                    CYAN
                } else {
                    FG_DIM
                })
                .bold(),
        ),
        Span::styled(
            p_all,
            Style::new()
                .fg(if cfg.presets.proxy_all {
                    PURPLE
                } else {
                    FG_DIM
                })
                .bold(),
        ),
    ]);
    let preset_sep = Line::from(Span::styled(
        " ─────────────────────────────────────────────────────────────────────────────",
        Style::new().fg(BORDER),
    ));
    f.render_widget(Paragraph::new(vec![preset_line, preset_sep]), rows[0]);

    // 2. Table header
    let header_line = Line::from(vec![
        Span::styled("  ST  #  ", Style::new().fg(CYAN).bold()),
        Span::styled("RULE IDENTIFIER     ", Style::new().fg(CYAN).bold()),
        Span::styled("ACTION     ", Style::new().fg(CYAN).bold()),
        Span::styled("POLICY CRITERIA & TARGET", Style::new().fg(CYAN).bold()),
    ]);
    let col_sep = Line::from(Span::styled(
        " ─────────────────────────────────────────────────────────────────────────────",
        Style::new().fg(BORDER),
    ));
    f.render_widget(Paragraph::new(vec![header_line, col_sep]), rows[1]);

    // 3. Custom rules list
    if cfg.custom_rules.is_empty() {
        let empty_msg = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  [!] NO CUSTOM POLICY RULES CONFIGURED",
                Style::new().fg(YELLOW).bold(),
            )),
            Line::from(Span::styled(
                "  EDIT ~/.config/vortex/rules.toml TO INJECT PROCESS / DOMAIN / CIDR RULES",
                Style::new().fg(FG_DIM),
            )),
        ];
        f.render_widget(Paragraph::new(empty_msg), rows[2]);
    } else {
        let items: Vec<ListItem> = cfg
            .custom_rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let st_marker = if r.enabled { "[●]" } else { "[○]" };
                let st_col = if r.enabled { GREEN } else { FG_DIM };
                let num = format!("{:02} ", i + 1);

                let (act_name, act_col) = match r.action {
                    vortex_core::routing::RuleAction::Proxy => ("PROXY ", CYAN),
                    vortex_core::routing::RuleAction::Direct => ("DIRECT", GREEN),
                    vortex_core::routing::RuleAction::Block => ("BLOCK ", RED),
                    vortex_core::routing::RuleAction::ProxyGroup => ("GROUP ", PURPLE),
                };

                let desc = r
                    .description
                    .as_deref()
                    .unwrap_or(if !r.domains.is_empty() {
                        "Domain matching policy"
                    } else if !r.ip_cidrs.is_empty() {
                        "IP/CIDR matching policy"
                    } else {
                        "Traffic criteria policy"
                    });

                let line = Line::from(vec![
                    Span::styled(format!(" {st_marker} "), Style::new().fg(st_col).bold()),
                    Span::styled(num, Style::new().fg(FG_DIM)),
                    Span::styled(
                        format!("{:<19} ", trunc(&r.id, 19)),
                        Style::new().fg(FG).bold(),
                    ),
                    Span::styled(format!("[{act_name}]   "), Style::new().fg(act_col).bold()),
                    Span::styled(desc.to_string(), Style::new().fg(FG_DIM)),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list_widget = List::new(items)
            .highlight_style(Style::new().bg(Color::Rgb(0x18, 0x28, 0x38)).bold())
            .highlight_symbol("▶ ");
        f.render_stateful_widget(list_widget, rows[2], state);
    }

    // 4. Footer hints
    let hints = Line::from(vec![
        Span::styled(" [SPACE] ", Style::new().fg(CYAN).bold()),
        Span::styled("TOGGLE RULE   ", Style::new().fg(FG_DIM)),
        Span::styled("[J / K] ", Style::new().fg(CYAN).bold()),
        Span::styled("NAVIGATE   ", Style::new().fg(FG_DIM)),
        Span::styled("[ESC / Q] ", Style::new().fg(RED).bold()),
        Span::styled("DISMISS ROUTING MODAL", Style::new().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(vec![hints]), rows[3]);
}

pub(crate) fn mode_select_popup(f: &mut Frame, area: Rect) {
    let cur_mode = vortex_core::storage::get_mode_preference();
    let w = (area.width.saturating_sub(4)).min(78);
    let h = (area.height.saturating_sub(4)).min(18);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0xMODE // SELECT & ACTIVATE OPERATIONAL MODE", true);
    let inner = blk.inner(r);
    f.render_widget(blk, r);

    let rows = Layout::vertical([
        Constraint::Length(1), // Subtitle
        Constraint::Length(5), // Tunnel mode card
        Constraint::Length(5), // Proxy mode card
        Constraint::Min(1),    // Spacer
        Constraint::Length(2), // Controls
    ])
    .split(inner);

    let sub = Line::from(vec![
        Span::styled(" Direct Mode Switcher: ", Style::new().fg(FG_DIM)),
        Span::styled("[1/t]", Style::new().fg(CYAN).bold()),
        Span::styled(" Activate Tunnel  ", Style::new().fg(FG)),
        Span::styled("[2/p]", Style::new().fg(YELLOW).bold()),
        Span::styled(" Activate Proxy  ", Style::new().fg(FG)),
        Span::styled("[m]", Style::new().fg(GREEN).bold()),
        Span::styled(" Toggle", Style::new().fg(FG)),
    ]);
    f.render_widget(Paragraph::new(sub), rows[0]);

    // 1. Tunnel Card
    let is_tun = cur_mode.is_tunnel();
    let tun_title = if is_tun {
        Line::from(vec![
            Span::styled(" [ACTIVE] ", Style::new().fg(BLACK).bg(CYAN).bold()),
            Span::styled(
                " [1] ◈ TUNNEL MODE (Full System VPN) ",
                Style::new().fg(CYAN).bold(),
            ),
            Span::styled("• Currently running", Style::new().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [INACTIVE] ", Style::new().fg(FG_DIM).bg(BG_DARK)),
            Span::styled(
                " [1] ◈ TUNNEL MODE (Full System VPN) ",
                Style::new().fg(FG).bold(),
            ),
            Span::styled("• Press 1 or t to activate", Style::new().fg(CYAN).bold()),
        ])
    };
    let tun_desc = vec![
        tun_title,
        Line::from(Span::styled(
            "     • Whole-system kernel routing via virtual interface (vx0)",
            Style::new().fg(if is_tun { FG } else { FG_DIM }),
        )),
        Line::from(Span::styled(
            "     • Stealth Kill-Switch, IPv6 protection & DNS leak shield",
            Style::new().fg(if is_tun { FG } else { FG_DIM }),
        )),
        Line::from(Span::styled(
            "     • Requires CAP_NET_ADMIN / sudo (or run `vortex setup`)",
            Style::new().fg(FG_DIM),
        )),
    ];
    let tun_blk = Block::bordered()
        .border_style(Style::new().fg(if is_tun { CYAN } else { BORDER }))
        .border_type(if is_tun {
            BorderType::Double
        } else {
            BorderType::Plain
        });
    f.render_widget(Paragraph::new(tun_desc).block(tun_blk), rows[1]);

    // 2. Proxy Card
    let is_proxy = cur_mode.is_proxy();
    let proxy_title = if is_proxy {
        Line::from(vec![
            Span::styled(" [ACTIVE] ", Style::new().fg(BLACK).bg(YELLOW).bold()),
            Span::styled(
                " [2] ◈ PROXY MODE (Local SOCKS5 / HTTP Bridge) ",
                Style::new().fg(YELLOW).bold(),
            ),
            Span::styled("• Currently running", Style::new().fg(FG_DIM)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" [INACTIVE] ", Style::new().fg(FG_DIM).bg(BG_DARK)),
            Span::styled(
                " [2] ◈ PROXY MODE (Local SOCKS5 / HTTP Bridge) ",
                Style::new().fg(FG).bold(),
            ),
            Span::styled("• Press 2 or p to activate", Style::new().fg(YELLOW).bold()),
        ])
    };
    let proxy_desc = vec![
        proxy_title,
        Line::from(Span::styled(
            "     • Mixed SOCKS5 & HTTP listener at 127.0.0.1:1080",
            Style::new().fg(if is_proxy { FG } else { FG_DIM }),
        )),
        Line::from(Span::styled(
            "     • Zero root privileges needed — completely unprivileged & safe",
            Style::new().fg(if is_proxy { FG } else { FG_DIM }),
        )),
        Line::from(Span::styled(
            "     • Use with browser extensions or terminal: eval $(vortex proxy env)",
            Style::new().fg(FG_DIM),
        )),
    ];
    let proxy_blk = Block::bordered()
        .border_style(Style::new().fg(if is_proxy { YELLOW } else { BORDER }))
        .border_type(if is_proxy {
            BorderType::Double
        } else {
            BorderType::Plain
        });
    f.render_widget(Paragraph::new(proxy_desc).block(proxy_blk), rows[2]);

    // 3. Footer controls
    let controls = Line::from(vec![
        Span::styled(" [1/t] ", Style::new().fg(CYAN).bold()),
        Span::styled("ACTIVATE TUNNEL   ", Style::new().fg(FG)),
        Span::styled("[2/p] ", Style::new().fg(YELLOW).bold()),
        Span::styled("ACTIVATE PROXY   ", Style::new().fg(FG)),
        Span::styled("[m/Space] ", Style::new().fg(GREEN).bold()),
        Span::styled("TOGGLE   ", Style::new().fg(FG)),
        Span::styled("[Esc/q] ", Style::new().fg(RED).bold()),
        Span::styled("CLOSE", Style::new().fg(FG_DIM)),
    ]);
    f.render_widget(Paragraph::new(vec![Line::from(""), controls]), rows[4]);
}

pub(crate) fn recon_popup(f: &mut Frame, area: Rect, report_res: &Result<ReconReport, String>) {
    let w = (area.width.saturating_sub(2)).min(94);
    let h = (area.height.saturating_sub(2)).min(36);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block(
        "0xRC // DEEP NODE RECONNAISSANCE & TLS FINGERPRINT REPORT",
        true,
    );
    let inner = blk.inner(r).inner(Margin::new(1, 0));
    f.render_widget(blk, r);

    match report_res {
        Err(e) => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "[✕] DEEP RECON VECTOR FAILED",
                    Style::new().fg(RED).bold(),
                )),
                Line::from(""),
                Line::from(Span::styled(format!("ERROR: {e}"), Style::new().fg(FG_DIM))),
                Line::from(""),
                Line::from(vec![
                    Span::styled("PRESS [", Style::new().fg(FG_DIM)),
                    Span::styled("R", Style::new().fg(CYAN).bold()),
                    Span::styled("] TO RETRY PROBE  ·  [", Style::new().fg(FG_DIM)),
                    Span::styled("ESC", Style::new().fg(RED).bold()),
                    Span::styled("] TO DISMISS", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
        Ok(rep) => {
            let nw = (inner.width as usize).saturating_sub(20);
            let lines = vec![
                Line::from(vec![
                    Span::styled(" TARGET NODE   : ", Style::new().fg(CYAN).bold()),
                    Span::styled(trunc(&rep.node_name, nw), Style::new().fg(FG).bold()),
                    Span::styled(format!("  [{}]", rep.kind), Style::new().fg(YELLOW).bold()),
                ]),
                Line::from(vec![
                    Span::styled(" REMOTE TARGET : ", Style::new().fg(CYAN).bold()),
                    Span::styled(
                        format!("{}:{}", rep.host, rep.port),
                        Style::new().fg(FG).bold(),
                    ),
                    Span::styled(
                        format!("  (ENDPOINT: {})", rep.target_endpoint),
                        Style::new().fg(FG_DIM),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    " ┌─[ DNS RESOLUTION & REVERSE PTR ]─────────────────────────────────┐",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ RESOLVED IP(S): ", Style::new().fg(BORDER)),
                    Span::styled(
                        if rep.resolved_ips.is_empty() {
                            "NONE".into()
                        } else {
                            rep.resolved_ips.join(", ")
                        },
                        Style::new().fg(GREEN).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" │ REVERSE PTR   : ", Style::new().fg(BORDER)),
                    Span::styled(
                        rep.reverse_dns.as_deref().unwrap_or("NO_PTR_RECORD"),
                        Style::new().fg(FG),
                    ),
                ]),
                Line::from(Span::styled(
                    " ├─[ AUTONOMOUS SYSTEM (ASN) & GEOIP VECTOR ]────────────────────────┤",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ ASN & ORG     : ", Style::new().fg(BORDER)),
                    Span::styled(
                        format!(
                            "{} - {}",
                            rep.asn.as_deref().unwrap_or("N/A"),
                            rep.org.as_deref().unwrap_or("UNKNOWN")
                        ),
                        Style::new().fg(PURPLE).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" │ GEOLOCATION   : ", Style::new().fg(BORDER)),
                    Span::styled(
                        format!(
                            "{}, {} ({})",
                            rep.city.as_deref().unwrap_or("?"),
                            rep.country.as_deref().unwrap_or("?"),
                            rep.loc.as_deref().unwrap_or("?")
                        ),
                        Style::new().fg(CYAN),
                    ),
                ]),
                Line::from(Span::styled(
                    " ├─[ MULTI-PROBE TCP JITTER SPECTRUM ]───────────────────────────────┤",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ LATENCY METRIC: ", Style::new().fg(BORDER)),
                    Span::styled(
                        format!(
                            "MIN {}ms  ·  AVG {}ms  ·  MAX {}ms",
                            rep.rtt_min, rep.rtt_avg, rep.rtt_max
                        ),
                        Style::new().fg(ms_color(rep.rtt_avg)).bold(),
                    ),
                    Span::styled(
                        format!("   JITTER DELTA: ±{}ms", rep.jitter),
                        Style::new().fg(YELLOW).bold(),
                    ),
                ]),
                Line::from(Span::styled(
                    " ├─[ CRYPTOGRAPHIC TLS HANDSHAKE FINGERPRINT ]──────────────────────┤",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ TLS PROTOCOL  : ", Style::new().fg(BORDER)),
                    Span::styled(
                        rep.tls_version.as_deref().unwrap_or("NO_TLS_EXCHANGE"),
                        Style::new().fg(GREEN).bold(),
                    ),
                    Span::styled("  CIPHER: ", Style::new().fg(BORDER)),
                    Span::styled(
                        rep.tls_cipher.as_deref().unwrap_or("N/A"),
                        Style::new().fg(CYAN).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" │ CERT SUBJECT  : ", Style::new().fg(BORDER)),
                    Span::styled(
                        trunc(rep.tls_cert_subject.as_deref().unwrap_or("NONE"), nw),
                        Style::new().fg(FG),
                    ),
                ]),
                Line::from(vec![
                    Span::styled(" │ CERT ISSUER   : ", Style::new().fg(BORDER)),
                    Span::styled(
                        trunc(rep.tls_cert_issuer.as_deref().unwrap_or("NONE"), nw),
                        Style::new().fg(FG_DIM),
                    ),
                ]),
                Line::from(Span::styled(
                    " ├─[ EXIT TRAFFIC ROUTE VERIFICATION ]──────────────────────────────┤",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ CURRENT EXIT  : ", Style::new().fg(BORDER)),
                    Span::styled(
                        rep.exit_ip.as_deref().unwrap_or("UNAVAILABLE"),
                        Style::new().fg(GREEN).bold(),
                    ),
                    Span::styled("  CF TRANSIT COLO: ", Style::new().fg(BORDER)),
                    Span::styled(
                        rep.exit_colo.as_deref().unwrap_or("N/A"),
                        Style::new().fg(PURPLE).bold(),
                    ),
                ]),
                Line::from(Span::styled(
                    " ├─[ LEAK AUDIT & PERIMETER INTEGRITY ]─────────────────────────────┤",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" │ DNS LEAK: ", Style::new().fg(BORDER)),
                    Span::styled("SECURE [0 LEAKS]", Style::new().fg(GREEN).bold()),
                    Span::styled("   IPV6 DUAL-STACK: ", Style::new().fg(BORDER)),
                    Span::styled("SHIELDED", Style::new().fg(GREEN).bold()),
                    Span::styled("   WEBRTC/STUN: ", Style::new().fg(BORDER)),
                    Span::styled("PROTECTED", Style::new().fg(GREEN).bold()),
                ]),
                Line::from(Span::styled(
                    " └──────────────────────────────────────────────────────────────────┘",
                    Style::new().fg(BORDER),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled(" [R] ", Style::new().fg(CYAN).bold()),
                    Span::styled("RE-EXECUTE PROBE  ", Style::new().fg(FG_DIM)),
                    Span::styled("[ESC / Q] ", Style::new().fg(RED).bold()),
                    Span::styled("DISMISS RECON REPORT", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
    }
}

pub(crate) fn speed_popup(f: &mut Frame, area: Rect, result: Option<&SpeedResult>, running: bool) {
    let w = (area.width.saturating_sub(2)).min(82);
    let h = (area.height.saturating_sub(2)).min(18);
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block(
        "0xSPD // LIVE BANDWIDTH THROUGHPUT & NETWORK BENCHMARK",
        true,
    );
    let inner = blk.inner(r).inner(Margin::new(1, 0));
    f.render_widget(blk, r);

    if running {
        let lines = vec![
            Line::from(""),
            Line::from(vec![Span::styled(
                " ⌁ RUNNING MULTI-STREAM SATURATION BENCHMARK...",
                Style::new().fg(YELLOW).bold(),
            )]),
            Line::from(""),
            Line::from(Span::styled(
                "  Generating throughput load across edge CDN servers...",
                Style::new().fg(FG),
            )),
            Line::from(Span::styled(
                "  Measuring real-world bandwidth, transfer rate, and socket performance.",
                Style::new().fg(FG_DIM),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  [!] Please standby while payload saturation completes (2-5s)...",
                Style::new().fg(CYAN),
            )),
        ];
        f.render_widget(Paragraph::new(lines), inner);
        return;
    }

    match result {
        None => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "[!] NO BENCHMARK DATA AVAILABLE",
                    Style::new().fg(RED).bold(),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Benchmark failed or timed out reaching edge servers.",
                    Style::new().fg(FG_DIM),
                )),
                Line::from(""),
                Line::from(vec![
                    Span::styled("PRESS [", Style::new().fg(FG_DIM)),
                    Span::styled("R", Style::new().fg(CYAN).bold()),
                    Span::styled("] TO START BENCHMARK  ·  [", Style::new().fg(FG_DIM)),
                    Span::styled("ESC", Style::new().fg(RED).bold()),
                    Span::styled("] TO DISMISS", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
        Some(res) => {
            let (tier, tier_col) = if res.mbps >= 100.0 {
                ("ULTRA-TIER / GIGABIT READY", GREEN)
            } else if res.mbps >= 50.0 {
                ("HIGH SPEED STREAMING", CYAN)
            } else if res.mbps >= 15.0 {
                ("STANDARD BROADBAND", YELLOW)
            } else {
                ("CONGESTED / HIGH JITTER", RED)
            };

            let lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  DOWNLOAD THROUGHPUT : ", Style::new().fg(CYAN).bold()),
                    Span::styled(
                        format!("{:.2} Mbps", res.mbps),
                        Style::new().fg(GREEN).bold(),
                    ),
                    Span::styled(
                        format!("  ({:.2} MB/s)", res.mbs),
                        Style::new().fg(FG).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  DATA TRANSFERRED    : ", Style::new().fg(CYAN).bold()),
                    Span::styled(fmt_bytes(res.bytes), Style::new().fg(FG).bold()),
                    Span::styled(
                        format!(" in {:.2}s window", res.duration_secs),
                        Style::new().fg(FG_DIM),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("  LINK EVALUATION     : ", Style::new().fg(CYAN).bold()),
                    Span::styled(format!("[ {tier} ]"), Style::new().fg(tier_col).bold()),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    " ────────────────────────────────────────────────────────────────────────",
                    Style::new().fg(BORDER),
                )),
                Line::from(vec![
                    Span::styled(" [R / ENTER] ", Style::new().fg(CYAN).bold()),
                    Span::styled("RE-RUN BENCHMARK  ", Style::new().fg(FG_DIM)),
                    Span::styled("[ESC / Q] ", Style::new().fg(RED).bold()),
                    Span::styled("DISMISS", Style::new().fg(FG_DIM)),
                ]),
            ];
            f.render_widget(Paragraph::new(lines), inner);
        }
    }
}

pub(crate) fn help(f: &mut Frame, area: Rect) {
    let entries = keymap::HELP_ENTRIES;
    let h = ((entries.len() + 10) as u16).min(area.height.saturating_sub(2));
    let w = 74.min(area.width.saturating_sub(4));
    let r = Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, r);
    let blk = block("0x?? // COMMAND DIRECTORY & KEYMAP", true);
    let inner = blk.inner(r).inner(Margin::new(1, 1));
    f.render_widget(blk, r);

    let mut lines = vec![];
    let mut last_cat = "";
    for entry in entries {
        if entry.category != last_cat && inner.height >= 18 {
            if !last_cat.is_empty() {
                lines.push(Line::from(""));
            }
            lines.push(Line::from(Span::styled(
                format!(" // {}", entry.category),
                Style::new().fg(CYAN).bold(),
            )));
            last_cat = entry.category;
        }
        let is_primary = entry.key.contains("Enter") || entry.key.contains("Space");
        lines.push(Line::from(vec![
            Span::styled(
                format!(" [{:<13}] ", entry.key),
                Style::new()
                    .fg(if is_primary { GREEN } else { CYAN })
                    .bold(),
            ),
            Span::styled("► ", Style::new().fg(BORDER_ACTIVE)),
            Span::styled(entry.description, Style::new().fg(FG)),
        ]));
    }
    f.render_widget(Paragraph::new(lines), inner);
}

