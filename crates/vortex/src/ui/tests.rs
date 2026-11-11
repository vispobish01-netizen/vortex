use super::*;
use crate::keymap::Mode;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::prelude::*;
use ratatui::widgets::*;
use vortex_core::benchmark::SpeedResult;
use vortex_core::ping::Ping;
use vortex_core::recon::ReconReport;
use vortex_core::store::{self, Kind, Profile, Security, Transport};
use vortex_core::tunnel::{self, ActiveFlow, Session};

fn prof(id: &str, name: &str, kind: Kind, data: &str) -> Profile {
    Profile {
        id: id.into(),
        name: name.into(),
        kind,
        server: "203.0.113.7:443".into(),
        data: data.into(),
        ..Default::default()
    }
}

fn render(w: u16, h: u16, app: &mut App) -> String {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(f, app)).unwrap();
    let b = t.backend().buffer().clone();
    (0..h)
        .map(|y| {
            (0..w)
                .map(|x| b[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn layouts_do_not_panic_and_show_latency() {
    let mut app = App::new();
    app.profiles = vec![
        prof("a", "Frankfurt Reality", Kind::Vless, "vless://u@203.0.113.7:443?security=reality&sni=example.com&pbk=k&type=grpc&serviceName=x#Frankfurt"),
        prof("b", "Home WG", Kind::Wg, "[Peer]\nEndpoint = 203.0.113.7:51820\n"),
        prof("c", "Dead one", Kind::Hy2, "hy2://pw@203.0.113.7:443#Dead"),
    ];
    app.pings.insert("a".into(), Ping::Ms(42));
    app.pings.insert("b".into(), Ping::Ms(280));
    app.pings.insert("c".into(), Ping::Timeout);
    app.rebuild();
    for (w, h) in [(120, 32), (90, 24), (70, 20), (30, 8), (12, 4)] {
        let out = render(w, h, &mut app);
        if w == 120 {
            println!("{out}");
        }
    }
    app.sort_ping = true;
    app.rebuild();
    assert_eq!(app.cur().map(|p| p.id.as_str()), Some("a"));
    app.filter = "wg".into();
    app.rebuild();
    assert_eq!(app.view.len(), 1);
    app.mode = Mode::Help;
    render(80, 24, &mut app);
    app.mode = Mode::Edit("x".into());
    render(80, 24, &mut app);
}

fn edit(s: &mut String, k: &KeyEvent) -> bool {
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Backspace => {
            s.pop();
            true
        }
        KeyCode::Char('u') if ctrl => {
            s.clear();
            true
        }
        KeyCode::Char('w') if ctrl => {
            let t = s.trim_end().len();
            s.truncate(t);
            while s
                .chars()
                .last()
                .map(|c| !c.is_whitespace())
                .unwrap_or(false)
            {
                s.pop();
            }
            true
        }
        KeyCode::Char(c) if !ctrl => {
            s.push(c);
            true
        }
        _ => false,
    }
}

#[test]
fn edit_keys() {
    let k = |c| KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE);
    let mut s = String::from("ab cd");
    assert!(edit(&mut s, &k('e')));
    assert_eq!(s, "ab cde");
    assert!(edit(
        &mut s,
        &KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL)
    ));
    assert_eq!(s, "ab ");
    assert!(edit(
        &mut s,
        &KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
    ));
    assert_eq!(s, "");
}

#[test]
fn connected_layout_renders_properly() {
    let mut app = App::new();
    let p = prof("a", "Frankfurt Reality", Kind::Vless, "vless://u@203.0.113.7:443?security=reality&sni=example.com&pbk=k&type=grpc&serviceName=x#Frankfurt");
    app.profiles = vec![p.clone()];
    app.view = vec![0];
    app.session = Some(Session {
        id: "a".into(),
        name: "Frankfurt Reality".into(),
        kind: Kind::Vless,
        server: "203.0.113.7:443".into(),
        iface: "vx0".into(),
        pid: Some(1337),
        sidecar_pid: None,
        backend: Some("sing-box+xray".into()),
        since: tunnel::now().saturating_sub(120),
        conf: "".into(),
    });
    app.down = vec![1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144];
    app.up = vec![512, 1024, 2048, 4096, 8192, 16384, 32768];
    app.down_peak = 262144;
    app.up_peak = 32768;
    app.rtt_hist = vec![42, 41, 43, 42, 45, 42, 40, 42];
    app.rtt = Some(42);
    app.ip = "185.220.101.5".into();
    let out = render(120, 32, &mut app);
    println!("{out}");
    assert!(out.contains("LINK ENGAGED"));
    assert!(out.contains("CHACHA20"));
    assert!(out.contains("PACKET FLOW"));
}

#[test]
fn test_qr_generation() {
    use qrcode::render::unicode;
    use qrcode::QrCode;
    let link = "vless://b6a03649-61f4-41aa-a51b-402c3cc6c547@203.0.113.7:443?security=reality&sni=example.com&pbk=1234567890abcdef1234567890abcdef1234567890a&type=grpc&serviceName=grpc-test#Frankfurt";
    let code = QrCode::new(link).unwrap();
    let qr_str = code.render::<unicode::Dense1x2>().quiet_zone(false).build();
    let lines: Vec<&str> = qr_str.lines().collect();
    println!(
        "QR (no quiet zone) lines: {}, width: {}",
        lines.len(),
        lines.first().map(|l| l.chars().count()).unwrap_or(0)
    );
    println!("\n{qr_str}\n");
}

#[test]
fn test_qr_modal_render() {
    let mut app = App::new();
    let p = prof(
        "test-qr",
        "Frankfurt QR",
        Kind::Vless,
        "vless://u@example.com:443?security=reality#Frankfurt",
    );
    let qr = store::generate_qr(&p.data).map_err(|e| format!("{e}"));
    app.qr_profile = Some(p);
    app.qr_code = Some(qr);
    app.qr_exported = Some("~/vortex-test-qr.conf".into());
    app.mode = Mode::Qr;
    let out = render(100, 30, &mut app);
    assert!(out.contains("0xQR // CONFIGURATION & QR EXPORT MATRIX"));
    assert!(out.contains("NODE TELEMETRY & CREDENTIALS"));
    assert!(out.contains("Frankfurt QR"));
    assert!(out.contains("EXPORT FILE"));
}

#[test]
fn test_subs_modal_render() {
    let mut app = App::new();
    let mut list = ListState::default();
    list.select(Some(0));
    let subs = vec![store::Subscription {
        id: "vip-node".into(),
        name: "VIP Dedicated Nodes".into(),
        url: "https://example.com/sub/token".into(),
        count: 12,
        updated: Some(1720000000),
        error: None,
    }];
    app.subs = subs;
    app.subs_list = list;
    app.mode = Mode::Subs;
    let out = render(100, 30, &mut app);
    assert!(out.contains("0xSUB // SUBSCRIPTION REGISTRY & SYNC MANAGER"));
    assert!(out.contains("VIP Dedicated Nodes"));
    assert!(out.contains("12 nodes"));
}

#[test]
fn test_ui_hotkeys_navigation() {
    let mut app = App::new();
    let p = prof(
        "test-hk",
        "HotKey Node",
        Kind::Vless,
        "vless://u@example.com:443#HotKey",
    );
    app.profiles = vec![p];
    app.rebuild();
    assert_eq!(app.view.len(), 1);

    // Press 's' to open QR modal
    app.handle_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE));
    assert!(matches!(app.mode, Mode::Qr));

    // Press Esc to dismiss QR modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.mode, Mode::Normal));

    // Press 'S' (Shift+s) to open Subs modal
    app.handle_key(KeyEvent::new(KeyCode::Char('S'), KeyModifiers::SHIFT));
    assert!(matches!(app.mode, Mode::Subs));

    // Press Esc to dismiss Subs modal
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.mode, Mode::Normal));

    // Press 'f' to toggle flows view
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
    assert!(app.show_flows);
    app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::NONE));
    assert!(!app.show_flows);

    // Press 'w' to initiate speed benchmark modal
    app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
    assert!(matches!(app.mode, Mode::Speed));
    app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(matches!(app.mode, Mode::Normal));

    // Test panel focus navigation with Tab and direct 1/2/3
    assert_eq!(app.focused_panel, 1);
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 2);
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 3);
    app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 1);
    app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 2);
    app.handle_key(KeyEvent::new(KeyCode::Char('3'), KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 3);
    app.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
    assert_eq!(app.focused_panel, 1);
}

#[test]
fn test_recon_modal_render() {
    let mut app = App::new();
    let report = ReconReport {
        node_name: "Frankfurt Cyber-Node".into(),
        kind: "VLESS".into(),
        target_endpoint: "203.0.113.7:443".into(),
        host: "203.0.113.7".into(),
        port: 443,
        resolved_ips: vec!["203.0.113.7".into()],
        reverse_dns: Some("node-fra.example.net".into()),
        asn: Some("AS13335".into()),
        org: Some("Cloudflare, Inc.".into()),
        city: Some("Frankfurt am Main".into()),
        country: Some("DE".into()),
        loc: Some("50.1109,8.6821".into()),
        rtt_min: 24,
        rtt_avg: 27,
        rtt_max: 31,
        jitter: 7,
        tls_version: Some("TLSv1.3".into()),
        tls_cipher: Some("TLS_AES_256_GCM_SHA384".into()),
        tls_cert_subject: Some("CN=*.example.net".into()),
        tls_cert_issuer: Some("CN=Let's Encrypt Authority".into()),
        exit_ip: Some("185.220.101.5".into()),
        exit_colo: Some("FRA".into()),
    };
    app.recon_report = Some(Ok(report));
    app.mode = Mode::Recon;
    let out = render(100, 32, &mut app);
    assert!(out.contains("0xRC // DEEP NODE RECONNAISSANCE & TLS FINGERPRINT REPORT"));
    assert!(out.contains("Frankfurt Cyber-Node"));
    assert!(out.contains("AS13335"));
    assert!(out.contains("TLSv1.3"));
    assert!(out.contains("TLS_AES_256_GCM_SHA384"));
}

#[test]
fn test_speed_modal_render() {
    let mut app = App::new();
    let speed = SpeedResult {
        bytes: 52_428_800,
        duration_secs: 4.12,
        mbps: 101.8,
        mbs: 12.72,
    };
    app.speed_result = Some(speed);
    app.speed_running = false;
    app.mode = Mode::Speed;
    let out = render(90, 20, &mut app);
    assert!(out.contains("0xSPD // LIVE BANDWIDTH THROUGHPUT & NETWORK BENCHMARK"));
    assert!(out.contains("101.80 Mbps"));
    assert!(out.contains("ULTRA-TIER / GIGABIT READY"));
}

#[test]
fn test_flows_table_render() {
    let mut app = App::new();
    app.show_flows = true;
    app.flows = vec![ActiveFlow {
        id: "flow-1".into(),
        network: "tcp".into(),
        host: "api.github.com:443".into(),
        destination: "140.82.121.6:443".into(),
        source: "127.0.0.1:48292".into(),
        process: "curl".into(),
        upload: 1024,
        download: 65536,
        duration_secs: None,
        rule: None,
    }];
    let p = prof("a", "Frankfurt", Kind::Vless, "vless://u@203.0.113.7:443");
    app.profiles = vec![p];
    app.view = vec![0];
    app.list.select(Some(0));
    let out = render(110, 30, &mut app);
    assert!(out.contains("PACKET FLOWS"));
    assert!(out.contains("api.github.com:443"));
    assert!(out.contains("curl"));
}

#[test]
fn test_snapshot_tcp_node() {
    let mut app = App::new();
    let mut p = prof(
        "tcp-node",
        "US-1",
        Kind::Trojan,
        "trojan://pass@1.2.3.4:443#Trojan",
    );
    p.transport = Transport::Tcp;
    p.security = Security::Tls;
    app.profiles = vec![p];
    app.rebuild();
    let out = render(120, 30, &mut app);
    assert!(out.contains("TCP"));
    assert!(out.contains("US-1"));
}

#[test]
fn test_snapshot_udp_quic_node() {
    let mut app = App::new();
    let mut p = prof("quic-node", "US-1", Kind::Hy2, "hy2://pass@1.2.3.4:443#Hy2");
    p.transport = Transport::Quic;
    p.security = Security::Tls;
    app.profiles = vec![p];
    app.rebuild();
    let out = render(120, 30, &mut app);
    assert!(out.contains("UDP/QUIC"));
    assert!(out.contains("US-1"));
}

#[test]
fn test_snapshot_ws_node() {
    let mut app = App::new();
    let mut p = prof(
        "ws-node",
        "US-1",
        Kind::Vless,
        "vless://u@1.2.3.4:443?type=ws#VlessWS",
    );
    p.transport = Transport::Ws;
    p.security = Security::Tls;
    app.profiles = vec![p];
    app.rebuild();
    let out = render(120, 30, &mut app);
    assert!(out.contains("TCP+WS"));
    assert!(out.contains("US-1"));
}

#[test]
fn test_snapshot_unknown_transport_node() {
    let mut app = App::new();
    let mut p = prof("unk-node", "US-1", Kind::Vless, "vless://u@1.2.3.4:443#Unk");
    p.transport = Transport::Unknown;
    p.security = Security::Unknown;
    app.profiles = vec![p];
    app.rebuild();
    let out = render(120, 30, &mut app);
    assert!(out.contains("--"));
    assert!(out.contains("US-1"));
}

#[test]
fn test_snapshot_narrow_terminal_column_hidden() {
    let mut app = App::new();
    let mut p = prof("node-1", "US-1", Kind::Hy2, "hy2://pass@1.2.3.4:443#Hy2");
    p.transport = Transport::Quic;
    app.profiles = vec![p];
    app.rebuild();

    // Wide terminal (width >= 100): transport column is shown in profiles list
    let wide_out = render(120, 30, &mut app);
    let wide_line = wide_out
        .lines()
        .find(|l| l.contains("US-1"))
        .expect("node line in wide");
    let wide_left_col = wide_line.split('│').nth(1).unwrap_or("");
    assert!(wide_left_col.contains("UDP/QUIC"));

    // Narrow terminal (width < 100): transport column is hidden in profiles list
    let narrow_out = render(90, 30, &mut app);
    let narrow_line = narrow_out
        .lines()
        .find(|l| l.contains("US-1"))
        .expect("node line in narrow");
    let narrow_left_col = narrow_line.split('│').nth(1).unwrap_or("");
    assert!(!narrow_left_col.contains("UDP/QUIC"));
    assert!(narrow_left_col.contains("US-1"));
}

#[test]
fn test_flows_table_columns_and_summary() {
    let mut app = App::new();
    app.show_flows = true;
    let mut flows = vec![];
    for i in 0..42 {
        flows.push(ActiveFlow {
            id: format!("tcp-{i}"),
            network: "tcp".into(),
            host: format!("host{i}.com:443"),
            destination: format!("1.2.3.4:{i}"),
            source: "127.0.0.1:1234".into(),
            process: "curl".into(),
            upload: 100,
            download: 200,
            duration_secs: None,
            rule: None,
        });
    }
    for i in 0..7 {
        flows.push(ActiveFlow {
            id: format!("udp-{i}"),
            network: "udp".into(),
            host: format!("dns{i}.com:53"),
            destination: format!("8.8.8.8:{i}"),
            source: "127.0.0.1:4321".into(),
            process: "c-ares".into(),
            upload: 50,
            download: 50,
            duration_secs: None,
            rule: None,
        });
    }
    app.flows = flows;
    let out = render(110, 30, &mut app);
    assert!(out.contains("TCP 42 · UDP 7"));
    assert!(out.contains("PORT"));
}

#[test]
fn test_traffic_panel_split() {
    let mut app = App::new();
    let p = prof(
        "conn-p",
        "Connected Node",
        Kind::Vless,
        "vless://u@1.2.3.4:443#Conn",
    );
    app.profiles = vec![p];
    app.rebuild();
    app.session = Some(Session {
        id: "conn-p".into(),
        name: "Connected Node".into(),
        kind: Kind::Vless,
        server: "1.2.3.4:443".into(),
        iface: "vx0".into(),
        pid: Some(1337),
        sidecar_pid: None,
        backend: Some("sing-box+xray".into()),
        since: tunnel::now().saturating_sub(60),
        conf: "".into(),
    });
    // 78% TCP, 22% UDP
    app.flows = vec![
        ActiveFlow {
            id: "f1".into(),
            network: "tcp".into(),
            host: "example.com:443".into(),
            destination: "1.2.3.4:443".into(),
            source: "127.0.0.1:1000".into(),
            process: "curl".into(),
            upload: 3900,
            download: 3900, // 7800 bytes
            duration_secs: None,
            rule: None,
        },
        ActiveFlow {
            id: "f2".into(),
            network: "udp".into(),
            host: "dns.com:53".into(),
            destination: "8.8.8.8:53".into(),
            source: "127.0.0.1:2000".into(),
            process: "dig".into(),
            upload: 1100,
            download: 1100, // 2200 bytes
            duration_secs: None,
            rule: None,
        },
    ];
    let out = render(110, 30, &mut app);
    assert!(out.contains("TCP 78% · UDP 22%"));
}

#[test]
fn test_sort_and_filter_by_transport() {
    let mut app = App::new();
    let mut p1 = prof("p1", "Alpha Node", Kind::Trojan, "trojan://u@1.2.3.4:443");
    p1.transport = Transport::Tcp;
    let mut p2 = prof("p2", "Beta Node", Kind::Hy2, "hy2://u@1.2.3.4:443");
    p2.transport = Transport::Quic;
    let mut p3 = prof("p3", "Gamma Node", Kind::Wg, "wg://u@1.2.3.4:443");
    p3.transport = Transport::Udp;
    app.profiles = vec![p1, p2, p3];
    app.rebuild();
    assert_eq!(app.view.len(), 3);

    // Cycle transport filter: All -> Tcp -> Udp -> All via key 'p'
    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.transport_filter, TransportFilter::Tcp);
    assert_eq!(app.view.len(), 1);
    assert_eq!(app.profiles[app.view[0]].id, "p1");

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.transport_filter, TransportFilter::Udp);
    // p2 is Quic (UDP based) and p3 is Udp
    assert_eq!(app.view.len(), 2);

    app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
    assert_eq!(app.transport_filter, TransportFilter::All);
    assert_eq!(app.view.len(), 3);
}
