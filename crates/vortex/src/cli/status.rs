use anyhow::Result;
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::model::OperationalMode;
use vortex_core::{ping, shield, storage, tunnel};

use super::get_ipc;

pub fn fmt_ping(r: ping::Ping) -> String {
    match r {
        ping::Ping::Ms(m) => format!("{m:>5} ms"),
        ping::Ping::Timeout => "  timeout".into(),
    }
}

pub fn trunc_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

pub fn detect_country_flag(name: &str) -> String {
    let trimmed = name.trim();
    let mut chars = trimmed.chars();
    if let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        if ('\u{1F1E6}'..='\u{1F1FF}').contains(&c1) && ('\u{1F1E6}'..='\u{1F1FF}').contains(&c2) {
            let mut flag_str = String::new();
            flag_str.push(c1);
            flag_str.push(c2);
            return flag_str;
        }
    }

    let lower = trimmed.to_lowercase();
    let flag = if lower.contains("germany")
        || lower.contains("frankfurt")
        || lower.contains("berlin")
        || lower.starts_with("de")
        || lower.contains("-de-")
        || lower.ends_with("-de")
    {
        "🇩🇪"
    } else if lower.contains("united states")
        || lower.contains("america")
        || lower.contains("ashburn")
        || lower.contains("los angeles")
        || lower.contains("new york")
        || lower.contains("chicago")
        || lower.contains("miami")
        || lower.starts_with("us")
        || lower.contains("-us-")
        || lower.ends_with("-us")
    {
        "🇺🇸"
    } else if lower.contains("netherlands")
        || lower.contains("amsterdam")
        || lower.starts_with("nl")
        || lower.contains("-nl-")
        || lower.ends_with("-nl")
    {
        "🇳🇱"
    } else if lower.contains("france")
        || lower.contains("paris")
        || lower.starts_with("fr")
        || lower.contains("-fr-")
        || lower.ends_with("-fr")
    {
        "🇫🇷"
    } else if lower.contains("united kingdom")
        || lower.contains("london")
        || lower.contains("england")
        || lower.starts_with("gb")
        || lower.starts_with("uk")
        || lower.contains("-gb-")
        || lower.ends_with("-gb")
    {
        "🇬🇧"
    } else if lower.contains("turkey")
        || lower.contains("istanbul")
        || lower.starts_with("tr")
        || lower.contains("-tr-")
        || lower.ends_with("-tr")
    {
        "🇹🇷"
    } else if lower.contains("singapore")
        || lower.starts_with("sg")
        || lower.contains("-sg-")
        || lower.ends_with("-sg")
    {
        "🇸🇬"
    } else if lower.contains("japan")
        || lower.contains("tokyo")
        || lower.contains("osaka")
        || lower.starts_with("jp")
        || lower.contains("-jp-")
        || lower.ends_with("-jp")
    {
        "🇯🇵"
    } else if lower.contains("canada")
        || lower.contains("toronto")
        || lower.contains("montreal")
        || lower.starts_with("ca")
        || lower.contains("-ca-")
        || lower.ends_with("-ca")
    {
        "🇨🇦"
    } else if lower.contains("finland")
        || lower.contains("helsinki")
        || lower.starts_with("fi")
        || lower.contains("-fi-")
        || lower.ends_with("-fi")
    {
        "🇫🇮"
    } else if lower.contains("sweden")
        || lower.contains("stockholm")
        || lower.starts_with("se")
        || lower.contains("-se-")
        || lower.ends_with("-se")
    {
        "🇸🇪"
    } else if lower.contains("switzerland")
        || lower.contains("zurich")
        || lower.starts_with("ch")
        || lower.contains("-ch-")
        || lower.ends_with("-ch")
    {
        "🇨🇭"
    } else if lower.contains("iran")
        || lower.contains("tehran")
        || lower.starts_with("ir")
        || lower.contains("-ir-")
        || lower.ends_with("-ir")
    {
        "🇮🇷"
    } else if lower.contains("uae")
        || lower.contains("dubai")
        || lower.starts_with("ae")
        || lower.contains("-ae-")
        || lower.ends_with("-ae")
    {
        "🇦🇪"
    } else if lower.contains("poland")
        || lower.contains("warsaw")
        || lower.starts_with("pl")
        || lower.contains("-pl-")
        || lower.ends_with("-pl")
    {
        "🇵🇱"
    } else if lower.contains("spain")
        || lower.contains("madrid")
        || lower.starts_with("es")
        || lower.contains("-es-")
        || lower.ends_with("-es")
    {
        "🇪🇸"
    } else if lower.contains("italy")
        || lower.contains("milan")
        || lower.contains("rome")
        || lower.starts_with("it")
        || lower.contains("-it-")
        || lower.ends_with("-it")
    {
        "🇮🇹"
    } else if lower.contains("russia")
        || lower.contains("moscow")
        || lower.starts_with("ru")
        || lower.contains("-ru-")
        || lower.ends_with("-ru")
    {
        "🇷🇺"
    } else if lower.contains("ukraine")
        || lower.contains("kyiv")
        || lower.starts_with("ua")
        || lower.contains("-ua-")
        || lower.ends_with("-ua")
    {
        "🇺🇦"
    } else if lower.contains("hong kong")
        || lower.starts_with("hk")
        || lower.contains("-hk-")
        || lower.ends_with("-hk")
    {
        "🇭🇰"
    } else if lower.contains("taiwan")
        || lower.contains("taipei")
        || lower.starts_with("tw")
        || lower.contains("-tw-")
        || lower.ends_with("-tw")
    {
        "🇹🇼"
    } else if lower.contains("korea")
        || lower.contains("seoul")
        || lower.starts_with("kr")
        || lower.contains("-kr-")
        || lower.ends_with("-kr")
    {
        "🇰🇷"
    } else if lower.contains("india")
        || lower.contains("mumbai")
        || lower.starts_with("in")
        || lower.contains("-in-")
        || lower.ends_with("-in")
    {
        "🇮🇳"
    } else if lower.contains("australia")
        || lower.contains("sydney")
        || lower.starts_with("au")
        || lower.contains("-au-")
        || lower.ends_with("-au")
    {
        "🇦🇺"
    } else if lower.contains("brazil")
        || lower.contains("sao paulo")
        || lower.starts_with("br")
        || lower.contains("-br-")
        || lower.ends_with("-br")
    {
        "🇧🇷"
    } else if lower.contains("austria")
        || lower.contains("vienna")
        || lower.starts_with("at")
        || lower.contains("-at-")
        || lower.ends_with("-at")
    {
        "🇦🇹"
    } else if lower.contains("norway")
        || lower.contains("oslo")
        || lower.starts_with("no")
        || lower.contains("-no-")
        || lower.ends_with("-no")
    {
        "🇳🇴"
    } else if lower.contains("denmark")
        || lower.contains("copenhagen")
        || lower.starts_with("dk")
        || lower.contains("-dk-")
        || lower.ends_with("-dk")
    {
        "🇩🇰"
    } else if lower.contains("belgium")
        || lower.contains("brussels")
        || lower.starts_with("be")
        || lower.contains("-be-")
        || lower.ends_with("-be")
    {
        "🇧🇪"
    } else {
        "🌐"
    };
    flag.to_string()
}

pub fn format_node_with_flag(name: &str, max_len: usize) -> String {
    let flag = detect_country_flag(name);
    let trimmed = name.trim();
    if trimmed.starts_with(&flag) {
        trunc_str(trimmed, max_len)
    } else {
        format!("{flag} {}", trunc_str(trimmed, max_len.saturating_sub(3)))
    }
}

pub fn escape_pango(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn format_status_json(
    connected: bool,
    name: &str,
    kind_tag: &str,
    server: &str,
    uptime_secs: u64,
    armed: bool,
    mode: OperationalMode,
) -> serde_json::Value {
    let shield_class = if armed { "shield-armed" } else { "shield-off" };
    if connected {
        let uptime_fmt = if uptime_secs < 60 {
            format!("{uptime_secs}s")
        } else if uptime_secs < 3600 {
            format!("{}m {}s", uptime_secs / 60, uptime_secs % 60)
        } else {
            format!("{}h {}m", uptime_secs / 3600, (uptime_secs % 3600) / 60)
        };

        let raw_text = format_node_with_flag(name, 16);
        let text = escape_pango(&raw_text);
        let tooltip = format!(
            "<b>Vortex VPN &amp; Proxy</b>\n<b>Mode:</b> {}\n<b>Status:</b> Connected\n<b>Node:</b> {} ({})\n<b>Endpoint:</b> {}\n<b>Shield:</b> {}\n<b>Uptime:</b> {}\n<i>Left-click: toggle · Right-click: menu</i>",
            escape_pango(mode.display_name()),
            escape_pango(name),
            escape_pango(kind_tag),
            escape_pango(server),
            if armed { "ARMED 🛡️" } else { "OFF" },
            uptime_fmt
        );

        serde_json::json!({
            "text": text,
            "alt": "connected",
            "tooltip": tooltip,
            "class": ["connected", shield_class],
            "connected": true,
            "mode": mode.as_str(),
            "node": name,
            "protocol": kind_tag,
            "server": server,
            "shield": armed,
            "uptime_secs": uptime_secs,
        })
    } else {
        let text = if armed {
            "󰌙 Off 🛡️"
        } else {
            "󰌙 Off"
        };
        let tooltip = format!(
            "<b>Vortex VPN &amp; Proxy</b>\n<b>Mode:</b> {}\n<b>Status:</b> Disconnected\n<b>Shield:</b> {}\n<i>Left-click: connect · Right-click: menu</i>",
            escape_pango(mode.display_name()),
            if armed { "ARMED 🛡️" } else { "OFF" }
        );

        serde_json::json!({
            "text": text,
            "alt": "disconnected",
            "tooltip": tooltip,
            "class": ["disconnected", shield_class],
            "connected": false,
            "mode": mode.as_str(),
            "shield": armed,
        })
    }
}

pub fn format_status_error_json(err: &str) -> serde_json::Value {
    serde_json::json!({
        "text": "vortex ?",
        "class": ["error"],
        "tooltip": escape_pango(err),
    })
}

pub fn handle_status(args: &[String]) -> Result<()> {
    let json_mode = args
        .iter()
        .any(|a| a == "--json" || a == "--waybar" || a == "-j");

    if json_mode {
        let res = (|| -> Result<()> {
            let daemon_status = if let Some(client) = get_ipc() {
                match client.request_sync(&IpcRequest::GetStatus) {
                    Ok(IpcResponse::Status(st)) => Some(st),
                    _ => None,
                }
            } else {
                None
            };

            let cur_mode = daemon_status
                .as_ref()
                .map(|st| st.mode)
                .unwrap_or_else(storage::get_mode_preference);

            let (connected, name, kind_tag, server, uptime_secs, armed) =
                if let Some(st) = &daemon_status {
                    let (name, kind_tag) = if let Some(p) = &st.active_profile {
                        (p.name.clone(), p.kind.tag().to_string())
                    } else if let Some(s) = tunnel::load_session() {
                        (s.name, s.kind.tag().to_string())
                    } else {
                        ("Connected".to_string(), "".to_string())
                    };
                    let srv = st.server_endpoint.clone().unwrap_or_default();
                    (
                        st.connected,
                        name,
                        kind_tag,
                        srv,
                        st.uptime_secs,
                        st.shield_armed,
                    )
                } else {
                    let sess = tunnel::load_session();
                    let armed = shield::is_armed();
                    match sess {
                        Some(s) => {
                            let up = tunnel::now().saturating_sub(s.since);
                            (
                                true,
                                s.name,
                                s.kind.tag().to_string(),
                                s.server,
                                up,
                                armed,
                            )
                        }
                        None => (
                            false,
                            String::new(),
                            String::new(),
                            String::new(),
                            0,
                            armed,
                        ),
                    }
                };

            let json = format_status_json(
                connected,
                &name,
                &kind_tag,
                &server,
                uptime_secs,
                armed,
                cur_mode,
            );
            println!("{}", serde_json::to_string(&json)?);
            Ok(())
        })();

        if let Err(e) = res {
            let err_json = format_status_error_json(&e.to_string());
            println!(
                "{}",
                serde_json::to_string(&err_json).unwrap_or_else(|_| {
                    "{\"class\":[\"error\"],\"text\":\"vortex ?\",\"tooltip\":\"error\"}".to_string()
                })
            );
        }
        return Ok(());
    }

    let daemon_status = if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::GetStatus) {
            Ok(IpcResponse::Status(st)) => Some(st),
            _ => None,
        }
    } else {
        None
    };

    let cur_mode = daemon_status
        .as_ref()
        .map(|st| st.mode)
        .unwrap_or_else(storage::get_mode_preference);

    let (connected, name, kind_tag, server, uptime_secs, armed, is_daemon) =
        if let Some(st) = &daemon_status {
            let (name, kind_tag) = if let Some(p) = &st.active_profile {
                (p.name.clone(), p.kind.tag().to_string())
            } else if let Some(s) = tunnel::load_session() {
                (s.name, s.kind.tag().to_string())
            } else {
                ("Connected".to_string(), "".to_string())
            };
            let srv = st.server_endpoint.clone().unwrap_or_default();
            (
                st.connected,
                name,
                kind_tag,
                srv,
                st.uptime_secs,
                st.shield_armed,
                true,
            )
        } else {
            let sess = tunnel::load_session();
            let armed = shield::is_armed();
            match sess {
                Some(s) => {
                    let up = tunnel::now().saturating_sub(s.since);
                    (
                        true,
                        s.name,
                        s.kind.tag().to_string(),
                        s.server,
                        up,
                        armed,
                        false,
                    )
                }
                None => (
                    false,
                    String::new(),
                    String::new(),
                    String::new(),
                    0,
                    armed,
                    false,
                ),
            }
        };

    let daemon_str = if is_daemon {
        "\x1b[1;32mvortexd active\x1b[0m"
    } else {
        "\x1b[2mvortexd inactive (direct mode)\x1b[0m"
    };

    let shield_str = if armed {
        "\x1b[1;32m[SHIELD: ARMED]\x1b[0m"
    } else {
        "\x1b[2m[SHIELD: OFF]\x1b[0m"
    };

    let mode_str = match cur_mode {
        OperationalMode::Tunnel => "\x1b[1;36m[TUNNEL]\x1b[0m",
        OperationalMode::Proxy => "\x1b[1;33m[PROXY]\x1b[0m",
    };

    if connected {
        println!(
            "● {} ({}) via {}  {}  {}  [{daemon_str}]",
            name, kind_tag, server, mode_str, shield_str
        );
        println!("  uptime {}s · exit {}", uptime_secs, tunnel::public_ip());
        println!("  proxy bridge: socks5://127.0.0.1:1080 · http://127.0.0.1:1080");
    } else {
        println!("○ Disconnected  {mode_str}  {shield_str}  [{daemon_str}]");
        println!("  proxy bridge: socks5://127.0.0.1:1080 · http://127.0.0.1:1080");
        println!("  run `vortex up` to connect, `vortex proxy` to manage environment");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_country_flag_existing_emoji() {
        assert_eq!(detect_country_flag("🇩🇪 Frankfurt"), "🇩🇪");
        assert_eq!(detect_country_flag("🇺🇸 US-Ashburn"), "🇺🇸");
        assert_eq!(detect_country_flag("🇯🇵 Tokyo 01"), "🇯🇵");
    }

    #[test]
    fn test_detect_country_flag_keywords() {
        assert_eq!(detect_country_flag("Frankfurt Fast-01"), "🇩🇪");
        assert_eq!(detect_country_flag("Amsterdam-1"), "🇳🇱");
        assert_eq!(detect_country_flag("Tokyo VIP"), "🇯🇵");
        assert_eq!(detect_country_flag("Custom Unknown"), "🌐");
    }

    #[test]
    fn test_format_node_with_flag_no_duplicates() {
        assert_eq!(format_node_with_flag("🇩🇪 Frankfurt", 20), "🇩🇪 Frankfurt");
        assert_eq!(
            format_node_with_flag("Frankfurt Fast", 20),
            "🇩🇪 Frankfurt Fast"
        );
    }

    #[test]
    fn test_status_json_waybar_format() {
        let node_name = "A & <B>";
        let val = format_status_json(
            true,
            node_name,
            "vless",
            "1.2.3.4:443",
            120,
            true,
            OperationalMode::Tunnel,
        );

        let json_str = serde_json::to_string(&val).expect("must be valid JSON");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("must parse back");

        // 1. class is an array of strings
        let class = parsed["class"].as_array().expect("class must be a JSON array");
        assert_eq!(
            class,
            serde_json::json!(["connected", "shield-armed"]).as_array().unwrap()
        );

        // 2. text and tooltip contain no raw & or < from node names
        let text = parsed["text"].as_str().expect("text must be string");
        let tooltip = parsed["tooltip"].as_str().expect("tooltip must be string");

        assert!(text.contains("A &amp; &lt;B&gt;"));
        assert!(!text.contains("A & <B>"));
        assert!(!text.contains('<'));

        assert!(tooltip.contains("A &amp; &lt;B&gt;"));
        assert!(!tooltip.contains("A & <B>"));
        assert!(tooltip.contains("<b>Vortex VPN &amp; Proxy</b>"));

        // Verify no raw & in text
        for part in text.split('&').skip(1) {
            assert!(part.starts_with("amp;") || part.starts_with("lt;") || part.starts_with("gt;"));
        }

        // Test disconnected
        let disc_val = format_status_json(
            false,
            "",
            "",
            "",
            0,
            false,
            OperationalMode::Proxy,
        );
        let disc_parsed: serde_json::Value = serde_json::from_str(&disc_val.to_string()).unwrap();
        assert_eq!(
            disc_parsed["class"].as_array().unwrap(),
            serde_json::json!(["disconnected", "shield-off"]).as_array().unwrap()
        );

        // Test error format
        let err_val = format_status_error_json("internal error: connection to <daemon> & socket failed");
        let err_parsed: serde_json::Value = serde_json::from_str(&err_val.to_string()).unwrap();
        assert_eq!(
            err_parsed["class"].as_array().unwrap(),
            serde_json::json!(["error"]).as_array().unwrap()
        );
        assert_eq!(err_parsed["text"], "vortex ?");
        let err_tip = err_parsed["tooltip"].as_str().unwrap();
        assert!(err_tip.contains("&lt;daemon&gt; &amp; socket failed"));
        assert!(!err_tip.contains('<'));
    }
}
