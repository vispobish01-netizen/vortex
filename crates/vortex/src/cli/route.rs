use anyhow::{bail, Result};
use vortex_core::ipc::{IpcRequest, IpcResponse};
use vortex_core::routing::{ExplainResult, RuleAction, RulesConfig};

use super::get_ipc;

fn load_rules() -> RulesConfig {
    if let Some(client) = get_ipc() {
        if let Ok(IpcResponse::RulesConfig(cfg)) = client.request_sync(&IpcRequest::GetRulesConfig)
        {
            return cfg;
        }
    }
    RulesConfig::load()
}

fn save_rules(cfg: &RulesConfig) -> Result<()> {
    if let Some(client) = get_ipc() {
        match client.request_sync(&IpcRequest::SetRulesConfig(cfg.clone()))? {
            IpcResponse::RulesConfig(_) | IpcResponse::Ok => return Ok(()),
            IpcResponse::Error(e) => bail!("Daemon routing error: {e}"),
            _ => {}
        }
    }
    cfg.save()
}

fn explain_target(target: &str) -> Result<ExplainResult> {
    if let Some(client) = get_ipc() {
        if let Ok(IpcResponse::ExplainRoute(res)) = client.request_sync(&IpcRequest::ExplainRoute {
            target: target.to_string(),
            protocol: None,
            port: None,
            process: None,
        }) {
            return Ok(res);
        }
    }
    Ok(RulesConfig::load().explain(target, None, None, None))
}

pub fn handle_route(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("list");
    match sub {
        "list" => {
            let rcfg = load_rules();
            println!("\x1b[1;36m◈ 0xROUTE // SPLIT TUNNELING & ROUTING RULES MATRIX\x1b[0m");
            println!("  \x1b[1mPreset Filters:\x1b[0m");
            println!(
                "    Bypass LAN (RFC1918)    : {}",
                if rcfg.presets.bypass_lan {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Block Trackers & Ads    : {}",
                if rcfg.presets.block_ads {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Direct Domestic GeoIP   : {}",
                if rcfg.presets.direct_domestic {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "    Global Proxy Fallback   : {}",
                if rcfg.presets.proxy_all {
                    "\x1b[1;32mENABLED\x1b[0m"
                } else {
                    "\x1b[2mDISABLED\x1b[0m"
                }
            );
            println!(
                "\n  \x1b[1mCustom Rules ({} active):\x1b[0m",
                rcfg.custom_rules.len()
            );
            for (i, r) in rcfg.custom_rules.iter().enumerate() {
                let act = match r.action {
                    RuleAction::Proxy => "\x1b[1;36mPROXY\x1b[0m",
                    RuleAction::Direct => "\x1b[1;32mDIRECT\x1b[0m",
                    RuleAction::Block => "\x1b[1;31mBLOCK\x1b[0m",
                    RuleAction::ProxyGroup => "\x1b[1;35mGROUP\x1b[0m",
                };
                println!(
                    "    [{:02}] {:<18} -> {act} ({})",
                    i + 1,
                    r.id,
                    r.description.as_deref().unwrap_or("custom rule")
                );
            }
            println!("\n\x1b[2mExplain resolution with `vortex route explain <target>`\x1b[0m");
        }
        "explain" => {
            let target = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route explain <target>"))?;
            let res = explain_target(target)?;
            println!("\x1b[1;36m◈ ROUTE POLICY RESOLUTION FOR:\x1b[0m {target}\n");
            println!(
                "  Matched Rule : \x1b[1m{}\x1b[0m (Rule #{})",
                res.rule_id, res.rule_index
            );
            let (act_str, act_col) = match res.action {
                RuleAction::Proxy => ("PROXY (TUNNEL)", "\x1b[1;36m"),
                RuleAction::Direct => ("DIRECT (BYPASS)", "\x1b[1;32m"),
                RuleAction::Block => ("BLOCK (REJECT)", "\x1b[1;31m"),
                RuleAction::ProxyGroup => ("PROXY GROUP", "\x1b[1;35m"),
            };
            println!("  Final Action : {act_col}{act_str}\x1b[0m");
            println!("  Match Reason : {}", res.reason);
        }
        "bypass" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route bypass <domain>"))?;
            let mut rcfg = load_rules();
            if rcfg.add_bypass_domain(domain) {
                save_rules(&rcfg)?;
                println!("added direct bypass domain: {domain}");
            }
        }
        "block" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route block <domain>"))?;
            let mut rcfg = load_rules();
            if rcfg.add_block_domain(domain) {
                save_rules(&rcfg)?;
                println!("added blocked domain: {domain}");
            }
        }
        "clear" => {
            let mut rcfg = load_rules();
            if rcfg.clear_cli_domain_rules() {
                save_rules(&rcfg)?;
            }
            println!("cleared custom domain rules");
        }
        other => bail!("unknown route command '{other}' — try list, explain, bypass, block, clear"),
    }
    Ok(())
}
