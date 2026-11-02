use anyhow::{bail, Result};
use vortex_core::tunnel;

pub fn handle_route(args: &[String]) -> Result<()> {
    let sub = args.get(1).map(String::as_str).unwrap_or("list");
    let mut cfg = tunnel::load_routing();
    match sub {
        "list" => {
            let rcfg = vortex_core::routing::RulesConfig::load();
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
                    vortex_core::routing::RuleAction::Proxy => "\x1b[1;36mPROXY\x1b[0m",
                    vortex_core::routing::RuleAction::Direct => "\x1b[1;32mDIRECT\x1b[0m",
                    vortex_core::routing::RuleAction::Block => "\x1b[1;31mBLOCK\x1b[0m",
                    vortex_core::routing::RuleAction::ProxyGroup => "\x1b[1;35mGROUP\x1b[0m",
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
            let rcfg = vortex_core::routing::RulesConfig::load();
            let res = rcfg.explain(target, None, None, None);
            println!("\x1b[1;36m◈ ROUTE POLICY RESOLUTION FOR:\x1b[0m {target}\n");
            println!(
                "  Matched Rule : \x1b[1m{}\x1b[0m (Rule #{})",
                res.rule_id, res.rule_index
            );
            let (act_str, act_col) = match res.action {
                vortex_core::routing::RuleAction::Proxy => ("PROXY (TUNNEL)", "\x1b[1;36m"),
                vortex_core::routing::RuleAction::Direct => ("DIRECT (BYPASS)", "\x1b[1;32m"),
                vortex_core::routing::RuleAction::Block => ("BLOCK (REJECT)", "\x1b[1;31m"),
                vortex_core::routing::RuleAction::ProxyGroup => ("PROXY GROUP", "\x1b[1;35m"),
            };
            println!("  Final Action : {act_col}{act_str}\x1b[0m");
            println!("  Match Reason : {}", res.reason);
        }
        "bypass" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route bypass <domain>"))?;
            if !cfg.direct_domains.contains(&domain.to_string()) {
                cfg.direct_domains.push(domain.to_string());
                tunnel::save_routing(&cfg)?;
                println!("added direct bypass domain: {domain}");
            }
        }
        "block" => {
            let domain = args
                .get(2)
                .ok_or_else(|| anyhow::anyhow!("usage: vortex route block <domain>"))?;
            if !cfg.blocked_domains.contains(&domain.to_string()) {
                cfg.blocked_domains.push(domain.to_string());
                tunnel::save_routing(&cfg)?;
                println!("added blocked domain: {domain}");
            }
        }
        "clear" => {
            cfg.direct_domains.clear();
            cfg.blocked_domains.clear();
            tunnel::save_routing(&cfg)?;
            println!("cleared custom domain rules");
        }
        other => bail!("unknown route command '{other}' — try list, explain, bypass, block, clear"),
    }
    Ok(())
}
