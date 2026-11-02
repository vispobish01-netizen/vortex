use anyhow::{bail, Result};

const BASH_COMPLETION: &str = r#"# Bash completion for vortex
_vortex_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="add list ls up down toggle best ping pick qr conf proxy mode shield leaks recon speed flows route history sub update auth rename rm status completion"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi

    case "${prev}" in
        up|recon|qr|conf|auth|rename|rm|pick)
            local profiles=$(vortex list 2>/dev/null | awk '{print $3}')
            COMPREPLY=( $(compgen -W "${profiles}" -- ${cur}) )
            return 0
            ;;
        mode)
            COMPREPLY=( $(compgen -W "tunnel proxy toggle status" -- ${cur}) )
            return 0
            ;;
        status)
            COMPREPLY=( $(compgen -W "--json --waybar" -- ${cur}) )
            return 0
            ;;
        shield)
            COMPREPLY=( $(compgen -W "on off status" -- ${cur}) )
            return 0
            ;;
        route)
            COMPREPLY=( $(compgen -W "list explain bypass block clear" -- ${cur}) )
            return 0
            ;;
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _vortex_completions vortex
"#;

const ZSH_COMPLETION: &str = r#"#compdef vortex
_vortex() {
    local -a commands
    commands=(
        'add:import share link, sub URL, QR image, or .conf/.ovpn'
        'list:list all imported profiles'
        'up:connect to profile by name or number'
        'down:disconnect active tunnel'
        'toggle:connect fastest if down, disconnect if up'
        'best:test latency and connect to fastest node'
        'ping:measure RTT of all profiles'
        'pick:interactive fuzzy node selector (rofi/fuzzel/zenity)'
        'qr:display terminal QR code for mobile import'
        'conf:show raw configuration text'
        'proxy:manage local SOCKS5/HTTP proxy bridge (:1080)'
        'mode:set or inspect operational mode (tunnel vs proxy)'
        'shield:toggle nftables stealth kill switch'
        'leaks:run comprehensive DNS, IPv6, and STUN leak audit'
        'recon:perform deep node reconnaissance'
        'speed:measure live bandwidth throughput under load'
        'flows:live socket and packet traffic sniffer'
        'route:manage split tunneling, LAN bypass, and domain rules'
        'history:inspect traffic accounting and metrics'
        'sub:manage remote subscriptions'
        'update:sync all subscriptions'
        'status:display active tunnel & shield status'
        'completion:generate shell autocompletions'
    )
    _describe -t commands 'vortex commands' commands
}
_vortex "$@"
"#;

const FISH_COMPLETION: &str = r#"# Fish completion for vortex
complete -c vortex -f
complete -c vortex -n "__fish_use_subcommand" -a "add" -d "Import share link or config"
complete -c vortex -n "__fish_use_subcommand" -a "list" -d "List profiles"
complete -c vortex -n "__fish_use_subcommand" -a "up" -d "Connect to profile"
complete -c vortex -n "__fish_use_subcommand" -a "down" -d "Disconnect tunnel"
complete -c vortex -n "__fish_use_subcommand" -a "toggle" -d "Toggle tunnel connection"
complete -c vortex -n "__fish_use_subcommand" -a "best" -d "Connect to fastest node"
complete -c vortex -n "__fish_use_subcommand" -a "ping" -d "Test latency of all nodes"
complete -c vortex -n "__fish_use_subcommand" -a "pick" -d "Interactive node selector"
complete -c vortex -n "__fish_use_subcommand" -a "mode" -d "Set or inspect operational mode"
complete -c vortex -n "__fish_seen_subcommand_from mode" -a "tunnel proxy toggle status" -d "Operational modes"
complete -c vortex -n "__fish_use_subcommand" -a "shield" -d "Toggle kill switch shield"
complete -c vortex -n "__fish_use_subcommand" -a "leaks" -d "Run leak audit"
complete -c vortex -n "__fish_use_subcommand" -a "route" -d "Split tunneling rules"
complete -c vortex -n "__fish_use_subcommand" -a "history" -d "Traffic history"
complete -c vortex -n "__fish_use_subcommand" -a "status" -d "Show tunnel status"
complete -c vortex -n "__fish_seen_subcommand_from status" -l json -d "Output Waybar/JSON status"
complete -c vortex -n "__fish_seen_subcommand_from status" -l waybar -d "Output Waybar/JSON status"
"#;

pub fn handle_completion(args: &[String]) -> Result<()> {
    let shell = args.get(1).map(String::as_str).unwrap_or("bash");
    match shell {
        "bash" => print!("{BASH_COMPLETION}"),
        "zsh" => print!("{ZSH_COMPLETION}"),
        "fish" => print!("{FISH_COMPLETION}"),
        other => bail!("unsupported shell '{other}' — try bash, zsh, fish"),
    }
    Ok(())
}
