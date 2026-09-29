# vortex ◢

Minimal terminal VPN/proxy manager for Omarchy. One list, one keypress, whole-system tunnel.

| Protocol | Engine | Import |
|---|---|---|
| VLESS (Reality, WS, gRPC, TLS…), VMess, Trojan, Shadowsocks, Hysteria2, TUIC | `sing-box` TUN (auto-route + strict-route) | share link, subscription URL |
| WireGuard | `wg-quick` | `.conf` |
| AmneziaWG | `awg-quick` | `.conf`, Amnezia `vpn://` link |
| OpenVPN | `openvpn` | `.ovpn` (certs next to the file are inlined) |

## Install
    ./install.sh

## Use
    vortex                # TUI
    vortex add <link | https://sub-url | file.conf>
    vortex list | up [n|name] | down | status
    vortex ping           # latency of every profile, fastest first
    vortex best           # test all, connect to the fastest
    vortex rename <n|name> <new name> | rm <n|name>

`vortex up` with no argument reconnects the last-used profile.

TUI keys (`?` shows them in-app):
`⏎` connect · `space` disconnect · `a` add · `v` paste from clipboard · `/` filter · `t`/`T` test latency (all / selected) · `o` sort by latency · `r` rename · `d` delete · `l` core log · `i` refresh exit IP · `q` quit (tunnel keeps running) · `Q` quit + disconnect.
Pasting (ctrl+shift+v) anywhere in the list imports directly. Latency is tested on launch; while connected the header and traffic pane show live RTT through the tunnel.

## Notes
- Runs as root (re-execs through `sudo`). Profiles live in `/etc/vortex/profiles` (0600).
- All sing-box protocols share one TUN (`vx0`); DNS goes through the tunnel (DoH), the proxy server itself is resolved directly.
- Server latency can only be measured while disconnected (a connected tunnel would route the probe through itself).
- Don't run alongside TorJet — both rewrite routing/firewall rules.
- Not supported yet: Xray-only transports (xhttp), OpenVPN username/password prompts, Amnezia Xray/Cloak containers, kill-switch for wg/ovpn.
