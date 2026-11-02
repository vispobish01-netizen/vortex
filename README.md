# vortex ◢

Tactical egress daemon, terminal cockpit, and VPN/proxy manager built natively for Linux & Omarchy.

```
┌─────────────────────────────────────────────────────────────┐
│ 1. AMBIENT DESKTOP CITIZEN (Omarchy / Hyprland / Waybar)    │
│    • Waybar module: [🇩🇪 DE-01 42ms 🛡️]                     │
│    • Hotkey toggle (`Super+V`), Rofi/Fuzzel node picker     │
│    • Desktop notifications on connect, disconnect & failover│
├─────────────────────────────────────────────────────────────┤
│ 2. TACTICAL TERMINAL COCKPIT (`vortex` TUI / CLI)           │
│    • Keyboard-first (Vim motions), sub-millisecond launch   │
│    • Packet flows sniffer, latency jitter, deep node recon  │
│    • Split tunneling, domain rules, and live benchmarks     │
├─────────────────────────────────────────────────────────────┤
│ 3. DETERMINISTIC SYSTEM DAEMON (`vortexd` + `nftables`)     │
│    • Background service managing TUN & routing over IPC     │
│    • Non-root client execution via Unix domain socket       │
│    • Atomic nftables kill-switch & IPv6 leak protection     │
│    • Multi-layer active probing and autonomous failover     │
└─────────────────────────────────────────────────────────────┘
```

---

## Supported Protocols & Ingestion

Paste any link, scan a QR code, or point to a file:

| Protocol | Engine | Ingestion Format |
|---|---|---|
| **VLESS** (REALITY, Vision, XHTTP, PQ `mlkem768x25519plus`, ECH), **VMess**, **Trojan**, **Shadowsocks**, **Hysteria 2** | `xray-core` / `sing-box` TUN (`vx0`) | Share URLs (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`), raw Xray JSON, subscription endpoints |
| **WireGuard** | `wg-quick` (`vxwg0`) | `.conf` file |
| **AmneziaWG** | `awg-quick` (`vxawg0`) | `.conf` file, Amnezia `vpn://` links |
| **OpenVPN** | `openvpn` (`tun0`) | `.ovpn` file (embedded or inline certs) with credential save mode |

---

## Xray-Core Managed Engine

Vortex includes native, first-class lifecycle management for [Xray-core](https://github.com/XTLS/Xray-core):

- **Dynamic Release Discovery**: Queries upstream GitHub releases (including pre-releases) to acquire the newest release (e.g. `v26.9.30+`).
- **Security & Integrity**: Strict SHA256/SHA512 `.dgst` checksum verification before extraction. Downloads run entirely unprivileged (never as root).
- **Atomic Symlinks & Rollbacks**: Installed to `~/.local/share/vortex/xray/<version>/` with an atomic `current` symlink. Rollbacks take a single command.
- **Modern Transports**: Full support for VLESS `xtls-rprx-vision`, REALITY (publicKey, shortId, serverName, fingerprint, spiderX), XHTTP, gRPC, WebSocket, TLS with ECH & certificate pinning, and post-quantum `mlkem768x25519plus`.
- **System-Wide TUN & Routing Shield**: Kernel TUN inbound (`vx0`), gRPC stats query over internal IPC, DoH leak protection, remote server route exclusion to prevent routing loops, and isolated ephemeral instance probing.

```bash
vortex xray install            # Dynamically fetch, verify & install newest stable Xray-core
vortex xray update             # Check for newer releases and refresh geoip.dat / geosite.dat
vortex xray version            # Inspect active Xray version, source (system vs managed), and path
vortex xray doctor             # Audit binary permissions, kernel TUN support, and dependencies
vortex xray rollback           # Instantly switch back to the previously installed version
vortex xray test <config.json> # Validate Xray JSON syntax and routing schema
```

---

## Install & Service Setup

```bash
./install.sh

# Enable vortexd daemon (enables passwordless CLI commands & desktop widgets):
systemctl --user enable --now vortexd.service
```

---

## CLI & Desktop Commands

```bash
vortex                         # Launch the tactical TUI cockpit
vortex status [--json|--waybar]# Query active tunnel status (human-readable or Waybar JSON)
vortex toggle                  # Instant toggle: disconnect if active, connect fastest if down
vortex pick [query]            # Fuzzy node picker (fuzzel / rofi / wofi / zenity / CLI)
vortex up [n|name]             # Connect to profile (number, name, or last used)
vortex down                    # Disconnect active tunnel
vortex best                    # Probe all nodes, connect to the fastest
vortex ping                    # Measure latency of every profile
vortex shield [on|off]         # Toggle atomic nftables stealth kill-switch shield
vortex leaks                   # Run comprehensive leak audit (IP, DNS, IPv6, WebRTC)
vortex flows                   # Live socket & active connection traffic sniffer
vortex history [--json]        # Cumulative traffic accounting & usage statistics
vortex route                   # Manage split tunneling, LAN bypass, and domain rules
vortex recon [n|name]          # Deep node reconnaissance (ASN, GeoIP, TLS cert, jitter)
vortex speed                   # Measure live throughput & bandwidth under load
vortex qr [n|name]             # Render compact terminal QR code for mobile import
vortex conf [n|name]           # View / export raw configuration (--copy, --export)
vortex sub list|add|update|rm  # Manage remote subscription endpoints
vortex completion <shell>      # Generate shell completions (bash, zsh, fish)
```

---

## Desktop & Waybar Integration

See [docs/DESKTOP.md](docs/DESKTOP.md) for full configuration guides.

### Waybar Module Integration
1. Ensure the `vortexd` ambient user service is running:
   ```bash
   systemctl --user enable --now vortexd
   ```
2. Add `"custom/vortex"` to `modules-right` (or `modules-left`) in `~/.config/waybar/config.jsonc`:
   ```jsonc
   "modules-right": [
       // ... existing modules
       "custom/vortex"
   ],
   ```
3. Copy-paste the module snippet from `packaging/waybar/config.jsonc` into `~/.config/waybar/config.jsonc`:
   ```jsonc
   "custom/vortex": {
       "format": "{}",
       "return-type": "json",
       "interval": 2,
       "exec": "vortex status --json",
       "on-click": "vortex toggle",
       "on-click-right": "vortex pick",
       "tooltip": true
   }
   ```
4. Append CSS styles from `packaging/waybar/style.css` into `~/.config/waybar/style.css`:
   ```css
   #custom-vortex {
       padding: 0 10px;
       margin: 0 4px;
       font-weight: bold;
       border-radius: 6px;
       transition: all 0.2s ease-in-out;
   }
   #custom-vortex.connected {
       color: #00ffcc;
       background: rgba(0, 240, 255, 0.12);
       border: 1px solid rgba(0, 240, 255, 0.35);
   }
   #custom-vortex.connected.shield-armed {
       border-bottom: 2px solid #00f0ff;
       box-shadow: 0 0 8px rgba(0, 240, 255, 0.25);
   }
   #custom-vortex.disconnected {
       color: #608a8e;
       background: rgba(22, 61, 68, 0.25);
       border: 1px solid rgba(96, 138, 142, 0.2);
   }
   ```
5. Restart Waybar:
   ```bash
   omarchy-restart-waybar || pkill -SIGUSR2 waybar
   ```

### Hyprland Bindings (`~/.config/hypr/bindings.lua` or `hyprland.conf`)
```conf
bind = $mainMod, V, exec, vortex toggle
bind = $mainMod SHIFT, V, exec, vortex pick
bind = $mainMod ALT, V, exec, vortex shield
```

---

## TUI Controls

- `⏎` : Connect selected node
- `Space` : Disconnect tunnel
- `a` : Import profile from string or link
- `v` : Paste from clipboard
- `/` : Live fuzzy search and filter (by name, transport e.g. `/udp`, `/reality`, `/ws`)
- `t` / `T` : Probe latency (all nodes / selected node)
- `o` : Cycle sort order (Name &rarr; Latency &rarr; Transport)
- `p` : Cycle transport filter (ALL &rarr; TCP ONLY &rarr; UDP ONLY)
- `f` : Toggle between Packet Traffic Spectrum and Live Packet Flows sniffer
- `s` : Subscription manager overlay
- `b` : Live throughput benchmark modal
- `r` : Deep node reconnaissance report
- `q` : Safe quit (tunnel continues running in background)
- `Q` : Quit and disconnect tunnel

---

## Documentation

- [Architecture & Design](docs/ARCHITECTURE.md)
- [Protocols & Engines](docs/PROTOCOLS.md)
- [Security & Threat Model](docs/SECURITY.md)
- [Implementation & Verification Plan](docs/PLAN.md)
- [Desktop & Bar Integration](docs/DESKTOP.md)
