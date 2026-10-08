# Vortex Desktop & Omarchy Integration Guide

Vortex provides deep, native desktop integration for Linux power users, particularly within Arch Linux and Omarchy (Hyprland / Wayland) environments.

---

## 1. Ambient System Daemon (`vortexd`)

Vortex is built around a split client-daemon architecture:
- **`vortexd`** runs as a background service managing network routing, `sing-box` TUN interfaces, `awg-quick`, `openvpn`, atomic `nftables` kill-switches, active multi-layer health probes, and failover.
- **`vortex`** CLI and TUI communicate over a secure Unix domain socket (`$XDG_RUNTIME_DIR/vortex.sock`).

### Enabling the User Service

```bash
# Enable and start vortexd in background:
systemctl --user enable --now vortexd.service
```

> **Why run vortexd as a service?**
> When `vortexd` is active, you can connect, disconnect, switch profiles, toggle kill-switch shields, and query metrics **without requiring `sudo` or typing your password** in the terminal or graphical hotkeys!

---

## 2. Desktop Status Bar (Waybar / Omarchy Bar)

Vortex outputs native Waybar-compatible JSON with `vortex status --json` (or `vortex status --waybar`).

### Waybar Configuration (`~/.config/waybar/config.jsonc`)

Add `"custom/vortex"` to your `modules-right` or `modules-left` array:

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

### Waybar Stylesheet (`~/.config/waybar/style.css`)

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

---

## 3. Hyprland Keybindings (`~/.config/hypr/bindings.lua` or `hyprland.conf`)

Add instant keyboard shortcuts to control your egress tunnel globally:

```conf
# Toggle tunnel on/off (connects to fastest or last-used node if down, disconnects if up):
bind = $mainMod, V, exec, vortex toggle

# Quick fuzzy egress node selector (opens fuzzel / rofi / wofi / zenity):
bind = $mainMod SHIFT, V, exec, vortex pick

# Toggle nftables stealth kill-switch shield:
bind = $mainMod ALT, V, exec, vortex shield
```

---

## 4. Desktop Notifications

Vortex automatically sends non-intrusive desktop notifications via `notify-send` for:
- Tunnel connected (showing country flag, node name, and latency)
- Tunnel disconnected
- Stealth kill-switch shield armed / disarmed
- Automatic failover triggered when a node experiences packet loss or outage

---

## 5. Shell Autocompletions

Generate completion scripts for your shell:

```bash
# Bash:
vortex completion bash > ~/.local/share/bash-completion/completions/vortex

# Zsh:
vortex completion zsh > ~/.zfunc/_vortex

# Fish:
vortex completion fish > ~/.config/fish/completions/vortex.fish
```
