#!/usr/bin/env bash
# Vortex installer for Arch / Omarchy
set -euo pipefail
cd "$(dirname "$0")"

echo "› dependencies (pacman)"
sudo pacman -S --needed --noconfirm rust sing-box wireguard-tools openvpn systemd-resolvconf curl wl-clipboard nftables

echo "› building release binaries"
cargo build --release

echo "› installing binaries"
# System-wide installation
sudo install -Dm755 target/release/vortex /usr/local/bin/vortex
sudo install -Dm755 target/release/vortexd /usr/local/bin/vortexd

# User-local installation (ensures local PATH and systemd --user service find it)
mkdir -p "$HOME/.local/bin"
install -Dm755 target/release/vortex "$HOME/.local/bin/vortex"
install -Dm755 target/release/vortexd "$HOME/.local/bin/vortexd"

echo "› setting up system directories & permissions"
sudo mkdir -p /etc/vortex/profiles
sudo chmod 755 /etc/vortex /etc/vortex/profiles
sudo chmod -R a+r /etc/vortex/profiles 2>/dev/null || true

echo "› installing systemd user service"
mkdir -p "$HOME/.config/systemd/user"
install -Dm644 packaging/vortexd.service "$HOME/.config/systemd/user/vortexd.service"
systemctl --user daemon-reload || true

echo "› installing shell autocompletions"
if [[ -d "$HOME/.local/share/bash-completion/completions" || -d "/usr/share/bash-completion" ]]; then
    mkdir -p "$HOME/.local/share/bash-completion/completions"
    target/release/vortex completion bash > "$HOME/.local/share/bash-completion/completions/vortex" || true
fi
if command -v fish >/dev/null 2>&1; then
    mkdir -p "$HOME/.config/fish/completions"
    target/release/vortex completion fish > "$HOME/.config/fish/completions/vortex.fish" || true
fi
if [[ -d "$HOME/.zfunc" ]]; then
    target/release/vortex completion zsh > "$HOME/.zfunc/_vortex" || true
fi

cat <<MSG

============================================================
✔ Vortex installation complete!
============================================================

Quick Start:
  vortex                               # Launch tactical TUI cockpit
  vortex status                        # Query tunnel status
  vortex up [node]                     # Connect egress tunnel
  vortex toggle                        # Quick toggle on/off

Enable Background Daemon (for rootless CLI & Waybar widget):
  systemctl --user enable --now vortexd.service

Desktop Integration (Hyprland & Waybar):
  See packaging/hyprland/bindings.conf and packaging/waybar/
  Full documentation: docs/DESKTOP.md

Optional (AmneziaWG profiles):
  yay -S amneziawg-tools amneziawg-dkms
MSG
