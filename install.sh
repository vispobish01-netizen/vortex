#!/usr/bin/env bash
# Vortex installer for Arch / Omarchy
set -euo pipefail
cd "$(dirname "$0")"

echo "› dependencies (pacman)"
sudo pacman -S --needed --noconfirm rust sing-box wireguard-tools openvpn systemd-resolvconf curl wl-clipboard

echo "› building"
cargo build --release

echo "› installing to /usr/local/bin/vortex"
sudo install -Dm755 target/release/vortex /usr/local/bin/vortex

cat <<MSG

done.  run:  vortex

optional (AmneziaWG profiles):
  yay -S amneziawg-tools amneziawg-dkms
MSG
