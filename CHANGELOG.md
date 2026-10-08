# Changelog

All notable changes to `vortex` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-10-08

### Added
- **First-Class Xray-Core Backend**:
  - `XrayBackend` implementation supporting system TUN inbound (`vx0`), gRPC stats query over internal local IPC, supervised child process lifecycle, and auto-restart with backoff.
  - Automatic detection of system `xray` binary (e.g. from Arch Linux package) or self-managed binaries in `~/.local/share/vortex/xray/current/`.
- **Dynamic Xray Lifecycle Management (`vortex xray`)**:
  - `vortex xray install`: Dynamically discovers the newest release from GitHub releases API (including pre-release tags, e.g. `v26.9.30`), verifies SHA256/SHA512 checksums from `.dgst` file, and installs atomically with a `current` symlink. Downloads run unprivileged (never as root).
  - `vortex xray update`: Checks and upgrades to newer releases, and updates `geoip.dat` and `geosite.dat`.
  - `vortex xray version`: Displays the detected or active Xray version, managed/system status, and executable path.
  - `vortex xray doctor`: Runs comprehensive diagnostics verifying binary integrity, execution permissions, Linux kernel TUN module (`/dev/net/tun`), and network connectivity.
  - `vortex xray rollback`: Instantly switches back to the previously installed version without downtime.
  - `vortex xray test <config.json>`: Syntax-checks raw Xray configuration files via `xray run -test -config`.
- **Advanced Protocol & Transport Ingestion**:
  - Full link parsing and Xray JSON generation for VLESS, VMess, Trojan, Shadowsocks, and Hysteria 2.
  - Support for VLESS `xtls-rprx-vision` flow and REALITY transport (`publicKey`, `shortId`, `serverName`, `fingerprint`, `spiderX`).
  - Support for XHTTP, WebSocket, gRPC, TCP, and TLS with Encrypted Client Hello (ECH) and certificate pinning.
  - Support for post-quantum key exchange (`mlkem768x25519plus`).
  - Raw Xray JSON import and validation.
- **Routing & Leak Protection**:
  - Remote proxy server IP exclusion from tunnel routes to prevent routing loops.
  - Atomic nftables kill-switch shield integration (`vortex_shield`).
  - DoH and tunnel-directed DNS protection preventing DNS/IPv6 leakage.
  - Multi-layer active probing and latency measurement through isolated ephemeral Xray instances.
- **TUI & CLI Integration**:
  - Protocol badge, Xray version, and live throughput indicators in TUI cockpit and status headers.
  - Full headless CLI support for all Xray operations.
- **Comprehensive Test Suite**:
  - Unit tests for link parsing, malformed inputs, URL encodings, snapshot testing of Xray config generation, and `.dgst` checksum verification.
  - Integration tests with mock GitHub release server and mock Xray binary execution.

## [0.2.0] - 2026-10-01

### Added
- Multi-protocol support (sing-box, WireGuard, AmneziaWG, OpenVPN).
- Tactical Ratatui TUI cockpit with packet traffic sniffer and live flows.
- Ambient desktop integration (Waybar module, Hyprland hotkeys, Rofi/Fuzzel node picker).
- Age-encrypted profile storage with 0600 permissions.
- Atomic nftables kill-switch and active failover probing.

## [0.1.0] - 2026-09-28

### Added
- Initial release of Vortex daemon (`vortexd`) and terminal client (`vortex`).
