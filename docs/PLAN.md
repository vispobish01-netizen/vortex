# Vortex Implementation & Verification Plan

**Version:** 1.0.0  
**Project:** Vortex VPN & Proxy Terminal Manager (Linux / Omarchy / Arch)  
**Workspace:** `vortex-core`, `vortexd`, `vortex`

---

## 1. Executive Summary & Goals

Vortex is a terminal VPN/proxy manager designed for Linux environments. The codebase features a Cargo workspace composed of:
1. `vortex-core`: Core data models, serialization, error types (`thiserror`), IPC protocols (`serde`), cryptographic storage (`age` / `argon2id` / `keyring`), link and QR parsing, multi-layer probing, `nftables` leak protection, and protocol backends implementing the `Backend` trait.
2. `vortexd`: Privileged background daemon executing with minimal capabilities, managing core lifecycles, routing, failover, and metrics. Exposes a versioned JSON-RPC Unix domain socket (`/run/vortex/vortex.sock`).
3. `vortex`: Unified client binary providing full-featured CLI subcommands and a rich interactive TUI (`ratatui`) communicating strictly with `vortexd` via IPC; never touches the network stack directly. Includes Omarchy theme detection and fallback dark teal/purple palette.

---

## 2. Requirement Checklist & Architecture Matrix

| Section | Feature Area | Description & Status | Target File(s) |
|---|---|---|---|
| **§ 1** | Workspace Architecture | Workspace crates (`vortex-core`, `vortexd`, `vortex`), systemd service, Unix socket at `/run/vortex/vortex.sock` (0660 group vortex), versioned JSON-RPC protocol | `crates/vortex-core/src/ipc.rs`, `crates/vortexd/src/main.rs`, `packaging/vortexd.service` |
| **§ 2** | Protocol Backends (`trait Backend`) | Common trait (`start`, `stop`, `validate_config`, `query_traffic`). Modular backends: `SingBoxBackend`, `ThroneBridgeBackend`, `XrayBackend`, `WireGuardBackend`, `OpenVpnBackend`, `Hysteria2Backend`, `AmneziaBackend` | `crates/vortex-core/src/backend.rs`, `crates/vortex-core/src/xray/`, `crates/vortex-core/src/backends/` |
| **§ 3** | Config Import | Parsers for share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tuic://`, `.conf`, `.ovpn`), lossless `CustomOutbound` & `CustomConfig` JSON (Xray/sing-box), subscriptions, clipboard, QR images (`rqrr`). | `crates/vortex-core/src/parser.rs`, `crates/vortex-core/src/storage.rs` |
| **§ 4** | Whole-system Tunnel | Transparent tunnel via `vx0` TUN + Clash API `:9090` / local SOCKS5 bridge, DNS leak prevention, IPv6 isolation, server IP exclusion, clean teardown. | `crates/vortex-core/src/tunnel.rs`, `crates/vortex-core/src/backends/singbox.rs`, `crates/vortex-core/src/routing.rs` |
| **§ 5** | Safety & Firewall | `nftables` kill-switch table (`table inet vortex`), atomic apply/rollback, LAN allow, leak test suite, split tunneling (`rules.toml`). | `crates/vortex-core/src/shield.rs`, `crates/vortex-core/src/leak.rs`, `crates/vortex-core/src/routing.rs` |
| **§ 6** | Reliability | Multi-layer probes (TCP, TLS, real HTTP via Xray bridge, jitter/loss), auto-failover with hysteresis and backoff, parallel ping testing. | `crates/vortex-core/src/probe.rs`, `crates/vortex-core/src/ping.rs` |
| **§ 7** | Storage & Security | Encrypted configs (`age`), zeroize secrets, file capability helpers (`cap_net_admin,cap_net_raw`), secret redaction in logs. | `crates/vortex-core/src/crypto.rs`, `crates/vortex-core/src/storage.rs`, `crates/vortex-core/src/model.rs` |
| **§ 8** | TUI (`ratatui`) | Omarchy color integration, dark teal/purple default, Dashboard, Flows, Rules, Subs, Logs, Recon/Speed modals, Vim bindings (`?`). Routes operations through `vortexd` IPC when online. | `crates/vortex/src/ui/`, `crates/vortex/src/keymap.rs` |
| **§ 9** | Observability | Structured logs, metrics, `vortex doctor` & `vortex check` diagnosing firewall, routes, DNS, permissions, Sing-Box + Xray dual-core readiness. | `crates/vortex-core/src/history.rs`, `crates/vortex/src/cli/diagnostics.rs` |
| **§ 10** | Quality & Packaging | Unit/integration tests (`cargo test`), GitHub Actions CI, docs (`ARCHITECTURE.md`, `PROTOCOLS.md`, `SECURITY.md`), completions, installer & systemd/desktop packaging. | `docs/`, `.github/workflows/ci.yml`, `install.sh`, `packaging/` |

---

## 3. Step-by-Step Implementation Strategy

### Step 1: Trait `Backend` Unification & Throne Dual-Core Bridge
- Unified `Backend` trait + `resolve_backend` / `resolve_backend_for_session` in `crates/vortex-core/src/backend.rs`.
- Modular backends:
  - `SingBoxBackend` & `ThroneBridgeBackend` in `crates/vortex-core/src/backends/singbox.rs`
  - `XrayBackend` in `crates/vortex-core/src/xray/backend.rs`
  - `WireGuardBackend`, `AmneziaBackend`, `OpenVpnBackend`, `Hysteria2Backend`

### Step 2: System Tunnel, Routing, and NFTables Kill-Switch
- `crates/vortex-core/src/shield.rs` uses atomic `table inet vortex` with strict drop policy, loopback exemption, DHCP, optional RFC1918 LAN allow, and remote endpoint bypass, persisting state under `active_run_dir()` & `user_config_dir()`.
- Automatic teardown and stale rule recovery (`cleanup_stale_rules`).

### Step 3: Storage & Security Hardening
- Audit secret encryption with `age` / passphrase derived via Argon2id or secure tokens.
- Ensure secrets are never dumped in plaintext into logs or formatted output (using `p.redacted_link()`).
- Verify least-privilege checks in `privilege.rs` and systemd unit definitions.

### Step 4: Daemon IPC Protocol and CLI Unification
- Verify `/run/vortex/vortex.sock` socket binding, permission handling (group vortex / 0660 or 0600 fallback), and versioned request/response protocol.
- Enhance CLI subcommands in `vortex` to support the required commands: `add`/`import`, `list`, `connect`/`up`, `disconnect`/`down`, `status`, `test`/`ping`, `kill-switch`/`shield`, `routes`/`route`, `export`, `doctor`.
- Implement `doctor` command output checking DNS, routes, firewall (`nft`), permissions, and core binaries.

### Step 5: TUI Polish & Daemon Decoupling
- Verify TUI operation using daemon IPC when available and preserving standalone capabilities.
- Ensure views: Dashboard, Servers, Routes, Logs, Settings, Help overlay (`?`), and command palette (`:`).

### Step 6: Documentation, CI & Packaging
- Create comprehensive documentation:
  - `docs/ARCHITECTURE.md` (with Mermaid diagrams)
  - `docs/PROTOCOLS.md` (protocol specifics, transport and security matrix)
  - `docs/SECURITY.md` (threat model, encryption at rest, capability drops)
- Create Arch / Omarchy installer (`install.sh`), systemd user unit (`packaging/vortexd.service`), and desktop bindings (`packaging/waybar/`, `packaging/hyprland/`).
- Create GitHub Actions CI workflow (`.github/workflows/ci.yml`) testing fmt, clippy, test, x86_64 and aarch64 build targets.
- Create shell completions (bash, zsh, fish).
- Future packaging: Arch Linux `PKGBUILD` and man pages.

---

## 4. Verification & Testing Criteria
- `cargo check --workspace` passes cleanly.
- `cargo clippy --workspace -- -D warnings` passes with 0 warnings.
- `cargo test --workspace` passes all tests.
- Standalone CLI execution (`--help`, `doctor`, `check`, `list`, etc.) functions reliably.
