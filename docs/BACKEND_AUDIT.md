# Vortex Backend Audit: sing-box vs Xray-core

**Document Version:** 1.0.0  
**Date:** November 2026  
**Status:** Architectural Assessment & Recommendation  

---

## 1. Executive Summary

Vortex currently operates a dual-engine architecture for advanced anti-censorship proxy and VPN capabilities. While WireGuard, AmneziaWG, and OpenVPN are managed via standard system utilities or dedicated wrappers, the core proxy layer (VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC) is split between two separate Go-based core engines:
1. **`sing-box`**: Invoked directly by `tunnel.rs` for transparent TUN interface routing (`vortex0`), SOCKS5/HTTP local bridging, and Clash API connection flow inspection.
2. **`xray-core`**: Maintained through an isolated subsystem (`crates/vortex-core/src/xray/`), featuring an automated release downloader/checksum verifier, dedicated JSON configuration synthesizer, and gRPC statistics client.

This dual-engine architecture accounts for **~8,800 lines of code** across `vortex-core` and `vortex`, with significant duplication in configuration synthesis, routing rule translation, privilege management, and telemetry polling.

This audit evaluates the exclusive feature sets of each engine, catalogs file-by-file line count footprints, pinpoints exact sites of code duplication, and delivers concrete recommendations with estimated line reductions.

---

## 2. Feature & Protocol Coverage Comparison

| Capability / Protocol | `sing-box` Alone | `Xray-core` Alone | Both Backends | Notes |
| :--- | :---: | :---: | :---: | :--- |
| **VLESS (Standard TCP/WS/gRPC)** | | | **Yes** | Shared outbound configuration |
| **VLESS Reality** | Basic | **Advanced** | | Xray supports full uTLS fingerprinting (Chrome, iOS, Safari, Firefox), SpiderX crawling, and Short IDs |
| **XTLS Vision (`xtls-rprx-vision`)** | Limited | **Full** | | Xray original implementation with zero-copy splicing and TLS padding |
| **XHTTP (Split HTTP/2 & Packet-Up)** | No | **Yes** | | Xray proprietary transport designed to circumvent DPI rate-limiting |
| **Post-Quantum Cryptography (ML-KEM)** | Experimental | **Yes** | | Xray native Kyber-768/1024 hybrid key encapsulation |
| **VMess (AEAD / WebSocket / gRPC)** | | | **Yes** | Both support VMess with zero-length headers |
| **Trojan** | | | **Yes** | Standard TLS trojan implementation |
| **Shadowsocks (2022 / SIP002)** | | | **Yes** | Both support standard AEAD and modern 2022 ciphers |
| **Hysteria2 (QUIC-based)** | Native | Proxy/Fallback | | `sing-box` has native protocol implementation; Xray wraps standard transport |
| **TUIC (v5 QUIC)** | **Yes** | No | | Only `sing-box` natively supports TUIC |
| **WireGuard / AmneziaWG Embedding** | **Yes** | Limited | | `sing-box` can route WireGuard outbounds directly in TUN mode |
| **Native Linux TUN Interface** | **Yes** | No | | `sing-box` creates and routes `vortex0` with internal gVisor/mixed TCP stack; Xray requires external `tun2socks` |
| **Clash API Controller (`:9090`)** | **Yes** | No | | Enables real-time socket tracking, per-connection speeds, and active flow termination |
| **gRPC Statistics Service (`:10085`)** | No | **Yes** | | Xray internal gRPC API for user and outbound byte counters |
| **Automated In-App Binary Downloader** | No | **Yes** | | `crates/vortex-core/src/xray/install.rs` downloads, verifies SHA-256 DGST, and unpacks releases |

---

## 3. File Breakdown & Line Counts

The following 15 files comprise the backend implementation surface area (totaling **8,804 lines**):

| File | Total Lines | sing-box Specific | Xray Specific | Shared / Agnostic | Description |
| :--- | :---: | :---: | :---: | :---: | :--- |
| `crates/vortex-core/src/xray/install.rs` | 768 | 0 | 768 | 0 | GitHub release downloader, DGST verifier, semver updater |
| `crates/vortex-core/src/xray/config.rs` | 738 | 0 | 738 | 0 | Dedicated Xray JSON config builder & tests |
| `crates/vortex-core/src/xray/backend.rs` | 404 | 0 | 404 | 0 | `Backend` trait impl, process lifecycle, gRPC stats query |
| `crates/vortex-core/src/xray/mod.rs` | 12 | 0 | 12 | 0 | Subsystem re-exports |
| `crates/vortex-core/src/tunnel.rs` | 1,425 | 374 | 170 | 881 | Process execution, TUN setup, Clash API polling, session state |
| `crates/vortex-core/src/store.rs` | 1,526 | 215 | 195 | 1,116 | Profile persistence, `to_singbox_outbound`, `to_xray_outbound` |
| `crates/vortex-core/src/parser.rs` | 1,352 | 95 | 225 | 1,032 | URI parser, XHTTP/Reality parameters, raw config ingestion |
| `crates/vortex-core/src/routing.rs` | 668 | 150 | 145 | 373 | `to_singbox_rules` vs `to_xray_routing` rules generators |
| `crates/vortex-core/src/probe.rs` | 441 | 35 | 45 | 361 | Latency measurement, metrics calculation, auto-best selection |
| `crates/vortex-core/src/privilege.rs` | 377 | 62 | 58 | 257 | Linux file capabilities (`setcap`), binary path resolution |
| `crates/vortex-core/src/model.rs` | 494 | 18 | 24 | 452 | `Kind` enum, `Transport::Xhttp`, `OperationalMode` |
| `crates/vortex-core/src/backends/hysteria2.rs` | 143 | 25 | 25 | 93 | Hysteria2 backend wrapper prioritizing hysteria > sing-box/xray |
| `crates/vortex-core/src/backend.rs` | 47 | 0 | 15 | 32 | `Backend` trait definition and `resolve_backend` router |
| `crates/vortex-core/src/recon.rs` | 248 | 0 | 0 | 248 | TLS ALPN, certificate, and GeoIP reconnaissance |
| `crates/vortex/src/cli/xray.rs` | 161 | 0 | 161 | 0 | CLI commands: `vortex xray install/update/status/check` |
| **Total** | **8,804** | **974** | **2,995** | **4,835** | |

*(Note: `tests/xray_tests.rs` adds an additional **404 lines** of Xray-specific integration tests).*

---

## 4. Code Duplication Sites

### 4.1. Outbound Configuration Generation
* **sing-box**: `crates/vortex-core/src/store.rs` (`to_singbox_outbound()`, lines 750–950, ~200 lines).
* **Xray**: `crates/vortex-core/src/xray/config.rs` (`generate_xray_config()`, lines 80–310, ~230 lines).
* **Duplication**: Both modules take a parsed `Profile` and construct almost identical JSON blocks for VLESS, VMess, Trojan, and Shadowsocks. Key differences are purely syntactic (e.g. `server` vs `address`, `server_port` vs `port`, `tls.server_name` vs `streamSettings.tlsSettings.serverName`).

### 4.2. Routing Rules Conversion
* **sing-box**: `crates/vortex-core/src/routing.rs` (`to_singbox_rules()`, lines 105–250, ~145 lines) translates `RulesConfig` into sing-box 1.8+ `route.rules` using `rule_set`, `domain_suffix`, and `ip_cidr`.
* **Xray**: `crates/vortex-core/src/routing.rs` (`to_xray_routing()`, lines 255–395, ~140 lines) translates the identical `RulesConfig` into Xray `routing.rules` using `type: "field"`, `domain: [...]`, and `ip: [...]`.
* **Duplication**: Identical business logic (LAN bypass, ad-blocking lists, DNS hijack rules, direct fallback) is coded twice in parallel branches.

### 4.3. Privilege & Binary Capability Management
* **Location**: `crates/vortex-core/src/privilege.rs`.
* **Duplication**: `resolve_singbox_binary()` and `resolve_xray_binary()` implement identical path search logic (checking PATH, then `~/.local/share/vortex/bin/`). `setup_capabilities()` applies identical `setcap cap_net_admin,cap_net_bind_service+ep` calls to each binary. Preflight inspection duplicates capability verification code for both binaries.

### 4.4. Telemetry and Flow Inspection
* **Location**: `crates/vortex-core/src/tunnel.rs`.
* **Duplication**: To report live bandwidth and active connections, Vortex maintains:
  1. An HTTP client querying the sing-box Clash API at `127.0.0.1:9090/connections` and `127.0.0.1:9090/traffic`.
  2. A gRPC client and CLI parser querying Xray's `StatsService` at `127.0.0.1:10085`.

---

## 5. Architectural Assessment: Standardizing on ONE Backend

### Option A: Standardize Exclusively on `sing-box` (Deprecate Xray)

Under this option, `sing-box` becomes the sole engine for proxy and TUN operation.

* **Advantages**:
  1. **Native TUN Operation**: `sing-box` manages the Linux TUN interface (`vortex0`) internally without external helper binaries (`tun2socks`), implementing transparent system-wide VPN out-of-the-box.
  2. **Active Flow Telemetry**: Built-in Clash API enables real-time socket inspection, country-level traffic monitoring, and interactive connection killing in the TUI (`[3] PACKET FLOWS`).
  3. **Broad Protocol Breadth**: Covers TUIC, WireGuard, AmneziaWG, Hysteria2, Shadowsocks, VMess, and Trojan natively.
  4. **Code Cleanliness**: Eliminates the entire `xray/` subsystem, automated downloader, and gRPC client.
* **Disadvantages / Gaps**:
  1. **Loss of Cutting-Edge Transports**: Loss of native XHTTP and Post-Quantum ML-KEM handshake support.
  2. **Binary Distribution**: `sing-box` does not have an in-app binary installer in Vortex; users must rely on distro packages (`pacman -S sing-box`) or a newly written generic downloader.
* **Estimated Lines Removed**:
  - `crates/vortex-core/src/xray/` (1,922 lines)
  - `crates/vortex/src/cli/xray.rs` (161 lines)
  - `tests/xray_tests.rs` (404 lines)
  - Xray routing & store generation in `routing.rs`, `store.rs`, `privilege.rs`, `tunnel.rs`, `model.rs` (~420 lines)
  - **Net Reduction: ~2,907 lines** (~15.0% of total codebase).

---

### Option B: Standardize Exclusively on `Xray-core` (Deprecate sing-box)

Under this option, `Xray-core` becomes the sole engine for proxy operation.

* **Advantages**:
  1. **Supreme Anti-Censorship**: Industry-leading VLESS Reality, XTLS Vision, XHTTP, and Post-Quantum ML-KEM support with authentic browser TLS fingerprint camouflage.
  2. **Zero-Dependency Installation**: Fully self-contained installer (`vortex xray install`) with SHA-256 DGST validation, independent of host package managers.
* **Disadvantages / Gaps**:
  1. **No Native Linux TUN**: Xray is a proxy server, not a transparent VPN provider. Running system-wide VPN mode would require bundling and maintaining `tun2socks` or complex nftables/TPROXY policy routing loops.
  2. **Loss of Protocols**: Loss of native TUIC protocol support.
  3. **Loss of Flow Sniffing**: No native Clash API equivalent for per-socket connection tracking and termination in the TUI.
* **Estimated Lines Removed**:
  - sing-box rules generator in `routing.rs` (~150 lines)
  - sing-box outbound generator in `store.rs` (~215 lines)
  - sing-box TUN execution and Clash API client in `tunnel.rs` (~374 lines)
  - sing-box capability checks in `privilege.rs` (~62 lines)
  - sing-box UI diagnostics and status checks (~80 lines)
  - **Gross Reduction: ~881 lines**.
  - **Net Addition**: Adding `tun2socks` or TPROXY handling to replicate TUN mode would add **~500–700 lines**, yielding a negligible net reduction of **~200–300 lines**.

---

## 6. Concrete Recommendation

### Recommendation: **Option A (Standardize on `sing-box`)**

If the goal is to **reduce code bloat, simplify maintenance, and preserve full system VPN functionality**:

1. **Retain `sing-box` as the Foundation**:
   `sing-box` is the only engine capable of providing both transparent system-wide TUN routing (`vortex0`) and fine-grained per-socket flow telemetry via the Clash API controller. Standardizing on Xray would require introducing an external `tun2socks` subsystem, defeating the bloat-reduction goal.

2. **Port the Release Downloader**:
   Adapt the robust release downloader from `crates/vortex-core/src/xray/install.rs` into a generic binary installer for `sing-box` (`~200 lines`), allowing self-contained binary management on any Linux distribution without system package manager friction.

3. **Prune Xray Subsystems**:
   Deprecate `crates/vortex-core/src/xray/`, `crates/vortex/src/cli/xray.rs`, `tests/xray_tests.rs`, and Xray outbound/routing generators, immediately removing **~2,900 lines of redundant code**.

4. **Refactor sing-box into the `Backend` Trait**:
   Move sing-box execution from the hardcoded procedural code in `tunnel.rs` into a clean `SingBoxBackend` implementing `crates/vortex-core/src/backend.rs::Backend`.
