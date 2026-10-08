# Vortex TUI Guide

This document describes the Vortex Terminal User Interface (TUI), with a focus on node metadata taxonomy, packet flows, and controls.

## Protocol vs Transport vs Security

Vortex distinguishes between the application-level proxy protocol, the underlying layer 4/transport stream framing, and the cryptographic security layer. Metadata is always derived from the parsed node configuration and never guessed from the protocol name alone.

| Protocol | Transport Display | Security Display | Description & Derivation Rule |
| :--- | :--- | :--- | :--- |
| **VLESS** | `TCP`<br>`TCP+WS`<br>`TCP+gRPC`<br>`TCP+Reality` | `TLS` / `TLS 1.3`<br>`Reality`<br>`none (warn)` | Derived from link `type`/`network` query parameters and `security` mode. VLESS with `security=reality` displays `TCP+Reality` or `TCP+gRPC`. If security is `none`, a security warning is shown. |
| **VMess** | `TCP`<br>`TCP+WS`<br>`TCP+gRPC`<br>`TCP+H2` | `TLS`<br>`none (warn)` | Derived from VMess JSON payload (`net`, `tls`). WebSocket and gRPC transports are framed over TCP. |
| **Trojan** | `TCP`<br>`TCP+WS`<br>`TCP+gRPC` | `TLS` (default)<br>`Reality` | Trojan mandates TLS encapsulation. Underlying transport derived from `type` parameter (defaults to `TCP`). |
| **Shadowsocks** | `TCP`<br>`UDP` | `None` / `TLS` (plugin) | Standard SIP002 is `TCP`. When `?udp=1` flag or standalone UDP is configured, displays `UDP`. Plugins like `v2ray-plugin` or `obfs-local` configure transport framing. |
| **Hysteria 2** | `UDP/QUIC` | `TLS` | QUIC-native protocol running over UDP with mandatory TLS encryption. Optional obfuscation kinds (e.g. `salamander`) are captured as kind-only (passwords are strictly never stored). |
| **WireGuard** | `UDP` | `None` | Tunnel encapsulation natively operates over UDP. Security is handled by WireGuard's Curve25519 noise protocol, so `Security::None` is expected and does not trigger warnings. |
| **OpenVPN** | `TCP`<br>`UDP` | `TLS` | Parsed directly from the `proto` directive in `.ovpn` configurations (`proto udp` or `proto tcp`). If undetermined, displays `--`. |
| **Sing-box JSON** | *Per Outbound* | *Per Outbound* | Derived directly from the outbound definition's `type`, `transport`, and `tls` blocks. |
| **Unknown** | `--` | `--` | If transport or security cannot be determined from parsed parameters, displays `--`. Values are never guessed. |

### Nodes Panel Columns

- **Transport Column**: Displayed immediately after the protocol tag (`[VLESS]`, `[HYST2]`, etc.) in dim text so the row remains readable.
- **Fixed Width Alignment**: Column is fixed-width (11 chars) with clean truncation/ellipsis if necessary.
- **Responsive Layout**: On narrow terminals (< 100 columns), the Transport column is hidden automatically to prioritize the node alias and latency probe telemetry.

### Keybindings & Controls

- `o`: Cycle sorting mode: **Name** &rarr; **Latency** &rarr; **Transport**.
- `p`: Cycle transport filter: **ALL** &rarr; **TCP ONLY** &rarr; **UDP ONLY** (applies to both the node matrix and active flows view).
- `/`: Search nodes by name, protocol tag, server endpoint, or transport specifier (e.g. `/udp`, `/ws`, `/grpc`, `/reality`).
- `f`: Toggle between Packet Traffic Spectrum and Live Packet Flows sniffer.

### Connection & Telemetry Panel

- Shows active `Protocol`, `Transport`, and `Security` rows.
- If `Security` is `none` on a non-WireGuard node, a warning marker `⚠ none (warn)` is displayed along with security notice advice.
- Endpoint displays the destination port adjacent to the host address.

### Packet Flows View (`f`)

- Displays active network socket connections with L4 protocol (`TCP`, `UDP`, `ICMP`) and destination port (`PORT`).
- Top summary counter line displays total flow distribution: `TCP 42 · UDP 7`.
- Flows can be filtered by transport using key `p`.
- Connected traffic panel displays byte distribution split (`TCP 78% · UDP 22%`) under cumulative totals when flow metrics are available.
