# Vortex Protocol Specification & Backend Architecture

Vortex provides a unified interface across modern censorship-resistant and standard VPN protocols.

---

## 1. Protocol Backend Matrix

| Protocol | Backend Driver | Transports & Features | Binary / Core Management | Traffic Accounting |
|---|---|---|---|---|
| **VLESS** | `ThroneBridgeBackend` (or `XrayBackend` TUN fallback) | TCP, Reality (`mldsa65`), XTLS-Vision, WS, HTTPUpgrade, gRPC, XHTTP, XDrive, PQ (`mlkem768x25519plus`), ECH, `fragment`, `dialerProxy` | `sing-box` (TUN master) + managed `xray` under `~/.local/share/vortex/xray` | Clash API (`:9090`), sysfs `vx0`, & Xray Stats API |
| **VMess / Trojan / Shadowsocks** | `ThroneBridgeBackend` / `SingBoxBackend` | TCP, WS, HTTPUpgrade, gRPC, H2, AEAD / SIP002 / SIP008 / 2022 | `sing-box` + managed `xray` bridge | Clash API / sysfs / Xray Stats API |
| **Custom Xray / sing-box JSON** | `ThroneBridgeBackend` (`CustomConfig`/`CustomOutbound`) or `SingBoxBackend` | Lossless preservation of full `outbounds`, `routing`, `fragment`, `dialerProxy`, `balancers`, `observatory`, `selector` | Bridged behind `sing-box` (`vortex-bridge-in` + `route_exclude_address`) or direct `SingBoxBackend` | Clash API / Xray Stats API |
| **Hysteria 2** | `Hysteria2Backend` -> `SingBoxBackend` / `hysteria` | QUIC, Salamander Obfuscation, Port Hopping | `sing-box` (URIs/JSON) or native `hysteria` (YAML) | Clash API / sysfs |
| **TUIC (v5)** | `SingBoxBackend` | QUIC, congestion control, ALPN | `sing-box` | Clash API / sysfs |
| **WireGuard** | `WireGuardBackend` | Kernel WireGuard interface (`vxwg0`) + `resolvectl` DNS | `wg-quick` / `wg` | `wg show` / sysfs |
| **AmneziaWG** | `AmneziaBackend` | Junk packets (`Jc`/`Jmin`/`Jmax`), Magic headers (`S1`/`S2`, `H1`-`H4`) | `awg-quick` / `awg` | `awg show` / sysfs |
| **OpenVPN** | `OpenVpnBackend` | TCP, UDP, inline TLS-Auth/TLS-Crypt, User/Pass | Managed `openvpn` subprocess with credential stripping | sysfs `tun*` |

---

## 2. Share Link & Config Ingestion

Vortex (`parser.rs`) parses multiple link and config formats into strongly-typed `Profile` entries tagged with `CoreEngine` and `ProfilePayloadKind` (`Standard`, `CustomOutbound`, `CustomConfig`):

### VLESS (`vless://`)
- **Format**: `vless://<uuid>@<host>:<port>?type=<transport>&security=<sec>&sni=<sni>&pbk=<public-key>&sid=<short-id>&fp=<fingerprint>&flow=<flow>&encryption=<pq-enc>#<tag>`
- **Transports**: TCP, WebSocket, HTTPUpgrade, gRPC, H2, XHTTP (`path`, `host`, `mode`, `extra`), XDrive (`type=xdrive`).
- **Post-Quantum & Reality**: Extracts `encryption=mlkem768x25519plus.*`, `pqv` (`mldsa65Verify`), `ech`, and `pbk`/`password`.

### Custom JSON Outbounds & Full Configs (Throne / Xray / sing-box)
- Lossless detection of full JSON documents (with `inbounds`, `routing`/`route`, `balancers`, `fragment`, `dialerProxy`, `observatory`) and partial outbound arrays/objects.

### VMess (`vmess://`), Trojan (`trojan://`), Shadowsocks (`ss://`), Hysteria 2 (`hy2://`), TUIC (`tuic://`)
- Full URI parsing including Salamander obfuscation (`obfs=salamander`), SIP002 & legacy base64 SS forms, and TUIC v5 fields.

### WireGuard / AmneziaWG (`.conf`, `awg://`, `vpn://`) & OpenVPN (`.ovpn`)
- Full INI `[Interface]`/`[Peer]` parsing with IPv6 sanitization and Amnezia obfuscation parameters.
- `.ovpn` ingestion with external `<ca>`/`<cert>`/`<key>`/`<tls-auth>`/`<tls-crypt>` file inlining and auth detection.

---

## 3. Subscription Endpoints & Multi-Format Ingestion

- Ingestion of HTTP/HTTPS subscriptions, Base64 link lists, JSON arrays, QR code images (`rqrr` / `zbarimg`), and local files.
- Deduplication, tagging, auth preservation across refreshes, and multi-layer latency probing.
