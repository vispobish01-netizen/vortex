# Vortex Protocol Specification & Backend Architecture

Vortex provides a unified interface across modern censorship-resistant and standard VPN protocols.

---

## 1. Protocol Backend Matrix

| Protocol | Backend Driver | Transports & Features | Binary / Core Management | Traffic Accounting |
|---|---|---|---|---|
| **VLESS** | `XrayBackend` | TCP, Reality, XTLS-Vision, WS, gRPC, HTTPUpgrade, XHTTP | Managed under `/var/lib/vortex/cores/xray` (pinned, SHA-256 verified) | Xray gRPC Stats API (`/stats.StatsService/QueryStats`) |
| **VMess** | `XrayBackend` | TCP, WS, gRPC, mKCP | Managed under `/var/lib/vortex/cores/xray` | Xray gRPC Stats API |
| **Trojan** | `XrayBackend` | TLS, WebSocket, gRPC | Managed under `/var/lib/vortex/cores/xray` | Xray gRPC Stats API |
| **Shadowsocks** | `XrayBackend` | AEAD (2022-blake3, chacha20-poly1305, aes-gcm), SIP002, SIP008 | Managed under `/var/lib/vortex/cores/xray` | Xray gRPC Stats API |
| **Hysteria 2** | `Hysteria2Backend` | QUIC, Salamander Obfuscation, Port Hopping | Subprocess execution (`hysteria` or `sing-box`) | Subprocess socket stats / Netlink interface stats |
| **WireGuard** | `WireGuardBackend` | Kernel WireGuard interface, Netlink | Native Linux kernel / `wg` / `ip link` | Kernel Netlink statistics (`rtnetlink`) |
| **AmneziaWG** | `AmneziaBackend` | Junk packets (Jmin/Jmax), Magic headers (S1/S2, H1-H4) | Kernel module / `awg-quick` / `awg` | Kernel Netlink statistics |
| **OpenVPN** | `OpenVpnBackend` | TCP, UDP, TLS-Auth, TLS-Crypt, User/Pass | Managed subprocess with UNIX management socket | Management interface queries (`bytecount`, `status`) |

---

## 2. Share Link & Config Ingestion

Vortex parses multiple link formats into the strongly-typed internal `Profile` data structure:

### VLESS (`vless://`)
- **Format**: `vless://<uuid>@<host>:<port>?type=<transport>&security=<sec>&sni=<sni>&pbk=<public-key>&sid=<short-id>&fp=<fingerprint>&flow=<flow>#<tag>`
- **Reality Parameters**: Validated for public key (`pbk`), short ID (`sid`), and SNI.
- **Transports**: TCP, WebSocket (`path`, `host`), gRPC (`serviceName`), XHTTP (`path`, `mode`).

### VMess (`vmess://`)
- **Format**: Standard Base64 JSON containing `v`, `ps`, `add`, `port`, `id`, `aid`, `net`, `type`, `host`, `path`, `tls`, `sni`.

### Trojan (`trojan://`)
- **Format**: `trojan://<password>@<host>:<port>?type=<transport>&sni=<sni>#<tag>`

### Shadowsocks (`ss://`)
- **Format**: SIP002 (`ss://<base64(method:password)>@<host>:<port>#<tag>`) and legacy formats with URL-encoded tags.

### Hysteria 2 (`hy2://` / `hysteria2://`)
- **Format**: `hy2://<auth>@<host>:<port>?sni=<sni>&insecure=1&obfs=<type>&obfs-password=<pw>#<tag>`

### WireGuard & AmneziaWG (`.conf`, `awg://`, `vpn://`)
- Full INI-style `[Interface]` and `[Peer]` block parsing.
- Extraction of `PrivateKey`, `Address`, `DNS`, `PublicKey`, `Endpoint`, `AllowedIPs`, and Amnezia parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`, `H2`, `H3`, `H4`).

### OpenVPN (`.ovpn`)
- Inline certificate/key parsing (`<ca>`, `<cert>`, `<key>`, `<tls-auth>`, `<tls-crypt>`).
- Detection of authentication requirements (`auth-user-pass`).

---

## 3. Subscription Endpoints & Base64 Ingestion

- Ingestion of HTTP/HTTPS subscription endpoints.
- Support for Base64 encoded multi-line link lists and plain text subscription feeds.
- Automatic server deduplication, tagging, and latency benchmarking.
