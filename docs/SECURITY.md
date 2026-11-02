# Vortex Security & Threat Model

Vortex is designed to operate safely in adversarial environments characterized by deep packet inspection (DPI), active probing, and local network eavesdropping.

---

## 1. Threat Model

### Adversary Capabilities
1. **Network Adversary (ISP / State Firewall)**:
   - Deep packet inspection (DPI) looking for known VPN handshakes (WireGuard, OpenVPN, standard TLS).
   - Active probing of detected endpoints.
   - DNS hijacking, spoofing, and SNI filtering.
   - IPv6 leakage exploitation when dual-stack tunnels are misconfigured.
2. **Local Adversary (Public Wi-Fi / Malicious LAN)**:
   - ARP spoofing, DHCP manipulation, gateway eavesdropping.
3. **Local Machine Eavesdropper (Unprivileged User / Stalkerware)**:
   - Reading stored configurations containing private keys and passwords.
   - Sniffing IPC domain sockets or inspecting process arguments.

---

## 2. Security Countermeasures

### 2.1 Encryption at Rest
- Server credentials, private keys, and subscription details are stored encrypted using `age` (XChaCha20-Poly1305 + scrypt/Argon2id).
- Passphrases can be derived interactively or securely cached via the OS Keyring (`secret-service` / `kwallet`).
- Plaintext configs are never written to unencrypted temporary files on disk.

### 2.2 In-Memory Secret Zeroization
- Sensitive data structures, such as `Auth`, zeroize their contents on drop using the `zeroize` crate (`Zeroize` and `ZeroizeOnDrop`).
- Private keys and passwords are wiped immediately after handshake initialization.

### 2.3 Privilege Separation & Capability Bounding
- The unprivileged client (`vortex`) has **zero** network administration privileges. It interacts with `vortexd` strictly via a Unix domain socket at `/run/vortex/vortex.sock`.
- The Unix domain socket permissions are enforced at `0660` owned by group `vortex` (or `0600` for user fallback).
- Systemd service hardening for `vortexd.service`:
  ```ini
  [Service]
  CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
  AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
  NoNewPrivileges=yes
  ProtectSystem=strict
  ProtectHome=read-only
  ProtectKernelTunables=yes
  ProtectControlGroups=yes
  RestrictRealtime=yes
  RestrictSUIDSGID=yes
  PrivateTmp=yes
  ```

### 2.4 Strict Leak Protection (nftables Kill-Switch)
- Atomic `table inet vortex` firewall table.
- Default policy on `output`: `drop`.
- Allowed paths:
  1. Loopback interface (`iifname "lo" accept`).
  2. Tunnel interface (`oifname "vortex0" accept`).
  3. DHCP traffic (`udp sport 68 dport 67 accept`).
  4. Explicit IP and port of the active VPN remote server endpoint.
  5. Optional RFC1918 LAN allow (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) when LAN bypass is enabled.
- Automatic disarming and idempotent rollback on graceful shutdown or crash recovery.

### 2.5 Logging and Telemetry Rules
- Secrets, private keys, UUIDs, passwords, and raw share links are **never logged**.
- Any display or logging of profile endpoints uses `vortex_core::model::redact_link()` or `redact_secret()`.
