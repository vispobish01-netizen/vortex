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
- The unprivileged client (`vortex`) interacts with `vortexd` strictly via a Unix domain socket (`$XDG_RUNTIME_DIR/vortex.sock` for user systemd service, or `/run/vortex/vortex.sock` when run system-wide).
- Ephemeral runtime configs (`singbox.json`, `xray.json`, `ovpn.conf`, `ovpn.auth`) are written with strict `0600` permissions inside `active_run_dir()` (`$XDG_RUNTIME_DIR/vortex` or `/run/vortex`).
- File capabilities (`vortex setup`) grant `cap_net_admin,cap_net_bind_service,cap_net_raw+ep` to managed `sing-box` and `xray` binaries so TUN creation and `SO_BINDTODEVICE` egress binding avoid running interactive UI sessions under `sudo`.

### 2.4 Strict Leak Protection (nftables Kill-Switch)
- Atomic `table inet vortex` firewall table.
- Default policy on `output`: `drop`.
- Allowed paths:
  1. Loopback interface (`oifname "lo" accept`).
  2. Active tunnel interface (`oifname "vx0" accept`, `vxwg0`, `vxawg0`, or `tun*`).
  3. DHCP traffic (`udp sport 68 udp dport 67 accept`).
  4. Explicit IP and port of the active VPN remote server endpoint.
  5. Optional RFC1918 LAN allow (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) when LAN bypass is enabled.
- Preference (`shield_enabled`) stored under `user_config_dir()` and state (`shield.json`) under `active_run_dir()`, with automatic disarming and idempotent rollback on crash recovery.

### 2.5 Logging and Telemetry Rules
- Secrets, private keys, UUIDs, passwords, and raw share links are **never logged**.
- Any display or logging of profile endpoints uses `vortex_core::model::redact_link()` or `redact_secret()`.
