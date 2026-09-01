# NetSpecter v1.0.0

> **Advanced WiFi security auditing suite — built for authorized penetration testers.**

First stable release of NetSpecter. Combines the GTK4 GUI / aircrack-ng orchestration from the upstream airgorah codebase with a full set of attack and reporting modules written from scratch.

## What's in 1.0.0

### 🔐 Encryption coverage
- **WPA / WPA2-Personal** — 4-way handshake capture + offline dictionary attack
- **PMKID auto-attack** — passive EAPOL M1 capture, **no client required, no deauth needed**
- **WPA3-SAE** detection + transition-mode downgrade flag (PSK + SAE on the same AP = crackable)
- **WEP** — IVs collection (Fragmentation / ARP-replay / ChopChop) + aircrack-ng crack
- **OWE** detection

### 🛡️ WPS attacks
- Pixie Dust — offline PIN recovery via weak PRNG (Ralink / Realtek / Broadcom / Qualcomm)
- Online brute — Reaver / Bully orchestration with rate-limit / lockout detection
- NULL PIN — historical `00000000` probe
- Full WPS TLV parser (tag 0x104A / 0x101E / 0x1018 / 0x1014 / 0x1015 / 0x103B / 0x103C)

### 👻 Hidden SSID discovery
- Probe-request harvesting (passive)
- Targeted deauth-to-reveal (active)
- Vendor-OUI fingerprinting (Cisco / Linksys / Ubiquiti / Aruba / TP-Link)

### 🎭 Fluxion-style Evil Twin
- hostapd + dnsmasq + iptables NAT orchestration
- 2 captive-portal skins (router-mimic dark + ISP-mimic light)
- PMKID verification of captured credentials (the smoking gun)
- Customisable skin template under `templates/`

### 🧙 Smart Wizard
- 6-step guided flow (Authorize → Scan → Identify → Capture → Crack → Report)
- Optimal attack selection per encryption class
- Hidden-recovery waterfall
- GTK4 notebook tab with run/run-all actions

### 📊 Reporting + Safety
- HTML (Handlebars template) + JSON reports
- wkhtmltopdf-based PDF generation (operator opt-in)
- Auto-finding generation with CVSS-style severity
- SHA-256-chained audit log (tamper-evident)
- Consent gate (operator + scope + ROE + tamper detection)
- GitHub Actions CI (fmt + clippy + test + build + audit + docs)

## 🛠 Build

```bash
git clone https://github.com/AbD02018/NetSpecter
cd NetSpecter
cargo build --release
sudo ./target/release/netspecter-agent &
./target/release/netspecter
```

System dependencies:
- Linux kernel 5.10+
- GTK 4.6+
- Aircrack-ng suite (`airodump-ng`, `aireplay-ng`, `aircrack-ng`)
- Optional: `hostapd`, `dnsmasq`, `iptables`, `wkhtmltopdf`, `wireshark`
- Wireless adapter with monitor mode + packet injection

## 📦 Release artifacts

This release builds for:
- `x86_64-unknown-linux-gnu` (Intel / AMD desktop)
- `aarch64-unknown-linux-gnu` (ARM64 / Apple Silicon under Linux)

Each archive contains:
- `netspecter` — the GTK4 GUI
- `netspecter-agent` — the privileged wireless daemon
- `templates/` — captive-portal + report templates
- `README.md`, `LICENSE`, `NOTICE.md`

## ⚖️ Ethics

NetSpecter is published for **authorized security testing only**. Operators must have **explicit written authorization** before using this software against any network or device. See the README ethics section for full guidance, including the legal context under Egypt's Law No. 175 of 2018.

## 🙏 Acknowledgements

Derived from Airgorah by Martin Olivier (MIT). See `NOTICE.md` for the full attribution. The cryptographic primitives (PMK via PBKDF2-HMAC-SHA1, PMKID via HMAC-SHA1) follow IEEE 802.11i reference vectors and are unit-tested against the canonical values.

## ⚠️ Known limitations

- **WPS Pixie Dust crypto recovery** is bounded by the chip-pattern table; chip-specific weaknesses (e.g. the Ralink `E-S1=0` pattern) are implemented at the parsing layer but the full offline secret-derivation loop is intentionally a stub — operators should cross-reference with the canonical `pixiedust-loop` implementation when verifying.
- **Evil Twin automation** requires a second wireless adapter; built-in laptop adapters cannot run monitor mode on the original interface while hostapd drives the fake AP on a second.
- **GTK4 GUI** is single-window; multi-window workflows (e.g. wizard + scan + evil-twin simultaneously) require window tiling at the OS level.
- **CI** is Linux-only; macOS / Windows builds would need additional GTK4-port work.

## 📜 License

GNU GPL-3.0-or-later for the NetSpecter additions and modifications; the Airgorah-derived portions retain their original MIT terms (see `NOTICE.md`).

<sub>Built by [@AbD02018](https://github.com/AbD02018) — for the defenders who need to think like attackers.</sub>