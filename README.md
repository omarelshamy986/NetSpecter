# 🕸️ NetSpecter

> **Advanced WiFi security auditing suite — built for authorized penetration testers.**

[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![GTK4](https://img.shields.io/badge/GTK-4.6-green.svg)](https://www.gtk.org)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#-requirements)
[![Version](https://img.shields.io/badge/version-2.2.0-purple.svg)](Cargo.toml)

NetSpecter is a native Linux tool for assessing the security posture of WiFi networks under **explicit, written authorization**. It discovers nearby networks and clients, captures the various authentication handshakes each encryption class exposes, and offers a guided workflow for the workflows a red team or pentester runs end-to-end — from scan to signed report.

It is written in **Rust** with a **GTK4** GUI and an out-of-process privileged agent that owns the wireless interface.

> 🔒 **This is an offensive security tool.** Use it only against networks you own or have written permission to test. See [Ethics & Law](#-ethics--law) below.

---

## ✨ Capabilities

### 🔐 Encryption coverage

| Encryption | Attack surface |
|---|---|
| **WPA / WPA2 (PSK)** | 4-way handshake capture + dictionary / rule-based cracking |
| **WPA / WPA2 (PMKID)** | **PMKID auto-attack** — captures the PMKID from the very first EAPOL frame, **no client required, no deauth needed** |
| **WPA3-SAE** | Detection of transition-mode downgrade (WPA2/WPA3 mixed), dragonblood signal collection |
| **WEP** | IVs collection with replay acceleration + statistical / PTW cracking |
| **Open / OWE** | Visibility, signal-mapping, client enumeration |

### 🛡️ WPS attacks

| Mode | Description |
|---|---|
| **Pixie Dust** | Offline PIN recovery via weak PRNG in many WPS chipsets (Realtek, Ralink, Broadcom) — crack in seconds, no wordlist |
| **Reaver / WPS PIN brute** | Online PIN enumeration with rate-limiting and lockout awareness |
| **NULL PIN** | Probes for the historic `00000000` bypass |
| **Online brute-force** | Configurable delay, exponential backoff on WPS lockout |

### 👻 Hidden SSID discovery

| Method | Description |
|---|---|
| **Probe-request harvesting** | Clients reveal their associated ESSID in probe requests when roaming — passive collection |
| **Targeted deauth-to-reveal** | Forces any connected client to retransmit the ESSID in re-association frames |
| **Beacon-frame fingerprinting** | Heuristics on vendor / BSSID / channel to recover an empty SSID from known vendor OUI patterns |

### 🎭 Fluxion-style Evil Twin

> The classic social-engineering flow for WPA-Personal: present a fake AP that imitates the real one, push clients onto it with a deauth flood, and serve a captive portal that requests the WiFi password under the guise of "re-authentication".

| Component | Purpose |
|---|---|
| **`hostapd`** | Spins up a fake AP with the target's ESSID and BSSID |
| **`dnsmasq`** | Captive-portal DNS redirection + DHCP lease to attacker |
| **`lighttpd` / built-in** | Serves the captive portal (fully templated, customizable) |
| **`iptables`** | NAT + DNS poisoning so the portal is inescapable |
| **Built-in credential sink** | Logs captured credentials with timestamps + client fingerprint |

The captive-portal HTML is fully templated via `templates/portal.html.askama` and ships with **two default skins** (router-mimic and ISP-mimic). Operators are expected to customize the skin to match the target environment.

### 🧙 Smart Wizard

A guided, step-by-step flow for operators who don't want to remember the optimal sequence:

```
┌─ Step 1: Authorize ────────────────┐
│   Confirm scope + consent + log    │
└────────────────────────────────────┘
            ↓
┌─ Step 2: Scan ─────────────────────┐
│   Live channel scan, ESSID/Client   │
│   enumeration, signal strength      │
└────────────────────────────────────┘
            ↓
┌─ Step 3: Identify ─────────────────┐
│   Encryption class + best attack    │
│   (WPS, PMKID, full handshake…)    │
└────────────────────────────────────┘
            ↓
┌─ Step 4: Capture ──────────────────┐
│   Run the optimal capture strategy  │
│   (PMKID first → handshake → WPS)   │
└────────────────────────────────────┘
            ↓
┌─ Step 5: Crack ────────────────────┐
│   Hashcat / John / aircrack-ng      │
│   auto-detected and dispatched      │
└────────────────────────────────────┘
            ↓
┌─ Step 6: Report ───────────────────┐
│   HTML + PDF with findings,         │
│   timestamps, evidence trail,       │
│   remediation guidance              │
└────────────────────────────────────┘
```

### 📊 Reporting

- **HTML report** — interactive, dark-themed, includes AP map, attack timeline, captured materials
- **PDF report** — print-ready, signed-by-agent
- **JSON export** — for ingestion into Nessus / Dradis / custom pipelines

---

## 📋 Requirements

| Requirement | Reason |
|---|---|
| **Linux** (kernel 5.10+) | Monitor mode + packet injection |
| **Rust 1.75+** | Build (GTK4 bindings require recent toolchain) |
| **GTK 4.6+** | GUI runtime |
| **Aircrack-ng suite** | `airodump-ng`, `aireplay-ng`, `aircrack-ng` |
| **External tools** (optional) | `hostapd`, `dnsmasq`, `iptables`, `lighttpd` (only required for Evil-Twin) |
| **Wireless adapter** | Must support **monitor mode** + **packet injection**. See [adapter compatibility list](docs/adapters.md). |

---

## 🛠 Build

```bash
git clone https://github.com/AbD02018/NetSpecter.git
cd NetSpecter
cargo build --release
sudo ./target/release/netspecter-agent &
./target/release/netspecter
```

Or via the prebuilt `.deb` / `.rpm` from the [Releases](../../releases) page (Debian / RedHat / Arch).

---

## 🖼 Screenshots

> _To be added — pending operator environment._

---

## 🗂 Architecture

```
NetSpecter
├── crates/
│   ├── common/             # Shared types, IPC protocol, parsers, crypto helpers
│   ├── agent/              # Privileged process — owns the wireless interface
│   │   ├── backend/
│   │   │   ├── scan.rs          # Live AP + client scanner
│   │   │   ├── capture.rs       # Handshake + PMKID capture
│   │   │   ├── deauth.rs        # Deauth / disassoc injection
│   │   │   ├── pmkid.rs         # PMKID auto-extraction
│   │   │   ├── wps.rs           # WPS enumeration + Pixie Dust / Reaver
│   │   │   ├── wep.rs           # WEP IVs collection + cracking
│   │   │   ├── wpa3.rs          # WPA3-SAE detection + transition-mode scan
│   │   │   ├── hidden.rs        # Hidden SSID discovery
│   │   │   ├── evil_twin.rs     # Fluxion-style rogue AP + captive portal
│   │   │   ├── report.rs        # HTML/PDF/JSON report generation
│   │   │   ├── audit.rs         # Timestamped audit log
│   │   │   └── consent.rs       # Explicit-consent gate
│   │   └── ...
│   └── gui/                # Unprivileged GTK4 frontend
│       ├── frontend/
│       │   ├── pages/
│       │   │   ├── wizard.rs        # Smart-wizard guided flow
│       │   │   ├── scan.rs          # Live scan view
│       │   │   ├── attacks.rs       # Attack matrix
│       │   │   ├── reports.rs       # Report viewer
│       │   │   └── consent.rs       # First-run consent modal
│       └── ...
├── templates/
│   ├── portal-router.askama      # Evil-twin captive portal (router skin)
│   ├── portal-isp.askama         # Evil-twin captive portal (ISP skin)
│   ├── report-html.askama        # Pentest report (HTML)
│   └── report-pdf.askama         # Pentest report (PDF)
├── docs/
│   ├── adapters.md          # Wireless adapter compatibility
│   ├── wizard.md            # Smart-wizard walkthrough
│   ├── evil-twin.md         # Evil-twin operator manual
│   ├── reporting.md         # Report generation & customization
│   └── ethics.md            # Ethics & law (read first)
├── Cargo.toml
├── README.md
├── LICENSE
├── NOTICE.md
└── .github/workflows/ci.yml
```

---

## ⚖ Ethics & Law

> **READ BEFORE USE.**

NetSpecter is published for **authorized security testing only**. Operators must have **explicit written authorization** (a signed Rules of Engagement, a penetration-test contract, or equivalent) before using this software against any network or device.

### What "authorized" means in practice

- ✅ Testing your own network or lab
- ✅ Testing a client's network under a signed pentest contract
- ✅ Testing networks in a Capture-the-Flag / security-training context (HackTheBox, TryHackMe, custom labs)
- ❌ Neighbors' WiFi
- ❌ Public hotspots without operator permission
- ❌ Your employer's network outside an authorized test
- ❌ Any network where you have not been granted explicit written permission

### Legal context (Egypt)

The Arab Republic of Egypt's **Law No. 175 of 2018 on Anti-Cyber and Information Technology Crimes** criminalizes unauthorized access to networks and information systems. Penalties include imprisonment and fines. Other jurisdictions have comparable statutes (CFAA in the US, Computer Misuse Act in the UK, etc.).

### Operator consent gate

NetSpecter is published as a private tool. Operators are expected to follow their own professional and legal standards for testing scope.

---

## 🙏 Acknowledgements

NetSpecter builds on the work of **Martin Olivier** — [`airgorah`](https://github.com/martin-olivier/airgorah). The workspace structure, GTK4 GUI skeleton, aircrack-ng orchestration, and native WPA-handshake detection are derived from Airgorah, used under the MIT License. See [NOTICE.md](NOTICE.md) for the full attribution.

WPA-SAE analysis is informed by the **dragonblood** research by Mathy Vanhoef.

---

## 📜 License

[GNU GPL-3.0-or-later](LICENSE). All modifications and NetSpecter additions by AbD02018 are GPL-3.0-or-later; the Airgorah-derived portions retain their original MIT terms.

<sub>Built by [@AbD02018](https://github.com/AbD02018) — for the defenders who need to think like attackers.</sub>