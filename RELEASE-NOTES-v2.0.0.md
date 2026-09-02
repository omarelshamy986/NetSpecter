# NetSpecter v2.0.0 — Multi-Radio Attack Suite

> The largest release: six new modules transform NetSpecter from a WiFi-audit tool into a full-spectrum wireless attack platform.

## What's new in 2.0

### PR #13a — 🔵 BLE reconnaissance (`common/src/ble.rs`)
- Active + passive BLE scanning model, AD-struct parser
- Device extraction: name (Complete/Shortened Local Name), manufacturer
  data (0xFF), service UUIDs (16/32-bit, deduped), TX power
- Heuristic classifier: iBeacon, Eddystone, FitnessTracker (0x180D),
  MedicalDevice (0x1809/0x1822), HID (0x1812), SmartLock, AssetTracker,
  GenericBle, Unknown
- 15 unit tests

### PR #13b — ⌨️ Wireless HID (`common/src/hid.rs`)
- ESB packet model + protocol families (Logitech Unifying, Dell,
  Microsoft, generic keyboard/mouse)
- USB HID usage-code → printable-char rendering with shift handling
- Keystroke session rendering; encrypted devices flagged honestly
- Injection frame builder for authorized replay
- Vendor fingerprinting by address prefix + payload shape
- 22 unit tests

### PR #13c — 🎭 KARMA / Mana rogue AP (`common/src/karma.rs`)
- PNL learning from broadcast probes (case-insensitive aggregation)
- Target ranking by distinct client count, capped by max VAPs
- Per-ESSID hostapd config generation; channels spread 1/6/11
- Mana hand-off config stub for Enterprise targets (hostapd-mana)
- 11 unit tests

### PR #13d — 🔓 Offline cracker pipeline (`common/src/cracker.rs`)
- Hashcat mode mapping (22000 / 2500), WEP → aircrack-ng
- Hashfile format sniffing (PMKID vs EAPOL vs john-style)
- Command construction for unattended runs (`-w 4 -O --machine-readable`)
- Machine-readable status parser (multi-device speed summing, progress)
- Potfile-line recovery parsing, wordlist size estimation
- FIFO crack queue with job lifecycle
- 19 unit tests

### PR #13e — ⚡ Mass parallel scheduler (`common/src/scheduler.rs`)
- Priority scheduling: PMKID → WPS → Handshake → Hidden → Cracking
- Channel arbitration — same-channel jobs serialize, other channels run
- Worker pool with injected attack closure (test-friendly), deadline-safe
- `plan_batch()` — wifite-style auto flow per target
- Bridge into the crack queue
- 18 unit tests

### PR #13f — 📜 Caplet scripting (`common/src/caplet.rs`)
- Linear automation language: `set` / `run` / `sleep` + `#` comments
- `{var}` interpolation, `|| continue` shell-style error tolerance
- Numbered parse errors, round-trip rendering
- Deliberately no loops/conditionals — predictable and auditable
- 15 unit tests

## Stats

- 6 new modules, ~3,300 lines, 100 new unit tests
- Total: 7 crates modules, ~9,000 lines Rust, ~200 unit tests
- 21 PRs, tags v1.0.0 → v2.0.0

## Ethics

NetSpecter remains a private tool for authorized testing. KARMA affects
every matching client in range (inherent to the attack) and HID/BLE
modules require dedicated hardware — operators are responsible for
staying inside their authorized scope.

<sub>Built by [@AbD02018](https://github.com/AbD02018)</sub>