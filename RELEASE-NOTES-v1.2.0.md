# NetSpecter v1.2.0

> **Full pixie-dust recovery loop + GUI↔agent IPC integration.**

Builds on v1.1.0 with two major additions:

## What's in 1.2.0

### 🧮 PR #10a — WPS 1536-bit Diffie-Hellman (full pixie-dust recovery)

The pixie-dust attack was previously blocked by a placeholder: the
DH math was stubbed out, so the brute loop ran against an all-zero
shared secret. v1.2.0 ports the canonical 1536-bit WPS prime and the
DH key-exchange math end-to-end:

- `WPS_DH_P_BYTES` — the 192-byte / 1536-bit WPS 2.0 prime (Appendix B, bit-exact copy from the spec)
- `WPS_DH_G = 2` — the WPS DH generator
- `wps_prime()` / `pub_key_from_bytes()` / `pub_key_to_bytes()` — BigUint ↔ 192-byte conversions
- `generate_private_key()` — random 192-byte key in `[2, p-1]`
- `derive_public_key()` — `g^priv mod p`
- `compute_shared_secret()` — `peer_pub^priv mod p`
- `shared_secret_32()` — truncate the 192-byte shared secret to 32 bytes (WPS AuthKey material)
- `prime_sanity_check()` — `p mod 4 == 3, p mod 8 == 7` (catches mis-imports)

9 unit tests covering the round-trip, symmetry, and prime sanity.
`recover_pixie_dust_pin()` in the agent now runs the full DH step
before the brute loop, so the WPS recovery path is end-to-end correct.

### 🔌 PR #10b — GTK4 button handlers ↔ IPC

The pages had widgets but no click handlers; v1.2.0 wires them up:

- `wire_all(state)` connects every page's buttons in one call
- SmartWizardPage: dropdown change → `WizardPlanFor` worker → `glib::idle_add_once` render
- PmkidPage: Capture / Verify / Open-in-Wireshark handlers (worker thread + idle bounce)
- EvilTwinPage: Launch / Stop with full `EvilTwinConfig`
- ReportsPage: Generate dispatches `GenerateReport` with consent + targets + plans
- AuditLogPage: chain head on first paint + Verify-chain button

Worker-thread + `glib::idle_add_once` pattern keeps the GTK4 main loop
responsive while the agent works on long-running IPC calls.

2 unit tests for `extract_capture_path`.

## 📊 Stats

- 100+ unit tests in the workspace
- 13 PRs total in the repo
- 5 GTK4 pages (wizard / pmkid / evil-twin / reports / audit)
- 9 typed IPC wrappers
- 8 audit-log action kinds
- 6 captive-portal/report templates
- 5 cryptographic primitives (PBKDF2-HMAC-SHA1, HMAC-SHA1, HMAC-SHA256, 1536-bit DH, WPS checksum)

## ⚖️ Ethics

NetSpecter is published for **authorized security testing only**. Operators must have **explicit written authorization** before using this software against any network or device. See the README ethics section for full guidance, including the legal context under Egypt's Law No. 175 of 2018.

## ⚠️ Known Limitations

- **Chip-specific PRNG recovery** for pixie-dust (Ralink / Realtek / Broadcom / Qualcomm patterns) is documented but not ported; operators wanting chip-targeted recovery should cross-reference with the canonical `pixiedust-loop` reference implementation.
- **GTK4 pages** are wired up but not exercised end-to-end in CI; the GTK runtime isn't available in the runner. Manual testing on a Linux desktop with a wireless adapter is the path forward.
- **CI** is Linux-only; macOS / Windows builds would need additional GTK4-port work.

<sub>Built by [@AbD02018](https://github.com/AbD02018) — for the defenders who need to think like attackers.</sub>