# NetSpecter Architecture

> The map for anyone adding a feature to this codebase. Read this first, then the module you need.

## The big picture

NetSpecter is four crates with a strict privilege split:

```
┌─────────────────────────────┐        ┌──────────────────────────────┐
│  netspecter (GUI, GTK4)     │        │  netspecter-cli (terminal)   │
│  runs as your user          │        │  runs as your user           │
└──────────────┬──────────────┘        └──────────────┬───────────────┘
               │  framed-JSON over a per-instance     │
               │  Unix socket (netspecter_common::ipc) │
               ▼                                       ▼
        ┌──────────────────────────────────────────────────┐
        │  netspecter-agent  (root, spawned via pkexec)    │
        │  owns the wireless card, scans, attacks,         │
        │  captures. Serves ONE client; full cleanup on    │
        │  disconnect.                                    │
        └──────────────────────┬───────────────────────────┘
                               │ uses
                               ▼
        ┌──────────────────────────────────────────────────┐
        │  netspecter-common  (shared, no privilege)       │
        │  IPC wire types, crypto, scheduler, autopwn      │
        │  ranking, cracker plumbing, types, channels      │
        └──────────────────────────────────────────────────┘
```

**Why this shape**: the GUI never holds root. Every privileged operation is a
request/response over the socket, so a GUI crash can never leak a monitor-mode
card or an orphaned deauth. The agent cleans everything up on disconnect by
design (see `crates/agent/src/main.rs` header docs).

## Where a new feature goes

| You are adding… | It lives in… | Steps |
|---|---|---|
| A new attack on WiFi | `crates/agent/src/backend/<attack>.rs` | 1) module with `run()` style API (see `wps.rs`, `evil_twin.rs` for the pattern) 2) register in `backend/mod.rs` 3) IPC request/response variants in `common/src/ipc.rs` 4) agent dispatch in `agent/src/server.rs` 5) GUI page in `gui/src/frontend/pages/` 6) CLI menu entry in `cli/src/main.rs` |
| GUI-only behavior | `crates/gui/src/frontend/**` | pages/ for screens, connections/ for flows. Never talk to the card directly — always through `gui/src/backend/client.rs` |
| CLI-only behavior | `crates/cli/src/main.rs` | menu-driven, one function per flow |
| Shared logic both fronts need | `crates/common/src/**` | pure data + logic only; no privilege, no GTK, no root paths |
| A new external tool integration | `crates/common/src/deps.rs` + the module that shells out to it | declare in deps (required vs optional per front), then `Command::new` at the call site with `is_installed()` guards |
| Report/parsing of tool output | `crates/common/src/cracker.rs` (hashcat/aircrack output) or a new `common` module | parsers get fuzz-style tests — see `fuzz_parse_*` in `cracker.rs` tests |

## The attack-module pattern

Every attack in `agent/src/backend/` follows the same shape — keep new ones
consistent:

1. **Config struct** (serde, plain data) — what the operator chose.
2. **`launch(config) -> Result<Session, Error>`** — starts daemons/threads,
   returns a **Session handle** holding child PIDs/kill handles.
3. **`stop(&Session)`** — precise teardown: kill by PID, restore services
   (`interface.rs` restores NetworkManager), remove NAT rules. Never
   `pkill` by name.
4. **Errors**: `thiserror` enum per module. No unwraps in prod paths (see
   the panic-hygiene sweep, commit d12da77).
5. **Globals** (live state) go through `globals::lock_ok()` — poison-recovering
   lock helper; never `lock().unwrap()`.

## IPC protocol — the contract

`crates/common/src/ipc.rs` is the single source of truth:

- `Request` / `Response` enums (serde). One variant per operation.
- Framed JSON codec in the same file (`write_msg` / `read_msg`).
- Adding an operation = add variant pair + agent dispatch arm in
  `agent/src/server.rs` `match` + client helper in `gui/src/backend/client.rs`
  (and/or `ipc_client.rs` for the GUI page-side client).

## Modules that exist but are dormant

`common::karma`, `common::hid`, `common::ble`, `common::caplet` are fully
written but **not wired to any front-end yet** (inherited from the airgorah
fork, kept because they're solid building blocks):

- **karma** — KARMA/Mana rogue-AP (probe-response attack)
- **hid** — MouseJack/KeySniffer class wireless keyboard/mouse attacks
- **ble** — BLE reconnaissance (scan_req/scan_resp parsing)
- **caplet** — bettercap-style command-script engine for attack automation

If you want any of these as a feature: wire it like any other attack module
(see the table above) — the logic is already written and unit-tested.

## Testing conventions

- Unit tests live in the same file under `#[cfg(test)] mod tests`.
- Parsers that eat external bytes/text get **fuzz-style tests**: deterministic
  LCG byte streams + all-truncations (see `sniffer.rs`, `pmkid.rs`,
  `cracker.rs` tests). Any new parser must ship with these.
- CI gates: `ci` workflow (check+test+doc+audit, `RUSTFLAGS=-D warnings`) and
  `docker` workflow (clippy advisory + native builds x86_64 + aarch64).
- GTK widget tests need a display — they skip cleanly on headless CI via the
  `gtk_available()` helper convention.

## Conventions worth keeping

- **ASCII only** in `.fpm` / packaging files (Ruby shellsplit breaks otherwise).
- Commit messages document the *why* — repo history is the changelog.
- All user-facing strings in the CLI are plain `println!`/helpers (`ok`, `warn`
  in `cli/src/main.rs`); the GUI shows errors via `ErrorDialog::spawn(window,
  title, body)` — 3 args.
- Release = tag `v*`; the release workflow builds natively per arch
  (x86_64 on `ubuntu-latest`, aarch64 on `ubuntu-24.04-arm` — do NOT
  cross-compile GTK4, it dies at glib-sys).

## File map (the ones you'll touch most)

```
crates/common/src/ipc.rs          ← every IPC variant lives here
crates/agent/src/server.rs        ← the root-side request dispatcher
crates/agent/src/backend/         ← one file per attack/capability
crates/gui/src/backend/client.rs  ← GUI→agent typed helpers
crates/gui/src/frontend/pages/    ← one file per GUI screen
crates/cli/src/main.rs            ← whole CLI (menu flows)
crates/common/src/scheduler.rs    ← attack job scheduling + pools
crates/common/src/cracker.rs      ← hashcat/john/aircrack integration + output parsing
```
