# AGENTS.md — contributor & AI-agent ground rules

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first — it has the crate map, the
attack-module pattern, and the "where does my change go" table. This file is
the rules of the road for anyone (human or agent) touching the code.

## Hard rules

1. **No `unwrap()`/`expect()` in production paths.** Errors return
   `Result`/`Option`; a broken icon or bad input degrades, never panics.
   Globals lock via `lock_ok()` (poison-recovering) — never `lock().unwrap()`.
   The only allowed `expect`s are documented infallible-by-construction ones
   (search `infallible by construction`).
2. **The GUI/CLI never touch the wireless card.** Privileged work goes through
   the IPC protocol (`common/src/ipc.rs`) to the agent. One variant pair per
   operation: `Request`/`Response` + agent dispatch arm in
   `agent/src/server.rs` + client helper in `gui/src/backend/client.rs`.
3. **Every parser that eats external bytes/text ships with fuzz-style tests**
   (deterministic LCG streams + all-truncations — see `fuzz_*` in
   `sniffer.rs`/`pmkid.rs`/`cracker.rs` tests). No exceptions.
4. **Attacks own their cleanup.** A new attack module returns a Session handle
   and `stop()` kills by PID, restores services, removes NAT rules — never
   `pkill` by name (kills the wrong process).
5. **CI is the verifier.** Local toolchain is old (cargo 1.75, lock v4) — you
   likely can't build here. Write code, sanity-check braces/import placement
   statically, push, and read the REAL GitHub logs:
   `gh api repos/AbD02018/NetSpecter/actions/jobs/<id>/logs` (strip ANSI).
6. **RustCrypto crates move as one wave.** sha1/sha2/hmac/pbkdf2/digest share
   trait bounds — bump them together or `HmacSha1`/`pbkdf2_hmac` break
   (E0277 CoreProxy). See PR #7 for the pattern.
7. **GTK builds are native per-arch** — x86_64 on `ubuntu-latest`, aarch64 on
   `ubuntu-24.04-arm`. Never cross-compile GTK4 (dies at glib-sys pkg-config).
8. **Workflows need unique `name:`** — two workflows named `ci`/`CI` make
   GitHub dispatch only one per push (this silently broke CI once).

## Conventions

- Commit messages document the *why* — the history is the changelog.
- Tests live in-file under `#[cfg(test)] mod tests`; GTK widget tests skip on
  headless CI.
- ASCII only in `.fpm`/packaging files.
- GUI errors surface via `ErrorDialog::spawn(window, title, body)` (3 args).
- Release = tag `v*` (release workflow publishes; draft is flipped manually).

## Quick orientation for a new agent

```
ARCHITECTURE.md                ← start here (map + patterns)
crates/common/src/ipc.rs       ← the IPC contract
crates/agent/src/server.rs     ← root-side dispatcher
crates/agent/src/backend/*.rs  ← one module per capability
crates/gui/src/frontend/       ← GUI screens (pages/, connections/)
crates/cli/src/main.rs         ← the terminal front-end
```

Dormant-but-complete modules awaiting wiring: `karma`, `hid`, `ble`, `caplet`
(see ARCHITECTURE.md §Modules that exist but are dormant).
