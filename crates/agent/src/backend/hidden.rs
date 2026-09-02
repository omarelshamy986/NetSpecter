//! Hidden-SSID discovery.
//!
//! An "hidden" AP is one whose beacon frames don't carry an ESSID (the
//! operator has unchecked "Broadcast SSID" in the admin UI).  Clients that
//! are configured for that network still send *probe requests* containing
//! the ESSID they're looking for — that's the foothold.
//!
//! ## Methods
//!
//! 1. **Probe-request harvesting (passive)** — listen for probe requests on
//!    the target BSSID's channel; every probe a connected client sends
//!    carries the ESSID. Once we see a probe from any client addressed at
//!    the target's BSSID, we recover the ESSID.
//!
//! 2. **Targeted deauth-to-reveal (active)** — deauth every connected
//!    client; on re-association, the client transmits a re-association
//!    request frame that includes the ESSID, broadcasting it on the
//!    channel where we can hear it.
//!
//! 3. **Vendor-OUI fingerprinting** — many enterprise APs ship with a
//!    default ESSID derived from their model + serial number; if the
//!    operator has previously trained the fingerprint table we can guess
//!    the ESSID without ever seeing it.
//!
//! Methods 1 and 2 produce *observed* ESSIDs (high confidence); method 3
//! produces a *guess* and is always surfaced as such.
//!
//! Method 2 is the only active attack in this module — methods 1 and 3
//! are fully passive.

use netspecter_common::types::*;
use libwifi::{Addresses, Frame};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// A candidate ESSID recovered for a hidden AP, with its evidence trail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HiddenSsidCandidate {
    pub essid: String,
    pub source: SsidSource,
    /// How many times the ESSID was observed (probe requests / re-association frames).
    pub observations: u32,
    /// Wall-clock of the first observation.
    pub first_seen: String,
    /// The MAC address of the client that leaked the ESSID.
    pub leaking_client: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SsidSource {
    /// Recovered from a probe request.
    ProbeRequest,
    /// Recovered from a re-association frame after deauth.
    DeauthReassoc,
    /// Recovered from a probe response (rare, only on hidden APs with
    /// misconfigured firmware).
    ProbeResponse,
    /// Vendor-OUI / model-number guess from the fingerprint table.
    VendorGuess,
}

/// Run passive probe-request harvesting against a hidden AP.
///
/// Sits on the channel and listens for as long as `timeout` allows. Returns
/// the highest-confidence candidate found in that window (most observations
/// wins ties).
pub fn harvest_via_probes(
    bssid: &str,
    timeout: Duration,
    on_observation: &mut dyn FnMut(&HiddenSsidCandidate),
) -> Option<HiddenSsidCandidate> {
    let bssid_bytes = netspecter_common::crypto::parse_mac(bssid)?;
    let iface = super::interface::get_iface().clone()?;
    let socket = super::raw_socket::open(&iface).ok()?;

    let deadline = Instant::now() + timeout;
    let mut counts: HashMap<String, HiddenSsidCandidate> = HashMap::new();
    let mut frame = vec![0u8; 4096];

    while Instant::now() < deadline {
        match super::raw_socket::recv(&socket, &mut frame) {
            Ok(n) if n > 0 => {
                let parsed = match libwifi::parse_frame(&frame[..n], false) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if let Some(candidate) = extract_essid_from_probe(&parsed, &bssid_bytes) {
                    let entry = counts
                        .entry(candidate.essid.clone())
                        .or_insert_with(|| candidate.clone());
                    entry.observations += 1;
                    on_observation(entry);
                }
            }
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    counts
        .into_values()
        .max_by_key(|c| c.observations)
}

fn extract_essid_from_probe(frame: &Frame, target_bssid: &[u8; 6]) -> Option<HiddenSsidCandidate> {
    let probe = match frame {
        Frame::ProbeRequest(p) => p,
        _ => return None,
    };
    let header = &probe.header;
    let Some(bssid) = header.bssid() else {
        return None;
    };
    if bssid.to_long_string().to_lowercase() != netspecter_common::crypto::format_mac(target_bssid).to_lowercase() {
        return None;
    }
    let essid = probe.station_info.essid()?;
    if essid.is_empty() || essid.starts_with("<hidden") {
        return None;
    }
    // Transmitter (TA) is addr2 of the management frame; Addresses gives
    // us the (addr1, addr2, addr3) triple.
    let (_, ta, _) = header.addresses();
    let leaking_client = Some(ta.to_long_string());

    Some(HiddenSsidCandidate {
        essid: essid.to_string(),
        source: SsidSource::ProbeRequest,
        observations: 1,
        first_seen: chrono::Utc::now().to_rfc3339(),
        leaking_client,
    })
}

/// Run an active deauth-to-reveal attack.
///
/// Deauths every client of the target AP, then listens on the channel for
/// re-association requests. Each re-assoc frame carries the ESSID the
/// client is associating to — which is exactly the hidden ESSID we're
/// trying to recover.
pub fn reveal_via_deauth(
    bssid: &str,
    channel: &str,
    timeout: Duration,
) -> Option<HiddenSsidCandidate> {
    let iface = super::interface::get_iface().clone()?;
    let bssid_bytes = netspecter_common::crypto::parse_mac(bssid)?;

    // Step 1: deauth every client. The agent already has a deauth loop in
    // `deauth.rs`; we use the broadcast variant here (FF:FF:FF:FF:FF:FF).
    let ap = AP {
        essid: "<hidden>".into(),
        bssid: bssid.into(),
        band: if channel.parse::<u32>().unwrap_or(0) > 14 { "5".into() } else { "2.4".into() },
        channel: channel.into(),
        power: "-1".into(),
        privacy: "?".into(),
        hidden: true,
        handshake: false,
        saved_handshake: None,
        first_time_seen: chrono::Utc::now().to_rfc3339(),
        last_time_seen: chrono::Utc::now().to_rfc3339(),
        clients: Default::default(),
    };
    if let Err(e) = super::deauth::launch_deauth_attack(&iface, ap, None, 5, true) {
        log::warn!("deauth-to-reveal: launch failed for {bssid}: {e}");
        return None;
    }

    // Step 2: listen for re-association frames. They carry the ESSID the
    // client is trying to join.
    let socket = super::raw_socket::open(&iface).ok()?;
    let deadline = Instant::now() + timeout;
    let mut frame = vec![0u8; 4096];
    let mut candidate: Option<HiddenSsidCandidate> = None;

    while Instant::now() < deadline {
        match super::raw_socket::recv(&socket, &mut frame) {
            Ok(n) if n > 0 => {
                let parsed = match libwifi::parse_frame(&frame[..n], false) {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if let Some(c) = extract_essid_from_reassoc(&parsed, &bssid_bytes) {
                    candidate = Some(c);
                    break;
                }
            }
            _ => std::thread::sleep(Duration::from_millis(50)),
        }
    }

    // Step 3: stop the deauth loop (we already have the answer, or we don't).
    super::deauth::stop_deauth_attack(bssid);

    candidate
}

fn extract_essid_from_reassoc(frame: &Frame, target_bssid: &[u8; 6]) -> Option<HiddenSsidCandidate> {
    let reassoc = match frame {
        Frame::ReassociationRequest(r) => r,
        _ => return None,
    };
    let header = &reassoc.header;
    let Some(bssid) = header.bssid() else { return None; };
    if bssid.to_long_string().to_lowercase() != netspecter_common::crypto::format_mac(target_bssid).to_lowercase() {
        return None;
    }
    let essid = reassoc.station_info.essid()?;
    if essid.is_empty() || essid.starts_with("<hidden") {
        return None;
    }
    Some(HiddenSsidCandidate {
        essid: essid.to_string(),
        source: SsidSource::DeauthReassoc,
        observations: 1,
        first_seen: chrono::Utc::now().to_rfc3339(),
        leaking_client: None,
    })
}

/// Run the full hidden-SSID discovery flow.
///
/// Strategy:
/// 1. Start with a passive probe harvest (60s window, no noise).
/// 2. If no candidate surfaces, escalate to deauth-to-reveal (15s window,
///    targets the AP with a broadcast deauth).
/// 3. If still nothing, fall back to vendor-OUI fingerprinting (a pure
///    guess; surfaced with a `VendorGuess` source tag).
pub fn discover_hidden_essid(
    bssid: &str,
    channel: &str,
) -> Vec<HiddenSsidCandidate> {
    let mut out = Vec::new();

    // Step 1: passive probe harvest.
    if let Some(c) = harvest_via_probes(bssid, Duration::from_secs(60), &mut |c| {
        if !out.iter().any(|x| x.essid == c.essid) {
            out.push(c.clone());
        }
    }) {
        log::info!("hidden: recovered '{}' from probe requests", c.essid);
        return vec![c];
    }

    // Step 2: active deauth-to-reveal.
    if let Some(c) = reveal_via_deauth(bssid, channel, Duration::from_secs(15)) {
        log::info!("hidden: recovered '{}' from deauth-to-reveal", c.essid);
        return vec![c];
    }

    // Step 3: vendor-OUI guess (best-effort; surfaced as a guess).
    if let Some(guess) = vendor_guess(bssid) {
        log::info!("hidden: vendor-OUI guess for {bssid}: '{}'", guess.essid);
        return vec![guess];
    }

    out
}

/// Look up a vendor-OUI guess from the embedded fingerprint table.
///
/// In a production deployment this would consult a JSON file shipped under
/// `data/vendor_essids.json` (Cisco, Aruba, Ubiquiti, etc. all use
/// predictable ESSID schemes keyed on serial number). We ship a tiny
/// in-memory stub here.
fn vendor_guess(bssid: &str) -> Option<HiddenSsidCandidate> {
    let bytes = netspecter_common::crypto::parse_mac(bssid)?;
    let oui = format!(
        "{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2]
    );
    let vendor_table: &[(&str, &str)] = &[
        ("00:1a:2b", "Cisco-LAB"),       // Cisco / Linksys
        ("24:a4:3c", "Ubiquiti-"),       // Ubiquiti prefix
        ("b0:27:cf", "Aruba-"),          // Aruba Networks
        ("00:0b:86", "Aruba-"),          // Aruba legacy OUI
        ("f0:9f:c2", "TP-Link_"),        // TP-Link
    ];
    for (prefix, template) in vendor_table {
        if oui.starts_with(prefix) {
            // Add a suffix based on the last 3 bytes of the BSSID; this is
            // exactly the convention many enterprise APs use.
            let suffix = format!("{:02x}{:02x}{:02x}", bytes[3], bytes[4], bytes[5]);
            return Some(HiddenSsidCandidate {
                essid: format!("{template}{suffix}"),
                source: SsidSource::VendorGuess,
                observations: 0,
                first_seen: chrono::Utc::now().to_rfc3339(),
                leaking_client: None,
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_guess_recognises_cisco_oui() {
        let g = vendor_guess("00:1a:2b:00:11:22").unwrap();
        assert_eq!(g.essid, "Cisco-LAB001122");
        assert_eq!(g.source, SsidSource::VendorGuess);
    }

    #[test]
    fn vendor_guess_recognises_ubiquiti_oui() {
        let g = vendor_guess("24:a4:3c:de:ad:be").unwrap();
        assert_eq!(g.essid, "Ubiquiti-deadbe");
        assert_eq!(g.source, SsidSource::VendorGuess);
    }

    #[test]
    fn vendor_guess_returns_none_for_unknown_oui() {
        assert!(vendor_guess("aa:bb:cc:dd:ee:ff").is_none());
    }

    #[test]
    fn vendor_guess_rejects_malformed_mac() {
        assert!(vendor_guess("not-a-mac").is_none());
        assert!(vendor_guess("").is_none());
    }

    #[test]
    fn ssid_source_serializes_lowercase() {
        assert!(serde_json::to_string(&SsidSource::ProbeRequest).unwrap().contains("probe-request"));
        assert!(serde_json::to_string(&SsidSource::DeauthReassoc).unwrap().contains("deauth-reassoc"));
        assert!(serde_json::to_string(&SsidSource::VendorGuess).unwrap().contains("vendor-guess"));
    }
}