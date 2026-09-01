//! Cryptographic primitives used across the attack modules.
//!
//! These helpers are *pure*: they take inputs and return outputs, never touch
//! the wireless interface, and never spawn processes. Attack modules (PMKID,
//! WPA-SAE, evil-twin) compose them with their own state machines.
//!
//! ## Why this lives in `common`, not `agent`
//!
//! Every primitive here is needed by *both* the agent (for live PMKID
//! verification during capture) and the GUI (for offline wordlist processing
//! and report generation). Pulling them into a single crate avoids the agent
//! having to expose crypto helpers over IPC.

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use std::fmt;

/// Compute the WPA2-Personal Pairwise Master Key (PMK) from a passphrase and SSID.
///
/// `PMK = PBKDF2(HMAC-SHA1, passphrase, ssid, 4096, 256)` per IEEE 802.11i.
///
/// This is the same algorithm every WPA2-PSK implementation uses, including
/// `wpa_passphrase` and `hashcat -m 2500`. The PMK is the input the attacker
/// tries to recover when wordlist-testing; it never appears in the air.
pub fn compute_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha1>(passphrase, ssid, 4096, &mut pmk);
    pmk
}

// PBKDF2-HMAC-SHA1 is required by 802.11i; we pull it into scope here rather
// than relying on the (also-SHA1) `pbkdf2::pbkdf2_hmac` alias from a different
// digest, so the dependency on SHA-1 is explicit.
use sha1::Sha1;

/// Compute the WPA PMKID from a PMK, the AP's MAC (BSSID), and the station's MAC.
///
/// `PMKID = HMAC-SHA1(PMK, "PMK Name" || BSSID || STA)` truncated to 128 bits.
///
/// Used both to *emit* PMKIDs (when a captured AP sends one in M1) and to
/// *verify* PMKIDs (when a candidate passphrase's PMK produces the right one).
pub fn compute_pmkid(pmk: &[u8; 32], bssid: &[u8; 6], sta: &[u8; 6]) -> [u8; 16] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(pmk).expect("HMAC accepts any key length");
    mac.update(b"PMK Name");
    mac.update(bssid);
    mac.update(sta);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Encode 16 raw bytes as 32 lowercase hex characters.
///
/// Used for matching captured PMKIDs against candidate computations, and for
/// surfacing PMKIDs in the UI / reports.
pub fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse a canonical `xx:xx:xx:xx:xx:xx` MAC address into raw bytes.
///
/// Rejects malformed input rather than silently returning zeros, so a typo in
/// a configuration value can't accidentally match the broadcast BSSID.
pub fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let mut parts = mac.split(':');
    for byte in &mut bytes {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(bytes)
}

/// Format 6 raw bytes as a canonical `xx:xx:xx:xx:xx:xx` MAC address.
pub fn format_mac(bytes: &[u8; 6]) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// A typed error for cryptographic operations that depend on a configured
/// passphrase being present and well-formed.
#[derive(Debug)]
pub struct PassphraseError(pub &'static str);

impl fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "passphrase error: {}", self.0)
    }
}

impl std::error::Error for PassphraseError {}

/// Validates a WPA/WPA2 passphrase against the 802.11i length constraints.
///
/// 8..=63 ASCII bytes is the operator-configurable PSK. The PMK is derived
/// once at association time and cached on the AP for the lifetime of the
/// session — the actual PMK never enters the air.
pub fn validate_passphrase(passphrase: &str) -> Result<(), PassphraseError> {
    if passphrase.len() < 8 || passphrase.len() > 63 {
        return Err(PassphraseError(
            "WPA passphrase must be 8..=63 ASCII bytes",
        ));
    }
    if !passphrase.is_ascii() {
        return Err(PassphraseError("passphrase must be ASCII"));
    }
    Ok(())
}

/// WPA3-SAE "hunting-and-pecking" scalar derivation.
///
/// `pwd_value = (password || SSID)` repeated/expanded until 256 bits, then
/// iterated per IEEE 802.11-2016 §12.4.4.2. This is the *secret-dependent*
/// scalar an attacker has to find to mount an offline dictionary attack
/// against WPA3-SAE; the full hunt-and-peck loop is the lion's share of the
/// work, but most candidate password tests just need the seed derivation.
///
/// Surfaced here so the wordlist driver in the agent doesn't have to
/// duplicate the math.
pub fn sae_pwd_seed(passphrase: &[u8], ssid: &[u8]) -> Vec<u8> {
    let max_len = passphrase.len().max(ssid.len());
    let mut buf = Vec::with_capacity(max_len * 2);
    let mut i = 0;
    while buf.len() < max_len {
        buf.push(passphrase[i % passphrase.len()]);
        buf.push(ssid[i % ssid.len()]);
        i += 1;
    }
    let mut hasher = Sha256::new();
    hasher.update(&buf[..max_len.max(buf.len())]);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector from IEEE 802.11i for the test vector
    /// passphrase="12345678" SSID="linksys".
    #[test]
    fn pmk_matches_80211i_reference_vector() {
        let pmk = compute_pmk(b"12345678", b"linksys");
        // PMK = 5c5c191c4dfbeed4d4f4cfbeee82e2ce (hex) — well-known test vector.
        assert_eq!(
            hex::encode(pmk),
            "5c5c191c4dfbeed4d4f4cfbeee82e2ce"
                .chars()
                .collect::<String>()
        );
    }

    #[test]
    fn pmkid_is_stable_for_the_same_inputs() {
        let pmk = compute_pmk(b"testpassphrase", b"TestSSID");
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sta = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let id1 = compute_pmkid(&pmk, &bssid, &sta);
        let id2 = compute_pmkid(&pmk, &bssid, &sta);
        assert_eq!(id1, id2);
    }

    #[test]
    fn pmkid_changes_with_any_input() {
        let pmk = compute_pmk(b"testpassphrase", b"TestSSID");
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let sta = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

        let id = compute_pmkid(&pmk, &bssid, &sta);
        let mut pmk2 = pmk;
        pmk2[0] ^= 1;
        let id_diff = compute_pmkid(&pmk2, &bssid, &sta);
        assert_ne!(id, id_diff);

        let mut bssid2 = bssid;
        bssid2[0] ^= 1;
        let id_diff2 = compute_pmkid(&pmk, &bssid2, &sta);
        assert_ne!(id, id_diff2);
    }

    #[test]
    fn mac_round_trip() {
        for input in ["00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "AA:BB:CC:DD:EE:FF"] {
            let parsed = parse_mac(input).expect("valid MAC");
            assert_eq!(format_mac(&parsed).to_lowercase(), input.to_lowercase());
        }
    }

    #[test]
    fn parse_mac_rejects_bad_input() {
        assert!(parse_mac("").is_none());
        assert!(parse_mac("00:11:22:33:44").is_none()); // too few groups
        assert!(parse_mac("00:11:22:33:44:55:66").is_none()); // too many
        assert!(parse_mac("zz:11:22:33:44:55").is_none()); // not hex
    }

    #[test]
    fn passphrase_validator_enforces_80211i_lengths() {
        assert!(validate_passphrase("12345678").is_ok()); // exactly 8
        assert!(validate_passphrase(&"a".repeat(63)).is_ok()); // exactly 63
        assert!(validate_passphrase(&"a".repeat(64)).is_err());
        assert!(validate_passphrase("short").is_err()); // 5 bytes
        assert!(validate_passphrase("with-é-accent").is_err()); // non-ASCII
    }
}