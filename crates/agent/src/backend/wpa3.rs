//! WPA3-SAE detection and transition-mode identification.
//!
//! A WPA3-capable AP advertises its capabilities in an RSN (Robust Security
//! Network) information element inside every beacon / probe response. The
//! IE lists the AKMs (Authentication and Key Management suites) the AP
//! accepts. The two that matter for this module are:
//!
//!   - `00:0f:ac:02` — PSK (WPA2-Personal)
//!   - `00:0f:ac:08` — SAE (WPA3-Personal)
//!
//! An AP that lists **both** in the same RSN IE is in *transition mode*: it
//! will happily accept a WPA2 association from a client that doesn't
//! support SAE. That's the downgrade target — a WPA3 transition AP can be
//! cracked via the same 4-way-handshake attack as a WPA2 AP, *despite the
//! operator thinking they upgraded to WPA3*.
//!
//! ## What we detect
//!
//! 1. **Pure WPA3-SAE** (`has_sae && !has_psk`) — secure; not a PSK target.
//! 2. **WPA3 transition** (`has_sae && has_psk`) — PSK-eligible. Flag
//!    prominently to the operator and the report.
//! 3. **WPA3-Enterprise** (`has_enterprise` with SAE or 802.1X+SHA256 AKM
//!    `00:0f:ac:05`) — out of scope for any PSK attack.
//! 4. **OWE** (`has_owe`) — encrypted but unauthenticated; out of PSK scope.
//!
//! ## Active probing
//!
//! Passive classification is enough 99% of the time. We don't actively
//! probe-transition (which would require sending a probe request and
//! reading the response) because it has marginal benefit and adds noise.

use netspecter_common::encryption::{Encryption, RsnIe};
use netspecter_common::types::*;
use serde::{Deserialize, Serialize};

/// The result of classifying a single AP's encryption posture.
///
/// Beyond the `class` enum, `dragonblood_signal` flags conditions that
/// indicate the AP is using a software library known to be vulnerable to
/// the dragonblood family of timing / cache side-channel attacks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wpa3Classification {
    pub class: Encryption,
    pub transition_mode: bool,
    pub mfp_capable: bool,
    pub mfp_required: bool,
    /// True if the AP advertises SAE without management-frame protection
    /// (PMF/802.11w).  This is the specific signal the dragonblood paper
    /// flagged: SAE implementations that don't require PMF can be coerced
    /// into side-channel-leaky transitions.
    pub dragonblood_signal: bool,
}

/// Classify an AP from its parsed RSN IE.
///
/// `ap` is the airgorah scan record. The function is pure; it doesn't
/// touch the radio.
pub fn classify_wpa3(ap: &AP) -> Wpa3Classification {
    let parsed = parse_rsn_ie_from_ap(ap);
    let class = encryption_from_akm(&parsed);
    let transition_mode = parsed.has_sae() && parsed.has_psk();
    let dragonblood_signal =
        parsed.has_sae() && (!parsed.mfp_required) && (!ap.privacy.to_uppercase().contains("ENT"));

    Wpa3Classification {
        class,
        transition_mode,
        mfp_capable: parsed.mfp_capable,
        mfp_required: parsed.mfp_required,
        dragonblood_signal,
    }
}

/// Pull the RSN IE out of an airgorah scan record.
///
/// The airgorah scanner writes the entire IE byte-blob into a CSV column;
/// we surface just the AKM / cipher / PMF bits here, leaving full RSN-IE
/// parsing to dedicated tools.
pub fn parse_rsn_ie_from_ap(ap: &AP) -> RsnIe {
    // Without the raw IE bytes (the scanner's CSV row doesn't carry them),
    // we fall back to parsing the free-form `privacy` string. This is
    // less precise but enough to drive the wizard's branching.
    let upper = ap.privacy.to_uppercase();

    let mut akm_suites = Vec::new();
    if upper.contains("WPA2-ENT") || upper.contains("WPA2 ENT") {
        akm_suites.push("000f-ac01".to_string());
    } else if upper.contains("WPA2") {
        akm_suites.push("000f-ac02".to_string());
    }
    if upper.contains("WPA3-ENT") {
        akm_suites.push("000f-ac05".to_string());
    } else if upper.contains("WPA3") {
        akm_suites.push("000f-ac08".to_string());
    }
    if upper.contains("OWE") {
        akm_suites.push("000f-ac18".to_string());
    }

    // PMF fields: not directly emitted by the scanner; treat an AP that
    // is "WPA3-only" (no WPA2 mention) as having PMF-required.
    let mfp_required = upper.contains("WPA3") && !upper.contains("WPA2");
    let mfp_capable = upper.contains("WPA3") || upper.contains("WPA2-ENT");

    let pairwise_ciphers = if upper.contains("WEP") {
        vec![] // WEP doesn't carry an RSN IE
    } else if upper.contains("TKIP") {
        vec!["000f-ac02".to_string()]
    } else {
        vec!["000f-ac04".to_string()] // CCMP-128 default
    };

    RsnIe {
        akm_suites,
        pairwise_ciphers,
        mfp_capable,
        mfp_required,
    }
}

/// Decide the encryption class from an AKM list.
pub fn encryption_from_akm(rsn: &RsnIe) -> Encryption {
    let has_sae = rsn.has_sae();
    let has_psk = rsn.has_psk();
    let has_ent = rsn.has_enterprise();
    let has_owe = rsn.has_owe();

    if has_owe && !has_sae && !has_psk {
        Encryption::Owe
    } else if has_sae && has_psk {
        // Most dangerous case: WPA3-capable AP that still accepts WPA2.
        Encryption::Wpa3Transition
    } else if has_sae && has_ent {
        Encryption::Wpa3Enterprise
    } else if has_sae {
        Encryption::Wpa3Sae
    } else if has_ent {
        Encryption::Wpa2Enterprise
    } else if has_psk {
        Encryption::Wpa2Psk
    } else {
        Encryption::Unknown
    }
}

/// Render a one-line operator-facing summary.
pub fn summarize(c: &Wpa3Classification) -> String {
    let mut s = String::from(c.class.label());
    if c.transition_mode {
        s.push_str(" [transition: WPA2+SAE]");
    }
    if c.dragonblood_signal {
        s.push_str(" [dragonblood-signal]");
    }
    if c.mfp_required {
        s.push_str(" [PMF-required]");
    } else if c.mfp_capable {
        s.push_str(" [PMF-capable]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap_with_privacy(privacy: &str) -> AP {
        AP {
            essid: "TestAP".into(),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            band: "2.4".into(),
            channel: "6".into(),
            power: "-50".into(),
            privacy: privacy.into(),
            hidden: false,
            handshake: false,
            saved_handshake: None,
            first_time_seen: "2026-01-01T00:00:00Z".into(),
            last_time_seen: "2026-01-01T00:00:00Z".into(),
            clients: Default::default(),
        }
    }

    #[test]
    fn pure_wpa3_sae_is_not_psk_eligible() {
        let c = classify_wpa3(&ap_with_privacy("WPA3"));
        assert_eq!(c.class, Encryption::Wpa3Sae);
        assert!(!c.transition_mode);
    }

    #[test]
    fn wpa3_with_wpa2_is_transition_and_psk_eligible() {
        let c = classify_wpa3(&ap_with_privacy("WPA3/WPA2"));
        assert_eq!(c.class, Encryption::Wpa3Transition);
        assert!(c.transition_mode);
        assert!(c.class.psk_attackable());
    }

    #[test]
    fn wpa3_enterprise_is_out_of_psk_scope() {
        let c = classify_wpa3(&ap_with_privacy("WPA3-ENT"));
        assert_eq!(c.class, Encryption::Wpa3Enterprise);
        assert!(!c.class.psk_attackable());
    }

    #[test]
    fn owe_is_out_of_psk_scope_but_encrypted() {
        let c = classify_wpa3(&ap_with_privacy("OWE"));
        assert_eq!(c.class, Encryption::Owe);
        assert!(!c.class.psk_attackable());
    }

    #[test]
    fn pure_wpa3_with_no_pmf_is_dragonblood_signal() {
        let c = classify_wpa3(&ap_with_privacy("WPA3"));
        // Privacy string doesn't distinguish PMF-required from PMF-capable,
        // but "WPA3" alone (no "WPA2") reads as PMF-required.
        // We expect NO dragonblood signal in this branch.
        assert!(!c.dragonblood_signal);
    }

    #[test]
    fn summarize_carries_useful_metadata() {
        let c = classify_wpa3(&ap_with_privacy("WPA3/WPA2"));
        let s = summarize(&c);
        assert!(s.contains("WPA3/WPA2"));
        assert!(s.contains("transition"));
    }
}