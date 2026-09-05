//! Per-target attackability scoring - the "where do I start" advisor.
//!
//! Pure logic over the AP snapshot: no I/O, fully unit-testable. The CLI
//! renders the score next to each target so an operator sees the ranked
//! picture before touching anything. Higher = more attack paths.

use crate::encryption::Encryption;
use crate::types::AP;
use crate::wps_default_pins::default_pin_candidates;

/// A target's attackability breakdown.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RiskScore {
    /// 0..=100 composite.
    pub score: u32,
    /// Human-readable drivers, strongest first (shown in the CLI).
    pub reasons: Vec<String>,
}

/// Score one AP. Deterministic over the AP fields; the default-PIN consult
/// is a pure table lookup.
pub fn score_ap(ap: &AP) -> RiskScore {
    let mut score = 0u32;
    let mut reasons: Vec<String> = Vec::new();
    let enc = Encryption::from_privacy_field(&ap.privacy);

    // Encryption class - the classic ladder, via the shared classifier.
    if enc == Encryption::Wep {
        score += 60;
        reasons.push("WEP - statistically cracked in minutes (PTW)".into());
    } else if enc.has_sae() && !enc.downgrade_target() {
        score += 10;
        reasons.push("WPA3-SAE - no offline path (dragonfly); downgrade only".into());
    } else if enc.has_psk() {
        score += 30;
        if enc.downgrade_target() {
            score += 10;
            reasons.push("WPA2/WPA3 transition - downgrade to WPA2 path available".into());
        }
    } else {
        // Open / OWE / unclassified.
        score += 40;
        reasons.push("open or unclassified network - capture the clients instead".into());
    }

    // WPS exposure - the instant-win multiplier (WPS is overwhelmingly a
    // WPA2-Personal feature; that's also how the wizard detects it).
    if enc.wps_eligible() {
        score += 25;
        let pins = default_pin_candidates(&ap.bssid, &ap.essid);
        let algo_hit = pins
            .iter()
            .any(|c| c.source.contains("ComputePIN") || c.source.contains("Arcadyan") || c.source.contains("kcdtv"));
        if algo_hit {
            score += 20;
            reasons.push("WPS + vendor default-PIN algorithm known (instant win likely)".into());
        } else if !pins.is_empty() {
            score += 10;
            reasons.push("WPS on - NULL/static factory PINs worth a shot".into());
        } else {
            reasons.push("WPS path - Pixie Dust / online brute".into());
        }
    }

    // Already have material? The report writes itself.
    if ap.handshake {
        score += 20;
        reasons.push("4-way handshake already captured".into());
    }
    if ap.saved_handshake.is_some() {
        score += 5;
    }

    // Hidden = free probe harvest first.
    if ap.hidden || ap.essid.is_empty() {
        score += 5;
        reasons.push("hidden SSID - recoverable via probes/deauth reveal".into());
    }

    // Clients present = deauth/handshake/evil-twin all live.
    if !ap.clients.is_empty() {
        score += 10;
        reasons.push(format!(
            "{} associated client(s) - deauth/handshake paths live",
            ap.clients.len()
        ));
    }

    score = score.min(100);
    if reasons.is_empty() {
        reasons.push("no notable exposure - manual review".into());
    }
    RiskScore { score, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn base_ap() -> AP {
        AP {
            band: "2.4".into(),
            power: "-50".into(),
            first_time_seen: String::new(),
            last_time_seen: String::new(),
            saved_handshake: None,
            clients: HashMap::new(),
            essid: "TestNet".into(),
            bssid: "C8:3A:35:12:34:56".into(),
            channel: "6".into(),
            vendor: "Test".into(),
            privacy: "WPA2".into(),
            hidden: false,
            handshake: false,
        }
    }

    #[test]
    fn wpa2_baseline_is_moderate() {
        let s = score_ap(&base_ap());
        assert!((25..=45).contains(&s.score), "score {}", s.score);
    }

    #[test]
    fn wep_scores_high_and_says_why() {
        let ap = AP { privacy: "WEP".into(), ..base_ap() };
        let s = score_ap(&ap);
        assert!(s.score >= 60, "score {}", s.score);
        assert!(s.reasons.iter().any(|r| r.contains("WEP")));
    }

    #[test]
    fn wps_with_known_pin_algorithm_is_instant_win() {
        // C8:3A:35 = the ComputePIN family, WPA2 privacy -> wps_eligible.
        let ap = AP { privacy: "WPA2".into(), ..base_ap() };
        let s = score_ap(&ap);
        assert!(s.score >= 50, "score {}", s.score);
        assert!(s.reasons.iter().any(|r| r.contains("default-PIN")));
    }

    fn client() -> crate::types::Client {
        crate::types::Client {
            mac: "AA:BB:CC:DD:EE:FF".into(),
            packets: "42".into(),
            power: "-45".into(),
            first_time_seen: String::new(),
            last_time_seen: String::new(),
            vendor: "Test".into(),
            probes: String::new(),
        }
    }

    #[test]
    fn score_never_exceeds_100() {
        let mut clients = HashMap::new();
        clients.insert("AA:BB:CC:DD:EE:FF".into(), client());
        let ap = AP {
            privacy: "WEP".into(),
            handshake: true,
            hidden: true,
            saved_handshake: Some("/tmp/x.cap".into()),
            clients,
            ..base_ap()
        };
        let s = score_ap(&ap);
        assert!(s.score <= 100);
        assert!(!s.reasons.is_empty());
    }

    #[test]
    fn clients_and_handshake_add_paths() {
        let mut clients = HashMap::new();
        clients.insert("AA:BB:CC:DD:EE:FF".into(), client());
        let ap = AP {
            handshake: true,
            clients,
            ..base_ap()
        };
        let s = score_ap(&ap);
        assert!(s.reasons.iter().any(|r| r.contains("handshake")));
        assert!(s.reasons.iter().any(|r| r.contains("client")));
    }

    #[test]
    fn hidden_essid_surfaces() {
        let ap = AP { hidden: true, ..base_ap() };
        let s = score_ap(&ap);
        assert!(s.reasons.iter().any(|r| r.contains("hidden")));
    }
}
