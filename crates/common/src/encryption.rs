//! Encryption-class identifiers and metadata for discovered access points.
//!
//! [`Encryption`] is the operator-facing enum a [`crate::types::AP`] carries; it
//! classifies the AP into one of the well-known security profiles and is
//! consulted by every attack module to decide whether the target is in scope.
//!
//! The "detected" variants (e.g. [`Encryption::Wpa3Transition`]) describe a
//! observed *behavior* (here, a WPA3-SAE AP that still accepts WPA2
//! associations), not a configuration bit, so the agent classifies them from
//! observed frames rather than the AP's claimed AKM suites.

use serde::{Deserialize, Serialize};

/// How the AP secures its traffic, as observed by the agent.
///
/// Every variant is reachable from a single passive capture; [`Encryption::Unknown`]
/// is the catch-all for frames that look encrypted but cannot be classified
/// (most often: an 802.11w / PMF-protected management frame).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encryption {
    /// Open network — no encryption.
    Open,
    /// WEP — broken since 2004; collected as IVs for offline cracking.
    Wep,
    /// WPA-Personal (TKIP) — legacy, susceptible to Beck-Tews / Ohigashi-Morii.
    Wpa,
    /// WPA2-Personal (CCMP/AES) — current default; 4-way handshake subject to
    /// offline dictionary attack once M2 + ANonce are captured.
    Wpa2Psk,
    /// WPA2-Enterprise (802.1X) — AP requires an EAP exchange; in scope for
    /// client-side attacks, not PSK capture.
    Wpa2Enterprise,
    /// WPA3-SAE only — AP only accepts SAE associations. Out of scope for
    /// offline PSK attacks; relevant for transition-mode downgrade probes.
    Wpa3Sae,
    /// WPA3-SAE AP that ALSO accepts WPA2 associations. This is the dragonblood
    /// downgrade target — a WPA2 client can be forced onto it and the WPA2
    /// handshake is then captured.
    Wpa3Transition,
    /// WPA3-Enterprise (192-bit) — out of scope for any PSK-style attack.
    Wpa3Enterprise,
    /// OWE (Opportunistic Wireless Encryption) — RFC 8110. Encryption is enabled
    /// but without authentication; relevant for visibility, not credential attack.
    Owe,
    /// Captured an RSN/WPA IE we couldn't classify (e.g. vendor-private AKM).
    Unknown,
}

impl Encryption {
    /// Short, scan-list-friendly label for this encryption class.
    pub fn label(&self) -> &'static str {
        match self {
            Encryption::Open => "OPN",
            Encryption::Wep => "WEP",
            Encryption::Wpa => "WPA",
            Encryption::Wpa2Psk => "WPA2",
            Encryption::Wpa2Enterprise => "WPA2-ENT",
            Encryption::Wpa3Sae => "WPA3",
            Encryption::Wpa3Transition => "WPA3/WPA2",
            Encryption::Wpa3Enterprise => "WPA3-ENT",
            Encryption::Owe => "OWE",
            Encryption::Unknown => "?",
        }
    }

    /// Is this encryption class in scope for an offline PSK attack?
    ///
    /// Drives the Smart-Wizard's "best attack" decision.
    pub fn psk_attackable(&self) -> bool {
        matches!(
            self,
            Encryption::Wpa2Psk | Encryption::Wpa3Transition
        )
    }

    /// Is this encryption class in scope for a PMKID capture?
    pub fn pmkid_eligible(&self) -> bool {
        matches!(
            self,
            Encryption::Wpa2Psk | Encryption::Wpa3Transition
        )
    }

    /// Is this encryption class WEP (and therefore IVs-collection eligible)?
    pub fn wep_ivs_eligible(&self) -> bool {
        matches!(self, Encryption::Wep)
    }

    /// Is this encryption class likely to expose WPS (Pixie Dust, Reaver)?
    pub fn wps_eligible(&self) -> bool {
        // WPS is configured independently of encryption; the heuristic we use is
        // that WPS is most commonly seen alongside WPA2-Personal / WPA / WPA2-ENT,
        // but it has historically been present on open networks too.
        !matches!(self, Encryption::Wpa3Sae | Encryption::Wpa3Enterprise)
    }

    /// Is this AP a downgrade target (WPA3-SAE with WPA2 fallback)?
    pub fn downgrade_target(&self) -> bool {
        matches!(self, Encryption::Wpa3Transition)
    }
}

impl Default for Encryption {
    fn default() -> Self {
        Encryption::Unknown
    }
}

/// The result of classifying a single AP, with the supporting evidence.
///
/// The agent fills this in once during scan; later modules (PMKID capture,
/// WPS probes, evil-twin) read it without re-classifying.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionProfile {
    /// The classified encryption class.
    pub class: Encryption,

    /// RSN information element if seen in the beacon / probe response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsn_ie: Option<RsnIe>,

    /// True if the AP advertises a WPA3 transition mode (both SAE and PSK in
    /// the same beacon). `false` if the AP is purely WPA3-SAE.
    pub transition_mode: bool,

    /// Whether the beacon / probe response includes a WPS IE (vendor-extended).
    pub wps_advertised: bool,

    /// First time the agent observed this profile.
    pub first_seen: String,
}

/// A parsed RSN / WPA information element, surfaced to the GUI for visibility.
///
/// Only the fields the agent needs to make attack-selection decisions are
/// surfaced here — full RSN IE parsing is intentionally minimal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RsnIe {
    /// AKM suites present in the IE, as 4-byte OUI/type pairs encoded as
    /// 8-character hex strings (e.g. `"000f-ac02"` for PSK, `"000f-ac08"` for
    /// SAE, `"000f-ac01"` for 802.1X).
    pub akm_suites: Vec<String>,
    /// Pairwise cipher suites present, encoded the same way.
    pub pairwise_ciphers: Vec<String>,
    /// True if the IE indicates management-frame protection (802.11w / PMF).
    pub mfp_capable: bool,
    /// True if the IE mandates management-frame protection.
    pub mfp_required: bool,
}

impl RsnIe {
    /// True if the IE advertises SAE (WPA3-Personal).
    pub fn has_sae(&self) -> bool {
        self.akm_suites.iter().any(|s| s == "000f-ac08")
    }

    /// True if the IE advertises PSK (WPA2-Personal).
    pub fn has_psk(&self) -> bool {
        self.akm_suites.iter().any(|s| s == "000f-ac02")
    }

    /// True if the IE advertises 802.1X (Enterprise).
    pub fn has_enterprise(&self) -> bool {
        self.akm_suites
            .iter()
            .any(|s| s == "000f-ac01" || s == "000f-ac05")
    }

    /// True if the IE indicates an "OWE only" AP (RFC 8110).
    pub fn has_owe(&self) -> bool {
        self.akm_suites.iter().any(|s| s == "000f-ac18")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_match_canonical_wifi_scanner_short_names() {
        assert_eq!(Encryption::Open.label(), "OPN");
        assert_eq!(Encryption::Wpa2Psk.label(), "WPA2");
        assert_eq!(Encryption::Wpa3Sae.label(), "WPA3");
        assert_eq!(Encryption::Wpa3Transition.label(), "WPA3/WPA2");
    }

    #[test]
    fn psk_attack_targets_only_include_wpa2_psk_and_transition() {
        assert!(Encryption::Wpa2Psk.psk_attackable());
        assert!(Encryption::Wpa3Transition.psk_attackable());
        assert!(!Encryption::Wpa3Sae.psk_attackable());
        assert!(!Encryption::Wep.psk_attackable());
        assert!(!Encryption::Open.psk_attackable());
        assert!(!Encryption::Wpa3Enterprise.psk_attackable());
    }

    #[test]
    fn wpa3_sae_is_not_wps_eligible_but_transition_is() {
        assert!(!Encryption::Wpa3Sae.wps_eligible());
        assert!(Encryption::Wpa3Transition.wps_eligible());
        assert!(Encryption::Wpa2Psk.wps_eligible());
    }

    #[test]
    fn wep_ivs_only_target_wep_aps() {
        assert!(Encryption::Wep.wep_ivs_eligible());
        assert!(!Encryption::Wpa2Psk.wep_ivs_eligible());
        assert!(!Encryption::Open.wep_ivs_eligible());
    }

    #[test]
    fn rsn_ie_akm_helpers_detect_sae_psk_and_enterprise() {
        let rsn = RsnIe {
            akm_suites: vec!["000f-ac02".to_string(), "000f-ac08".to_string()],
            pairwise_ciphers: vec!["000f-ac04".to_string()],
            mfp_capable: true,
            mfp_required: true,
        };
        assert!(rsn.has_psk());
        assert!(rsn.has_sae());
        assert!(!rsn.has_enterprise());

        let ent = RsnIe {
            akm_suites: vec!["000f-ac01".to_string()],
            ..rsn.clone()
        };
        assert!(ent.has_enterprise());
        assert!(!ent.has_sae());

        let owe = RsnIe {
            akm_suites: vec!["000f-ac18".to_string()],
            ..rsn.clone()
        };
        assert!(owe.has_owe());
    }
}