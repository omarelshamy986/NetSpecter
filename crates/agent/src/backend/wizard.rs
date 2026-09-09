//! Smart-wizard orchestration logic.
//!
//! The wizard walks an operator through the optimal engagement flow:
//!
//! 1. **Authorize** — confirm scope + consent + log the audit entry.
//! 2. **Scan** — find nearby APs and clients.
//! 3. **Identify** — classify encryption, decide which attacks apply.
//! 4. **Capture** — pick the cheapest viable attack; run it.
//! 5. **Crack** — hand off to hashcat / aircrack-ng / john.
//! 6. **Report** — emit HTML + PDF + JSON.
//!
//! This module owns the *decisions* — "given an AP, what's the cheapest
//! attack in scope?". The GUI owns the visual flow; it asks the agent for
//! the next step via IPC, and the agent consults this module.
//!
//! The output is a `WizardPlan` — an ordered list of `WizardStep` that
//! the GUI can render as a checklist.

use netspecter_common::encryption::Encryption;
use netspecter_common::types::*;
use serde::{Deserialize, Serialize};

/// What the wizard recommends the operator do for a single target AP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WizardPlan {
    pub bssid: String,
    pub essid: String,
    pub encryption: Encryption,
    pub steps: Vec<WizardStep>,
    pub rationale: String,
}

/// One step in the plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WizardStep {
    pub order: u8,
    pub title: String,
    pub description: String,
    pub kind: WizardStepKind,
    /// Approximate runtime in seconds, surfaced to the GUI as a progress hint.
    pub estimated_secs: u32,
    /// True if the step modifies the radio (deauth / injection / fake AP).
    pub requires_active_radio: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WizardStepKind {
    /// Passive observation only.
    PassiveScan,
    /// Active deauth / injection.
    ActiveAttack,
    /// Offline processing (PMKID crack, WEP key recovery).
    OfflineCrack,
    /// Social-engineering attack (Evil Twin / captive portal).
    SocialEngineering,
    /// Hidden-SSID recovery.
    HiddenSsidRecovery,
    /// Report generation.
    Report,
}

/// Generate the plan for an AP given its observed posture.
///
/// The rules here are the project's "best practice" defaults. An operator
/// who knows better can opt out of any step from the GUI; the wizard is a
/// suggestion, not a hard sequence.
pub fn plan_for(ap: &AP) -> WizardPlan {
    let encryption = Encryption::from_privacy_field(&ap.privacy);
    let mut steps = Vec::new();
    let mut rationale = String::new();

    // Step 0: every AP needs a passive scan first (already done by the time
    // we got here, but include it for symmetry and for log/audit clarity).
    steps.push(WizardStep {
        order: 0,
        title: "Passive scan".into(),
        description: format!(
            "Discover clients and signal strength for {} ({})",
            ap.essid, ap.bssid
        ),
        kind: WizardStepKind::PassiveScan,
        estimated_secs: 30,
        requires_active_radio: false,
    });

    // Hidden-SSID recovery, if the AP is hidden.
    if ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden") {
        steps.push(WizardStep {
            order: 1,
            title: "Hidden-SSID recovery".into(),
            description: "Recover the broadcast ESSID via probe harvest \
                         + targeted deauth-to-reveal + vendor-OUI guess"
                .into(),
            kind: WizardStepKind::HiddenSsidRecovery,
            estimated_secs: 90,
            requires_active_radio: true,
        });
        rationale.push_str("AP broadcasts no ESSID — recovery is mandatory. ");
    }

    // Encryption-specific attack selection.
    let next_order = steps.len() as u8;
    match encryption {
        Encryption::Wep => {
            rationale.push_str("WEP is broken; IVs collection leads to a guaranteed key recovery. ");
            steps.push(WizardStep {
                order: next_order,
                title: "WEP IVs collection".into(),
                description: "Run fragmentation or ARP-replay attack to force IV generation".into(),
                kind: WizardStepKind::ActiveAttack,
                estimated_secs: 600, // 10 minutes typical
                requires_active_radio: true,
            });
            steps.push(WizardStep {
                order: next_order + 1,
                title: "WEP key recovery".into(),
                description: "Offline aircrack-ng run on the IVs file".into(),
                kind: WizardStepKind::OfflineCrack,
                estimated_secs: 60,
                requires_active_radio: false,
            });
        }
        Encryption::Wpa2Psk | Encryption::Wpa3Transition => {
            // The PMKID attack is the cheapest *if* the AP supports it; the
            // classic 4-way handshake attack is the fallback.
            rationale.push_str(
                "WPA2-Personal — prefer PMKID (no client, no deauth). \
                 Fallback: 4-way handshake with deauth if no PMKID surfaces.",
            );
            steps.push(WizardStep {
                order: next_order,
                title: "PMKID harvest".into(),
                description: "Associate with the AP (no PSK) and capture EAPOL M1".into(),
                kind: WizardStepKind::ActiveAttack,
                estimated_secs: 60,
                requires_active_radio: true,
            });
            steps.push(WizardStep {
                order: next_order + 1,
                title: "PMKID crack".into(),
                description: "Hashcat -m 22000 against a wordlist".into(),
                kind: WizardStepKind::OfflineCrack,
                estimated_secs: 3600,
                requires_active_radio: false,
            });
            steps.push(WizardStep {
                order: next_order + 2,
                title: "4-way handshake capture".into(),
                description: "Deauth a connected client, capture M2 + ANonce".into(),
                kind: WizardStepKind::ActiveAttack,
                estimated_secs: 60,
                requires_active_radio: true,
            });
            steps.push(WizardStep {
                order: next_order + 3,
                title: "Handshake crack".into(),
                description: "Hashcat -m 2500 against a wordlist".into(),
                kind: WizardStepKind::OfflineCrack,
                estimated_secs: 3600,
                requires_active_radio: false,
            });
        }
        Encryption::Wpa => {
            rationale.push_str("WPA (TKIP) — Beck-Tews / Ohigashi-Morii attacks are in scope.");
            steps.push(WizardStep {
                order: next_order,
                title: "WPA TKIP attack".into(),
                description: "Beck-Tews keystream recovery or chop-chop on TKIP".into(),
                kind: WizardStepKind::ActiveAttack,
                estimated_secs: 900,
                requires_active_radio: true,
            });
        }
        Encryption::Wpa3Sae => {
            rationale.push_str(
                "WPA3-SAE only — not in scope for offline PSK recovery. \
                 Try the dragonblood side-channel scan if the operator opts in.",
            );
            steps.push(WizardStep {
                order: next_order,
                title: "Dragonblood side-channel scan".into(),
                description: "Optional: timing side-channel against the SAE implementation".into(),
                kind: WizardStepKind::ActiveAttack,
                estimated_secs: 3600,
                requires_active_radio: true,
            });
        }
        Encryption::Wpa3Enterprise | Encryption::Wpa2Enterprise => {
            rationale.push_str("Enterprise — out of scope for PSK attacks.");
        }
        Encryption::Open | Encryption::Owe => {
            rationale.push_str(
                "Open / OWE — no encryption key to recover; the finding is \
                 the absence of authentication, captured in the report.",
            );
        }
        Encryption::Unknown => {
            rationale.push_str("Encryption class could not be determined; manual review required.");
        }
    }

    // WPS step (only if the encryption class is WPS-eligible).
    if encryption.wps_eligible() {
        let next_order = steps.len() as u8;
        steps.push(WizardStep {
            order: next_order,
            title: "WPS Pixie Dust".into(),
            description: "Cheap offline PIN recovery via weak PRNG".into(),
            kind: WizardStepKind::ActiveAttack,
            estimated_secs: 30,
            requires_active_radio: true,
        });
        steps.push(WizardStep {
            order: next_order + 1,
            title: "WPS online brute (fallback)".into(),
            description: "Reaver / Bully PIN enumeration".into(),
            kind: WizardStepKind::ActiveAttack,
            estimated_secs: 14400, // 4 hours
            requires_active_radio: true,
        });
    }

    // Evil-Twin as a social-engineering fallback for PSK networks.
    if encryption.psk_attackable() {
        let next_order = steps.len() as u8;
        steps.push(WizardStep {
            order: next_order,
            title: "Evil-Twin (social engineering)".into(),
            description: "Fake AP + captive portal asking for the WiFi password".into(),
            kind: WizardStepKind::SocialEngineering,
            estimated_secs: 3600,
            requires_active_radio: true,
        });
    }

    // Report.
    let next_order = steps.len() as u8;
    steps.push(WizardStep {
        order: next_order,
        title: "Generate report".into(),
        description: "HTML + PDF + JSON report".into(),
        kind: WizardStepKind::Report,
        estimated_secs: 30,
        requires_active_radio: false,
    });

    WizardPlan {
        bssid: ap.bssid.clone(),
        essid: ap.essid.clone(),
        encryption,
        steps,
        rationale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(privacy: &str, hidden: bool) -> AP {
        AP {
            essid: if hidden { "<hidden>".into() } else { "Net".into() },
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            band: "2.4".into(),
            channel: "6".into(),
            power: "-50".into(),
            privacy: privacy.into(),
            hidden,
            handshake: false,
            saved_handshake: None,
            first_time_seen: "2026-01-01T00:00:00Z".into(),
            last_time_seen: "2026-01-01T00:00:00Z".into(),
            clients: Default::default(),
        }
    }

    #[test]
    fn plan_for_wpa2_psk_includes_pmkid_and_handshake() {
        let p = plan_for(&ap("WPA2", false));
        assert!(p.steps.iter().any(|s| matches!(s.kind, WizardStepKind::ActiveAttack) && s.title.contains("PMKID")));
        assert!(p.steps.iter().any(|s| matches!(s.kind, WizardStepKind::OfflineCrack) && s.title.contains("crack")));
        assert!(p.rationale.contains("PMKID"));
    }

    #[test]
    fn plan_for_wep_includes_ivs_and_recovery() {
        let p = plan_for(&ap("WEP", false));
        assert!(p.steps.iter().any(|s| s.title.contains("IVs")));
        assert!(p.steps.iter().any(|s| s.title.contains("recovery")));
    }

    #[test]
    fn plan_for_wpa3_sae_only_includes_dragonblood() {
        let p = plan_for(&ap("WPA3", false));
        assert!(p.steps.iter().any(|s| s.title.contains("Dragonblood")));
        assert!(!p.steps.iter().any(|s| s.title.contains("PMKID")));
    }

    #[test]
    fn plan_for_wpa3_transition_includes_pmkid() {
        let p = plan_for(&ap("WPA3/WPA2", false));
        assert!(p.steps.iter().any(|s| s.title.contains("PMKID")));
    }

    #[test]
    fn plan_for_hidden_ap_includes_hidden_recovery() {
        let p = plan_for(&ap("WPA2", true));
        assert!(p.steps.iter().any(|s| matches!(s.kind, WizardStepKind::HiddenSsidRecovery)));
    }

    #[test]
    fn plan_for_enterprise_skips_psk_attacks() {
        let p = plan_for(&ap("WPA2-ENT", false));
        assert!(p.rationale.contains("out of scope"));
        assert!(!p.steps.iter().any(|s| s.title.contains("PMKID")));
    }

    #[test]
    fn plan_includes_wps_for_wpa2() {
        let p = plan_for(&ap("WPA2", false));
        assert!(p.steps.iter().any(|s| s.title.contains("Pixie Dust")));
    }

    #[test]
    fn plan_includes_evil_twin_for_psk_networks() {
        let p = plan_for(&ap("WPA2", false));
        assert!(p.steps.iter().any(|s| matches!(s.kind, WizardStepKind::SocialEngineering)));
    }

    #[test]
    fn steps_are_in_order() {
        let p = plan_for(&ap("WPA2", false));
        for (i, s) in p.steps.iter().enumerate() {
            assert_eq!(s.order as usize, i);
        }
    }
}