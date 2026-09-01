//! NetSpecter backend types — the IPC-visible types the GUI and agent
//! share. These types live in `common` (rather than in the agent module
//! tree) so the GUI can name them without depending on the agent crate.
//!
//! The agent-side definitions (the "canonical" sources) live in their
//! respective modules: `agent/src/backend/{pmkid,wizard,hidden,
//! evil_twin,consent,report}.rs`. We shadow them here for the wire.

use serde::{Deserialize, Serialize};

// ──────────────────────── PMKID ────────────────────────

/// A captured PMKID, ready for offline cracking.
///
/// Mirrors `airgorah_agent::backend::pmkid::PmkidCapture`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PmkidCapture {
    pub bssid: String,
    pub station: String,
    pub essid: String,
    pub pmkid_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_path: Option<String>,
    pub captured_at: String,
}

// ──────────────────────── Hidden SSID ────────────────────────

/// Source of a recovered hidden-SSID candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SsidSource {
    ProbeRequest,
    DeauthReassoc,
    ProbeResponse,
    VendorGuess,
}

/// A candidate ESSID for a hidden AP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HiddenSsidCandidate {
    pub essid: String,
    pub source: SsidSource,
    pub observations: u32,
    pub first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaking_client: Option<String>,
}

// ──────────────────────── Evil Twin ────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvilTwinConfig {
    pub iface: String,
    pub ssid: String,
    pub bssid: String,
    pub channel: u8,
    pub portal_template: String,
    pub nat: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub submitted_at: String,
    pub client_mac: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvilTwinSession {
    pub config: EvilTwinConfig,
    pub portal_url: String,
    pub credentials: Vec<CapturedCredential>,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostapd_pid: Option<u32>,
}

// ──────────────────────── Wizard ────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WizardStepKind {
    PassiveScan,
    ActiveAttack,
    OfflineCrack,
    SocialEngineering,
    HiddenSsidRecovery,
    Report,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WizardStep {
    pub order: u8,
    pub title: String,
    pub description: String,
    pub kind: WizardStepKind,
    pub estimated_secs: u32,
    pub requires_active_radio: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WizardPlan {
    pub bssid: String,
    pub essid: String,
    /// Encryption class label (string form for serialization round-trip).
    pub encryption_label: String,
    pub steps: Vec<WizardStep>,
    pub rationale: String,
}

// ──────────────────────── Consent ────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub operator: String,
    pub scope: String,
    pub rules_of_engagement: String,
    pub agreed_at: String,
    pub record_digest: String,
}

// ──────────────────────── Report ────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetReport {
    pub bssid: String,
    pub essid: String,
    pub encryption: String,
    pub channel: String,
    pub clients_observed: u32,
    pub handshake_captured: bool,
    pub pmkid_captured: bool,
    pub wps_recovered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_recovery: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmkid_capture_round_trips() {
        let p = PmkidCapture {
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            station: "11:22:33:44:55:66".into(),
            essid: "TestNet".into(),
            pmkid_hex: "00112233445566778899aabbccddeeff".into(),
            capture_path: Some("/tmp/cap.pcap".into()),
            captured_at: "2026-01-01T00:00:00Z".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        let back: PmkidCapture = serde_json::from_str(&j).unwrap();
        assert_eq!(back.essid, "TestNet");
        assert_eq!(back.pmkid_hex.len(), 32);
    }

    #[test]
    fn wizard_step_kind_serializes_lowercase() {
        assert!(serde_json::to_string(&WizardStepKind::PassiveScan).unwrap().contains("passive-scan"));
        assert!(serde_json::to_string(&WizardStepKind::ActiveAttack).unwrap().contains("active-attack"));
        assert!(serde_json::to_string(&WizardStepKind::OfflineCrack).unwrap().contains("offline-crack"));
        assert!(serde_json::to_string(&WizardStepKind::SocialEngineering).unwrap().contains("social-engineering"));
        assert!(serde_json::to_string(&WizardStepKind::HiddenSsidRecovery).unwrap().contains("hidden-ssid-recovery"));
        assert!(serde_json::to_string(&WizardStepKind::Report).unwrap().contains("report"));
    }

    #[test]
    fn evil_twin_config_round_trips() {
        let c = EvilTwinConfig {
            iface: "wlan1".into(),
            ssid: "Free-WiFi".into(),
            bssid: String::new(),
            channel: 6,
            portal_template: "templates/portal-router.html".into(),
            nat: true,
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: EvilTwinConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.ssid, "Free-WiFi");
        assert_eq!(back.channel, 6);
    }

    #[test]
    fn target_report_skips_none_optional_fields() {
        let t = TargetReport {
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            essid: "Test".into(),
            encryption: "WPA2".into(),
            channel: "6".into(),
            clients_observed: 0,
            handshake_captured: false,
            pmkid_captured: false,
            wps_recovered: false,
            hidden_recovery: None,
        };
        let j = serde_json::to_string(&t).unwrap();
        assert!(!j.contains("hidden_recovery")); // skipped via Option
    }

    #[test]
    fn consent_record_round_trips() {
        let c = ConsentRecord {
            operator: "abdo".into(),
            scope: "essid:Office".into(),
            rules_of_engagement: "ROE-001".into(),
            agreed_at: "2026-01-01T00:00:00Z".into(),
            record_digest: "abcd".into(),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: ConsentRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back.operator, "abdo");
    }
}