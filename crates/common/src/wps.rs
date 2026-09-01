//! WPS-related types shared across the IPC boundary.
//!
//! The agent parses WPS IEs out of beacon frames and reports the recovered
//! data to the GUI; the GUI uses the data to drive the wizard's
//! "best attack" selection.

use serde::{Deserialize, Serialize};

/// The WPS configuration advertised by an access point.
///
/// `version` is the WPS spec version (typically 2.0). `state` reports
/// whether WPS is currently `Configured` (a client has registered) or
/// `Not Configured` (factory default, the dangerous state for an AP).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WpsConfig {
    pub version: u8,
    pub state: WpsState,
    pub locked: bool,
    /// True if the AP advertises the WPS PIN method (most do).
    pub pin_method: bool,
    /// True if the AP advertises the WPS PBC (push-button) method.
    pub pbc_method: bool,
    /// Manufacturer string from the WPS IE.
    pub manufacturer: String,
    /// Model string from the WPS IE.
    pub model: String,
    /// Model number from the WPS IE.
    pub model_number: String,
    /// Device name from the WPS IE.
    pub device_name: String,
}

/// Whether an AP has been "configured" via WPS yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WpsState {
    /// Factory default — WPS PIN is the only path into the network.
    NotConfigured,
    /// A client has registered and the PIN has been changed.
    Configured,
}

/// Result of a WPS attack — see `wps::WpsResult` for the agent-side
/// record; this is the subset that crosses the IPC boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WpsOutcome {
    pub bssid: String,
    pub pin: Option<String>,
    pub psk: Option<String>,
    pub method: WpsAttackMethod,
    pub duration_secs: u64,
    pub status: String,
}

/// How the WPS PIN was recovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WpsAttackMethod {
    /// Pixie Dust — offline cryptographic recovery from a weak PRNG.
    PixieDust,
    /// Online brute — Reaver / Bully enumerated the PIN space.
    OnlineBrute,
    /// Historical `00000000` NULL PIN accepted.
    NullPin,
    /// No recovery.
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wps_state_serializes_to_lowercase() {
        let j = serde_json::to_string(&WpsState::NotConfigured).unwrap();
        assert!(j.contains("not-configured"));
        let j2 = serde_json::to_string(&WpsState::Configured).unwrap();
        assert!(j2.contains("configured"));
    }

    #[test]
    fn wps_config_round_trips() {
        let c = WpsConfig {
            version: 2,
            state: WpsState::NotConfigured,
            locked: false,
            pin_method: true,
            pbc_method: true,
            manufacturer: "TP-Link".into(),
            model: "Archer C7".into(),
            model_number: "1.0".into(),
            device_name: "Wi-Fi Router".into(),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: WpsConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.version, 2);
        assert_eq!(back.state, WpsState::NotConfigured);
        assert!(back.pin_method);
    }
}