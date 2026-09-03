//! The IPC contract between the GUI and the privileged agent.
//!
//! Wire format: a 4-byte big-endian length prefix followed by a JSON-encoded
//! [`Request`] or [`Response`].

use crate::autopwn::AutoPwnConfig;
use crate::types::*;
use crate::wps::WpsOutcome;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};

// Re-export the NetSpecter-specific types so consumers of the IPC module
// can name them without reaching into the individual submodules.
pub use crate::backend_types::{
    CapturedCredential, EvilTwinConfig, EvilTwinSession, HiddenSsidCandidate,
    PmkidCapture, SsidSource, TargetReport, WizardPlan, WizardStep,
    WizardStepKind,
};

/// Directory the agent creates (as root) to hold its listening socket.
pub const RUNTIME_DIR: &str = "/run/netspecter";

/// Hard cap on a single framed message, guarding against a bogus length prefix.
const MAX_MSG_LEN: usize = 64 * 1024 * 1024;

/// Per-instance socket path, keyed by the launching user's uid and the GUI's
/// process id. Each GUI instance gets its own agent and socket, so several
/// instances running at once (e.g. one per wireless card) do not collide.
pub fn socket_path(uid: u32, instance: u32) -> String {
    format!("{RUNTIME_DIR}/{uid}-{instance}.sock")
}

/// A command sent by the GUI to the agent.
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum Request {
    /// First message on a new connection: negotiate the protocol version and
    /// trigger the agent's dependency check.
    Hello {
        version: String,
    },

    // --- interface ---
    // Interface enumeration and 5 GHz capability are unprivileged and handled
    // GUI-side, only monitor-mode control crosses the boundary.
    EnableMonitor {
        iface: String,
        kill_network_manager: bool,
    },
    SetMac {
        iface: String,
        mac: MacMode,
    },
    DisableMonitor {
        iface: String,
    },

    // --- scan ---
    StartScan {
        iface: String,
        ghz_2_4: bool,
        ghz_5: bool,
        channels: Option<String>,
    },
    StopScan,
    IsScanning,
    /// Drop the accumulated access-point / client data (the "restart" action).
    ResetScanData,
    /// Poll for the current merged scan snapshot (sent on the GUI's refresh timer).
    GetScanData,

    // --- attacks ---
    StartDeauth {
        bssid: String,
        clients: Option<Vec<String>>,
        /// Send rounds per second (each round hits every target once).
        rate: u32,
        /// Also send a disassociation frame alongside each deauth.
        disassoc: bool,
    },
    StopDeauth {
        bssid: String,
    },
    StopAllDeauth,

    // --- capture ---
    /// Read one chunk of the saved capture at `offset`; the GUI streams the file
    /// in bounded pieces so a long capture never has to fit in one frame.
    GetCaptureChunk {
        offset: u64,
    },

    /// Ask the agent to clean up and exit.
    Shutdown,

    // ─── NetSpecter-specific extensions (PMKID / WPS / Hidden / Evil-Twin / Wizard / Report / Audit) ───

    /// Trigger a PMKID harvest against the given BSSID. Returns the captured
    /// PMKID record (or `Error` on timeout).
    HarvestPmkid {
        bssid: String,
        essid: String,
        timeout_secs: u64,
    },

    /// Verify a candidate passphrase against a previously-captured PMKID.
    /// Returns `Bool(true)` if the passphrase is the AP's PSK.
    VerifyPskAgainstPmkid {
        candidate: String,
        ssid: String,
        bssid: String,
        sta: String,
        pmkid_hex: String,
    },

    /// Build a Smart-Wizard plan for a target AP. Returns the plan.
    WizardPlanFor {
        ap: AP,
    },

    /// Discover the ESSID of a hidden AP. Returns up to three candidates
    /// (probe / deauth / vendor-OUI), with the highest-confidence first.
    DiscoverHiddenSsid {
        bssid: String,
        channel: String,
    },

    /// Launch a beacon-flooding attack against a hidden AP to provoke
    /// probe requests from clients. Returns the recovered candidate (or
    /// `Error` on timeout).
    BeaconFloodHidden {
        bssid: String,
        channel: u8,
        timeout_secs: u64,
    },

    /// Probe the historical `00000000` NULL PIN against the target.
    /// Returns the WPS outcome (PIN/PSK when the AP accepts it).
    TryWpsNullPin {
        bssid: String,
    },

    /// Attempt a Pixie Dust attack (offline weak-PRNG recovery).
    /// Sub-second when the chipset is vulnerable.
    TryWpsPixieDust {
        bssid: String,
        channel: String,
    },

    /// Run an online WPS PIN brute-force (Reaver / Bully).
    /// Can take hours; `timeout_secs` bounds the run.
    TryWpsOnlineBrute {
        bssid: String,
        channel: String,
        timeout_secs: u64,
    },

    /// Launch the full Auto-Pwn pipeline (discover → hidden recovery →
    /// rank → attack → crack). The agent streams PipelineEvent messages
    /// over a dedicated progress socket; this request returns the final
    /// AutoPwnResult.
    StartAutoPwn {
        config: AutoPwnConfig,
    },

    /// Poll the running Auto-Pwn pipeline for events since the last
    /// poll. Returns an empty batch when the pipeline is idle.
    PollAutoPwn,

    /// Launch an Evil-Twin session. Returns the new session record.
    LaunchEvilTwin {
        config: EvilTwinConfig,
    },

    /// Stop an Evil-Twin session by its `iface`.
    StopEvilTwin {
        iface: String,
    },

    /// Render a pentest report. Returns the paths of the produced files.
    GenerateReport {
        targets: Vec<TargetReport>,
        plans: Vec<WizardPlan>,
        output_dir: String,
    },
}

/// Paths of a generated report — the payload of
/// [`Response::ReportPaths`].
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct ReportPaths {
    pub html: Option<String>,
    pub json: String,
    pub pdf: Option<String>,
}

/// A reply from the agent to a [`Request`].
#[derive(Debug, Serialize, serde::Deserialize)]
pub enum Response {
    Ok,
    Error {
        message: String,
    },
    /// Reply to [`Request::Hello`]: the required tools the agent found missing
    /// (empty when everything it needs is present).
    Setup {
        missing_dependencies: Vec<String>,
    },
    /// The (possibly renamed) monitor-mode interface name.
    MonitorEnabled {
        iface: String,
    },
    Bool(bool),
    ScanData {
        aps: Vec<AP>,
        unlinked: Vec<Client>,
        attacked: Vec<AttackState>,
        channel: Option<u32>,
    },
    /// One chunk of the capture; `last` marks the final one.
    CaptureChunk {
        data: Vec<u8>,
        last: bool,
    },

    // ─── NetSpecter-specific extension responses ───

    /// Reply to [`Request::HarvestPmkid`] — the captured PMKID record.
    PmkidCapture(PmkidCapture),

    /// Reply to [`Request::WizardPlanFor`] — the wizard's plan for the AP.
    WizardPlan(WizardPlan),

    /// Reply to [`Request::DiscoverHiddenSsid`] — 0..=3 candidate ESSIDs,
    /// sorted by descending confidence.
    HiddenSsidCandidates(Vec<HiddenSsidCandidate>),

    /// Reply to [`Request::LaunchEvilTwin`] — the live session record.
    EvilTwinSession(EvilTwinSession),

    /// Reply to any WPS attack request — the outcome record.
    WpsOutcome(WpsOutcome),

    /// Reply to [`Request::GenerateReport`] — the paths of the rendered
    /// files (HTML, JSON, optional PDF).
    ReportPaths(ReportPaths),

    /// Reply to [`Request::StartAutoPwn`] — the pipeline has launched;
    /// poll with PollAutoPwn for events and the final result.
    AutoPwnStarted,

    /// Reply to [`Request::PollAutoPwn`] — events since the last poll,
    /// plus the final result once the pipeline completes.
    AutoPwnEvents {
        events: Vec<crate::autopwn::PipelineEvent>,
        result: Option<crate::autopwn::AutoPwnResult>,
    },
}

/// Write a length-prefixed JSON frame.
pub fn write_msg<W: Write, T: Serialize>(w: &mut W, msg: &T) -> io::Result<()> {
    let data =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if data.len() > MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message exceeds maximum frame length",
        ));
    }

    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(&data)?;
    w.flush()
}

/// Read a length-prefixed JSON frame. Returns `UnexpectedEof` on a clean
/// disconnect, which the agent uses as its teardown trigger.
pub fn read_msg<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;

    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "declared frame length exceeds maximum",
        ));
    }

    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;

    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
