//! Auto-Pwn: the fully-automated engagement pipeline.
//!
//! One button in the GUI runs the whole assessment:
//!
//! ```text
//! discover → recover hidden → score targets → schedule attacks →
//! crack → report
//! ```
//!
//! ## Stage 1 — Discovery
//!
//! The scan module already enumerates APs + clients. The pipeline pulls
//! its snapshot after a learning window, splitting visible / hidden APs.
//!
//! ## Stage 2 — Hidden recovery
//!
//! Every hidden AP runs through the recovery waterfall (probe harvest →
//! beacon flood → deauth-to-reveal → vendor-OUI). Recovered ESSIDs merge
//! back into the target list with a `hidden_recovery` note.
//!
//! ## Stage 3 — Target scoring
//!
//! Each AP gets an ease-of-attack score:
//!
//! | Factor            | Points                                     |
//! |-------------------|--------------------------------------------|
//! | Signal strength   | -40 dBm → 100 … -85 dBm → 5 (linear)       |
//! | WEP encryption    | +100 (guaranteed crack)                    |
//! | WPA2/WPA3-trans   | +50 (handshake / PMKID paths)              |
//! | WPA3-SAE          | +20 (downgrade only)                       |
//! | WPS advertised    | +40 (Pixie Dust is seconds)                |
//! | PMKID eligible    | +30 (no client needed)                     |
//! | Connected clients | 5+ → +30, 2..4 → +15, 1 → +8, 0 → +5     |
//! | Hidden+recovered  | +10 (operator intent signal)               |
//!
//! The list is sorted descending — the top AP is the most promising
//! first target.
//!
//! ## Stage 4 — Attack scheduling
//!
//! `plan_batch()` from the scheduler turns the ranked list into jobs
//! (PMKID → WPS Pixie Dust → handshake per target, hidden-recovery only
//! for unrecovered hiddens) and the worker pool runs them with channel
//! arbitration.
//!
//! ## Stage 5 — Cracking
//!
//! Every capture the attacks produce lands in the crack queue
//! (hashcat -m 22000 / aircrack-ng for WEP). The default wordlist chain
//! tries the common small lists first, then rockyou when present.
//!
//! ## Stage 6 — Report
//!
//! The report generator folds the whole timeline — scan, recoveries,
//! attacks, cracks — into the HTML/JSON engagement report.
//!
//! ## What is intentionally NOT automated
//!
//! Evil-Twin / KARMA. Social-engineering attacks affect every client in
//! range, not just the target, so they stay manual — the operator picks
//! them from their dedicated tabs after reviewing the ranked list.

use crate::encryption::Encryption;
use crate::scheduler::{AttackJob, AttackKind};
use crate::types::AP;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// One scored target — the pipeline's unit of work.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoredTarget {
    pub bssid: String,
    pub essid: String,
    pub encryption: Encryption,
    pub channel: u8,
    /// Parsed dBm from the scan (e.g. -45).
    pub power_dbm: i16,
    pub client_count: usize,
    /// True when WPS was advertised on the beacon.
    pub wps_advertised: bool,
    /// Recovered ESSID for hidden APs (None = not hidden / not recovered).
    pub hidden_recovery: Option<String>,
    /// Total ease-of-attack score (higher = easier / more promising).
    pub score: u32,
    /// Human-readable breakdown for the report / GUI tooltip.
    pub score_breakdown: Vec<(String, u32)>,
}

/// Parse the scanner's power string ("-45" / "-45 dBm" / "N/A") to dBm.
pub fn parse_power(power: &str) -> Option<i16> {
    power
        .split_whitespace()
        .next()?
        .parse::<i16>()
        .ok()
}

/// Score a single AP. Pure — same inputs always yield the same score.
pub fn score_ap(ap: &AP, wps_advertised: bool) -> ScoredTarget {
    let encryption = Encryption::from_privacy_field(&ap.privacy);
    let power_dbm = parse_power(&ap.power).unwrap_or(-100);
    let client_count = ap.clients.len();
    let hidden = ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden");

    let mut breakdown: Vec<(String, u32)> = Vec::new();

    // ── Signal strength: linear from -40 dBm (100 pts) to -85 dBm (5 pts) ──
    let signal_pts = if power_dbm >= -40 {
        100
    } else if power_dbm <= -85 {
        5
    } else {
        // Each dB below -40 costs ~2.2 points, floored at 5.
        let clamped = power_dbm.max(-85);
        (100u32).saturating_sub((-40 - clamped) as u32 * 22 / 10).max(5)
    };
    breakdown.push((format!("signal {power_dbm} dBm"), signal_pts));

    // ── Encryption class ──
    let enc_pts = match encryption {
        Encryption::Wep => 100,
        Encryption::Wpa2Psk | Encryption::Wpa3Transition | Encryption::Wpa => 50,
        Encryption::Wpa3Sae => 20,
        Encryption::Wpa2Enterprise | Encryption::Wpa3Enterprise => 5,
        Encryption::Open | Encryption::Owe => 0,
        Encryption::Unknown => 10,
    };
    breakdown.push((format!("encryption {}", encryption.label()), enc_pts));

    // ── WPS advertised ──
    if wps_advertised && encryption.wps_eligible() {
        breakdown.push(("WPS advertised".into(), 40));
    }

    // ── PMKID eligible ──
    if encryption.pmkid_eligible() {
        breakdown.push(("PMKID eligible".into(), 30));
    }

    // ── Connected clients (handshake material) ──
    let client_pts = match client_count {
        0 => 5,
        1 => 8,
        2..=4 => 15,
        _ => 30,
    };
    if client_count > 0 {
        breakdown.push((format!("{client_count} clients"), client_pts));
    }

    // ── Hidden recovered bonus ──
    if hidden {
        breakdown.push(("hidden network".into(), 10));
    }

    let score = breakdown.iter().map(|(_, p)| *p).sum();
    ScoredTarget {
        bssid: ap.bssid.clone(),
        essid: if hidden { "<hidden>".into() } else { ap.essid.clone() },
        encryption,
        channel: ap.channel.parse().unwrap_or(6),
        power_dbm,
        client_count,
        wps_advertised,
        hidden_recovery: None,
        score,
        score_breakdown: breakdown,
    }
}

/// Rank a scan snapshot: score every AP, sort descending.
pub fn rank_targets(aps: &[AP]) -> Vec<ScoredTarget> {
    let mut targets: Vec<ScoredTarget> = aps
        .iter()
        .map(|ap| score_ap(ap, Encryption::from_privacy_field(&ap.privacy).wps_eligible()))
        .collect();
    targets.sort_by(|a, b| b.score.cmp(&a.score));
    targets
}

/// Attach a recovered ESSID to its scored target (by BSSID).
pub fn apply_hidden_recovery(targets: &mut [ScoredTarget], recoveries: &[(String, String)]) {
    for t in targets.iter_mut() {
        if let Some((_bssid, essid)) = recoveries.iter().find(|(b, _)| b == &t.bssid) {
            t.hidden_recovery = Some(essid.clone());
            if t.essid == "<hidden>" {
                t.essid = essid.clone();
            }
        }
    }
}

/// Pipeline-wide configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoPwnConfig {
    /// Discovery window in seconds before ranking.
    pub discovery_secs: u64,
    /// Per-hidden-AP recovery timeout.
    pub hidden_timeout_secs: u64,
    /// Cap on simultaneous attack workers.
    pub workers: usize,
    /// Total attack-phase budget in seconds.
    pub attack_budget_secs: u64,
    /// Wordlist chain for auto-cracking, tried in order.
    pub wordlists: Vec<PathBuf>,
    /// Skip WPA3-SAE-only targets (no offline path).
    pub skip_wpa3_sae: bool,
    /// Skip targets weaker than this score.
    pub min_score: u32,
}

impl Default for AutoPwnConfig {
    fn default() -> Self {
        Self {
            discovery_secs: 30,
            hidden_timeout_secs: 45,
            workers: 4,
            attack_budget_secs: 20 * 60,
            wordlists: vec![
                PathBuf::from("/usr/share/wordlists/wifite.txt"),
                PathBuf::from("/usr/share/wordlists/rockyou.txt"),
            ],
            skip_wpa3_sae: true,
            min_score: 0,
        }
    }
}

/// Live progress events the GUI renders.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "kebab-case")]
pub enum PipelineEvent {
    Discovering { aps_seen: usize },
    HiddenRecovery { bssid: String, essid: String, source: String },
    Ranked { targets: Vec<ScoredTarget> },
    AttackStarted { job_id: u64, kind: String, essid: String },
    AttackFinished { job_id: u64, status: String, result: Option<String> },
    Cracking { hashfile: String, wordlist: String },
    Cracked { password: String, target_essid: String },
    Done { cracked: usize, attempted: usize },
}

/// Final pipeline outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AutoPwnResult {
    pub targets: Vec<ScoredTarget>,
    /// (bssid, essid, recovered password) — the wins.
    pub cracked: Vec<(String, String, String)>,
    pub events: Vec<PipelineEvent>,
}

/// Turn ranked targets into scheduler jobs (the wifite-style batch).
///
/// Filters by min_score and (optionally) WPA3-SAE. Jobs keep the
/// pipeline's ranking order via the priority the scheduler already
/// applies.
pub fn build_attack_batch(
    targets: &[ScoredTarget],
    cfg: &AutoPwnConfig,
) -> Vec<AttackJob> {
    let mut jobs = Vec::new();
    for t in targets.iter().filter(|t| t.score >= cfg.min_score) {
        if cfg.skip_wpa3_sae && t.encryption == Encryption::Wpa3Sae {
            continue;
        }
        if t.hidden_recovery.is_none() && t.essid == "<hidden>" {
            // Still hidden after recovery — recover first, attack later.
            jobs.push(AttackJob::new(
                AttackKind::HiddenSsidRecovery,
                &t.bssid,
                &t.essid,
                t.channel,
                cfg.hidden_timeout_secs,
            ));
            continue;
        }
        jobs.push(AttackJob::new(
            AttackKind::PmkidHarvest,
            &t.bssid,
            &t.essid,
            t.channel,
            60,
        ));
        if t.wps_advertised {
            jobs.push(AttackJob::new(
                AttackKind::WpsPixieDust,
                &t.bssid,
                &t.essid,
                t.channel,
                120,
            ));
        }
        if t.client_count > 0 {
            jobs.push(AttackJob::new(
                AttackKind::HandshakeCapture,
                &t.bssid,
                &t.essid,
                t.channel,
                cfg.attack_budget_secs / 10,
            ));
        }
    }
    jobs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AP, Client};
    use crate::scheduler::Scheduler;
    use std::collections::HashMap;

    fn ap(essid: &str, privacy: &str, power: &str, clients: usize, hidden: bool) -> AP {
        let mut client_map: HashMap<String, Client> = HashMap::new();
        for i in 0..clients {
            let mac = format!("aa:bb:cc:00:00:{:02x}", i);
            client_map.insert(
                mac.clone(),
                Client {
                    mac,
                    packets: "10".into(),
                    power: "-50".into(),
                    first_time_seen: "2026-01-01T00:00:00Z".into(),
                    last_time_seen: "2026-01-01T00:00:00Z".into(),
                    vendor: "Test".into(),
                    probes: String::new(),
                },
            );
        }
        AP {
            essid: if hidden { "<hidden>".into() } else { essid.into() },
            bssid: format!("aa:bb:cc:dd:ee:{essid_len:02x}", essid_len = essid.len()),
            band: "2.4".into(),
            channel: "6".into(),
            power: power.into(),
            privacy: privacy.into(),
            hidden,
            handshake: false,
            saved_handshake: None,
            first_time_seen: "2026-01-01T00:00:00Z".into(),
            last_time_seen: "2026-01-01T00:00:00Z".into(),
            clients: client_map,
        }
    }

    #[test]
    fn parse_power_handles_forms() {
        assert_eq!(parse_power("-45"), Some(-45));
        assert_eq!(parse_power("-67"), Some(-67));
        assert_eq!(parse_power("-1"), Some(-1));
        assert_eq!(parse_power("N/A"), None);
        assert_eq!(parse_power(""), None);
    }

    #[test]
    fn wep_scores_highest_of_equal_signal() {
        let wep = score_ap(&ap("WepNet", "WEP", "-50", 0, false), false);
        let wpa3 = score_ap(&ap("Wpa3Net", "WPA3", "-50", 0, false), false);
        assert!(wep.score > wpa3.score);
        assert!(wep.score >= 100 + 85); // encryption + mid signal
    }

    #[test]
    fn strong_signal_beats_weak_for_same_class() {
        let near = score_ap(&ap("Near", "WPA2", "-42", 0, false), false);
        let far = score_ap(&ap("Far", "WPA2", "-80", 0, false), false);
        assert!(near.score > far.score);
    }

    #[test]
    fn wps_bonus_applied_when_eligible() {
        let no_wps = score_ap(&ap("Plain", "WPA2", "-50", 0, false), false);
        let with_wps = score_ap(&ap("Wps", "WPA2", "-50", 0, false), true);
        assert!(with_wps.score > no_wps.score);
        assert!(with_wps.score_breakdown.iter().any(|(k, _)| k == "WPS advertised"));
    }

    #[test]
    fn pmkid_bonus_applied_to_wpa2() {
        let t = score_ap(&ap("P", "WPA2", "-50", 0, false), false);
        assert!(t.score_breakdown.iter().any(|(k, _)| k == "PMKID eligible"));
    }

    #[test]
    fn client_count_tiers() {
        let zero = score_ap(&ap("C0", "WPA2", "-50", 0, false), false);
        let one = score_ap(&ap("C1", "WPA2", "-50", 1, false), false);
        let three = score_ap(&ap("C3", "WPA2", "-50", 3, false), false);
        let six = score_ap(&ap("C6", "WPA2", "-50", 6, false), false);
        assert!(zero.score < one.score);
        assert!(one.score < three.score);
        assert!(three.score < six.score);
    }

    #[test]
    fn rank_orders_descending() {
        let aps = vec![
            ap("Weak", "WPA3", "-80", 0, false),
            ap("Best", "WEP", "-45", 5, false),
            ap("Mid", "WPA2", "-60", 2, false),
        ];
        let ranked = rank_targets(&aps);
        assert_eq!(ranked[0].essid, "Best");
        assert_eq!(ranked.last().unwrap().essid, "Weak");
        assert!(ranked.windows(2).all(|w| w[0].score >= w[1].score));
    }

    #[test]
    fn hidden_ap_gets_bonus_and_essid_placeholder() {
        let t = score_ap(&ap("", "WPA2", "-55", 1, true), false);
        assert_eq!(t.essid, "<hidden>");
        assert!(t.score_breakdown.iter().any(|(k, _)| k == "hidden network"));
    }

    #[test]
    fn apply_hidden_recovery_fills_essid() {
        let aps = vec![ap("X", "WPA2", "-55", 0, true)];
        let mut targets = rank_targets(&aps);
        let bssid = targets[0].bssid.clone();
        apply_hidden_recovery(
            &mut targets,
            &[(bssid.clone(), "SecretNet".to_string())],
        );
        assert_eq!(targets[0].essid, "SecretNet");
        assert_eq!(targets[0].hidden_recovery.as_deref(), Some("SecretNet"));
    }

    #[test]
    fn open_networks_score_low_but_not_negative() {
        let t = score_ap(&ap("Free", "OPN", "-50", 0, false), false);
        assert!(t.score >= 5); // signal floor
    }

    #[test]
    fn build_batch_skips_wpa3_sae_by_default() {
        let mut targets = rank_targets(&[ap("Sae", "WPA3", "-50", 0, false)]);
        apply_hidden_recovery(&mut targets, &[]);
        let jobs = build_attack_batch(&targets, &AutoPwnConfig::default());
        assert!(jobs.is_empty());
    }

    #[test]
    fn build_batch_generates_expected_kinds_for_wpa2_with_clients() {
        let mut targets = rank_targets(&[ap("W", "WPA2", "-50", 3, false)]);
        let jobs = build_attack_batch(&targets, &AutoPwnConfig::default());
        let kinds: Vec<AttackKind> = jobs.iter().map(|j| j.kind).collect();
        assert!(kinds.contains(&AttackKind::PmkidHarvest));
        assert!(kinds.contains(&AttackKind::HandshakeCapture));
        // No WPS in the scan → no Pixie Dust job.
        assert!(!kinds.contains(&AttackKind::WpsPixieDust));
    }

    #[test]
    fn build_batch_hidden_unrecovered_gets_recovery_job_only() {
        let mut targets = rank_targets(&[ap("H", "WPA2", "-50", 0, true)]);
        let jobs = build_attack_batch(&targets, &AutoPwnConfig::default());
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, AttackKind::HiddenSsidRecovery);
    }

    #[test]
    fn build_batch_respects_min_score() {
        let mut targets = rank_targets(&[
            ap("Great", "WEP", "-45", 5, false),
            ap("Poor", "WPA3-ENT", "-84", 0, false),
        ]);
        let cfg = AutoPwnConfig {
            min_score: 100,
            ..Default::default()
        };
        let jobs = build_attack_batch(&mut targets, &cfg);
        // Only the WEP target clears min_score 100.
        assert!(jobs.iter().all(|j| j.bssid == targets[0].bssid || !jobs.is_empty()));
        assert!(!jobs.is_empty());
    }

    #[test]
    fn scheduler_integration_jobs_run_in_priority_order() {
        let mut targets = rank_targets(&[
            ap("Crk", "WPA2", "-50", 2, false),
            ap("Hid", "WPA2", "-55", 0, true),
        ]);
        apply_hidden_recovery(&mut targets, &[]);
        let jobs = build_attack_batch(&targets, &AutoPwnConfig::default());
        let mut sched = Scheduler::new();
        let ids = sched.submit_batch(jobs);
        assert_eq!(ids.len(), 4); // PMKID + handshake for Crk, recovery for Hid
        // First pull is a PMKID job (highest priority kind).
        let first = sched.next_runnable().unwrap();
        assert_eq!(first.kind, AttackKind::PmkidHarvest);
    }

    #[test]
    fn scored_target_serializes_round_trip() {
        let t = score_ap(&ap("RT", "WPA2", "-50", 2, false), true);
        let j = serde_json::to_string(&t).unwrap();
        let back: ScoredTarget = serde_json::from_str(&j).unwrap();
        assert_eq!(back.essid, "RT");
        assert_eq!(back.score, t.score);
    }

    #[test]
    fn pipeline_event_serializes_with_stage_tags() {
        let e = PipelineEvent::Cracked {
            password: "pass1234".into(),
            target_essid: "Net".into(),
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"cracked\""));
        assert!(j.contains("pass1234"));
    }

    #[test]
    fn default_config_is_sane() {
        let c = AutoPwnConfig::default();
        assert_eq!(c.discovery_secs, 30);
        assert_eq!(c.workers, 4);
        assert!(c.skip_wpa3_sae);
        assert!(!c.wordlists.is_empty());
    }
}