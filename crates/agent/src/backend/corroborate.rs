//! Multi-source hidden-SSID corroboration.
//!
//! Different hidden-SSID recovery techniques have different confidence
//! profiles:
//!
//! - **ProbeRequest**: high confidence when observed — the client is
//!   directly asking for the network by name. Loses points only when the
//!   ESSID matches a *very common* one (e.g. "linksys") where a client
//!   might probe the wrong network.
//! - **DeauthReassoc**: very high — the client retransmitted the ESSID
//!   during re-association, which is a strong affirmative signal.
//! - **ProbeResponse**: low — APs that *do* respond with their hidden
//!   ESSID in a probe response are leaking it, but vendors sometimes
//!   send garbage here (placeholder strings, "<hidden>", etc).
//! - **VendorGuess**: very low — a heuristic. Useful as a fallback when
//!   no observed signal exists.
//! - **BeaconFlood**: very high — we actively provoked the client and
//!   it answered our BSSID with a specific ESSID, which is a deliberate
//!   authentication intent.
//!
//! The corroborator's job is to:
//!
//! 1. Collect every candidate ESSID from every source.
//! 2. Group by ESSID string (case-insensitive).
//! 3. For each unique ESSID, sum a confidence score across all sources
//!    that produced it.
//! 4. Return the candidates sorted by descending score.
//!
//! A report from this module reads as "ESSID 'Office-5G' is recovered with
//! HIGH confidence from 3 independent sources (Probe + DeauthReassoc +
//! BeaconFlood)", which is exactly what an auditor wants to see.

use airgorah_common::backend_types::HiddenSsidCandidate;
use airgorah_common::backend_types::SsidSource;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence bands the corroborator surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Multiple independent sources agree.
    High,
    /// One observed source (probe / deauth / beacon-flood).
    Medium,
    /// Heuristic-only (vendor-OUI guess) or weak observation.
    Low,
    /// No source produced any candidate.
    None,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
            Confidence::None => "—",
        }
    }
}

/// A corroborated ESSID: the candidate + the per-source contributions
/// that led to its confidence score.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorroboratedCandidate {
    pub essid: String,
    pub confidence: Confidence,
    pub score: u32,
    /// All sources that produced this ESSID, with their individual
    /// observation counts.
    pub sources: Vec<SourceContribution>,
    /// Total number of distinct clients / frames that leaked this ESSID.
    pub total_observations: u32,
    /// The first time any source saw this ESSID.
    pub first_seen: String,
}

/// One source's contribution to a corroborated candidate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceContribution {
    pub source: SsidSource,
    pub observations: u32,
    pub leaking_client: Option<String>,
    pub first_seen: String,
}

/// The corroborator: takes a list of raw candidates and returns the
/// best ESSIDs with their confidence assessments.
///
/// The corroboration policy is conservative — *more independent sources
/// agreeing* outranks a single source with many observations. An attacker
/// who controls the probe path can fabricate observations but cannot make
/// two independent techniques agree on the same ESSID without a real
/// network behind them.
pub fn corroborate(candidates: &[HiddenSsidCandidate]) -> Vec<CorroboratedCandidate> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut grouped: HashMap<String, Vec<&HiddenSsidCandidate>> = HashMap::new();
    for c in candidates {
        grouped
            .entry(c.essid.to_uppercase())
            .or_default()
            .push(c);
    }

    let mut out: Vec<CorroboratedCandidate> = grouped
        .into_iter()
        .filter_map(|(_key_upper, group)| {
            if group.is_empty() {
                return None;
            }
            // Pick the original-cased ESSID from the first entry.
            let essid = group[0].essid.clone();

            // Per-source contributions.
            let mut per_source: HashMap<SsidSource, SourceContribution> = HashMap::new();
            let mut total_observations = 0u32;
            for c in &group {
                total_observations += c.observations;
                let entry = per_source
                    .entry(c.source)
                    .or_insert_with(|| SourceContribution {
                        source: c.source,
                        observations: 0,
                        leaking_client: c.leaking_client.clone(),
                        first_seen: c.first_seen.clone(),
                    });
                entry.observations += c.observations;
                if entry.leaking_client.is_none() {
                    entry.leaking_client = c.leaking_client.clone();
                }
                if entry.first_seen > c.first_seen {
                    // keep earliest
                    entry.first_seen = c.first_seen.clone();
                }
            }
            let sources: Vec<SourceContribution> = per_source.into_values().collect();

            // Score = sum of base scores by source + observation bonus.
            let mut score = 0u32;
            for s in &sources {
                score += base_score(s.source);
                score += (s.observations as u32).saturating_sub(1) * observation_bonus(s.source);
            }

            // Confidence = band from score + number of independent sources.
            let independent = sources.len();
            let confidence = match (score, independent) {
                (s, n) if s >= 80 && n >= 2 => Confidence::High,
                (s, _) if s >= 50 => Confidence::High,
                (s, n) if s >= 30 && n >= 2 => Confidence::Medium,
                (s, _) if s >= 20 => Confidence::Medium,
                (s, _) if s >= 5 => Confidence::Low,
                _ => Confidence::Low,
            };

            let first_seen = sources
                .iter()
                .map(|s| s.first_seen.clone())
                .min()
                .unwrap_or_default();

            Some(CorroboratedCandidate {
                essid,
                confidence,
                score,
                sources,
                total_observations,
                first_seen,
            })
        })
        .collect();

    // Sort by score descending, then by total_observations descending.
    out.sort_by(|a, b| b.score.cmp(&a.score).then(b.total_observations.cmp(&a.total_observations)));
    out
}

fn base_score(source: SsidSource) -> u32 {
    match source {
        SsidSource::DeauthReassoc => 60,
        SsidSource::BeaconFlood => 50,
        SsidSource::ProbeRequest => 40,
        SsidSource::ProbeResponse => 15,
        SsidSource::VendorGuess => 5,
    }
}

fn observation_bonus(source: SsidSource) -> u32 {
    // Repeat observations of the same source only get a small bonus — we
    // weight independent *kinds* of evidence higher than raw counts.
    match source {
        SsidSource::DeauthReassoc | SsidSource::BeaconFlood | SsidSource::ProbeRequest => 5,
        SsidSource::ProbeResponse => 2,
        SsidSource::VendorGuess => 1,
    }
}

/// Render a corroborator report as a human-readable string.
pub fn summarize(c: &CorroboratedCandidate) -> String {
    let mut s = format!("[{}] '{}' (score {})", c.confidence.label(), c.essid, c.score);
    s.push_str(&format!(" — {} sources:", c.sources.len()));
    for src in &c.sources {
        s.push_str(&format!(" {}x{}", src.source_label(), src.observations));
    }
    if let Some(client) = c.sources.iter().find_map(|s| s.leaking_client.as_ref()) {
        s.push_str(&format!(" (leaked by {})", client));
    }
    s
}

impl SsidSource {
    pub fn source_label(&self) -> &'static str {
        match self {
            SsidSource::ProbeRequest => "probe",
            SsidSource::DeauthReassoc => "deauth-reassoc",
            SsidSource::ProbeResponse => "probe-resp",
            SsidSource::VendorGuess => "vendor-guess",
            SsidSource::BeaconFlood => "beacon-flood",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(essid: &str, source: SsidSource, observations: u32) -> HiddenSsidCandidate {
        HiddenSsidCandidate {
            essid: essid.into(),
            source,
            observations,
            first_seen: "2026-01-01T00:00:00Z".into(),
            leaking_client: None,
        }
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(corroborate(&[]).is_empty());
    }

    #[test]
    fn single_probe_is_medium_confidence() {
        let cands = vec![candidate("Office-5G", SsidSource::ProbeRequest, 1)];
        let result = corroborate(&cands);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].confidence, Confidence::Medium);
        assert_eq!(result[0].essid, "Office-5G");
    }

    #[test]
    fn two_independent_sources_promote_to_high() {
        let cands = vec![
            candidate("Office-5G", SsidSource::ProbeRequest, 1),
            candidate("Office-5G", SsidSource::DeauthReassoc, 1),
        ];
        let result = corroborate(&cands);
        assert_eq!(result[0].confidence, Confidence::High);
        assert_eq!(result[0].sources.len(), 2);
    }

    #[test]
    fn vendor_guess_only_is_low_confidence() {
        let cands = vec![candidate("Office-5G", SsidSource::VendorGuess, 1)];
        let result = corroborate(&cands);
        assert_eq!(result[0].confidence, Confidence::Low);
    }

    #[test]
    fn beacon_flood_with_probe_is_high() {
        let cands = vec![
            candidate("Office-5G", SsidSource::BeaconFlood, 1),
            candidate("Office-5G", SsidSource::ProbeRequest, 1),
        ];
        let result = corroborate(&cands);
        assert_eq!(result[0].confidence, Confidence::High);
    }

    #[test]
    fn case_insensitive_grouping() {
        let cands = vec![
            candidate("Office-5G", SsidSource::ProbeRequest, 1),
            candidate("office-5g", SsidSource::DeauthReassoc, 1),
            candidate("OFFICE-5G", SsidSource::BeaconFlood, 1),
        ];
        let result = corroborate(&cands);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].sources.len(), 3);
        assert_eq!(result[0].confidence, Confidence::High);
    }

    #[test]
    fn sort_by_score_descending() {
        let cands = vec![
            candidate("VendorGuess-Net", SsidSource::VendorGuess, 1),
            candidate("Real-Net", SsidSource::ProbeRequest, 1),
            candidate("Real-Net", SsidSource::DeauthReassoc, 1),
        ];
        let result = corroborate(&cands);
        assert_eq!(result[0].essid, "Real-Net");
        assert!(result[0].score > result[1].score);
    }

    #[test]
    fn confidence_ordering_is_correct() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
        assert!(Confidence::Low > Confidence::None);
    }

    #[test]
    fn confidence_labels_are_uppercase() {
        assert_eq!(Confidence::High.label(), "HIGH");
        assert_eq!(Confidence::Medium.label(), "MEDIUM");
        assert_eq!(Confidence::Low.label(), "LOW");
    }

    #[test]
    fn source_label_is_compact() {
        assert_eq!(SsidSource::ProbeRequest.source_label(), "probe");
        assert_eq!(SsidSource::BeaconFlood.source_label(), "beacon-flood");
        assert_eq!(SsidSource::VendorGuess.source_label(), "vendor-guess");
    }

    #[test]
    fn summary_includes_score_and_sources() {
        let cands = vec![
            candidate("Office-5G", SsidSource::ProbeRequest, 1),
            candidate("Office-5G", SsidSource::DeauthReassoc, 1),
        ];
        let result = corroborate(&cands);
        let s = summarize(&result[0]);
        assert!(s.contains("Office-5G"));
        assert!(s.contains("probe"));
        assert!(s.contains("deauth-reassoc"));
        assert!(s.contains("2 sources"));
    }

    #[test]
    fn total_observations_sums_across_sources() {
        let cands = vec![
            candidate("X", SsidSource::ProbeRequest, 5),
            candidate("X", SsidSource::DeauthReassoc, 3),
        ];
        let result = corroborate(&cands);
        assert_eq!(result[0].total_observations, 8);
    }

    #[test]
    fn leaking_client_propagates_to_first_source() {
        let cands = vec![
            HiddenSsidCandidate {
                essid: "X".into(),
                source: SsidSource::ProbeRequest,
                observations: 1,
                first_seen: "2026-01-01T00:00:00Z".into(),
                leaking_client: Some("aa:bb:cc:dd:ee:ff".into()),
            },
            candidate("X", SsidSource::DeauthReassoc, 1),
        ];
        let result = corroborate(&cands);
        assert!(result[0].sources.iter().any(|s| s.leaking_client.is_some()));
    }
}