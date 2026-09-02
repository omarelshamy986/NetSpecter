//! Pentest-report generator (HTML + JSON).
//!
//! Two output formats:
//!
//! - **HTML** — interactive, dark-themed, includes the full attack timeline,
//!   findings, audit-log excerpt, evidence references, and remediation
//!   guidance per finding. This is what the operator hands to the client.
//!
//! - **JSON** — the same content in a structured form for ingestion into
//!   Nessus / Dradis / custom pipelines. JSON is the canonical machine-
//!   readable report; the HTML is the human-readable rendering.
//!
//! ## PDF
//!
//! PDF generation is delegated to `wkhtmltopdf` or the browser's print
//! pathway — we render to HTML first, then let the operator pick. Native
//! PDF emission is a separate concern (see TODO in `render_pdf`).
//!
//! ## Templates
//!
//! HTML uses Handlebars (`handlebars` crate) with the template at
//! `templates/report-html.hbs`. JSON is straightforward serde.

use chrono::{DateTime, Utc};
use handlebars::Handlebars;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(thiserror::Error, Debug)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("template error: {0}")]
    Template(String),
    #[error("JSON error: {0}")]
    Json(String),
}

/// One finding the report surfaces.
///
/// A finding has a CVSS-style severity, a free-text description, evidence
/// references (paths to captures / pcapngs), and a remediation hint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub description: String,
    pub evidence: Vec<EvidenceRef>,
    pub remediation: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: String, // "pmkid", "handshake", "wep-ivs", "wps-pin", "evil-twin-credential"
    pub description: String,
    pub path: PathBuf,
}

/// The full report payload — both HTML and JSON are derived from this.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub engagement_id: String,
    pub generated_at: DateTime<Utc>,
    pub operator: String,
    pub scope: String,
    pub rules_of_engagement: String,
    pub targets: Vec<TargetReport>,
    pub findings: Vec<Finding>,
    pub audit_chain_digest: String,
    pub wizard_plans: Vec<netspecter_common::ipc::WizardPlan>,
}

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
    pub hidden_recovery: Option<String>,
}

/// Render the JSON form.
pub fn render_json(report: &Report, path: &Path) -> Result<(), ReportError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(report).map_err(|e| ReportError::Json(e.to_string()))?;
    fs::write(path, s)?;
    Ok(())
}

/// Render the HTML form using Handlebars.
pub fn render_html(report: &Report, template_path: &Path, output_path: &Path) -> Result<(), ReportError> {
    let template = fs::read_to_string(template_path)
        .map_err(|e| ReportError::Template(format!("read template: {e}")))?;
    let mut hb = Handlebars::new();
    hb.register_template_string("report", template)
        .map_err(|e| ReportError::Template(e.to_string()))?;

    let mut ctx = HashMap::new();
    ctx.insert("report", report);
    let html = hb
        .render("report", &ctx)
        .map_err(|e| ReportError::Template(e.to_string()))?;

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, html)?;
    Ok(())
}

/// Render PDF via an external `wkhtmltopdf` invocation. The caller may
/// opt out by passing `None`; in that case the function is a no-op and the
/// operator is expected to print the HTML to PDF manually.
pub fn render_pdf(
    html_path: &Path,
    pdf_path: &Path,
) -> Result<(), ReportError> {
    let wkhtmltopdf = netspecter_common::deps::which("wkhtmltopdf");
    let wk = match wkhtmltopdf {
        Some(p) => p,
        None => {
            return Err(ReportError::Template(
                "wkhtmltopdf not in PATH; install wkhtmltopdf or skip PDF rendering".into(),
            ));
        }
    };
    let status = std::process::Command::new(wk)
        .arg(html_path)
        .arg(pdf_path)
        .status()?;
    if !status.success() {
        return Err(ReportError::Template(format!(
            "wkhtmltopdf failed: {status}"
        )));
    }
    Ok(())
}

/// Build a default Finding list from the report's existing state.
///
/// This is the "auto-generate findings from observations" path — useful
/// when the operator wants a quick draft to hand-edit rather than writing
/// every finding from scratch.
pub fn auto_findings(report: &Report) -> Vec<Finding> {
    let mut findings = Vec::new();
    for target in &report.targets {
        // WEP target = always Critical.
        if target.encryption == "WEP" {
            findings.push(Finding {
                id: format!("WEP-{}", target.bssid.replace(':', "")),
                title: format!("WEP encryption in use on {}", target.essid),
                severity: Severity::Critical,
                description:
                    "WEP is broken; an attacker with a few minutes of capture time can recover the key."
                        .into(),
                evidence: vec![EvidenceRef {
                    kind: "wep-ivs".into(),
                    description: "WEP IVs capture file".into(),
                    path: PathBuf::from(format!(
                        "~/.netspecter/captures/wep_{}.ivs",
                        target.bssid.replace(':', "")
                    )),
                }],
                remediation:
                    "Migrate to WPA3-SAE or, at minimum, WPA2-Personal with a strong passphrase."
                        .into(),
            });
        }

        // WPA2 with handshake captured = High.
        if target.handshake_captured {
            findings.push(Finding {
                id: format!("HS-{}", target.bssid.replace(':', "")),
                title: format!("WPA2 4-way handshake captured for {}", target.essid),
                severity: Severity::High,
                description:
                    "The WPA2 4-way handshake was captured; offline dictionary attack is in scope."
                        .into(),
                evidence: vec![EvidenceRef {
                    kind: "handshake".into(),
                    description: "WPA2 handshake capture (pcap)".into(),
                    path: PathBuf::from(format!(
                        "~/.netspecter/captures/{}_{}.cap",
                        target.essid, target.bssid.replace(':', "")
                    )),
                }],
                remediation:
                    "Use a passphrase with at least 12 random characters; consider WPA3-SAE."
                        .into(),
            });
        }

        // PMKID captured = Critical (no client needed).
        if target.pmkid_captured {
            findings.push(Finding {
                id: format!("PMKID-{}", target.bssid.replace(':', "")),
                title: format!("PMKID captured for {}", target.essid),
                severity: Severity::Critical,
                description:
                    "PMKID was captured from EAPOL M1 without requiring a connected client. \
                     Offline dictionary attack is fully in scope."
                        .into(),
                evidence: vec![EvidenceRef {
                    kind: "pmkid".into(),
                    description: "PMKID + hashcat-ready .hc22000 file".into(),
                    path: PathBuf::from(format!(
                        "~/.netspecter/captures/{}_{}/pmkid_attack.hc22000",
                        target.essid,
                        target.bssid.replace(':', "")
                    )),
                }],
                remediation:
                    "Disable roaming features that publish PMKID; upgrade to WPA3-SAE (no PMKID)."
                        .into(),
            });
        }

        // WPS PIN recovered = Critical.
        if target.wps_recovered {
            findings.push(Finding {
                id: format!("WPS-{}", target.bssid.replace(':', "")),
                title: format!("WPS PIN recovered for {}", target.essid),
                severity: Severity::Critical,
                description:
                    "The WPS PIN was recovered via Pixie Dust (offline) or online brute; \
                     the WPA-PSK is derivable from it."
                        .into(),
                evidence: vec![EvidenceRef {
                    kind: "wps-pin".into(),
                    description: "Reaver / Bully session log with recovered PIN".into(),
                    path: PathBuf::from("~/.netspecter/captures/wps/".to_string()
                        + &target.bssid.replace(':', "")
                        + ".log"),
                }],
                remediation: "Disable WPS on the access point.".into(),
            });
        }
    }
    findings
}

/// Build a Report from wizard plans + target observations.
pub fn build_report(
    engagement_id: &str,
    operator: &str,
    audit_digest: &str,
    targets: Vec<TargetReport>,
    plans: Vec<netspecter_common::ipc::WizardPlan>,
) -> Report {
    let mut report = Report {
        engagement_id: engagement_id.into(),
        generated_at: Utc::now(),
        operator: operator.into(),
        scope: String::new(),
        rules_of_engagement: String::new(),
        targets,
        findings: Vec::new(),
        audit_chain_digest: audit_digest.into(),
        wizard_plans: plans,
    };
    report.findings = auto_findings(&report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn render_json_writes_valid_json() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.json");
        let report = Report {
            engagement_id: "ENG-001".into(),
            generated_at: Utc::now(),
            operator: "abdo".into(),
            scope: "test scope".into(),
            rules_of_engagement: "ROE-001".into(),
            targets: vec![],
            findings: vec![],
            audit_chain_digest: "abcd".into(),
            wizard_plans: vec![],
        };
        render_json(&report, &path).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["engagement_id"], "ENG-001");
        assert_eq!(parsed["operator"], "abdo");
    }

    #[test]
    fn auto_findings_emits_critical_for_wep_and_pmkid() {
        let report = Report {
            engagement_id: "x".into(),
            generated_at: Utc::now(),
            operator: "op".into(),
            scope: "s".into(),
            rules_of_engagement: "r".into(),
            audit_chain_digest: "d".into(),
            targets: vec![
                TargetReport {
                    bssid: "aa:bb:cc:dd:ee:01".into(),
                    essid: "WEP-NET".into(),
                    encryption: "WEP".into(),
                    channel: "6".into(),
                    clients_observed: 0,
                    handshake_captured: false,
                    pmkid_captured: false,
                    wps_recovered: false,
                    hidden_recovery: None,
                },
                TargetReport {
                    bssid: "aa:bb:cc:dd:ee:02".into(),
                    essid: "PMKID-NET".into(),
                    encryption: "WPA2".into(),
                    channel: "6".into(),
                    clients_observed: 0,
                    handshake_captured: false,
                    pmkid_captured: true,
                    wps_recovered: false,
                    hidden_recovery: None,
                },
            ],
            findings: vec![],
            wizard_plans: vec![],
        };
        let findings = auto_findings(&report);
        let wep = findings.iter().find(|f| f.id.contains("WEP")).unwrap();
        assert!(matches!(wep.severity, Severity::Critical));
        let pmkid = findings.iter().find(|f| f.id.contains("PMKID")).unwrap();
        assert!(matches!(pmkid.severity, Severity::Critical));
    }

    #[test]
    fn severity_label_is_uppercase() {
        assert_eq!(Severity::Critical.label(), "CRITICAL");
        assert_eq!(Severity::High.label(), "HIGH");
    }
}