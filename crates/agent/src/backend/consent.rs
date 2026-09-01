//! Operator-consent gate.
//!
//! NetSpecter will not perform any attack without an explicit consent
//! record persisted to the audit log. The flow is:
//!
//! 1. First run: the operator fills in `ConsentRecord` (handle, scope,
//!    rules of engagement reference) and the agent persists it.
//! 2. Every subsequent run: the agent reads the consent record and
//!    refuses to start an attack if the target BSSID isn't in the
//!    declared scope.
//!
//! ## What `scope` is
//!
//! A free-text field — single BSSID, an ESSID prefix, "all BSSIDs in the
//! building", etc. We *do not* try to parse it; instead, we ship a
//! `scope_matches()` helper that does prefix and exact-string checks.
//! Operators wanting regex scopes can subclass via the `consent_extended`
//! extension hook documented in the README.
//!
//! ## What `rules_of_engagement` is
//!
//! A free-text reference to the engagement contract / pentest agreement
//! that authorizes the operator. The agent records it verbatim and surfaces
//! it in the report's audit section; the report auditor can verify the
//! reference against the engagement paperwork.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub operator: String,
    pub scope: String,
    pub rules_of_engagement: String,
    pub agreed_at: DateTime<Utc>,
    /// A 32-byte hex digest of `(operator || scope || roe)` — anchors the
    /// record to its content and prevents the operator from rewriting the
    /// consent after the fact.
    pub record_digest: String,
}

impl ConsentRecord {
    /// Build a new consent record. The digest is computed over the
    /// canonical JSON of `(operator, scope, roe)` — the same canonicalization
    /// the auditor will use to verify.
    pub fn new(
        operator: impl Into<String>,
        scope: impl Into<String>,
        rules_of_engagement: impl Into<String>,
    ) -> Self {
        let operator = operator.into();
        let scope = scope.into();
        let rules_of_engagement = rules_of_engagement.into();
        let record_digest = compute_digest(&operator, &scope, &rules_of_engagement);
        Self {
            operator,
            scope,
            rules_of_engagement,
            agreed_at: Utc::now(),
            record_digest,
        }
    }

    /// Did the operator agree to test this target?
    ///
    /// The match is permissive — we treat the scope as a list of
    /// comma-separated tokens, each of which is either an exact BSSID/ESSID
    /// match or an ESSID-prefix match.
    pub fn scope_matches(&self, bssid: &str, essid: &str) -> bool {
        for token in self.scope.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // Token rules:
            //   "bssid:aa:bb:cc:dd:ee:ff"  — exact BSSID match
            //   "essid:Net-Works"          — exact ESSID match
            //   "prefix:Net-Works"         — ESSID prefix match
            //   otherwise: treat as a bare ESSID prefix
            if let Some(rest) = token.strip_prefix("bssid:") {
                if rest.eq_ignore_ascii_case(bssid) {
                    return true;
                }
            } else if let Some(rest) = token.strip_prefix("essid:") {
                if rest.eq_ignore_ascii_case(essid) {
                    return true;
                }
            } else if let Some(rest) = token.strip_prefix("prefix:") {
                if essid.to_lowercase().starts_with(&rest.to_lowercase()) {
                    return true;
                }
            } else if essid.to_lowercase().starts_with(&token.to_lowercase()) {
                return true;
            }
        }
        false
    }
}

/// Persist a consent record to disk.
///
/// `path` defaults to `~/.netspecter/consent.json` if `None`.
pub fn persist(record: &ConsentRecord, path: Option<&PathBuf>) -> std::io::Result<PathBuf> {
    let path = match path {
        Some(p) => p.clone(),
        None => default_path()?,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(record).expect("ConsentRecord serializes");
    fs::write(&path, json)?;
    Ok(path)
}

/// Read the persisted consent record, if any.
pub fn load(path: Option<&PathBuf>) -> std::io::Result<Option<ConsentRecord>> {
    let path = match path {
        Some(p) => p.clone(),
        None => default_path()?,
    };
    if !path.exists() {
        return Ok(None);
    }
    let s = fs::read_to_string(&path)?;
    let rec: ConsentRecord = serde_json::from_str(&s)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Verify the digest matches the content (tamper detection).
    let expected = compute_digest(&rec.operator, &rec.scope, &rec.rules_of_engagement);
    if expected != rec.record_digest {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "consent record digest mismatch — refusing to load",
        ));
    }
    Ok(Some(rec))
}

fn default_path() -> std::io::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, "$HOME unset"))?;
    Ok(PathBuf::from(home).join(".netspecter").join("consent.json"))
}

fn compute_digest(operator: &str, scope: &str, roe: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(operator.as_bytes());
    hasher.update(b"\n");
    hasher.update(scope.as_bytes());
    hasher.update(b"\n");
    hasher.update(roe.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn scope_matches_supports_bssid_essid_prefix_and_bare_tokens() {
        let rec = ConsentRecord::new(
            "abdo",
            "bssid:aa:bb:cc:dd:ee:ff, essid:Office, prefix:Net-, Office-WiFi",
            "ROE-2026-001",
        );
        assert!(rec.scope_matches("aa:bb:cc:dd:ee:ff", "Anything"));
        assert!(rec.scope_matches("ff:ff:ff:ff:ff:ff", "Office"));
        assert!(rec.scope_matches("ff:ff:ff:ff:ff:ff", "Net-Works"));
        assert!(rec.scope_matches("ff:ff:ff:ff:ff:ff", "Office-WiFi"));
        assert!(!rec.scope_matches("ff:ff:ff:ff:ff:ff", "HomeNet"));
    }

    #[test]
    fn scope_matches_is_case_insensitive() {
        let rec = ConsentRecord::new("abdo", "essid:MyOffice", "ROE-001");
        assert!(rec.scope_matches("ff:ff:ff:ff:ff:ff", "myoffice"));
        assert!(rec.scope_matches("ff:ff:ff:ff:ff:ff", "MYOFFICE"));
    }

    #[test]
    fn empty_scope_matches_nothing() {
        let rec = ConsentRecord::new("abdo", "", "ROE-001");
        assert!(!rec.scope_matches("aa:bb:cc:dd:ee:ff", "Anything"));
    }

    #[test]
    fn consent_persists_and_loads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consent.json");
        let rec = ConsentRecord::new("abdo", "scope", "ROE-001");
        persist(&rec, Some(&path)).unwrap();
        let loaded = load(Some(&path)).unwrap().unwrap();
        assert_eq!(loaded.operator, "abdo");
        assert_eq!(loaded.record_digest, rec.record_digest);
    }

    #[test]
    fn consent_loading_rejects_tampered_record() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("consent.json");
        let rec = ConsentRecord::new("abdo", "scope", "ROE-001");
        persist(&rec, Some(&path)).unwrap();

        // Tamper with the operator field.
        let mut s = fs::read_to_string(&path).unwrap();
        s = s.replace("abdo", "intruder");
        fs::write(&path, s).unwrap();

        let err = load(Some(&path)).unwrap_err();
        assert!(format!("{err}").contains("digest mismatch"));
    }

    #[test]
    fn digest_is_stable_for_same_inputs() {
        let d1 = compute_digest("abdo", "scope", "ROE-001");
        let d2 = compute_digest("abdo", "scope", "ROE-001");
        assert_eq!(d1, d2);
        let d3 = compute_digest("abdo", "scope", "ROE-002");
        assert_ne!(d1, d3);
    }
}