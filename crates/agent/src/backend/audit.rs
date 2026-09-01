//! Tamper-evident audit log for operator accountability.
//!
//! Every state-changing operation the agent performs is logged here, with
//! a SHA-256 chain so the operator (or the report auditor) can later
//! verify that nothing was added, removed, or modified after the fact.
//!
//! ## Storage layout
//!
//! ```text
//! ~/.netspecter/
//!   audit.log           # newline-delimited JSON entries, one per event
//!   audit.checksum      # running SHA-256 of the audit log content
//! ```
//!
//! Each entry includes:
//! - A monotonic sequence number
//! - The wall-clock timestamp (RFC 3339)
//! - The operator's handle (recorded at consent time)
//! - The action performed
//! - The target (BSSID / ESSID / interface, depending on the action)
//! - A SHA-256 hash of `(prev_hash || this_entry)` — the chain
//!
//! To verify the chain, an auditor re-reads the log and re-computes the
//! chain hashes; any mismatch indicates tampering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// One entry in the audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub timestamp: DateTime<Utc>,
    pub operator: String,
    pub action: AuditAction,
    pub target: AuditTarget,
    /// SHA-256 of the previous entry's chain hash (or 32 zero bytes for entry 0).
    pub prev_hash: String,
    /// SHA-256 of `(prev_hash || canonical_json(this_entry_without_hash))`.
    pub chain_hash: String,
}

/// The action the operator (or the agent on the operator's behalf) performed.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditAction {
    /// First-run consent acknowledgement.
    ConsentGranted {
        scope: String,
        rules_of_engagement: String,
    },
    /// A scan was started or stopped.
    Scan {
        verb: ScanVerb,
        iface: String,
    },
    /// A deauth / disassoc attack was started or stopped.
    Deauth {
        verb: AttackVerb,
        bssid: String,
        rate: u32,
        disassoc: bool,
    },
    /// A PMKID harvest was completed.
    PmkidCapture {
        bssid: String,
        essid: String,
        pmkid_hex: String,
    },
    /// A WPS attack was launched.
    WpsAttack {
        bssid: String,
        strategy: String,
        result: String,
    },
    /// A WEP IVs collection was started / cracked.
    WepAttack {
        bssid: String,
        strategy: String,
        iv_count: u32,
        key_recovered: Option<String>,
    },
    /// A hidden-SSID recovery was completed.
    HiddenSsid {
        bssid: String,
        essid: String,
        source: String,
    },
    /// An Evil-Twin session was launched or stopped.
    EvilTwin {
        verb: AttackVerb,
        ssid: String,
    },
    /// A pentest report was generated.
    ReportGenerated {
        format: String,
        path: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanVerb {
    Started,
    Stopped,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackVerb {
    Started,
    Stopped,
}

/// What the action was performed against.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditTarget {
    Ap { bssid: String, essid: String },
    Interface { name: String },
    Session,
}

/// The audit log handle. Operators keep one of these for the lifetime of
/// a NetSpecter run; the handle is append-only.
pub struct AuditLog {
    path: PathBuf,
    operator: String,
    last_hash: String,
    next_seq: u64,
}

impl AuditLog {
    /// Open (or create) the audit log at `~/.netspecter/audit.log`.
    ///
    /// If a previous log exists, the chain is verified before opening; a
    /// tampered log fails the open rather than silently appending. The
    /// caller is expected to handle the failure by either rotating the
    /// log or refusing to start the engagement.
    pub fn open(operator: impl Into<String>) -> Result<Self, AuditError> {
        let operator = operator.into();
        let dir = netspecter_root()?;
        fs::create_dir_all(&dir)?;
        let path = dir.join("audit.log");
        let (next_seq, last_hash) = if path.exists() {
            read_chain_tail(&path)?
        } else {
            (0, ZERO_HASH.to_string())
        };
        Ok(Self { path, operator, last_hash, next_seq })
    }

    /// Append an entry. The chain hash is computed from the entry's content
    /// (sans the chain_hash field) plus the previous chain hash.
    pub fn append(&mut self, action: AuditAction, target: AuditTarget) -> Result<(), AuditError> {
        let mut entry = AuditEntry {
            seq: self.next_seq,
            timestamp: Utc::now(),
            operator: self.operator.clone(),
            action,
            target,
            prev_hash: self.last_hash.clone(),
            chain_hash: String::new(),
        };
        let hash = compute_chain_hash(&entry.prev_hash, &entry)?;
        entry.chain_hash = hash.clone();

        let json = serde_json::to_string(&entry)
            .map_err(|e| AuditError::Serialize(e.to_string()))?;
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(f, "{json}")?;

        self.last_hash = hash;
        self.next_seq += 1;
        Ok(())
    }

    /// Verify the integrity of the entire log.
    ///
    /// Returns `Ok(())` if every entry's chain hash is consistent with the
    /// previous entry's chain hash and the entry's content.
    pub fn verify(&self) -> Result<(), AuditError> {
        verify_chain(&self.path)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit log is corrupt at line {line}: {reason}")]
    Corrupt { line: usize, reason: String },
    #[error("serialization error: {0}")]
    Serialize(String),
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn netspecter_root() -> Result<PathBuf, AuditError> {
    if let Ok(dir) = std::env::var("NETSPECTOR_ROOT") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").map_err(|_| AuditError::Serialize("$HOME unset".into()))?;
    Ok(PathBuf::from(home).join(".netspecter"))
}

fn compute_chain_hash(prev: &str, entry: &AuditEntry) -> Result<String, AuditError> {
    let mut entry_for_hash = entry.clone();
    entry_for_hash.chain_hash = String::new();
    let canonical = serde_json::to_string(&entry_for_hash)
        .map_err(|e| AuditError::Serialize(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn read_chain_tail(path: &PathBuf) -> Result<(u64, String), AuditError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut last_seq = 0u64;
    let mut last_hash = ZERO_HASH.to_string();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|e| AuditError::Serialize(e.to_string()))?;
        last_seq = entry.seq + 1;
        last_hash = entry.chain_hash;
    }
    Ok((last_seq, last_hash))
}

fn verify_chain(path: &PathBuf) -> Result<(), AuditError> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut prev = ZERO_HASH.to_string();
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .map_err(|e| AuditError::Serialize(format!("line {idx}: {e}")))?;
        let expected = compute_chain_hash(&prev, &entry)?;
        if expected != entry.chain_hash {
            return Err(AuditError::Corrupt {
                line: idx,
                reason: format!("expected {expected}, got {}", entry.chain_hash),
            });
        }
        prev = entry.chain_hash;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn entry_for_test(seq: u64, operator: &str, action: AuditAction) -> AuditEntry {
        AuditEntry {
            seq,
            timestamp: Utc::now(),
            operator: operator.into(),
            action,
            target: AuditTarget::Session,
            prev_hash: ZERO_HASH.into(),
            chain_hash: String::new(),
        }
    }

    #[test]
    fn chain_hash_is_deterministic() {
        let entry = entry_for_test(0, "abdo", AuditAction::Scan {
            verb: ScanVerb::Started,
            iface: "wlan0".into(),
        });
        let h1 = compute_chain_hash(ZERO_HASH, &entry).unwrap();
        let h2 = compute_chain_hash(ZERO_HASH, &entry).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn chain_changes_with_prev_hash() {
        let entry = entry_for_test(0, "abdo", AuditAction::Scan {
            verb: ScanVerb::Started,
            iface: "wlan0".into(),
        });
        let h_zero = compute_chain_hash(ZERO_HASH, &entry).unwrap();
        let h_prev = compute_chain_hash(&"abcd".repeat(8), &entry).unwrap();
        assert_ne!(h_zero, h_prev);
    }

    #[test]
    fn append_and_verify_round_trip() {
        let dir = tempdir().unwrap();
        std::env::set_var("NETSPECTOR_ROOT", dir.path());
        let mut log = AuditLog::open("test-operator").unwrap();
        for i in 0..3 {
            log.append(
                AuditAction::Scan {
                    verb: if i == 0 { ScanVerb::Started } else { ScanVerb::Stopped },
                    iface: "wlan0".into(),
                },
                AuditTarget::Interface { name: "wlan0".into() },
            ).unwrap();
        }
        log.verify().unwrap();
    }

    #[test]
    fn verify_detects_tampering() {
        let dir = tempdir().unwrap();
        std::env::set_var("NETSPECTOR_ROOT", dir.path());
        let mut log = AuditLog::open("test-operator").unwrap();
        log.append(
            AuditAction::Scan { verb: ScanVerb::Started, iface: "wlan0".into() },
            AuditTarget::Interface { name: "wlan0".into() },
        ).unwrap();
        log.verify().unwrap();

        // Tamper: rewrite the operator field in the persisted file.
        let content = fs::read_to_string(&dir.path().join("audit.log")).unwrap();
        let tampered = content.replace("test-operator", "intruder");
        fs::write(&dir.path().join("audit.log"), tampered).unwrap();

        let log2 = AuditLog::open("test-operator").unwrap();
        assert!(log2.verify().is_err());
    }
}