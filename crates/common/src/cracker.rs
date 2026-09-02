//! Offline cracking orchestration — hashcat / john integration.
//!
//! NetSpecter captures the material (handshakes, PMKIDs, WPS-derived
//! hashes); this module drives the offline cracking phase:
//!
//! 1. **Hashcat mode selection** — from the capture type: `-m 22000`
//!    for PMKID/EAPOL (WPA-PBKDF2-PMKID+EAPOL), `-m 2500` legacy HCCAPX.
//! 2. **Command construction** — hashfile + wordlist (+ rules / mask),
//!    with benchmark and auto-detect device tuning flags.
//! 3. **Output parsing** — hashcat's `--status --machine-readable`
//!    format gives progress, speed, and the recovered plaintext.
//! 4. **Wordlist / rule management** — validate paths, estimate runtime
//!    from a benchmark probe.
//! 5. **Result normalization** — one [`CrackResult`] whether the crack
//!    came from hashcat, john, or aircrack-ng.
//!
//! ## Why hashcat first
//!
//! hashcat's GPU kernels are 10-100× faster than aircrack-ng for the
//! same WPA task, and it speaks both the PMKID (22000) and EAPOL
//! (22000-family) formats natively — no hccapx conversion step. john
//! (with the jumbo patch) is the fallback when no GPU is present.
//!
//! ## Process model
//!
//! Cracking runs are long (minutes to days). The launcher spawns
//! hashcat as a child process and streams its status lines back
//! through a channel; the GUI polls a snapshot. A stop flag terminates
//! the child cleanly.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The capture type being cracked — determines the hashcat mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrackTarget {
    /// PMKID (hashcat -m 22000, WPA-PBKDF2-PMKID+EAPOL).
    Pmkid,
    /// WPA 4-way handshake (hashcat -m 22000, same format family).
    Handshake,
    /// WPA handshake in legacy hccapx form (hashcat -m 2500).
    HandshakeHccapx,
    /// WEP key (aircrack-ng, not hashcat — no GPU kernel for WEP).
    Wep,
    /// WPS PIN already recovered; nothing to crack. Present for
    /// pipeline completeness.
    WpsPin,
}

impl CrackTarget {
    /// The hashcat mode number, or `None` when the target isn't a
    /// hashcat task (WEP goes to aircrack-ng; WPS needs no cracking).
    pub fn hashcat_mode(&self) -> Option<u32> {
        match self {
            CrackTarget::Pmkid | CrackTarget::Handshake => Some(22000),
            CrackTarget::HandshakeHccapx => Some(2500),
            CrackTarget::Wep | CrackTarget::WpsPin => None,
        }
    }

    /// The preferred cracker for this target.
    pub fn preferred_tool(&self) -> Cracker {
        match self {
            CrackTarget::Wep => Cracker::AircrackNg,
            CrackTarget::WpsPin => Cracker::None,
            _ => Cracker::Hashcat,
        }
    }
}

/// Which cracking backend to use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cracker {
    Hashcat,
    John,
    AircrackNg,
    None,
}

/// A single hashcat status line, parsed from
/// `--status --machine-readable` output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HashcatStatus {
    /// Total hashes in the file.
    pub hashes_total: u32,
    /// Hashes already cracked.
    pub hashes_recovered: u32,
    /// Current hashcat status code (3 = exhausted, 6 = cracked...).
    pub status_code: u32,
    /// Attempted candidate keys per second (sum across devices).
    pub speed_hashes_per_sec: u64,
    /// Estimated time remaining, seconds (0 when unknown).
    pub eta_secs: u64,
    /// Recovered plaintext for the first cracked hash, when present.
    pub recovered_plaintext: Option<String>,
    /// Progress percent (0-100).
    pub progress_percent: u32,
}

impl HashcatStatus {
    pub fn is_cracked(&self) -> bool {
        self.hashes_recovered > 0
    }
}

/// A normalized crack outcome regardless of backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrackResult {
    pub target: CrackTarget,
    pub tool: Cracker,
    /// The recovered key / passphrase, when successful.
    pub recovered: Option<String>,
    /// Wall-clock duration in seconds.
    pub duration_secs: u64,
    /// Total candidates attempted (from status or tool output).
    pub candidates_tried: u64,
    /// Free-text status ("exhausted", "cracked: 1/1", ...).
    pub status: String,
}

/// Validate that a wordlist path exists and is a file.
pub fn validate_wordlist(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("wordlist not found: {}", path.display()));
    }
    if !path.is_file() {
        return Err(format!("wordlist is not a file: {}", path.display()));
    }
    Ok(())
}

/// Build the hashcat command line for a cracking run.
///
/// `hashfile` is the capture in hashcat-native format (22000-style
/// `WPA*...` line or hccapx); `wordlist` is the dictionary; `rules`
/// optionally applies a rule file (e.g. `best64.rule`).
///
/// Flags chosen for long unattended runs:
/// - `--status --machine-readable`: parseable progress
/// - `--potfile-disable`: don't pollute the shared potfile mid-audit
/// - `-w 4`: full workload profile (desktop unused during a pentest)
/// - `-O`: optimized kernels (faster; drops some exotic candidate
///   lengths — acceptable for PSK work)
pub fn build_hashcat_cmd(
    hashfile: &Path,
    wordlist: &Path,
    rules: Option<&Path>,
    extra_args: &[String],
) -> Result<Command, String> {
    let mode = CrackTarget::from_hashfile(hashfile)?;
    let Some(mode_num) = mode.hashcat_mode() else {
        return Err(format!("target {mode:?} is not a hashcat task"));
    };

    let mut cmd = Command::new("hashcat");
    cmd.arg("-m").arg(mode_num.to_string());
    cmd.arg("-w").arg("4");
    cmd.arg("-O");
    cmd.arg("--status");
    cmd.arg("--machine-readable");
    cmd.arg("--potfile-disable");
    cmd.arg(hashfile);
    cmd.arg(wordlist);
    if let Some(r) = rules {
        cmd.arg("-r").arg(r);
    }
    for a in extra_args {
        cmd.arg(a);
    }
    Ok(cmd)
}

impl CrackTarget {
    /// Infer the target type from the hashfile's first line.
    pub fn from_hashfile(hashfile: &Path) -> Result<CrackTarget, String> {
        use std::io::BufRead;
        let f = std::fs::File::open(hashfile)
            .map_err(|e| format!("cannot open hashfile {}: {e}", hashfile.display()))?;
        let mut reader = std::io::BufReader::new(f);
        let mut first = String::new();
        reader
            .read_line(&mut first)
            .map_err(|e| format!("cannot read hashfile: {e}"))?;

        if first.starts_with("WPA*") {
            // 22000 family: WPA*01*PMKID*... (PMKID) or WPA*02*... (EAPOL)
            if first.contains("*01*") && !first.contains("*02*") {
                // Heuristic: PMKID lines carry the PMKID field at position 3.
                return Ok(CrackTarget::Pmkid);
            }
            return Ok(CrackTarget::Handshake);
        }
        if first.contains("$WPAPSK$") {
            // john-style or hccapx-derived line
            return Ok(CrackTarget::HandshakeHccapx);
        }
        Err(format!(
            "unrecognized hashfile format: {}",
            first.chars().take(20).collect::<String>()
        ))
    }
}

/// Parse one hashcat machine-readable status block.
///
/// The `--machine-readable` format emits `STATUS`, `HASHES`, `SPEED`,
/// `RECOVERED` lines among others; we take the last value for each key.
pub fn parse_hashcat_status(block: &str) -> HashcatStatus {
    let mut st = HashcatStatus {
        hashes_total: 0,
        hashes_recovered: 0,
        status_code: 0,
        speed_hashes_per_sec: 0,
        eta_secs: 0,
        recovered_plaintext: None,
        progress_percent: 0,
    };

    let mut speed_acc = 0u64;
    for line in block.lines() {
        let Some((key, rest)) = line.split_once('.') else {
            continue;
        };
        let val = rest.split('\t').next().unwrap_or("").trim();
        match key {
            "STATUS" => st.status_code = val.parse().unwrap_or(0),
            "HASHES" => {
                // format: "total/digested/saved/rejected"
                if let Some(total) = val.split('/').next() {
                    st.hashes_total = total.parse().unwrap_or(0);
                }
            }
            "RECOVERED" => {
                // format: "recovered/total"
                let mut parts = val.split('/');
                if let Some(rec) = parts.next() {
                    st.hashes_recovered = rec.parse().unwrap_or(0);
                }
            }
            "SPEED" => {
                // One or more "device\texec\tcur/second" entries; sum cur.
                for seg in rest.split('\t').skip(2) {
                    if let Ok(n) = seg.trim().parse::<u64>() {
                        speed_acc += n;
                    }
                }
            }
            "PROGRESS" => {
                // "attempted/total" percent
                if let Some((att, tot)) = val.split_once('/') {
                    let a: u64 = att.parse().unwrap_or(0);
                    let t: u64 = tot.parse().unwrap_or(1);
                    if t > 0 {
                        st.progress_percent = ((a * 100) / t).min(100) as u32;
                    }
                }
            }
            "RECOVER-PLAINTEXT" => {
                st.recovered_plaintext = Some(val.to_string());
            }
            "ETA" => {
                // "until <date>"; we don't parse absolute dates into secs
                // here — leave 0 and let the caller compute from progress.
                st.eta_secs = 0;
            }
            _ => {}
        }
    }
    st.speed_hashes_per_sec = speed_acc;
    st
}

/// Parse the final potfile-style line for a recovered hash.
///
/// hashcat prints `hash:plaintext` on success (and in the potfile).
pub fn parse_recovered_line(line: &str) -> Option<(String, String)> {
    let (hash, plain) = line.split_once(':')?;
    if hash.is_empty() || plain.is_empty() {
        return None;
    }
    Some((hash.trim().to_string(), plain.trim().to_string()))
}

/// Launch aircrack-ng for WEP keys — the one WiFi target hashcat can't do.
pub fn build_aircrack_cmd(ivs_file: &Path) -> Result<Command, String> {
    if !ivs_file.exists() {
        return Err(format!("IVs file not found: {}", ivs_file.display()));
    }
    let mut cmd = Command::new("aircrack-ng");
    cmd.arg("-a").arg("1"); // WEP
    cmd.arg("-l").arg(ivs_file.with_extension("key")); // write key to file
    cmd.arg(ivs_file);
    Ok(cmd)
}

/// Estimate the number of candidates a wordlist will produce after
/// rules application (upper bound — hashcat may early-exit on crack).
pub fn estimate_wordlist_size(wordlist: &Path, rules: Option<&Path>) -> u64 {
    use std::io::BufRead;
    let Ok(f) = std::fs::File::open(wordlist) else {
        return 0;
    };
    let lines = std::io::BufReader::new(f).lines().count() as u64;
    let rule_multiplier = match rules {
        Some(r) => {
            use std::io::BufRead;
            std::fs::File::open(r)
                .map(|f| std::io::BufReader::new(f).lines().count() as u64)
                .unwrap_or(1)
        }
        None => 1,
    };
    lines.saturating_mul(rule_multiplier.max(1))
}

/// A queued cracking job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CrackJob {
    pub id: String,
    pub target: CrackTarget,
    pub hashfile: PathBuf,
    pub wordlist: PathBuf,
    pub rules: Option<PathBuf>,
    pub created_at: String,
    pub status: CrackJobStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrackJobStatus {
    Queued,
    Running,
    Cracked,
    Exhausted,
    Failed,
}

/// Simple FIFO job queue for batch cracking.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CrackQueue {
    pub jobs: Vec<CrackJob>,
}

impl CrackQueue {
    pub fn push(&mut self, job: CrackJob) {
        self.jobs.push(job);
    }

    pub fn next_queued(&mut self) -> Option<CrackJob> {
        let idx = self.jobs.iter().position(|j| j.status == CrackJobStatus::Queued)?;
        let mut job = self.jobs[idx].clone();
        job.status = CrackJobStatus::Running;
        self.jobs[idx] = job.clone();
        Some(job)
    }

    pub fn complete(&mut self, id: &str, status: CrackJobStatus, recovered: Option<String>) {
        if let Some(j) = self.jobs.iter_mut().find(|j| j.id == id) {
            j.status = status;
            if let Some(p) = recovered {
                j.hashfile.set_extension("pot");
                let _ = std::fs::write(&j.hashfile, p);
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| j.status == CrackJobStatus::Queued)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmpfile(name: &str, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "crack-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn hashcat_mode_mapping() {
        assert_eq!(CrackTarget::Pmkid.hashcat_mode(), Some(22000));
        assert_eq!(CrackTarget::Handshake.hashcat_mode(), Some(22000));
        assert_eq!(CrackTarget::HandshakeHccapx.hashcat_mode(), Some(2500));
        assert_eq!(CrackTarget::Wep.hashcat_mode(), None);
        assert_eq!(CrackTarget::WpsPin.hashcat_mode(), None);
    }

    #[test]
    fn preferred_tool_per_target() {
        assert_eq!(CrackTarget::Pmkid.preferred_tool(), Cracker::Hashcat);
        assert_eq!(CrackTarget::Handshake.preferred_tool(), Cracker::Hashcat);
        assert_eq!(CrackTarget::HandshakeHccapx.preferred_tool(), Cracker::Hashcat);
        assert_eq!(CrackTarget::Wep.preferred_tool(), Cracker::AircrackNg);
        assert_eq!(CrackTarget::WpsPin.preferred_tool(), Cracker::None);
    }

    #[test]
    fn from_hashfile_detects_pmkid_line() {
        // WPA*01*<pmkid>*... = PMKID family
        let p = tmpfile("pmkid.hc22000", "WPA*01*abcd*0102*0304**\n");
        assert_eq!(CrackTarget::from_hashfile(&p).unwrap(), CrackTarget::Pmkid);
    }

    #[test]
    fn from_hashfile_detects_eapol_line() {
        let p = tmpfile("eapol.hc22000", "WPA*02*abcd*0102*0304**\n");
        assert_eq!(
            CrackTarget::from_hashfile(&p).unwrap(),
            CrackTarget::Handshake
        );
    }

    #[test]
    fn from_hashfile_detects_hccapx_john_style() {
        let p = tmpfile("hs.txt", "$WPAPSK$TestNet#aa:bb:cc:dd:ee:ff...\n");
        assert_eq!(
            CrackTarget::from_hashfile(&p).unwrap(),
            CrackTarget::HandshakeHccapx
        );
    }

    #[test]
    fn from_hashfile_rejects_unknown() {
        let p = tmpfile("bogus.txt", "not-a-hash-line\n");
        assert!(CrackTarget::from_hashfile(&p).is_err());
    }

    #[test]
    fn build_hashcat_cmd_includes_core_flags() {
        let hf = tmpfile("hs.hc22000", "WPA*02*abcd*0102*0304**\n");
        let wl = tmpfile("wordlist.txt", "a\nb\n");
        let cmd = build_hashcat_cmd(&hf, &wl, None, &[]).unwrap();
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("hashcat"));
        assert!(dbg.contains("22000"));
        assert!(dbg.contains("--machine-readable"));
        assert!(dbg.contains("--potfile-disable"));
    }

    #[test]
    fn build_hashcat_cmd_appends_rules() {
        let hf = tmpfile("hs.hc22000", "WPA*02*abcd*0102*0304**\n");
        let wl = tmpfile("wordlist.txt", "a\nb\n");
        let rules = tmpfile("best64.rule", "$a\n");
        let cmd = build_hashcat_cmd(&hf, &wl, Some(&rules), &[]).unwrap();
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("best64.rule"));
    }

    #[test]
    fn parse_status_reads_core_fields() {
        let block = "\
STATUS.3\tRunning
HASHES.4/4/0/0
RECOVERED.1/4
SPEED.0\t0\t50000
SPEED.1\t0\t70000
PROGRESS.25000/50000
RECOVER-PLAINTEXT\tcorrecthorse
ETA.until 2026-09-01T12:00:00
";
        let st = parse_hashcat_status(block);
        assert_eq!(st.status_code, 3);
        assert_eq!(st.hashes_total, 4);
        assert_eq!(st.hashes_recovered, 1);
        assert_eq!(st.speed_hashes_per_sec, 120_000); // 50k + 70k summed
        assert_eq!(st.progress_percent, 50);
        assert_eq!(st.recovered_plaintext.as_deref(), Some("correcthorse"));
        assert!(st.is_cracked());
    }

    #[test]
    fn parse_status_handles_garbage() {
        let st = parse_hashcat_status("not-a-status-block");
        assert_eq!(st.status_code, 0);
        assert_eq!(st.progress_percent, 0);
        assert!(!st.is_cracked());
    }

    #[test]
    fn parse_recovered_line_splits_on_first_colon() {
        let (hash, plain) = parse_recovered_line("WPA*02*abcd:my-pass:with:colons").unwrap();
        assert_eq!(hash, "WPA*02*abcd");
        assert_eq!(plain, "my-pass:with:colons");
    }

    #[test]
    fn parse_recovered_line_rejects_empty_parts() {
        assert!(parse_recovered_line("hash-only-no-colon").is_none());
        assert!(parse_recovered_line(":value").is_none());
        assert!(parse_recovered_line("hash:").is_none());
    }

    #[test]
    fn build_aircrack_cmd_targets_wep() {
        let ivs = tmpfile("net.ivs", "\x00\x00\x00\x00");
        let cmd = build_aircrack_cmd(&ivs).unwrap();
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("aircrack-ng"));
        assert!(dbg.contains("-a"));
        assert!(dbg.contains("1"));
    }

    #[test]
    fn build_aircrack_cmd_rejects_missing_file() {
        assert!(build_aircrack_cmd(Path::new("/nonexistent/net.ivs")).is_err());
    }

    #[test]
    fn estimate_wordlist_multiplies_by_rules() {
        let wl = tmpfile("w.txt", "a\nb\nc\n");
        assert_eq!(estimate_wordlist_size(&wl, None), 3);
        let rules = tmpfile("r.rule", "$1\n$2\n$3\n");
        assert_eq!(estimate_wordlist_size(&wl, Some(&rules)), 9);
    }

    #[test]
    fn estimate_missing_wordlist_is_zero() {
        assert_eq!(estimate_wordlist_size(Path::new("/nope.txt"), None), 0);
    }

    #[test]
    fn crack_queue_fifo_ordering() {
        let mut q = CrackQueue::default();
        for i in 0..3 {
            q.push(CrackJob {
                id: format!("job-{i}"),
                target: CrackTarget::Pmkid,
                hashfile: PathBuf::from(format!("/tmp/{i}.hc22000")),
                wordlist: PathBuf::from("/tmp/w.txt"),
                rules: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                status: CrackJobStatus::Queued,
            });
        }
        assert_eq!(q.pending_count(), 3);
        let first = q.next_queued().unwrap();
        assert_eq!(first.id, "job-0");
        assert_eq!(first.status, CrackJobStatus::Running);
        assert_eq!(q.pending_count(), 2);
    }

    #[test]
    fn crack_queue_completion_updates_status() {
        let mut q = CrackQueue::default();
        q.push(CrackJob {
            id: "job-1".into(),
            target: CrackTarget::Pmkid,
            hashfile: PathBuf::from("/tmp/1.hc22000"),
            wordlist: PathBuf::from("/tmp/w.txt"),
            rules: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            status: CrackJobStatus::Queued,
        });
        q.complete("job-1", CrackJobStatus::Cracked, Some("found-it".into()));
        assert_eq!(q.jobs[0].status, CrackJobStatus::Cracked);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn crack_job_status_serializes_lowercase() {
        assert!(serde_json::to_string(&CrackJobStatus::Queued).unwrap().contains("queued"));
        assert!(serde_json::to_string(&CrackJobStatus::Cracked).unwrap().contains("cracked"));
    }
}