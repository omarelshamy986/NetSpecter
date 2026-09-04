//! Mass parallel attack orchestration — the wifite-style "attack
//! everything at once" engine.
//!
//! Single-target attacks are fine for a scoped pentest; a full-site
//! assessment needs throughput. This module schedules attack jobs
//! across the available radios and workers:
//!
//! - **Worker pool** — N worker threads (default: 4). Each worker
//!   pulls jobs from a shared queue. GPU-bound cracking jobs run in
//!   the cracker pipeline; radio-bound jobs (deauth / PMKID harvest)
//!   are serialized per radio.
//! - **Radio arbitration** — one monitor interface can only listen on
//!   one channel at a time, so channel-hopping attacks are grouped:
//!   jobs on the same channel run concurrently, jobs on different
//!   channels are interleaved.
//! - **Job lifecycle** — Queued → Running → (Cracked | Captured |
//!   Exhausted | Failed), with per-job progress snapshots the GUI can
//!   poll.
//! - **Priority** — PMKID jobs run first (fast, passive), then WPS
//!   Pixie Dust (fast, active), then handshake capture (needs
//!   clients), then wordlist cracking (slow). The operator can pin a
//!   job to the front.
//!
//! ## What this module does NOT do
//!
//! It doesn't touch the radio directly — every job is a call into one
//! of the existing attack modules (`pmkid`, `wps`, `deauth`,
//! `evil_twin`). This module is pure scheduling + state.

use crate::cracker::{CrackJob, CrackJobStatus, CrackTarget};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The kind of attack a job represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackKind {
    PmkidHarvest,
    WpsPixieDust,
    HandshakeCapture,
    HiddenSsidRecovery,
    Cracking,
}

impl AttackKind {
    /// Default scheduling priority — lower runs first.
    pub fn priority(&self) -> u32 {
        match self {
            AttackKind::PmkidHarvest => 10,
            AttackKind::WpsPixieDust => 20,
            AttackKind::HandshakeCapture => 30,
            AttackKind::HiddenSsidRecovery => 40,
            AttackKind::Cracking => 50,
        }
    }
}

/// A schedulable attack job.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttackJob {
    pub id: u64,
    pub kind: AttackKind,
    /// Target BSSID (empty for global jobs like cracking).
    pub bssid: String,
    pub essid: String,
    /// Channel the attack operates on — the arbitration key.
    pub channel: u8,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Human-readable label for the GUI.
    pub label: String,
    pub status: AttackJobStatus,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    /// Free-text result ("PMKID captured", "timeout", "PIN recovered: ...").
    pub result: Option<String>,
}

impl AttackJob {
    pub fn new(kind: AttackKind, bssid: &str, essid: &str, channel: u8, timeout_secs: u64) -> Self {
        Self {
            id: next_job_id(),
            kind,
            bssid: bssid.into(),
            essid: essid.into(),
            channel,
            timeout_secs,
            label: format!("{kind:?} {essid}"),
            status: AttackJobStatus::Queued,
            created_at: chrono::Utc::now().to_rfc3339(),
            started_at: None,
            finished_at: None,
            result: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackJobStatus {
    Queued,
    Running,
    Captured,
    Cracked,
    Exhausted,
    Failed,
}

impl AttackJobStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            AttackJobStatus::Captured
                | AttackJobStatus::Cracked
                | AttackJobStatus::Exhausted
                | AttackJobStatus::Failed
        )
    }
}

fn next_job_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Shared scheduler state.
#[derive(Default)]
pub struct Scheduler {
    jobs: Vec<AttackJob>,
    /// Channel → currently-running job id (radio arbitration).
    channel_locks: HashMap<u8, u64>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a job. Returns its assigned id.
    pub fn submit(&mut self, mut job: AttackJob) -> u64 {
        job.id = next_job_id();
        let id = job.id;
        self.jobs.push(job);
        id
    }

    /// Submit a batch (wifite-style "attack the top-N networks").
    pub fn submit_batch(&mut self, jobs: Vec<AttackJob>) -> Vec<u64> {
        jobs.into_iter().map(|j| self.submit(j)).collect()
    }

    /// Pick the next runnable job: priority order, skipping jobs whose
    /// channel is occupied by a running job, marking it Running.
    pub fn next_runnable(&mut self) -> Option<AttackJob> {
        // Sort candidates by priority, then by submission order.
        let mut candidates: Vec<(usize, u32)> = self
            .jobs
            .iter()
            .enumerate()
            .filter(|(_, j)| j.status == AttackJobStatus::Queued)
            .map(|(i, j)| (i, j.kind.priority()))
            .collect();
        candidates.sort_by_key(|a| a.1);

        for (idx, _) in candidates {
            let channel = self.jobs[idx].channel;
            let occupied = self
                .channel_locks
                .values()
                .any(|running_id| {
                    self.jobs
                        .iter()
                        .any(|j| j.id == *running_id && j.channel == channel)
                });
            if occupied {
                continue;
            }
            // Claim the channel.
            let id = self.jobs[idx].id;
            self.channel_locks.insert(channel, id);
            let job = &mut self.jobs[idx];
            job.status = AttackJobStatus::Running;
            job.started_at = Some(chrono::Utc::now().to_rfc3339());
            return Some(job.clone());
        }
        None
    }

    /// Mark a job finished, releasing its channel.
    pub fn complete(&mut self, id: u64, status: AttackJobStatus, result: Option<String>) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            job.status = status;
            job.finished_at = Some(chrono::Utc::now().to_rfc3339());
            job.result = result;
        }
        self.channel_locks.retain(|_, v| *v != id);
    }

    /// Snapshot of all jobs (for GUI polling).
    pub fn snapshot(&self) -> Vec<AttackJob> {
        self.jobs.clone()
    }

    /// Per-status counts for the dashboard.
    pub fn status_counts(&self) -> HashMap<AttackJobStatus, usize> {
        let mut m: HashMap<AttackJobStatus, usize> = HashMap::new();
        for j in &self.jobs {
            *m.entry(j.status).or_default() += 1;
        }
        m
    }

    /// Cancel a queued job (running jobs must time out naturally).
    pub fn cancel(&mut self, id: u64) -> bool {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            if job.status == AttackJobStatus::Queued {
                job.status = AttackJobStatus::Failed;
                job.result = Some("cancelled by operator".into());
                return true;
            }
        }
        false
    }
}

/// The pool runner: spawns `workers` threads that pull from the
/// scheduler until the queue is drained or `deadline` passes.
///
/// `attack_fn` is the callback the agent provides — it receives the
/// job and returns the terminal status + result text. Keeping the
/// actual radio work behind a closure lets tests inject a fake.
pub fn run_pool<F>(
    scheduler: Arc<Mutex<Scheduler>>,
    workers: usize,
    deadline: Instant,
    attack_fn: F,
) where
    F: Fn(&AttackJob) -> (AttackJobStatus, Option<String>) + Send + Sync + 'static,
{
    let attack_fn = Arc::new(attack_fn);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let sched = Arc::clone(&scheduler);
        let f = Arc::clone(&attack_fn);
        handles.push(std::thread::spawn(move || {
            while Instant::now() < deadline {
                let job = {
                    let mut s = sched.lock().unwrap_or_else(|p| p.into_inner());
                    s.next_runnable()
                };
                let Some(job) = job else {
                    // Queue drained (or all channels busy) — small backoff.
                    std::thread::sleep(Duration::from_millis(200));
                    let s = sched.lock().unwrap_or_else(|p| p.into_inner());
                    if s.status_counts()
                        .get(&AttackJobStatus::Queued)
                        .copied()
                        .unwrap_or(0)
                        == 0
                        && s.status_counts()
                            .get(&AttackJobStatus::Running)
                            .copied()
                            .unwrap_or(0)
                            == 0
                    {
                        drop(s);
                        return;
                    }
                    drop(s);
                    continue;
                };
                let (status, result) = f(&job);
                let mut s = sched.lock().unwrap_or_else(|p| p.into_inner());
                s.complete(job.id, status, result);
            }
        }));
    }
    // Join only until the deadline: a worker stuck inside attack_fn past the
    // deadline must not stall the caller (the pool's exit condition is the
    // deadline). An unfinished JoinHandle detaches on drop — the straggler
    // completes its in-flight call and exits its loop on its own.
    for h in handles {
        while Instant::now() < deadline && !h.is_finished() {
            std::thread::sleep(Duration::from_millis(50));
        }
        if h.is_finished() {
            let _ = h.join();
        } // else: drop(h) detaches the still-running worker
    }
}

/// Bridge: convert a captured-material list into a prioritized attack
/// batch (the wifite "auto" flow).
pub fn plan_batch(
    targets: &[(String, String, u8, bool, bool)], // (bssid, essid, channel, wps, hidden)
    timeout_per_target: u64,
) -> Vec<AttackJob> {
    let mut jobs = Vec::new();
    for (bssid, essid, channel, wps, hidden) in targets {
        if *hidden {
            jobs.push(AttackJob::new(
                AttackKind::HiddenSsidRecovery,
                bssid,
                essid,
                *channel,
                timeout_per_target,
            ));
            continue;
        }
        // PMKID first for every WPA2 target.
        jobs.push(AttackJob::new(
            AttackKind::PmkidHarvest,
            bssid,
            essid,
            *channel,
            timeout_per_target.min(60),
        ));
        if *wps {
            jobs.push(AttackJob::new(
                AttackKind::WpsPixieDust,
                bssid,
                essid,
                *channel,
                timeout_per_target.min(120),
            ));
        }
        jobs.push(AttackJob::new(
            AttackKind::HandshakeCapture,
            bssid,
            essid,
            *channel,
            timeout_per_target,
        ));
    }
    jobs
}

/// Helper to build a crack queue entry from a captured handshake file.
pub fn to_crack_job(hashfile: &Path, wordlist: &Path, id: &str) -> Option<CrackJob> {
    let target = CrackTarget::from_hashfile(hashfile).ok()?;
    Some(CrackJob {
        id: id.into(),
        target,
        hashfile: hashfile.to_path_buf(),
        wordlist: wordlist.to_path_buf(),
        rules: None,
        created_at: chrono::Utc::now().to_rfc3339(),
        status: CrackJobStatus::Queued,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(kind: AttackKind, bssid: &str, channel: u8) -> AttackJob {
        AttackJob::new(kind, bssid, "TestNet", channel, 60)
    }

    #[test]
    fn job_ids_are_sequential() {
        let j1 = job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:01", 6);
        let j2 = job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:02", 6);
        assert!(j2.id > j1.id);
    }

    #[test]
    fn priority_orders_pmkid_before_cracking() {
        assert!(AttackKind::PmkidHarvest.priority() < AttackKind::Cracking.priority());
        assert!(AttackKind::WpsPixieDust.priority() < AttackKind::HandshakeCapture.priority());
    }

    #[test]
    fn scheduler_runs_highest_priority_first() {
        let mut s = Scheduler::new();
        let crack = job(AttackKind::Cracking, "aa:bb:cc:dd:ee:01", 6);
        let pmkid = job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:02", 6);
        s.submit(crack);
        s.submit(pmkid);

        let next = s.next_runnable().unwrap();
        assert_eq!(next.kind, AttackKind::PmkidHarvest);
        assert_eq!(next.status, AttackJobStatus::Running);
    }

    #[test]
    fn channel_arbitration_blocks_same_channel() {
        let mut s = Scheduler::new();
        let j1 = job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:01", 6);
        let j2 = job(AttackKind::WpsPixieDust, "aa:bb:cc:dd:ee:02", 6);
        let j3 = job(AttackKind::HandshakeCapture, "aa:bb:cc:dd:ee:03", 11);
        s.submit(j1);
        s.submit(j2);
        s.submit(j3);

        // First pull: highest priority on any channel → PMKID (ch 6).
        let first = s.next_runnable().unwrap();
        assert_eq!(first.kind, AttackKind::PmkidHarvest);

        // Second pull: ch 6 is locked → jump to ch 11 job (Handshake),
        // skipping the ch-6 WPS job despite its higher priority.
        let second = s.next_runnable().unwrap();
        assert_eq!(second.channel, 11);
    }

    #[test]
    fn complete_releases_channel() {
        let mut s = Scheduler::new();
        let j1 = job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:01", 6);
        let j2 = job(AttackKind::WpsPixieDust, "aa:bb:cc:dd:ee:02", 6);
        let id1 = s.submit(j1);
        s.submit(j2);

        let first = s.next_runnable().unwrap();
        assert_eq!(first.channel, 6);
        s.complete(id1, AttackJobStatus::Captured, Some("PMKID ok".into()));

        // Channel 6 is free again → WPS job can run.
        let second = s.next_runnable().unwrap();
        assert_eq!(second.kind, AttackKind::WpsPixieDust);
    }

    #[test]
    fn cancel_only_affects_queued_jobs() {
        let mut s = Scheduler::new();
        let id = s.submit(job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:01", 6));
        assert!(s.cancel(id));
        assert!(!s.cancel(id)); // already terminal

        // Running jobs can't be cancelled via this path.
        let id2 = s.submit(job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:02", 6));
        let _ = s.next_runnable();
        assert!(!s.cancel(id2));
    }

    #[test]
    fn status_counts_aggregate() {
        let mut s = Scheduler::new();
        let id1 = s.submit(job(AttackKind::PmkidHarvest, "aa:bb:cc:dd:ee:01", 6));
        s.submit(job(AttackKind::WpsPixieDust, "aa:bb:cc:dd:ee:02", 11));
        let _ = s.next_runnable();
        s.complete(id1, AttackJobStatus::Captured, None);

        let counts = s.status_counts();
        assert_eq!(counts.get(&AttackJobStatus::Captured), Some(&1));
        assert_eq!(counts.get(&AttackJobStatus::Queued), Some(&1));
    }

    #[test]
    fn run_pool_drains_queue_with_fake_attack() {
        let sched = Arc::new(Mutex::new(Scheduler::new()));
        for i in 0..4 {
            sched
                .lock()
                .unwrap()
                .submit(job(AttackKind::PmkidHarvest, &format!("aa:bb:cc:dd:ee:0{i}"), 6 + i as u8));
        }
        run_pool(
            Arc::clone(&sched),
            2,
            Instant::now() + Duration::from_secs(5),
            |j| {
                // Fake instant success.
                (AttackJobStatus::Captured, Some(format!("done {}", j.bssid)))
            },
        );
        let counts = sched.lock().unwrap_or_else(|p| p.into_inner()).status_counts();
        assert_eq!(counts.get(&AttackJobStatus::Captured), Some(&4));
        assert_eq!(counts.get(&AttackJobStatus::Queued), None);
    }

    #[test]
    fn run_pool_respects_deadline_on_stuck_jobs() {
        let sched = Arc::new(Mutex::new(Scheduler::new()));
        // One job; the fake attack sleeps forever — the pool must exit
        // at the deadline without hanging the test.
        sched
            .lock()
            .unwrap()
            .submit(job(AttackKind::Cracking, "aa:bb:cc:dd:ee:01", 6));
        let started = Instant::now();
        run_pool(
            Arc::clone(&sched),
            1,
            Instant::now() + Duration::from_millis(300),
            |_j| {
                std::thread::sleep(Duration::from_secs(30));
                (AttackJobStatus::Cracked, None)
            },
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn plan_batch_generates_pmkid_wps_handshake_for_wps_targets() {
        let targets = vec![
            ("aa:bb:cc:dd:ee:01".into(), "WithWps".into(), 6u8, true, false),
        ];
        let jobs = plan_batch(&targets, 120);
        let kinds: Vec<AttackKind> = jobs.iter().map(|j| j.kind).collect();
        assert_eq!(
            kinds,
            vec![
                AttackKind::PmkidHarvest,
                AttackKind::WpsPixieDust,
                AttackKind::HandshakeCapture
            ]
        );
    }

    #[test]
    fn plan_batch_skips_wps_for_non_wps_targets() {
        let targets = vec![
            ("aa:bb:cc:dd:ee:01".into(), "NoWps".into(), 6u8, false, false),
        ];
        let jobs = plan_batch(&targets, 120);
        let kinds: Vec<AttackKind> = jobs.iter().map(|j| j.kind).collect();
        assert_eq!(
            kinds,
            vec![AttackKind::PmkidHarvest, AttackKind::HandshakeCapture]
        );
    }

    #[test]
    fn plan_batch_hidden_targets_get_hidden_recovery_only() {
        let targets = vec![
            ("aa:bb:cc:dd:ee:01".into(), "<hidden>".into(), 6u8, false, true),
        ];
        let jobs = plan_batch(&targets, 120);
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].kind, AttackKind::HiddenSsidRecovery);
    }

    #[test]
    fn plan_batch_caps_pmkid_timeout_at_60() {
        let targets = vec![
            ("aa:bb:cc:dd:ee:01".into(), "X".into(), 6u8, false, false),
        ];
        let jobs = plan_batch(&targets, 600);
        let pmkid = jobs.iter().find(|j| j.kind == AttackKind::PmkidHarvest).unwrap();
        assert_eq!(pmkid.timeout_secs, 60);
    }

    #[test]
    fn to_crack_job_sniffs_target_from_hashfile() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!(
            "sched-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hf = dir.join("test.hc22000");
        let mut f = std::fs::File::create(&hf).unwrap();
        f.write_all(b"WPA*02*abcd*0102*0304**\n").unwrap();
        let wl = dir.join("w.txt");
        std::fs::File::create(&wl).unwrap();

        let job = to_crack_job(&hf, &wl, "j-1").unwrap();
        assert_eq!(job.id, "j-1");
        assert_eq!(job.target, CrackTarget::Handshake);
        assert_eq!(job.status, CrackJobStatus::Queued);
    }

    #[test]
    fn to_crack_job_returns_none_for_bad_hashfile() {
        let bad = Path::new("/nonexistent/x.hc22000");
        assert!(to_crack_job(bad, Path::new("/tmp/w.txt"), "j-2").is_none());
    }

    #[test]
    fn terminal_statuses_are_detected() {
        assert!(AttackJobStatus::Captured.is_terminal());
        assert!(AttackJobStatus::Cracked.is_terminal());
        assert!(AttackJobStatus::Exhausted.is_terminal());
        assert!(AttackJobStatus::Failed.is_terminal());
        assert!(!AttackJobStatus::Queued.is_terminal());
        assert!(!AttackJobStatus::Running.is_terminal());
    }
}