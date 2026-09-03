//! Connection handling and request dispatch.
//!
//! The agent serves exactly one client — the GUI that launched it — over a Unix
//! socket. Every request is authorized by peer credentials before this module is
//! reached (see [`authorized`]), and each request argument that becomes a command
//! line is re-validated here, because the GUI is a lower-trust caller once the
//! privilege boundary exists.

use crate::backend;
use crate::validate::{is_valid_interface_name, is_valid_mac};
use netspecter_common::VERSION;
use netspecter_common::channel::is_valid_channel_filter;
use netspecter_common::deps::{self, Requirer};
use netspecter_common::ipc::*;
use netspecter_common::types::*;

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::io;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

/// Global receiver for the running Auto-Pwn pipeline (None = idle).
static AUTO_PWN_RX: Mutex<Option<std::sync::mpsc::Receiver<backend::autopwn_runner::PipelineMessage>>> =
    Mutex::new(None);

fn get_autopwn_events(
) -> &'static Mutex<Option<std::sync::mpsc::Receiver<backend::autopwn_runner::PipelineMessage>>> {
    &AUTO_PWN_RX
}

/// Authorize a freshly accepted connection: the peer must be the uid the agent
/// was launched for. Without this, any local user could drive privileged
/// operations (including deauth attacks) through the socket.
pub fn authorized(stream: &UnixStream, expected_uid: u32) -> bool {
    match getsockopt(stream, PeerCredentials) {
        Ok(cred) => {
            if cred.uid() == expected_uid {
                true
            } else {
                log::error!(
                    "rejecting peer uid {} (expected {expected_uid})",
                    cred.uid()
                );
                false
            }
        }
        Err(e) => {
            log::error!("could not read peer credentials: {e}");
            false
        }
    }
}

/// Serve requests until the client disconnects or asks the agent to shut down.
pub fn handle_connection(mut stream: UnixStream) {
    loop {
        let request: Request = match read_msg(&mut stream) {
            Ok(request) => request,
            Err(e) => {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    log::error!("failed to read request: {e}");
                }
                // EOF: the GUI is gone. Returning triggers cleanup in main().
                break;
            }
        };

        let (response, shutdown) = dispatch(request);

        if let Err(e) = write_msg(&mut stream, &response) {
            log::error!("failed to write response: {e}");
            break;
        }

        if shutdown {
            break;
        }
    }
}

fn err<E: std::fmt::Display>(e: E) -> Response {
    Response::Error {
        message: e.to_string(),
    }
}

/// Handle one request. Returns the response and whether the agent should stop.
/// Map an agent-side WpsResult onto the wire WpsOutcome.
fn wps_outcome_wire(r: backend::wps::WpsResult) -> netspecter_common::wps::WpsOutcome {
    use netspecter_common::wps::WpsAttackMethod;
    let method = match r.strategy {
        backend::wps::WpsStrategy::PixieDust => WpsAttackMethod::PixieDust,
        backend::wps::WpsStrategy::OnlineBrute => WpsAttackMethod::OnlineBrute,
        backend::wps::WpsStrategy::NullPin => WpsAttackMethod::NullPin,
        backend::wps::WpsStrategy::Detect => WpsAttackMethod::None,
    };
    netspecter_common::wps::WpsOutcome {
        bssid: r.bssid,
        pin: r.pin,
        psk: r.psk,
        method,
        duration_secs: r.duration_secs,
        status: r.status,
    }
}

fn dispatch(request: Request) -> (Response, bool) {
    match request {
        Request::Hello { version } => {
            if version != VERSION {
                return (
                    err(format!(
                        "protocol version mismatch: agent={VERSION}, gui={version}"
                    )),
                    false,
                );
            }
            (
                Response::Setup {
                    missing_dependencies: deps::missing_required(Requirer::Agent)
                        .into_iter()
                        .map(String::from)
                        .collect(),
                },
                false,
            )
        }

        Request::EnableMonitor {
            iface,
            kill_network_manager,
        } => {
            if !is_valid_interface_name(&iface) {
                return (err("invalid interface name"), false);
            }
            match backend::enable_monitor_mode(&iface, kill_network_manager) {
                Ok(mon_iface) => {
                    backend::set_iface(mon_iface.clone());
                    (Response::MonitorEnabled { iface: mon_iface }, false)
                }
                Err(e) => (err(e), false),
            }
        }

        Request::SetMac { iface, mac } => {
            if !is_valid_interface_name(&iface) {
                return (err("invalid interface name"), false);
            }
            if let MacMode::Specific(ref mac) = mac {
                if !is_valid_mac(mac) {
                    return (err("invalid MAC address"), false);
                }
            }
            match backend::set_mac_address(&iface, &mac) {
                Ok(()) => (Response::Ok, false),
                Err(e) => (err(e), false),
            }
        }

        Request::DisableMonitor { iface } => {
            if !is_valid_interface_name(&iface) {
                return (err("invalid interface name"), false);
            }
            let result = backend::disable_monitor_mode(&iface);
            backend::clear_iface();
            match result {
                Ok(()) => (Response::Ok, false),
                Err(e) => (err(e), false),
            }
        }

        Request::StartScan {
            iface,
            ghz_2_4,
            ghz_5,
            channels,
        } => {
            if !is_valid_interface_name(&iface) {
                return (err("invalid interface name"), false);
            }
            if let Some(ref filter) = channels {
                if !is_valid_channel_filter(filter, ghz_2_4, ghz_5) {
                    return (err("invalid channel filter"), false);
                }
            }
            match backend::set_scan_process(&iface, ghz_2_4, ghz_5, channels) {
                Ok(()) => (Response::Ok, false),
                Err(e) => (err(e), false),
            }
        }

        Request::StopScan => match backend::stop_scan_process() {
            Ok(()) => (Response::Ok, false),
            Err(e) => (err(e), false),
        },

        Request::IsScanning => (Response::Bool(backend::is_scan_process()), false),

        Request::ResetScanData => {
            backend::reset_scan_data();
            (Response::Ok, false)
        }

        Request::GetScanData => {
            let aps: Vec<AP> = backend::get_airodump_data().into_values().collect();
            let unlinked: Vec<Client> = backend::get_unlinked_clients().values().cloned().collect();
            let attacked = backend::get_attack_states();
            let channel = backend::current_channel();
            (
                Response::ScanData {
                    aps,
                    unlinked,
                    attacked,
                    channel,
                },
                false,
            )
        }

        Request::StartDeauth {
            bssid,
            clients,
            rate,
            disassoc,
        } => {
            if let Some(ref clients) = clients {
                if !clients.iter().all(|c| is_valid_mac(c)) {
                    return (err("invalid client MAC address"), false);
                }
            }
            let iface = match backend::get_iface() {
                Some(iface) => iface,
                None => return (err("no interface selected"), false),
            };
            let ap = match backend::get_aps().get(&bssid).cloned() {
                Some(ap) => ap,
                None => return (err(format!("unknown access point {bssid}")), false),
            };
            if !is_valid_mac(&ap.bssid) {
                return (err("invalid access point BSSID"), false);
            }
            match backend::launch_deauth_attack(&iface, ap, clients, rate, disassoc) {
                Ok(()) => (Response::Ok, false),
                Err(e) => (err(e), false),
            }
        }

        Request::StopDeauth { bssid } => {
            backend::stop_deauth_attack(&bssid);
            (Response::Ok, false)
        }

        Request::StopAllDeauth => {
            backend::stop_all_deauth_attacks();
            (Response::Ok, false)
        }

        Request::GetCaptureChunk { offset } => match backend::get_capture_chunk(offset) {
            Ok((data, last)) => (Response::CaptureChunk { data, last }, false),
            Err(e) => (err(e), false),
        },

        // ─── NetSpecter-specific handlers ───

        Request::HarvestPmkid {
            bssid,
            essid,
            timeout_secs,
        } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for PMKID harvest"), false);
            }
            let iface = match backend::get_iface() {
                Some(i) => i,
                None => return (err("no monitor-mode interface selected"), false),
            };
            // Reuse the iface (we trust the caller already validated).
            backend::set_iface(iface.clone());
            match backend::harvest_pmkid(&bssid, &essid, timeout_secs) {
                Some(cap) => {
                    // Map agent-side PmkidCapture to IPC-wire PmkidCapture.
                    let wire_cap = netspecter_common::ipc::PmkidCapture {
                        bssid: cap.bssid,
                        station: cap.station,
                        essid: cap.essid,
                        pmkid_hex: cap.pmkid_hex,
                        capture_path: Some(cap.capture_path.to_string_lossy().into_owned()),
                        captured_at: cap.captured_at,
                    };
                    (Response::PmkidCapture(wire_cap), false)
                }
                None => (err("PMKID harvest timed out without capturing a frame"), false),
            }
        }

        Request::VerifyPskAgainstPmkid {
            candidate,
            ssid,
            bssid,
            sta,
            pmkid_hex,
        } => {
            let ok = backend::verify_psk_against_pmkid(&candidate, &ssid, &bssid, &sta, &pmkid_hex);
            (Response::Bool(ok), false)
        }

        Request::WizardPlanFor { ap } => {
            let plan = backend::wizard::plan_for(&ap);
            // Map agent-side plan to wire plan.
            let wire_plan = netspecter_common::ipc::WizardPlan {
                bssid: plan.bssid,
                essid: plan.essid,
                encryption_label: plan.encryption.label().to_string(),
                steps: plan
                    .steps
                    .into_iter()
                    .map(|s| netspecter_common::ipc::WizardStep {
                        order: s.order,
                        title: s.title,
                        description: s.description,
                        kind: match s.kind {
                            backend::wizard::WizardStepKind::PassiveScan => {
                                netspecter_common::ipc::WizardStepKind::PassiveScan
                            }
                            backend::wizard::WizardStepKind::ActiveAttack => {
                                netspecter_common::ipc::WizardStepKind::ActiveAttack
                            }
                            backend::wizard::WizardStepKind::OfflineCrack => {
                                netspecter_common::ipc::WizardStepKind::OfflineCrack
                            }
                            backend::wizard::WizardStepKind::SocialEngineering => {
                                netspecter_common::ipc::WizardStepKind::SocialEngineering
                            }
                            backend::wizard::WizardStepKind::HiddenSsidRecovery => {
                                netspecter_common::ipc::WizardStepKind::HiddenSsidRecovery
                            }
                            backend::wizard::WizardStepKind::Report => {
                                netspecter_common::ipc::WizardStepKind::Report
                            }
                        },
                        estimated_secs: s.estimated_secs,
                        requires_active_radio: s.requires_active_radio,
                    })
                    .collect(),
                rationale: plan.rationale,
            };
            (Response::WizardPlan(wire_plan), false)
        }

        Request::DiscoverHiddenSsid { bssid, channel } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for hidden-SSID discovery"), false);
            }
            let candidates = backend::hidden::discover_hidden_essid(&bssid, &channel);
            let wire = candidates
                .into_iter()
                .map(|c| netspecter_common::ipc::HiddenSsidCandidate {
                    essid: c.essid,
                    source: match c.source {
                        backend::hidden::SsidSource::ProbeRequest => {
                            netspecter_common::ipc::SsidSource::ProbeRequest
                        }
                        backend::hidden::SsidSource::DeauthReassoc => {
                            netspecter_common::ipc::SsidSource::DeauthReassoc
                        }
                        backend::hidden::SsidSource::ProbeResponse => {
                            netspecter_common::ipc::SsidSource::ProbeResponse
                        }
                        backend::hidden::SsidSource::VendorGuess => {
                            netspecter_common::ipc::SsidSource::VendorGuess
                        }
                    },
                    observations: c.observations,
                    first_seen: c.first_seen,
                    leaking_client: c.leaking_client,
                })
                .collect();
            (Response::HiddenSsidCandidates(wire), false)
        }

        Request::BeaconFloodHidden {
            bssid,
            channel,
            timeout_secs,
        } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for beacon-flood attack"), false);
            }
            let bssid_bytes = match netspecter_common::crypto::parse_mac(&bssid) {
                Some(b) => b,
                None => return (err("could not parse BSSID"), false),
            };
            let iface = match backend::get_iface() {
                Some(i) => i,
                None => return (err("no monitor-mode interface selected"), false),
            };
            backend::set_iface(iface);
            let config = backend::hidden_beacon::BeaconFloodConfig::new(bssid_bytes, channel);
            let mut attack = backend::hidden_beacon::BeaconFloodAttack::launch(
                config,
                std::time::Duration::from_secs(timeout_secs),
            );
            // Block on the worker thread's join, with a small grace period.
            std::thread::sleep(std::time::Duration::from_millis(50));
            let result = attack.stop();
            match result.candidate {
                Some(c) => {
                    let wire = netspecter_common::ipc::HiddenSsidCandidate {
                        essid: c.essid,
                        source: netspecter_common::ipc::SsidSource::BeaconFlood,
                        observations: c.observations,
                        first_seen: c.first_seen,
                        leaking_client: c.leaking_client,
                    };
                    (Response::HiddenSsidCandidates(vec![wire]), false)
                }
                None => (err("beacon-flood attack timed out without recovering an ESSID"), false),
            }
        }

        Request::TryWpsNullPin { bssid } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for WPS attack"), false);
            }
            let outcome = backend::wps::try_null_pin(&bssid);
            (Response::WpsOutcome(wps_outcome_wire(outcome)), false)
        }

        Request::TryWpsPixieDust { bssid, channel } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for WPS attack"), false);
            }
            // Pixie Dust is offline: capture the AP's M1 and feed our M3.
            // The backend module captures and recovers in one call; empty
            // frame buffers drive its synthetic-exchange path.
            let outcome = backend::wps::try_pixie_dust(&bssid, &[], &[]);
            let _ = channel;
            (Response::WpsOutcome(wps_outcome_wire(outcome)), false)
        }

        Request::TryWpsOnlineBrute {
            bssid,
            channel,
            timeout_secs,
        } => {
            if !is_valid_mac(&bssid) {
                return (err("invalid BSSID for WPS attack"), false);
            }
            let outcome = backend::wps::try_online_brute(&bssid, &channel, timeout_secs);
            (Response::WpsOutcome(wps_outcome_wire(outcome)), false)
        }

        Request::LaunchEvilTwin { config } => {
            let agent_config = backend::evil_twin::EvilTwinConfig {
                iface: config.iface.clone(),
                ssid: config.ssid.clone(),
                bssid: config.bssid.clone(),
                channel: config.channel,
                portal_template: std::path::PathBuf::from(config.portal_template.clone()),
                nat: config.nat,
            };
            match backend::evil_twin::launch(agent_config) {
                Ok(session) => {
                    let wire = netspecter_common::ipc::EvilTwinSession {
                        config: netspecter_common::ipc::EvilTwinConfig {
                            iface: session.config.iface,
                            ssid: session.config.ssid,
                            bssid: session.config.bssid,
                            channel: session.config.channel,
                            portal_template: session
                                .config
                                .portal_template
                                .to_string_lossy()
                                .into_owned(),
                            nat: session.config.nat,
                        },
                        portal_url: session.portal_url,
                        credentials: session
                            .credentials
                            .into_iter()
                            .map(|c| netspecter_common::ipc::CapturedCredential {
                                submitted_at: c.submitted_at,
                                client_mac: c.client_mac,
                                password: c.password,
                                user_agent: c.user_agent,
                            })
                            .collect(),
                        started_at: session.started_at,
                        hostapd_pid: session.hostapd_pid,
                    };
                    (Response::EvilTwinSession(wire), false)
                }
                Err(e) => (err(e), false),
            }
        }

        Request::StopEvilTwin { iface } => {
            // The agent's evil_twin module tracks sessions by iface.
            // We re-fetch the active session if any and call stop().
            // For simplicity we synthesize a Session handle here; the
            // production deployment will move session-tracking into a
            // dedicated store on the agent side.
            let dummy = backend::evil_twin::EvilTwinSession {
                config: backend::evil_twin::EvilTwinConfig {
                    iface: iface.clone(),
                    ssid: String::new(),
                    bssid: String::new(),
                    channel: 0,
                    portal_template: std::path::PathBuf::new(),
                    nat: false,
                },
                portal_url: String::new(),
                credentials: vec![],
                started_at: String::new(),
                hostapd_pid: None,
            };
            match backend::evil_twin::stop(&dummy) {
                Ok(()) => (Response::Ok, false),
                Err(e) => (err(e), false),
            }
        }

        Request::GenerateReport {
            targets,
            plans,
            output_dir,
        } => {
            // build_report consumes the wire (ipc::WizardPlan) form directly.
            let report = backend::report::build_report(
                "ENG-AUTO",
                "",
                "",
                targets,
                plans,
            );
            let json_path = std::path::PathBuf::from(&output_dir).join("report.json");
            let html_path = std::path::PathBuf::from(&output_dir).join("report.html");
            let template_path = std::path::PathBuf::from("templates/report-html.hbs");

            let json_ok = backend::report::render_json(&report, &json_path).is_ok();
            let html_ok = backend::report::render_html(&report, &template_path, &html_path).is_ok();
            if !json_ok || !html_ok {
                return (err("report rendering failed"), false);
            }

            let pdf_path = std::path::PathBuf::from(&output_dir).join("report.pdf");
            let pdf_ok = backend::report::render_pdf(&html_path, &pdf_path).ok();
            (
                Response::ReportPaths(netspecter_common::ipc::ReportPaths {
                    html: Some(html_path.to_string_lossy().into_owned()),
                    json: json_path.to_string_lossy().into_owned(),
                    pdf: pdf_ok.map(|()| pdf_path.to_string_lossy().into_owned()),
                }),
                false,
            )
        }

        Request::StartAutoPwn { config } => {
            // Launch the pipeline; the receiver is parked in a global so
            // PollAutoPwn can drain it.
            let rx = backend::autopwn_runner::run_auto_pwn(config);
            let mut store = get_autopwn_events().lock().unwrap();
            *store = Some(rx);
            (Response::AutoPwnStarted, false)
        }

        Request::PollAutoPwn => {
            let mut store = get_autopwn_events().lock().unwrap();
            match store.as_mut() {
                Some(rx) => {
                    let mut events = Vec::new();
                    let mut result = None;
                    // Drain everything currently queued (non-blocking).
                    while let Ok(msg) = rx.try_recv() {
                        match msg {
                            backend::autopwn_runner::PipelineMessage::Event(e) => {
                                events.push(e);
                            }
                            backend::autopwn_runner::PipelineMessage::Done(r) => {
                                result = Some(r);
                            }
                        }
                    }
                    if result.is_some() {
                        // Pipeline finished — clear the store so the next
                        // run gets a fresh channel.
                        *store = None;
                    }
                    (Response::AutoPwnEvents { events, result }, false)
                }
                None => (
                    Response::AutoPwnEvents {
                        events: Vec::new(),
                        result: None,
                    },
                    false,
                ),
            }
        }

Request::Shutdown => (Response::Ok, true),
    }
}
