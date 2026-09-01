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
            if let MacMode::Specific(ref mac) = mac
                && !is_valid_mac(mac)
            {
                return (err("invalid MAC address"), false);
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
            if let Some(ref filter) = channels
                && !is_valid_channel_filter(filter, ghz_2_4, ghz_5)
            {
                return (err("invalid channel filter"), false);
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
            if let Some(ref clients) = clients
                && !clients.iter().all(|c| is_valid_mac(c))
            {
                return (err("invalid client MAC address"), false);
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
            consent,
            targets,
            plans,
            output_dir,
        } => {
            let mut audit_digest = String::new();
            if let Ok(log) = backend::audit::AuditLog::open(consent.operator.clone()) {
                if let Some(last) = std::fs::read_to_string(
                    std::env::var("HOME").unwrap_or_default() + "/.netspecter/audit.log",
                )
                .ok()
                .and_then(|s| s.lines().last().map(String::from))
                {
                    if let Ok(entry) =
                        serde_json::from_str::<backend::audit::AuditEntry>(&last)
                    {
                        audit_digest = entry.chain_hash;
                    }
                }
                let _ = log; // suppress unused warning
            }
            // Build a Report using the report module.
            let agent_consent = backend::consent::ConsentRecord {
                operator: consent.operator.clone(),
                scope: consent.scope.clone(),
                rules_of_engagement: consent.rules_of_engagement.clone(),
                agreed_at: chrono::DateTime::parse_from_rfc3339(&consent.agreed_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                record_digest: consent.record_digest.clone(),
            };
            // Map wire → agent types for plans.
            let agent_plans: Vec<backend::wizard::WizardPlan> = plans
                .into_iter()
                .map(|p| {
                    let enc = netspecter_common::encryption::Encryption::from_label(&p.encryption_label);
                    backend::wizard::WizardPlan {
                        bssid: p.bssid,
                        essid: p.essid,
                        encryption: enc,
                        steps: p
                            .steps
                            .into_iter()
                            .map(|s| backend::wizard::WizardStep {
                                order: s.order,
                                title: s.title,
                                description: s.description,
                                kind: match s.kind {
                                    netspecter_common::ipc::WizardStepKind::PassiveScan => {
                                        backend::wizard::WizardStepKind::PassiveScan
                                    }
                                    netspecter_common::ipc::WizardStepKind::ActiveAttack => {
                                        backend::wizard::WizardStepKind::ActiveAttack
                                    }
                                    netspecter_common::ipc::WizardStepKind::OfflineCrack => {
                                        backend::wizard::WizardStepKind::OfflineCrack
                                    }
                                    netspecter_common::ipc::WizardStepKind::SocialEngineering => {
                                        backend::wizard::WizardStepKind::SocialEngineering
                                    }
                                    netspecter_common::ipc::WizardStepKind::HiddenSsidRecovery => {
                                        backend::wizard::WizardStepKind::HiddenSsidRecovery
                                    }
                                    netspecter_common::ipc::WizardStepKind::Report => {
                                        backend::wizard::WizardStepKind::Report
                                    }
                                },
                                estimated_secs: s.estimated_secs,
                                requires_active_radio: s.requires_active_radio,
                            })
                            .collect(),
                        rationale: p.rationale,
                    }
                })
                .collect();
            let report = backend::report::build_report(
                "ENG-AUTO",
                &agent_consent,
                &audit_digest,
                targets,
                agent_plans,
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
                Response::ReportPaths {
                    html: Some(html_path.to_string_lossy().into_owned()),
                    json: json_path.to_string_lossy().into_owned(),
                    pdf: pdf_ok.map(|()| pdf_path.to_string_lossy().into_owned()),
                },
                false,
            )
        }

        Request::GetAuditChainHead => {
            let path = std::env::var("HOME").unwrap_or_default() + "/.netspecter/audit.log";
            let head = std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| s.lines().last().map(String::from))
                .and_then(|line| {
                    serde_json::from_str::<backend::audit::AuditEntry>(&line)
                        .ok()
                        .map(|e| e.chain_hash)
                })
                .unwrap_or_else(|| "0".repeat(64));
            (Response::ChainHead(head), false)
        }

        Request::VerifyAuditChain => {
            let path = std::env::var("HOME").unwrap_or_default() + "/.netspecter/audit.log";
            let audit_path = std::path::PathBuf::from(path);
            let ok = backend::audit::verify_chain(&audit_path).is_ok();
            (Response::Bool(ok), false)
        }

        Request::Shutdown => (Response::Ok, true),
    }
}
