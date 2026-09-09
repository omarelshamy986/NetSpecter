//! IPC event handlers — wires up the GTK4 buttons in each page to
//! the IPC client (see `crate::ipc_client::IpcClient`).
//!
//! Each page exposes a `wire_handlers(&shared_state)` method that takes
//! the shared app state and connects the buttons. The handlers run their
//! IPC calls on a worker thread (because GTK4 runs everything on the main
//! thread) and bounce results back to the main loop as plain-`Send`
//! messages over an `std::sync::mpsc` channel; a `glib::timeout_add_local`
//! pump on the main thread drains the queue and applies the UI updates.
//!
//! ## Why worker threads + a channel pump?
//!
//! IPC calls block on the agent's response; running them on the main GTK4
//! thread would freeze the UI for the duration. GTK4 widgets are not
//! `Send`, so the worker thread must never capture them — it sends
//! `UiMsg` values instead, and only the main-thread pump touches widgets.

// Handlers are wired from the app shell (itself driven from main());
// under test builds the whole wiring is gone, so the dead-code lint
// needs this allowance to not flag every wire_* entry point.
#![allow(dead_code)]

use gtk4::glib;
use gtk4::prelude::*;

use crate::app_shell::SharedState;
use crate::frontend::pages::{
    AuditLogPage, EvilTwinPage, PmkidPage, ReportsPage, SmartWizardPage,
};

/// Plain-`Send` messages a worker thread sends back to the GUI pump.
pub enum UiMsg {
    /// Replace the wizard plan checklist.
    WizardPlan(netspecter_common::ipc::WizardPlan),
    /// Set the PMKID result label.
    PmkidResult(String),
    /// Log a failure at info level (rendered into the status label by
    /// the pump when applicable).
    Failure(String),
    /// Evil-twin launch succeeded — note in the status line.
    EvilTwinLaunched { ssid: String, iface: String },
    /// Evil-twin launch failed — note in the status line.
    EvilTwinFailed(String),
    /// Report generation finished — rows to append to the Reports list.
    ReportReady { rows: Vec<(String, String)> },
}

/// Spawn `f` on a worker thread, forwarding its `UiMsg` output to a
/// main-thread pump that owns no widgets.
pub fn spawn_with_pump<F>(state: &SharedState, f: F)
where
    F: FnOnce(std::sync::mpsc::Sender<UiMsg>) + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel::<UiMsg>();
    std::thread::spawn(move || f(tx));

    // Main-thread pump: drains whatever has arrived every 150ms.
    let state = state.clone();
    glib::timeout_add_local(std::time::Duration::from_millis(150), move || {
        loop {
            match rx.try_recv() {
                Ok(msg) => apply_msg(&state, msg),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    // Worker done and queue drained — stop the pump.
                    return glib::ControlFlow::Break;
                }
            }
        }
        glib::ControlFlow::Continue
    });
}

/// Apply one worker message to the UI. Runs on the main thread only.
fn apply_msg(state: &SharedState, msg: UiMsg) {
    let s = state.borrow();
    match msg {
        UiMsg::WizardPlan(plan) => {
            s.wizard_page.render_plan(&plan);
        }
        UiMsg::PmkidResult(text) => {
            s.pmkid_page.result_label.set_text(&text);
        }
        UiMsg::Failure(text) => {
            log::warn!("{text}");
            s.status_label.set_text(&text);
        }
        UiMsg::EvilTwinLaunched { ssid, iface } => {
            s.evil_twin_page.stop_btn.set_sensitive(true);
            s.status_label
                .set_text(&format!("Evil twin launched: {ssid} on {iface}"));
        }
        UiMsg::EvilTwinFailed(text) => {
            s.status_label.set_text(&text);
        }
        UiMsg::ReportReady { rows } => {
            for (title, path) in rows {
                let row = ReportsPage::build_report_row(&title, &path);
                s.reports_page.list.append(&row);
            }
        }
    }
}

/// Connect every page's UI handlers to the shared IPC client.
///
/// Idempotent — safe to call once per page.
pub fn wire_all(state: SharedState) {
    // All borrows here are immutable (RefCell allows them to coexist);
    // no `wire_handlers` takes a shared mutable borrow during wiring.
    let s = state.borrow();
    s.autopwn_page.wire_handlers(state.clone());
    s.wizard_page.wire_handlers(state.clone());
    s.pmkid_page.wire_handlers(state.clone());
    s.evil_twin_page.wire_handlers(state.clone());
    s.hidden_networks_page.wire_handlers(state.clone());
    s.reports_page.wire_handlers(state.clone());
    s.audit_log_page.wire_handlers(state.clone());
}

// ─────────────────────────────────────────────────────────────────
// SmartWizardPage
// ─────────────────────────────────────────────────────────────────

impl SmartWizardPage {
    pub fn wire_handlers(&self, state: SharedState) {
        // The "Generate plan" path: dispatch WizardPlanFor and render the
        // resulting plan into the page's checklist. The worker sends the
        // plan back as a `UiMsg`; the main-thread pump renders it.
        let state_for_target = state.clone();
        if let Some(dropdown) = self.target_dropdown() {
            dropdown.connect_selected_notify(move |dd| {
                let s = state_for_target.borrow();
                let idx = dd.selected();
                let aps = s.wizard_page.ap_snapshot();
                if (idx as usize) < aps.len() {
                    let ap = aps[idx as usize].clone();
                    let ipc = s.ipc.clone();
                    drop(s);
                    spawn_with_pump(&state_for_target, move |tx| {
                        match ipc.wizard_plan_for(ap) {
                            Ok(plan) => {
                                let _ = tx.send(UiMsg::WizardPlan(plan));
                            }
                            Err(e) => {
                                let _ = tx.send(UiMsg::Failure(format!(
                                    "wizard_plan_for failed: {e}"
                                )));
                            }
                        }
                    });
                }
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────
// PmkidPage
// ─────────────────────────────────────────────────────────────────

impl PmkidPage {
    pub fn wire_handlers(&self, state: SharedState) {
        // The "Capture PMKID" button dispatches HarvestPmkid on a worker
        // thread and updates the result label when the agent responds.
        let capture_btn = self.capture_btn.clone();
        let state_for_btn = state.clone();

        capture_btn.connect_clicked(move |_btn| {
            let s = state_for_btn.borrow();
            let Some(ap) = s.selected_ap() else {
                return;
            };
            let ipc = s.ipc.clone();
            let bssid = ap.bssid.clone();
            let essid = ap.essid.clone();
            drop(s);

            spawn_with_pump(&state_for_btn, move |tx| {
                match ipc.harvest_pmkid(&bssid, &essid, 60) {
                    Ok(cap) => {
                        let path = cap.capture_path.unwrap_or_default();
                        let _ = tx.send(UiMsg::PmkidResult(format!(
                            "Captured!\nBSSID: {}\nESSID: {}\nPMKID: {}\nAt: {}\nCapture: {}",
                            cap.bssid, cap.essid, cap.pmkid_hex, cap.captured_at, path
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(UiMsg::PmkidResult(format!("harvest failed: {e}")));
                    }
                }
            });
        });

        // Verify: dispatch VerifyPskAgainstPmkid with the typed
        // candidate from the entry field, then display "match"/"no match".
        let verify_btn = self.verify_btn.clone();
        let entry = self.verify_entry.clone();
        let state_for_verify = state.clone();

        verify_btn.connect_clicked(move |_btn| {
            let candidate = entry.text().to_string();
            if candidate.is_empty() {
                return;
            }
            let s = state_for_verify.borrow();
            let Some(ap) = s.selected_ap() else { return };
            let ipc = s.ipc.clone();
            let bssid = ap.bssid.clone();
            let essid = ap.essid.clone();
            drop(s);
            let sta = "02:00:00:00:01:00".to_string();
            // The captured PMKID should come from the latest harvest. For
            // now we re-run the harvest quickly and use the result.
            spawn_with_pump(&state_for_verify, move |tx| {
                let cap = match ipc.harvest_pmkid(&bssid, &essid, 60) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let pmkid_hex = cap.pmkid_hex.clone();
                let ok = ipc
                    .verify_psk(&candidate, &essid, &bssid, &sta, &pmkid_hex)
                    .unwrap_or(false);
                let label_text = if ok {
                    format!("✓ Match: '{candidate}' is the network PSK")
                } else {
                    format!("✗ No match for '{candidate}'")
                };
                let _ = tx.send(UiMsg::PmkidResult(format!(
                    "{label_text}\nBSSID: {bssid}\nESSID: {essid}\nPMKID: {pmkid_hex}"
                )));
            });
        });

        // Open the capture PCAP in Wireshark via xdg-open.
        let open_pcap_btn = self.open_pcap_btn.clone();
        let result_label_for_open = self.result_label.clone();
        open_pcap_btn.connect_clicked(move |_btn| {
            let text = result_label_for_open.text().to_string();
            if let Some(path) = extract_capture_path(&text) {
                let _ = std::process::Command::new("wireshark").arg(&path).spawn();
            }
        });
    }
}

fn extract_capture_path(text: &str) -> Option<String> {
    // The result label's last line carries "Capture: <path>" — parse that.
    for line in text.lines().rev() {
        if let Some(rest) = line.strip_prefix("Capture: ") {
            return Some(rest.to_string());
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────
// EvilTwinPage
// ─────────────────────────────────────────────────────────────────

impl EvilTwinPage {
    pub fn wire_handlers(&self, state: SharedState) {
        // Launch the Evil Twin session.
        let launch_btn = self.launch_btn.clone();
        let iface_entry = self.iface_entry.clone();
        let ssid_entry = self.ssid_entry.clone();
        let bssid_entry = self.bssid_entry.clone();
        let channel_spin = self.channel_spin.clone();
        let nat_switch = self.nat_switch.clone();
        let state_for_launch = state.clone();

        launch_btn.connect_clicked(move |_btn| {
            let iface = iface_entry.text().to_string();
            let ssid = ssid_entry.text().to_string();
            let bssid = bssid_entry.text().to_string();
            let channel = channel_spin.value() as u8;
            let nat = nat_switch.is_active();

            if iface.is_empty() || ssid.is_empty() {
                return;
            }

            let config = netspecter_common::ipc::EvilTwinConfig {
                iface: iface.clone(),
                ssid: ssid.clone(),
                bssid,
                channel,
                portal_template: "templates/portal-router.html".to_string(),
                nat,
            };

            let ipc = state_for_launch.borrow().ipc.clone();
            spawn_with_pump(&state_for_launch, move |tx| {
                match ipc.launch_evil_twin(config) {
                    Ok(session) => {
                        let _ = tx.send(UiMsg::EvilTwinLaunched {
                            ssid: session.config.ssid,
                            iface: session.config.iface,
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(UiMsg::EvilTwinFailed(format!(
                            "launch failed: {e}"
                        )));
                    }
                }
            });
        });

        // Stop the Evil Twin session.
        let state_for_stop = state.clone();
        let iface_entry_for_stop = self.iface_entry.clone();
        self.stop_btn
            .connect_clicked(move |_btn| {
                let iface = iface_entry_for_stop.text().to_string();
                let ipc = state_for_stop.borrow().ipc.clone();
                std::thread::spawn(move || {
                    let _ = ipc.stop_evil_twin(&iface);
                });
            });
    }
}

// ─────────────────────────────────────────────────────────────────
// ReportsPage
// ─────────────────────────────────────────────────────────────────

impl ReportsPage {
    pub fn wire_handlers(&self, state: SharedState) {
        let generate_btn = self.generate_btn.clone();
        let state_for_gen = state.clone();

        generate_btn.connect_clicked(move |_btn| {
            let ipc = state_for_gen.borrow().ipc.clone();

            // Build a single-target plan and ask the agent to render the
            // report into a tmp directory. v1.3.0 no longer requires a
            // ConsentRecord — the engagement_id is sufficient.
            let target = netspecter_common::ipc::TargetReport {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
                essid: "TestNet".into(),
                encryption: "WPA2".into(),
                channel: "6".into(),
                clients_observed: 0,
                handshake_captured: false,
                pmkid_captured: true,
                wps_recovered: false,
                hidden_recovery: None,
            };
            let plan = netspecter_common::ipc::WizardPlan {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
                essid: "TestNet".into(),
                encryption_label: "WPA2".into(),
                steps: vec![],
                rationale: "demo plan".into(),
            };

            let output_dir = format!(
                "/tmp/netspecter-reports/{}",
                chrono::Utc::now().timestamp()
            );
            spawn_with_pump(&state_for_gen, move |tx| {
                let _ = std::fs::create_dir_all(&output_dir);
                match ipc.generate_report(vec![target], vec![plan], &output_dir) {
                    Ok(paths) => {
                        let mut rows = vec![(
                            "Demo engagement".to_string(),
                            paths.json.clone(),
                        )];
                        if let Some(html) = &paths.html {
                            rows.push(("Demo (HTML)".to_string(), html.clone()));
                        }
                        let _ = tx.send(UiMsg::ReportReady { rows });
                    }
                    Err(e) => {
                        let _ = tx.send(UiMsg::Failure(format!(
                            "generate_report failed: {e}"
                        )));
                    }
                }
            });
        });
    }
}

// ─────────────────────────────────────────────────────────────────
// AuditLogPage
// ─────────────────────────────────────────────────────────────────

impl AuditLogPage {
    pub fn wire_handlers(&self, _state: SharedState) {
        // No IPC — v1.3.0 removed the audit-chain verify / chain-head
        // endpoints. The page renders the persisted file (if any) on
        // first paint.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_capture_path_handles_known_format() {
        let text = "Captured!\nBSSID: aa:bb\nCapture: /tmp/foo.pcap";
        assert_eq!(extract_capture_path(text), Some("/tmp/foo.pcap".to_string()));
    }

    #[test]
    fn extract_capture_path_returns_none_when_absent() {
        assert_eq!(extract_capture_path("nothing here"), None);
    }
}