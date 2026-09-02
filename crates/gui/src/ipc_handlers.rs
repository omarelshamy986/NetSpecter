//! IPC event handlers — wires up the GTK4 buttons in each page to
//! the [`IpcClient`].
//!
//! Each page exposes a `wire_handlers(&shared_state)` method that takes
//! the shared app state and connects the buttons. The handlers run their
//! IPC calls on a worker thread (because GTK4 runs everything on the main
//! thread) and use [`glib::idle_add`] to bounce results back to the main
//! loop for UI updates.
//!
//! ## Why worker threads?
//!
//! IPC calls block on the agent's response; running them on the main GTK4
//! thread would freeze the UI for the duration. The `std::thread::spawn`
//! + `glib::idle_add` pattern keeps the UI responsive while the agent
//! works, and is the canonical Rust+GTK4 approach.

use gtk4::glib;
use gtk4::prelude::*;

use crate::app_shell::SharedState;
use crate::frontend::pages::{
    AuditLogPage, EvilTwinPage, PmkidPage, ReportsPage, SmartWizardPage,
};

/// Connect every page's UI handlers to the shared IPC client.
///
/// Idempotent — safe to call once per page.
pub fn wire_all(state: SharedState) {
    let mut s = state.borrow_mut();
    s.wizard_page.wire_handlers(state.clone());
    s.pmkid_page.wire_handlers(state.clone());
    s.evil_twin_page.wire_handlers(state.clone());
    s.reports_page.wire_handlers(state.clone());
    s.audit_log_page.wire_handlers(state.clone());
}

// ─────────────────────────────────────────────────────────────────
// SmartWizardPage
// ─────────────────────────────────────────────────────────────────

impl SmartWizardPage {
    pub fn wire_handlers(&self, state: SharedState) {
        // The "Generate plan" path: dispatch WizardPlanFor and render the
        // resulting plan into the page's checklist.
        let state_for_target = state.clone();
        if let Some(dropdown) = &self.state.borrow().target_dropdown {
            dropdown.connect_selected_notify(move |dd| {
                let s = state_for_target.borrow();
                let idx = dd.selected();
                let aps = &s.ap_snapshot;
                if idx < aps.len() as u32 {
                    let ap = aps[idx as usize].clone();
                    let ipc = s.ipc.clone();
                    let state2 = state_for_target.clone();
                    std::thread::spawn(move || {
                        match ipc.wizard_plan_for(ap) {
                            Ok(plan) => {
                                let page = state2.borrow().wizard_page.clone();
                                let plan_for_idle = plan;
                                glib::idle_add_once(move || {
                                    page.render_plan(&plan_for_idle);
                                });
                            }
                            Err(e) => {
                                glib::idle_add_once(move || {
                                    log::warn!("wizard_plan_for failed: {e}");
                                });
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
        let result_label = self.result_label.clone();
        let capture_btn = self.capture_btn.clone();
        let state_for_btn = state.clone();

        capture_btn.connect_clicked(move |_btn| {
            let s = state_for_btn.borrow();
            let target = s.selected_ap();
            let Some(ap) = target else {
                glib::idle_add_once(|| {});
                return;
            };
            let ipc = s.ipc.clone();
            let bssid = ap.bssid.clone();
            let essid = ap.essid.clone();
            let result_label_clone = result_label.clone();
            std::thread::spawn(move || {
                match ipc.harvest_pmkid(&bssid, &essid, 60) {
                    Ok(cap) => {
                        let path = cap.capture_path.unwrap_or_default();
                        let captured_at = cap.captured_at;
                        let pmkid = cap.pmkid_hex;
                        let bssid_s = cap.bssid;
                        let essid_s = cap.essid;
                        glib::idle_add_once(move || {
                            result_label_clone.set_text(&format!(
                                "Captured!\nBSSID: {}\nESSID: {}\nPMKID: {}\nAt: {}\nCapture: {}",
                                bssid_s, essid_s, pmkid, captured_at, path
                            ));
                        });
                    }
                    Err(e) => {
                        let msg = format!("harvest failed: {e}");
                        glib::idle_add_once(move || {
                            result_label_clone.set_text(&msg);
                        });
                    }
                }
            });
        });

        // Verify: dispatch VerifyPskAgainstPmkid with the typed
        // candidate from the entry field, then display "match"/"no match".
        let verify_btn = self.verify_btn.clone();
        let result_label_for_verify = self.result_label.clone();
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
            let sta = "02:00:00:00:01:00".to_string();
            // The captured PMKID should come from the latest harvest. For
            // now we re-run the harvest quickly and use the result.
            let result_label_clone = result_label_for_verify.clone();
            std::thread::spawn(move || {
                let cap = match ipc.harvest_pmkid(&bssid, &essid, 60) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let pmkid_hex = cap.pmkid_hex.clone();
                let ok = ipc.verify_psk(&candidate, &essid, &bssid, &sta, &pmkid_hex).unwrap_or(false);
                let label_text = if ok {
                    format!("✓ Match: '{}' is the network PSK", candidate)
                } else {
                    format!("✗ No match for '{}'", candidate)
                };
                let pmkid_for_label = pmkid_hex;
                let bssid_for_label = bssid.clone();
                let essid_for_label = essid.clone();
                glib::idle_add_once(move || {
                    result_label_clone.set_text(&format!(
                        "{label_text}\nBSSID: {bssid_for_label}\nESSID: {essid_for_label}\nPMKID: {pmkid_for_label}"
                    ));
                });
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
        let stop_btn = self.stop_btn.clone();
        let creds_view = self.creds_view.clone();
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
                ssid,
                bssid,
                channel,
                portal_template: "templates/portal-router.html".to_string(),
                nat,
            };

            let ipc = state_for_launch.borrow().ipc.clone();
            let stop_btn_clone = stop_btn.clone();
            std::thread::spawn(move || match ipc.launch_evil_twin(config) {
                Ok(session) => {
                    glib::idle_add_once(move || {
                        stop_btn_clone.set_sensitive(true);
                        log::info!(
                            "evil twin launched: {} on {}",
                            session.config.ssid,
                            session.config.iface,
                        );
                    });
                }
                Err(e) => {
                    let msg = format!("launch failed: {e}");
                    glib::idle_add_once(move || {
                        log::warn!("{msg}");
                    });
                }
            });
        });

        // Stop the Evil Twin session.
        let state_for_stop = state.clone();
        stop_btn.connect_clicked(move |_btn| {
            let iface = iface_entry.text().to_string();
            let ipc = state_for_stop.borrow().ipc.clone();
            std::thread::spawn(move || {
                let _ = ipc.stop_evil_twin(&iface);
            });
        });

        // Suppress the unused warning for creds_view; the page polls
        // credentials itself via the IPC connection.
        let _ = creds_view;
    }
}

// ─────────────────────────────────────────────────────────────────
// ReportsPage
// ─────────────────────────────────────────────────────────────────

impl ReportsPage {
    pub fn wire_handlers(&self, state: SharedState) {
        let generate_btn = self.generate_btn.clone();
        let list = self.list.clone();
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

            let output_dir = format!("/tmp/netspecter-reports/{}", chrono::Utc::now().timestamp());
            let list_clone = list.clone();
            std::thread::spawn(move || {
                let _ = std::fs::create_dir_all(&output_dir);
                match ipc.generate_report(vec![target], vec![plan], &output_dir) {
                    Ok(paths) => {
                        glib::idle_add_once(move || {
                            let row1 = ReportsPage::build_report_row(
                                "Demo engagement",
                                &paths.json,
                            );
                            list_clone.append(&row1);

                            if let Some(html) = &paths.html {
                                let row2 = ReportsPage::build_report_row(
                                    "Demo (HTML)",
                                    html,
                                );
                                list_clone.append(&row2);
                            }
                        });
                    }
                    Err(e) => {
                        log::warn!("generate_report failed: {e}");
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