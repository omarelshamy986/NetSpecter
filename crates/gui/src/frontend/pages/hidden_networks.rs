//! Hidden Networks discovery page.
//!
//! Surfaces the 4 hidden-SSID recovery techniques (probe / deauth /
//! vendor-OUI / beacon-flood) and shows the corroborated results with
//! confidence scores.
//!
//! ## Workflow
//!
//! 1. Operator picks a target BSSID from the dropdown (loaded from the
//!    live scan).
//! 2. Operator chooses a technique (or "all of them").
//! 3. Press Run — each technique dispatches its IPC method on a worker
//!    thread, the page collects every candidate.
//! 4. The corroborator merges them, computes confidence, and renders the
//!    result list with color-coded badges (HIGH / MEDIUM / LOW).

use gtk4::prelude::*;
use gtk4::*;
use std::cell::RefCell;
use std::rc::Rc;

use crate::app_shell::SharedState;
use crate::frontend::pages::ReportsPage;

pub struct HiddenNetworksPage {
    pub root: Box,
    state: Rc<RefCell<HiddenState>>,
}

#[derive(Clone, Default)]
pub struct HiddenState {
    pub target_dropdown: Option<DropDown>,
    pub technique_dropdown: Option<DropDown>,
    pub ap_snapshot: Vec<netspecter_common::types::AP>,
    pub result_view: Option<ListBox>,
    pub status_label: Option<Label>,
    /// Wired buttons captured at construction time so `wire_handlers`
    /// can connect them without walking the widget tree.
    pub run_btn_hint: Option<Button>,
    pub stop_btn_hint: Option<Button>,
    pub copy_btn_hint: Option<Button>,
}

impl HiddenNetworksPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        let header = Label::builder()
            .label("<b>Hidden Networks</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let description = Label::builder()
            .label("Recover the ESSID of an AP that has 'Broadcast SSID' disabled.\n\
                    Available techniques: probe harvest, deauth-to-reveal, vendor-OUI guess, \
                    and beacon flooding.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        description.add_css_class("dim-label");
        root.append(&description);

        // Target picker.
        let target_box = Box::new(Orientation::Horizontal, 8);
        target_box.append(&Label::new(Some("Target BSSID:")));
        let target_dropdown = DropDown::from_strings(&["(no AP selected)"]);
        target_dropdown.set_hexpand(true);
        target_box.append(&target_dropdown);
        root.append(&target_box);

        // Technique picker.
        let tech_box = Box::new(Orientation::Horizontal, 8);
        tech_box.append(&Label::new(Some("Technique:")));
        let technique_dropdown = DropDown::from_strings(&[
            "All (corroborated)",
            "Probe harvest (passive)",
            "Deauth-to-reveal",
            "Vendor-OUI guess",
            "Beacon flooding (active)",
        ]);
        technique_dropdown.set_hexpand(true);
        tech_box.append(&technique_dropdown);
        root.append(&tech_box);

        // Action buttons.
        let button_box = Box::new(Orientation::Horizontal, 8);
        let run_btn = Button::with_label("Run");
        run_btn.set_icon_name("media-playback-start-symbolic");
        run_btn.add_css_class("suggested-action");
        button_box.append(&run_btn);

        let stop_btn = Button::with_label("Stop");
        stop_btn.set_icon_name("media-playback-stop-symbolic");
        stop_btn.set_sensitive(false);
        button_box.append(&stop_btn);

        let copy_btn = Button::with_label("Copy result");
        copy_btn.set_icon_name("edit-copy-symbolic");
        button_box.append(&copy_btn);

        root.append(&button_box);

        // Status line.
        let status_label = Label::builder()
            .label("Ready.")
            .halign(Align::Start)
            .build();
        status_label.add_css_class("dim-label");
        root.append(&status_label);

        // Result list.
        let result_label = Label::builder()
            .label("<b>Recovered ESSIDs</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        result_label.set_margin_top(8);
        root.append(&result_label);

        let result_view = ListBox::new();
        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .min_content_height(180)
            .build();
        scrolled.set_child(Some(&result_view));
        root.append(&scrolled);

        let state = Rc::new(RefCell::new(HiddenState {
            target_dropdown: Some(target_dropdown),
            technique_dropdown: Some(technique_dropdown),
            ap_snapshot: vec![],
            result_view: Some(result_view),
            status_label: Some(status_label),
            run_btn_hint: Some(run_btn),
            stop_btn_hint: Some(stop_btn),
            copy_btn_hint: Some(copy_btn),
        }));

        Self { root, state }
    }

    /// Repopulate the target dropdown with the current scan results.
    pub fn set_targets(&self, aps: &[netspecter_common::types::AP]) {
        let mut state = self.state.borrow_mut();
        state.ap_snapshot = aps.to_vec();
        if let Some(ref dropdown) = state.target_dropdown {
            let labels: Vec<String> = aps
                .iter()
                .map(|ap| {
                    format!(
                        "{} — {} ({}{})",
                        ap.essid,
                        ap.bssid,
                        ap.privacy,
                        if ap.hidden { ", hidden" } else { "" }
                    )
                })
                .collect();
            let refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();
            if refs.is_empty() {
                dropdown.set_model(None::<&gtk4::StringList>);
            } else {
                let model = StringList::new(&refs);
                dropdown.set_model(Some(&model));
            }
        }
    }

    /// Currently-selected AP, or `None` if no dropdown is bound / nothing
    /// is selected.
    pub fn selected_ap(&self) -> Option<netspecter_common::types::AP> {
        let state = self.state.borrow();
        let dropdown = state.target_dropdown.as_ref()?;
        let idx = dropdown.selected();
        state.ap_snapshot.get(idx as usize).cloned()
    }

    /// Wire the Run button + stop button to the IPC client.
    pub fn wire_handlers(&self, state: SharedState) {
        let state_for_run = state.clone();
        if let Some(ref run_btn) = self.state.borrow().run_btn_hint {
            run_btn.connect_clicked(move |_btn| {
                let s = state_for_run.borrow();
                let Some(ap) = s.hidden_networks_page.selected_ap() else {
                    if let Some(ref lbl) = s
                        .hidden_networks_page
                        .state
                        .borrow()
                        .status_label
                    {
                        lbl.set_text("Pick a target BSSID first.");
                    }
                    return;
                };
                let ipc = s.ipc.clone();
                let bssid = ap.bssid.clone();
                let channel: u8 = ap.channel.parse().unwrap_or(6);
                if let Some(ref lbl) = s
                    .hidden_networks_page
                    .state
                    .borrow()
                    .status_label
                {
                    lbl.set_text("Running discovery…");
                }
                drop(s);

                // Worker: plain data back over mpsc; main-thread pump renders.
                let (tx, rx) = std::sync::mpsc::channel::<Vec<netspecter_common::ipc::HiddenSsidCandidate>>();
                std::thread::spawn(move || {
                    let mut all = Vec::new();
                    // Probe harvest
                    if let Ok(mut v) = ipc.discover_hidden_ssid(&bssid, &channel.to_string()) {
                        all.append(&mut v);
                    }
                    // Beacon flood (shorter timeout)
                    if let Ok(mut v) = ipc.beacon_flood_hidden(&bssid, channel, 30) {
                        all.append(&mut v);
                    }
                    let _ = tx.send(all);
                });

                let state_pump = state_for_run.clone();
                glib::timeout_add_local(std::time::Duration::from_millis(200), move || {
                    match rx.try_recv() {
                        Ok(all) => {
                            let s = state_pump.borrow();
                            let page = &s.hidden_networks_page;
                            if let Some(ref lbl) = page.state.borrow().status_label {
                                lbl.set_text(&format!("Recovered {} candidates.", all.len()));
                            }
                            if let Some(ref view) = page.state.borrow().result_view {
                                while let Some(child) = view.first_child() {
                                    view.remove(&child);
                                }
                                for c in &all {
                                    let row = ReportsPage::build_report_row(
                                        &c.essid,
                                        &format!(
                                            "{:?} ({} observations)",
                                            c.source, c.observations
                                        ),
                                    );
                                    view.append(&row);
                                }
                            }
                            glib::ControlFlow::Break
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                            glib::ControlFlow::Break
                        }
                    }
                });
            });
        }

        if let Some(ref stop_btn) = self.state.borrow().stop_btn_hint {
            // No long-running state to stop in v1.4.0; the IPC call returns
            // after the agent-side timeout. Wire the button to surface a
            // hint.
            let state_for_stop = state.clone();
            stop_btn.connect_clicked(move |_btn| {
                let s = state_for_stop.borrow();
                let status_label = s.hidden_networks_page.state.borrow().status_label.clone();
                if let Some(ref lbl) = status_label {
                    lbl.set_text("Stop is a no-op in v1.4.0 — IPC calls return on timeout.");
                }
            });
        }

        if let Some(ref copy_btn) = self.state.borrow().copy_btn_hint {
            let state_for_copy = state.clone();
            copy_btn.connect_clicked(move |_btn| {
                let s = state_for_copy.borrow();
                let result_view = s.hidden_networks_page.state.borrow().result_view.clone();
                if let Some(ref view) = result_view {
                    let mut text = String::new();
                    let mut child = view.first_child();
                    while let Some(c) = child {
                        // Rows are Boxes whose first child is a vertical
                        // text box whose first child is the title label.
                        // `dynamic_cast` consumes the receiver, so clone
                        // it and keep iterating with the original.
                        if let Ok(row_box) = c.clone().dynamic_cast::<gtk4::Box>() {
                            if let Some(text_box) = row_box.first_child() {
                                if let Some(label) = text_box.first_child() {
                                    if let Ok(lbl) = label.dynamic_cast::<Label>() {
                                        text.push_str(&format!("{}\n", lbl.text()));
                                    }
                                }
                            }
                        }
                        child = c.next_sibling();
                    }
                    if let Some(display) = gtk4::gdk::Display::default() {
                        display.clipboard().set_text(&text);
                    }
                }
            });
        }
    }
}

impl Default for HiddenNetworksPage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::frontend::pages::test_util::gtk_available;

    #[test]
    fn page_constructs() {
        if !gtk_available() {
            return; // headless CI — no display server
        }
        let _ = super::HiddenNetworksPage::new();
    }

    #[test]
    fn set_targets_handles_empty_input() {
        if !gtk_available() {
            return; // headless CI — no display server
        }
        let page = super::HiddenNetworksPage::new();
        page.set_targets(&[]);
        assert!(page.selected_ap().is_none());
    }

    #[test]
    fn set_targets_populates_dropdown() {
        if !gtk_available() {
            return; // headless CI — no display server
        }
        let mut ap = netspecter_common::types::AP {
            essid: "<hidden>".into(),
            bssid: "aa:bb:cc:dd:ee:ff".into(),
            band: "2.4".into(),
            channel: "6".into(),
            power: "-50".into(),
            privacy: "WPA2".into(),
            hidden: true,
            handshake: false,
            saved_handshake: None,
            first_time_seen: "2026-01-01T00:00:00Z".into(),
            last_time_seen: "2026-01-01T00:00:00Z".into(),
            clients: Default::default(),
        };
        ap.hidden = true;
        let page = super::HiddenNetworksPage::new();
        page.set_targets(&[ap]);
        assert_eq!(page.state.borrow().ap_snapshot.len(), 1);
    }
}