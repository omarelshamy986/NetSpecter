//! Auto-Pwn page — the one-button engagement.
//!
//! Press Start -> the agent runs the full pipeline (discover, hidden
//! recovery, rank, attack, crack) and this page renders the live
//! event stream: scanning status, recovered hidden ESSIDs, the ranked
//! target table with scores, per-attack progress, and the final
//! cracked-password wins.
//!
//! ## Layout
//!
//! ```text
//! +----------------------------------------------+
//! | [>] Auto-Pwn Everything  [X] Stop (spinner)  |
//! +----------------------------------------------+
//! | status line (current stage)                   |
//! +----------------------------------------------+
//! | Ranked targets (scrollable rows):             |
//! |  #1  Linksys-5G   WPA2  -45dBm  [x] 240 pts   |
//! |  #2  NETGEAR      WEP   -60dBm  [x] 195 pts   |
//! |  #3  <hidden\>     WPA2  -55dBm  [.]  90 pts   |
//! +----------------------------------------------+
//! | Cracked:                                      |
//! |  [v] Linksys-5G -> sunshine1985               |
//! |  [v] NETGEAR -> AA:BB:CC:DD:EE                |
//! +----------------------------------------------+
//! ```

use gtk4::prelude::*;
use gtk4::*;
use std::cell::RefCell;
use std::rc::Rc;

use crate::app_shell::SharedState;

pub struct AutoPwnPage {
    pub root: Box,
    state: Rc<RefCell<AutoPwnState>>,
}

#[derive(Default)]
pub struct AutoPwnState {
    pub status_label: Option<Label>,
    pub targets_list: Option<ListBox>,
    pub cracked_list: Option<ListBox>,
    pub start_btn: Option<Button>,
    pub stop_btn: Option<Button>,
}

impl AutoPwnPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        // ── Header ──
        let header = Label::builder()
            .label("<b>Auto-Pwn</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let description = Label::builder()
            .label("One click: discover every network in range, recover hidden \
                    SSIDs, rank targets by ease of attack, run the optimal \
                    attack per target, and crack what's captured.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        description.add_css_class("dim-label");
        root.append(&description);

        // ── Buttons ──
        let button_box = Box::new(Orientation::Horizontal, 8);

        let start_btn = Button::with_label("Auto-Pwn Everything");
        start_btn.set_icon_name("media-playback-start-symbolic");
        start_btn.add_css_class("suggested-action");
        button_box.append(&start_btn);

        let stop_btn = Button::with_label("Stop");
        stop_btn.set_icon_name("media-playback-stop-symbolic");
        stop_btn.set_sensitive(false);
        button_box.append(&stop_btn);

        root.append(&button_box);

        // ── Status ──
        let status_label = Label::builder()
            .label("Idle. Press Auto-Pwn to begin.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        status_label.add_css_class("dim-label");
        root.append(&status_label);

        // ── Ranked targets ──
        let targets_header = Label::builder()
            .label("<b>Ranked targets</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        targets_header.set_margin_top(8);
        root.append(&targets_header);

        let targets_list = ListBox::new();
        let targets_scroll = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .min_content_height(200)
            .build();
        targets_scroll.set_child(Some(&targets_list));
        root.append(&targets_scroll);

        // ── Cracked ──
        let cracked_header = Label::builder()
            .label("<b>Cracked</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        cracked_header.set_margin_top(8);
        root.append(&cracked_header);

        let cracked_list = ListBox::new();
        let cracked_scroll = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .min_content_height(120)
            .build();
        cracked_scroll.set_child(Some(&cracked_list));
        root.append(&cracked_scroll);

        let state = Rc::new(RefCell::new(AutoPwnState {
            status_label: Some(status_label),
            targets_list: Some(targets_list),
            cracked_list: Some(cracked_list),
            start_btn: Some(start_btn),
            stop_btn: Some(stop_btn),
        }));

        Self { root, state }
    }

    /// Update the status line from a pipeline stage event.
    pub fn set_status(&self, text: &str) {
        if let Some(ref lbl) = self.state.borrow().status_label {
            lbl.set_text(text);
        }
    }

    /// Append a ranked-target row (#rank, essid, encryption, power, score).
    pub fn add_target_row(&self, rank: usize, essid: &str, enc: &str, power: i16, score: u32) {
        if let Some(ref list) = self.state.borrow().targets_list {
            let row = Box::new(Orientation::Horizontal, 8);
            row.set_margin_top(4);
            row.set_margin_bottom(4);
            row.set_margin_start(6);
            row.set_margin_end(6);

            let rank_label = Label::builder()
                .label(format!("#{rank}"))
                .halign(Align::Start)
                .build();
            rank_label.add_css_class("dim-label");
            row.append(&rank_label);

            let essid_label = Label::builder()
                .label(essid)
                .halign(Align::Start)
                .ellipsize(gtk4::pango::EllipsizeMode::End)
                .build();
            essid_label.set_hexpand(true);
            row.append(&essid_label);

            let enc_label = Label::builder()
                .label(enc)
                .halign(Align::End)
                .build();
            enc_label.add_css_class("dim-label");
            row.append(&enc_label);

            let power_label = Label::builder()
                .label(format!("{power} dBm"))
                .halign(Align::End)
                .build();
            power_label.add_css_class("dim-label");
            row.append(&power_label);

            let score_label = Label::builder()
                .label(format!("{score} pts"))
                .halign(Align::End)
                .build();
            row.append(&score_label);

            list.append(&row);
        }
    }

    /// Append a cracked win row (essid → password).
    pub fn add_cracked_row(&self, essid: &str, password: &str) {
        if let Some(ref list) = self.state.borrow().cracked_list {
            let row = Box::new(Orientation::Horizontal, 8);
            row.set_margin_top(4);
            row.set_margin_bottom(4);
            row.set_margin_start(6);
            row.set_margin_end(6);

            let check = Label::builder().label("✓").halign(Align::Start).build();
            row.append(&check);

            let essid_label = Label::builder()
                .label(essid)
                .halign(Align::Start)
                .ellipsize(gtk4::pango::EllipsizeMode::End)
                .build();
            row.append(&essid_label);

            let arrow = Label::builder().label("→").halign(Align::Start).build();
            arrow.add_css_class("dim-label");
            row.append(&arrow);

            let pass_label = Label::builder()
                .label(password)
                .halign(Align::Start)
                .selectable(true)
                .ellipsize(gtk4::pango::EllipsizeMode::End)
                .build();
            pass_label.set_hexpand(true);
            row.append(&pass_label);

            let copy_btn = Button::from_icon_name("edit-copy-symbolic");
            copy_btn.set_tooltip_text(Some("Copy password"));
            copy_btn.set_valign(Align::Center);
            let pw = password.to_string();
            copy_btn.connect_clicked(move |_| {
                if let Some(display) = gtk4::gdk::Display::default() {
                    display.clipboard().set_text(&pw);
                }
            });
            row.append(&copy_btn);

            list.append(&row);
        }
    }

    /// Wire the Start/Stop buttons to the IPC client.
    ///
    /// Start dispatches StartAutoPwn on a worker thread; the worker pumps
    /// the event stream and sends each batch back as a plain-`Send`
    /// message over an `std::sync::mpsc` channel. A
    /// `glib::timeout_add_local` pump on the main thread renders the
    /// events and applies the final result — widgets never leave the
    /// main thread.
    pub fn wire_handlers(&self, state: SharedState) {
        let state_for_start = state.clone();

        if let Some(ref start_btn) = self.state.borrow().start_btn {
            let state_inner_start = self.state.clone();
            start_btn.connect_clicked(move |_btn| {
                let s = state_inner_start.borrow();
                if let (Some(ref start), Some(ref stop), Some(ref status)) =
                    (&s.start_btn, &s.stop_btn, &s.status_label)
                {
                    start.set_sensitive(false);
                    stop.set_sensitive(true);
                    status.set_text("Launching Auto-Pwn pipeline…");
                }
                drop(s);

                let ipc = state_for_start.borrow().ipc.clone();

                // Channel + main-thread pump FIRST (we're on the main
                // thread inside the clicked handler) — then the worker.
                let (tx, rx) = std::sync::mpsc::channel::<AutoPwnMsg>();
                let state_pump = state_for_start.clone();
                glib::timeout_add_local(
                    std::time::Duration::from_millis(200),
                    move || {
                        let mut final_done = false;
                        loop {
                            match rx.try_recv() {
                                Ok(AutoPwnMsg::Batch { events, result }) => {
                                    let s = state_pump.borrow();
                                    let page = &s.autopwn_page;
                                    for ev in &events {
                                        render_event(page, ev);
                                    }
                                    if let Some(res) = result {
                                        let inner = page.state.borrow();
                                        if let (Some(ref start), Some(ref stop), Some(ref status)) =
                                            (&inner.start_btn, &inner.stop_btn, &inner.status_label)
                                        {
                                            start.set_sensitive(true);
                                            stop.set_sensitive(false);
                                            status.set_text(&format!(
                                                "Done — {} cracked of {} attempted.",
                                                res.cracked.len(),
                                                res.targets.len()
                                            ));
                                        }
                                        final_done = true;
                                    }
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                                    final_done = true;
                                    break;
                                }
                            }
                        }
                        if final_done {
                            glib::ControlFlow::Break
                        } else {
                            glib::ControlFlow::Continue
                        }
                    },
                );

                std::thread::spawn(move || {
                    // Launch, then pump the event stream back to the GUI
                    // through the channel — plain data only.
                    if ipc
                        .call(netspecter_common::ipc::Request::StartAutoPwn {
                            config: netspecter_common::autopwn::AutoPwnConfig::default(),
                        })
                        .is_err()
                    {
                        return;
                    }
                    loop {
                        match ipc.poll_auto_pwn() {
                            Ok((events, result)) => {
                                let done = result.is_some();
                                let _ = tx.send(AutoPwnMsg::Batch { events, result });
                                if done {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                });
            });
        }

        if let Some(ref stop_btn) = self.state.borrow().stop_btn {
            let state_inner_stop = self.state.clone();
            stop_btn.connect_clicked(move |_btn| {
                // v2.1: Stop disables the button; the pipeline exits at
                // its own budget boundary (worker pool deadline).
                let s = state_inner_stop.borrow();
                if let (Some(ref start), Some(ref stop), Some(ref status)) =
                    (&s.start_btn, &s.stop_btn, &s.status_label)
                {
                    stop.set_sensitive(false);
                    start.set_sensitive(true);
                    status.set_text("Stopped (pipeline drains at its own pace).");
                }
            });
        }
    }
}

/// Plain-`Send` batches the autopwn worker forwards to the GUI pump.
enum AutoPwnMsg {
    Batch {
        events: Vec<netspecter_common::autopwn::PipelineEvent>,
        result: Option<netspecter_common::autopwn::AutoPwnResult>,
    },
}

/// Render one pipeline event onto the page.
fn render_event(page: &AutoPwnPage, ev: &netspecter_common::autopwn::PipelineEvent) {
    use netspecter_common::autopwn::PipelineEvent as PE;
    match ev {
        PE::Discovering { aps_seen } => {
            page.set_status(&format!("Scanning… {aps_seen} APs seen so far."));
        }
        PE::HiddenRecovery { bssid, essid, source } => {
            page.set_status(&format!(
                "Recovered hidden ESSID '{essid}' from {bssid} ({source})."
            ));
        }
        PE::Ranked { targets } => {
            page.set_status(&format!("Ranked {} targets — attacks starting.", targets.len()));
            for (i, t) in targets.iter().enumerate() {
                page.add_target_row(i + 1, &t.essid, t.encryption.label(), t.power_dbm, t.score);
            }
        }
        PE::AttackStarted { essid, kind, .. } => {
            page.set_status(&format!("Running {kind} on {essid}…"));
        }
        PE::AttackFinished { job_id, status, result, .. } => {
            let note = result.clone().unwrap_or_default();
            page.set_status(&format!("job #{job_id}: {status} {note}"));
        }
        PE::Cracking { hashfile, wordlist } => {
            page.set_status(&format!(
                "Cracking {} (wordlist: {})…",
                hashfile.rsplit('/').next().unwrap_or(hashfile),
                wordlist.rsplit('/').next().unwrap_or(wordlist),
            ));
        }
        PE::Cracked { password, target_essid } => {
            page.add_cracked_row(target_essid, password);
        }
        PE::Done { cracked, attempted } => {
            page.set_status(&format!(
                "Pipeline done — {cracked} cracked of {attempted} attempted."
            ));
        }
    }
}

impl Default for AutoPwnPage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::gtk_available;

    #[test]
    fn page_constructs() {
        if !gtk_available() {
            return; // headless CI — no display server
        }
        let _ = super::AutoPwnPage::new();
    }
}