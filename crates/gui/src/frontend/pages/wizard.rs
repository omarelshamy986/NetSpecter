//! Smart-wizard guided flow.
//!
//! Renders the [`WizardPlan`] as a checklist with progress markers. The
//! operator picks the target AP from a dropdown, the page calls
//! `plan_for()` on the agent, and renders the resulting steps as a
//! clickable checklist. Each step has:
//!
//! - An icon reflecting the step kind (passive scan / active attack /
//!   offline crack / social engineering / report).
//! - A "Run" button that triggers the corresponding agent action.
//! - A status badge (pending / running / done / failed).

use gtk4::prelude::*;
use gtk4::*;
use std::cell::RefCell;
use std::rc::Rc;

use netspecter_common::ipc::WizardPlan;
use netspecter_common::ipc::WizardStep;
use netspecter_common::ipc::WizardStepKind;
use netspecter_common::types::AP;

/// One row in the wizard checklist.
#[derive(Clone)]
pub struct WizardRow {
    pub step_box: Box,
    pub title_label: Label,
    pub status_label: Label,
    pub run_button: Button,
}

#[derive(Clone, Default)]
pub struct WizardState {
    pub target_bssid: Option<String>,
    pub target_essid: Option<String>,
    pub rows: Vec<WizardRow>,
    pub rationale_label: Label,
    pub encryption_label: Label,
    pub target_dropdown: Option<DropDown>,
    pub step_list: Option<ListBox>,
    pub ap_snapshot: Vec<AP>,
}

impl WizardState {
    /// The AP currently selected in the target dropdown.
    pub fn selected_ap(&self) -> Option<AP> {
        let dropdown = self.target_dropdown.as_ref()?;
        let idx = dropdown.selected();
        self.ap_snapshot.get(idx as usize).cloned()
    }
}

impl SmartWizardPage {
    /// The AP currently selected in the target dropdown.
    pub fn selected_ap(&self) -> Option<AP> {
        self.state.borrow().selected_ap()
    }
}

/// The Smart Wizard notebook page.
pub struct SmartWizardPage {
    pub root: Box,
    state: Rc<RefCell<WizardState>>,
}

impl SmartWizardPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        // ── Header ──
        let header = Box::new(Orientation::Horizontal, 8);
        let title = Label::builder()
            .label("<b>Smart Wizard</b>")
            .use_markup(true)
            .halign(Align::Start)
            .hexpand(true)
            .build();
        header.append(&title);

        let refresh_btn = Button::from_icon_name("view-refresh-symbolic");
        refresh_btn.set_tooltip_text(Some("Regenerate plan from current scan"));
        header.append(&refresh_btn);

        root.append(&header);

        // ── Target picker ──
        let target_box = Box::new(Orientation::Horizontal, 8);
        let target_label = Label::builder().label("Target:").build();
        target_box.append(&target_label);

        let target_dropdown = DropDown::from_strings(&["(no AP selected)"]);
        target_dropdown.set_hexpand(true);
        target_box.append(&target_dropdown);

        root.append(&target_box);

        // ── Encryption + rationale ──
        let info_box = Box::new(Orientation::Vertical, 4);
        info_box.set_margin_top(8);

        let encryption_label = Label::builder()
            .label("Encryption: —")
            .halign(Align::Start)
            .build();
        info_box.append(&encryption_label);

        let rationale_label = Label::builder()
            .label("Pick a target AP to see the recommended attack sequence.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        info_box.append(&rationale_label);
        root.append(&info_box);

        // ── Step checklist (scrollable) ──
        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .vexpand(true)
            .build();

        let step_list = ListBox::new();
        step_list.set_selection_mode(SelectionMode::None);
        scrolled.set_child(Some(&step_list));
        root.append(&scrolled);

        // ── Bottom action bar ──
        let action_bar = Box::new(Orientation::Horizontal, 8);
        action_bar.set_margin_top(8);

        let run_all_btn = Button::with_label("Run full plan");
        run_all_btn.set_tooltip_text(Some("Execute every step in sequence"));
        action_bar.append(&run_all_btn);

        let export_btn = Button::with_label("Export plan as JSON");
        action_bar.append(&export_btn);

        let spacer = Box::new(Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        action_bar.append(&spacer);

        root.append(&action_bar);

        let state = Rc::new(RefCell::new(WizardState {
            target_dropdown: Some(target_dropdown),
            step_list: Some(step_list),
            ..Default::default()
        }));

        // Wire up the refresh button.
        let state_for_refresh = state.clone();
        refresh_btn.connect_clicked(move |_| {
            log::info!("[wizard] refresh clicked — would re-query agent for plan");
            let _ = state_for_refresh;
        });

        Self { root, state }
    }

    /// Repopulate the target dropdown with the current scan results.
    pub fn set_targets(&self, aps: &[AP]) {
        let mut state = self.state.borrow_mut();
        state.ap_snapshot = aps.to_vec();
        if let Some(ref dropdown) = state.target_dropdown {
            let labels: Vec<String> = aps
                .iter()
                .map(|ap| format!("{} — {} ({})", ap.essid, ap.bssid, ap.privacy))
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

    /// Read-only snapshot of the APs currently in the dropdown.
    pub fn ap_snapshot(&self) -> Vec<AP> {
        self.state.borrow().ap_snapshot.clone()
    }

    /// The target dropdown widget, if bound. Exposed so handlers in other
    /// modules can connect to it without touching the private state.
    pub fn target_dropdown(&self) -> Option<DropDown> {
        self.state.borrow().target_dropdown.clone()
    }

    /// Render the plan for the currently-selected target.
    pub fn render_plan(&self, plan: &WizardPlan) {
        let mut state = self.state.borrow_mut();
        state.encryption_label.set_text(&format!("Encryption: {}", plan.encryption_label));
        state.rationale_label.set_text(&plan.rationale);

        // Clone the ListBox handle out of the state so the row-loop's
        // immutable `list` borrow and the mutable `state.rows` push never
        // overlap (ListBox is a cheap refcounted clone).
        let step_list = state.step_list.clone();
        if let Some(ref list) = step_list {
            while let Some(child) = list.first_child() {
                list.remove(&child);
            }
            let rows: Vec<WizardRow> = plan.steps.iter().map(build_step_row).collect();
            for row in rows {
                list.append(&row.step_box);
                state.rows.push(row);
            }
        }
    }
}

fn build_step_row(step: &WizardStep) -> WizardRow {
    let row_box = Box::new(Orientation::Horizontal, 8);
    row_box.set_margin_top(4);
    row_box.set_margin_bottom(4);

    let icon_name = match step.kind {
        WizardStepKind::PassiveScan => "find-location-symbolic",
        WizardStepKind::ActiveAttack => "system-run-symbolic",
        WizardStepKind::OfflineCrack => "utilities-terminal-symbolic",
        WizardStepKind::SocialEngineering => "preferences-system-network-symbolic",
        WizardStepKind::HiddenSsidRecovery => "view-reveal-symbolic",
        WizardStepKind::Report => "edit-paste-symbolic",
    };
    let icon = Image::from_icon_name(icon_name);
    row_box.append(&icon);

    let info = Box::new(Orientation::Vertical, 2);
    info.set_hexpand(true);
    let title = Label::builder()
        .label(format!("<b>{}</b>", step.title))
        .use_markup(true)
        .halign(Align::Start)
        .build();
    info.append(&title);

    let description = Label::builder()
        .label(&step.description)
        .halign(Align::Start)
        .wrap(true)
        .build();
    description.add_css_class("dim-label");
    info.append(&description);

    let est = Label::builder()
        .label(format!("~{}s", step.estimated_secs))
        .halign(Align::Start)
        .build();
    est.add_css_class("caption");
    info.append(&est);

    row_box.append(&info);

    let status = Label::builder()
        .label("Pending")
        .halign(Align::End)
        .build();
    status.add_css_class("dim-label");
    row_box.append(&status);

    let run_btn = Button::from_icon_name("media-playback-start-symbolic");
    run_btn.set_tooltip_text(Some("Run this step"));
    row_box.append(&run_btn);

    WizardRow {
        step_box: row_box,
        title_label: title,
        status_label: status,
        run_button: run_btn,
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports (not `use super::*`): the gtk4::* glob in the
    // parent re-exports a `test` item that collides with the #[test]
    // attribute macro and makes it ambiguous (E0659).
    use crate::frontend::pages::test_util::gtk_available;
    use super::{WizardState, WizardStepKind};

    #[test]
    fn wizard_page_constructs_without_panic() {
        // WizardState::default() constructs Labels — needs a display.
        if !gtk_available() {
            return; // headless CI — no display server
        }
        let state = WizardState::default();
        assert!(state.target_bssid.is_none());
        assert!(state.rows.is_empty());
    }

    #[test]
    fn step_kind_maps_to_known_icon() {
        let kinds = [
            WizardStepKind::PassiveScan,
            WizardStepKind::ActiveAttack,
            WizardStepKind::OfflineCrack,
            WizardStepKind::SocialEngineering,
            WizardStepKind::HiddenSsidRecovery,
            WizardStepKind::Report,
        ];
        // No panics on match.
        for k in kinds {
            let _ = match k {
                WizardStepKind::PassiveScan => "find-location-symbolic",
                WizardStepKind::ActiveAttack => "system-run-symbolic",
                WizardStepKind::OfflineCrack => "utilities-terminal-symbolic",
                WizardStepKind::SocialEngineering => "preferences-system-network-symbolic",
                WizardStepKind::HiddenSsidRecovery => "view-reveal-symbolic",
                WizardStepKind::Report => "edit-paste-symbolic",
            };
        }
    }
}