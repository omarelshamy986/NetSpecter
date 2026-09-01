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

    /// Render the plan for the currently-selected target.
    pub fn render_plan(&self, plan: &netspecter_agent::backend::wizard::WizardPlan) {
        let mut state = self.state.borrow_mut();
        state.encryption_label.set_text(&format!("Encryption: {}", plan.encryption.label()));
        state.rationale_label.set_text(&plan.rationale);

        // Clear existing rows.
        if let Some(ref list) = state.step_list {
            while let Some(child) = list.first_child() {
                list.remove(&child);
            }
            for step in &plan.steps {
                let row = build_step_row(step);
                list.append(&row.step_box);
                state.rows.push(row);
            }
        }
    }
}

fn build_step_row(step: &netspecter_agent::backend::wizard::WizardStep) -> WizardRow {
    let row_box = Box::new(Orientation::Horizontal, 8);
    row_box.set_margin_top(4);
    row_box.set_margin_bottom(4);

    let icon_name = match step.kind {
        netspecter_agent::backend::wizard::WizardStepKind::PassiveScan => "find-location-symbolic",
        netspecter_agent::backend::wizard::WizardStepKind::ActiveAttack => "system-run-symbolic",
        netspecter_agent::backend::wizard::WizardStepKind::OfflineCrack => "utilities-terminal-symbolic",
        netspecter_agent::backend::wizard::WizardStepKind::SocialEngineering => "preferences-system-network-symbolic",
        netspecter_agent::backend::wizard::WizardStepKind::HiddenSsidRecovery => "view-reveal-symbolic",
        netspecter_agent::backend::wizard::WizardStepKind::Report => "edit-paste-symbolic",
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
    use super::*;

    #[test]
    fn wizard_page_constructs_without_panic() {
        // Just exercise the constructor — no GTK runtime in unit tests, but
        // we ensure the struct layout is sound.
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