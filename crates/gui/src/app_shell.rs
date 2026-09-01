//! AppData + page-to-IPC wiring.
//!
//! Owns the shared `IpcClient` handle and the GTK4 widget tree. Pages
//! hold a `Rc<IpcClient>` so they can dispatch requests to the agent
//! without going through the GUI frontend module.
//!
//! This module is the single entry point for the GTK4 application: it
//! builds the notebook, embeds each page, and forwards IPC events.

use gtk4::prelude::*;
use gtk4::*;
use std::cell::RefCell;
use std::rc::Rc;

use crate::frontend::pages::{
    AuditLogPage, EvilTwinPage, HiddenNetworksPage, PmkidPage, ReportsPage,
    SmartWizardPage,
};
use crate::ipc_client::IpcClient;

/// Shared application state.
pub struct AppState {
    pub ipc: IpcClient,
    pub wizard_page: SmartWizardPage,
    pub pmkid_page: PmkidPage,
    pub evil_twin_page: EvilTwinPage,
    pub hidden_networks_page: HiddenNetworksPage,
    pub reports_page: ReportsPage,
    pub audit_log_page: AuditLogPage,
    pub status_label: Label,
    pub notebook: Notebook,
}

impl AppState {
    /// The AP currently selected in the wizard's target dropdown.
    /// Returns `None` if no dropdown is bound or nothing is selected.
    pub fn selected_ap(&self) -> Option<netspecter_common::types::AP> {
        self.wizard_page.state.borrow().selected_ap()
    }
}

pub type SharedState = Rc<RefCell<AppState>>;

/// Build the application shell — a notebook with the 5 NetSpecter pages
/// plus the original Scan tab.
pub fn build_shell(app: &Application, ipc: IpcClient) -> SharedState {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("NetSpecter")
        .default_width(1280)
        .default_height(800)
        .build();

    let vbox = Box::new(Orientation::Vertical, 0);
    window.set_child(Some(&vbox));

    // Header bar.
    let header = HeaderBar::new();
    let title_label = Label::new(Some("NetSpecter"));
    title_label.add_css_class("title");
    header.set_title_widget(Some(&title_label));
    vbox.append(&header);

    // Status bar (bottom).
    let status_bar = Box::new(Orientation::Horizontal, 8);
    status_bar.set_margin_start(8);
    status_bar.set_margin_end(8);
    status_bar.set_margin_top(4);
    status_bar.set_margin_bottom(4);

    let status_label = Label::builder()
        .label(if ipc.is_connected() {
            "● Agent connected"
        } else {
            "○ Agent offline"
        })
        .halign(Align::Start)
        .hexpand(true)
        .build();
    status_bar.append(&status_label);

    let reconnect_btn = Button::from_icon_name("view-refresh-symbolic");
    reconnect_btn.set_tooltip_text(Some("Reconnect to agent"));
    status_bar.append(&reconnect_btn);

    // Notebook with tabs.
    let notebook = Notebook::new();
    notebook.set_vexpand(true);
    notebook.set_hexpand(true);

    let wizard_page = SmartWizardPage::new();
    let pmkid_page = PmkidPage::new();
    let evil_twin_page = EvilTwinPage::new();
    let hidden_networks_page = HiddenNetworksPage::new();
    let reports_page = ReportsPage::new();
    let audit_log_page = AuditLogPage::new();

    notebook.append_page(&wizard_page.root, Some(&Label::new(Some("🧙 Wizard"))));
    notebook.append_page(&pmkid_page.root, Some(&Label::new(Some("🔑 PMKID"))));
    notebook.append_page(&evil_twin_page.root, Some(&Label::new(Some("🎭 Evil Twin"))));
    notebook.append_page(&hidden_networks_page.root, Some(&Label::new(Some("👻 Hidden"))));
    notebook.append_page(&reports_page.root, Some(&Label::new(Some("📊 Reports"))));
    notebook.append_page(&audit_log_page.root, Some(&Label::new(Some("📋 Audit"))));

    vbox.append(&notebook);
    vbox.append(&status_bar);

    let state = Rc::new(RefCell::new(AppState {
        ipc: ipc.clone(),
        wizard_page,
        pmkid_page,
        evil_twin_page,
        hidden_networks_page,
        reports_page,
        audit_log_page,
        status_label,
        notebook,
    }));

    // Wire the reconnect button.
    let state_for_btn = state.clone();
    reconnect_btn.connect_clicked(move |btn| {
        let mut s = state_for_btn.borrow_mut();
        if s.ipc.is_connected() {
            s.ipc.disconnect();
        }
        match s.ipc.connect() {
            Ok(()) => {
                s.status_label.set_text("● Agent connected");
                btn.set_icon_name("view-refresh-symbolic");
            }
            Err(e) => {
                s.status_label.set_text(&format!("○ Reconnect failed: {e}"));
            }
        }
    });

    window.present();
    state
}

#[cfg(test)]
mod tests {
    #[test]
    fn module_compiles() {
        // Smoke test — just ensure the module loads.
        let _ = std::any::type_name::<super::AppState>();
    }
}