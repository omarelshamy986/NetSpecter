//! Evil-Twin configuration page.
//!
//! Renders the Evil-Twin config (`netspecter_common::ipc::EvilTwinConfig`) as a form: SSID, BSSID, channel, captive-
//! portal skin, NAT toggle. On launch, the page calls `evil_twin::launch()`
//! and streams credential captures as they arrive.

// Constructed from the app shell (driven from main()); test builds
// replace main() and would otherwise flag the whole page as dead code.
#![allow(dead_code)]

use gtk4::prelude::*;
use gtk4::*;

pub struct EvilTwinPage {
    pub root: Box,
    pub launch_btn: Button,
    pub stop_btn: Button,
    pub iface_entry: Entry,
    pub ssid_entry: Entry,
    pub bssid_entry: Entry,
    pub channel_spin: SpinButton,
    pub nat_switch: Switch,
    pub creds_view: ListBox,
}

impl EvilTwinPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        let header = Label::builder()
            .label("<b>Evil Twin</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let warning = Label::builder()
            .label("⚠ This panel launches a Fluxion-style rogue AP + captive portal.\n\
                    Use only on networks you are authorized to test.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        warning.add_css_class("warning-label");
        root.append(&warning);

        // Form grid.
        let grid = Grid::new();
        grid.set_column_spacing(8);
        grid.set_row_spacing(8);
        grid.set_margin_top(8);

        grid.attach(&Label::new(Some("Interface:")), 0, 0, 1, 1);
        let iface_entry = Entry::new();
        iface_entry.set_text("wlan1");
        iface_entry.set_placeholder_text(Some("monitor-mode interface for the fake AP"));
        grid.attach(&iface_entry, 1, 0, 1, 1);

        grid.attach(&Label::new(Some("SSID:")), 0, 1, 1, 1);
        let ssid_entry = Entry::new();
        ssid_entry.set_placeholder_text(Some("ESSID to advertise (matches target)"));
        grid.attach(&ssid_entry, 1, 1, 1, 1);

        grid.attach(&Label::new(Some("BSSID:")), 0, 2, 1, 1);
        let bssid_entry = Entry::new();
        bssid_entry.set_placeholder_text(Some("BSSID (leave blank for random)"));
        grid.attach(&bssid_entry, 1, 2, 1, 1);

        grid.attach(&Label::new(Some("Channel:")), 0, 3, 1, 1);
        let channel_spin = SpinButton::with_range(1.0, 165.0, 1.0);
        channel_spin.set_value(6.0);
        grid.attach(&channel_spin, 1, 3, 1, 1);

        grid.attach(&Label::new(Some("Portal skin:")), 0, 4, 1, 1);
        let _skin_dropdown = DropDown::from_strings(&[
            "router-mimic (dark)",
            "ISP-mimic (light)",
        ]);
        grid.attach(&_skin_dropdown, 1, 4, 1, 1);

        grid.attach(&Label::new(Some("Enable NAT:")), 0, 5, 1, 1);
        let nat_switch = Switch::new();
        nat_switch.set_active(true);
        grid.attach(&nat_switch, 1, 5, 1, 1);

        root.append(&grid);

        // Action buttons.
        let button_box = Box::new(Orientation::Horizontal, 8);
        button_box.set_margin_top(8);

        let launch_btn = Button::with_label("Launch Evil Twin");
        launch_btn.set_icon_name("media-playback-start-symbolic");
        launch_btn.add_css_class("destructive-action");
        button_box.append(&launch_btn);

        let stop_btn = Button::with_label("Stop");
        stop_btn.set_icon_name("media-playback-stop-symbolic");
        stop_btn.set_sensitive(false);
        button_box.append(&stop_btn);

        root.append(&button_box);

        // Captured credentials list.
        let creds_label = Label::builder()
            .label("<b>Captured credentials</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        creds_label.set_margin_top(12);
        root.append(&creds_label);

        let creds_view = ListBox::new();
        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .min_content_height(120)
            .build();
        scrolled.set_child(Some(&creds_view));
        root.append(&scrolled);

        Self {
            root,
            launch_btn,
            stop_btn,
            iface_entry,
            ssid_entry,
            bssid_entry,
            channel_spin,
            nat_switch,
            creds_view,
        }
    }
}

impl Default for EvilTwinPage {
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
        let _ = super::EvilTwinPage::new();
    }
}