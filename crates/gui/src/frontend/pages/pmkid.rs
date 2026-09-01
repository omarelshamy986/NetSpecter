//! PMKID-capture dedicated tab.
//!
//! Operators running a PMKID-only engagement (no clients on the target,
//! no deauth required) get a focused view that:
//!
//! 1. Lists candidate target APs from the live scan.
//! 2. On selection, launches `harvest_pmkid()` on the agent.
//! 3. Surfaces the captured PMKID, the source PCAP path, and a one-click
//!    `Open in Wireshark` action.
//! 4. Offers a paste-PMKID-to-verify field for the operator to drop in
//!    a candidate passphrase; the page calls `verify_psk_against_pmkid()`
//!    and renders the result with confidence.

use gtk4::prelude::*;
use gtk4::*;

pub struct PmkidPage {
    pub root: Box,
}

impl PmkidPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        let header = Label::builder()
            .label("<b>PMKID Capture</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let description = Label::builder()
            .label("Passive PMKID harvest — no client, no deauth required.\n\
                    Select an AP from the scan and press Capture. The agent will \
                    associate and capture the EAPOL M1 PMKID.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        description.add_css_class("dim-label");
        root.append(&description);

        // Target picker.
        let target_box = Box::new(Orientation::Horizontal, 8);
        target_box.append(&Label::new(Some("Target:")));
        let target_dropdown = DropDown::from_strings(&["(no AP selected)"]);
        target_dropdown.set_hexpand(true);
        target_box.append(&target_dropdown);
        root.append(&target_box);

        // Action buttons.
        let button_box = Box::new(Orientation::Horizontal, 8);
        let capture_btn = Button::with_label("Capture PMKID");
        capture_btn.set_icon_name("media-playback-start-symbolic");
        button_box.append(&capture_btn);

        let verify_btn = Button::with_label("Verify candidate");
        verify_btn.set_icon_name("dialog-ok-symbolic");
        button_box.append(&verify_btn);

        let open_pcap_btn = Button::with_label("Open capture in Wireshark");
        open_pcap_btn.set_icon_name("document-open-symbolic");
        button_box.append(&open_pcap_btn);

        root.append(&button_box);

        // Result area.
        let result_label = Label::builder()
            .label("No capture yet.")
            .halign(Align::Start)
            .wrap(true)
            .selectable(true)
            .build();
        result_label.set_margin_top(8);
        root.append(&result_label);

        // Hashcat helper line.
        let hashcat_box = Box::new(Orientation::Horizontal, 8);
        hashcat_box.set_margin_top(8);
        let hashcat_label = Label::builder()
            .label("hashcat -m 22000 ~/.netspecter/captures/<essid>_<bssid>/pmkid_attack.hc22000 <wordlist>")
            .selectable(true)
            .build();
        hashcat_label.add_css_class("monospace");
        hashcat_label.add_css_class("dim-label");
        hashcat_box.append(&hashcat_label);
        root.append(&hashcat_box);

        Self { root }
    }
}

impl Default for PmkidPage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn page_constructs() {
        // Just verifies the module compiles.
        let _ = super::PmkidPage::new();
    }
}