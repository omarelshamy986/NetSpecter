//! Audit-log viewer.
//!
//! Read-only view of the SHA-256-chained audit log. The page surfaces:
//!
//! - The current chain-head digest (the report auditor can pin this).
//! - The operator handle recorded at consent.
//! - A scrolling list of every entry, with timestamp + action + target.
//! - A "Verify chain" button that walks the chain and reports tampering.

use gtk4::prelude::*;
use gtk4::*;

pub struct AuditLogPage {
    pub root: Box,
    pub head_label: Label,
    pub verify_btn: Button,
}

impl AuditLogPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        let header = Label::builder()
            .label("<b>Audit Log</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let description = Label::builder()
            .label("Tamper-evident SHA-256-chained log of every operator action.\n\
                    'Verify chain' walks the log and reports any inconsistency.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        description.add_css_class("dim-label");
        root.append(&description);

        // Chain head + verify button.
        let head_box = Box::new(Orientation::Horizontal, 8);
        head_box.set_margin_top(8);
        head_box.append(&Label::new(Some("Chain head:")));
        let head_label = Label::new(Some("—"));
        head_label.set_selectable(true);
        head_label.add_css_class("monospace");
        head_label.set_hexpand(true);
        head_box.append(&head_label);

        let verify_btn = Button::with_label("Verify chain");
        verify_btn.set_icon_name("dialog-ok-symbolic");
        head_box.append(&verify_btn);

        root.append(&head_box);

        // Entry list (read-only).
        let list = ListBox::new();
        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .vexpand(true)
            .build();
        scrolled.set_child(Some(&list));
        root.append(&scrolled);

        Self { root, head_label, verify_btn }
    }
}

impl Default for AuditLogPage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn page_constructs() {
        let _ = super::AuditLogPage::new();
    }
}