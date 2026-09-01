//! Audit-log viewer.
//!
//! Read-only view of the persisted audit log file (if any). The page
//! surfaces the file path and the last few entries for transparency.
//! Tamper detection and chain verification have been removed in v1.3.0.

use gtk4::prelude::*;
use gtk4::*;

pub struct AuditLogPage {
    pub root: Box,
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
            .label("Read-only view of any persisted audit log file.\n\
                    The file lives at ~/.netspecter/audit.log when present.")
            .halign(Align::Start)
            .wrap(true)
            .build();
        description.add_css_class("dim-label");
        root.append(&description);

        let list = ListBox::new();
        let scrolled = ScrolledWindow::builder()
            .hscrollbar_policy(PolicyType::Never)
            .vscrollbar_policy(PolicyType::Automatic)
            .vexpand(true)
            .build();
        scrolled.set_child(Some(&list));
        root.append(&scrolled);

        Self { root }
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