//! Reports-viewer page.
//!
//! Lists every report the agent has generated (HTML, JSON, PDF), with
//! quick actions: open in browser / reveal in file manager / regenerate.
//!
//! Rows are plain GTK4 (Box + labels + buttons) — no libadwaita
//! dependency; ActionRow is an Adwaita widget and this crate only
//! links gtk4.

use gtk4::prelude::*;
use gtk4::*;

pub struct ReportsPage {
    pub root: Box,
    pub list: ListBox,
    pub generate_btn: Button,
}

impl ReportsPage {
    pub fn new() -> Self {
        let root = Box::new(Orientation::Vertical, 12);
        root.set_margin_top(12);
        root.set_margin_bottom(12);
        root.set_margin_start(12);
        root.set_margin_end(12);

        let header = Label::builder()
            .label("<b>Pentest Reports</b>")
            .use_markup(true)
            .halign(Align::Start)
            .build();
        root.append(&header);

        let description = Label::builder()
            .label("Every generated report appears below. \
                    Use 'Open' to launch in the system browser; \
                    use 'Reveal' to open the file in your file manager.")
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

        // Action bar.
        let bar = Box::new(Orientation::Horizontal, 8);
        let generate_btn = Button::with_label("Generate new report");
        generate_btn.set_icon_name("document-new-symbolic");
        bar.append(&generate_btn);

        let regenerate_btn = Button::with_label("Regenerate from current state");
        regenerate_btn.set_icon_name("view-refresh-symbolic");
        bar.append(&regenerate_btn);

        let export_pdf_btn = Button::with_label("Export PDF");
        export_pdf_btn.set_icon_name("document-save-as-symbolic");
        bar.append(&export_pdf_btn);

        root.append(&bar);

        Self { root, list, generate_btn }
    }

    /// Build one report row (title + subtitle + open/reveal buttons).
    /// Shared by this page and by the IPC handlers that append rows.
    pub fn build_report_row(title: &str, subtitle: &str) -> Box {
        let row = Box::new(Orientation::Horizontal, 8);
        row.set_margin_top(6);
        row.set_margin_bottom(6);
        row.set_margin_start(6);
        row.set_margin_end(6);
        row.add_css_class("report-row");

        let text = Box::new(Orientation::Vertical, 2);
        text.set_hexpand(true);

        let title_label = Label::builder()
            .label(title)
            .halign(Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build();
        text.append(&title_label);

        let subtitle_label = Label::builder()
            .label(subtitle)
            .halign(Align::Start)
            .ellipsize(gtk4::pango::EllipsizeMode::End)
            .build();
        subtitle_label.add_css_class("dim-label");
        text.append(&subtitle_label);

        row.append(&text);

        let open_btn = Button::from_icon_name("document-open-symbolic");
        open_btn.set_tooltip_text(Some("Open in browser"));
        open_btn.set_valign(Align::Center);
        let path_open = subtitle.to_string();
        open_btn.connect_clicked(move |_| {
            let _ = std::process::Command::new("xdg-open").arg(&path_open).spawn();
        });
        row.append(&open_btn);

        let reveal_btn = Button::from_icon_name("folder-symbolic");
        reveal_btn.set_tooltip_text(Some("Reveal in file manager"));
        reveal_btn.set_valign(Align::Center);
        let path_reveal = subtitle.to_string();
        reveal_btn.connect_clicked(move |_| {
            let _ = std::process::Command::new("xdg-open")
                .arg(std::path::Path::new(&path_reveal).parent().unwrap_or(std::path::Path::new("/tmp")))
                .spawn();
        });
        row.append(&reveal_btn);

        row
    }

    /// Add a report entry to the list.
    pub fn add_report(&self, label: &str, path: &str) {
        let row = Self::build_report_row(label, path);
        self.list.append(&row);
    }
}

impl Default for ReportsPage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn page_constructs() {
        let _ = super::ReportsPage::new();
    }
}