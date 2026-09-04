#![allow(unused)]

use gtk4::gdk_pixbuf::Pixbuf;
use gtk4::prelude::*;
use gtk4::*;
use std::io::BufReader;

/// Decode an icon, falling back to a blank 1x1 pixbuf.
///
/// The icons are compile-time embedded bytes, so this cannot realistically
/// fail — but a corrupted build artifact must never crash the GUI over a
/// decorative image. A blank icon degrades gracefully.
fn pixbuf_or_blank(icon: &'static [u8]) -> Pixbuf {
    Pixbuf::from_read(BufReader::new(icon)).unwrap_or_else(|_| {
        log::warn!("failed to decode an embedded icon — using a blank one");
        Pixbuf::new(gtk4::gdk::Colorspace::Rgb, true, 8, 1, 1).unwrap_or_else(|| {
            // 1x1 RGBA cannot fail to allocate in practice; this is the last resort.
            Pixbuf::new(gtk4::gdk::Colorspace::Rgb, false, 8, 1, 1)
                .expect("allocating a 1x1 pixbuf")
        })
    })
}

pub struct IconButton {
    pub handle: Button,
    image: Image,
}

impl IconButton {
    pub fn new(icon: &'static [u8]) -> Self {
        let pixbuf = pixbuf_or_blank(icon);
        let image = Image::from_pixbuf(Some(&pixbuf));
        let handle = Button::builder().child(&image).build();

        Self { handle, image }
    }

    pub fn set_tooltip_text(&self, text: Option<&str>) {
        self.handle.set_tooltip_text(text)
    }

    pub fn set_sensitive(&self, sensitive: bool) {
        self.handle.set_sensitive(sensitive)
    }

    pub fn set_icon(&self, icon: &'static [u8]) {
        let pixbuf = pixbuf_or_blank(icon);
        self.image.set_from_pixbuf(Some(&pixbuf))
    }

    pub fn connect_clicked<F: Fn(&Button) + 'static>(&self, f: F) -> glib::SignalHandlerId {
        self.handle.connect_clicked(f)
    }

    pub fn set_margin_bottom(&self, margin_bottom: i32) {
        self.handle.set_margin_bottom(margin_bottom)
    }

    pub fn set_margin_end(&self, margin_end: i32) {
        self.handle.set_margin_end(margin_end)
    }

    pub fn set_margin_start(&self, margin_start: i32) {
        self.handle.set_margin_start(margin_start)
    }

    pub fn set_margin_top(&self, margin_top: i32) {
        self.handle.set_margin_top(margin_top)
    }
}
