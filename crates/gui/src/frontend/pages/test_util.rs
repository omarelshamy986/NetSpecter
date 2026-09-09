//! Shared test helpers for the GTK4 pages.
//!
//! Unit tests that construct GTK widgets need a display server. On a
//! headless CI runner there is none, so `gtk4::init()` fails — those
//! tests skip themselves instead of failing the build. Locally (with a
//! display or xvfb) they run for real.

/// Initialize GTK for tests once per process. Returns `false` when no
/// display is available (headless CI) — callers should skip.
pub fn gtk_available() -> bool {
    use std::sync::atomic::{AtomicBool, Ordering};
    static INIT: AtomicBool = AtomicBool::new(false);
    static OK: AtomicBool = AtomicBool::new(false);

    if !INIT.swap(true, Ordering::SeqCst) {
        // First caller initializes; everyone else reuses the result.
        let ok = gtk4::init().is_ok();
        OK.store(ok, Ordering::SeqCst);
    }
    OK.load(Ordering::SeqCst)
}
