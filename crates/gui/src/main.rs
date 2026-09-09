use gtk4::gio::ApplicationFlags;
use gtk4::prelude::*;
use gtk4::{Application, Settings};

mod app_shell;
mod backend;
mod frontend;
mod globals;
mod ipc_client;
mod ipc_handlers;
mod types;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = gtk4::init() {
        // No display / broken GTK install: a message on stderr beats a silent panic.
        eprintln!("could not initialize GTK4: {e}");
        eprintln!("If running over SSH, forward X: ssh -X, or set DISPLAY/WAYLAND_DISPLAY.");
        std::process::exit(1);
    }

    // Optional cosmetic setting — missing schemas (flatpak-style setups) must not
    // abort startup over an icon-theme name.
    if let Some(settings) = Settings::default() {
        settings.set_gtk_icon_theme_name(Some("Adwaita"));
    } else {
        log::warn!("gtk Settings schema unavailable — keeping the default icon theme");
    }

    let application = Application::builder()
        .application_id(globals::APP_ID)
        .flags(ApplicationFlags::NON_UNIQUE)
        .build();

    application.connect_activate(frontend::build_ui);
    application.run();
}
