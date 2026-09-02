//! GUI-side IPC client.
//!
//! Wraps the framed-JSON socket protocol in a small, async-friendly API.
//! Each NetSpecter page holds an `IpcClient` handle; the client dispatches
//! `Request` variants and returns typed `Response` variants.
//!
//! The client is **synchronous** (blocking calls) — GTK4 runs on the main
//! thread, so async dispatch would have to bounce back to the main loop
//! anyway. Pages that want non-blocking behavior should run their IPC
//! calls on a worker thread and `glib::idle_add()` the result back.
//!
//! ## Wire format
//!
//! 4-byte big-endian length prefix, then JSON. Matches what the agent
//! produces (`common::ipc::{write_msg, read_msg}`).
//!
//! ## Reconnect
//!
//! The agent may restart between GUI sessions; the client exposes
//! `connect()` / `disconnect()` and re-opens the socket on demand. A
//! dropped connection surfaces as `IpcError::Disconnected`, which the
//! pages translate to a "agent offline" status indicator.

use netspecter_common::ipc::{read_msg, write_msg, Request, Response};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(thiserror::Error, Debug)]
pub enum IpcError {
    #[error("agent is not connected — call connect() first")]
    Disconnected,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(String),
    #[error("agent returned error: {0}")]
    AgentError(String),
    #[error("agent response was not the expected variant")]
    UnexpectedResponse,
}

/// A typed wrapper around the agent's Unix-domain socket.
///
/// The handle is cheap to clone (it's an `Arc<Mutex<Option<UnixStream>>>`),
/// so pages can each own their own copy without paying for an extra socket.
#[derive(Clone)]
pub struct IpcClient {
    stream: Arc<Mutex<Option<UnixStream>>>,
    socket_path: String,
}

impl IpcClient {
    /// Create a client handle pointing at the agent's socket. The client
    /// is initially disconnected; call `connect()` to open the stream.
    pub fn new(uid: u32, instance: u32) -> Self {
        let path = netspecter_common::ipc::socket_path(uid, instance);
        Self {
            stream: Arc::new(Mutex::new(None)),
            socket_path: path,
        }
    }

    /// Create a client handle for a custom socket path (used by tests).
    pub fn with_path(path: impl Into<String>) -> Self {
        Self {
            stream: Arc::new(Mutex::new(None)),
            socket_path: path.into(),
        }
    }

    /// Open the socket and send the `Hello` handshake. Idempotent.
    pub fn connect(&self) -> Result<(), IpcError> {
        let mut guard = self.stream.lock().expect("IpcClient mutex poisoned");
        if guard.is_some() {
            return Ok(());
        }
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        *guard = Some(stream);

        // Handshake.
        let version = netspecter_common::VERSION.to_string();
        write_msg(guard.as_mut().unwrap(), &Request::Hello { version })?;
        let response: Response = read_msg(guard.as_mut().unwrap())?;
        match response {
            Response::Setup { .. } => Ok(()),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Close the underlying socket, if open.
    pub fn disconnect(&self) {
        let mut guard = self.stream.lock().expect("IpcClient mutex poisoned");
        if let Some(stream) = guard.take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// True if the underlying socket is currently open.
    pub fn is_connected(&self) -> bool {
        self.stream
            .lock()
            .expect("IpcClient mutex poisoned")
            .is_some()
    }

    /// The path of the agent socket.
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    /// Dispatch a typed request and return the typed response.
    ///
    /// Convenience wrappers (e.g. `harvest_pmkid()`) wrap this with the
    /// response-variant unpacking, so pages never have to match on the
    /// enum themselves.
    pub fn call(&self, req: Request) -> Result<Response, IpcError> {
        let mut guard = self.stream.lock().expect("IpcClient mutex poisoned");
        let stream = guard.as_mut().ok_or(IpcError::Disconnected)?;
        write_msg(stream, &req)?;
        let resp: Response = read_msg(stream)?;
        Ok(resp)
    }

    // ── typed convenience wrappers ──

    /// Trigger a PMKID harvest.
    pub fn harvest_pmkid(
        &self,
        bssid: &str,
        essid: &str,
        timeout_secs: u64,
    ) -> Result<netspecter_common::ipc::PmkidCapture, IpcError> {
        match self.call(Request::HarvestPmkid {
            bssid: bssid.into(),
            essid: essid.into(),
            timeout_secs,
        })? {
            Response::PmkidCapture(c) => Ok(c),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Verify a candidate passphrase against a captured PMKID.
    pub fn verify_psk(
        &self,
        candidate: &str,
        ssid: &str,
        bssid: &str,
        sta: &str,
        pmkid_hex: &str,
    ) -> Result<bool, IpcError> {
        match self.call(Request::VerifyPskAgainstPmkid {
            candidate: candidate.into(),
            ssid: ssid.into(),
            bssid: bssid.into(),
            sta: sta.into(),
            pmkid_hex: pmkid_hex.into(),
        })? {
            Response::Bool(b) => Ok(b),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Build a Smart-Wizard plan for the given AP.
    pub fn wizard_plan_for(
        &self,
        ap: netspecter_common::types::AP,
    ) -> Result<netspecter_common::ipc::WizardPlan, IpcError> {
        match self.call(Request::WizardPlanFor { ap })? {
            Response::WizardPlan(p) => Ok(p),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Discover the ESSID of a hidden AP.
    pub fn discover_hidden_ssid(
        &self,
        bssid: &str,
        channel: &str,
    ) -> Result<Vec<netspecter_common::ipc::HiddenSsidCandidate>, IpcError> {
        match self.call(Request::DiscoverHiddenSsid {
            bssid: bssid.into(),
            channel: channel.into(),
        })? {
            Response::HiddenSsidCandidates(c) => Ok(c),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Launch a beacon-flooding attack to provoke probe requests from
    /// clients of a hidden AP. Returns a single-element vector with the
    /// recovered candidate on success.
    pub fn beacon_flood_hidden(
        &self,
        bssid: &str,
        channel: u8,
        timeout_secs: u64,
    ) -> Result<Vec<netspecter_common::ipc::HiddenSsidCandidate>, IpcError> {
        match self.call(Request::BeaconFloodHidden {
            bssid: bssid.into(),
            channel,
            timeout_secs,
        })? {
            Response::HiddenSsidCandidates(c) => Ok(c),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Launch the full Auto-Pwn pipeline. Poll with poll_auto_pwn for
    /// live events; the final result arrives in a poll batch.
    pub fn start_auto_pwn(
        &self,
        config: netspecter_common::autopwn::AutoPwnConfig,
    ) -> Result<(), IpcError> {
        match self.call(Request::StartAutoPwn { config })? {
            Response::AutoPwnStarted => Ok(()),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Poll the running Auto-Pwn pipeline: events since the last poll,
    /// plus the final result once complete.
    pub fn poll_auto_pwn(
        &self,
    ) -> Result<
        (
            Vec<netspecter_common::autopwn::PipelineEvent>,
            Option<netspecter_common::autopwn::AutoPwnResult>,
        ),
        IpcError,
    > {
        match self.call(Request::PollAutoPwn)? {
            Response::AutoPwnEvents { events, result } => Ok((events, result)),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Launch an Evil-Twin session.
    pub fn launch_evil_twin(
        &self,
        config: netspecter_common::ipc::EvilTwinConfig,
    ) -> Result<netspecter_common::ipc::EvilTwinSession, IpcError> {
        match self.call(Request::LaunchEvilTwin { config })? {
            Response::EvilTwinSession(s) => Ok(s),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Stop an Evil-Twin session by interface.
    pub fn stop_evil_twin(&self, iface: &str) -> Result<(), IpcError> {
        match self.call(Request::StopEvilTwin { iface: iface.into() })? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }

    /// Generate a report. Returns the paths of the produced files.
    pub fn generate_report(
        &self,
        targets: Vec<netspecter_common::ipc::TargetReport>,
        plans: Vec<netspecter_common::ipc::WizardPlan>,
        output_dir: &str,
    ) -> Result<netspecter_common::ipc::ReportPaths, IpcError> {
        match self.call(Request::GenerateReport {
            targets,
            plans,
            output_dir: output_dir.into(),
        })? {
            Response::ReportPaths(p) => Ok(p),
            Response::Error { message } => Err(IpcError::AgentError(message)),
            _ => Err(IpcError::UnexpectedResponse),
        }
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

/// Pure-I/O helpers exposed for unit-testing the wire format without an
/// actual agent.
pub mod test_helpers {
    use super::*;

    /// Write a length-prefixed JSON request to anything `Write`-able.
    pub fn write_request<W: Write>(w: &mut W, req: &Request) -> std::io::Result<()> {
        write_msg(w, req)
    }

    /// Read a length-prefixed JSON response from anything `Read`-able.
    pub fn read_response<R: Read>(r: &mut R) -> std::io::Result<Response> {
        read_msg(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn spawn_mock_agent(responder: fn(Request) -> Response) -> String {
        let dir = tempdir_uniq();
        let path = dir.join("agent.sock");
        let listener = UnixListener::bind(&path).expect("bind");

        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let mut stream = stream;
                // Read the handshake (Hello) and reply with Setup.
                let req: Request = read_msg(&mut stream).unwrap();
                assert!(matches!(req, Request::Hello { .. }));
                write_msg(&mut stream, &Response::Setup { missing_dependencies: vec![] }).unwrap();
                // Loop on subsequent requests.
                loop {
                    let req: Request = match read_msg(&mut stream) {
                        Ok(r) => r,
                        Err(_) => return,
                    };
                    if matches!(req, Request::Shutdown) {
                        let _ = write_msg(&mut stream, &Response::Ok);
                        return;
                    }
                    let resp = responder(req);
                    if write_msg(&mut stream, &resp).is_err() {
                        return;
                    }
                }
            }
        });

        path.to_string_lossy().into_owned()
    }

    fn tempdir_uniq() -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("netspecter-ipc-{stamp}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn connect_and_handshake() {
        let path = spawn_mock_agent(|_| Response::Ok);
        let client = IpcClient::with_path(path);
        client.connect().unwrap();
        assert!(client.is_connected());
        client.disconnect();
        assert!(!client.is_connected());
    }

    #[test]
    fn harvest_pmkid_round_trip() {
        let path = spawn_mock_agent(|_| Response::PmkidCapture(
            netspecter_common::ipc::PmkidCapture {
                bssid: "aa:bb:cc:dd:ee:ff".into(),
                station: "11:22:33:44:55:66".into(),
                essid: "TestNet".into(),
                pmkid_hex: "00112233445566778899aabbccddeeff".into(),
                capture_path: Some("/tmp/cap.pcap".into()),
                captured_at: "2026-01-01T00:00:00Z".into(),
            },
        ));
        let client = IpcClient::with_path(path);
        client.connect().unwrap();
        let cap = client.harvest_pmkid("aa:bb:cc:dd:ee:ff", "TestNet", 60).unwrap();
        assert_eq!(cap.essid, "TestNet");
        assert_eq!(cap.pmkid_hex.len(), 32);
    }

    #[test]
    fn verify_psk_round_trip() {
        let path = spawn_mock_agent(|_| Response::Bool(true));
        let client = IpcClient::with_path(path);
        client.connect().unwrap();
        let ok = client
            .verify_psk("12345678", "linksys", "aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", "00112233445566778899aabbccddeeff")
            .unwrap();
        assert!(ok);
    }

    #[test]
    fn call_without_connect_returns_disconnected() {
        let client = IpcClient::with_path("/nonexistent");
        let err = client.call(Request::IsScanning).unwrap_err();
        assert!(matches!(err, IpcError::Disconnected));
    }

    #[test]
    fn agent_error_propagates() {
        let path = spawn_mock_agent(|_| Response::Error {
            message: "PMKID harvest timed out".into(),
        });
        let client = IpcClient::with_path(path);
        client.connect().unwrap();
        let err = client.harvest_pmkid("aa:bb:cc:dd:ee:ff", "X", 1).unwrap_err();
        match err {
            IpcError::AgentError(m) => assert_eq!(m, "PMKID harvest timed out"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unexpected_response_variant_is_caught() {
        let path = spawn_mock_agent(|_| Response::Ok);
        let client = IpcClient::with_path(path);
        client.connect().unwrap();
        // harvest_pmkid expects Response::PmkidCapture, but the mock returns Ok.
        let err = client.harvest_pmkid("aa:bb:cc:dd:ee:ff", "X", 1).unwrap_err();
        assert!(matches!(err, IpcError::UnexpectedResponse));
    }
}