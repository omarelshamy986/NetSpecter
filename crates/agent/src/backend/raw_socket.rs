//! Shared raw `AF_PACKET` socket helpers for capturing and injecting 802.11
//! frames on the monitor interface. The capture engine ([`super::sniffer`]) reads
//! radiotap-prefixed frames off it; the deauth engine ([`super::deauth`]) injects
//! them.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Open a raw `AF_PACKET` socket bound to `iface`, seeing/sending every frame.
pub fn open(iface: &str) -> io::Result<OwnedFd> {
    let eth_p_all = (libc::ETH_P_ALL as u16).to_be();

    // SAFETY: standard socket(2) call; the returned fd is immediately wrapped in an
    // OwnedFd so it is closed on drop.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all as i32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };

    let ifindex = interface_index(iface)?;

    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = eth_p_all;
    addr.sll_ifindex = ifindex as i32;

    // SAFETY: bind(2) with a correctly sized sockaddr_ll.
    let ret = unsafe {
        libc::bind(
            socket.as_raw_fd(),
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(socket)
}

/// Set a receive timeout, so a capture loop can hop channels and poll a stop flag.
pub fn set_recv_timeout(socket: &OwnedFd, millis: i64) -> io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: millis / 1000,
        tv_usec: (millis % 1000) * 1000,
    };
    // SAFETY: setsockopt(2) with a correctly sized timeval.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &timeout as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive one frame, returning the number of bytes read (0 on an empty read).
pub fn recv(socket: &OwnedFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: recv(2) into a buffer of the given length.
    let n = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Send one raw frame (radiotap header followed by the 802.11 frame).
pub fn send(socket: &OwnedFd, frame: &[u8]) -> io::Result<()> {
    // SAFETY: send(2) from a buffer of the given length.
    let n = unsafe {
        libc::send(
            socket.as_raw_fd(),
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Inject an 802.11 open-system authentication request and an
/// association request toward an AP, as the first step of the PMKID
/// harvest (the AP answers EAPOL M1 to any associating station).
///
/// Builds both frames with a minimal radiotap preamble and sends them
/// back to back. The caller listens for the AP's EAPOL response on the
/// same socket.
pub fn associate_open(
    socket: &OwnedFd,
    bssid: &[u8; 6],
    station: &[u8; 6],
) -> io::Result<()> {
    // ── Authentication request (type/subtype 0xB0) ──
    let mut auth = Vec::with_capacity(8 + 30);
    auth.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0]); // radiotap
    auth.push(0xb0); // frame control: authentication
    auth.push(0x00);
    auth.extend_from_slice(&[0x00, 0x00]); // duration
    auth.extend_from_slice(bssid); // addr1: AP
    auth.extend_from_slice(station); // addr2: us
    auth.extend_from_slice(bssid); // addr3: BSSID
    auth.extend_from_slice(&[0x00, 0x00]); // seq
    auth.extend_from_slice(&[0x00, 0x00]); // auth algorithm: open
    auth.extend_from_slice(&[0x01, 0x00]); // auth transaction seq: 1
    auth.extend_from_slice(&[0x00, 0x00]); // status: success
    send(socket, &auth)?;

    // ── Association request (type/subtype 0x00) ──
    let mut assoc = Vec::with_capacity(8 + 36);
    assoc.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0]); // radiotap
    assoc.push(0x00); // frame control: association request
    assoc.push(0x00);
    assoc.extend_from_slice(&[0x00, 0x00]); // duration
    assoc.extend_from_slice(bssid); // addr1: AP
    assoc.extend_from_slice(station); // addr2: us
    assoc.extend_from_slice(bssid); // addr3: BSSID
    assoc.extend_from_slice(&[0x00, 0x00]); // seq
    assoc.extend_from_slice(&[0x01, 0x00]); // capability: ESS
    assoc.extend_from_slice(&[0x01, 0x00]); // listen interval: 1 TU
    // SSID IE: broadcast/empty (the AP knows its own ESSID)
    assoc.push(0x00);
    assoc.push(0x00);
    // Supported rates IE (same set the beacon module uses)
    assoc.push(0x01);
    assoc.push(0x08);
    assoc.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c]);
    send(socket, &assoc)?;

    Ok(())
}

/// Resolve an interface name to its kernel index.
fn interface_index(iface: &str) -> io::Result<u32> {
    let name = CString::new(iface).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name contains a nul")
    })?;
    // SAFETY: if_nametoindex(3) reads a valid C string; returns 0 on error.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}
