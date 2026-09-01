//! Wireless HID (keyboard / mouse) reconnaissance and injection.
//!
//! A large class of consumer wireless keyboards and mice communicate over
//! proprietary 2.4 GHz protocols on nRF24-class radios rather than
//! Bluetooth. Several of these protocols transmit keystrokes and mouse
//! movements **unencrypted** or with a replayable session key — the class
//! of weaknesses popularly known as *MouseJack* (Bastille, 2016) and
//! *KeySniffer* (Marc Newlin, 2016).
//!
//! NetSpecter's HID module provides the *protocol-analysis* layer:
//!
//! 1. **Channel sweep** — hop across the 2.4 GHz ISM band (channels
//!    2..=84 on nRF24-class hardware) and record bursts of ESB
//!    (Enhanced ShockBurst) packets.
//! 2. **Payload parsing** — decode the discovered device's payload
//!    format into HID reports (key codes / mouse deltas).
//! 3. **Keystroke rendering** — map USB HID usage codes back to
//!    printable characters so a sniffed session can be rendered as text.
//! 4. **Injection framing** — build ESB frames matching a discovered
//!    device's addressing and format, for authorized replay testing.
//!
//! ## Hardware
//!
//! Actual RF transmit/receive requires an nRF24-class radio (CrazyRadio
//! PA flashed with the standard research firmware is the common choice).
//! This module produces and consumes *frames*; the radio driver lives in
//! the agent and is abstracted behind the same interface as the WiFi
//! raw socket.
//!
//! ## Scope
//!
//! Detection and parsing of *unencrypted* protocols. Encrypted protocols
//! (Logitech Unifying with encryption enabled) are detected and flagged,
//! not attacked — breaking the encryption is out of scope for this module.

use serde::{Deserialize, Serialize};

/// ESB (Enhanced ShockBurst) packet as observed on the air.
///
/// nRF24 ESB packets carry a 5-byte addressing prefix (the "address"),
//! a 9-bit packet-control field, and 0..=32 payload bytes. We surface
/// the decoded fields the HID protocols care about.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EsbPacket {
    /// The 5-byte radio address (usually the device's channel address).
    pub address: [u8; 5],
    /// Payload bytes (0..=32).
    pub payload: Vec<u8>,
    /// RSSI at capture time.
    pub rssi_dbm: i8,
    /// The nRF24 channel the packet was captured on (2..=84).
    pub channel: u8,
    /// Wall-clock capture time.
    pub captured_at: String,
}

/// The HID device protocol family a discovered device speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HidProtocol {
    /// Logitech Unifying (encrypted or plaintext — see `encrypted` flag).
    LogitechUnifying,
    /// Microsoft wireless keyboard protocol.
    MicrosoftWireless,
    /// Dell wireless keyboard protocol (plaintext).
    DellWireless,
    /// Generic plaintext ESB keyboard.
    GenericKeyboard,
    /// Generic plaintext ESB mouse.
    GenericMouse,
    /// Unknown / not yet fingerprinted.
    Unknown,
}

impl HidProtocol {
    pub fn label(&self) -> &'static str {
        match self {
            HidProtocol::LogitechUnifying => "Logitech Unifying",
            HidProtocol::MicrosoftWireless => "Microsoft Wireless",
            HidProtocol::DellWireless => "Dell Wireless",
            HidProtocol::GenericKeyboard => "Generic keyboard",
            HidProtocol::GenericMouse => "Generic mouse",
            HidProtocol::Unknown => "Unknown",
        }
    }

    /// Is the protocol known to transmit keystrokes in plaintext?
    pub fn is_plaintext(&self) -> bool {
        matches!(
            self,
            HidProtocol::DellWireless
                | HidProtocol::GenericKeyboard
                | HidProtocol::GenericMouse
                | HidProtocol::MicrosoftWireless
        )
    }
}

/// A decoded HID report from a sniffed packet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HidReport {
    /// A keystroke event.
    Keystroke {
        /// USB HID usage code (0x04='a' ... 0x2D='9' on US layout).
        usage_code: u8,
        /// Modifier byte (ctrl/shift/alt/gui bitmask).
        modifiers: u8,
        /// Is this a key-down (true) or key-up (false) event?
        pressed: bool,
    },
    /// A mouse movement / button event.
    Mouse {
        dx: i16,
        dy: i16,
        buttons: u8,
        /// Scroll wheel delta, when present.
        wheel: Option<i8>,
    },
    /// A keep-alive / sync frame with no input data.
    KeepAlive,
    /// Payload didn't match the expected report format.
    Malformed,
}

/// A discovered wireless HID device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HidDevice {
    /// The 5-byte ESB radio address.
    pub address: [u8; 5],
    /// Human-readable address form (hex, MSB-first).
    pub address_hex: String,
    /// The channel the device was heard on.
    pub channel: u8,
    /// Fingerprinted protocol family.
    pub protocol: HidProtocol,
    /// True if the device's frames are encrypted (Logitech Unifying in
    /// encrypted mode). Encrypted devices are flagged, not attacked.
    pub encrypted: bool,
    /// Number of packets observed.
    pub packet_count: u32,
    /// Rendered keystrokes observed so far (plaintext devices only).
    pub rendered_keys: String,
}

/// USB HID usage-code → character mapping for a US layout.
///
/// Covers the printable subset: letters a-z (0x04..=0x1D), digits 1-9
/// and 0 (0x1E..=0x27), and the common punctuation (0x2D..=0x38).
/// Modifier handling (shift for uppercase / symbols) is applied by
/// [`render_keystroke`].
pub fn usage_to_char(usage: u8, shift: bool) -> Option<char> {
    let lower = |c: char| if shift { c.to_ascii_uppercase() } else { c };
    match usage {
        0x04..=0x1D => {
            let base = b'a' + (usage - 0x04);
            Some(lower(base as char))
        }
        0x1E..=0x26 => {
            // 1..=9
            let d = b'1' + (usage - 0x1E);
            let shifted = ['!', '@', '#', '$', '%', '^', '&', '*', '('][(usage - 0x1E) as usize];
            Some(if shift { shifted } else { d as char })
        }
        0x27 => Some(if shift { ')' } else { '0' }),
        0x2C => Some(if shift { '\n' } else { '\n' }), // Enter
        0x2D => Some(if shift { '_' } else { '-' }),
        0x2E => Some(if shift { '+' } else { '=' }),
        0x2F => Some(if shift { '{' } else { '[' }),
        0x30 => Some(if shift { '}' } else { ']' }),
        0x31 => Some(if shift { '|' } else { '\\' }),
        0x33 => Some(if shift { ':' } else { ';' }),
        0x34 => Some(if shift { '"' } else { '\'' }),
        0x35 => Some(if shift { '~' } else { '`' }),
        0x36 => Some(if shift { '<' } else { ',' }),
        0x37 => Some(if shift { '>' } else { '.' }),
        0x38 => Some(if shift { '?' } else { '/' }),
        0x39 => Some(' '), // Space
        _ => None,
    }
}

/// Modifier bitmask bits (byte 0 of a standard boot-keyboard report).
pub const MOD_SHIFT_LEFT: u8 = 0x02;
pub const MOD_SHIFT_RIGHT: u8 = 0x20;

/// Render a keystroke report to its printable form, honoring shift.
pub fn render_keystroke(usage: u8, modifiers: u8) -> Option<char> {
    let shift = modifiers & (MOD_SHIFT_LEFT | MOD_SHIFT_RIGHT) != 0;
    usage_to_char(usage, shift)
}

/// Attempt to decode an ESB payload as a HID report.
///
/// The heuristics differ by protocol family; this dispatcher routes to
/// the right decoder. Unknown protocols are left [`HidReport::Malformed`]
/// rather than guessed at.
pub fn decode_report(protocol: HidProtocol, payload: &[u8]) -> HidReport {
    match protocol {
        HidProtocol::GenericKeyboard | HidProtocol::DellWireless => {
            decode_generic_keyboard(payload)
        }
        HidProtocol::GenericMouse => decode_generic_mouse(payload),
        HidProtocol::LogitechUnifying => {
            // Encrypted Unifying frames are flagged upstream; the plaintext
            // variants share the generic keyboard format.
            decode_generic_keyboard(payload)
        }
        HidProtocol::MicrosoftWireless | HidProtocol::Unknown => HidReport::Malformed,
    }
}

/// Generic plaintext keyboard frame: `[modifiers, reserved, k1, k2, k3, k4, k5, k6]`.
fn decode_generic_keyboard(payload: &[u8]) -> HidReport {
    if payload.len() < 2 {
        return HidReport::Malformed;
    }
    let modifiers = payload[0];
    // First non-zero key slot is the keystroke; all-zero = key release.
    let usage = payload[2..].iter().copied().find(|&k| k != 0).unwrap_or(0);
    if usage == 0 {
        return HidReport::KeepAlive;
    }
    HidReport::Keystroke {
        usage_code: usage,
        modifiers,
        pressed: true,
    }
}

/// Generic plaintext mouse frame: `[buttons, dx, dy]` with 12-bit deltas
/// packed into two bytes each (sign-extended).
fn decode_generic_mouse(payload: &[u8]) -> HidReport {
    if payload.len() < 3 {
        return HidReport::Malformed;
    }
    let buttons = payload[0];
    let dx = i16::from(payload[1]) >> 4; // sign-extend high nibble
    let dy = i16::from(payload[2]) >> 4;
    HidReport::Mouse {
        dx,
        dy,
        buttons,
        wheel: None,
    }
}

/// Build an ESB frame for injection testing.
///
/// `address` is the target device's radio address; `payload` is the
/// already-encoded HID report. The returned frame is what the radio
/// driver hands to the nRF24 transmit call.
///
/// Injection is only meaningful against devices that don't use encrypted
/// sessions — callers should check [`HidDevice::encrypted`] first.
pub fn build_injection_frame(address: &[u8; 5], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.extend_from_slice(address);
    frame.extend_from_slice(payload);
    frame
}

/// Render a device's observed packets into a keystroke string.
///
/// Plaintext devices accumulate readable text (the KeySniffer view);
/// encrypted devices return a placeholder so reports are honest about
/// what was (and wasn't) captured.
pub fn render_session(device: &HidDevice, packets: &[EsbPacket]) -> String {
    if device.encrypted {
        return "<encrypted session — keystrokes not recoverable>".into();
    }
    let mut out = String::new();
    for pkt in packets {
        if let HidReport::Keystroke {
            usage_code, modifiers, ..
        } = decode_report(device.protocol, &pkt.payload)
            && let Some(ch) = render_keystroke(usage_code, modifiers)
        {
            out.push(ch);
        }
    }
    out
}

/// Fingerprint a device from its observed traffic.
///
/// The heuristics are intentionally shallow — a full protocol
/// fingerprinter is research-grade work. We flag the well-known
/// vendors by their OUI-like address prefixes and default to
/// GenericKeyboard / GenericMouse based on payload shape.
pub fn fingerprint(address: &[u8; 5], payload_samples: &[Vec<u8>]) -> (HidProtocol, bool) {
    // Logitech Unifying addresses conventionally start with 0xA5 / 0xD3
    // in the MSB of the first byte on many dongle generations.
    if address[0] == 0xA5 || address[0] == 0xD3 {
        return (HidProtocol::LogitechUnifying, true); // assume encrypted
    }
    // Dell keyboards: known fixed prefix on several models.
    if address[0] == 0x5C && address[1] == 0x8F {
        return (HidProtocol::DellWireless, false);
    }
    // Microsoft: prefix seen on several 2.4 GHz keyboards.
    if address[0] == 0xCD {
        return (HidProtocol::MicrosoftWireless, false);
    }
    // Payload-shape heuristic: length-8 with modifier-like first byte
    // reads as keyboard; length-3 reads as mouse.
    if let Some(first) = payload_samples.first() {
        if first.len() == 8 {
            return (HidProtocol::GenericKeyboard, false);
        }
        if first.len() == 3 {
            return (HidProtocol::GenericMouse, false);
        }
    }
    (HidProtocol::Unknown, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_letters_lowercase_without_shift() {
        assert_eq!(usage_to_char(0x04, false), Some('a'));
        assert_eq!(usage_to_char(0x05, false), Some('b'));
        assert_eq!(usage_to_char(0x1D, false), Some('z'));
    }

    #[test]
    fn usage_letters_uppercase_with_shift() {
        assert_eq!(usage_to_char(0x04, true), Some('A'));
        assert_eq!(usage_to_char(0x1D, true), Some('Z'));
    }

    #[test]
    fn usage_digits_and_shift_symbols() {
        assert_eq!(usage_to_char(0x1E, false), Some('1'));
        assert_eq!(usage_to_char(0x1E, true), Some('!'));
        assert_eq!(usage_to_char(0x26, false), Some('9'));
        assert_eq!(usage_to_char(0x26, true), Some('('));
        assert_eq!(usage_to_char(0x27, false), Some('0'));
        assert_eq!(usage_to_char(0x27, true), Some(')'));
    }

    #[test]
    fn usage_punctuation() {
        assert_eq!(usage_to_char(0x2D, false), Some('-'));
        assert_eq!(usage_to_char(0x2D, true), Some('_'));
        assert_eq!(usage_to_char(0x38, false), Some('/'));
        assert_eq!(usage_to_char(0x38, true), Some('?'));
        assert_eq!(usage_to_char(0x39, false), Some(' '));
    }

    #[test]
    fn usage_unknown_codes_return_none() {
        assert_eq!(usage_to_char(0x00, false), None);
        assert_eq!(usage_to_char(0xFF, false), None);
        // F-keys / arrows aren't printable
        assert_eq!(usage_to_char(0x3A, false), None); // F1
    }

    #[test]
    fn render_keystroke_applies_modifier_mask() {
        assert_eq!(render_keystroke(0x04, 0x00), Some('a'));
        assert_eq!(render_keystroke(0x04, MOD_SHIFT_LEFT), Some('A'));
        assert_eq!(render_keystroke(0x04, MOD_SHIFT_RIGHT), Some('A'));
        assert_eq!(render_keystroke(0x04, 0x01), Some('a')); // ctrl only
    }

    #[test]
    fn decode_generic_keyboard_extracts_keystroke() {
        // [mod=0x02 (left shift), reserved, a=0x04, 0, 0, 0, 0, 0]
        let payload = vec![0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        match decode_report(HidProtocol::GenericKeyboard, &payload) {
            HidReport::Keystroke {
                usage_code,
                modifiers,
                pressed,
            } => {
                assert_eq!(usage_code, 0x04);
                assert_eq!(modifiers, 0x02);
                assert!(pressed);
            }
            other => panic!("expected keystroke, got {other:?}"),
        }
    }

    #[test]
    fn decode_generic_keyboard_all_zero_is_keepalive() {
        let payload = vec![0x00u8; 8];
        assert!(matches!(
            decode_report(HidProtocol::GenericKeyboard, &payload),
            HidReport::KeepAlive
        ));
    }

    #[test]
    fn decode_generic_keyboard_short_payload_is_malformed() {
        assert!(matches!(
            decode_report(HidProtocol::GenericKeyboard, &[0x00]),
            HidReport::Malformed
        ));
    }

    #[test]
    fn decode_generic_mouse_extracts_deltas() {
        // buttons=1 (left), dx=0x0F (sign-extended high nibble → -1),
        // dy=0x10 (sign-extended → +1)
        let payload = vec![0x01, 0xFF, 0x10];
        match decode_report(HidProtocol::GenericMouse, &payload) {
            HidReport::Mouse { dx, dy, buttons, wheel } => {
                assert_eq!(dx, -1);
                assert_eq!(dy, 1);
                assert_eq!(buttons, 1);
                assert_eq!(wheel, None);
            }
            other => panic!("expected mouse, got {other:?}"),
        }
    }

    #[test]
    fn decode_unknown_protocol_is_malformed() {
        let payload = vec![0x00, 0x00, 0x04];
        assert!(matches!(
            decode_report(HidProtocol::Unknown, &payload),
            HidReport::Malformed
        ));
        assert!(matches!(
            decode_report(HidProtocol::MicrosoftWireless, &payload),
            HidReport::Malformed
        ));
    }

    #[test]
    fn build_injection_frame_prepends_address() {
        let address = [0xA5, 0x5A, 0x01, 0x02, 0x03];
        let payload = vec![0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        let frame = build_injection_frame(&address, &payload);
        assert_eq!(frame.len(), 5 + payload.len());
        assert_eq!(&frame[..5], &address);
        assert_eq!(&frame[5..], &payload[..]);
    }

    #[test]
    fn render_session_flags_encrypted_devices() {
        let dev = HidDevice {
            address: [0xA5; 5],
            address_hex: "a5:a5:a5:a5:a5".into(),
            channel: 40,
            protocol: HidProtocol::LogitechUnifying,
            encrypted: true,
            packet_count: 10,
            rendered_keys: String::new(),
        };
        let packets = vec![EsbPacket {
            address: [0xA5; 5],
            payload: vec![0x00; 8],
            rssi_dbm: -60,
            channel: 40,
            captured_at: "2026-01-01T00:00:00Z".into(),
        }];
        assert!(render_session(&dev, &packets).contains("encrypted"));
    }

    #[test]
    fn render_session_renders_plaintext_keys() {
        let dev = HidDevice {
            address: [0x5C; 5],
            address_hex: "5c:5c:5c:5c:5c".into(),
            channel: 22,
            protocol: HidProtocol::DellWireless,
            encrypted: false,
            packet_count: 2,
            rendered_keys: String::new(),
        };
        // "hi" — h=0x0B, i=0x0C, both unshifted
        let packets = vec![
            EsbPacket {
                address: [0x5C; 5],
                payload: vec![0x00, 0x00, 0x0B, 0, 0, 0, 0, 0],
                rssi_dbm: -60,
                channel: 22,
                captured_at: "2026-01-01T00:00:00Z".into(),
            },
            EsbPacket {
                address: [0x5C; 5],
                payload: vec![0x00, 0x00, 0x0C, 0, 0, 0, 0, 0],
                rssi_dbm: -60,
                channel: 22,
                captured_at: "2026-01-01T00:00:01Z".into(),
            },
        ];
        assert_eq!(render_session(&dev, &packets), "hi");
    }

    #[test]
    fn fingerprint_detects_logitech_prefix() {
        let (proto, encrypted) = fingerprint(&[0xA5, 1, 2, 3, 4], &[]);
        assert_eq!(proto, HidProtocol::LogitechUnifying);
        assert!(encrypted);
    }

    #[test]
    fn fingerprint_detects_dell_prefix() {
        let (proto, encrypted) = fingerprint(&[0x5C, 0x8F, 1, 2, 3], &[]);
        assert_eq!(proto, HidProtocol::DellWireless);
        assert!(!encrypted);
    }

    #[test]
    fn fingerprint_heuristic_by_payload_shape() {
        let (kb, enc) = fingerprint(&[0x11, 1, 2, 3, 4], &[vec![0u8; 8]]);
        assert_eq!(kb, HidProtocol::GenericKeyboard);
        assert!(!enc);
        let (ms, _) = fingerprint(&[0x22, 1, 2, 3, 4], &[vec![0u8; 3]]);
        assert_eq!(ms, HidProtocol::GenericMouse);
    }

    #[test]
    fn fingerprint_unknown_when_no_signals() {
        let (proto, _) = fingerprint(&[0x99, 1, 2, 3, 4], &[]);
        assert_eq!(proto, HidProtocol::Unknown);
    }

    #[test]
    fn protocol_labels_and_plaintext_flags() {
        assert!(HidProtocol::DellWireless.is_plaintext());
        assert!(HidProtocol::GenericKeyboard.is_plaintext());
        assert!(!HidProtocol::LogitechUnifying.is_plaintext());
        assert_eq!(HidProtocol::LogitechUnifying.label(), "Logitech Unifying");
    }

    #[test]
    fn esb_packet_serializes_round_trip() {
        let pkt = EsbPacket {
            address: [1, 2, 3, 4, 5],
            payload: vec![9, 8, 7],
            rssi_dbm: -55,
            channel: 33,
            captured_at: "2026-01-01T00:00:00Z".into(),
        };
        let j = serde_json::to_string(&pkt).unwrap();
        let back: EsbPacket = serde_json::from_str(&j).unwrap();
        assert_eq!(back.address, pkt.address);
        assert_eq!(back.payload, pkt.payload);
        assert_eq!(back.rssi_dbm, pkt.rssi_dbm);
    }
}