//! WPS (Wi-Fi Protected Setup) TLV parser.
//!
//! WPS messages are TLV (Type-Length-Value) encoded. The relevant tags for
//! Pixie Dust / PIN recovery are stable across vendors and defined in the
//! WPS 2.0 specification:
//!
//! | Tag    | Name              | Length |
//! |--------|-------------------|--------|
//! | 0x104A | Public Key        | 192    |
//! | 0x101E | E-Nonce           | 16     |
//! | 0x1018 | Authenticator     | 8      |
//! | 0x1014 | E-Hash1           | 20     |
//! | 0x1015 | E-Hash2           | 20     |
//! | 0x103B | E-S1 (encrypted)  | 16     |
//! | 0x103C | E-S2 (encrypted)  | 16     |
//!
//! The parser is generic over any TLV stream: it walks the stream, surfaces
//! the well-known fields by tag, and ignores everything else. The higher-
//! level WPS-attack code in `wps.rs` consumes the parsed fields to drive
//! Pixie-Dust recovery.
//!
//! ## Frame layout
//!
//! WPS messages ride inside EAPOL data frames (the WPS exchange happens
//! over EAPOL after the standard WPA 4-way). The EAPOL payload carries a
//! vendor-specific WPS IE. We don't *parse* EAPOL here — we walk whatever
//! raw bytes the caller gives us and look for the WPS TLV tags.

use std::collections::HashMap;

/// A single TLV entry parsed out of a WPS message.
#[derive(Clone, Debug)]
pub struct Tlv {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// Result of parsing a WPS message — the well-known fields pre-extracted,
/// plus the raw TLV list for anything the recovery code wants to inspect.
#[derive(Clone, Debug, Default)]
pub struct WpsMessage {
    pub public_key: Option<[u8; 192]>,
    pub e_nonce: Option<[u8; 16]>,
    pub authenticator: Option<[u8; 8]>,
    pub e_hash1: Option<[u8; 20]>,
    pub e_hash2: Option<[u8; 20]>,
    pub e_s1: Option<[u8; 16]>,
    pub e_s2: Option<[u8; 16]>,
    /// All TLVs, keyed by tag. Used by chip-specific recovery code.
    pub raw: HashMap<u16, Vec<u8>>,
}

impl WpsMessage {
    /// Did this message contain the fields needed for Pixie Dust M1?
    pub fn has_m1_fields(&self) -> bool {
        self.public_key.is_some() && self.e_nonce.is_some()
    }

    /// Did this message contain the fields needed for Pixie Dust M3?
    pub fn has_m3_fields(&self) -> bool {
        self.e_hash1.is_some() && self.e_hash2.is_some() && self.authenticator.is_some()
    }
}

/// Errors the parser can return.
#[derive(Debug)]
pub enum TlvError {
    /// Hit the end of the buffer before reading a complete TLV header.
    Truncated,
    /// A length field extends past the end of the buffer.
    LengthOverflow,
    /// A field's length doesn't match what the tag requires (e.g. E-Nonce
    /// that's not exactly 16 bytes).
    WrongLength { tag: u16, expected: usize, got: usize },
    /// The buffer is too short to even contain a TLV header.
    TooShort,
}

/// Parse a raw WPS message buffer into a [`WpsMessage`].
///
/// Walks the buffer tag-by-tag. Tags are big-endian u16; the length field
/// that follows is also big-endian u16 (the WPS spec is unambiguous on
/// this).
pub fn parse(data: &[u8]) -> Result<WpsMessage, TlvError> {
    let mut msg = WpsMessage::default();
    let mut offset = 0;

    while offset < data.len() {
        if data.len() - offset < 4 {
            // Trailer of <4 bytes — could be padding; treat as end-of-stream.
            break;
        }
        let tag = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        let end = offset.checked_add(len).ok_or(TlvError::LengthOverflow)?;
        if end > data.len() {
            return Err(TlvError::Truncated);
        }
        let value = &data[offset..end];
        offset = end;

        // Store the raw TLV for downstream consumers.
        msg.raw.insert(tag, value.to_vec());

        // Pre-extract the well-known fields.
        match tag {
            0x104A if value.len() == 192 => {
                let mut arr = [0u8; 192];
                arr.copy_from_slice(value);
                msg.public_key = Some(arr);
            }
            0x101E if value.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(value);
                msg.e_nonce = Some(arr);
            }
            0x1018 if value.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(value);
                msg.authenticator = Some(arr);
            }
            0x1014 if value.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(value);
                msg.e_hash1 = Some(arr);
            }
            0x1015 if value.len() == 20 => {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(value);
                msg.e_hash2 = Some(arr);
            }
            0x103B if value.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(value);
                msg.e_s1 = Some(arr);
            }
            0x103C if value.len() == 16 => {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(value);
                msg.e_s2 = Some(arr);
            }
            _ => { /* ignore unknown tags */ }
        }
    }
    Ok(msg)
}

/// Build a WPS TLV-encoded message from a list of `(tag, value)` pairs.
///
/// Used by tests and by any future code that wants to *emit* a WPS message
/// (e.g. for fuzzing). The output is the concatenation of each entry's
/// 4-byte big-endian header followed by the value bytes.
pub fn build(entries: &[(u16, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (tag, value) in entries {
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

/// The two parsed WPS messages needed for Pixie Dust — M1 (AP → STA) and
/// M3 (STA → AP). Together they carry the public-key / nonce / hash fields
/// the recovery loop consumes.
#[derive(Clone, Debug)]
pub struct ParsedExchange {
    pub m1: WpsMessage,
    pub m3: WpsMessage,
}

impl ParsedExchange {
    /// True if both messages contain the fields required for recovery.
    pub fn is_complete(&self) -> bool {
        self.m1.has_m1_fields() && self.m3.has_m3_fields()
    }

    /// Parse both M1 and M3 buffers.
    pub fn parse(m1: &[u8], m3: &[u8]) -> Result<Self, TlvError> {
        Ok(Self {
            m1: parse(m1)?,
            m3: parse(m3)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tag.to_be_bytes());
        v.extend_from_slice(&(value.len() as u16).to_be_bytes());
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn parse_extracts_public_key() {
        let pk = [0xab; 192];
        let msg = parse(&tlv(0x104A, &pk)).unwrap();
        assert!(msg.public_key.is_some());
        assert_eq!(msg.public_key.unwrap()[0], 0xab);
        assert_eq!(msg.public_key.unwrap()[191], 0xab);
    }

    #[test]
    fn parse_extracts_all_known_fields() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(0x104A, &[0x01; 192]));
        buf.extend_from_slice(&tlv(0x101E, &[0x02; 16]));
        buf.extend_from_slice(&tlv(0x1018, &[0x03; 8]));
        buf.extend_from_slice(&tlv(0x1014, &[0x04; 20]));
        buf.extend_from_slice(&tlv(0x1015, &[0x05; 20]));
        buf.extend_from_slice(&tlv(0x103B, &[0x06; 16]));
        buf.extend_from_slice(&tlv(0x103C, &[0x07; 16]));

        let msg = parse(&buf).unwrap();
        assert!(msg.has_m1_fields());
        assert!(msg.has_m3_fields());
        assert_eq!(msg.e_nonce.unwrap()[0], 0x02);
        assert_eq!(msg.e_hash1.unwrap()[0], 0x04);
        assert_eq!(msg.e_hash2.unwrap()[0], 0x05);
        assert_eq!(msg.e_s1.unwrap()[0], 0x06);
        assert_eq!(msg.e_s2.unwrap()[0], 0x07);
    }

    #[test]
    fn parse_ignores_unknown_tags() {
        let buf = tlv(0x9999, &[1, 2, 3]);
        let msg = parse(&buf).unwrap();
        assert!(!msg.has_m1_fields());
        assert!(msg.raw.contains_key(&0x9999));
    }

    #[test]
    fn parse_rejects_truncated_buffer() {
        // tag + length header claiming 10 bytes, but only 2 are present.
        let mut buf = vec![0x10, 0x4A, 0x00, 0x10]; // tag=0x104A, len=16
        buf.extend_from_slice(&[0x00; 2]);
        let err = parse(&buf).unwrap_err();
        assert!(matches!(err, TlvError::Truncated));
    }

    #[test]
    fn parse_handles_zero_length_value() {
        let buf = tlv(0x104A, &[]);
        let msg = parse(&buf).unwrap();
        assert!(msg.public_key.is_none()); // wrong length, so skipped
        assert!(msg.raw.contains_key(&0x104A));
    }

    #[test]
    fn parse_handles_padding_after_records() {
        // After a valid TLV, a <4-byte padding should be tolerated.
        let mut buf = tlv(0x104A, &[0xff; 192]);
        buf.extend_from_slice(&[0xde, 0xad]); // 2-byte padding
        let msg = parse(&buf).unwrap();
        assert!(msg.public_key.is_some());
    }

    #[test]
    fn build_round_trips_through_parse() {
        // Bind the vectors first: &[..][..] inside the entries vec
        // creates temporaries that are freed at the end of the statement,
        // while `build(&entries)` still borrows them (E0716).
        let big = [0xab; 192];
        let mid = [0xcd; 16];
        let small = [0xef; 8];
        let entries = vec![
            (0x104Au16, &big[..]),
            (0x101Eu16, &mid[..]),
            (0x1018u16, &small[..]),
        ];
        let encoded = build(&entries);
        let msg = parse(&encoded).unwrap();
        assert_eq!(msg.public_key.unwrap()[100], 0xab);
        assert_eq!(msg.e_nonce.unwrap()[5], 0xcd);
        assert_eq!(msg.authenticator.unwrap()[3], 0xef);
    }

    #[test]
    fn parsed_exchange_requires_both_messages() {
        let pk = [0xab; 192];
        let m1 = build(&[(0x104A, &pk[..]), (0x101E, &[0x02; 16][..])]);
        let m3 = build(&[
            (0x1018, &[0x03; 8][..]),
            (0x1014, &[0x04; 20][..]),
            (0x1015, &[0x05; 20][..]),
        ]);
        let ex = ParsedExchange::parse(&m1, &m3).unwrap();
        assert!(ex.is_complete());
    }

    #[test]
    fn parsed_exchange_incomplete_when_m3_missing_hashes() {
        let pk = [0xab; 192];
        let m1 = build(&[(0x104A, &pk[..]), (0x101E, &[0x02; 16][..])]);
        let m3 = build(&[(0x1018, &[0x03; 8][..])]); // no E-Hash1/E-Hash2
        let ex = ParsedExchange::parse(&m1, &m3).unwrap();
        assert!(!ex.is_complete());
    }

    #[test]
    fn wrong_length_for_e_nonce_is_ignored_not_panicked() {
        let buf = tlv(0x101E, &[0xab; 8]); // wrong length for E-Nonce
        let msg = parse(&buf).unwrap();
        assert!(msg.e_nonce.is_none());
    }
}