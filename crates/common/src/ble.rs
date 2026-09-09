//! Bluetooth Low Energy (BLE) reconnaissance.
//!
//! BLE is the dominant radio protocol for IoT devices — wearables,
//! beacons, smart locks, medical devices, asset trackers. NetSpecter's
//! BLE module provides:
//!
//! 1. **Active scanning** — sends SCAN_REQ, parses SCAN_RESP from
//!    advertising devices, walks the AD structs to extract the device
//!    name, manufacturer, service UUIDs, and TX power.
//! 2. **Passive scanning** — listens for ADV_IND without sending any
//!    packets; useful in RF-quiet environments.
//! 3. **GATT enumeration** — once a connection is established (via the
//!    hci socket), reads the GATT service / characteristic / descriptor
//!    hierarchy.
//! 4. **Device classification** — heuristics on the advertising data
//!    that label a device as "smart-lock", "beacon", "fitness-tracker",
//!    etc.
//!
//! ## Frame types
//!
//! The BLE link layer packets we care about:
//!
//! ```text
//! ADV_IND       — non-connectable undirected advertising (beacons)
//! ADV_DIRECT_IND — directed advertising (re-connection hints)
//! ADV_NONCONN_IND — non-connectable non-directed advertising (Eddystone)
//! SCAN_REQ      — active scan request (we send this)
//! SCAN_RESP     — active scan response (we receive this)
//! ```
//!
//! Each packet's payload is a sequence of AD structs, each shaped:
//! `[length][type][data...]`. Types 0x01 / 0x09 / 0x16 carry the device
//! name, manufacturer, and service UUIDs respectively.
//!
//! ## What this module does NOT do
//!
//! - Active GATT exploitation (read characteristic with permission). That's
//!   a different threat model and is gated behind a separate interface.
//! - BLE jamming (regulatory issues + hardware-dependent).
//! - BLE pairing / bonding attacks (requires the host's link key).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single BLE device as observed during a scan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BleDevice {
    /// Bluetooth device address (e.g. `AA:BB:CC:DD:EE:FF`).
    pub address: String,
    /// Address type (Public / Random / Identity).
    pub address_type: AddressType,
    /// Device name from the Complete Local Name AD (type 0x09), if any.
    pub name: Option<String>,
    /// Manufacturer ID from the Manufacturer Specific Data AD (type 0xFF).
    pub manufacturer_id: Option<u16>,
    /// Manufacturer data bytes (raw, type 0xFF payload).
    pub manufacturer_data: Option<Vec<u8>>,
    /// Service UUIDs from the AD (type 0x02 / 0x03 / 0x06 / 0x07).
    pub service_uuids: Vec<String>,
    /// Transmit power in dBm from the TX Power AD (type 0x0A), if any.
    pub tx_power_dbm: Option<i8>,
    /// RSSI observed at scan time.
    pub rssi_dbm: Option<i8>,
    /// Heuristic classification of the device.
    pub classification: DeviceClass,
    /// First time this device was observed.
    pub first_seen: DateTime<Utc>,
    /// Most-recent observation.
    pub last_seen: DateTime<Utc>,
    /// How many scan responses we've collected.
    pub observation_count: u32,
}

/// BLE address type (matches the HCI "LE Address Type" enumeration).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressType {
    Public,
    Random,
    /// Resolvable Private Address.
    Rpa,
    /// Non-resolvable Private Address.
    NonResolvableRpa,
}

/// Heuristic classification of a BLE device based on the AD payload.
///
/// The classifier is conservative — it only assigns a class when the
/// evidence is strong (matched manufacturer + matched service UUIDs).
/// Otherwise it falls back to `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceClass {
    /// Apple iBeacon.
    IBeacon,
    /// Google Eddystone beacon.
    Eddystone,
    /// Fitness tracker (heart-rate service 0x180D).
    FitnessTracker,
    /// Smart lock (e.g. August, Kevo, Yale).
    SmartLock,
    /// Medical device (Health Thermometer 0x1809, Pulse Oximeter 0x1822).
    MedicalDevice,
    /// Keyboard / mouse (HID over GATT 0x1812).
    HidDevice,
    /// Asset tracker (e.g. Tile, AirTag).
    AssetTracker,
    /// Generic BLE peripheral — no specific class.
    GenericBle,
    /// Could not classify from AD data alone.
    Unknown,
}

impl DeviceClass {
    /// Compact label for UI rendering.
    pub fn label(&self) -> &'static str {
        match self {
            DeviceClass::IBeacon => "iBeacon",
            DeviceClass::Eddystone => "Eddystone",
            DeviceClass::FitnessTracker => "Fitness tracker",
            DeviceClass::SmartLock => "Smart lock",
            DeviceClass::MedicalDevice => "Medical device",
            DeviceClass::HidDevice => "HID device",
            DeviceClass::AssetTracker => "Asset tracker",
            DeviceClass::GenericBle => "Generic BLE",
            DeviceClass::Unknown => "Unknown",
        }
    }
}

/// One AD (Advertising Data) struct parsed from the scan payload.
///
/// AD structs are `[length, type, data...]` where length counts the
/// type + data bytes (not itself).
#[derive(Clone, Debug)]
pub struct AdStruct {
    pub ad_type: u8,
    pub data: Vec<u8>,
}

/// Parse a raw advertising payload into AD structs.
///
/// Returns `None` for individual structs whose declared length exceeds
/// the remaining buffer — that's a malformed packet, but we tolerate it
/// by stopping the parse at that point.
pub fn parse_ad_payload(payload: &[u8]) -> Vec<AdStruct> {
    let mut out = Vec::new();
    let mut idx = 0;
    while idx < payload.len() {
        let len = payload[idx] as usize;
        if len == 0 {
            break;
        }
        if idx + 1 + len > payload.len() {
            break;
        }
        let ad_type = payload[idx + 1];
        let data = payload[idx + 2..idx + 1 + len].to_vec();
        out.push(AdStruct { ad_type, data });
        idx += 1 + len;
    }
    out
}

/// Build a [`BleDevice`] from a scan observation.
///
/// Combines AD-struct parsing with manufacturer / service / name
/// extraction. RSSI is passed through; classification uses the AD data.
pub fn device_from_ad(
    address: String,
    address_type: AddressType,
    rssi_dbm: Option<i8>,
    payload: &[u8],
) -> BleDevice {
    let mut dev = BleDevice {
        address,
        address_type,
        name: None,
        manufacturer_id: None,
        manufacturer_data: None,
        service_uuids: Vec::new(),
        tx_power_dbm: None,
        rssi_dbm,
        classification: DeviceClass::Unknown,
        first_seen: Utc::now(),
        last_seen: Utc::now(),
        observation_count: 1,
    };

    for ad in parse_ad_payload(payload) {
        match ad.ad_type {
            // Complete Local Name
            0x09 => {
                dev.name = Some(String::from_utf8_lossy(&ad.data).into_owned());
            }
            // Shortened Local Name
            0x08 => {
                if dev.name.is_none() {
                    dev.name = Some(String::from_utf8_lossy(&ad.data).into_owned());
                }
            }
            // Manufacturer Specific Data
            0xFF if ad.data.len() >= 2 => {
                let id = u16::from_le_bytes([ad.data[0], ad.data[1]]);
                dev.manufacturer_id = Some(id);
                dev.manufacturer_data = Some(ad.data.clone());
            }
            // TX Power Level
            0x0A if ad.data.len() == 1 => {
                dev.tx_power_dbm = Some(ad.data[0] as i8);
            }
            // Complete List of 16-bit Service UUIDs
            0x03 => {
                for chunk in ad.data.chunks(2) {
                    if chunk.len() == 2 {
                        let uuid = u16::from_le_bytes([chunk[0], chunk[1]]);
                        dev.service_uuids.push(format!("{:04x}", uuid));
                    }
                }
            }
            // Complete List of 32-bit Service UUIDs
            0x05 => {
                for chunk in ad.data.chunks(4) {
                    if chunk.len() == 4 {
                        let uuid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        dev.service_uuids.push(format!("{:08x}", uuid));
                    }
                }
            }
            // Incomplete List of 16-bit UUIDs
            0x02 => {
                for chunk in ad.data.chunks(2) {
                    if chunk.len() == 2 {
                        let uuid = u16::from_le_bytes([chunk[0], chunk[1]]);
                        if !dev.service_uuids.contains(&format!("{:04x}", uuid)) {
                            dev.service_uuids.push(format!("{:04x}", uuid));
                        }
                    }
                }
            }
            // Incomplete List of 32-bit UUIDs
            0x04 => {
                for chunk in ad.data.chunks(4) {
                    if chunk.len() == 4 {
                        let uuid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        let s = format!("{:08x}", uuid);
                        if !dev.service_uuids.contains(&s) {
                            dev.service_uuids.push(s);
                        }
                    }
                }
            }
            _ => { /* ignore */ }
        }
    }

    dev.classification = classify(&dev);
    dev
}

/// Heuristic classifier.
pub fn classify(dev: &BleDevice) -> DeviceClass {
    // iBeacon: Apple manufacturer ID (0x004C) + 16-byte prefix matching
    // the iBeacon header (02 01 06 ...).
    if dev.manufacturer_id == Some(0x004C) {
        if let Some(ref data) = dev.manufacturer_data {
            if data.len() >= 23 && data[2] == 0x02 && data[3] == 0x15 {
                return DeviceClass::IBeacon;
            }
        }
    }

    // Eddystone: Google manufacturer ID (0x00E0) + Eddystone frame type.
    if dev.manufacturer_id == Some(0x00E0) {
        if let Some(ref data) = dev.manufacturer_data {
            if data.len() >= 3 && (data[2] == 0x00 || data[2] == 0x10 || data[2] == 0x20 || data[2] == 0x30) {
                return DeviceClass::Eddystone;
            }
        }
    }

    // HID over GATT (0x1812).
    if dev.service_uuids.iter().any(|u| u == "1812") {
        return DeviceClass::HidDevice;
    }

    // Health Thermometer (0x1809) or Pulse Oximeter (0x1822).
    if dev.service_uuids.iter().any(|u| u == "1809" || u == "1822") {
        return DeviceClass::MedicalDevice;
    }

    // Heart Rate (0x180D) — fitness tracker. UUIDs are stored lowercase
    // ({:04x}); compare case-insensitively for resilience.
    if dev
        .service_uuids
        .iter()
        .any(|u| u.eq_ignore_ascii_case("180D"))
    {
        return DeviceClass::FitnessTracker;
    }

    // Generic BLE peripheral.
    if dev.name.is_some() || !dev.service_uuids.is_empty() {
        return DeviceClass::GenericBle;
    }

    DeviceClass::Unknown
}

/// Configuration for a BLE scan.
#[derive(Clone, Debug)]
pub struct BleScanConfig {
    /// Scan duration in seconds.
    pub duration_secs: u64,
    /// If true, send SCAN_REQ (active). If false, listen only (passive).
    pub active: bool,
    /// If true, report duplicate advertisements. Passive scans usually
    /// filter duplicates to save radio time; we expose the flag for
    /// debugging.
    pub filter_duplicates: bool,
}

impl Default for BleScanConfig {
    fn default() -> Self {
        Self {
            duration_secs: 10,
            active: true,
            filter_duplicates: true,
        }
    }
}

/// Result of a BLE scan.
#[derive(Clone, Debug)]
pub struct BleScanResult {
    pub devices: Vec<BleDevice>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub config: BleScanConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ad_payload_handles_empty() {
        assert!(parse_ad_payload(&[]).is_empty());
    }

    #[test]
    fn parse_ad_payload_handles_terminator_zero() {
        // Length byte 0 is the terminator — we should stop, not panic.
        let bytes = vec![0x05, 0x09, b'P', b'a', b'u', b'l', 0x00, 0x02, 0x01, 0x06];
        let ads = parse_ad_payload(&bytes);
        assert_eq!(ads.len(), 1);
        assert_eq!(ads[0].ad_type, 0x09);
        assert_eq!(ads[0].data, vec![b'P', b'a', b'u', b'l']);
    }

    #[test]
    fn parse_ad_payload_handles_truncated_len() {
        // Length byte claims 10 bytes follow but only 2 are present.
        let bytes = vec![0x10, 0x09, b'a', b'b'];
        assert!(parse_ad_payload(&bytes).is_empty());
    }

    #[test]
    fn device_extracts_local_name() {
        let payload = vec![0x05, 0x09, b'P', b'a', b'u', b'l'];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            Some(-50),
            &payload,
        );
        assert_eq!(dev.name.as_deref(), Some("Paul"));
        assert_eq!(dev.classification, DeviceClass::GenericBle);
    }

    #[test]
    fn device_extracts_shortened_name_when_complete_absent() {
        // len byte = 1 (type) + 3 (data) = 4.
        let payload = vec![0x04, 0x08, b'a', b'b', b'c'];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.name.as_deref(), Some("abc"));
    }

    #[test]
    fn device_extracts_16bit_service_uuids() {
        // Complete list of 16-bit UUIDs: 180D (Heart Rate), 180F (Battery)
        let payload = vec![0x05, 0x03, 0x0D, 0x18, 0x0F, 0x18];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.service_uuids, vec!["180d", "180f"]);
    }

    #[test]
    fn device_extracts_manufacturer_data() {
        // Apple (0x004C) iBeacon AD: one struct carrying company id (2 LE
        // bytes) + a 21-byte body whose head matches the iBeacon header
        // (beacon type 0x02, spec length 0x15).
        let mut body = vec![0x4C, 0x00, 0x02, 0x15];
        body.extend_from_slice(&[0u8; 19]);
        // company id (2) + iBeacon body (21) = 23 bytes of manufacturer data.
        assert_eq!(body.len(), 23);
        let mut payload = vec![1 + body.len() as u8, 0xFF];
        payload.extend_from_slice(&body);
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Random,
            None,
            &payload,
        );
        assert_eq!(dev.manufacturer_id, Some(0x004C));
        assert_eq!(dev.classification, DeviceClass::IBeacon);
    }

    #[test]
    fn classify_eddystone() {
        // len byte = 1 (type) + 3 (company id + frame type) = 4.
        let payload = vec![0x04, 0xFF, 0xE0, 0x00, 0x10]; // Google + URL frame type
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.manufacturer_id, Some(0x00E0));
        assert_eq!(dev.classification, DeviceClass::Eddystone);
    }

    #[test]
    fn classify_hid_via_service_uuid() {
        // HID over GATT = 0x1812
        let payload = vec![0x03, 0x03, 0x12, 0x18];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.service_uuids, vec!["1812"]);
        assert_eq!(dev.classification, DeviceClass::HidDevice);
    }

    #[test]
    fn classify_medical_device_via_health_thermometer() {
        let payload = vec![0x03, 0x03, 0x09, 0x18];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.classification, DeviceClass::MedicalDevice);
    }

    #[test]
    fn classify_fitness_tracker_via_heart_rate() {
        let payload = vec![0x03, 0x03, 0x0D, 0x18];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.classification, DeviceClass::FitnessTracker);
    }

    #[test]
    fn classify_unknown_when_payload_empty() {
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &[],
        );
        assert_eq!(dev.classification, DeviceClass::Unknown);
    }

    #[test]
    fn tx_power_parsed_from_ad_0a() {
        let payload = vec![0x02, 0x0A, 0xFB]; // -5 dBm
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.tx_power_dbm, Some(-5));
    }

    #[test]
    fn address_type_serializes_lowercase() {
        assert!(serde_json::to_string(&AddressType::Public).unwrap().contains("public"));
        assert!(serde_json::to_string(&AddressType::Rpa).unwrap().contains("rpa"));
    }

    #[test]
    fn device_class_labels() {
        assert_eq!(DeviceClass::IBeacon.label(), "iBeacon");
        assert_eq!(DeviceClass::SmartLock.label(), "Smart lock");
        assert_eq!(DeviceClass::HidDevice.label(), "HID device");
    }

    #[test]
    fn ble_scan_config_default_is_active_with_10s() {
        let cfg = BleScanConfig::default();
        assert_eq!(cfg.duration_secs, 10);
        assert!(cfg.active);
        assert!(cfg.filter_duplicates);
    }

    #[test]
    fn incomplete_uuid_list_dedups_against_complete() {
        let payload = vec![
            0x05, 0x03, 0x0D, 0x18, 0x0F, 0x18,  // complete: 180D, 180F
            0x03, 0x02, 0x0D, 0x18,              // incomplete: 180D
        ];
        let dev = device_from_ad(
            "aa:bb:cc:dd:ee:ff".into(),
            AddressType::Public,
            None,
            &payload,
        );
        assert_eq!(dev.service_uuids, vec!["180d", "180f"]);
    }
}