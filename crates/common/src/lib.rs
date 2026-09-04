//! Shared building blocks between the unprivileged `netspecter` GUI and the
//! privileged `netspecter-agent` process.
//!
//! This crate contains only data and pure/utility logic: the wire types, the
//! IPC protocol and its framed-JSON codec, and a couple of utilities that both
//! sides need.

pub mod autopwn;
pub mod backend_types;
pub mod ble;
pub mod caplet;
pub mod channel;
pub mod cracker;
pub mod crypto;
pub mod deps;
pub mod encryption;
pub mod handshake;
pub mod hid;
pub mod ipc;
pub mod karma;
pub mod scheduler;
pub mod types;
pub mod wps;
pub mod wps_crypto;
pub mod wps_default_pins;
pub mod wps_dh;
pub mod wordlists;
pub mod wps_tlv;

pub use types::*;

pub const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));
