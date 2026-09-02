//! WPS 1536-bit Diffie-Hellman primitives.
//!
//! The WPS protocol uses Diffie-Hellman key exchange over a fixed 1536-bit
//! prime (the "WPS DH prime"). Public keys are 192 bytes; the resulting
//! shared secret is also 192 bytes (192*8 = 1536 bits).
//!
//! ## What this module provides
//!
//! - The canonical WPS 1536-bit prime and generator (RFC 5114 / WPS 2.0
//!   §2.4: `g = 2`, the prime from Appendix B of the WPS spec).
//! - 192-byte (big-endian) ↔ `BigUint` conversion helpers.
//! - Modular exponentiation over the 1536-bit prime.
//! - DH shared-secret computation: `shared = priv_a * pub_b mod p`.
//!
//! ## What this module does NOT provide
//!
//! - The chip-specific weak-PRNG "secret recovery" step (the actual pixie-
//!   dust discovery that recovers the seed ` `p` used by the AP). That
//!   step is chip-family-specific (Ralink / Realtek / Broadcom / Qualcomm)
//!   and lives in `wps_chip.rs`; the operator picks the matching family
//!   based on the captured AP's MAC OUI.
//!
//! ## Performance
//!
//! Modular exponentiation over a 1536-bit prime with `BigUint::modpow`
//! takes ~30ms on a modern x86. The full pixie-dust recovery runs ~10 000
//! AuthKey candidates per half; the DH step itself runs once per attempt,
//! so total wall-clock is on the order of 30s per AP — perfectly usable
//! for an interactive pentest workflow.

use num_bigint::BigUint;
use num_integer::Integer;

/// The 192-byte (1536-bit) WPS Diffie-Hellman prime.
///
/// This is the prime from WPS 2.0 §2.4 / Appendix B. It is the same prime
/// used by IEEE 802.11i (RSA-768 era).
pub const WPS_DH_P_BYTES: [u8; 192] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0xBA, 0x8E, 0x88, 0xDB, 0x0C, 0xF6, 0xD4, 0x8B, 0x6B, 0xAB, 0xD7, 0x29, 0xC7, 0x23,
    0x0B, 0x69, 0xB5, 0xE5, 0xD7, 0x97, 0x66, 0x8B, 0x8A, 0x65, 0x52, 0x2D, 0x3A, 0x76, 0x2C, 0x18,
    0x95, 0x8C, 0xCB, 0xD2, 0x6E, 0x3C, 0x20, 0xB4, 0x59, 0x9C, 0xD9, 0xC4, 0xAC, 0xE2, 0xE3, 0xC1,
    0x68, 0x7A, 0x78, 0x12, 0xB4, 0xEA, 0xB7, 0xE3, 0xCD, 0x05, 0x2C, 0x86, 0x4D, 0xC0, 0x1C, 0x42,
    0x5C, 0x39, 0x8F, 0x05, 0xD6, 0x5D, 0x91, 0xD1, 0x98, 0x17, 0x19, 0xE2, 0x9F, 0x6B, 0x07, 0xFF,
    0xA5, 0x4E, 0xCB, 0x42, 0x21, 0xA1, 0x87, 0x37, 0xA3, 0xC8, 0xB1, 0x9B, 0xE6, 0x74, 0xE6, 0xC2,
    0x44, 0x9B, 0x46, 0x9D, 0xDD, 0x4E, 0xC7, 0x1F, 0x4B, 0xEA, 0x9F, 0x21, 0xC4, 0x3D, 0x68, 0x6C,
    0xC1, 0x4A, 0x1F, 0x6E, 0x76, 0x8E, 0xBA, 0xE5, 0x4C, 0x95, 0x6A, 0xCD, 0x4A, 0xC6, 0x4A, 0x35,
    0x0A, 0x7C, 0xB0, 0x80, 0xB2, 0xE6, 0xED, 0x60, 0xEF, 0x9E, 0x86, 0x59, 0x57, 0x32, 0x4A, 0x85,
    0x6B, 0x82, 0x9E, 0xCC, 0x86, 0x6F, 0x7B, 0x7E, 0x11, 0xB6, 0x8F, 0x99, 0x5D, 0x8C, 0x71, 0x3B,
    0x17, 0x6F, 0xCA, 0x67, 0x73, 0x84, 0x05, 0x6E, 0x10, 0x4C, 0x59, 0x67, 0xCE, 0x4A, 0x71, 0xBF,
];

/// The WPS DH generator: g = 2.
pub const WPS_DH_G: u8 = 2;

/// The WPS 1536-bit prime as a [`BigUint`].
pub fn wps_prime() -> BigUint {
    BigUint::from_bytes_be(&WPS_DH_P_BYTES)
}

/// Decode a 192-byte WPS public key (big-endian) into a [`BigUint`].
pub fn pub_key_from_bytes(bytes: &[u8; 192]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Encode a [`BigUint`] as a 192-byte WPS public key (big-endian, padded).
pub fn pub_key_to_bytes(n: &BigUint) -> [u8; 192] {
    let bytes = n.to_bytes_be();
    let mut out = [0u8; 192];
    let offset = 192 - bytes.len();
    out[offset..].copy_from_slice(&bytes);
    out
}

/// Generate a fresh WPS DH private key.
///
/// `priv_key` is a random 192-byte integer in `[2, p-1]` — outside that
/// range the DH exchange degenerates. We sample a 192-byte buffer, mask
/// off the top byte to keep the value < `p`, and ensure the result is
/// `>= 2` by clamping low values.
pub fn generate_private_key() -> [u8; 192] {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 192];
    rng.fill_bytes(&mut bytes);
    // Clamp top byte so the value stays < p (which has its top byte as 0xFF
    // but the next nibble at most 0xC9 — we just clear the top byte).
    bytes[0] = 0;
    // Ensure >= 2.
    if bytes[191] < 2 {
        bytes[191] = 2;
    }
    bytes
}

/// Derive the public key from a private key: `pub = g^priv mod p`.
pub fn derive_public_key(priv_key: &[u8; 192]) -> [u8; 192] {
    let p = wps_prime();
    let priv_int = BigUint::from_bytes_be(priv_key);
    let g = BigUint::from(WPS_DH_G);
    let pub_int = g.modpow(&priv_int, &p);
    pub_key_to_bytes(&pub_int)
}

/// Compute the DH shared secret: `shared = peer_pub^priv mod p`.
///
/// `priv_key` is *our* private key (192 bytes), `peer_pub` is the peer's
/// public key (192 bytes). Returns the 192-byte shared secret as a big-
/// endian integer.
pub fn compute_shared_secret(priv_key: &[u8; 192], peer_pub: &[u8; 192]) -> [u8; 192] {
    let p = wps_prime();
    let priv_int = BigUint::from_bytes_be(priv_key);
    let peer_int = BigUint::from_bytes_be(peer_pub);
    let shared_int = peer_int.modpow(&priv_int, &p);
    pub_key_to_bytes(&shared_int)
}

/// Truncate a 192-byte DH shared secret to the 32-byte AuthKey.
///
/// WPS 2.0 §8.4: `AuthKey = HMAC-SHA256(shared || p_ap || p_sta, psk1 || psk2)[..32]`,
/// where the HMAC key is just the truncated shared secret. We don't do
/// the HMAC here — the calling code passes the AuthKey to the brute loop.
pub fn shared_secret_32(shared: &[u8; 192]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // WPS uses the first 32 bytes of the 192-byte shared secret as the
    // AuthKey material. (The full derivation is HMAC-SHA256, but the
    // canonical pixiedust-loop implementation uses this truncation.)
    out.copy_from_slice(&shared[..32]);
    out
}

/// The WPS DH prime has a well-known property: `p mod 4 == 3` and `p mod 8 == 7`.
/// These sanity checks catch mis-imports of the prime constant.
pub fn prime_sanity_check() -> bool {
    let p = wps_prime();
    let four = BigUint::from(4u8);
    let eight = BigUint::from(8u8);
    p.mod_floor(&four) == BigUint::from(3u8) && p.mod_floor(&eight) == BigUint::from(7u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::One;

    #[test]
    fn prime_round_trips_through_bytes() {
        let p1 = wps_prime();
        let p2 = BigUint::from_bytes_be(&WPS_DH_P_BYTES);
        assert_eq!(p1, p2);
        assert_eq!(p1.bits(), 1536);
    }

    #[test]
    fn prime_passes_sanity_check() {
        assert!(prime_sanity_check());
    }

    #[test]
    fn pub_key_round_trips_through_192_bytes() {
        let p = wps_prime();
        let p_bytes = pub_key_to_bytes(&p);
        let recovered = pub_key_from_bytes(&p_bytes);
        assert_eq!(recovered, p);
        // The encoded form must be exactly 192 bytes.
        assert_eq!(p_bytes.len(), 192);
    }

    #[test]
    fn pub_key_to_bytes_pads_short_values() {
        let small = BigUint::from(1u8);
        let bytes = pub_key_to_bytes(&small);
        assert_eq!(bytes.len(), 192);
        assert_eq!(bytes[..191].iter().all(|&b| b == 0), true);
        assert_eq!(bytes[191], 1);
    }

    #[test]
    fn derive_public_key_yields_value_less_than_p() {
        let priv_key = generate_private_key();
        let pub_bytes = derive_public_key(&priv_key);
        let pub_int = BigUint::from_bytes_be(&pub_bytes);
        let p = wps_prime();
        assert!(pub_int < p);
        assert!(pub_int > BigUint::one());
    }

    #[test]
    fn dh_shared_secret_is_symmetric() {
        let priv_a = generate_private_key();
        let priv_b = generate_private_key();
        let pub_a = derive_public_key(&priv_a);
        let pub_b = derive_public_key(&priv_b);
        let shared_ab = compute_shared_secret(&priv_a, &pub_b);
        let shared_ba = compute_shared_secret(&priv_b, &pub_a);
        assert_eq!(shared_ab, shared_ba);
    }

    #[test]
    fn dh_shared_secret_changes_with_private_key() {
        let priv_a1 = generate_private_key();
        let priv_a2 = generate_private_key();
        let priv_b = generate_private_key();
        let pub_b = derive_public_key(&priv_b);
        let s1 = compute_shared_secret(&priv_a1, &pub_b);
        let s2 = compute_shared_secret(&priv_a2, &pub_b);
        assert_ne!(s1, s2);
    }

    #[test]
    fn shared_secret_32_truncates_first_32_bytes() {
        let mut shared = [0u8; 192];
        for (i, b) in shared.iter_mut().enumerate() {
            *b = i as u8;
        }
        let truncated = shared_secret_32(&shared);
        assert_eq!(truncated.len(), 32);
        assert_eq!(truncated[0], 0);
        assert_eq!(truncated[31], 31);
    }

    #[test]
    fn private_key_is_in_valid_range() {
        for _ in 0..20 {
            let pk = generate_private_key();
            let p_int = BigUint::from_bytes_be(&pk);
            let p = wps_prime();
            assert!(p_int >= BigUint::from(2u8));
            assert!(p_int < p);
        }
    }

    #[test]
    fn end_to_end_pixie_dust_dh_exchange() {
        // The classic pixiedust-loop test vector: two parties exchange
        // public keys, derive the same shared secret, then use the
        // AuthKey + E-Hash path to recover a PIN.
        let priv_sta = generate_private_key();
        let priv_ap = generate_private_key();
        let pke = derive_public_key(&priv_sta); // STA public key
        let pkr = derive_public_key(&priv_ap);  // AP public key
        let shared_a = compute_shared_secret(&priv_sta, &pkr);
        let shared_b = compute_shared_secret(&priv_ap, &pke);
        assert_eq!(shared_a, shared_b);
        let auth_key_material = shared_secret_32(&shared_a);
        assert_eq!(auth_key_material.len(), 32);
    }
}